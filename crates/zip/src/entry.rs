//! Describes a `zip` archive

use std::fmt::Write;
use std::io::Cursor;
use std::path::Path;

use ahash::AHashSet;
use cms::signed_data::{SignerIdentifier, SignerInfo};
use flate2::{Decompress, FlushDecompress, Status};
use log::warn;
use md5::{Digest, Md5};
use memchr::memmem;
use sha1::Sha1;
use sha2::Sha256;
use winnow::binary::{le_u32, le_u64, length_take};
use winnow::combinator::repeat;
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::take;
use x509_cert::Certificate;
use x509_cert::der::oid::db::DB;
use x509_cert::der::{Decode, Encode};
use x509_cert::name::Name;

use crate::signature::{CertificateInfo, Signature};
use crate::source::Source;
use crate::structs::{
    CentralDirectory, CentralDirectoryEntry, EndOfCentralDirectory, LocalFileHeader,
};
use crate::{CertificateError, FileCompressionType, ReadSeek, ZipError, ber};

/// Maximum allowed uncompressed size for a file entry.
const MAX_UNCOMPRESSED_SIZE: usize = u32::MAX as usize;

/// Caps the self-healing forward scan so a corrupt archive can't degrade to a quadratic scan.
const SELF_HEAL_MAX_SCAN: usize = 1 << 20;

/// How far back from a claimed offset to search; corrupt offsets shift by a few bytes.
const SELF_HEAL_BACKWARD: usize = 1 << 16;

/// Window size for the backward EOCD signature search from the end of the stream.
const EOCD_SEARCH_WINDOW: usize = 4096;

/// Fixed part of a local file header: `4 (magic) + 26 (fields)`.
const LOCAL_HEADER_FIXED_LEN: usize = 30;

/// Upper bound for the APK Signing Block region read out of the source.
///
/// Real signing blocks are at most a few megabytes (certificates plus verity
/// padding to a 4096 multiple); anything larger is malformed data that must
/// not be pulled into memory.
const MAX_SIGNING_BLOCK_SIZE: usize = 64 * 1024 * 1024;

/// Represents a parsed ZIP archive.
///
/// Reads lazily from a seekable source: only the central directory is kept
/// in memory; local file headers and entry data are fetched on demand.
pub struct ZipEntry {
    /// Lazily-read backing source.
    source: Source,

    /// Absolute offset of the central directory.
    central_dir_offset: usize,

    /// Central directory structure
    central_directory: CentralDirectory,
}

impl std::fmt::Debug for ZipEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipEntry")
            .field("len", &self.source.len())
            .field("central_dir_offset", &self.central_dir_offset)
            .field("entries", &self.central_directory.ordered_names.len())
            .finish_non_exhaustive()
    }
}

/// Metadata of a single archive entry, without reading its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryInfo {
    /// Compression method declared in the central directory
    /// ([`ZipEntry::METHOD_STORED`], [`ZipEntry::METHOD_DEFLATED`], or another value in tampered archives)
    pub compression_method: u16,

    /// Compressed size, in bytes
    pub compressed_size: u32,

    /// Uncompressed size, in bytes
    pub uncompressed_size: u32,

    /// The local header's compression method disagrees with the central directory's
    pub tampered: bool,
}

/// Implementation of basic methods
impl ZipEntry {
    /// Compression method `0`: uncompressed entry data.
    ///
    /// See: <https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT> (4.4.5)
    pub const METHOD_STORED: u16 = 0;

    /// Compression method `8`: Deflate-compressed entry data.
    ///
    /// See: <https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT> (4.4.5)
    pub const METHOD_DEFLATED: u16 = 8;

    /// Parses the local file header at `offset`, reading it lazily from the source.
    ///
    /// Two bounded reads: the fixed part first (to learn the name and extra
    /// field lengths), then the variable part. The entry data offset is
    /// always computed from the local header's own lengths, which may
    /// legitimately differ from the central directory copy.
    fn read_local_header_at(&self, offset: usize) -> Result<LocalFileHeader, ZipError> {
        let mut fixed = [0u8; LOCAL_HEADER_FIXED_LEN];
        self.source.read_exact_at(offset, &mut fixed)?;

        // name and extra lengths live at the tail of the fixed part
        let name_len = u16::from_le_bytes([fixed[26], fixed[27]]) as usize;
        let extra_len = u16::from_le_bytes([fixed[28], fixed[29]]) as usize;

        // one buffer: the fixed part, with the variable part read into its tail
        let total = LOCAL_HEADER_FIXED_LEN + name_len + extra_len;
        let mut raw = Vec::with_capacity(total);
        raw.extend_from_slice(&fixed);
        raw.resize(total, 0);
        self.source.read_exact_at(
            offset + LOCAL_HEADER_FIXED_LEN,
            &mut raw[LOCAL_HEADER_FIXED_LEN..],
        )?;

        let mut header = LocalFileHeader::parse(&raw, 0).map_err(|_| ZipError::ParseError)?;
        // `parse` sees only the freshly-read slice, so patch in the real stream offset
        header.offset = offset;
        Ok(header)
    }

    /// Parses the entry's local file header: the claimed offset when it hosts
    /// a header with a matching filename, otherwise the self-healing scan.
    fn read_local_header_verified(
        &self,
        entry: &CentralDirectoryEntry,
    ) -> Result<LocalFileHeader, ZipError> {
        let claim = entry.local_header_offset as usize;
        let expected_name = entry.file_name.as_bytes();

        if let Ok(header) = self.read_local_header_at(claim)
            && header.file_name.as_ref() == expected_name
        {
            return Ok(header);
        }

        let offset = self
            .find_local_header_offset(claim, expected_name)
            .ok_or(ZipError::FileNotFound)?;
        self.read_local_header_at(offset)
            .map_err(|_| ZipError::FileNotFound)
    }

    /// Recovers the real local file header offset for an entry whose
    /// `local_header_offset` is corrupt: scans a bounded, filename-verified
    /// window for a matching `PK\x03\x04`.
    ///
    /// Skips the claimed offset; the caller has already tried it.
    fn find_local_header_offset(&self, claim: usize, expected_name: &[u8]) -> Option<usize> {
        // bounded scan for a matching local header, verified by filename.
        let start = claim.saturating_sub(SELF_HEAL_BACKWARD);
        let end = self
            .source
            .len()
            .min(self.central_dir_offset)
            .min(claim.saturating_add(SELF_HEAL_MAX_SCAN));
        if end <= start {
            return None;
        }

        // read the scan window once, then walk it
        let window = self.source.read_bytes_at(start, end - start).ok()?;
        let mut pos = 0;
        while let Some(rel) = memmem::find(&window[pos..], b"PK\x03\x04") {
            let candidate = start + pos + rel;
            if candidate != claim
                && let Ok(header) = self.read_local_header_at(candidate)
                && header.file_name.as_ref() == expected_name
            {
                return Some(candidate);
            }
            pos += rel + 1;
        }
        None
    }

    /// Creates a new `ZipEntry` from raw in-memory ZIP data.
    ///
    /// Wraps the bytes in a [`Cursor`] and delegates to [`ZipEntry::from_reader`],
    /// so in-memory and file-backed archives share the same lazy reading path.
    ///
    /// # Errors
    ///
    /// Returns a [ZipError] if:
    /// - The input does not start with a valid ZIP signature [ZipError::InvalidHeader];
    /// - The End of Central Directory cannot be found [ZipError::NotFoundEOCD];
    /// - Parsing of the EOCD or central directory fails [ZipError::ParseError].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use apk_info_zip::{ZipEntry, ZipError};
    /// let data = std::fs::read("archive.zip").unwrap();
    /// let zip = ZipEntry::new(data).expect("failed to parse ZIP archive");
    /// ```
    pub fn new(input: Vec<u8>) -> Result<ZipEntry, ZipError> {
        Self::from_reader(Cursor::new(input))
    }

    /// Creates a new `ZipEntry` that lazily reads a ZIP archive from any
    /// seekable source, for example a [`std::fs::File`]. Only the central
    /// directory is loaded into memory.
    ///
    /// # Errors
    ///
    /// Returns a [ZipError] if:
    /// - The stream is too short or does not start with a valid ZIP signature [ZipError::InvalidHeader];
    /// - The End of Central Directory cannot be found [ZipError::NotFoundEOCD];
    /// - Parsing of the EOCD or central directory fails [ZipError::ParseError].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use apk_info_zip::{ZipEntry, ZipError};
    /// let file = std::fs::File::open("app.apk").unwrap();
    /// let zip = ZipEntry::from_reader(file).expect("failed to parse ZIP archive");
    /// ```
    pub fn from_reader(reader: impl ReadSeek + 'static) -> Result<ZipEntry, ZipError> {
        Self::parse(Source::new(Box::new(reader))?)
    }

    /// Opens a file on disk and parses it lazily; the file is never fully
    /// read into memory.
    ///
    /// # Errors
    ///
    /// Returns a [ZipError] if the file cannot be opened
    /// ([ZipError::IoError]), or anything [`ZipEntry::from_reader`] reports.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use apk_info_zip::{ZipEntry, ZipError};
    /// let zip = ZipEntry::open("app.apk").expect("failed to parse ZIP archive");
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<ZipEntry, ZipError> {
        let file = std::fs::File::open(path)?;
        Self::from_reader(file)
    }

    fn parse(source: Source) -> Result<ZipEntry, ZipError> {
        // perform basic sanity check
        let mut magic = [0u8; 4];
        source.read_exact_at(0, &mut magic)?;
        if magic != *b"PK\x03\x04" {
            return Err(ZipError::InvalidHeader);
        }

        let eocd_offset = Self::find_eocd_offset(&source).ok_or(ZipError::NotFoundEOCD)?;

        // the EOCD record plus up to a maximum-size archive comment
        let eocd_len = (source.len() - eocd_offset).min(22 + u16::MAX as usize);
        let eocd_bytes = source.read_bytes_at(eocd_offset, eocd_len)?;
        let eocd =
            EndOfCentralDirectory::parse(&mut &eocd_bytes[..]).map_err(|_| ZipError::ParseError)?;

        // Prefer the EOCD's declared CD offset;
        // derive it (`eocd - cd_size`) only when prepended/polyglot data left it stale.
        let declared = eocd.central_dir_offset as usize;
        let derived = eocd_offset
            .checked_sub(eocd.central_dir_size as usize)
            .ok_or(ZipError::ParseError)?;

        let mut cd_magic = [0u8; 4];
        let central_dir_offset = if source
            .read_exact_at(declared, &mut cd_magic)
            .is_ok_and(|_| cd_magic == *b"PK\x01\x02")
        {
            declared
        } else {
            derived
        };

        // Read from the CD offset to EOF; `central_dir_size` can understate the
        // real record area in a tampered archive. Parse at most `total_entries`
        // records, like Android's loop over `num_records`, so a decoy appended
        // past the count (which still installs and runs) can't shadow a real
        // entry such as the manifest.
        let cd_bytes =
            source.read_bytes_at(central_dir_offset, source.len() - central_dir_offset)?;
        let central_directory = CentralDirectory::parse(&cd_bytes, 0, eocd.total_entries as usize)
            .map_err(|_| ZipError::ParseError)?;

        Ok(ZipEntry {
            source,
            central_dir_offset,
            central_directory,
        })
    }

    /// Finds the EOCD, scanning 4KB windows backward with a 3-byte overlap so a
    /// signature on a window edge still matches.
    ///
    /// Accepts a candidate only if its comment reaches the exact end of the
    /// stream ([`Self::eocd_spans_to_end`]) — Android's invariant, which ignores
    /// a fake `PK\x05\x06` planted in the archive comment. Falls back to the
    /// rightmost match when none qualifies, so a broken archive still parses.
    fn find_eocd_offset(source: &Source) -> Option<usize> {
        const MAGIC: &[u8; 4] = b"PK\x05\x06";

        let total_len = source.len();
        let mut fallback = None;

        // one reusable window for the whole backward scan
        let mut window = vec![0u8; EOCD_SEARCH_WINDOW];
        let mut end = total_len;
        loop {
            let start = end.saturating_sub(EOCD_SEARCH_WINDOW);
            let len = end - start;
            source.read_exact_at(start, &mut window[..len]).ok()?;

            // Walk candidate signatures in this window from the rightmost.
            let mut upto = len;
            while let Some(pos) = memmem::rfind(&window[..upto], MAGIC) {
                let offset = start + pos;
                if Self::eocd_spans_to_end(source, &window[..len], start, offset, total_len) {
                    return Some(offset);
                }
                // remember the first (rightmost) candidate as a lenient fallback
                fallback.get_or_insert(offset);
                // keep searching strictly earlier in the window
                upto = pos + MAGIC.len() - 1;
            }

            if start == 0 {
                return fallback;
            }

            // step back, overlapping by 3 bytes
            end = start + MAGIC.len() - 1;
        }
    }

    /// Whether an EOCD at `offset`, plus its declared comment, ends exactly at
    /// the stream's end — the mark of the real record over a comment-embedded
    /// decoy. Reads `comment_length` from `window` (already read from
    /// `win_start`), touching the source only when that field crosses the edge.
    fn eocd_spans_to_end(
        source: &Source,
        window: &[u8],
        win_start: usize,
        offset: usize,
        total_len: usize,
    ) -> bool {
        // 22-byte fixed record; comment_length is the u16 at offset + 20
        let Some(fields_end) = offset.checked_add(22) else {
            return false;
        };
        if fields_end > total_len {
            return false;
        }

        let rel = offset - win_start;
        let comment_len = if rel + 22 <= window.len() {
            u16::from_le_bytes([window[rel + 20], window[rel + 21]])
        } else {
            let mut buf = [0u8; 2];
            if source.read_exact_at(offset + 20, &mut buf).is_err() {
                return false;
            }
            u16::from_le_bytes(buf)
        } as usize;

        fields_end + comment_len == total_len
    }

    /// Returns an iterator over the names of all files in the ZIP archive,
    /// in central directory record order.
    ///
    /// The order comes straight from the archive, so repeated parses of the
    /// same file yield the same sequence (unlike hash map iteration, which is
    /// random per process).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use apk_info_zip::ZipEntry;
    /// # let zip_data = std::fs::read("archive.zip").unwrap();
    /// # let zip = ZipEntry::new(zip_data).unwrap();
    /// for filename in zip.namelist() {
    ///     println!("{}", filename);
    /// }
    /// ```
    pub fn namelist(&self) -> impl Iterator<Item = &str> + '_ {
        self.central_directory
            .ordered_names
            .iter()
            .map(|x| x.as_ref())
    }

    /// Returns metadata of `filename` (sizes, compression method, tamper flag)
    /// without reading or decompressing its data.
    ///
    /// The tamper flag mirrors the detection of [`ZipEntry::read`]: the entry is
    /// marked tampered when its local header's compression method disagrees with
    /// the central directory's.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use apk_info_zip::ZipEntry;
    /// # let zip_data = std::fs::read("archive.zip").unwrap();
    /// # let zip = ZipEntry::new(zip_data).unwrap();
    /// let info = zip.entry_info("example.txt").expect("failed to get entry info");
    /// println!("{} bytes, tampered: {}", info.uncompressed_size, info.tampered);
    /// ```
    pub fn entry_info(&self, filename: &str) -> Option<EntryInfo> {
        let entry = self.central_directory.entries.get(filename)?;

        // local header is read lazily; a corrupt claimed offset falls back
        // to the bounded self-healing scan, and an unhealable entry is a miss
        let local_method = self
            .read_local_header_verified(entry)
            .ok()?
            .compression_method;

        Some(EntryInfo {
            compression_method: entry.compression_method,
            compressed_size: entry.compressed_size,
            uncompressed_size: entry.uncompressed_size,
            tampered: local_method != entry.compression_method,
        })
    }

    /// Reads the contents of a file from the ZIP archive.
    ///
    /// This method handles both normally compressed files and tampered files
    /// where the compression metadata may be inconsistent. It returns the
    /// uncompressed file contents along with the detected compression type.
    ///
    /// # Notes
    ///
    /// The method attempts to handle files that have tampered headers:
    /// - If the compression method indicates compression but the compressed
    ///   size equals the uncompressed size, the file is treated as
    ///   [FileCompressionType::StoredTampered].
    /// - If decompression fails but the data is still present, it falls back
    ///   to [FileCompressionType::StoredTampered].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use apk_info_zip::{ZipEntry, ZipError, FileCompressionType};
    /// # let zip_data = std::fs::read("archive.zip").unwrap();
    /// # let zip = ZipEntry::new(zip_data).unwrap();
    /// let (data, compression) = zip.read("example.txt").expect("failed to read file");
    /// match compression {
    ///     FileCompressionType::Stored | FileCompressionType::Deflated => println!("all fine"),
    ///     FileCompressionType::StoredTampered | FileCompressionType::DeflatedTampered => println!("tampering detected"),
    /// }
    /// ```
    pub fn read(&self, filename: &str) -> Result<(Vec<u8>, FileCompressionType), ZipError> {
        let central_directory_entry = self
            .central_directory
            .entries
            .get(filename)
            .ok_or(ZipError::FileNotFound)?;

        // Parse the local file header lazily; a corrupt claimed offset falls
        // back to the bounded self-healing scan.
        let local_header = self.read_local_header_verified(central_directory_entry)?;

        let method = central_directory_entry.compression_method;
        let compressed_size = central_directory_entry.compressed_size as usize;
        let uncompressed_size = central_directory_entry.uncompressed_size as usize;
        let tampered = local_header.compression_method != method;

        if uncompressed_size > MAX_UNCOMPRESSED_SIZE {
            return Err(ZipError::FileTooLarge);
        }

        // data offset is derived from the local header's own lengths
        let offset = local_header.offset + local_header.size();
        // read lengths come from the central directory: local sizes are
        // zeroed under the data-descriptor flag
        let read_data = |len: usize| self.source.read_bytes_at(offset, len);

        match (method, compressed_size == uncompressed_size) {
            (Self::METHOD_STORED, _) => {
                // stored (no compression)
                let data = read_data(uncompressed_size)?;
                let compression = if tampered {
                    FileCompressionType::StoredTampered
                } else {
                    FileCompressionType::Stored
                };
                Ok((data, compression))
            }
            (Self::METHOD_DEFLATED, _) => {
                // deflate default
                let compressed_data = read_data(compressed_size)?;
                let mut uncompressed_data = Vec::with_capacity(uncompressed_size);

                Decompress::new(false)
                    .decompress_vec(
                        &compressed_data,
                        &mut uncompressed_data,
                        FlushDecompress::Finish,
                    )
                    .map_err(|_| ZipError::DecompressionError)?;

                let compression = if tampered {
                    FileCompressionType::DeflatedTampered
                } else {
                    FileCompressionType::Deflated
                };
                Ok((uncompressed_data, compression))
            }
            (_, true) => {
                // unknown method but stored-sized
                let data = read_data(uncompressed_size)?;
                Ok((data, FileCompressionType::StoredTampered))
            }
            (_, false) => {
                // unknown method: try deflate, then fall back to stored
                let compressed_data = read_data(compressed_size)?;
                let mut uncompressed_data = Vec::with_capacity(uncompressed_size);
                let mut decompressor = Decompress::new(false);

                let status = decompressor.decompress_vec(
                    &compressed_data,
                    &mut uncompressed_data,
                    FlushDecompress::Finish,
                );

                // check if decompression was actually successful
                let is_valid = decompressor.total_in() == compressed_data.len() as u64;
                match status {
                    Ok(Status::Ok) | Ok(Status::StreamEnd) if is_valid => {
                        Ok((uncompressed_data, FileCompressionType::DeflatedTampered))
                    }
                    _ => {
                        // fallback to stored tampered
                        let data = read_data(uncompressed_size)?;
                        Ok((data, FileCompressionType::StoredTampered))
                    }
                }
            }
        }
    }

    /// Parses an archive nested inside this one, e.g. the base apk of a
    /// `xapk`/`apkm` container.
    ///
    /// For a stored entry, it reads the inner archive in place through a window
    /// over the same source, so a large inner apk costs one central directory
    /// read. For any other entry, it decompresses the data into memory first
    /// and gets the same bytes as [`ZipEntry::read`].
    ///
    /// # Errors
    ///
    /// Returns a [ZipError] if the entry cannot be read, or the nested data is
    /// not a valid archive (see [`ZipEntry::from_reader`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use apk_info_zip::ZipEntry;
    /// let container = ZipEntry::open("app.apkm").unwrap();
    /// let base = container.open_nested("base.apk").expect("failed to parse inner apk");
    /// ```
    pub fn open_nested(&self, filename: &str) -> Result<ZipEntry, ZipError> {
        let entry = self
            .central_directory
            .entries
            .get(filename)
            .ok_or(ZipError::FileNotFound)?;

        let method = entry.compression_method;
        let size = entry.uncompressed_size as usize;

        let stored = method == Self::METHOD_STORED
            || (method != Self::METHOD_DEFLATED
                && entry.compressed_size == entry.uncompressed_size);
        if !stored || size > MAX_UNCOMPRESSED_SIZE {
            let (data, _) = self.read(filename)?;
            return Self::new(data);
        }

        let local_header = self.read_local_header_verified(entry)?;
        let offset = local_header.offset + local_header.size();
        Self::parse(self.source.slice(offset, size)?)
    }
}

/// Implementation for certificate parsing
///
/// Very cool research about signature blocks: <https://goa2023.nullcon.net/doc/goa-2023/Android-SigMorph-Covert-Communication-Exploiting-Android-Signing-Schemes.pdf>
impl ZipEntry {
    /// Magic of APK signing block
    ///
    /// See: <https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block>
    pub const APK_SIGNATURE_MAGIC: &[u8] = b"APK Sig Block 42";

    /// Magic of V2 Signature Scheme
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/v2/V2SchemeConstants.java#23>
    pub const SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109871a;

    /// Magic of V3 Signature Scheme
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/v3/V3SchemeConstants.java#25>
    pub const SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

    /// Magic of V3.1 Signature Scheme
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/v3/V3SchemeConstants.java#26>
    pub const SIGNATURE_SCHEME_V31_BLOCK_ID: u32 = 0x1b93ad61;

    /// Magic of V3.2 Signature Scheme
    ///
    /// See: <https://xrefandroid.com/android-17.0.0_r1/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/v3/V3SchemeConstants.java#27>
    pub const SIGNATURE_SCHEME_V32_BLOCK_ID: u32 = 0x70e1c89f;

    /// Magic of V1 source stamp signing
    ///
    /// Includes metadata such as timestamp of the build, the version of the build tools, source code's git commit hash, etc
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/stamp/SourceStampConstants.java#23>
    pub const V1_SOURCE_STAMP_BLOCK_ID: u32 = 0x2b09189e;

    /// Magic of V2 source stamp signing
    ///
    /// Includes metadata such as timestamp of the build, the version of the build tools, source code's git commit hash, etc
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/stamp/SourceStampConstants.java#24>
    pub const V2_SOURCE_STAMP_BLOCK_ID: u32 = 0x6dff800d;

    /// Used to increase the size of the signing block (including the length and magic) to a multiple 4096
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java#100>
    pub const VERITY_PADDING_BLOCK_ID: u32 = 0x42726577;

    /// Block that contains dependency metadata, which is saved by the Android Gradle plugin to identify any issues related to dependencies
    ///
    /// This data is compressed, encrypted by a Google Play signing key, so we can't extract it.
    ///
    /// Dependency information for Play Console: <https://developer.android.com/build/dependencies#dependency-info-play>
    ///
    /// See: <https://cs.android.com/android-studio/platform/tools/base/+/mirror-goog-studio-main:signflinger/src/com/android/signflinger/SignedApk.java;l=58?q=0x504b4453>
    pub const DEPENDENCY_INFO_BLOCK_ID: u32 = 0x504b4453;

    /// Used to track channels of distribution for an APK, mostly Chinese APKs have this
    ///
    /// Alsow known as `MEITAN_APK_CHANNEL_BLOCK`
    pub const APK_CHANNEL_BLOCK_ID: u32 = 0x71777777;

    /// ByteDance build config, a JSON object with feature flags, stored next to the Walle channel
    ///
    /// Not documented publicly. Samples (sha256):
    /// - `a1112a0c941f865847c2fab9138cf815735268fbfcd41d697412fb80992c7395` - Toutiao (`com.ss.android.article.news`)
    /// - `4225e058411e61dfbde8310819f7551cbbc95b75d35cec1e1d3c24f718b2ec75` - Toutiao 10.1.2
    pub const BYTEDANCE_BLOCK_ID: u32 = 0x71777776;

    /// ByteDance padding, a few thousand ASCII `1` characters
    ///
    /// Not documented publicly. Samples (sha256):
    /// - `a1112a0c941f865847c2fab9138cf815735268fbfcd41d697412fb80992c7395` - Toutiao (`com.ss.android.article.news`)
    /// - `c400ae7596f5eeaa3e3b942be1f0da0f1fe7835c6cb51618a898c3f09145b840` - Douyin (`com.ss.android.ugc.aweme`)
    pub const BYTEDANCE_PADDING_BLOCK_ID: u32 = 0x71777775;

    /// Google Play Frosting ID
    pub const GOOGLE_PLAY_FROSTING_ID: u32 = 0x2146444e;

    /// Zero block ID
    pub const ZERO_BLOCK_ID: u32 = 0xff3b5998;

    /// The signature of some Chinese packer
    ///
    /// See: <https://github.com/mcxiaoke/packer-ng-plugin/blob/ffbe05a2d27406f3aea574d083cded27f0742160/common/src/main/java/com/mcxiaoke/packer/common/PackerCommon.java#L29>
    pub const PACKER_NG_SIG_V2: u32 = 0x7a786b21;

    /// Some apk protector/parser, idk, seen in the wild
    ///
    /// The channel information in the ID-Value pair
    ///
    /// See: <https://edgeone.ai/document/58005>
    pub const VASDOLLY_V2: u32 = 0x881155ff;

    /// Extracts information from a v1 (APK-style) signature in the ZIP archive.
    ///
    /// Follows apksig `V1SchemeVerifier`: every `META-INF/*.RSA`, `*.DSA` or
    /// `*.EC` signature block that sits directly in `META-INF/` and has a
    /// matching `.SF` file is a signer, other block files are ignored. The
    /// reported certificates are the ones each signer's `SignerInfo` points
    /// to, followed by their issuer chains, merged across signers.
    ///
    /// A malformed signature block is skipped with a warning; the call fails
    /// only if no signature block could be parsed at all.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use apk_info_zip::{ZipEntry, Signature};
    /// # let zip_data = std::fs::read("archive.zip").unwrap();
    /// # let archive = ZipEntry::new(zip_data).unwrap();
    /// match archive.get_signature_v1() {
    ///     Ok(Some(Signature::V1(certs))) => println!("Found {} certificates", certs.len()),
    ///     Ok(Some(_)) => println!("v1 call returned a non-v1 signature"),
    ///     Ok(None) => println!("No v1 signature found"),
    ///     Err(err) => eprintln!("Error parsing signature: {:?}", err),
    /// }
    /// ```
    pub fn get_signature_v1(&self) -> Result<Option<Signature>, CertificateError> {
        let names: AHashSet<&str> = self.namelist().collect();

        let mut certificates: Vec<CertificateInfo> = Vec::new();
        let mut parsed = false;
        let mut failed = false;

        for block in self
            .namelist()
            .filter(|name| Self::is_v1_signature_block(name))
        {
            let stem = &block[..block.rfind('.').unwrap_or(block.len())];
            if !names.contains(format!("{stem}.SF").as_str()) {
                warn!("v1 signature block {block} has no matching .SF file, ignoring it");
                continue;
            }

            let signer = self
                .read(block)
                .map_err(CertificateError::from)
                .and_then(|(data, _)| Self::parse_v1_signature_block(&data));

            match signer {
                Ok(chain) => {
                    parsed = true;
                    for certificate in chain {
                        if !certificates.contains(&certificate) {
                            certificates.push(certificate);
                        }
                    }
                }
                Err(err) => {
                    warn!("skipping malformed v1 signature block {block}: {err}");
                    failed = true;
                }
            }
        }

        match (parsed, failed) {
            (true, _) => Ok(Some(Signature::V1(certificates))),
            (false, true) => Err(CertificateError::ParseError),
            // just apk without signatures
            (false, false) => Ok(None),
        }
    }

    /// `META-INF/<name>.RSA|.DSA|.EC`, without subdirectories.
    fn is_v1_signature_block(name: &str) -> bool {
        name.strip_prefix("META-INF/").is_some_and(|rest| {
            !rest.contains('/')
                && (rest.ends_with(".RSA") || rest.ends_with(".DSA") || rest.ends_with(".EC"))
        })
    }

    /// Returns the signing certificate of a PKCS#7 signature block and its
    /// issuer chain.
    ///
    /// The blob is walked as BER so that every certificate keeps its original
    /// bytes for fingerprints. The certificate comes from the first
    /// `SignerInfo` that resolves to one: a certificate the `SignerInfo` does
    /// not point to is not the signer, even if it comes first in the set.
    fn parse_v1_signature_block(data: &[u8]) -> Result<Vec<CertificateInfo>, CertificateError> {
        // 1.2.840.113549.1.7.2
        const SIGNED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

        let mut input = data;
        let content_info = ber::read(&mut input).ok_or(CertificateError::ParseError)?;
        let fields = ber::children(&content_info).ok_or(CertificateError::ParseError)?;
        let [content_type, content, ..] = fields.as_slice() else {
            return Err(CertificateError::ParseError);
        };
        if content_type.content != SIGNED_DATA_OID || content.tag != [0xa0] {
            return Err(CertificateError::ParseError);
        }

        // SignedData: version, digestAlgorithms, encapContentInfo,
        // certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos
        let signed_data = ber::children(content)
            .and_then(|children| children.into_iter().next())
            .ok_or(CertificateError::ParseError)?;
        let fields = ber::children(&signed_data).ok_or(CertificateError::ParseError)?;

        let certificates: Vec<(Certificate, &[u8])> =
            match fields.iter().skip(3).find(|field| field.tag == [0xa0]) {
                Some(set) => ber::children(set)
                    .ok_or(CertificateError::ParseError)?
                    .into_iter()
                    .filter_map(|tlv| decode_certificate(tlv.raw).map(|cert| (cert, tlv.raw)))
                    .collect(),
                None => Vec::new(),
            };

        let signer_infos = fields
            .iter()
            .skip(3)
            .find(|field| field.tag == [0x31])
            .and_then(ber::children)
            .ok_or(CertificateError::ParseError)?;

        for signer_info in signer_infos {
            let Some(signer_info) =
                ber::to_der(signer_info.raw).and_then(|der| SignerInfo::from_der(&der).ok())
            else {
                continue;
            };
            let SignerIdentifier::IssuerAndSerialNumber(id) = &signer_info.sid else {
                continue;
            };

            let leaf = certificates.iter().position(|(cert, _)| {
                let tbs = cert.tbs_certificate();
                tbs.serial_number() == &id.serial_number && same_name(tbs.issuer(), &id.issuer)
            });

            if let Some(leaf) = leaf {
                return Ok(Self::certificate_chain(&certificates, leaf));
            }
        }

        Err(CertificateError::SignerError)
    }

    /// Builds the chain from `leaf` by following issuers through the
    /// certificate set, like apksig `Certificate.getCertificateChain`.
    fn certificate_chain(
        certificates: &[(Certificate, &[u8])],
        leaf: usize,
    ) -> Vec<CertificateInfo> {
        let mut unused: Vec<usize> = (0..certificates.len()).filter(|&i| i != leaf).collect();
        let mut chain = vec![leaf];
        let mut current = leaf;

        loop {
            let tbs = certificates[current].0.tbs_certificate();
            if same_name(tbs.subject(), tbs.issuer()) {
                break;
            }

            let Some(position) = unused.iter().position(|&i| {
                same_name(certificates[i].0.tbs_certificate().subject(), tbs.issuer())
            }) else {
                break;
            };

            current = unused.remove(position);
            chain.push(current);
        }

        chain
            .into_iter()
            .map(|i| certificate_info(&certificates[i].0, certificates[i].1))
            .collect()
    }

    /// Parses the APK Signature Block and extracts useful information.
    ///
    /// This method checks for the presence of an APK Signature Scheme block
    /// at the end of the ZIP archive and attempts to parse all contained
    /// signatures (v2, v3, etc.).
    ///
    /// Parsing is lenient: an ID-value pair whose value is malformed is
    /// skipped by its declared length, and the blocks after it are still
    /// reported.
    ///
    /// <div class="warning">
    ///
    /// This method handles only v2+ signature blocks.
    ///
    /// v1 signatures are handled separately - [ZipEntry::get_signature_v1].
    ///
    /// </div>
    pub fn get_signatures_other(&self) -> Result<Vec<Signature>, CertificateError> {
        let offset = self.central_dir_offset;

        // The APK Signing Block ends exactly 24 bytes before the central
        // directory: `u64` block size + 16 bytes of magic. Only this bounded
        // region is read out of the source.
        if offset < 24 {
            return Err(CertificateError::ParseError);
        }
        let tail = self
            .source
            .read_bytes_at(offset - 24, 24)
            .map_err(|_| CertificateError::ParseError)?;
        let mut slice: &[u8] = &tail;

        let size_of_block = le_u64::<&[u8], ContextError>
            .parse_next(&mut slice)
            .map_err(|_| CertificateError::ParseError)?;

        let magic = take::<usize, &[u8], ContextError>(16usize)
            .parse_next(&mut slice)
            .map_err(|_| CertificateError::ParseError)?;

        // if the magic does not match, then assume that there is no v2+ block with signatures
        if magic != Self::APK_SIGNATURE_MAGIC {
            return Ok(Vec::new());
        }

        // the block spans [offset - (size_of_block + 8), offset - 24):
        // size of block (full) - 8 bytes (size of block - start) - 24 (end signature)
        let total = size_of_block
            .checked_add(8)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(CertificateError::ParseError)?;

        // does not fit before the central directory, or absurdly large
        // (real signing blocks are at most a few megabytes): treat as absent
        if !(24..=MAX_SIGNING_BLOCK_SIZE).contains(&total) || total > offset {
            return Ok(Vec::new());
        }

        let block = self
            .source
            .read_bytes_at(offset - total, total - 24)
            .map_err(|_| CertificateError::ParseError)?;
        let mut slice: &[u8] = &block;

        let size_of_block_start = le_u64::<&[u8], ContextError>
            .parse_next(&mut slice)
            .map_err(|_| CertificateError::ParseError)?;

        // A block whose own sizes disagree is corrupt: treat it as absent
        // rather than failing the whole signature listing. The v1 JAR
        // signature, if any, is still reported by the caller.
        if size_of_block != size_of_block_start {
            warn!(
                "apk signing block size mismatch: start={size_of_block_start}, end={size_of_block}, treating the block as absent"
            );
            return Ok(Vec::new());
        }

        // Android stops at the first pair it can't read and never sees the
        // pairs after it, so the walk stops there too, with one clear warning
        // instead of a cascade of garbage ids
        if let Some(broken) = Self::find_unreadable_pair(slice) {
            warn!(
                "apk signing block is corrupted: the pair at offset 0x{:x} runs past the end of the block, the pairs from there on are unreachable",
                offset - total + 8 + broken
            );
            slice = &slice[..broken];
        }

        let mut signatures: Vec<Signature> =
            repeat::<&[u8], Option<Signature>, Vec<Option<Signature>>, ContextError, _>(
                0..,
                self.parse_apk_signatures(),
            )
            .parse_next(&mut slice)
            .map_err(|_| CertificateError::ParseError)?
            .into_iter()
            .flatten()
            .collect();

        // schemes go first regardless of the pair order in the block
        signatures.sort_by_key(Signature::order);

        Ok(signatures)
    }

    /// Returns the offset of the first pair whose header or value runs past
    /// the end of `pairs`, like the "size out of range" check of apksig
    /// `ApkSigningBlockUtils.findApkSignatureSchemeBlock`.
    fn find_unreadable_pair(pairs: &[u8]) -> Option<usize> {
        let mut offset = 0;
        while offset < pairs.len() {
            let rest = &pairs[offset..];
            let Some(size) = rest
                .first_chunk::<8>()
                .map(|size| u64::from_le_bytes(*size))
            else {
                return Some(offset);
            };
            // a pair with `size < 4` is still walked as a 12-byte header
            let size = size.max(4);
            if size > (rest.len() - 8) as u64 {
                return Some(offset);
            }
            offset += 8 + size as usize;
        }

        None
    }

    #[allow(unused)]
    fn parse_digest<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            // digest_block_length, signature_algorithm_id, digest_length, digest
            let (_, signature_algorithm_id, digest) =
                (le_u32, le_u32, length_take(le_u32)).parse_next(input)?;

            Ok((signature_algorithm_id, digest))
        }
    }

    fn parse_certificate<'a>() -> impl Parser<&'a [u8], Option<CertificateInfo>, ContextError> {
        move |input: &mut &'a [u8]| {
            let raw = length_take(le_u32).parse_next(input)?;

            let Some(certificate) = decode_certificate(raw) else {
                warn!(
                    "skipping a certificate that is neither DER nor BER (sha256={})",
                    hex(&Sha256::digest(raw))
                );
                return Ok(None);
            };

            Ok(Some(certificate_info(&certificate, raw)))
        }
    }

    #[allow(unused)]
    fn parse_attribute_v2<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let (attribute_length, id) = (le_u32, le_u32).parse_next(input)?;
            let value = take(attribute_length.saturating_sub(4)).parse_next(input)?;

            Ok((id, value))
        }
    }

    #[allow(unused)]
    fn parse_attribute_v3<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let (attribute_length, id) = (le_u32, le_u32).parse_next(input)?;
            let value = take(attribute_length.saturating_sub(4)).parse_next(input)?;
            let _const_id = le_u32.parse_next(input)?;
            // also should be somekind of Proof-of-rotation struct, but skip for now

            Ok((id, value))
        }
    }

    #[allow(unused)]
    fn parse_signature<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            // signature_block_length, signature_algorithm_id, signature_length, signature
            let (_, signature_algorithm_id, signature) =
                (le_u32, le_u32, length_take(le_u32)).parse_next(input)?;

            Ok((signature_algorithm_id, signature))
        }
    }

    fn parse_signer_v2<'a>() -> impl Parser<&'a [u8], Vec<CertificateInfo>, ContextError> {
        move |input: &mut &'a [u8]| {
            // 1 - parse signer
            let mut signer_data = length_take(le_u32).parse_next(input)?;

            // 1.1 - parse signed data
            let mut signed_data = length_take(le_u32).parse_next(&mut signer_data)?;

            // 1.1.1 - parse digests
            let mut _digests_data = length_take(le_u32).parse_next(&mut signed_data)?;
            // uncomment this block if actually need parse digests
            // let digests: Vec<(u32, &[u8])> =
            //     repeat(0.., Self::parse_digest()).parse_next(&mut digests_data)?;

            // 1.1.2 - parse certificates
            let mut certificates_data = length_take(le_u32).parse_next(&mut signed_data)?;
            let certificates: Vec<Option<CertificateInfo>> =
                repeat(0.., Self::parse_certificate()).parse_next(&mut certificates_data)?;

            // 1.1.3 - parse attributes
            let mut _attributes_data = length_take(le_u32).parse_next(&mut signed_data)?;
            // uncomment this block if actually need parse attributes
            // let attributes: Vec<(u32, &[u8])> =
            //     repeat(0.., Self::parse_attribute_v2()).parse_next(&mut attributes_data)?;

            // 1.2 - parse signatures
            let mut _signatures_data = length_take(le_u32).parse_next(&mut signer_data)?;
            // uncomment this block if actually need parse signatures
            // let signatures: Vec<(u32, &[u8])> =
            //     repeat(0.., Self::parse_signature()).parse_next(&mut signatures_data)?;

            // 1.3 - parse public key
            let _public_key = length_take(le_u32).parse_next(&mut signer_data)?;

            Ok(certificates.into_iter().flatten().collect())
        }
    }

    fn parse_signer_v3<'a>() -> impl Parser<&'a [u8], Vec<CertificateInfo>, ContextError> {
        move |input: &mut &'a [u8]| {
            // 1 - parse signer
            let mut signer_data = length_take(le_u32).parse_next(input)?;

            // 1.1 - parse signed data
            let mut signed_data = length_take(le_u32).parse_next(&mut signer_data)?;

            // 1.1.1 - parse digests
            let mut _digests_data = length_take(le_u32).parse_next(&mut signed_data)?;
            // uncomment this block if actually need parse digests
            // let digests: Vec<(u32, &[u8])> =
            //     repeat(0.., Self::parse_digest()).parse_next(&mut digests_data)?;

            // 1.1.2 - parse certificates
            let mut certificates_data = length_take(le_u32).parse_next(&mut signed_data)?;
            let certificates: Vec<Option<CertificateInfo>> =
                repeat(0.., Self::parse_certificate()).parse_next(&mut certificates_data)?;

            // 1.1.3 - parse sdk's
            let (_min_sdk, _max_sdk) = (le_u32, le_u32).parse_next(&mut signed_data)?;

            // 1.1.4 - parse attributes
            let mut _attributes_data = length_take(le_u32).parse_next(&mut signed_data)?;
            // uncomment this block if actually need parse attributes
            // let attributes: Vec<(u32, &[u8])> =
            //     repeat(0.., Self::parse_attribute_v3()).parse_next(&mut attributes_data)?;

            // 1.2 - parse duplicates sdk
            let (_duplicate_min_sdk, _duplicate_max_sdk) =
                (le_u32, le_u32).parse_next(&mut signer_data)?;

            // 1.3 - parse signatures
            let mut _signatures_data = length_take(le_u32).parse_next(&mut signer_data)?;
            // uncomment this block if actually need parse signatures
            // let signatures: Vec<(u32, &[u8])> =
            //     repeat(0.., Self::parse_signature()).parse_next(&mut signatures_data)?;

            // 1.4 - parse public key
            let _public_key = length_take(le_u32).parse_next(&mut signer_data)?;

            Ok(certificates.into_iter().flatten().collect())
        }
    }

    /// Parses one ID-value pair, `None` for a pair that is skipped.
    fn parse_apk_signatures<'a>(&self) -> impl Parser<&'a [u8], Option<Signature>, ContextError> {
        // Android looks a pair up by ID and takes the first match
        // (apksig `ApkSigningBlockUtils.findApkSignatureSchemeBlock`), so a
        // repeated ID is never seen by the platform
        let mut seen = AHashSet::new();

        move |input: &mut &'a [u8]| {
            let (size, id) = (le_u64, le_u32).parse_next(input)?;

            if !seen.insert(id) {
                warn!(
                    "duplicate signing block pair 0x{id:08x} (size=0x{size:08x}), Android uses only the first one, skipping"
                );
                let _ = take::<usize, &[u8], ContextError>(size.saturating_sub(4) as usize)
                    .parse_next(input)?;
                return Ok(None);
            }

            // A malformed pair must not hide the blocks that follow it
            // Skips the pair by its declared length, and continues with the next pair
            let mut value: &'a [u8] = input;
            match Self::parse_signature_pair_value(id, size).parse_next(&mut value) {
                Ok(signature) => {
                    *input = value;
                    Ok(signature)
                }
                Err(_) => {
                    warn!(
                        "malformed signing block pair 0x{id:08x} (size=0x{size:08x}), skipping the pair"
                    );

                    // skip the declared value; a length running past the end
                    // of the block is a hard error and ends the walk
                    let _ = take::<usize, &[u8], ContextError>(size.saturating_sub(4) as usize)
                        .parse_next(input)?;

                    Ok(None)
                }
            }
        }
    }

    /// Parses the value of a single ID-value pair of the APK Signing Block,
    /// `None` for padding and blocks that are not reported.
    fn parse_signature_pair_value<'a>(
        id: u32,
        size: u64,
    ) -> impl Parser<&'a [u8], Option<Signature>, ContextError> {
        move |input: &mut &'a [u8]| {
            let signature = match id {
                Self::SIGNATURE_SCHEME_V2_BLOCK_ID => {
                    let mut signers_data = length_take(le_u32).parse_next(input)?;

                    let certificates =
                        repeat::<_, Vec<CertificateInfo>, Vec<Vec<CertificateInfo>>, _, _>(
                            1..,
                            Self::parse_signer_v2(),
                        )
                        .parse_next(&mut signers_data)?
                        .into_iter()
                        .flatten()
                        .collect();

                    Ok(Signature::V2(certificates))
                }
                Self::SIGNATURE_SCHEME_V3_BLOCK_ID => {
                    let mut signers_data = length_take(le_u32).parse_next(input)?;

                    let certificates =
                        repeat::<_, Vec<CertificateInfo>, Vec<Vec<CertificateInfo>>, _, _>(
                            1..,
                            Self::parse_signer_v3(),
                        )
                        .parse_next(&mut signers_data)?
                        .into_iter()
                        .flatten()
                        .collect();

                    Ok(Signature::V3(certificates))
                }
                Self::SIGNATURE_SCHEME_V31_BLOCK_ID => {
                    let mut signers_data = length_take(le_u32).parse_next(input)?;

                    let certificates =
                        repeat::<_, Vec<CertificateInfo>, Vec<Vec<CertificateInfo>>, _, _>(
                            1..,
                            Self::parse_signer_v3(),
                        )
                        .parse_next(&mut signers_data)?
                        .into_iter()
                        .flatten()
                        .collect();

                    Ok(Signature::V31(certificates))
                }
                Self::SIGNATURE_SCHEME_V32_BLOCK_ID => {
                    let mut signers_data = length_take(le_u32).parse_next(input)?;

                    let certificates =
                        repeat::<_, Vec<CertificateInfo>, Vec<Vec<CertificateInfo>>, _, _>(
                            1..,
                            Self::parse_signer_v3(),
                        )
                        .parse_next(&mut signers_data)?
                        .into_iter()
                        .flatten()
                        .collect();

                    Ok(Signature::V32(certificates))
                }
                Self::APK_CHANNEL_BLOCK_ID => {
                    let data = take(size.saturating_sub(4) as usize).parse_next(input)?;

                    Ok(Signature::ApkChannelBlock(
                        String::from_utf8_lossy(data).trim().to_string(),
                    ))
                }
                Self::V1_SOURCE_STAMP_BLOCK_ID => {
                    // https://cs.android.com/android/platform/superproject/main/+/main:tools/apksig/src/main/java/com/android/apksig/internal/apk/stamp/V1SourceStampSigner.java;l=86;bpv=0;bpt=1
                    let _stamp_block_prefix = le_u32.parse_next(input)?;

                    let certificate = Self::parse_certificate().parse_next(input)?;

                    // i don't think that it is useful information
                    let _signed_data = length_take(le_u32).parse_next(input)?;

                    certificate
                        .map(Signature::StampBlockV1)
                        .ok_or_else(ContextError::new)
                }
                Self::V2_SOURCE_STAMP_BLOCK_ID => {
                    // https://cs.android.com/android/platform/superproject/main/+/main:tools/apksig/src/main/java/com/android/apksig/internal/apk/stamp/V2SourceStampSigner.java;l=124;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=0;bpt=1

                    let _stamp_block_prefix = le_u32.parse_next(input)?;
                    let certificate = Self::parse_certificate().parse_next(input)?;

                    // i don't think that it is useful information
                    let _signed_digests_data = length_take(le_u32).parse_next(input)?;

                    // i don't think that it is useful information
                    let _encoded_stamp_attributes = length_take(le_u32).parse_next(input)?;

                    // i don't think that it is useful information
                    let _signed_attributes = length_take(le_u32).parse_next(input)?;

                    certificate
                        .map(Signature::StampBlockV2)
                        .ok_or_else(ContextError::new)
                }
                Self::PACKER_NG_SIG_V2 => {
                    let data = take(size.saturating_sub(4) as usize).parse_next(input)?;

                    Ok(Signature::PackerNextGenV2(data.to_vec()))
                }
                Self::GOOGLE_PLAY_FROSTING_ID => {
                    let _ = take(size.saturating_sub(4) as usize).parse_next(input)?;
                    Ok(Signature::GooglePlayFrosting)
                }
                Self::VASDOLLY_V2 => {
                    let data = take(size.saturating_sub(4) as usize).parse_next(input)?;
                    Ok(Signature::VasDollyV2(
                        String::from_utf8_lossy(data).trim().to_owned(),
                    ))
                }
                Self::BYTEDANCE_BLOCK_ID => {
                    let data = take(size.saturating_sub(4) as usize).parse_next(input)?;
                    Ok(Signature::ByteDance(
                        String::from_utf8_lossy(data).trim().to_owned(),
                    ))
                }
                Self::VERITY_PADDING_BLOCK_ID
                | Self::DEPENDENCY_INFO_BLOCK_ID
                | Self::ZERO_BLOCK_ID
                | Self::BYTEDANCE_PADDING_BLOCK_ID => {
                    // not interesting blocks
                    let _ = take(size.saturating_sub(4) as usize).parse_next(input)?;
                    return Ok(None);
                }
                // no block uses a zero id, it shows up when the pairs lost alignment
                0 => {
                    warn!(
                        "signing block pair with a zero id (size=0x{size:08x}), the block is likely misaligned"
                    );

                    let _ = take(size.saturating_sub(4) as usize).parse_next(input)?;

                    return Ok(None);
                }
                _ => {
                    // highlight new interesting blocks
                    warn!(
                        "got unknown id block - 0x{:08x} (size=0x{:08x}), please open issue on github, let's try to figure out",
                        id, size
                    );

                    let _ = take(size.saturating_sub(4) as usize).parse_next(input)?;

                    return Ok(None);
                }
            };

            signature.map(Some)
        }
    }
}

impl From<Certificate> for CertificateInfo {
    fn from(value: Certificate) -> Self {
        let encoded = value.to_der().unwrap_or_default();
        certificate_info(&value, &encoded)
    }
}

/// Builds the certificate summary, with fingerprints over `raw`, the bytes
/// the certificate was stored as.
///
/// Android identifies a signer by the original encoding, which differs from
/// a DER re-encoding when the certificate is BER.
fn certificate_info(certificate: &Certificate, raw: &[u8]) -> CertificateInfo {
    let cert = certificate.tbs_certificate();

    CertificateInfo {
        serial_number: hex(cert.serial_number().as_bytes()),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        valid_from: cert.validity().not_before.to_string(),
        valid_until: cert.validity().not_after.to_string(),
        signature_type: DB
            .by_oid(&cert.signature().oid)
            .unwrap_or_default()
            .to_string(),
        md5_fingerprint: hex(&Md5::digest(raw)),
        sha1_fingerprint: hex(&Sha1::digest(raw)),
        sha256_fingerprint: hex(&Sha256::digest(raw)),
    }
}

/// Compares distinguished names the way Java's `X500Principal.equals` does,
/// ignoring the string type and case: a `SignerInfo` may spell the issuer as
/// `PrintableString` while the certificate uses `UTF8String`.
fn same_name(a: &Name, b: &Name) -> bool {
    a == b || a.to_string().to_lowercase() == b.to_string().to_lowercase()
}

/// Parses a certificate as strict DER, falling back to BER like Android does.
fn decode_certificate(raw: &[u8]) -> Option<Certificate> {
    Certificate::from_der(raw)
        .ok()
        .or_else(|| Certificate::from_der(&ber::to_der(raw)?).ok())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, x| {
        _ = write!(out, "{x:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};

    use ahash::AHashMap;

    use super::*;

    /// Builds a minimal, well-formed two-file STORED zip archive and returns it
    /// together with the byte position of each central directory entry's
    /// `local_header_offset` field (so tests can corrupt it).
    fn build_archive(entries: &[(&str, &[u8])]) -> (Vec<u8>, AHashMap<String, usize>) {
        build_archive_gap(entries, 0)
    }

    /// Like [`build_archive`], but inserts `gap` filler bytes between the CD and
    /// the EOCD (e.g. a ZIP64 EOCD record), so the declared `cd_offset` no
    /// longer equals `eocd_offset - cd_size`.
    fn build_archive_gap(
        entries: &[(&str, &[u8])],
        gap: usize,
    ) -> (Vec<u8>, AHashMap<String, usize>) {
        let mut data = Vec::new();

        struct Meta {
            name: String,
            local_header_offset: u32,
            size: u32,
            cd_off_field: usize,
        }
        let mut metas = Vec::new();

        // local file headers + raw (stored) data
        for (name, content) in entries {
            let size = content.len() as u32;
            let lho = data.len() as u32;
            data.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            data.extend_from_slice(&20u16.to_le_bytes()); // version needed
            data.extend_from_slice(&0u16.to_le_bytes()); // flags
            data.extend_from_slice(&0u16.to_le_bytes()); // method = stored
            data.extend_from_slice(&0u16.to_le_bytes()); // mod time
            data.extend_from_slice(&0u16.to_le_bytes()); // mod date
            data.extend_from_slice(&0u32.to_le_bytes()); // crc (not verified)
            data.extend_from_slice(&size.to_le_bytes());
            data.extend_from_slice(&size.to_le_bytes());
            data.extend_from_slice(&(name.len() as u16).to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes()); // extra len
            data.extend_from_slice(name.as_bytes());
            data.extend_from_slice(content);
            metas.push(Meta {
                name: name.to_string(),
                local_header_offset: lho,
                size,
                cd_off_field: 0,
            });
        }

        // central directory
        let cd_start = data.len() as u32;
        for m in &mut metas {
            data.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            data.extend_from_slice(&20u16.to_le_bytes()); // version made by
            data.extend_from_slice(&20u16.to_le_bytes()); // version needed
            data.extend_from_slice(&0u16.to_le_bytes()); // flags
            data.extend_from_slice(&0u16.to_le_bytes()); // method
            data.extend_from_slice(&0u16.to_le_bytes()); // mod time
            data.extend_from_slice(&0u16.to_le_bytes()); // mod date
            data.extend_from_slice(&0u32.to_le_bytes()); // crc
            data.extend_from_slice(&m.size.to_le_bytes());
            data.extend_from_slice(&m.size.to_le_bytes());
            data.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes()); // extra len
            data.extend_from_slice(&0u16.to_le_bytes()); // comment len
            data.extend_from_slice(&0u16.to_le_bytes()); // disk number
            data.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            data.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            m.cd_off_field = data.len();
            data.extend_from_slice(&m.local_header_offset.to_le_bytes());
            data.extend_from_slice(m.name.as_bytes());
        }
        let cd_size = data.len() as u32 - cd_start;

        // bytes between the central directory and the EOCD (not counted in cd_size)
        data.extend(std::iter::repeat_n(0, gap));

        // EOCD
        data.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // disk number
        data.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&cd_size.to_le_bytes());
        data.extend_from_slice(&cd_start.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // comment len

        let mut fields = AHashMap::new();
        for m in metas {
            fields.insert(m.name, m.cd_off_field);
        }
        (data, fields)
    }

    fn corrupt_offset(data: &mut [u8], field: usize, value: u32) {
        data[field..field + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn cd_offset_declared_wins_over_derived_when_gap_present() {
        // ZIP64 record between CD and EOCD: the declared cd_offset points at the
        // real CD, while `eocd_offset - cd_size` lands `gap` bytes too late.
        let (data, _) = build_archive_gap(&[("a.txt", b"a"), ("b.txt", b"bb")], 76);

        let zip = ZipEntry::new(data).unwrap();
        assert_eq!(zip.namelist().count(), 2);
        assert_eq!(zip.read("a.txt").unwrap().0, b"a");
        assert_eq!(zip.read("b.txt").unwrap().0, b"bb");
    }

    #[test]
    fn namelist_follows_central_directory_order() {
        let entries: Vec<(&str, &[u8])> = ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"]
            .iter()
            .map(|n| (*n, n.as_bytes()))
            .collect();
        let (data, _) = build_archive(&entries);

        // two independent parses: hash map iteration is random per instance, so
        // both matching the archive order proves the names come from the CD records
        let zip1 = ZipEntry::new(data.clone()).unwrap();
        let zip2 = ZipEntry::new(data).unwrap();
        let expected = vec!["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"];
        assert_eq!(zip1.namelist().collect::<Vec<_>>(), expected);
        assert_eq!(zip2.namelist().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn read_works_on_healthy_archive() {
        let (data, _) = build_archive(&[("a.txt", b"hello"), ("b.txt", b"world!")]);
        let zip = ZipEntry::new(data).unwrap();
        assert_eq!(zip.read("a.txt").unwrap().0, b"hello");
        assert_eq!(zip.read("b.txt").unwrap().0, b"world!");
    }

    #[test]
    fn read_heals_shifted_local_header_offset() {
        let (mut data, fields) = build_archive(&[("a.txt", b"AAA"), ("b.txt", b"BBBBBBBB")]);
        // Corrupt b's local_header_offset: claim it is 40 bytes after reality.
        let orig = u32::from_le_bytes(
            data[fields["b.txt"]..fields["b.txt"] + 4]
                .try_into()
                .unwrap(),
        );
        corrupt_offset(&mut data, fields["b.txt"], orig + 40);

        let zip = ZipEntry::new(data).unwrap();
        // b.txt's local header is not in the fast index, so read must lazily heal it.
        assert_eq!(zip.read("b.txt").unwrap().0, b"BBBBBBBB");
        // The untouched entry still reads normally.
        assert_eq!(zip.read("a.txt").unwrap().0, b"AAA");
    }

    #[test]
    fn read_rejects_wrong_filename_during_recovery() {
        // Point b's claim at a.txt's local header. The exact-offset attempt finds
        // a.txt's header but its filename does not match, so recovery must keep
        // scanning until it reaches b.txt's own (matching) header.
        let (mut data, fields) = build_archive(&[("a.txt", b"AAA"), ("b.txt", b"BBBB")]);
        let a_claim = u32::from_le_bytes(
            data[fields["a.txt"]..fields["a.txt"] + 4]
                .try_into()
                .unwrap(),
        );
        corrupt_offset(&mut data, fields["b.txt"], a_claim);

        let zip = ZipEntry::new(data).unwrap();
        assert_eq!(zip.read("b.txt").unwrap().0, b"BBBB");
    }

    #[test]
    fn unhealable_offset_is_not_found() {
        let (mut data, fields) = build_archive(&[("a.txt", b"AAAAAAA"), ("b.txt", b"BBBBBB")]);
        // Corrupt b's claim to a huge offset well away from any local header, so
        // the bounded scan cannot reach it and read must report FileNotFound.
        corrupt_offset(&mut data, fields["b.txt"], u32::MAX - 100);

        let zip = ZipEntry::new(data).unwrap();
        assert_eq!(zip.read("b.txt").unwrap_err(), ZipError::FileNotFound);
        // a.txt (healthy) still reads.
        assert_eq!(zip.read("a.txt").unwrap().0, b"AAAAAAA");
    }

    #[test]
    fn read_missing_file_is_not_found() {
        let (data, _) = build_archive(&[("a.txt", b"hello")]);
        let zip = ZipEntry::new(data).unwrap();
        assert_eq!(zip.read("nope.txt").unwrap_err(), ZipError::FileNotFound);
    }
    /// A `ReadSeek` wrapper that counts how many bytes were actually read from
    /// the source, to prove that parsing stays lazy.
    struct CountingSource {
        inner: Cursor<Vec<u8>>,
        counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingSource {
        fn new(data: Vec<u8>) -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            use std::sync::atomic::AtomicUsize;
            let counter = std::sync::Arc::new(AtomicUsize::new(0));
            (
                Self {
                    inner: Cursor::new(data),
                    counter: std::sync::Arc::clone(&counter),
                },
                counter,
            )
        }
    }

    impl Read for CountingSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.counter
                .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
    }

    impl Seek for CountingSource {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// Opening an archive must read only the EOCD + central directory, never
    /// the entry payloads, no matter how big they are.
    #[test]
    fn construction_reads_only_metadata() {
        // a 1MB stored entry: if the whole file were read, the counter would
        // blow past the archive size
        let big = vec![0x41u8; 1024 * 1024];
        let (data, _) = build_archive(&[("big.bin", &big), ("small.txt", b"hi")]);

        let (source, counter) = CountingSource::new(data.clone());
        let zip = ZipEntry::from_reader(source).unwrap();

        // archive is ~1MB, but only the tail metadata (EOCD + CD + sanity
        // probes) may be read
        assert!(
            counter.load(std::sync::atomic::Ordering::Relaxed) < 32 * 1024,
            "construction read {} bytes, not lazy",
            counter.load(std::sync::atomic::Ordering::Relaxed)
        );
        assert_eq!(zip.namelist().count(), 2);

        // reading an entry pulls roughly its own size, not the whole archive
        let before = counter.load(std::sync::atomic::Ordering::Relaxed);
        let (data, compression) = zip.read("big.bin").unwrap();
        assert_eq!(data.len(), 1024 * 1024);
        assert_eq!(compression, FileCompressionType::Stored);
        assert!(
            counter.load(std::sync::atomic::Ordering::Relaxed) - before <= 1024 * 1024 + 512,
            "entry read pulled way more than the entry itself"
        );
    }

    /// `ZipEntry::open` reads a real file from disk through the same lazy path.
    #[test]
    fn open_reads_archive_from_file() {
        let (data, _) = build_archive(&[("a.txt", b"hello"), ("b.txt", b"world!")]);

        let path =
            std::env::temp_dir().join(format!("apk-info-lazy-test-{}.zip", std::process::id()));
        std::fs::write(&path, &data).expect("can't write temp archive");

        let zip = ZipEntry::open(&path).unwrap();
        assert_eq!(zip.read("a.txt").unwrap().0, b"hello");
        assert_eq!(zip.read("b.txt").unwrap().0, b"world!");

        std::fs::remove_file(&path).ok();
    }

    /// An EOCD hidden behind a comment long enough to straddle the search
    /// window boundary (4096) must still be found: adjacent windows overlap by
    /// `MAGIC.len() - 1` bytes precisely for this case.
    #[test]
    fn eocd_straddling_search_window_is_found() {
        let (data, _) = build_archive(&[("a.txt", b"hello")]);

        // rebuild the EOCD with a comment sized so the EOCD signature starts
        // exactly 2 bytes before the first 4096-byte window boundary:
        // comment length 4076 => magic at len - (22 + 4076) = len - 4098
        let mut data = data;
        let eocd: Vec<u8> = data.split_off(data.len() - 22);
        let comment = vec![0xCC; 4076];

        let mut patched = eocd;
        patched[20..22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        patched.extend_from_slice(&comment);
        data.extend_from_slice(&patched);

        let zip = ZipEntry::new(data).unwrap();
        assert_eq!(zip.read("a.txt").unwrap().0, b"hello");
    }

    /// A long comment that pushes the EOCD a full window back is found too
    /// (several backward window reads).
    #[test]
    fn eocd_with_multiview_comment_is_found() {
        let (data, _) = build_archive(&[("a.txt", b"hello")]);

        let mut data = data;
        let eocd: Vec<u8> = data.split_off(data.len() - 22);
        let comment = vec![0xAB; 8192];

        let mut patched = eocd;
        patched[20..22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        patched.extend_from_slice(&comment);
        data.extend_from_slice(&patched);

        let zip = ZipEntry::new(data).unwrap();
        assert_eq!(zip.read("a.txt").unwrap().0, b"hello");
    }
}
