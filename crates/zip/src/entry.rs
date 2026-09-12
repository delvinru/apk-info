//! Describes a `zip` archive

use std::fmt::Write;
use std::io::Cursor;
use std::path::Path;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
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

use crate::signature::{CertificateInfo, Signature};
use crate::source::Source;
use crate::structs::{
    CentralDirectory, CentralDirectoryEntry, EndOfCentralDirectory, LocalFileHeader,
};
use crate::{CertificateError, FileCompressionType, ReadSeek, ZipError};

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
    /// Compression method declared in the central directory (`0` = stored, `8` = deflate)
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

        // Read the central directory to the end of the stream: `central_dir_size`
        // may understate the real record area in a tampered archive, and the
        // parser stops at the first non-CDH magic anyway.
        let cd_bytes =
            source.read_bytes_at(central_dir_offset, source.len() - central_dir_offset)?;
        let central_directory =
            CentralDirectory::parse(&cd_bytes, 0).map_err(|_| ZipError::ParseError)?;

        Ok(ZipEntry {
            source,
            central_dir_offset,
            central_directory,
        })
    }

    /// Searches backwards from the end of the stream for the EOCD signature.
    ///
    /// Reads 4KB windows instead of the whole tail. Adjacent windows overlap
    /// by 3 bytes so a signature straddling a window edge is not missed.
    fn find_eocd_offset(source: &Source) -> Option<usize> {
        const MAGIC: &[u8; 4] = b"PK\x05\x06";

        // one reusable window for the whole backward scan
        let mut window = vec![0u8; EOCD_SEARCH_WINDOW];
        let mut end = source.len();
        loop {
            let start = end.saturating_sub(EOCD_SEARCH_WINDOW);
            let len = end - start;
            source.read_exact_at(start, &mut window[..len]).ok()?;

            if let Some(pos) = memmem::rfind(&window[..len], MAGIC) {
                return Some(start + pos);
            }

            if start == 0 {
                return None;
            }

            // step back, overlapping by 3 bytes
            end = start + MAGIC.len() - 1;
        }
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
            (0, _) => {
                // stored (no compression)
                let data = read_data(uncompressed_size)?;
                let compression = if tampered {
                    FileCompressionType::StoredTampered
                } else {
                    FileCompressionType::Stored
                };
                Ok((data, compression))
            }
            (8, _) => {
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
    /// This method searches for signature files in the `META-INF/` directory
    /// with extensions `.DSA`, `.EC`, or `.RSA`, reads the PKCS#7 data,
    /// and returns the associated certificates.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use apk_info_zip::{ZipEntry, Signature};
    /// # let zip_data = std::fs::read("archive.zip").unwrap();
    /// # let archive = ZipEntry::new(zip_data).unwrap();
    /// match archive.get_signature_v1() {
    ///     Ok(Signature::V1(certs)) => println!("Found {} certificates", certs.len()),
    ///     Ok(Signature::Unknown) => println!("No v1 signature found"),
    ///     Ok(_) => println!("v1 call returned a non-v1 signature"),
    ///     Err(err) => eprintln!("Error parsing signature: {:?}", err),
    /// }
    /// ```
    pub fn get_signature_v1(&self) -> Result<Signature, CertificateError> {
        let signature_file = match self.namelist().find(|name| {
            name.starts_with("META-INF/")
                && (name.ends_with(".DSA") || name.ends_with(".EC") || name.ends_with(".RSA"))
        }) {
            Some(v) => v,
            // just apk without signatures
            None => return Ok(Signature::Unknown),
        };

        let (data, _) = self
            .read(signature_file)
            .map_err(|_| CertificateError::ParseError)?;

        let info = ContentInfo::from_der(&data).map_err(|_| CertificateError::ParseError)?;
        let content = info
            .content
            .to_der()
            .map_err(|_| CertificateError::ParseError)?;

        let signed_data =
            SignedData::from_der(&content).map_err(|_| CertificateError::ParseError)?;

        let certs = signed_data
            .certificates
            .ok_or(CertificateError::ParseError)?
            .0
            .into_vec()
            .into_iter()
            .filter_map(|cert| {
                if let CertificateChoices::Certificate(cert) = cert {
                    Some(cert.into())
                } else {
                    None
                }
            })
            .collect();

        Ok(Signature::V1(certs))
    }

    /// Parses the APK Signature Block and extracts useful information.
    ///
    /// This method checks for the presence of an APK Signature Scheme block
    /// at the end of the ZIP archive and attempts to parse all contained
    /// signatures (v2, v3, etc.).
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

        if size_of_block != size_of_block_start {
            return Err(CertificateError::InvalidFormat(
                size_of_block_start,
                size_of_block,
            ));
        }

        let signatures: Vec<Signature> =
            repeat::<&[u8], Signature, Vec<Signature>, ContextError, _>(
                0..,
                self.parse_apk_signatures(),
            )
            .parse_next(&mut slice)
            .map_err(|_| CertificateError::ParseError)?
            .into_iter()
            .filter(|signature| signature != &Signature::Unknown)
            .collect();

        Ok(signatures)
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
            let certificate = length_take(le_u32).parse_next(input)?;

            Ok(Certificate::from_der(certificate).ok().map(Into::into))
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

    fn parse_apk_signatures<'a>(&self) -> impl Parser<&'a [u8], Signature, ContextError> {
        move |input: &mut &'a [u8]| {
            let (size, id) = (le_u64, le_u32).parse_next(input)?;

            match id {
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
                Self::VERITY_PADDING_BLOCK_ID
                | Self::DEPENDENCY_INFO_BLOCK_ID
                | Self::ZERO_BLOCK_ID => {
                    // not interesting blocks
                    let _ = take(size.saturating_sub(4) as usize).parse_next(input)?;
                    Ok(Signature::Unknown)
                }
                _ => {
                    // highlight new interesting blocks
                    warn!(
                        "got unknown id block - 0x{:08x} (size=0x{:08x}), please open issue on github, let's try to figure out",
                        id, size
                    );

                    let _ = take(size.saturating_sub(4) as usize).parse_next(input)?;

                    Ok(Signature::Unknown)
                }
            }
        }
    }
}

impl From<Certificate> for CertificateInfo {
    fn from(value: Certificate) -> Self {
        let mut cert_data = Vec::new();
        _ = value.encode_to_vec(&mut cert_data);
        let cert = value.tbs_certificate();

        CertificateInfo {
            serial_number: cert.serial_number().as_bytes().iter().fold(
                String::new(),
                |mut out, x| {
                    _ = write!(out, "{x:02x}");
                    out
                },
            ),
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            valid_from: cert.validity().not_before.to_string(),
            valid_until: cert.validity().not_after.to_string(),
            signature_type: DB
                .by_oid(&cert.signature().oid)
                .unwrap_or_default()
                .to_string(),
            md5_fingerprint: Md5::digest(&cert_data)
                .iter()
                .fold(String::new(), |mut out, x| {
                    _ = write!(out, "{x:02x}");
                    out
                }),
            sha1_fingerprint: Sha1::digest(&cert_data)
                .iter()
                .fold(String::new(), |mut out, x| {
                    _ = write!(out, "{x:02x}");
                    out
                }),
            sha256_fingerprint: Sha256::digest(&cert_data).iter().fold(
                String::new(),
                |mut out, x| {
                    _ = write!(out, "{x:02x}");
                    out
                },
            ),
        }
    }
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
