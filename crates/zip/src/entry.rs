//! Describes a `zip` archive

use std::fmt::Write;
use std::sync::Arc;

use ahash::AHashMap;
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
use crate::structs::{CentralDirectory, EndOfCentralDirectory, LocalFileHeader};
use crate::{CertificateError, FileCompressionType, ZipError};

/// Maximum allowed uncompressed size for a file entry.
const MAX_UNCOMPRESSED_SIZE: usize = u32::MAX as usize;

/// Caps the self-healing forward scan so a corrupt archive can't degrade to a quadratic scan.
const SELF_HEAL_MAX_SCAN: usize = 1 << 20;

/// How far back from a claimed offset to search; corrupt offsets shift by a few bytes.
const SELF_HEAL_BACKWARD: usize = 1 << 16;

/// Represents a parsed ZIP archive.
#[derive(Debug)]
pub struct ZipEntry {
    /// Owned zip data
    input: Vec<u8>,

    /// Absolute offset of the central directory.
    central_dir_offset: usize,

    /// Central directory structure
    central_directory: CentralDirectory,

    /// Information about local headers
    local_headers: AHashMap<Arc<str>, LocalFileHeader>,
}

/// Implementation of basic methods
impl ZipEntry {
    /// Recovers the real local file header offset for an entry whose
    /// `local_header_offset` is corrupt: tries the claim, then scans a bounded,
    /// filename-verified window for a matching `PK\x03\x04`.
    fn find_local_header_offset(&self, claim: usize, expected_name: &[u8]) -> Option<usize> {
        let input = &self.input;
        let central_dir_offset = self.central_dir_offset;

        // 1. exact claimed offset
        if let Ok(header) = LocalFileHeader::parse(input, claim)
            && header.file_name.as_ref() == expected_name
        {
            return Some(claim);
        }

        // 2. bounded scan for a matching local header, verified by filename.
        let start = claim.saturating_sub(SELF_HEAL_BACKWARD);
        let end = input
            .len()
            .min(central_dir_offset)
            .min(claim.saturating_add(SELF_HEAL_MAX_SCAN));
        let mut pos = start;
        while pos < end {
            match memmem::find(&input[pos..end], b"PK\x03\x04") {
                Some(rel) => {
                    let candidate = pos + rel;
                    if candidate == claim {
                        // same offset as the failed first attempt; move on
                        pos = candidate + 1;
                        continue;
                    }
                    if let Ok(header) = LocalFileHeader::parse(input, candidate)
                        && header.file_name.as_ref() == expected_name
                    {
                        return Some(candidate);
                    }
                    pos = candidate + 1;
                }
                None => break,
            }
        }
        None
    }

    /// Creates a new `ZipEntry` from raw ZIP data.
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
    /// ```
    /// # use apk_info_zip::{ZipEntry, ZipError};
    /// let data = std::fs::read("archive.zip").unwrap();
    /// let zip = ZipEntry::new(data).expect("failed to parse ZIP archive");
    /// ```
    pub fn new(input: Vec<u8>) -> Result<ZipEntry, ZipError> {
        // perform basic sanity check
        if !input.starts_with(b"PK\x03\x04") {
            return Err(ZipError::InvalidHeader);
        }

        let eocd_offset =
            EndOfCentralDirectory::find_eocd(&input, 4096).ok_or(ZipError::NotFoundEOCD)?;

        let eocd = EndOfCentralDirectory::parse(&mut &input[eocd_offset..])
            .map_err(|_| ZipError::ParseError)?;

        // Prefer the EOCD's declared CD offset;
        // derive it (`eocd - cd_size`) only when prepended/polyglot data left it stale.
        let declared = eocd.central_dir_offset as usize;
        let derived = eocd_offset
            .checked_sub(eocd.central_dir_size as usize)
            .ok_or(ZipError::ParseError)?;

        let central_dir_offset = if input
            .get(declared..)
            .is_some_and(|s| s.starts_with(b"PK\x01\x02"))
        {
            declared
        } else {
            derived
        };

        let central_directory = CentralDirectory::parse(&input, central_dir_offset)
            .map_err(|_| ZipError::ParseError)?;

        let local_headers = central_directory
            .entries
            .iter()
            .filter_map(|(filename, entry)| {
                let header =
                    LocalFileHeader::parse(&input, entry.local_header_offset as usize).ok()?;
                (header.file_name.as_ref() == entry.file_name.as_bytes())
                    .then(|| (Arc::clone(filename), header))
            })
            .collect();

        Ok(ZipEntry {
            input,
            central_dir_offset,
            central_directory,
            local_headers,
        })
    }

    /// Returns an iterator over the names of all files in the ZIP archive.
    ///
    /// # Examples
    ///
    /// ```
    /// # use apk_info_zip::ZipEntry;
    /// # let zip_data = std::fs::read("archive.zip").unwrap();
    /// # let zip = ZipEntry::new(zip_data).unwrap();
    /// for filename in zip.namelist() {
    ///     println!("{}", filename);
    /// }
    /// ```
    pub fn namelist(&self) -> impl Iterator<Item = &str> + '_ {
        self.central_directory.entries.keys().map(|x| x.as_ref())
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
    /// ```rust
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

        // Index miss = corrupt claim; lazily recover this one entry.
        let local_header = match self.local_headers.get(filename) {
            Some(header) => header.clone(),
            None => {
                let offset = self
                    .find_local_header_offset(
                        central_directory_entry.local_header_offset as usize,
                        central_directory_entry.file_name.as_bytes(),
                    )
                    .ok_or(ZipError::FileNotFound)?;
                LocalFileHeader::parse(&self.input, offset).map_err(|_| ZipError::FileNotFound)?
            }
        };

        let method = central_directory_entry.compression_method;
        let compressed_size = central_directory_entry.compressed_size as usize;
        let uncompressed_size = central_directory_entry.uncompressed_size as usize;
        let tampered = local_header.compression_method != method;

        if uncompressed_size > MAX_UNCOMPRESSED_SIZE {
            return Err(ZipError::FileTooLarge);
        }

        let offset = local_header.offset + local_header.size();
        let get_slice = |start: usize, end: usize| self.input.get(start..end).ok_or(ZipError::EOF);

        match (method, compressed_size == uncompressed_size) {
            (0, _) => {
                // stored (no compression)
                let slice = get_slice(offset, offset + uncompressed_size)?;
                let compression = if tampered {
                    FileCompressionType::StoredTampered
                } else {
                    FileCompressionType::Stored
                };
                Ok((slice.to_vec(), compression))
            }
            (8, _) => {
                // deflate default
                let compressed_data = get_slice(offset, offset + compressed_size)?;
                let mut uncompressed_data = Vec::with_capacity(uncompressed_size);

                Decompress::new(false)
                    .decompress_vec(
                        compressed_data,
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
                let slice = get_slice(offset, offset + uncompressed_size)?;
                Ok((slice.to_vec(), FileCompressionType::StoredTampered))
            }
            (_, false) => {
                // unknown method: try deflate, then fall back to stored
                let compressed_data = get_slice(offset, offset + compressed_size)?;
                let mut uncompressed_data = Vec::with_capacity(uncompressed_size);
                let mut decompressor = Decompress::new(false);

                let status = decompressor.decompress_vec(
                    compressed_data,
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
                        let slice = get_slice(offset, offset + uncompressed_size)?;
                        Ok((slice.to_vec(), FileCompressionType::StoredTampered))
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
    /// ```
    /// # use apk_info_zip::{ZipEntry, Signature};
    /// # let archive = ZipEntry::new(zip_data).unwrap();
    /// match archive.get_signature_v1() {
    ///     Ok(Signature::V1(certs)) => println!("Found {} certificates", certs.len()),
    ///     Ok(Signature::Unknown) => println!("No v1 signature found"),
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
        let mut slice = match self.input.get(offset.saturating_sub(24)..offset) {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };

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

        // size of block (full) - 8 bytes (size of block - start) - 24 (end signature)
        slice = match self
            .input
            .get(offset.saturating_sub((size_of_block + 8) as usize)..offset.saturating_sub(24))
        {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };

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
}
