use std::collections::HashMap;
use std::sync::Arc;

use flate2::{Decompress, FlushDecompress, Status};
use log::{debug, warn};
use openssl::hash::MessageDigest;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::{X509, X509Ref};
use winnow::binary::{le_u32, le_u64};
use winnow::combinator::repeat;
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::take;

use crate::errors::{CertificateError, FileCompressionType, ZipError};
use crate::signature::{CertificateInfo, Signature};
use crate::structs::{CentralDirectory, EndOfCentralDirectory, LocalFileHeader};

/// Represents a parsed ZIP archive
pub struct ZipEntry {
    /// Owned zip data
    input: Vec<u8>,

    /// EOCD structure
    eocd: EndOfCentralDirectory,

    /// Central directory structure
    central_directory: CentralDirectory,

    /// Information about local headers
    local_headers: HashMap<Arc<str>, LocalFileHeader>,
}

/// Implementation of common methods
impl ZipEntry {
    pub fn new(input: Vec<u8>) -> Result<ZipEntry, ZipError> {
        // perform basic sanity check
        if !input.starts_with(b"PK\x03\x04") {
            return Err(ZipError::InvalidHeader);
        }

        let eocd_offset =
            EndOfCentralDirectory::find_eocd(&input, 4096).ok_or(ZipError::NotFoundEOCD)?;

        let eocd = EndOfCentralDirectory::parse(&mut &input[eocd_offset..])
            .map_err(|_| ZipError::ParseError)?;

        let central_directory =
            CentralDirectory::parse(&input, &eocd).map_err(|_| ZipError::ParseError)?;

        let local_headers = central_directory
            .entries
            .iter()
            .filter_map(|(filename, entry)| {
                LocalFileHeader::parse(&input, entry.local_header_offset as usize)
                    .ok()
                    .map(|header| (Arc::clone(filename), header))
            })
            .collect();

        Ok(ZipEntry {
            input,
            eocd,
            central_directory,
            local_headers,
        })
    }

    /// Get list of the filenames from zip archive
    pub fn namelist(&self) -> impl Iterator<Item = &str> + '_ {
        self.central_directory.entries.keys().map(|x| x.as_ref())
    }

    /// Read tampered files from zip archive
    pub fn read(&self, filename: &str) -> Result<(Vec<u8>, FileCompressionType), ZipError> {
        let local_header = self
            .local_headers
            .get(filename)
            .ok_or(ZipError::FileNotFound)?;

        let central_directory_entry = self
            .central_directory
            .entries
            .get(filename)
            .ok_or(ZipError::FileNotFound)?;

        let (compressed_size, uncompressed_size) =
            if local_header.compressed_size == 0 || local_header.uncompressed_size == 0 {
                (
                    central_directory_entry.compressed_size as usize,
                    central_directory_entry.uncompressed_size as usize,
                )
            } else {
                (
                    local_header.compressed_size as usize,
                    local_header.uncompressed_size as usize,
                )
            };

        let offset = central_directory_entry.local_header_offset as usize + local_header.size();
        // helper to safely get a slice from input
        let get_slice = |start: usize, end: usize| self.input.get(start..end).ok_or(ZipError::EOF);

        match (
            local_header.compression_method,
            compressed_size == uncompressed_size,
        ) {
            (0, _) => {
                // stored (no compression)
                let slice = get_slice(offset, offset + uncompressed_size)?;
                Ok((slice.to_vec(), FileCompressionType::Stored))
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

                Ok((uncompressed_data, FileCompressionType::Deflated))
            }
            (_, true) => {
                // stored tampered
                let slice = get_slice(offset, offset + uncompressed_size)?;
                Ok((slice.to_vec(), FileCompressionType::StoredTampered))
            }
            (_, false) => {
                // deflate tampered
                let compressed_data = get_slice(offset, offset + compressed_size)?;
                let mut uncompressed_data = Vec::with_capacity(uncompressed_size);
                let mut decompressor = Decompress::new(false);

                let status = decompressor.decompress_vec(
                    compressed_data,
                    &mut uncompressed_data,
                    FlushDecompress::Finish,
                );

                // check if decompression was actually successfull
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
/// Very cool research about this: <https://goa2023.nullcon.net/doc/goa-2023/Android-SigMorph-Covert-Communication-Exploiting-Android-Signing-Schemes.pdf>
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

    /// Used to increase the size of the signing block (including the length and magic) to a mulitple 4096
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/tools/apksig/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java#100>
    pub const VERITY_PADDING_BLOCK_ID: u32 = 0x42726577;

    /// Block that contains dependency metadata, which is saved by the Android Gradle plugin to identify any issues related to dependencies
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

    /// Helper function to convert openssl [X509Ref] to [CertificateInfo]
    fn get_certificate_info(
        &self,
        certificate: &X509Ref,
    ) -> Result<CertificateInfo, CertificateError> {
        fn digest_hex(cert: &X509Ref, md: MessageDigest) -> Result<String, CertificateError> {
            Ok(const_hex::encode(
                cert.digest(md).map_err(CertificateError::StackError)?,
            ))
        }

        let serial_number = {
            let bn = certificate
                .serial_number()
                .to_bn()
                .map_err(CertificateError::StackError)?;

            const_hex::encode(bn.to_vec())
        };

        let subject = certificate
            .subject_name()
            .entries()
            .filter_map(|entry| {
                let key = entry.object().nid().short_name().unwrap_or_default();
                let value = entry.data().as_utf8().ok()?.to_string();
                Some(format!("{}={}", key, value))
            })
            .collect::<Vec<_>>()
            .join(" ");

        let valid_from = certificate.not_before().to_string();
        let valid_until = certificate.not_after().to_string();

        let signature_type = certificate
            .signature_algorithm()
            .object()
            .nid()
            .long_name()
            .map_err(CertificateError::StackError)?
            .to_string();

        let md5_fingerprint = digest_hex(certificate, MessageDigest::md5())?;
        let sha1_fingerprint = digest_hex(certificate, MessageDigest::sha1())?;
        let sha256_fingerprint = digest_hex(certificate, MessageDigest::sha256())?;

        Ok(CertificateInfo {
            serial_number,
            subject,
            valid_from,
            valid_until,
            signature_type,
            md5_fingerprint,
            sha1_fingerprint,
            sha256_fingerprint,
        })
    }

    /// Get information from v1 certificate
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
            .map_err(CertificateError::ZipError)?;

        let info = Pkcs7::from_der(&data).map_err(CertificateError::StackError)?;
        let certs = Stack::new().map_err(CertificateError::StackError)?;

        let certificates = info
            .signers(&certs, Pkcs7Flags::STREAM)
            .map_err(|_| CertificateError::SignerError)?
            .iter()
            .map(|signer| self.get_certificate_info(signer))
            .collect::<Result<Vec<CertificateInfo>, CertificateError>>()?;

        Ok(Signature::V1(certificates))
    }

    /// Parse APK signature block and extract usefull information
    pub fn get_signatures_other(&self) -> Result<Vec<Signature>, CertificateError> {
        let offset = self.eocd.central_dir_offset as usize;
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

    fn parse_digest<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let (_, signature_algorithm_id, digest_data_length) =
                (le_u32, le_u32, le_u32).parse_next(input)?;
            let digest = take(digest_data_length).parse_next(input)?;

            Ok((signature_algorithm_id, digest))
        }
    }

    fn parse_certificates<'a>() -> impl Parser<&'a [u8], X509, ContextError> {
        move |input: &mut &'a [u8]| {
            let certificate_length = le_u32.parse_next(input)?;
            let certificate = take(certificate_length).parse_next(input)?;

            // TODO: remove unwrap block
            Ok(X509::from_der(certificate).unwrap())
        }
    }

    fn parse_attributes<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let (attribute_length, id) = (le_u32, le_u32).parse_next(input)?;
            let value = take(attribute_length.saturating_sub(4)).parse_next(input)?;

            Ok((id, value))
        }
    }

    fn parse_attributes_v3<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let (attribute_length, id) = (le_u32, le_u32).parse_next(input)?;
            let value = take(attribute_length.saturating_sub(4)).parse_next(input)?;

            // TODO: i really need to check that id is equal 0x3ba06f8c ?
            let _const_id = le_u32.parse_next(input)?;

            // TODO: proof of rotation struct - just skip for now

            Ok((id, value))
        }
    }

    fn parse_signatures<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let (_signature_length, signature_algorithm_id, signature_data_length) =
                (le_u32, le_u32, le_u32).parse_next(input)?;
            let signature = take(signature_data_length).parse_next(input)?;

            Ok((signature_algorithm_id, signature))
        }
    }

    fn parse_signature_v3_like(
        &self,
        input: &mut &[u8],
    ) -> Result<Vec<CertificateInfo>, ContextError> {
        let _signers_length = le_u32.parse_next(input)?;

        // TODO: parse several signers
        let _signer_length = le_u32.parse_next(input)?;
        let _signed_data_length = le_u32.parse_next(input)?;

        // parse digest
        let digests_length = le_u32.parse_next(input)?;
        let mut digest_bytes = take(digests_length).parse_next(input)?;
        let _digests: Vec<(u32, &[u8])> =
            repeat(0.., Self::parse_digest()).parse_next(&mut digest_bytes)?;

        // parse certificates
        let certificates_length = le_u32.parse_next(input)?;
        let mut certificates_bytes = take(certificates_length).parse_next(input)?;
        let certificates: Vec<X509> =
            repeat(0.., Self::parse_certificates()).parse_next(&mut certificates_bytes)?;

        let (_min_sdk, _max_sdk) = (le_u32, le_u32).parse_next(input)?;

        // attributes
        let attributes_length = le_u32.parse_next(input)?;
        let mut attributes_bytes = take(attributes_length).parse_next(input)?;
        let _attributes: Vec<(u32, &[u8])> =
            repeat(0.., Self::parse_attributes_v3()).parse_next(&mut attributes_bytes)?;

        // duplicate min/max sdk
        let (_duplicate_min_sdk, _duplicate_max_sdk) = (le_u32, le_u32).parse_next(input)?;

        // signatures
        let signatures_length = le_u32.parse_next(input)?;
        let mut signatures_bytes = take(signatures_length).parse_next(input)?;
        let _signatures: Vec<(u32, &[u8])> =
            repeat(0.., Self::parse_signatures()).parse_next(&mut signatures_bytes)?;

        let public_key_length = le_u32.parse_next(input)?;
        let _public_key = take(public_key_length).parse_next(input)?;

        // filter certificates
        let certificates = certificates
            .iter()
            .filter_map(|cert| self.get_certificate_info(cert).ok())
            .collect();

        Ok(certificates)
    }

    fn parse_apk_signatures<'a>(&self) -> impl Parser<&'a [u8], Signature, ContextError> {
        move |input: &mut &'a [u8]| {
            let (size, id) = (le_u64, le_u32).parse_next(input)?;

            match id {
                Self::SIGNATURE_SCHEME_V2_BLOCK_ID => {
                    let _signers_length = le_u32.parse_next(input)?;
                    // TODO: need parse several signers

                    // parse signer
                    let _signer_length = le_u32.parse_next(input)?;

                    // parse signed data
                    let _signed_data_length = le_u32.parse_next(input)?;

                    // parse digests
                    let digests_length = le_u32.parse_next(input)?;
                    let mut digest_bytes = take(digests_length).parse_next(input)?;
                    let _digests: Vec<(u32, &[u8])> =
                        repeat(0.., Self::parse_digest()).parse_next(&mut digest_bytes)?;

                    let certificates_length = le_u32.parse_next(input)?;
                    let mut certificates_bytes = take(certificates_length).parse_next(input)?;
                    let certificates: Vec<X509> = repeat(0.., Self::parse_certificates())
                        .parse_next(&mut certificates_bytes)?;

                    let attributes_length = le_u32.parse_next(input)?;
                    let mut attributes_bytes = take(attributes_length).parse_next(input)?;
                    // often attributes is zero size
                    let _attributes: Vec<(u32, &[u8])> =
                        repeat(0.., Self::parse_attributes()).parse_next(&mut attributes_bytes)?;

                    // i honestly don't know i need consume another 4 zero bytes, but this is happens in apk
                    // not documented stuff, i can't figure out this from source code
                    let _ = le_u32.parse_next(input)?;

                    let signatures_length = le_u32.parse_next(input)?;
                    let mut signatures_bytes = take(signatures_length).parse_next(input)?;
                    let _signatures: Vec<(u32, &[u8])> =
                        repeat(0.., Self::parse_signatures()).parse_next(&mut signatures_bytes)?;

                    let public_key_length = le_u32.parse_next(input)?;
                    let _public_key = take(public_key_length).parse_next(input)?.to_vec();

                    let certificates = certificates
                        .iter()
                        .filter_map(|cert| self.get_certificate_info(cert).ok())
                        .collect();

                    Ok(Signature::V2(certificates))
                }
                Self::SIGNATURE_SCHEME_V3_BLOCK_ID => {
                    let certificates = self.parse_signature_v3_like(input)?;

                    Ok(Signature::V3(certificates))
                }
                Self::SIGNATURE_SCHEME_V31_BLOCK_ID => {
                    let certificates = self.parse_signature_v3_like(input)?;

                    Ok(Signature::V31(certificates))
                }
                Self::APK_CHANNEL_BLOCK_ID => {
                    let data = take(size.saturating_sub(4)).parse_next(input)?;

                    Ok(Signature::ApkChannelBlock(
                        String::from_utf8_lossy(data).to_string(),
                    ))
                }
                Self::V1_SOURCE_STAMP_BLOCK_ID => {
                    // https://cs.android.com/android/platform/superproject/main/+/main:tools/apksig/src/main/java/com/android/apksig/internal/apk/stamp/V1SourceStampSigner.java;l=86;bpv=0;bpt=1
                    let _stamp_block_prefix = le_u32.parse_next(input)?;

                    let certificate = Self::parse_certificates().parse_next(input)?;

                    // i don't think that it is usefull information
                    let signed_data_sequence_length = le_u32.parse_next(input)?;
                    let _signed_data =
                        take(signed_data_sequence_length as usize).parse_next(input)?;

                    // TODO: proper error message
                    let certificate = self
                        .get_certificate_info(&certificate)
                        .map_err(|_| ContextError::new())?;

                    Ok(Signature::StampBlockV1(certificate))
                }
                Self::V2_SOURCE_STAMP_BLOCK_ID => {
                    // https://cs.android.com/android/platform/superproject/main/+/main:tools/apksig/src/main/java/com/android/apksig/internal/apk/stamp/V2SourceStampSigner.java;l=124;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=0;bpt=1

                    let _stamp_block_prefix = le_u32.parse_next(input)?;
                    let certificate = Self::parse_certificates().parse_next(input)?;

                    // i don't think that it is usefull information
                    let signed_digests_sequence_length = le_u32.parse_next(input)?;
                    let _signed_digests_data =
                        take(signed_digests_sequence_length as usize).parse_next(input)?;

                    // i don't think that it is usefull information
                    let encoded_stamp_attributes_length = le_u32.parse_next(input)?;
                    let _encoded_stamp_attributes =
                        take(encoded_stamp_attributes_length as usize).parse_next(input)?;

                    // i don't think that it is usefull information
                    let signed_attributes_length = le_u32.parse_next(input)?;
                    let _signed_attributes =
                        take(signed_attributes_length as usize).parse_next(input)?;

                    // TODO: proper error message
                    let certificate = self
                        .get_certificate_info(&certificate)
                        .map_err(|_| ContextError::new())?;

                    Ok(Signature::StampBlockV2(certificate))
                }
                Self::VERITY_PADDING_BLOCK_ID
                | Self::DEPENDENCY_INFO_BLOCK_ID
                | Self::ZERO_BLOCK_ID => {
                    // not interesting blocks
                    let _ = take(size.saturating_sub(4)).parse_next(input)?;
                    Ok(Signature::Unknown)
                }
                // some maybe usefull block that we don't parse yet
                Self::GOOGLE_PLAY_FROSTING_ID => {
                    let _ = take(size.saturating_sub(4)).parse_next(input)?;
                    // maybe even remove this message, idk for now
                    debug!(
                        "got known id block - 0x{:08x} (size - 0x{:08x}), but don't know yet how to parse it",
                        id, size
                    );

                    Ok(Signature::Unknown)
                }
                _ => {
                    warn!("got unknown id block - 0x{:08x} (0x{:08x})", id, size);
                    let _ = take(size.saturating_sub(4)).parse_next(input)?;

                    Ok(Signature::Unknown)
                }
            }
        }
    }
}
