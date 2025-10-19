use flate2::Decompress;
use flate2::FlushDecompress;
use flate2::Status;
use openssl::hash::MessageDigest;
use openssl::pkcs7::Pkcs7;
use openssl::pkcs7::Pkcs7Flags;
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl::x509::X509Ref;
use std::collections::HashMap;
use winnow::binary::le_u32;
use winnow::binary::le_u64;
use winnow::combinator::repeat;
use winnow::error::ContextError;
use winnow::prelude::*;
use winnow::token::take;

use crate::errors::CertificateError;
use crate::signature::CertificateInfo;
use crate::signature::Signature;
use crate::signature::SignatureV1;
use crate::signature::SignatureV2;
use crate::{
    errors::{FileCompressionType, ZipError},
    structs::{
        central_directory::CentralDirectory, eocd::EndOfCentralDirectory,
        local_file_header::LocalFileHeader,
    },
};

/// Represents a parsed ZIP archive
pub struct ZipEntry {
    input: Vec<u8>,
    eocd: EndOfCentralDirectory,
    central_directory: CentralDirectory,
    local_headers: HashMap<String, LocalFileHeader>,
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
                    .map(|header| (filename.clone(), header))
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
    pub fn namelist(&self) -> impl Iterator<Item = &String> {
        self.central_directory.entries.keys()
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
impl ZipEntry {
    const APK_SIGNATURE_MAGIC: &[u8] = b"APK Sig Block 42";
    const SIGNATURE_V2_MAGIC: u32 = 0x7109871a;
    const SIGNATURE_V3_MAGIC: u32 = 0xf05368c0;

    const SOURCE_STAMP_BLOCK_ID: u32 = 0x6dff800d;

    /// Unknown stuff
    ///
    /// More info: <https://android.googlesource.com/platform/tools/apksig/+/refs/heads/master/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java#100>
    const VERITY_PADDING_BLOCK_ID: u32 = 0x42726577;

    /// Signing block id for SDK dependency block
    const DEPENDENCY_INFO_BLOCK_ID: u32 = 0x504b4453;

    /// Attribute to check whether a newer APK Signature Scheme signature was stripped
    const STRIPPING_PROTECTION_ATTR_ID: u32 = 0xbeeff00d;

    fn get_certificate_info(
        &self,
        certificate: &X509Ref,
    ) -> Result<CertificateInfo, CertificateError> {
        let serial_number = certificate
            .serial_number()
            .to_bn()
            .map_err(CertificateError::StackError)?
            .to_vec()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");

        let subject = certificate
            .subject_name()
            .entries()
            .map(|entry| {
                let key = entry.object().nid().short_name().unwrap_or_default();
                let value = match entry.data().as_utf8() {
                    Ok(v) => v.to_string(),
                    Err(_) => String::new(),
                };

                format!("{}={}", key, value)
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

        let md5_fingerprint = certificate
            .digest(MessageDigest::md5())
            .map_err(CertificateError::StackError)?
            .to_vec()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");

        let sha1_fingerprint = certificate
            .digest(MessageDigest::sha1())
            .map_err(CertificateError::StackError)?
            .to_vec()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");

        let sha256_fingerprint = certificate
            .digest(MessageDigest::sha256())
            .map_err(CertificateError::StackError)?
            .to_vec()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");

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
    pub fn get_certificates_v1(&self) -> Result<Vec<Signature>, CertificateError> {
        let signature_file = match self.namelist().find(|name| {
            name.starts_with("META-INF/")
                && (name.ends_with(".DSA") || name.ends_with(".EC") || name.ends_with(".RSA"))
        }) {
            Some(v) => v,
            // just apk without signatures
            None => return Ok(Vec::new()),
        };

        let (data, _) = self
            .read(signature_file)
            .map_err(CertificateError::ZipError)?;

        let info = Pkcs7::from_der(&data).map_err(CertificateError::StackError)?;
        let certs = Stack::new().map_err(CertificateError::StackError)?;
        let signers = info
            .signers(&certs, Pkcs7Flags::STREAM)
            .map_err(|_| CertificateError::SignerError)?;

        let certificates = signers
            .iter()
            .map(|signer| {
                Ok(Signature::V1(SignatureV1 {
                    certificate: self.get_certificate_info(signer)?,
                }))
            })
            .collect::<Result<Vec<Signature>, CertificateError>>()?;

        Ok(certificates)
    }

    pub fn get_certificates_v2(&self) -> Result<Vec<Signature>, CertificateError> {
        let offset = self.eocd.central_dir_offset as usize;
        let mut slice = match self.input.get(offset.saturating_sub(24)..offset) {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };

        let (size_of_block, _) = (
            le_u64::<&[u8], ContextError>,
            take(16usize).verify(|magic: &[u8]| magic == Self::APK_SIGNATURE_MAGIC),
        )
            .parse_next(&mut slice)
            .map_err(|_| CertificateError::ParseError)?;

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

        // TODO: refactor this code
        let blocks: Vec<Signature> = repeat(0.., self.parse_apk_signatures())
            .parse_next(&mut slice)
            .map_err(|_| CertificateError::ParseError)?;

        let filtered: Vec<Signature> = blocks
            .into_iter()
            .filter(|signature| *signature != Signature::Unknown)
            .collect();

        Ok(filtered)
    }

    fn parse_digest<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let _ = le_u32.parse_next(input)?;
            // println!("digest_length: 0x{:08X}", digest_length);

            let signature_algorithm_id = le_u32.parse_next(input)?;
            // println!("signature_algorithm_id: 0x{:08X}", signature_algorithm_id);

            let digest_data_length = le_u32.parse_next(input)?;
            // println!("digest_data_length: 0x{:08X}", digest_data_length);

            let digest = take(digest_data_length).parse_next(input)?;
            // print!("digest: ");
            // for byte in digest {
            //     print!("{:02X}", byte);
            // }
            // println!();

            Ok((signature_algorithm_id, digest))
        }
    }

    fn parse_certificates<'a>() -> impl Parser<&'a [u8], X509, ContextError> {
        move |input: &mut &'a [u8]| {
            let certificate_length = le_u32.parse_next(input)?;
            // println!("certificate_length: 0x{:08X}", certificate_length);

            let certificate = take(certificate_length).parse_next(input)?;
            // print!("certificate: ");
            // for byte in certificate {
            //     print!("{:02X}", byte);
            // }
            // println!();

            // TODO: remove unwrap block
            Ok(X509::from_der(certificate).unwrap())
        }
    }

    fn parse_attributes<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let attribute_length = le_u32.parse_next(input)?;
            // println!("attribute_length: 0x{:08x}", attribute_length);

            let id = le_u32.parse_next(input)?;
            // println!("attribute id: 0x{:08x}", id);

            let value = take(attribute_length.saturating_sub(4)).parse_next(input)?;
            // println!("value: {:02x?}", value);

            Ok((id, value))
        }
    }

    fn parse_signatures<'a>() -> impl Parser<&'a [u8], (u32, &'a [u8]), ContextError> {
        move |input: &mut &'a [u8]| {
            let _ = le_u32.parse_next(input)?;
            let signature_algorithm_id = le_u32.parse_next(input)?;
            let signature_data_length = le_u32.parse_next(input)?;
            let signature = take(signature_data_length).parse_next(input)?;

            Ok((signature_algorithm_id, signature))
        }
    }

    fn parse_apk_signatures<'a>(&self) -> impl Parser<&'a [u8], Signature, ContextError> {
        move |input: &mut &'a [u8]| {
            let (size, id) = (le_u64, le_u32).parse_next(input)?;
            // println!("size = 0x{:08x} id = 0x{:08x}", size, id);

            match id {
                Self::SIGNATURE_V2_MAGIC => {
                    let signers_length = le_u32.parse_next(input)?;
                    // println!("signers_length: 0x{:08X}", signers_length);

                    // TODO: need parse several signers

                    // parse signer
                    let signer_length = le_u32.parse_next(input)?;
                    // println!("signer_length: 0x{:08X}", signer_length);

                    // parse signed data
                    let signed_data_length = le_u32.parse_next(input)?;
                    // println!("signed_data_length: 0x{:08X}", signed_data_length);

                    // parse digests
                    let digests_length = le_u32.parse_next(input)?;
                    // println!("digests_length: 0x{:08X}", digests_length);
                    let mut digest_bytes = take(digests_length).parse_next(input)?;
                    let digests: Vec<(u32, &[u8])> =
                        repeat(0.., Self::parse_digest()).parse_next(&mut digest_bytes)?;

                    // println!("{digests:?}");

                    let certificates_length = le_u32.parse_next(input)?;
                    // println!("certificates_length: 0x{:08X}", certificates_length);

                    let mut certificates_bytes = take(certificates_length).parse_next(input)?;

                    let certificates: Vec<X509> = repeat(0.., Self::parse_certificates())
                        .parse_next(&mut certificates_bytes)?;
                    // println!("certificates: {:?}", certificates);

                    let attributes_length = le_u32.parse_next(input)?;
                    // println!("attributes length: 0x{:08x}", attributes_length);
                    let mut attributes_bytes = take(attributes_length).parse_next(input)?;

                    // often attributes is zero size
                    let attributes: Vec<(u32, &[u8])> =
                        repeat(0.., Self::parse_attributes()).parse_next(&mut attributes_bytes)?;
                    // println!("attributes: {:?}", attributes);

                    // i honestly don't know i need consume another 4 zero bytes, but this is happens in apk
                    // not documented stuff, i can't find this in source code
                    let _ = le_u32.parse_next(input)?;

                    let signatures_length = le_u32.parse_next(input)?;
                    // println!("signatures_length: {:08x}", signatures_length);
                    let mut signatures_bytes = take(signatures_length).parse_next(input)?;
                    let signatures: Vec<(u32, &[u8])> =
                        repeat(0.., Self::parse_signatures()).parse_next(&mut signatures_bytes)?;

                    // println!("signatures: {:?}", signatures);

                    let public_key_length = le_u32.parse_next(input)?;
                    // println!("public_key_length: {:08x}", public_key_length);
                    let public_key = take(public_key_length).parse_next(input)?;

                    // print!("public key: ");
                    // for byte in public_key {
                    // print!("{:02X}", byte);
                    // }
                    // println!();

                    let certificates = certificates
                        .iter()
                        .filter_map(|cert| self.get_certificate_info(cert).ok())
                        .collect();

                    Ok(Signature::V2(SignatureV2 { certificates }))
                }
                Self::SIGNATURE_V3_MAGIC => {
                    println!("got v3 magic (not yet implemented) - 0x{:08x}", id);
                    let _ = take(size.saturating_sub(4)).parse_next(input)?;

                    Ok(Signature::V3)
                }
                _ => {
                    println!("got unknown block skip - 0x{:08x}", id);
                    let _ = take(size.saturating_sub(4)).parse_next(input)?;

                    Ok(Signature::Unknown)
                }
            }
        }
    }
}
