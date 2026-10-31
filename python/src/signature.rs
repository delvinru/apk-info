//! Python classes for the signatures and their certificates.

use std::fmt;

use ::apk_info_zip::{CertificateInfo as ZipCertificateInfo, Signature as ZipSignature};
use pyo3::prelude::*;

/// A signing certificate.
#[pyclass(eq, frozen, from_py_object, module = "apk_info._apk_info")]
#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct CertificateInfo {
    #[pyo3(get)]
    serial_number: String,
    #[pyo3(get)]
    subject: String,
    #[pyo3(get)]
    issuer: String,
    #[pyo3(get)]
    valid_from: String,
    #[pyo3(get)]
    valid_until: String,
    #[pyo3(get)]
    signature_type: String,
    #[pyo3(get)]
    md5_fingerprint: String,
    #[pyo3(get)]
    sha1_fingerprint: String,
    #[pyo3(get)]
    sha256_fingerprint: String,
}

impl From<ZipCertificateInfo> for CertificateInfo {
    fn from(certificate: ZipCertificateInfo) -> Self {
        Self {
            serial_number: certificate.serial_number,
            subject: certificate.subject,
            issuer: certificate.issuer,
            valid_from: certificate.valid_from,
            valid_until: certificate.valid_until,
            signature_type: certificate.signature_type,
            md5_fingerprint: certificate.md5_fingerprint,
            sha1_fingerprint: certificate.sha1_fingerprint,
            sha256_fingerprint: certificate.sha256_fingerprint,
        }
    }
}

impl fmt::Debug for CertificateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertificateInfo(serial_number='{}', subject='{}', issuer='{}', valid_from='{}', \
             valid_until='{}', signature_type='{}', md5_fingerprint='{}', \
             sha1_fingerprint='{}', sha256_fingerprint='{}')",
            self.serial_number,
            self.subject,
            self.issuer,
            self.valid_from,
            self.valid_until,
            self.signature_type,
            self.md5_fingerprint,
            self.sha1_fingerprint,
            self.sha256_fingerprint
        )
    }
}

#[pymethods]
impl CertificateInfo {
    fn __repr__(&self) -> String {
        format!("{self:?}")
    }
}

/// A signature scheme or another block of the APK Signing Block.
///
/// The Python variants name their fields, unlike the Rust ones:
/// `Signature.V1(certificates=[...])`, `Signature.ApkChannelBlock(value="...")`.
#[pyclass(eq, frozen, module = "apk_info._apk_info")]
#[derive(PartialEq, Eq, Hash)]
pub(crate) enum Signature {
    V1 { certificates: Vec<CertificateInfo> },
    V2 { certificates: Vec<CertificateInfo> },
    V3 { certificates: Vec<CertificateInfo> },
    V31 { certificates: Vec<CertificateInfo> },
    V32 { certificates: Vec<CertificateInfo> },
    StampBlockV1 { certificate: CertificateInfo },
    StampBlockV2 { certificate: CertificateInfo },
    ApkChannelBlock { value: String },
    PackerNextGenV2 { value: Vec<u8> },
    GooglePlayFrosting {},
    VasDollyV2 { value: String },
    ByteDance { value: String },
}

impl From<ZipSignature> for Signature {
    fn from(signature: ZipSignature) -> Self {
        fn certificates(list: Vec<ZipCertificateInfo>) -> Vec<CertificateInfo> {
            list.into_iter().map(CertificateInfo::from).collect()
        }

        match signature {
            ZipSignature::V1(list) => Self::V1 {
                certificates: certificates(list),
            },
            ZipSignature::V2(list) => Self::V2 {
                certificates: certificates(list),
            },
            ZipSignature::V3(list) => Self::V3 {
                certificates: certificates(list),
            },
            ZipSignature::V31(list) => Self::V31 {
                certificates: certificates(list),
            },
            ZipSignature::V32(list) => Self::V32 {
                certificates: certificates(list),
            },
            ZipSignature::StampBlockV1(certificate) => Self::StampBlockV1 {
                certificate: certificate.into(),
            },
            ZipSignature::StampBlockV2(certificate) => Self::StampBlockV2 {
                certificate: certificate.into(),
            },
            ZipSignature::ApkChannelBlock(value) => Self::ApkChannelBlock { value },
            ZipSignature::PackerNextGenV2(value) => Self::PackerNextGenV2 { value },
            ZipSignature::GooglePlayFrosting => Self::GooglePlayFrosting {},
            ZipSignature::VasDollyV2(value) => Self::VasDollyV2 { value },
            ZipSignature::ByteDance(value) => Self::ByteDance { value },
        }
    }
}

#[pymethods]
impl Signature {
    fn __repr__(&self) -> String {
        match self {
            Self::V1 { certificates } => format!("Signature.V1(certificates={certificates:?})"),
            Self::V2 { certificates } => format!("Signature.V2(certificates={certificates:?})"),
            Self::V3 { certificates } => format!("Signature.V3(certificates={certificates:?})"),
            Self::V31 { certificates } => format!("Signature.V31(certificates={certificates:?})"),
            Self::V32 { certificates } => format!("Signature.V32(certificates={certificates:?})"),
            Self::StampBlockV1 { certificate } => {
                format!("Signature.StampBlockV1(certificate={certificate:?})")
            }
            Self::StampBlockV2 { certificate } => {
                format!("Signature.StampBlockV2(certificate={certificate:?})")
            }
            Self::ApkChannelBlock { value } => {
                format!("Signature.ApkChannelBlock(value='{value}')")
            }
            Self::PackerNextGenV2 { value } => {
                let hex: String = value.iter().map(|byte| format!("{byte:02x}")).collect();
                format!("Signature.PackerNextGenV2(channel='{hex}')")
            }
            Self::GooglePlayFrosting {} => "Signature.GooglePlayFrosting()".to_owned(),
            Self::VasDollyV2 { value } => format!("Signature.VasDollyV2(value='{value}')"),
            Self::ByteDance { value } => format!("Signature.ByteDance(value='{value}')"),
        }
    }
}
