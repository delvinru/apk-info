/// Describe used signature scheme in APK
///
/// Basic overview: <https://source.android.com/docs/security/features/apksigning>
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Signature {
    /// Default signature scheme based on JAR signing
    ///
    /// See: <https://source.android.com/docs/security/features/apksigning/v2#v1-verification>
    V1(Vec<CertificateInfo>),

    /// APK signature scheme v2
    ///
    /// See: <https://source.android.com/docs/security/features/apksigning/v2>
    V2(Vec<CertificateInfo>),

    /// APK signature scheme v3
    ///
    /// See: <https://source.android.com/docs/security/features/apksigning/v3>
    V3(Vec<CertificateInfo>),

    /// APK signature scheme v3.1
    ///
    /// See: <https://source.android.com/docs/security/features/apksigning/v3-1>
    V31(Vec<CertificateInfo>),

    /// APK signature scheme v4
    ///
    /// See: <https://source.android.com/docs/security/features/apksigning/v4>
    ///
    /// NOTE: not yet implemented and will never?
    V4,

    /// Some usefull information from apk channel block
    ApkChannelBlock(String),

    StampBlockV1(CertificateInfo),
    StampBlockV2(CertificateInfo),

    /// Got something that we don't know
    Unknown,
}

impl Signature {
    pub fn name(&self) -> String {
        match &self {
            Signature::V1(_) => "v1".to_owned(),
            Signature::V2(_) => "v2".to_owned(),
            Signature::V3(_) => "v3".to_owned(),
            Signature::V31(_) => "v3.1".to_owned(),
            Signature::V4 => "v4".to_owned(),
            Signature::ApkChannelBlock(_) => "APK Channel block".to_owned(),
            Signature::StampBlockV1(_) => "Stamp Block v1".to_owned(),
            Signature::StampBlockV2(_) => "Stamp Block v2".to_owned(),
            Signature::Unknown => "unknown".to_owned(),
        }
    }
}

/// Represents detailed information about an APK signing certificate.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CertificateInfo {
    /// The serial number of the certificate.
    pub serial_number: String,

    /// The subject of the certificate (typically the entity that signed the APK).
    pub subject: String,

    /// The date and time when the certificate becomes valid.
    pub valid_from: String,

    /// The date and time when the certificate expires.
    pub valid_until: String,

    /// The type of signature algorithm used (e.g., RSA, ECDSA).
    pub signature_type: String,

    /// MD5 fingerprint of the certificate.
    pub md5_fingerprint: String,

    /// SHA-1 fingerprint of the certificate.
    pub sha1_fingerprint: String,

    /// SHA-256 fingerprint of the certificate.
    pub sha256_fingerprint: String,
}

/// Representation of signature algorithm
///
/// More info: <https://source.android.com/docs/security/features/apksigning/v2#signature-algorithm-ids>
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc
    RsassaPssSha256 = 0x0101,

    /// RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc
    RsassaPssSha512 = 0x0102,

    /// RSASSA-PKCS1-v1_5 with SHA2-256 digest (deterministic signatures)
    RsassaPkcs1v15Sha256 = 0x0103,

    /// RSASSA-PKCS1-v1_5 with SHA2-512 digest (deterministic signatures)
    RsassaPkcs1v15Sha512 = 0x0104,

    /// ECDSA with SHA2-256 digest
    EcdsaSha256 = 0x0201,

    /// ECDSA with SHA2-512 digest
    EcdsaSha512 = 0x0202,

    /// DSA with SHA2-256 digest
    DsaSha256 = 0x0301,
}
