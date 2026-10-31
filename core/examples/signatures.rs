//! Signing certificates and other APK Signing Block entries.
//!
//! Usage: `cargo run --example signatures -- <path-to-apk> [<other-apk>]`

use std::collections::HashSet;

use apk_info::{Apk, Signature};

// --8<-- [start:compare]
/// SHA-256 fingerprints of every certificate that signs the APK.
fn signing_certificates(path: &str) -> Result<HashSet<String>, apk_info::APKError> {
    let mut fingerprints = HashSet::new();
    for signature in Apk::new(path)?.get_signatures()? {
        if let Signature::V1(certs)
        | Signature::V2(certs)
        | Signature::V3(certs)
        | Signature::V31(certs)
        | Signature::V32(certs) = signature
        {
            fingerprints.extend(certs.into_iter().map(|cert| cert.sha256_fingerprint));
        }
    }
    Ok(fingerprints)
}
// --8<-- [end:compare]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: signatures <path-to-apk> [<other-apk>]")?;
    let apk = Apk::new(&path)?;

    // --8<-- [start:all]
    for signature in apk.get_signatures()? {
        match &signature {
            Signature::V1(certs)
            | Signature::V2(certs)
            | Signature::V3(certs)
            | Signature::V31(certs)
            | Signature::V32(certs) => {
                for cert in certs {
                    println!("{}: {}", signature.name(), cert.subject);
                    println!("  issuer:  {}", cert.issuer);
                    println!("  valid:   {} .. {}", cert.valid_from, cert.valid_until);
                    println!("  sha256:  {}", cert.sha256_fingerprint);
                }
            }
            Signature::StampBlockV1(cert) | Signature::StampBlockV2(cert) => {
                println!("source stamp: {}", cert.subject);
            }
            Signature::ApkChannelBlock(value) | Signature::VasDollyV2(value) => {
                println!("channel: {value}");
            }
            other => println!("{}", other.name()),
        }
    }
    // --8<-- [end:all]

    if let Some(other) = args.next() {
        let a = signing_certificates(&path)?;
        let b = signing_certificates(&other)?;
        println!("same signer: {}", a == b);
    }

    Ok(())
}
