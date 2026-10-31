"""Signing certificates and other APK Signing Block entries.

Usage: python signatures.py <path-to-apk> [<other-apk>]
"""

import sys

from apk_info import APK, Signature

apk = APK(sys.argv[1])

# --8<-- [start:all]
for signature in apk.get_signatures():
    match signature:
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31() | Signature.V32():
            for cert in signature.certificates:
                print(f"{type(signature).__name__}: {cert.subject}")
                print(f"  issuer:  {cert.issuer}")
                print(f"  valid:   {cert.valid_from} .. {cert.valid_until}")
                print(f"  type:    {cert.signature_type}")
                print(f"  sha256:  {cert.sha256_fingerprint}")
        case Signature.StampBlockV1() | Signature.StampBlockV2():
            print(f"source stamp: {signature.certificate.subject}")
        case Signature.ApkChannelBlock() | Signature.VasDollyV2():
            print(f"channel: {signature.value}")
        case Signature.PackerNextGenV2():
            print(f"Packer-NG: {signature.value.hex()}")
        case Signature.GooglePlayFrosting():
            print("Google Play Frosting block present")
# --8<-- [end:all]

# --8<-- [start:compare]
def signing_certificates(path: str) -> set[str]:
    """SHA-256 fingerprints of every certificate that signs the APK."""
    fingerprints = set()
    for signature in APK(path).get_signatures():
        match signature:
            case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31() | Signature.V32():
                fingerprints.update(cert.sha256_fingerprint for cert in signature.certificates)
    return fingerprints


if len(sys.argv) > 2:
    a = signing_certificates(sys.argv[1])
    b = signing_certificates(sys.argv[2])
    print(f"same signer: {a == b}")
    print(f"shared:      {a & b}")
# --8<-- [end:compare]
