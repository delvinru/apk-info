import sys

from apk_info import APK, Signature

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} <apk>")
    sys.exit(1)

file = sys.argv[1]
apk = APK(file)

signatures = apk.get_signatures()
for signature in signatures:
    match signature:
        case Signature.V1() | Signature.V2() | Signature.V3() | Signature.V31():
            for cert in signature.certificates:
                print(f"{cert.subject=} {cert.issuer=} {cert.valid_from=} {cert.valid_until=}")
        case Signature.ApkChannelBlock():
            print(f"got apk channel block: {signature.value}")
        case _:
            print(f"oh, cool, library added some new feature - {signature}")
