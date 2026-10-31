//! Distinguished names as RFC 4514 strings.
//!
//! The output is the same as `Display` of [`Name`], but faster: `Display`
//! looks up the short name of every attribute type (`CN`, `O`, ...) with a
//! scan over the whole OID database, while here every type is looked up once
//! per process.

use std::fmt::Write;
use std::sync::{Mutex, OnceLock, PoisonError};

use ahash::AHashMap;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::der::asn1::{
    Ia5StringRef, ObjectIdentifier, PrintableStringRef, TeletexStringRef, Utf8StringRef,
};
use x509_cert::der::oid::db::DB;
use x509_cert::der::{Tag, Tagged};
use x509_cert::name::{Name, RelativeDistinguishedName};

/// Formats `name` like its `Display`.
pub(crate) fn to_string(name: &Name) -> String {
    let mut out = String::new();

    // RFC 4514 Section 2.1: the RDNs are reversed
    let rdns: &Vec<RelativeDistinguishedName> = name.as_ref().as_ref();
    for (i, rdn) in rdns.iter().rev().enumerate() {
        if i > 0 {
            out.push(',');
        }
        for (j, atv) in rdn.iter().enumerate() {
            if j > 0 {
                out.push('+');
            }
            write_attribute(&mut out, atv);
        }
    }

    out
}

fn write_attribute(out: &mut String, atv: &AttributeTypeAndValue) {
    let value = match atv.value.tag() {
        Tag::PrintableString => PrintableStringRef::try_from(&atv.value)
            .ok()
            .map(|s| s.as_str()),
        Tag::Utf8String => Utf8StringRef::try_from(&atv.value).ok().map(|s| s.as_str()),
        Tag::Ia5String => Ia5StringRef::try_from(&atv.value).ok().map(|s| s.as_str()),
        Tag::TeletexString => TeletexStringRef::try_from(&atv.value)
            .ok()
            .map(|s| s.as_str()),
        _ => None,
    };

    let (Some(key), Some(value)) = (shortest_name(&atv.oid), value) else {
        // an unknown type or a value that isn't a string: hex, rare
        _ = write!(out, "{atv}");
        return;
    };

    out.push_str(&key.to_ascii_uppercase());
    out.push('=');

    let mut chars = value.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || chars.peek().is_none() => out.push_str("\\ "),
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\x00'..='\x1f' | '\x7f' => _ = write!(out, "\\{:02x}", c as u8),
            _ => out.push(c),
        }
    }
}

/// The shortest name of an OID in the database, cached.
fn shortest_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    static CACHE: OnceLock<Mutex<AHashMap<ObjectIdentifier, Option<&'static str>>>> =
        OnceLock::new();

    let mut cache = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

    *cache.entry(*oid).or_insert_with(|| {
        // the first of the shortest names, like `Display`
        DB.find_names_for_oid(*oid)
            .fold(None, |best: Option<&'static str>, name| match best {
                Some(best) if best.len() <= name.len() => Some(best),
                _ => Some(name),
            })
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use x509_cert::der::asn1::{Any, SetOfVec};
    use x509_cert::der::{Decode, Encode};
    use x509_cert::name::RdnSequence;

    use super::*;

    fn same_as_display(name: &Name) {
        assert_eq!(to_string(name), name.to_string());
    }

    #[test]
    fn common_names_match_display() {
        for name in [
            "CN=Android Debug,O=Android,C=US",
            "CN=rsa-2048",
            "C=US,ST=California,L=Mountain View,O=Google Inc.,OU=Android,CN=Android",
            "CN=a+OU=b,O=c",
            "CN=with \\, comma \\+ plus \\\\ backslash \\\"quote\\\"",
            "CN=\\ leading and trailing\\ ,O=\\#hash",
            "UID=user,DC=example,DC=com",
        ] {
            same_as_display(&Name::from_str(name).unwrap_or_else(|e| panic!("{name}: {e}")));
        }
        same_as_display(&Name::default());
    }

    #[test]
    fn unusual_values_match_display() {
        let atv = |oid: &str, value: Any| AttributeTypeAndValue {
            oid: ObjectIdentifier::new(oid).unwrap(),
            value,
        };
        let rdns = [
            // a type missing from the database
            atv(
                "1.2.3.4.5",
                Any::new(Tag::Utf8String, b"x".to_vec()).unwrap(),
            ),
            // a value that isn't a string
            atv(
                "2.5.4.3",
                Any::new(Tag::OctetString, b"\x01\x02".to_vec()).unwrap(),
            ),
            // control characters
            atv(
                "2.5.4.3",
                Any::new(Tag::Utf8String, b"a\x01b\x7f".to_vec()).unwrap(),
            ),
            atv(
                "1.2.840.113549.1.9.1",
                Any::new(Tag::Ia5String, b"a@b.c".to_vec()).unwrap(),
            ),
        ];

        let mut sequence = RdnSequence::default();
        for atv in rdns {
            let mut set = SetOfVec::new();
            set.insert(atv).unwrap();
            sequence.push(RelativeDistinguishedName::from(set));
        }
        // the same encoding, so a Name can be built from the raw sequence
        same_as_display(&Name::from_der(&sequence.to_der().unwrap()).unwrap());
    }
}
