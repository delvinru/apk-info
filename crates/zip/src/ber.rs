//! Minimal BER reader for certificates and PKCS#7 blobs that are not strict DER.
//!
//! Android accepts BER-encoded signing certificates (non-minimal or indefinite
//! lengths) and uses their original bytes as the signer identity
//! (apksig `GuaranteedEncodedFormX509Certificate`). The `der` crate is strict,
//! so such input is normalized to DER for parsing, while fingerprints are
//! still computed over the original bytes.

/// Bounds the recursion on hostile input.
const MAX_DEPTH: usize = 64;

/// A single BER element.
pub(crate) struct Tlv<'a> {
    /// Identifier octets.
    pub(crate) tag: &'a [u8],

    /// Content octets, without the end-of-contents marker.
    pub(crate) content: &'a [u8],

    /// The whole element as encoded.
    pub(crate) raw: &'a [u8],
}

impl Tlv<'_> {
    #[inline]
    fn constructed(&self) -> bool {
        self.tag[0] & 0x20 != 0
    }
}

/// Reads one element from the front of `input` and advances past it.
pub(crate) fn read<'a>(input: &mut &'a [u8]) -> Option<Tlv<'a>> {
    read_at(input, 0)
}

fn read_at<'a>(input: &mut &'a [u8], depth: usize) -> Option<Tlv<'a>> {
    if depth > MAX_DEPTH {
        return None;
    }

    let start = *input;
    let first = *start.first()?;
    let mut pos = 1;

    // high-tag-number form
    if first & 0x1f == 0x1f {
        loop {
            let byte = *start.get(pos)?;
            pos += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let tag_end = pos;

    let length = *start.get(pos)?;
    pos += 1;

    let (content, end) = match length {
        0x00..=0x7f => {
            let end = pos + length as usize;
            (start.get(pos..end)?, end)
        }
        // indefinite length: children up to the `00 00` end-of-contents marker
        0x80 => {
            if first & 0x20 == 0 {
                return None;
            }

            let mut rest = &start[pos..];
            while !rest.starts_with(&[0, 0]) {
                read_at(&mut rest, depth + 1)?;
            }

            let content_end = start.len() - rest.len();
            (&start[pos..content_end], content_end + 2)
        }
        _ => {
            let count = (length & 0x7f) as usize;
            if count > size_of::<u32>() {
                return None;
            }

            let mut value = 0usize;
            for _ in 0..count {
                value = value << 8 | *start.get(pos)? as usize;
                pos += 1;
            }

            let end = pos.checked_add(value)?;
            (start.get(pos..end)?, end)
        }
    };

    *input = &start[end..];
    Some(Tlv {
        tag: &start[..tag_end],
        content,
        raw: &start[..end],
    })
}

/// Returns the child elements of a constructed element.
pub(crate) fn children<'a>(tlv: &Tlv<'a>) -> Option<Vec<Tlv<'a>>> {
    let mut rest = tlv.content;
    let mut out = Vec::new();
    while !rest.is_empty() {
        out.push(read(&mut rest)?);
    }

    Some(out)
}

/// Re-encodes a single BER element with minimal definite lengths.
///
/// Strict DER input comes out byte-for-byte unchanged.
pub(crate) fn to_der(input: &[u8]) -> Option<Vec<u8>> {
    let mut rest = input;
    let tlv = read(&mut rest)?;
    if !rest.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(input.len());
    write_der(&tlv, &mut out, 0)?;
    Some(out)
}

fn write_der(tlv: &Tlv, out: &mut Vec<u8>, depth: usize) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }

    out.extend_from_slice(tlv.tag);

    if !tlv.constructed() {
        write_length(out, tlv.content.len());
        out.extend_from_slice(tlv.content);
        return Some(());
    }

    let mut content = Vec::with_capacity(tlv.content.len());
    let mut rest = tlv.content;
    while !rest.is_empty() {
        write_der(&read(&mut rest)?, &mut content, depth + 1)?;
    }

    write_length(out, content.len());
    out.extend_from_slice(&content);
    Some(())
}

fn write_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }

    let bytes = length.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_input_is_unchanged() {
        // SEQUENCE { INTEGER 5, OCTET STRING "ab" }
        let der = [0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, b'a', b'b'];
        assert_eq!(to_der(&der).unwrap(), der);
    }

    #[test]
    fn non_minimal_length_is_shortened() {
        let ber = [0x30, 0x82, 0x00, 0x04, 0x02, 0x81, 0x01, 0x05];
        assert_eq!(to_der(&ber).unwrap(), [0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn indefinite_length_is_resolved() {
        let ber = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00];
        assert_eq!(to_der(&ber).unwrap(), [0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn long_content_gets_long_form_length() {
        let mut ber = vec![0x04, 0x83, 0x00, 0x01, 0x00];
        ber.extend(std::iter::repeat_n(0xaa, 256));
        let der = to_der(&ber).unwrap();
        assert_eq!(&der[..4], &[0x04, 0x82, 0x01, 0x00]);
        assert_eq!(der.len(), 4 + 256);
    }

    #[test]
    fn malformed_input_is_rejected() {
        // truncated content
        assert!(to_der(&[0x30, 0x05, 0x02, 0x01]).is_none());
        // indefinite length on a primitive
        assert!(to_der(&[0x04, 0x80, 0x00, 0x00]).is_none());
        // missing end-of-contents
        assert!(to_der(&[0x30, 0x80, 0x02, 0x01, 0x05]).is_none());
        // trailing bytes
        assert!(to_der(&[0x05, 0x00, 0x00]).is_none());
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let mut ber = Vec::new();
        for _ in 0..1000 {
            ber.extend([0x30, 0x80]);
        }
        for _ in 0..1000 {
            ber.extend([0x00, 0x00]);
        }
        assert!(to_der(&ber).is_none());
    }
}
