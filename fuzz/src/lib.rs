//! Helpers shared by the fuzz targets: an archive builder that can write every
//! inconsistency the parser has to tolerate, and the checks run on the parsed
//! results.

use std::io::Write as _;

use apk_info_zip::ZipEntry;
use flate2::Compression;
use flate2::write::DeflateEncoder;

/// Bounds the per-input work on archives with many entries.
const MAX_ENTRIES: usize = 32;

/// Calls every reader of a parsed archive, so the lazily parsed parts (local
/// headers, inflate, nested archives, signatures, the writer) are reached.
pub fn exercise_zip(zip: &ZipEntry) {
    let names: Vec<String> = zip.namelist().take(MAX_ENTRIES).map(String::from).collect();

    for name in &names {
        let _ = zip.contains(name);
        let _ = zip.entry_info(name);
        let _ = zip.read(name);
        if let Ok(nested) = zip.open_nested(name) {
            let _ = nested.namelist().count();
        }
    }

    let _ = zip.get_signature_v1();
    let _ = zip.get_signatures_other();
    let _ = zip.repack();
}

/// Panics if `xml` is not a well-formed, namespace-well-formed XML document.
pub fn check_xml(xml: &str) {
    if let Err(err) = roxmltree::Document::parse(xml) {
        panic!("malformed xml output: {err}\n{xml}");
    }
}

/// One archive entry, with every field the central directory record and the
/// local header can disagree on.
#[derive(Clone, Debug)]
pub struct RawEntry {
    /// Name in the central directory record.
    pub name: Vec<u8>,

    /// Name in the local header.
    pub local_name: Vec<u8>,

    /// Entry data as written to the archive (already compressed, if it is).
    pub data: Vec<u8>,

    pub crc32: u32,
    pub flags: u16,

    pub method: u16,
    pub local_method: u16,

    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_compressed_size: u32,
    pub local_uncompressed_size: u32,

    pub extra: Vec<u8>,
    pub local_extra: Vec<u8>,

    /// Added to the real local header offset in the central directory record.
    pub offset_delta: i64,
}

impl RawEntry {
    /// An honest entry with `content` stored as is.
    pub fn stored(name: &[u8], content: &[u8]) -> RawEntry {
        Self::honest(name, content, content.to_vec(), ZipEntry::METHOD_STORED)
    }

    /// An honest entry with `content` compressed with deflate.
    pub fn deflated(name: &[u8], content: &[u8]) -> RawEntry {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(content).expect("write to vec");
        let data = encoder.finish().expect("write to vec");
        Self::honest(name, content, data, ZipEntry::METHOD_DEFLATED)
    }

    fn honest(name: &[u8], content: &[u8], data: Vec<u8>, method: u16) -> RawEntry {
        let compressed_size = data.len() as u32;
        let uncompressed_size = content.len() as u32;

        RawEntry {
            name: name.to_vec(),
            local_name: name.to_vec(),
            data,
            crc32: crc32fast::hash(content),
            flags: 0,
            method,
            local_method: method,
            compressed_size,
            uncompressed_size,
            local_compressed_size: compressed_size,
            local_uncompressed_size: uncompressed_size,
            extra: Vec::new(),
            local_extra: Vec::new(),
            offset_delta: 0,
        }
    }
}

/// The parts of an archive around its entries.
#[derive(Clone, Debug, Default)]
pub struct Layout {
    /// Written between the last entry and the central directory, where the
    /// APK Signing Block lives.
    pub before_cd: Vec<u8>,

    /// Written between the central directory and the EOCD record.
    pub after_cd: Vec<u8>,

    /// Archive comment.
    pub comment: Vec<u8>,

    /// Overrides the entry count of the EOCD record.
    pub total_entries: Option<u16>,

    /// Added to the central directory size of the EOCD record.
    pub cd_size_delta: i64,

    /// Added to the central directory offset of the EOCD record.
    pub cd_offset_delta: i64,

    /// Writes the ZIP64 EOCD record and locator, and saturates the EOCD fields.
    pub zip64: bool,
}

/// Serializes `entries` into an archive laid out as `layout` says.
pub fn build_zip(entries: &[RawEntry], layout: &Layout) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::with_capacity(entries.len());

    for entry in entries {
        offsets.push(out.len() as u32);
        out.extend_from_slice(b"PK\x03\x04");
        put_u16(&mut out, 20); // version needed
        put_u16(&mut out, entry.flags);
        put_u16(&mut out, entry.local_method);
        put_u16(&mut out, 0); // time
        put_u16(&mut out, 0); // date
        put_u32(&mut out, entry.crc32);
        put_u32(&mut out, entry.local_compressed_size);
        put_u32(&mut out, entry.local_uncompressed_size);
        put_u16(&mut out, entry.local_name.len() as u16);
        put_u16(&mut out, entry.local_extra.len() as u16);
        out.extend_from_slice(&entry.local_name);
        out.extend_from_slice(&entry.local_extra);
        out.extend_from_slice(&entry.data);
    }

    out.extend_from_slice(&layout.before_cd);

    let cd_offset = out.len() as u64;
    for (entry, offset) in entries.iter().zip(offsets) {
        out.extend_from_slice(b"PK\x01\x02");
        put_u16(&mut out, 20); // version made by
        put_u16(&mut out, 20); // version needed
        put_u16(&mut out, entry.flags);
        put_u16(&mut out, entry.method);
        put_u16(&mut out, 0); // time
        put_u16(&mut out, 0); // date
        put_u32(&mut out, entry.crc32);
        put_u32(&mut out, entry.compressed_size);
        put_u32(&mut out, entry.uncompressed_size);
        put_u16(&mut out, entry.name.len() as u16);
        put_u16(&mut out, entry.extra.len() as u16);
        put_u16(&mut out, 0); // comment length
        put_u16(&mut out, 0); // disk number
        put_u16(&mut out, 0); // internal attributes
        put_u32(&mut out, 0); // external attributes
        put_u32(
            &mut out,
            (offset as i64).wrapping_add(entry.offset_delta) as u32,
        );
        out.extend_from_slice(&entry.name);
        out.extend_from_slice(&entry.extra);
    }
    let cd_size = out.len() as u64 - cd_offset;

    out.extend_from_slice(&layout.after_cd);

    let total_entries = layout.total_entries.unwrap_or(entries.len() as u16);
    let cd_size = (cd_size as i64).wrapping_add(layout.cd_size_delta) as u64;
    let cd_offset = (cd_offset as i64).wrapping_add(layout.cd_offset_delta) as u64;

    if layout.zip64 {
        let record_offset = out.len() as u64;
        out.extend_from_slice(b"PK\x06\x06");
        put_u64(&mut out, 44); // size of the rest of the record
        put_u16(&mut out, 45); // version made by
        put_u16(&mut out, 45); // version needed
        put_u32(&mut out, 0); // disk number
        put_u32(&mut out, 0); // disk with the central directory
        put_u64(&mut out, total_entries.into());
        put_u64(&mut out, total_entries.into());
        put_u64(&mut out, cd_size);
        put_u64(&mut out, cd_offset);

        out.extend_from_slice(b"PK\x06\x07");
        put_u32(&mut out, 0); // disk with the ZIP64 EOCD
        put_u64(&mut out, record_offset);
        put_u32(&mut out, 1); // total disks
    }

    out.extend_from_slice(b"PK\x05\x06");
    put_u16(&mut out, 0); // disk number
    put_u16(&mut out, 0); // disk with the central directory
    if layout.zip64 {
        put_u16(&mut out, u16::MAX);
        put_u16(&mut out, u16::MAX);
        put_u32(&mut out, u32::MAX);
        put_u32(&mut out, u32::MAX);
    } else {
        put_u16(&mut out, total_entries);
        put_u16(&mut out, total_entries);
        put_u32(&mut out, cd_size as u32);
        put_u32(&mut out, cd_offset as u32);
    }
    put_u16(&mut out, layout.comment.len() as u16);
    out.extend_from_slice(&layout.comment);

    out
}

/// Wraps the ID-value pairs into an APK Signing Block with consistent sizes.
pub fn signing_block(pairs: &[u8]) -> Vec<u8> {
    let size = (pairs.len() + 8 + 16) as u64;

    let mut block = Vec::with_capacity(pairs.len() + 32);
    put_u64(&mut block, size);
    block.extend_from_slice(pairs);
    put_u64(&mut block, size);
    block.extend_from_slice(ZipEntry::APK_SIGNATURE_MAGIC);
    block
}

#[inline]
fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
