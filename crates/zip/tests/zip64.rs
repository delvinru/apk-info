//! ZIP64 archives: 64-bit sizes and offsets in the central directory extra
//! field, and the ZIP64 end of central directory record and locator.
//!
//! The archives are small, every 32-bit field is saturated on purpose, so
//! the real values can only come from the ZIP64 structures.

use apk_info_zip::{FileCompressionType, ZipEntry};

const MAX32: u32 = u32::MAX;

/// Builds a stored archive where every size, offset and count lives only in
/// the ZIP64 structures. `prefix` is prepended to the archive without
/// adjusting any offset, like a polyglot or a self-extracting stub.
fn zip64_archive(files: &[(&str, &[u8])], prefix: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central_directory = Vec::new();

    for (name, data) in files {
        let offset = out.len() as u64;
        let size = data.len() as u64;
        let crc = crc32(data);

        // local header: sizes in its own ZIP64 extra field
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes()); // version needed
        out.extend_from_slice(&[0u8; 8]); // flags, method, time, date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&MAX32.to_le_bytes()); // csize
        out.extend_from_slice(&MAX32.to_le_bytes()); // usize
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(data);

        // central directory record: all three fields saturated
        central_directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central_directory.extend_from_slice(&45u16.to_le_bytes()); // version made by
        central_directory.extend_from_slice(&45u16.to_le_bytes()); // version needed
        central_directory.extend_from_slice(&[0u8; 8]); // flags, method, time, date
        central_directory.extend_from_slice(&crc.to_le_bytes());
        central_directory.extend_from_slice(&MAX32.to_le_bytes());
        central_directory.extend_from_slice(&MAX32.to_le_bytes());
        central_directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central_directory.extend_from_slice(&28u16.to_le_bytes()); // extra len
        central_directory.extend_from_slice(&[0u8; 10]); // comment, disk, attrs
        central_directory.extend_from_slice(&MAX32.to_le_bytes()); // local header offset
        central_directory.extend_from_slice(name.as_bytes());
        central_directory.extend_from_slice(&1u16.to_le_bytes());
        central_directory.extend_from_slice(&24u16.to_le_bytes());
        central_directory.extend_from_slice(&size.to_le_bytes()); // uncompressed
        central_directory.extend_from_slice(&size.to_le_bytes()); // compressed
        central_directory.extend_from_slice(&offset.to_le_bytes()); // local header
    }

    let cd_offset = out.len() as u64;
    out.extend_from_slice(&central_directory);

    // ZIP64 end of central directory record
    let record_offset = out.len() as u64;
    out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
    out.extend_from_slice(&44u64.to_le_bytes()); // size of the rest of the record
    out.extend_from_slice(&45u16.to_le_bytes()); // version made by
    out.extend_from_slice(&45u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u32.to_le_bytes()); // disk
    out.extend_from_slice(&0u32.to_le_bytes()); // cd disk
    out.extend_from_slice(&(files.len() as u64).to_le_bytes());
    out.extend_from_slice(&(files.len() as u64).to_le_bytes());
    out.extend_from_slice(&(central_directory.len() as u64).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());

    // ZIP64 end of central directory locator
    out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // disk
    out.extend_from_slice(&record_offset.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // total disks

    // end of central directory: every field saturated
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // disk numbers
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&MAX32.to_le_bytes());
    out.extend_from_slice(&MAX32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    let mut archive = prefix.to_vec();
    archive.extend(out);
    archive
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

const FILES: &[(&str, &[u8])] = &[
    ("manifest.json", b"{}"),
    ("base.apk", b"not really an apk"),
    ("config.ru.apk", b"split"),
];

fn assert_files(zip: &ZipEntry) {
    assert_eq!(
        zip.namelist().collect::<Vec<_>>(),
        ["manifest.json", "base.apk", "config.ru.apk"]
    );

    for (name, data) in FILES {
        let (read, compression) = zip.read(name).unwrap();
        assert_eq!(read, *data, "{name}");
        assert_eq!(compression, FileCompressionType::Stored);

        let info = zip.entry_info(name).unwrap();
        assert_eq!(info.uncompressed_size, data.len() as u64);
        assert_eq!(info.compressed_size, data.len() as u64);
    }
}

#[test]
fn zip64_sizes_offsets_and_counts_are_used() {
    let zip = ZipEntry::new(zip64_archive(FILES, b"")).unwrap();
    assert_files(&zip);
}

/// Prepended data makes every declared offset stale: the ZIP64 record is
/// found right before the locator, and the CD right before the record.
#[test]
fn zip64_with_prepended_data() {
    let mut archive = zip64_archive(FILES, b"");
    archive.splice(0..0, *b"PK\x03\x04 prepended stub ");
    // the local header offsets are stale too, the self-healing scan finds them
    let zip = ZipEntry::new(archive).unwrap();
    assert_files(&zip);
}
