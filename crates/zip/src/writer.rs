//! Implementation of a minimal zip writer used to rebuild archives from the
//! parsed contents of a [`ZipEntry`].
//!
//! The main purpose is to "repack" archives damaged using the `BadPack`
//! technique: read every entry exactly as [`ZipEntry::read`] decodes it (which
//! correctly handles tampered compression headers) and write the data back into
//! a fresh, well-formed zip archive that standard tools (`unzip`, `7z`, ...) can
//! parse without failing.

use std::io::Write;

use flate2::Compression;
use flate2::write::DeflateEncoder;

use crate::ZipEntry;

/// Magic signatures used by the zip format.
mod signature {
    pub const LOCAL_FILE_HEADER: u32 = 0x04034b50;
    pub const CENTRAL_DIRECTORY_FILE_HEADER: u32 = 0x02014b50;
    pub const END_OF_CENTRAL_DIRECTORY: u32 = 0x06054b50;
}

/// Fixed byte length of a local file header, before the file name.
///
/// `4 + 6*2 + 3*4 + 4*2 = 30`. Used both to write the header and to advance
/// the local-header offset, so a change to the layout must update it here.
const LOCAL_HEADER_LEN: u32 = 30;

/// Fixed byte length of a central directory file header, before the file name.
///
/// `4 + 11*2 + 2*4 + 2*2 - ... = 46`. Used to preallocate the central directory.
const CENTRAL_HEADER_LEN: u32 = 46;

/// Minimal little-endian header builder.
///
/// The write order mirrors the on-disk zip layout field by field, so the
/// header structure is readable directly from the call site.
struct LE<'a>(&'a mut Vec<u8>);

impl<'a> LE<'a> {
    fn u16(self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn u32(self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
}

/// Writes a local file header and its file name.
#[allow(clippy::too_many_arguments)]
fn write_local_header(
    out: &mut Vec<u8>,
    name: &[u8],
    crc: u32,
    csize: u32,
    usize_: u32,
    method: u16,
) {
    LE(out)
        .u32(signature::LOCAL_FILE_HEADER)
        .u16(20) // version needed to extract
        .u16(0) // general purpose bit flag
        .u16(method) // compression method
        .u16(0) // last mod time
        .u16(0x21) // last mod date
        .u32(crc)
        .u32(csize)
        .u32(usize_)
        .u16(name.len() as u16) // file name length
        .u16(0); // extra field length
    out.extend_from_slice(name);
}

/// Writes a central directory file header and its file name.
#[allow(clippy::too_many_arguments)]
fn write_central_header(
    cd: &mut Vec<u8>,
    name: &[u8],
    offset: u32,
    crc: u32,
    csize: u32,
    usize_: u32,
    method: u16,
) {
    LE(cd)
        .u32(signature::CENTRAL_DIRECTORY_FILE_HEADER)
        .u16(20) // version made by
        .u16(20) // version needed to extract
        .u16(0) // general purpose bit flag
        .u16(method) // compression method
        .u16(0) // last mod time
        .u16(0x21) // last mod date
        .u32(crc)
        .u32(csize)
        .u32(usize_)
        .u16(name.len() as u16) // file name length
        .u16(0) // extra field length
        .u16(0) // file comment length
        .u16(0) // disk number start
        .u16(0) // internal file attributes
        .u32(0) // external file attributes
        .u32(offset); // local header offset
    cd.extend_from_slice(name);
}

impl ZipEntry {
    /// Rebuilds the archive as a fresh, well-formed zip archive.
    ///
    /// Every entry is decoded with [`ZipEntry::read`] and then written back using `Deflate`
    /// compression, with correct naming, sizes and CRC32 checksums.
    /// The result is a valid zip archive that standard tools can parse.
    ///
    /// # Notes
    ///
    /// - The rebuilt archive is **not signed**: v1 signature files under
    ///   `META-INF/` and the APK Signature Block (v2/v3/stamp/channel blocks)
    ///   are not reproduced.
    /// - Directory entries (names ending with `/`) are skipped.
    ///
    /// # Errors
    ///
    /// Returns a [ZipError] if an entry cannot be read out: [ZipError::FileNotFound]
    /// if it cannot be located, [ZipError::EOF] if its data can't be sliced out,
    /// or [ZipError::DecompressionError] if it fails to decode.
    pub fn repack(&self) -> Result<Vec<u8>, crate::ZipError> {
        let names = self.namelist().count();

        let mut output: Vec<u8> = Vec::new();

        // Preallocate the central directory: each entry needs one fixed
        // CENTRAL_HEADER_LEN header before its filename.
        let mut central_directory: Vec<u8> =
            Vec::with_capacity(names * CENTRAL_HEADER_LEN as usize);

        // local file header offset of the current entry
        let mut offset = 0u32;
        let mut count = 0u16;

        for name in self.namelist() {
            // skip directory entries and entries with dangerous names
            if name.ends_with('/') || name.is_empty() {
                continue;
            }

            let data = self.read(name)?.0;
            let crc32 = crc32fast::hash(&data);
            let (compressed, uncompressed) = deflate(&data);

            write_local_header(
                &mut output,
                name.as_bytes(),
                crc32,
                compressed.len() as u32,
                uncompressed,
                8, // deflate
            );
            output
                .write_all(&compressed)
                .expect("write to Vec can't fail");

            write_central_header(
                &mut central_directory,
                name.as_bytes(),
                offset,
                crc32,
                compressed.len() as u32,
                uncompressed,
                8, // deflate
            );

            offset += LOCAL_HEADER_LEN + name.len() as u32 + compressed.len() as u32;
            count += 1;
        }

        // --- end of central directory record ---
        let central_dir_offset = output.len() as u32;
        output
            .write_all(&central_directory)
            .expect("write to Vec can't fail");
        LE(&mut output)
            .u32(signature::END_OF_CENTRAL_DIRECTORY)
            .u16(0) // disk number
            .u16(0) // disk with central directory
            .u16(count) // entries on this disk
            .u16(count) // total entries
            .u32(central_directory.len() as u32) // central directory size
            .u32(central_dir_offset) // central directory offset
            .u16(0); // comment length

        Ok(output)
    }
}

/// Deflates `data`, returning `(compressed, original_len)`.
fn deflate(data: &[u8]) -> (Vec<u8>, u32) {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .expect("write to encoder can't fail");
    let compressed = encoder.finish().expect("finish can't fail");
    (compressed, data.len() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileCompressionType;

    /// Builds a minimal zip archive. `hello.txt` is stored (method 0),
    /// `AndroidManifest.xml` is deflated (method 8).
    fn build_test_zip() -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        let mut offset: u32 = 0;

        let files: &[(&[u8], &[u8], u16)] = &[
            (b"hello.txt", b"hello world!", 0),
            (b"AndroidManifest.xml", b"<manifest/>", 8),
        ];

        for (name, data, method) in files {
            // data written to the archive (already compressed if needed)
            let payload = if *method == 0 {
                data.to_vec()
            } else {
                deflate(data).0
            };
            let crc = crc32fast::hash(data);

            write_local_header(
                &mut out,
                name,
                crc,
                payload.len() as u32,
                data.len() as u32,
                *method,
            );
            out.extend_from_slice(&payload);

            write_central_header(
                &mut cd,
                name,
                offset,
                crc,
                payload.len() as u32,
                data.len() as u32,
                *method,
            );

            offset += LOCAL_HEADER_LEN + name.len() as u32 + payload.len() as u32;
        }

        out.extend_from_slice(&cd);
        LE(&mut out)
            .u32(signature::END_OF_CENTRAL_DIRECTORY)
            .u16(0)
            .u16(0)
            .u16(files.len() as u16)
            .u16(files.len() as u16)
            .u32(cd.len() as u32)
            .u32(offset)
            .u16(0);

        out
    }

    #[test]
    fn header_lengths_match_consts() {
        // Guard against silent drift if a header field is added or removed:
        // the writer and the offset arithmetic in repack both rely on
        // LOCAL_HEADER_LEN / CENTRAL_HEADER_LEN staying in sync.
        let mut v = Vec::new();
        write_local_header(&mut v, b"x", 0, 0, 0, 8);
        assert_eq!(
            v.len() as u32,
            LOCAL_HEADER_LEN + 1,
            "update LOCAL_HEADER_LEN"
        );

        let mut c = Vec::new();
        write_central_header(&mut c, b"x", 0, 0, 0, 0, 8);
        assert_eq!(
            c.len() as u32,
            CENTRAL_HEADER_LEN + 1,
            "update CENTRAL_HEADER_LEN"
        );
    }

    #[test]
    fn repack_roundtrip_preserves_data() {
        let original = build_test_zip();
        let zip = ZipEntry::new(original).unwrap();

        let repacked = zip.repack().unwrap();
        let reparsed = ZipEntry::new(repacked).unwrap();

        // same set of files
        let mut names: Vec<_> = reparsed.namelist().collect();
        names.sort();
        assert_eq!(names, vec!["AndroidManifest.xml", "hello.txt"]);

        // data preserved exactly
        assert_eq!(reparsed.read("hello.txt").unwrap().0, b"hello world!");
        assert_eq!(
            reparsed.read("AndroidManifest.xml").unwrap().0,
            b"<manifest/>"
        );
    }

    #[test]
    fn repack_output_is_wellformed() {
        let zip = ZipEntry::new(build_test_zip()).unwrap();
        let repacked = zip.repack().unwrap();

        // reparsing proves the EOCD, central directory and local headers are valid
        assert!(ZipEntry::new(repacked).is_ok());
    }

    #[test]
    fn repack_normalizes_tampered_entry() {
        let mut original = build_test_zip();

        // Corrupt the first local file header's compression method to a bogus value,
        // mimicking the BadPack technique. The central directory still references it.
        // Local header starts at 0; method field is at offset 8 (after magic+version+flags).
        assert_eq!(&original[0..4], &0x04034b50u32.to_le_bytes()[..]);
        original[8..10].copy_from_slice(&55914u16.to_le_bytes());
        // make compressed size == uncompressed size so the reader treats it as StoredTampered
        original[18..22].copy_from_slice(&12u32.to_le_bytes());

        let zip = ZipEntry::new(original.clone()).unwrap();
        let (_, compression) = zip.read("hello.txt").unwrap();
        assert_eq!(compression, FileCompressionType::StoredTampered);

        // repack must produce a clean, valid archive with intact data
        let repacked = zip.repack().unwrap();
        assert!(ZipEntry::new(repacked.clone()).is_ok());

        let reparsed = ZipEntry::new(repacked).unwrap();
        assert_eq!(reparsed.read("hello.txt").unwrap().0, b"hello world!");
    }
}
