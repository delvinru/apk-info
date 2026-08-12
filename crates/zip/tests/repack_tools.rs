//! Integration tests that validate the archives produced by [`ZipEntry::repack`]
//! against real command-line zip tools available on the host (`zip`, `7zz`).
//!
//! These tests are skipped (with a message) when the required tool is not
//! installed, so they stay green on machines without the tooling.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use apk_info_zip::ZipEntry;

/// A private scratch directory unique to this test binary.
fn tmp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("apk_info_zip_tools_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// True if `tool` can be spawned (i.e. is on `$PATH` and executable).
fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Content files written into the fixture archive.
const FILES: &[(&str, &[u8])] = &[
    ("hello.txt", b"hello world!"),
    ("AndroidManifest.xml", b"<manifest xmlns=\"android\"/>"),
    // low-entropy binary payload exercising the deflate path
    (
        "bin.dat",
        &[0u8, 1, 2, 3, 254, 255, 128, 7, 0, 1, 2, 3, 4, 5, 6, 7],
    ),
];

/// Builds a `source.zip` in `dir` using the host `zip` tool and returns its path.
fn build_source_zip(dir: &Path) -> PathBuf {
    for (name, data) in FILES {
        fs::write(dir.join(name), data).unwrap();
    }
    let status = Command::new("zip")
        .current_dir(dir)
        .args(["-q", "source.zip"])
        .args(FILES.iter().map(|(name, _)| *name))
        .status()
        .unwrap();
    assert!(
        status.success(),
        "host `zip` failed to create the fixture archive"
    );
    dir.join("source.zip")
}

/// Repacks a source archive produced by the host and checks the result against
/// the host `zip` and `7zz` tools.
#[test]
fn repack_passes_host_zip_tools() {
    let zip_ok = tool_available("zip");
    let sevenzip_ok = tool_available("7zz");
    if !zip_ok && !sevenzip_ok {
        eprintln!("skipping: neither `zip` nor `7zz` is available on this host");
        return;
    }
    if !zip_ok {
        eprintln!("note: `zip` not available, skipping `zip -T` check");
    }
    if !sevenzip_ok {
        eprintln!("note: `7zz` not available, skipping `7zz` checks");
    }

    let dir = tmp_dir();
    let source = build_source_zip(&dir);

    // Feed a real tool-produced archive through our parser + writer.
    let zip = ZipEntry::new(fs::read(&source).unwrap()).unwrap();
    let repacked = zip.repack().unwrap();
    let repacked_file = dir.join("repacked.zip");
    fs::write(&repacked_file, repacked).unwrap();

    // Info-ZIP integrity check: `zip -T` verifies the archive and every CRC.
    if zip_ok {
        let status = Command::new("zip")
            .arg("-T")
            .arg(&repacked_file)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "host `zip -T` reported the repacked archive as invalid"
        );
    }

    if sevenzip_ok {
        // 7-Zip test: verifies structure and CRC of every entry.
        let status = Command::new("7zz")
            .arg("t")
            .arg(&repacked_file)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "host `7zz t` reported the repacked archive as invalid"
        );

        // 7-Zip extract: verify every entry's content roundtrips exactly.
        let extract_dir = dir.join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        let status = Command::new("7zz")
            .args(["x", "-y"])
            .arg(&repacked_file)
            .arg(format!("-o{}", extract_dir.display()))
            .status()
            .unwrap();
        assert!(
            status.success(),
            "host `7zz x` failed to extract the repacked archive"
        );

        for (name, data) in FILES {
            assert_eq!(
                &fs::read(extract_dir.join(name)).unwrap(),
                data,
                "extracted `{name}` differs from the source content"
            );
        }
    }
}

/// Ensures the repacked archive our own parser produces is also consumable by
/// our own reader after surviving the host tools (structural sanity on top of
/// the roundtrip unit tests).
#[test]
fn repacked_archive_is_self_consistent() {
    // Only meaningful if we can build a source archive from the host.
    if !tool_available("zip") {
        eprintln!("skipping: `zip` not available on this host");
        return;
    }

    let dir = tmp_dir();
    let source = build_source_zip(&dir);
    let zip = ZipEntry::new(fs::read(&source).unwrap()).unwrap();

    let repacked = zip.repack().unwrap();
    let reparsed = ZipEntry::new(repacked).unwrap();

    let mut names: Vec<_> = reparsed.namelist().collect();
    names.sort();
    let mut expected: Vec<_> = FILES.iter().map(|(name, _)| *name).collect();
    expected.sort();
    assert_eq!(names, expected);

    for (name, data) in FILES {
        assert_eq!(&reparsed.read(name).unwrap().0, data);
    }
}
