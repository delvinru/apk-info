#![no_main]

//! Builds archives from a structured description, so mutations land on the
//! header inconsistencies BadPack relies on instead of on offsets that never
//! line up. An archive built without any of them is also checked against its
//! known content.

use std::collections::HashSet;

use apk_info_fuzz::{Layout, RawEntry, build_zip, exercise_zip, signing_block};
use apk_info_zip::{FileCompressionType, ZipEntry};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Archive {
    entries: Vec<Entry>,
    signing_block: Option<Vec<u8>>,
    before_cd: Vec<u8>,
    after_cd: Vec<u8>,
    comment: Comment,
    eocd: Option<EocdTamper>,
    zip64: bool,
}

#[derive(Arbitrary, Debug)]
struct Entry {
    name: Name,
    content: Content,
    deflate: bool,
    tampers: Vec<Tamper>,
}

#[derive(Arbitrary, Debug)]
enum Name {
    Manifest,
    Resources,
    Dex,
    BaseApk,
    Directory,
    SignatureFile,
    SignatureBlock,
    Text(String),
    Raw(Vec<u8>),
}

impl Name {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Name::Manifest => b"AndroidManifest.xml".to_vec(),
            Name::Resources => b"resources.arsc".to_vec(),
            Name::Dex => b"classes.dex".to_vec(),
            Name::BaseApk => b"base.apk".to_vec(),
            Name::Directory => b"res/".to_vec(),
            Name::SignatureFile => b"META-INF/CERT.SF".to_vec(),
            Name::SignatureBlock => b"META-INF/CERT.RSA".to_vec(),
            Name::Text(name) => name.as_bytes().to_vec(),
            Name::Raw(name) => name.clone(),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Content {
    Bytes(Vec<u8>),
    /// An inner archive of stored entries, like the splits of an xapk.
    Archive(Vec<(String, Vec<u8>)>),
}

impl Content {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Content::Bytes(data) => data.clone(),
            Content::Archive(files) => {
                let entries: Vec<RawEntry> = files
                    .iter()
                    .map(|(name, data)| RawEntry::stored(name.as_bytes(), data))
                    .collect();
                build_zip(&entries, &Layout::default())
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Tamper {
    Method(u16),
    LocalMethod(u16),
    Sizes {
        compressed: u32,
        uncompressed: u32,
    },
    LocalSizes {
        compressed: u32,
        uncompressed: u32,
    },
    LocalName(Vec<u8>),
    Flags(u16),
    Crc(u32),
    Extra(Vec<u8>),
    LocalExtra(Vec<u8>),
    Offset(i16),
    /// Cuts the entry data short, keeping the declared sizes.
    Truncate(u16),
}

impl Tamper {
    fn apply(&self, entry: &mut RawEntry) {
        match self {
            Tamper::Method(method) => entry.method = *method,
            Tamper::LocalMethod(method) => entry.local_method = *method,
            Tamper::Sizes {
                compressed,
                uncompressed,
            } => {
                entry.compressed_size = *compressed;
                entry.uncompressed_size = *uncompressed;
            }
            Tamper::LocalSizes {
                compressed,
                uncompressed,
            } => {
                entry.local_compressed_size = *compressed;
                entry.local_uncompressed_size = *uncompressed;
            }
            Tamper::LocalName(name) => entry.local_name = name.clone(),
            Tamper::Flags(flags) => entry.flags = *flags,
            Tamper::Crc(crc) => entry.crc32 = *crc,
            Tamper::Extra(extra) => entry.extra = extra.clone(),
            Tamper::LocalExtra(extra) => entry.local_extra = extra.clone(),
            Tamper::Offset(delta) => entry.offset_delta = (*delta).into(),
            Tamper::Truncate(len) => entry.data.truncate((*len).into()),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Comment {
    Empty,
    Bytes(Vec<u8>),
    /// A second EOCD record inside the comment, as in BadPack samples.
    FakeEocd {
        total_entries: u16,
        cd_size: u32,
        cd_offset: u32,
        tail: Vec<u8>,
    },
}

impl Comment {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Comment::Empty => Vec::new(),
            Comment::Bytes(data) => data.clone(),
            Comment::FakeEocd {
                total_entries,
                cd_size,
                cd_offset,
                tail,
            } => {
                let mut out = b"PK\x05\x06\x00\x00\x00\x00".to_vec();
                out.extend_from_slice(&total_entries.to_le_bytes());
                out.extend_from_slice(&total_entries.to_le_bytes());
                out.extend_from_slice(&cd_size.to_le_bytes());
                out.extend_from_slice(&cd_offset.to_le_bytes());
                out.extend_from_slice(&(tail.len() as u16).to_le_bytes());
                out.extend_from_slice(tail);
                out
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
struct EocdTamper {
    total_entries: Option<u16>,
    cd_size_delta: i32,
    cd_offset_delta: i32,
}

fuzz_target!(|archive: Archive| {
    let mut entries = Vec::with_capacity(archive.entries.len());
    let mut expected = Vec::new();

    for entry in &archive.entries {
        let name = entry.name.bytes();
        let content = entry.content.bytes();

        let mut raw = RawEntry::deflated(&name, &content);
        // a deflated entry of the same size as its content reads as stored
        // tampered by design, so it is written stored instead
        if !entry.deflate || raw.data.len() == content.len() {
            raw = RawEntry::stored(&name, &content);
        }
        for tamper in &entry.tampers {
            tamper.apply(&mut raw);
        }

        if entry.tampers.is_empty() {
            expected.push((name, content));
        }
        entries.push(raw);
    }

    let mut before_cd = archive.before_cd.clone();
    if let Some(pairs) = &archive.signing_block {
        before_cd.extend_from_slice(&signing_block(pairs));
    }

    let comment = archive.comment.bytes();
    let layout = Layout {
        before_cd,
        after_cd: archive.after_cd.clone(),
        comment: comment.clone(),
        total_entries: archive.eocd.as_ref().and_then(|eocd| eocd.total_entries),
        cd_size_delta: archive
            .eocd
            .as_ref()
            .map_or(0, |eocd| eocd.cd_size_delta.into()),
        cd_offset_delta: archive
            .eocd
            .as_ref()
            .map_or(0, |eocd| eocd.cd_offset_delta.into()),
        zip64: archive.zip64,
    };

    let data = build_zip(&entries, &layout);
    let zip = ZipEntry::new(data);

    // without any inconsistency, every entry must read back as written; an
    // archive without entries doesn't start with a local header, so it's rejected
    let names: HashSet<&[u8]> = expected.iter().map(|(name, _)| name.as_slice()).collect();
    let honest = !entries.is_empty()
        && expected.len() == entries.len()
        && names.len() == entries.len()
        && expected
            .iter()
            .all(|(name, _)| !name.is_empty() && std::str::from_utf8(name).is_ok())
        && archive.eocd.is_none()
        && !comment.windows(4).any(|w| w == b"PK\x05\x06");

    if honest {
        let zip = zip.as_ref().expect("an honest archive must parse");
        assert_eq!(zip.namelist().count(), entries.len());

        for (name, content) in &expected {
            let name = std::str::from_utf8(name).unwrap();
            let (data, kind) = zip
                .read(name)
                .unwrap_or_else(|err| panic!("failed to read {name:?}: {err}"));
            assert_eq!(&data, content, "wrong content of {name:?}");
            assert!(
                matches!(
                    kind,
                    FileCompressionType::Stored | FileCompressionType::Deflated
                ),
                "{name:?} reported as {kind:?}"
            );

            let info = zip.entry_info(name).expect("entry info of an honest entry");
            assert!(!info.tampered, "{name:?} reported as tampered");
        }
    }

    if let Ok(zip) = zip {
        exercise_zip(&zip);
    }
});
