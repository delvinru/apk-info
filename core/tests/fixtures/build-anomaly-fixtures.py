#!/usr/bin/env python3
"""Builds the fixtures of `tests/anomalies.rs`: one structural defect per apk.

Every fixture is the AOSP CTS tinyapp (`v2-only-with-rsa-pkcs1-sha256-2048.apk`
from the zip crate fixtures) repacked with a single change to its zip headers,
manifest or resource table. The output is deterministic: rerun the script
after a change and commit what it writes.

    python3 core/tests/fixtures/build-anomaly-fixtures.py

The fixtures are unsigned: the repack drops the signing block.
"""

import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "anomalies"
BASE = HERE.parents[2] / "crates/zip/tests/fixtures/v2-only-with-rsa-pkcs1-sha256-2048.apk"

STORED, DEFLATED = 0, 8


# ---------------------------------------------------------------- zip writer


@dataclass
class Entry:
    name: bytes
    data: bytes
    method: int = DEFLATED

    # overrides, applied on top of an honest record
    lfh_name: bytes | None = None
    lfh_method: int | None = None
    cd_method: int | None = None
    flags: int = 0
    compressed_size: int | None = None
    cd_offset_delta: int = 0


@dataclass
class Archive:
    entries: list[Entry]
    gap: bytes = b""
    append: bytes = b""
    comment: bytes = b""
    extra_cd: list[Entry] = field(default_factory=list)
    total_entries_delta: int = 0


def deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def build(archive: Archive) -> bytes:
    body = bytearray()
    records = []
    for e in archive.entries + archive.extra_cd:
        payload = deflate(e.data) if e.method == DEFLATED else e.data
        crc = zlib.crc32(e.data)
        offset = len(body)
        lfh_name = e.lfh_name if e.lfh_name is not None else e.name
        lfh_method = e.lfh_method if e.lfh_method is not None else e.method
        compressed = e.compressed_size if e.compressed_size is not None else len(payload)
        if e not in archive.extra_cd:
            body += struct.pack(
                "<IHHHHHIIIHH", 0x04034B50, 20, e.flags, lfh_method, 0, 0x3A21,
                crc, compressed, len(e.data), len(lfh_name), 0,
            )
            body += lfh_name + payload
        cd_method = e.cd_method if e.cd_method is not None else e.method
        records.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, e.flags, cd_method, 0, 0x3A21,
                crc, compressed, len(e.data), len(e.name), 0, 0, 0, 0, 0,
                offset + e.cd_offset_delta,
            )
            + e.name
        )

    cd_offset = len(body)
    body += archive.gap
    honest = records[: len(archive.entries)]
    cd = b"".join(honest)
    extra = b"".join(records[len(archive.entries):])
    count = len(archive.entries) + archive.total_entries_delta
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, count, count, len(cd), cd_offset, len(archive.comment),
    )
    return bytes(body) + cd + extra + eocd + archive.comment + archive.append


# ------------------------------------------------------------- chunk helpers


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def chunks(data: bytes, start: int):
    """Splits a run of resource chunks into raw chunk bytes."""
    out, pos = [], start
    while pos + 8 <= len(data):
        size = u32(data, pos + 4)
        out.append(bytearray(data[pos:pos + size]))
        pos += size
    return out


def set_size(chunk: bytearray):
    struct.pack_into("<I", chunk, 4, len(chunk))


class StringPool:
    UTF8 = 1 << 8

    def __init__(self, chunk: bytes):
        self.flags = u32(chunk, 16)
        count, strings_start = u32(chunk, 8), u32(chunk, 20)
        self.strings = []
        for i in range(count):
            pos = strings_start + u32(chunk, 28 + 4 * i)
            if self.flags & self.UTF8:
                pos += 2 if chunk[pos] & 0x80 else 1
                n = chunk[pos]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | chunk[pos + 1]
                    pos += 1
                pos += 1
                self.strings.append(chunk[pos:pos + n].decode())
            else:
                n = u16(chunk, pos)
                self.strings.append(chunk[pos + 2:pos + 2 + 2 * n].decode("utf-16-le"))

    def add(self, s: str) -> int:
        self.strings.append(s)
        return len(self.strings) - 1

    def encode(self) -> bytearray:
        data, offsets = bytearray(), []
        for s in self.strings:
            offsets.append(len(data))
            if self.flags & self.UTF8:
                raw = s.encode()
                data += bytes([len(s.encode("utf-16-le")) // 2, len(raw)]) + raw + b"\0"
            else:
                raw = s.encode("utf-16-le")
                data += struct.pack("<H", len(raw) // 2) + raw + b"\0\0"
        data += b"\0" * (-len(data) % 4)
        strings_start = 28 + 4 * len(offsets)
        chunk = bytearray(struct.pack(
            "<HHIIIIII", 0x0001, 28, 0, len(offsets), 0, self.flags, strings_start, 0,
        ))
        for o in offsets:
            chunk += struct.pack("<I", o)
        chunk += data
        set_size(chunk)
        return chunk


class Manifest:
    """Binary XML split into the string pool, the resource map and the nodes."""

    def __init__(self, data: bytes):
        parts = chunks(data, 8)
        self.pool = StringPool(parts[0])
        self.resource_map = parts[1]
        self.nodes = parts[2:]

    def encode(self) -> bytes:
        body = self.pool.encode() + self.resource_map + b"".join(self.nodes)
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body

    def elements(self, name: str):
        """Indices of the start element nodes named `name`."""
        index = self.pool.strings.index(name)
        return [
            i for i, n in enumerate(self.nodes)
            if u16(n, 0) == 0x0102 and u32(n, 20) == index
        ]


def attribute(ns: int, name: int, raw: int, data_type: int, data: int) -> bytes:
    return struct.pack("<IIIHBBI", ns, name, raw, 8, 0, data_type, data)


def add_attribute(node: bytearray, attr: bytes):
    count = u16(node, 28)
    struct.pack_into("<H", node, 28, count + 1)
    node += attr
    set_size(node)


class Table:
    """Resource table split into the global string pool and the packages."""

    def __init__(self, data: bytes):
        parts = chunks(data, 12)
        self.pool = parts[0]
        self.packages = parts[1:]
        self.prefix = b""

    def encode(self, package_count=None) -> bytes:
        body = self.prefix + self.pool + b"".join(self.packages)
        count = len(self.packages) if package_count is None else package_count
        return struct.pack("<HHII", 0x0002, 12, 12 + len(body), count) + body

    @staticmethod
    def package_chunks(package: bytes):
        """The package header, then its chunks."""
        header_size = u16(package, 2)
        return package[:header_size], chunks(package, header_size)

    @staticmethod
    def package(header: bytes, parts) -> bytearray:
        package = bytearray(header) + b"".join(parts)
        set_size(package)
        return package


# ------------------------------------------------------------------ fixtures


def base_entries():
    with zipfile.ZipFile(BASE) as z:
        return {name: z.read(name) for name in z.namelist()}


def apk(files: dict, **overrides) -> Archive:
    """A plain repack of `files`, with per-entry overrides by name."""
    entries = []
    for name, data in files.items():
        method = STORED if name == "resources.arsc" else DEFLATED
        entry = Entry(name.encode(), data, method)
        for key, value in overrides.get(name, {}).items():
            setattr(entry, key, value)
        entries.append(entry)
    return Archive(entries)


def zip_fixtures(files):
    yield "clean.apk", build(apk(files))

    yield "zip-compression-method-mismatch.apk", build(
        apk(files, **{"AndroidManifest.xml": {"lfh_method": 0xFFFF}})
    )
    yield "zip-unknown-compression-method.apk", build(
        apk(files, **{"resources.arsc": {"cd_method": 0x1234, "lfh_method": 0x1234}})
    )
    yield "zip-stored-size-mismatch.apk", build(
        apk(files, **{"resources.arsc": {"compressed_size": 0x7FFF}})
    )

    yield "zip-encryption-flag.apk", build(apk(files, **{"classes.dex": {"flags": 1}}))
    yield "zip-entry-path-conflict.apk", build(
        apk({**files, "AndroidManifest.xml/x.png": b"decoy"})
    )
    yield "zip-invalid-utf8-name.apk", build(
        apk({**files, "assets/x": b"payload"},
            **{"assets/x": {"name": b"assets/\xff", "lfh_name": b"assets/\xff"}})
    )
    yield "zip-local-header-shifted.apk", build(
        apk(files, **{"classes.dex": {"cd_offset_delta": 3}})
    )
    yield "zip-local-header-missing.apk", build(
        apk(files, **{"classes.dex": {"lfh_name": b"classes.dey"}})
    )

    archive = apk(files)
    archive.entries.append(Entry(b"classes.dex", b"decoy"))
    yield "zip-duplicate-entry.apk", build(archive)

    archive = apk(files)
    archive.extra_cd.append(Entry(b"AndroidManifest.xml", b"DECOY"))
    yield "zip-extra-central-directory-record.apk", build(archive)

    archive = apk(files)
    archive.total_entries_delta = 1
    yield "zip-missing-central-directory-record.apk", build(archive)

    archive = apk(files)
    archive.append = b"\0" * 64
    yield "zip-eocd-not-at-end.apk", build(archive)

    # data between the entries and the directory, the end record not updated
    archive = apk(files)
    archive.gap = b"\0" * 64
    yield "zip-central-directory-shifted.apk", build(archive)

    # the planted signature sits in the last 21 bytes, where no real record fits
    archive = apk(files)
    archive.comment = b"\0" * 8 + b"PK\x05\x06" + b"\0" * 8
    yield "zip-fake-eocd-in-comment.apk", build(archive)


def manifest_fixtures(files):
    def with_manifest(edit):
        manifest = Manifest(files["AndroidManifest.xml"])
        edit(manifest)
        return build(apk({**files, "AndroidManifest.xml": manifest.encode()}))

    def decoy_name(m):
        # `android:name` as plain text next to the real one (a protector trick)
        [activity] = m.elements("activity")
        name = m.pool.add("android:name")
        value = m.pool.add("com.example.Decoy")
        add_attribute(m.nodes[activity], attribute(0xFFFFFFFF, name, value, 0x03, value))

    def garbage_attribute_name(m):
        [activity] = m.elements("activity")
        name = m.pool.add("@garbage/name")
        add_attribute(m.nodes[activity], attribute(0xFFFFFFFF, name, name, 0x03, name))

    def garbage_element_name(m):
        [category] = m.elements("category")
        name = m.pool.add("1nvalid element")
        struct.pack_into("<I", m.nodes[category], 20, name)
        # the end element keeps its name: the tree is matched by nesting

    def string_count(m):
        pool = m.pool.encode()
        struct.pack_into("<I", pool, 8, u32(pool, 8) + 5)
        m.pool.encode = lambda: pool

    def attribute_layout(m):
        # attributes start 4 bytes late and take 24 bytes each
        [activity] = m.elements("activity")
        node = m.nodes[activity]
        count = u16(node, 28)
        attrs = [node[36 + 20 * i: 56 + 20 * i] for i in range(count)]
        new = bytearray(node[:36]) + b"\xAA" * 4 + b"".join(a + b"\xBB" * 4 for a in attrs)
        struct.pack_into("<HH", new, 24, 0x18, 0x18)
        set_size(new)
        m.nodes[activity] = new

    def trailing_bytes(m):
        [activity] = m.elements("activity")
        m.nodes[activity] += b"\xCC" * 8
        set_size(m.nodes[activity])

    def node_header_size(m):
        m.nodes.insert(0, bytearray(struct.pack("<HHI", 0x0104, 0x08, 16) + b"\0" * 8))

    def non_xml_chunk(m):
        # a run of three: one anomaly
        for _ in range(3):
            m.nodes.insert(0, bytearray(struct.pack("<HHI", 0xFF00, 0x10, 16) + b"\0" * 8))

    def unclosed(m):
        # drop the end of `<category>`: `</intent-filter>` then closes it
        [category] = m.elements("category")
        del m.nodes[category + 1]

    def truncated(m):
        [activity] = m.elements("activity")
        m.nodes[activity:] = [m.nodes[activity][:30]]

    yield "manifest-decoy-attribute-name.apk", with_manifest(decoy_name)
    yield "manifest-invalid-attribute-name.apk", with_manifest(garbage_attribute_name)
    yield "manifest-invalid-element-name.apk", with_manifest(garbage_element_name)
    yield "manifest-string-count-mismatch.apk", with_manifest(string_count)
    yield "manifest-attribute-layout.apk", with_manifest(attribute_layout)
    yield "manifest-element-trailing-bytes.apk", with_manifest(trailing_bytes)
    yield "manifest-xml-node-header-size.apk", with_manifest(node_header_size)
    yield "manifest-non-xml-chunk.apk", with_manifest(non_xml_chunk)
    yield "manifest-unclosed-elements.apk", with_manifest(unclosed)
    yield "manifest-truncated.apk", with_manifest(truncated)


def resources_fixtures(files):
    def with_table(edit, package_count=None):
        table = Table(files["resources.arsc"])
        edit(table)
        return build(apk({**files, "resources.arsc": table.encode(package_count)}))

    def garbage_chunk(t):
        t.prefix = struct.pack("<HHI", 0x7777, 8, 16) + b"\0" * 8

    def duplicate_package(t):
        t.packages.append(bytearray(t.packages[0]))

    def entries_out_of_bounds(t):
        header, parts = Table.package_chunks(t.packages[0])
        for part in parts:
            if u16(part, 0) == 0x0201:
                struct.pack_into("<I", part, 12, 0x0FFFFFFF)
                break
        t.packages[0] = Table.package(header, parts)

    def duplicate_type(t):
        header, parts = Table.package_chunks(t.packages[0])
        i = next(i for i, p in enumerate(parts) if u16(p, 0) == 0x0201)
        parts.insert(i + 1, bytearray(parts[i]))
        t.packages[0] = Table.package(header, parts)

    def truncated(t):
        t.packages[0] = t.packages[0][: len(t.packages[0]) // 2]

    def package_header_size(t):
        # 4 bytes more than the newest layout, skipped by the parser
        header, parts = Table.package_chunks(t.packages[0])
        header = bytearray(header) + b"\0" * 4
        struct.pack_into("<H", header, 2, len(header))
        t.packages[0] = Table.package(header, parts)

    yield "resources-string-pool-garbage-chunk.apk", with_table(garbage_chunk)
    yield "resources-duplicate-package-id.apk", with_table(duplicate_package)
    yield "resources-type-entries-out-of-bounds.apk", with_table(entries_out_of_bounds)
    yield "resources-duplicate-type-chunk.apk", with_table(duplicate_type)
    yield "resources-unreadable.apk", with_table(truncated)
    yield "resources-package-header-size.apk", with_table(package_header_size)


def container_fixtures(files):
    base = build(apk(files))
    yield "container-guessed-base.xapk", build(
        Archive([Entry(b"app.apk", base, STORED)])
    )
    yield "container-tampered-base.apkm", build(
        Archive([
            Entry(
                b"base.apk",
                build(apk(files, **{"classes.dex": {"flags": 1}})),
                STORED,
            ),
        ])
    )
    yield "container-root-manifest-garbage.xapk", build(
        Archive([
            Entry(b"AndroidManifest.xml", b"\x03\x00\x08\x00garbage!"),
            Entry(b"base.apk", base, STORED),
        ])
    )


def main():
    files = base_entries()
    OUT.mkdir(exist_ok=True)
    for old in OUT.iterdir():
        old.unlink()
    for group in (zip_fixtures, manifest_fixtures, resources_fixtures, container_fixtures):
        for name, data in group(files):
            (OUT / name).write_bytes(data)
            print(f"{len(data):6} {name}")


if __name__ == "__main__":
    main()
