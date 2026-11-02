# Anomalies

`anomalies()` lists the structural defects of an APK, and `is_tampered()` tells whether any of them is rated `tampered`. On the command line, `apk-info show --anomalies` prints them. This page explains the ratings and lists every anomaly. For examples, see [Malformed APKs](../guides/malformed-apks.md#checking-an-apk-for-tampering).

Each anomaly has:

| Field | Description |
|---|---|
| `code` | stable identifier, e.g. `compression_method_mismatch` |
| `severity` | `tampered`, `suspicious` or `info` |
| `location` | an entry name (`classes.dex`), an entry of a container's base APK (`base.apk!classes.dex`), or none for the archive itself |
| `detail` | a human-readable description; in Rust, the `Display` of the anomaly |

## Severities

The parsers report facts: "the local header says method 55914, the central directory says 8". The severity is a separate judgment of what the fact means. It answers one question: could an ordinary build produce this?

### `tampered`

A known technique against static analysis tools. No build tool produces it: someone edited the file to break or mislead `unzip`, `apktool`, `androguard` and similar tools.

To be rated `tampered`, an anomaly must:

- never show up in clean apps: the collection of 5,714 store apps from the [Benchmarks](../benchmarks.md#collections) has no `tampered` anomaly;
- break or mislead another parser, e.g. hide the manifest, crash the decoder or show a different class name.

`tampered` doesn't mean that Android installs the file. Some of these tricks, like an unknown compression method or a name that isn't UTF-8, make Android reject the APK. They still mean the file was edited by hand, which is what triage needs to know.

### `suspicious`

Unusual, but with an innocent explanation besides tampering:

- plain corruption: a truncated download, a flipped bit, a broken repack of a modded app;
- an exotic build tool or a commercial protector, as used by some clean apps.

A `suspicious` anomaly alone doesn't make `is_tampered()` true. Look at the rest of the file before drawing a conclusion.

### `info`

A quirk that ordinary build tools produce too. It is listed for completeness and says nothing about tampering.

## Calibration

The ratings come from scans of four collections:

| Collection | Files | With a `tampered` anomaly |
|---|---|---|
| Clean store apps, see [Benchmarks](../benchmarks.md#collections) | 5,714 | 0 |
| VirusShare Android, 2020–2022 | 23,745 | 24 |
| Recent samples, 2026 | 223 | 66 |
| Recent samples, 2026 | 200 | 107 |

Most of the older VirusShare malware is built with ordinary tools, so few samples carry structural tricks. The recent samples come from packers that combine several of them.

The only clean app with an anomaly above `info` carries decoy `android:name` attributes, rated `suspicious`, see [`invalid_attribute_name`](#suspicious_1).

## Anomaly list

### `tampered` { #tampered_1 }

Zip archive:

| Code | What it means |
|---|---|
| `fake_eocd_in_comment` | an end of central directory signature planted in the archive comment, after the real record; a reader that takes the last signature fails to open the file. Android installs it |
| `extra_central_directory_records` | central directory records past the count in the end record. Android reads only the declared count; a reader that walks to the end of the directory lets a decoy shadow a real entry, such as the manifest. Android installs it |
| `duplicate_entry` | two central directory records with the same name; readers disagree on which one wins |
| `entry_path_conflict` | an entry path runs through another entry's file name, as in `AndroidManifest.xml/x.png`: extracting the archive fails on a file-versus-directory conflict |
| `invalid_utf8_name` | an entry name that isn't valid UTF-8. Android rejects the archive |
| `compression_method_mismatch` | the local header's compression method disagrees with the central directory's: the BadPack technique |
| `unknown_compression_method` | a compression method other than stored (0) or deflated (8), such as WinZip AES (99) |
| `stored_size_mismatch` | a stored (uncompressed) entry whose compressed and uncompressed sizes differ |
| `encryption_flag` | the encryption flag is set, but the data isn't encrypted; tools ask for a password or skip the entry. Packers often set it on hundreds of entries |

`AndroidManifest.xml` and `resources.arsc`:

| Code | What it means |
|---|---|
| `string_pool_garbage_chunk` | a chunk of another type where the string pool should be; the APKEditor `TableConfuser` does this to `resources.arsc` |
| `string_count_mismatch` | the declared string count disagrees with the offsets array |
| `string_offsets_out_of_bounds` | string offsets that point past the string data |
| `non_xml_chunk` | a run of chunks inside the XML tree that aren't XML nodes; some samples carry millions of them |
| `xml_node_header_size` | a run of XML node chunks whose header size isn't `0x10` |
| `attribute_start_shifted` | an element's attributes start further than right after its header |
| `attribute_size_mismatch` | an attribute record larger than the standard 20 bytes |
| `element_trailing_bytes` | bytes after the attributes of an element |
| `invalid_element_name` | an element name that isn't a valid XML name; the element is kept as `invalid-element` |
| `invalid_attribute_name` | an attribute name that isn't a valid XML name, dropped. A common one is `" >\n  </manifest>\n  android:name"`, which injects fake XML into tools that print the manifest as text. See [`suspicious`](#suspicious_1) for the decoy variant |
| `package_header_size` | a resource package header of an unexpected size |
| `type_entries_out_of_bounds` | a type chunk whose entry index array is larger than the chunk |
| `resources_unreadable` | `resources.arsc` is present but can't be read or parsed; resource references stay unresolved |

### `suspicious` { #suspicious_1 }

Zip archive:

| Code | What it means |
|---|---|
| `eocd_not_at_end` | the end of central directory record and its comment don't end at the end of the file: trailing data or a broken comment length |
| `central_directory_shifted` | the central directory isn't at the offset the end record declares: data inserted before it |
| `missing_central_directory_records` | fewer central directory records than declared: a truncated directory |
| `local_header_shifted` | an entry's local header isn't at the declared offset, but was found nearby |
| `local_header_missing` | no local header with the entry's name; often a damaged download or a broken repack |

`AndroidManifest.xml` and `resources.arsc`:

| Code | What it means |
|---|---|
| `invalid_attribute_name` | a decoy: an attribute literally named `android:name`, with no namespace and no resource ID, next to the real one. Android resolves attributes by resource ID and ignores it, as does apk-info; a tool that matches names as text shows the decoy's value. Commercial protectors use it in clean apps too |
| `unknown_chunk` | a run of chunks of a type the parser doesn't know |
| `truncated_xml` | the XML tree ends in the middle of a node |
| `unclosed_elements` | elements that are never closed |
| `no_packages` | a resource table that declares no packages |
| `duplicate_package_id` | two resource packages with the same ID; the second is skipped |

Containers (XAPK, APKM, APKS):

| Code | What it means |
|---|---|
| `root_manifest_unreadable` | the container has its own `AndroidManifest.xml` that doesn't parse; the base APK inside was used instead |

### `info` { #info_1 }

| Code | What it means |
|---|---|
| `duplicate_type_chunk` | two resource type chunks with the same ID and configuration; the first one is used |
| `guessed_base_apk` | the container doesn't name its base APK in a known way; it was guessed from the file names |

## Limits

- A parser keeps at most 16 anomalies of one kind for the manifest and for the resource table. A run of garbage chunks counts as one anomaly. Zip anomalies are listed per entry, so a packer that flags every entry yields one anomaly per entry.
- `anomalies()` reads the local header of every zip entry: one small read per entry. That's instant for a file in the page cache, but costs a random read per entry on a slow disk.
- A file that `APK()` / `Apk::new` can't open has no anomalies to list. In Rust, `ZipEntry::anomalies()` still checks the zip archive itself.
- CRC-32 and size mismatches between a local header and the central directory are not reported: none showed up in any of the collections above, clean or malicious.
- Not checked: a deflated entry that inflates to a size other than declared, and the APK Signing Block.
