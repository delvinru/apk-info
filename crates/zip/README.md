# apk-info-zip

Implementation of a custom error-agnostic zip parser.

The main purpose of this crate is to correctly unpack archives damaged using the `BadPack` technique.

## Example

```rust
let zip = ZipEntry::new(input).expect("can't parser zip file");
let (data, compression_method) = zip.read("AndroidManifest.xml");
```
