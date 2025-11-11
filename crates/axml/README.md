# apk-info-axml

A full-featured `Android Binary XML` (AXML) and `Android Resource` (ARSC) parser.

Handles all kinds of techniques that are aimed at breaking "standard" parsers,
so it allows you to extract information from more files.

## Example

```rust
let axml = AXML::new(input, None /* arsc */).expect("can't parse given axml file");
```
