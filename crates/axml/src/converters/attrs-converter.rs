use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::process::exit;

use quick_xml::Reader;
use quick_xml::events::Event;
use quick_xml::name::QName;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct AttrCollection {
    kind: AttrType,
    items: HashMap<u32, String>, // value -> name
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum AttrType {
    Flag,
    Enum,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} ./crates/axml/src/assets/attrs_manifest.xml ./crates/axml/src/assets/attrs_manifest.json",
            args[0]
        );
        exit(1);
    }

    let path = &args[1];
    let out = &args[2];
    let attrs_xml = std::fs::read_to_string(path)?;
    let mut reader = Reader::from_str(&attrs_xml);

    let mut buf = Vec::new();
    let mut data: HashMap<String, AttrCollection> = HashMap::new();
    let mut current_attr_name: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let name = e.name();
                if name == QName(b"attr") {
                    let mut attr_name = String::new();
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"name" {
                            attr_name = a.unescape_value()?.to_string();
                        }
                    }
                    current_attr_name = Some(attr_name);
                }
            }

            Event::Empty(e) => {
                let name = e.name();
                if name == QName(b"flag") || name == QName(b"enum") {
                    if let Some(attr_name) = current_attr_name.clone() {
                        let mut item_name = String::new();
                        let mut value_str = String::new();

                        for a in e.attributes().flatten() {
                            match a.key.as_ref() {
                                b"name" => item_name = a.unescape_value()?.to_string(),
                                b"value" => value_str = a.unescape_value()?.to_string(),
                                _ => {}
                            }
                        }

                        let value = parse_hex_or_dec(&value_str)?;

                        // определяем тип attr
                        let kind = if name == QName(b"flag") {
                            AttrType::Flag
                        } else {
                            AttrType::Enum
                        };

                        let entry = data.entry(attr_name).or_insert_with(|| AttrCollection {
                            kind,
                            items: HashMap::new(),
                        });

                        if !entry.items.contains_key(&value) {
                            entry.items.insert(value, item_name);
                        }
                    }
                }
            }

            Event::End(e) if e.name() == QName(b"attr") => {
                current_attr_name = None;
            }

            Event::Eof => break,
            _ => {}
        }

        buf.clear();
    }

    let json = serde_json::to_string(&data)?;
    let mut out = File::create(out)?;
    out.write_all(json.as_bytes())?;

    Ok(())
}

fn parse_hex_or_dec(s: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        // sometimes there "-1" so we threat this as u32::MAX to avoid performance drawback at runtime
        Ok(s.parse::<u32>().unwrap_or(u32::MAX))
    }
}
