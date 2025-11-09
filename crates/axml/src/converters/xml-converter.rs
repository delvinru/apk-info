use std::collections::HashMap;
use std::process::exit;

use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
struct SystemTypes {
    attr: HashMap<u32, String>,
    id: HashMap<u32, String>,
    style: HashMap<u32, String>,
    string: HashMap<u32, String>,
    dimen: HashMap<u32, String>,
    color: HashMap<u32, String>,
    array: HashMap<u32, String>,
    drawable: HashMap<u32, String>,
    layout: HashMap<u32, String>,
    anim: HashMap<u32, String>,
    integer: HashMap<u32, String>,
    animator: HashMap<u32, String>,
    interpolator: HashMap<u32, String>,
    mipmap: HashMap<u32, String>,
    transition: HashMap<u32, String>,
    raw: HashMap<u32, String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} ./crates/axml/src/assets/public.xml ./crates/axml/src/assets/public.json",
            args[0]
        );
        exit(1);
    }

    let path = &args[1];
    let out = &args[2];
    let public_xml = std::fs::read_to_string(path)?;

    let mut reader = Reader::from_str(&public_xml);
    let mut buf = Vec::new();
    let mut system_types = SystemTypes::default();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => panic!("Error at position {}: {:?}", reader.error_position(), e),
            Ok(Event::Eof) => break,
            Ok(Event::Empty(e)) => {
                if e.name().as_ref() == b"public" {
                    let attributes: HashMap<String, String> = e
                        .attributes()
                        .map(|attr_result| match attr_result {
                            Ok(a) => {
                                let key = reader
                                    .decoder()
                                    .decode(a.key.local_name().as_ref())
                                    .expect("can't get key")
                                    .to_string();

                                let value = a
                                    .decode_and_unescape_value(reader.decoder())
                                    .expect("can't get value")
                                    .to_string();

                                (key, value)
                            }
                            Err(_) => {
                                panic!("Can't read attributes of public field");
                            }
                        })
                        .collect();

                    let Some(type_) = attributes.get("type") else {
                        continue;
                    };
                    let Some(name) = attributes.get("name") else {
                        continue;
                    };
                    let Some(id) = attributes.get("id") else {
                        continue;
                    };

                    let name = name.clone();
                    let id = u32::from_str_radix(id.trim_start_matches("0x"), 16).unwrap();

                    let _ = match type_.as_str() {
                        "attr" => system_types.attr.insert(id, name),
                        "id" => system_types.id.insert(id, name),
                        "style" => system_types.style.insert(id, name),
                        "string" => system_types.string.insert(id, name),
                        "dimen" => system_types.dimen.insert(id, name),
                        "color" => system_types.color.insert(id, name),
                        "array" => system_types.array.insert(id, name),
                        "drawable" => system_types.drawable.insert(id, name),
                        "layout" => system_types.layout.insert(id, name),
                        "anim" => system_types.anim.insert(id, name),
                        "integer" => system_types.integer.insert(id, name),
                        "animator" => system_types.animator.insert(id, name),
                        "interpolator" => system_types.interpolator.insert(id, name),
                        "mipmap" => system_types.mipmap.insert(id, name),
                        "transition" => system_types.transition.insert(id, name),
                        "raw" => system_types.raw.insert(id, name),
                        &_ => {
                            eprintln!("got unknown type: {}", type_);
                            None
                        }
                    };
                }
            }
            _ => (),
        }
    }

    let system_types = serde_json::to_string(&system_types)?;
    std::fs::write(out, system_types)?;
    println!("saved json to {}", out);

    Ok(())
}
