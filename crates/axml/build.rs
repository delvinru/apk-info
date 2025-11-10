use std::collections::HashMap;
use std::path::PathBuf;
use std::{env, fs};

use phf_codegen::Map;
use serde::Deserialize;
use serde_json::Value;

fn generate_system_types() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let json_path = PathBuf::from("src/assets/public.json");
    let out_path = out_dir.join("system_types_phf.rs");

    let json_str = fs::read_to_string(&json_path).expect("cannot read public.json");
    let json: Value = serde_json::from_str(&json_str).expect("invalid JSON in public.json");
    let mut output = String::new();
    let categories = [
        "attr",
        "id",
        "style",
        "string",
        "dimen",
        "color",
        "array",
        "drawable",
        "layout",
        "anim",
        "integer",
        "animator",
        "interpolator",
        "mipmap",
        "transition",
        "raw",
    ];

    let mut map = Map::new();
    for cat in categories {
        if let Some(entries) = json.get(cat).and_then(|v| v.as_object()) {
            for (k, v) in entries {
                if let (Ok(id), Some(name)) = (k.parse::<u32>(), v.as_str()) {
                    let name = format!("\"android:{}/{}\"", cat, name);
                    map.entry(id, name);
                }
            }
        }
    }
    output.push_str(&format!(
        "static SYSTEM_TYPES: phf::Map<u32, &'static str> = {};\n\n",
        map.build()
    ));

    fs::write(&out_path, output).unwrap();
    println!("cargo:rerun-if-changed={}", json_path.display());
}

#[derive(Debug, Deserialize)]
pub struct AttrCollection {
    pub kind: String,
    pub items: HashMap<u32, String>,
}

pub type AttrMap = HashMap<String, AttrCollection>;

fn generate_map(map: &mut Map<'_, String>, path: &str) {
    // let json_path = PathBuf::from("src/assets/attrs_manifest.json");

    let json_path = PathBuf::from(path);
    let json_str = fs::read_to_string(&json_path).expect("cannot read attrs_manifest.json");
    let json: AttrMap =
        serde_json::from_str(&json_str).expect("invalid JSON in attrs_manifest.json");

    for (attr_name, collection) in json.into_iter() {
        let mut pairs: Vec<_> = collection
            .items
            .iter()
            .map(|(value, name)| (name.as_str(), *value))
            .collect();

        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let pairs_str = pairs
            .into_iter()
            .map(|(name, value)| format!("(\"{}\", {})", name, value))
            .collect::<Vec<_>>()
            .join(", ");

        let entry_code = format!("(\"{}\", &[{}])", collection.kind, pairs_str);

        map.entry(attr_name, entry_code);
    }

    println!("cargo:rerun-if-changed={}", json_path.display());
}

fn generate_attrs_manifest() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("attrs_manifest_phf.rs");

    let mut map = Map::new();

    generate_map(&mut map, "src/assets/attrs_manifest.json");
    generate_map(&mut map, "src/assets/attrs.json");

    let mut output = String::new();
    output.push_str("#[allow(clippy::type_complexity)]\n");
    output.push_str(&format!(
        "static ATTRS_MANIFEST: phf::Map<&'static str, (&'static str, &'static [(&'static str, u32)])> = {};\n\n",
        map.build()
    ));

    fs::write(&out_path, output).unwrap();
}

fn main() {
    generate_system_types();
    generate_attrs_manifest();
}
