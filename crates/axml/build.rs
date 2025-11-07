use std::path::PathBuf;
use std::{env, fs};

use phf_codegen::Map;
use serde_json::Value;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let json_path = PathBuf::from("src/assets/public.json");
    let out_path = out_dir.join("system_types.rs");

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

    for cat in categories {
        let mut map = Map::new();

        if let Some(entries) = json.get(cat).and_then(|v| v.as_object()) {
            for (k, v) in entries {
                if let (Ok(id), Some(name)) = (k.parse::<u32>(), v.as_str()) {
                    let name = format!("\"{}\"", name);
                    map.entry(id, name);
                }
            }
        }

        output.push_str(&format!(
            "pub static {}: phf::Map<u32, &'static str> = {};\n\n",
            cat.to_uppercase(),
            map.build()
        ));
    }

    fs::write(&out_path, output).unwrap();
    println!("cargo:rerun-if-changed={}", json_path.display());
}
