use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct SystemTypes {
    pub attr: HashMap<u32, String>,
    // not used for now
    // pub id: HashMap<u32, String>,
    // pub style: HashMap<u32, String>,
    // pub string: HashMap<u32, String>,
    // pub dimen: HashMap<u32, String>,
    // pub color: HashMap<u32, String>,
    // pub array: HashMap<u32, String>,
    // pub drawable: HashMap<u32, String>,
    // pub layout: HashMap<u32, String>,
    // pub anim: HashMap<u32, String>,
    // pub integer: HashMap<u32, String>,
    // pub animator: HashMap<u32, String>,
    // pub interpolator: HashMap<u32, String>,
    // pub mipmap: HashMap<u32, String>,
    // pub transition: HashMap<u32, String>,
    // pub raw: HashMap<u32, String>,
}

const SYSTEM_TYPES_DATA: &str = include_str!("./assets/public.json");

pub static SYSTEM_TYPES: Lazy<SystemTypes> = Lazy::new(|| {
    serde_json::from_str(SYSTEM_TYPES_DATA)
        .expect("cannot parse public.json (please report this bug)")
});

impl SystemTypes {
    pub fn get_attribute_name(&self, value: &u32) -> Option<&String> {
        self.attr.get(value)
    }
}
