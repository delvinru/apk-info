#![allow(unused, dead_code)]

use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub(crate) struct SystemTypes {
    pub(crate) attr: HashMap<u32, String>,
    pub(crate) id: HashMap<u32, String>,
    pub(crate) style: HashMap<u32, String>,
    pub(crate) string: HashMap<u32, String>,
    pub(crate) dimen: HashMap<u32, String>,
    pub(crate) color: HashMap<u32, String>,
    pub(crate) array: HashMap<u32, String>,
    pub(crate) drawable: HashMap<u32, String>,
    pub(crate) layout: HashMap<u32, String>,
    pub(crate) anim: HashMap<u32, String>,
    pub(crate) integer: HashMap<u32, String>,
    pub(crate) animator: HashMap<u32, String>,
    pub(crate) interpolator: HashMap<u32, String>,
    pub(crate) mipmap: HashMap<u32, String>,
    pub(crate) transition: HashMap<u32, String>,
    pub(crate) raw: HashMap<u32, String>,
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
