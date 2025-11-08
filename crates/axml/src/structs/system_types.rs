include!(concat!(env!("OUT_DIR"), "/system_types_phf.rs"));

#[inline(always)]
pub fn get_type_name(id: &u32) -> Option<&'static str> {
    SYSTEM_TYPES.get(id).copied()
}
