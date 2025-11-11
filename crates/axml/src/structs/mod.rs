//! Describes all the structures that are necessary for `AXML` and `ARSC` parsing.

pub mod attrs_manifest;
mod common;
mod res_string_pool;
mod res_table_config;
mod resource_table;
pub mod system_types;
mod xml_elements;

pub use common::*;
pub use res_string_pool::*;
pub use res_table_config::*;
pub use resource_table::*;
pub use xml_elements::*;
