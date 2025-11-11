use std::borrow::Cow;

use apk_info_xml::Element;
use log::warn;
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::take;

use crate::ARSC;
use crate::errors::AXMLError;
use crate::structs::{
    ResChunkHeader, ResourceHeaderType, StringPool, XMLHeader, XMLResourceMap, XmlCData,
    XmlEndElement, XmlNamespace, XmlParse, XmlStartElement, attrs_manifest,
};

/// Default android namespace
pub const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";

/// Represents an Android Binary XML (AXML) file.
///
/// This struct holds the root element of the parsed XML structure.
///
/// You can use this struct to traverse the XML tree, extract attributes,
/// or get a string representation of the XML.
#[derive(Debug)]
pub struct AXML {
    pub root: Element,
}

impl AXML {
    /// Parses a byte slice into an `AXML` structure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let axml = AXML::new(&mut input_bytes, Some(&arsc))?;
    /// ```
    pub fn new(input: &mut &[u8], arsc: Option<&ARSC>) -> Result<AXML, AXMLError> {
        // basic sanity check
        if input.len() < 8 {
            return Err(AXMLError::TooSmallError);
        }

        // parse header
        let header = ResChunkHeader::parse(input).map_err(|_| AXMLError::HeaderError)?;

        // header size must be 8 bytes, otherwise is non valid axml
        if header.header_size != 8 {
            return Err(AXMLError::HeaderSizeError(header.header_size));
        }

        // parse string pool
        let string_pool = StringPool::parse(input).map_err(|_| AXMLError::StringPoolError)?;

        // parse resource map
        let xml_resource = XMLResourceMap::parse(input).map_err(|_| AXMLError::ResourceMapError)?;

        // parse and get xml tree
        let root = Self::get_xml_tree(input, arsc, &string_pool, &xml_resource)
            .ok_or(AXMLError::MissingRoot)?;

        Ok(AXML { root })
    }

    fn get_xml_tree<'a>(
        input: &mut &[u8],
        arsc: Option<&ARSC>,
        string_pool: &'a StringPool,
        xml_resource: &'a XMLResourceMap,
    ) -> Option<Element> {
        let mut stack: Vec<Element> = Vec::with_capacity(16);

        loop {
            let chunk_header = match ResChunkHeader::parse(input) {
                Ok(v) => v,
                Err(ErrMode::Backtrack(_)) => break,
                Err(_) => return None,
            };

            // Skip non-xml chunks
            if chunk_header.type_ < ResourceHeaderType::XmlStartNamespace
                || chunk_header.type_ > ResourceHeaderType::XmlLastChunk
            {
                warn!("not a xml resource chunk: {chunk_header:?}");

                let _ =
                    take::<u32, &[u8], ContextError>(chunk_header.content_size()).parse_next(input);
                continue;
            }

            // another malware technique
            if chunk_header.header_size != 0x10 {
                warn!("xml resource chunk header size is not 0x10: {chunk_header:?}");

                let _ =
                    take::<u32, &[u8], ContextError>(chunk_header.content_size()).parse_next(input);
                continue;
            }

            let xml_header = match XMLHeader::parse(input, chunk_header) {
                Ok(v) => v,
                Err(_) => break,
            };

            match xml_header.header.type_ {
                ResourceHeaderType::XmlStartNamespace => {
                    let _ = XmlNamespace::parse(input, xml_header);
                }
                ResourceHeaderType::XmlEndNamespace => {
                    let _ = XmlNamespace::parse(input, xml_header);
                }
                ResourceHeaderType::XmlStartElement => {
                    let node = match XmlStartElement::parse(input, xml_header) {
                        Ok(v) => v,
                        Err(_) => break,
                    };

                    let Some(name) = string_pool.get(node.name) else {
                        continue;
                    };

                    let mut element = Element::with_capacity(name, node.attributes.len());

                    if name == "manifest" {
                        element.set_attribute_with_prefix(
                            Some("xlmns"),
                            "android",
                            ANDROID_NAMESPACE,
                        );
                    }

                    for attribute in &node.attributes {
                        let Some(attribute_name) =
                            string_pool.get_with_resources(attribute.name, xml_resource, true)
                        else {
                            continue;
                        };

                        // skip garbage strings
                        if attribute_name.contains(char::is_whitespace) {
                            warn!("skipped garbage attribute name: {:?}", attribute_name);
                            continue;
                        }

                        let ns_prefix = if string_pool
                            .get_with_resources(attribute.namespace_uri, xml_resource, false)
                            .is_some()
                        {
                            Some("android")
                        } else {
                            None
                        };

                        let value_str = attrs_manifest::get_attr_value(
                            attribute_name,
                            &attribute.typed_value.data,
                        )
                        .unwrap_or_else(|| {
                            Cow::Owned(attribute.typed_value.to_string(string_pool, arsc))
                        });

                        element.set_attribute_with_prefix(ns_prefix, attribute_name, &value_str);
                    }

                    stack.push(element);
                }
                ResourceHeaderType::XmlEndElement => {
                    let _ = XmlEndElement::parse(input, xml_header);

                    if stack.len() > 1 {
                        let finished = stack.pop().unwrap();
                        stack.last_mut().unwrap().append_child(finished);
                    }
                }
                ResourceHeaderType::XmlCdata => {
                    let _ = XmlCData::parse(input, xml_header);
                }
                _ => {
                    warn!("unknown header type: {:#?}", xml_header.header.type_);
                }
            }
        }

        (!stack.is_empty()).then(|| stack.remove(0))
    }

    /// Returns the pretty-printed XML as a string.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let xml_string = axml.get_xml_string();
    /// println!("{}", xml_string);
    /// ```
    #[inline]
    pub fn get_xml_string(&self) -> String {
        self.root.to_string()
    }

    /// Retrieves the value of an attribute from a specific tag.
    pub fn get_attribute_value(
        &self,
        tag: &str,
        name: &str,
        arsc: Option<&ARSC>,
    ) -> Option<String> {
        // check if root itself matches (<manifest> tag)
        let value = if self.root.name() == tag {
            self.root.attr(name)
        } else {
            // otherwise check other child elements
            self.root
                .descendants()
                .find(|el| el.name() == tag)
                .and_then(|el| el.attr(name))
        };

        match value {
            // resolve reference we found
            Some(v) if v.starts_with('@') => {
                if let Some(arsc) = arsc {
                    // safe slice, checked before
                    let name = &v[1..];
                    arsc.get_resource_value_by_name(name)
                } else {
                    Some(v.to_string())
                }
            }
            // just a value, not a reference
            Some(v) => Some(v.to_string()),
            None => None,
        }
    }

    /// Returns an iterator over attribute values for direct children with a specific tag.
    ///
    /// This is a faster version of [AXML::get_all_attribute_values] that only iterates over the root's direct children
    #[inline]
    pub fn get_root_attribute_values<'a>(
        &'a self,
        tag: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.root
            .childrens()
            .filter(move |el| el.name() == tag)
            .flat_map(move |el| {
                el.attributes()
                    .filter(move |attr| attr.name() == name)
                    .map(|attr| attr.value())
            })
    }

    /// Returns an iterator over attribute values for all descendants with a specific tag.
    #[inline]
    pub fn get_all_attribute_values<'a>(
        &'a self,
        tag: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.root
            .descendants()
            .filter(move |el| el.name() == tag)
            .flat_map(move |el| {
                el.attributes()
                    .filter(move |attr| attr.name() == name)
                    .map(|attr| attr.value())
            })
    }

    /// Extracts the main launcher activities from an APK manifest.
    ///
    /// Algorithm:
    /// 1. Search for all `<activity>` and `<activity-alias>` tags.
    /// 2. Look for `android.intent.action.MAIN` with `android.intent.category.LAUNCHER` or `android.intent.category.INFO`.
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310>
    pub fn get_main_activities(&self) -> impl Iterator<Item = &str> {
        self.root
            .childrens()
            .filter(|c| c.name() == "application")
            .flat_map(|app| app.childrens())
            .filter_map(|activity| {
                // check tag and enabled state
                let tag = activity.name();
                if (tag != "activity" && tag != "activity-alias")
                    || activity.attr("enabled") == Some("false")
                {
                    return None;
                }

                for intent_filter in activity.childrens() {
                    if intent_filter.name() != "intent-filter" {
                        continue;
                    }

                    let mut has_main = false;
                    let mut has_launcher = false;

                    for child in intent_filter.childrens() {
                        match (child.name(), child.attr("name")) {
                            ("action", Some("android.intent.action.MAIN")) => has_main = true,
                            ("category", Some("android.intent.category.LAUNCHER"))
                            | ("category", Some("android.intent.category.INFO")) => {
                                has_launcher = true
                            }
                            _ => {}
                        }
                    }

                    if has_main && has_launcher {
                        return activity.attr("name");
                    }
                }

                None
            })
    }
}
