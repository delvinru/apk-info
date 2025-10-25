#![allow(unused)]

use log::warn;
use minidom::Element;
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::take;

use crate::errors::AXMLError;
use crate::structs::res_chunk_header::{ResChunkHeader, ResourceType};
use crate::structs::res_string_pool::StringPool;
use crate::structs::xml_elements::{
    XMLHeader, XMLResourceMap, XmlCData, XmlElement, XmlEndElement, XmlNamespace, XmlNodeElements,
    XmlStartElement,
};
use crate::system_types::SYSTEM_TYPES;

const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";

#[derive(Debug)]
pub struct AXML {
    pub is_tampered: bool,

    header: ResChunkHeader,
    string_pool: StringPool,
    xml_resource: XMLResourceMap,

    pub root: Element,
}

impl AXML {
    pub fn new(input: &mut &[u8]) -> Result<AXML, AXMLError> {
        // basic sanity check
        if input.len() < 8 {
            return Err(AXMLError::TooSmallError);
        }

        // parse header
        let header = ResChunkHeader::parse(input).map_err(|_| AXMLError::HeaderError)?;

        let mut is_tampered = false;

        // some malware tamper this parameter
        // 25cd28cbf4886ea29e6c378dbcdc3b077c2b33a8c58053bbaefb368f4df11529
        if header.type_ != ResourceType::Xml {
            is_tampered = true;
        }

        // header size must be 8 bytes, otherwise is non valid axml
        if header.header_size != 8 {
            return Err(AXMLError::HeaderSizeError(header.header_size));
        }

        // parse string pool
        let string_pool = StringPool::parse(input).map_err(|_| AXMLError::StringPoolError)?;

        // parse resource map
        let xml_resource = XMLResourceMap::parse(input).map_err(|_| AXMLError::ResourceMapError)?;

        // parse xml tree
        let elements = Self::parse_xml_tree(input).map_err(|_| AXMLError::XmlTreeError)?;

        // create xml treee
        let root = Self::get_xml_tree(&elements, &string_pool, &xml_resource)
            .ok_or(AXMLError::MissingRoot)?;

        Ok(AXML {
            is_tampered,
            header,
            string_pool,
            xml_resource,
            root,
        })
    }

    fn parse_xml_tree(input: &mut &[u8]) -> ModalResult<Vec<XmlNodeElements>> {
        // NOTE: very bad sample, need research - dcafcffab0cc9a435c23ac4aac76afb329893ccdc535b7e4d57175e05706efba
        // NOTE: somehow aapt2 extracts all informations from this

        let mut elements: Vec<XmlNodeElements> = Vec::new();

        loop {
            let chunk_header = match ResChunkHeader::parse(input) {
                Ok(v) => v,
                Err(ErrMode::Backtrack(_)) => return Ok(elements),
                Err(e) => return Err(e),
            };

            // skip non xml chunks
            if chunk_header.type_ < ResourceType::XmlStartNamespace
                || chunk_header.type_ > ResourceType::XmlLastChunk
            {
                warn!("not a xml resource chunk: {chunk_header:?}");
                let _ =
                    take::<u32, &[u8], ContextError>(chunk_header.content_size()).parse_next(input);

                continue;
            };

            // another junk malware techniques
            if chunk_header.header_size != 0x10 {
                warn!("xml resource chunk header size is not 0x10: {chunk_header:?}");
                let _ =
                    take::<u32, &[u8], ContextError>(chunk_header.content_size()).parse_next(input);

                continue;
            }

            let xml_header = match XMLHeader::parse(input, chunk_header) {
                Ok(v) => v,
                Err(_) => return Ok(elements),
            };

            let element = match xml_header.header.type_ {
                ResourceType::XmlStartNamespace => {
                    let e = XmlNamespace::parse(input, xml_header)?;
                    XmlNodeElements::XmlStartNamespace(e)
                }
                ResourceType::XmlEndNamespace => {
                    let e = XmlNamespace::parse(input, xml_header)?;
                    XmlNodeElements::XmlEndNamespace(e)
                }
                ResourceType::XmlStartElement => {
                    let e = XmlStartElement::parse(input, xml_header)?;
                    XmlNodeElements::XmlStartElement(e)
                }
                ResourceType::XmlEndElement => {
                    let e = XmlEndElement::parse(input, xml_header)?;
                    XmlNodeElements::XmlEndElement(e)
                }
                ResourceType::XmlCdata => {
                    let e = XmlCData::parse(input, xml_header)?;
                    XmlNodeElements::XmlCData(e)
                }
                _ => {
                    eprintln!("unknown header type: {:#?}", xml_header.header.type_);
                    XmlNodeElements::Unknown
                }
            };

            elements.push(element);
        }
    }

    fn get_xml_tree<'a>(
        elements: &[XmlNodeElements],
        string_pool: &'a StringPool,
        xml_resource: &'a XMLResourceMap,
    ) -> Option<Element> {
        let mut stack: Vec<Element> = vec![];

        for node in elements {
            match node {
                XmlNodeElements::XmlStartElement(node) => {
                    let Some(name) = string_pool.get(node.name) else {
                        continue;
                    };

                    let mut element = Element::builder(name, "android");

                    if name == "manifest" {
                        element = element.attr("xmlns:android", ANDROID_NAMESPACE);
                    }

                    for attribute in &node.attributes {
                        let attribute_name = match Self::get_string_from_pool(
                            attribute.name,
                            string_pool,
                            xml_resource,
                        ) {
                            Some(name) => name,
                            None => continue,
                        };

                        // skip garbage strings
                        if attribute_name.contains(char::is_whitespace) {
                            warn!("skipped garbage attribute name: {:?}", attribute_name);
                            continue;
                        }

                        element = element
                            .attr(attribute_name, attribute.typed_value.to_string(string_pool));
                    }

                    stack.push(element.build());
                }

                XmlNodeElements::XmlEndElement(_) => {
                    if stack.len() > 1 {
                        let finished = stack.pop().unwrap();
                        stack.last_mut().unwrap().append_child(finished);
                    }
                }
                XmlNodeElements::XmlCData(node) => {
                    let Some(data) = string_pool.get(node.data) else {
                        continue;
                    };

                    if let Some(el) = stack.last_mut() {
                        el.append_text(data);
                    }
                }
                _ => continue,
            }
        }

        (!stack.is_empty()).then(|| stack.remove(0))
    }

    fn get_string_from_pool<'a>(
        idx: u32,
        string_pool: &'a StringPool,
        xml_resource: &'a XMLResourceMap,
    ) -> Option<&'a String> {
        if let Some(v) = string_pool.get(idx)
            && !v.is_empty()
        {
            return Some(v);
        }

        xml_resource
            .resource_ids
            .get(idx as usize)
            .and_then(|v| SYSTEM_TYPES.get_attribute_name(v))
    }

    #[inline]
    pub fn get_attribute_value(&self, tag: &str, name: &str) -> Option<&str> {
        if self.root.name() == tag {
            return self.root.attr(name);
        }

        self.root
            .children()
            .find(|x| x.name() == tag)
            .and_then(|x| x.attr(name))
    }

    pub fn get_all_attribute_values<'a>(
        &'a self,
        tag: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        let mut stack = vec![&self.root];

        std::iter::from_fn(move || {
            while let Some(elem) = stack.pop() {
                // Push children in original order (no `.rev()`)
                for child in elem.children() {
                    stack.push(child);
                }

                // If tag matches, yield the attribute value
                if elem.name() == tag {
                    for (attr_name, attr_value) in elem.attrs() {
                        if attr_name == name {
                            return Some(attr_value);
                        }
                    }
                }
            }
            None
        })
    }

    /// Get main activities from APK
    ///
    /// Algorithm:
    ///     - Search for all <activity> and <activity-alias> tags
    ///     - Search for Intent.ACTION_MAIN with
    ///
    /// See: <https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/core/java/android/app/ApplicationPackageManager.java;l=310?q=getLaunchIntentForPackage>
    pub fn get_main_activities(&self) -> impl Iterator<Item = &str> {
        self.root
            .children()
            .filter(|c| c.name() == "application")
            .flat_map(|app| app.children())
            .filter_map(|activity| {
                // check tag and enabled state
                let tag = activity.name();
                if (tag != "activity" && tag != "activity-alias")
                    || activity.attr("enabled") == Some("false")
                {
                    return None;
                }

                // find <intent-filter> with MAIN action + LAUNCHER/INFO category
                let has_matching_intent = activity.children().any(|intent_filter| {
                    if intent_filter.name() != "intent-filter" {
                        return false;
                    }

                    let mut has_main = false;
                    let mut has_launcher = false;

                    for child in intent_filter.children() {
                        match child.name() {
                            "action"
                                if child.attr("name") == Some("android.intent.action.MAIN") =>
                            {
                                has_main = true;
                            }
                            "category"
                                if matches!(
                                    child.attr("name"),
                                    Some("android.intent.category.LAUNCHER")
                                        | Some("android.intent.category.INFO")
                                ) =>
                            {
                                has_launcher = true;
                            }
                            _ => {}
                        }

                        if has_main && has_launcher {
                            return true;
                        }
                    }

                    false
                });

                if has_matching_intent {
                    return activity.attr("name");
                }
                None
            })
    }
}
