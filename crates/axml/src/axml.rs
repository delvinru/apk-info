use log::warn;
use minidom::Element;
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::take;

use crate::AXMLError;
use crate::structs::{
    ResChunkHeader, ResourceType, StringPool, XMLHeader, XMLResourceMap, XmlCData, XmlElement,
    XmlEndElement, XmlNamespace, XmlStartElement,
};

/// Default android namespace
const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";

pub mod system_types {
    include!(concat!(env!("OUT_DIR"), "/system_types.rs"));

    #[inline(always)]
    pub fn get_attr(idx: &u32) -> Option<&'static str> {
        ATTR.get(idx).copied()
    }
}

#[derive(Debug)]
pub struct AXML {
    pub is_tampered: bool,

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

        // parse and get xml tree
        let root =
            Self::get_xml_tree(input, &string_pool, &xml_resource).ok_or(AXMLError::MissingRoot)?;

        Ok(AXML { is_tampered, root })
    }

    fn get_xml_tree<'a>(
        input: &mut &[u8],
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
            if chunk_header.type_ < ResourceType::XmlStartNamespace
                || chunk_header.type_ > ResourceType::XmlLastChunk
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
                ResourceType::XmlStartNamespace => {
                    let _ = XmlNamespace::parse(input, xml_header);
                }
                ResourceType::XmlEndNamespace => {
                    let _ = XmlNamespace::parse(input, xml_header);
                }
                ResourceType::XmlStartElement => {
                    let node = match XmlStartElement::parse(input, xml_header) {
                        Ok(v) => v,
                        Err(_) => break,
                    };

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
                ResourceType::XmlEndElement => {
                    let _ = XmlEndElement::parse(input, xml_header);

                    if stack.len() > 1 {
                        let finished = stack.pop().unwrap();
                        stack.last_mut().unwrap().append_child(finished);
                    }
                }
                ResourceType::XmlCdata => {
                    let node = match XmlCData::parse(input, xml_header) {
                        Ok(v) => v,
                        Err(_) => break,
                    };

                    let Some(data) = string_pool.get(node.data) else {
                        continue;
                    };

                    if let Some(el) = stack.last_mut() {
                        el.append_text(data);
                    }
                }
                _ => {
                    warn!("unknown header type: {:#?}", xml_header.header.type_);
                }
            }
        }

        (!stack.is_empty()).then(|| stack.remove(0))
    }

    #[inline]
    fn get_string_from_pool<'a>(
        idx: u32,
        string_pool: &'a StringPool,
        xml_resource: &'a XMLResourceMap,
    ) -> Option<&'a str> {
        string_pool
            .get(idx)
            .map(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                xml_resource
                    .resource_ids
                    .get(idx as usize)
                    .and_then(|v| system_types::get_attr(v))
            })
    }

    // TODO: made pretty output
    pub fn get_xml_string(&self) -> String {
        String::from(&self.root)
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

    pub fn get_all_tags<'a>(&'a self, tag: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        let mut stack = vec![&self.root];

        std::iter::from_fn(move || {
            while let Some(elem) = stack.pop() {
                // Push children in original order (no `.rev()`)
                for child in elem.children() {
                    stack.push(child);
                }

                // If tag matches, yield the element
                if elem.name() == tag {
                    return Some(elem);
                }
            }
            None
        })
    }

    /// Get main activities from APK
    ///
    /// Algorithm:
    /// - Search for all `<activity>` and `<activity-alias>` tags
    /// - Search for `android.intent.action.MAIN` with `android.intent.category.LAUNCHER` or `android.intent.category.INFO`
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
