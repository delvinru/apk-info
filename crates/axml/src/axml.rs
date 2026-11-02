use std::borrow::Cow;
use std::collections::HashMap;

use apk_info_xml::{Element, is_valid_name};
use log::warn;
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::take;

use crate::ARSC;
use crate::anomaly::{self, Input, ResAnomaly};
use crate::errors::AXMLError;
use crate::structs::{
    ResChunkHeader, ResourceHeaderType, ResourceValueType, StringPool, XMLHeader, XMLResourceMap,
    XmlCData, XmlEndElement, XmlNamespace, XmlParse, XmlStartElement, attrs_manifest,
};

/// Default android namespace
pub const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";

/// Name given to an element whose name can't be read or written as XML.
///
/// Android doesn't know such a tag and skips it with everything inside, so the
/// element is kept with its children under this name rather than dropped or
/// flattened into its parent.
pub const INVALID_ELEMENT_NAME: &str = "invalid-element";

/// Represents an Android Binary XML (AXML) file.
///
/// This struct holds the root element of the parsed XML structure.
///
/// You can use this struct to traverse the XML tree, extract attributes,
/// or get a string representation of the XML.
#[derive(Debug)]
pub struct AXML {
    pub root: Element,

    /// Raw resource id of reference-typed attributes, keyed by `(element, attr)`.
    /// Lets [`AXML::get_attribute_value`] resolve a reference by its exact id instead of a
    /// (potentially ambiguous/redacted) resource name.
    reference_ids: ReferenceIds,

    /// Defects the parser recovered from, in the order met.
    anomalies: Vec<ResAnomaly>,
}

/// Map of `(element name, attribute name)` to the raw resource id of a reference
/// attribute, captured while parsing an AXML tree.
type ReferenceIds = HashMap<(String, String), u32>;

impl AXML {
    /// Parses a byte slice into an `AXML` structure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let axml = AXML::new(&mut input_bytes, Some(&arsc))?;
    /// ```
    pub fn new(bytes: &mut &[u8], arsc: Option<&ARSC>) -> Result<AXML, AXMLError> {
        // basic sanity check
        if bytes.len() < 8 {
            return Err(AXMLError::TooSmallError);
        }

        let mut input = anomaly::input(bytes);

        // parse header
        let header = ResChunkHeader::parse(&mut input.input).map_err(|_| AXMLError::HeaderError)?;

        // header size must be 8 bytes, otherwise is non valid axml
        if header.header_size != 8 {
            return Err(AXMLError::HeaderSizeError(header.header_size));
        }

        // parse string pool
        let string_pool = StringPool::parse(&mut input).map_err(|_| AXMLError::StringPoolError)?;

        // parse resource map
        let xml_resource =
            XMLResourceMap::parse(&mut input.input).map_err(|_| AXMLError::ResourceMapError)?;

        // parse and get xml tree
        let (root, reference_ids) =
            Self::get_xml_tree(&mut input, arsc, &string_pool, &xml_resource)
                .ok_or(AXMLError::MissingRoot)?;

        *bytes = input.input;

        Ok(AXML {
            root,
            reference_ids,
            anomalies: input.state.into_vec(),
        })
    }

    /// Defects in the binary XML that the parser recovered from.
    ///
    /// An empty slice means the document is well-formed, as far as the parser
    /// can tell.
    #[inline]
    pub fn anomalies(&self) -> &[ResAnomaly] {
        &self.anomalies
    }

    fn get_xml_tree<'a>(
        input: &mut Input<'_>,
        arsc: Option<&ARSC>,
        string_pool: &'a StringPool,
        xml_resource: &'a XMLResourceMap,
    ) -> Option<(Element, ReferenceIds)> {
        let mut stack: Vec<Element> = Vec::with_capacity(16);
        // the stack never pops the root, so open elements are counted apart
        let mut depth = 0usize;
        let mut reference_ids: ReferenceIds = HashMap::new();

        loop {
            let chunk_header = match ResChunkHeader::parse(&mut input.input) {
                Ok(v) => v,
                Err(ErrMode::Backtrack(_)) => break,
                Err(_) => return None,
            };

            // Skip non-xml chunks
            if !is_xml_node(&chunk_header) {
                let skipped = skip_run(&mut input.input, &chunk_header, |h| !is_xml_node(h));
                warn!("skipped {skipped} non-xml chunks, the first: {chunk_header:?}");
                input.state.push(ResAnomaly::NonXmlChunk {
                    chunk_type: (&chunk_header.type_).into(),
                });
                continue;
            }

            // another malware technique
            if chunk_header.header_size != 0x10 {
                let skipped = skip_run(&mut input.input, &chunk_header, |h| {
                    is_xml_node(h) && h.header_size != 0x10
                });
                warn!(
                    "skipped {skipped} xml chunks with a header size other than 0x10, the first: {chunk_header:?}"
                );
                input.state.push(ResAnomaly::XmlNodeHeaderSize {
                    header_size: chunk_header.header_size,
                });
                continue;
            }

            let xml_header = match XMLHeader::parse(&mut input.input, chunk_header) {
                Ok(v) => v,
                Err(_) => {
                    input.state.push(ResAnomaly::TruncatedXml);
                    break;
                }
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
                        Err(_) => {
                            input.state.push(ResAnomaly::TruncatedXml);
                            break;
                        }
                    };

                    // why is_attribute_name == true? idk, but this works, for example - b1e83615e07999862f15f5649656941f754db4ed31458b4b6b5ba9d36bc1b1b3
                    // an element with a name that can't be read or written as xml
                    // stays in the tree under a placeholder: skipping it would let
                    // its end element close the parent instead
                    let name = match string_pool.get_with_resources(node.name, xml_resource, true) {
                        Some(name) if is_valid_name(&name) => name,
                        name => {
                            warn!(
                                "invalid element name {name:?}, replaced with {INVALID_ELEMENT_NAME:?}"
                            );
                            input.state.push(ResAnomaly::InvalidElementName {
                                name: name.map(Cow::into_owned),
                            });
                            Cow::Borrowed(INVALID_ELEMENT_NAME)
                        }
                    };

                    let mut element = Element::with_capacity(&name, node.attributes.len());

                    // The `android` namespace is always in scope in decoded binary XML.
                    if stack.is_empty() {
                        element.set_attribute_with_prefix(
                            Some("xmlns"),
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

                        // skip garbage strings: they can't be written as xml
                        if !is_valid_name(&attribute_name) {
                            warn!("skipped garbage attribute name: {:?}", attribute_name);
                            input.state.push(ResAnomaly::InvalidAttributeName {
                                name: attribute_name.into_owned(),
                            });
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
                            &attribute_name,
                            &attribute.typed_value.data,
                        )
                        .unwrap_or_else(|| {
                            Cow::Owned(attribute.typed_value.to_string(string_pool, arsc))
                        });

                        if matches!(
                            attribute.typed_value.data_type,
                            ResourceValueType::Reference | ResourceValueType::DynamicReference
                        ) {
                            reference_ids.insert(
                                (name.to_string(), attribute_name.to_string()),
                                attribute.typed_value.data,
                            );
                        }

                        element.set_attribute_with_prefix(ns_prefix, &attribute_name, &value_str);
                    }

                    stack.push(element);
                    depth += 1;
                }
                ResourceHeaderType::XmlEndElement => {
                    depth = depth.saturating_sub(1);
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
                    input.state.push(ResAnomaly::UnknownChunk {
                        chunk_type: (&xml_header.header.type_).into(),
                    });
                }
            }
        }

        if depth != 0 {
            input
                .state
                .push(ResAnomaly::UnclosedElements { count: depth });
        }

        // returns root of the tree plus (element, attr) -> resource id
        (!stack.is_empty()).then(|| (stack.remove(0), reference_ids))
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
                    // stripped resource name of the reference, e.g. "string/(name removed)"
                    let stripped = &v[1..];

                    // resolve by exact id first: by-name may be ambiguous (redacted names
                    // shared by many resources), picking the wrong entry
                    if let Some(id) = self.reference_ids.get(&(tag.to_string(), name.to_string())) {
                        arsc.get_resource_value(*id)
                            .or_else(|| arsc.get_resource_value_by_name(stripped))
                    } else {
                        arsc.get_resource_value_by_name(stripped)
                    }
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

/// Whether a chunk is an XML tree node.
#[inline]
fn is_xml_node(header: &ResChunkHeader) -> bool {
    (ResourceHeaderType::XmlStartNamespace..=ResourceHeaderType::XmlLastChunk)
        .contains(&header.type_)
}

/// Skips the chunk whose `first` header was just read, then every following
/// chunk `skip` accepts. Returns how many chunks were skipped.
///
/// A crafted manifest has millions of garbage chunks in a row: the run is
/// walked on a local copy of the input, which stays in registers.
fn skip_run(
    input: &mut &[u8],
    first: &ResChunkHeader,
    skip: impl Fn(&ResChunkHeader) -> bool,
) -> usize {
    let mut data = *input;
    let _ = take::<u32, &[u8], ContextError>(first.content_size()).parse_next(&mut data);

    let mut skipped = 1;
    loop {
        let mut next = data;
        match ResChunkHeader::parse(&mut next) {
            Ok(header) if skip(&header) => {
                data = next;
                let _ =
                    take::<u32, &[u8], ContextError>(header.content_size()).parse_next(&mut data);
                skipped += 1;
            }
            _ => break,
        }
    }

    *input = data;
    skipped
}
