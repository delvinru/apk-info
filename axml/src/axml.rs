use minidom::Element;
use winnow::{
    error::{ContextError, ErrMode},
    prelude::*,
    token::take,
};

use crate::{
    errors::AXMLError,
    structs::{
        res_chunk_header::{ResChunkHeader, ResourceType},
        res_string_pool::StringPool,
        xml_elements::{
            XMLHeader, XMLResourceMap, XmlAttributeElement, XmlCData, XmlElement, XmlEndElement,
            XmlEndNamespace, XmlNodeElements, XmlStartElement, XmlStartNamespace,
        },
    },
    system_types::SYSTEM_TYPES,
};

#[derive(Debug)]
pub struct AXML {
    pub header: ResChunkHeader,
    pub is_tampered: bool,
    pub string_pool: StringPool,
    pub xml_resource: XMLResourceMap,
    pub root: Element,
}

impl AXML {
    pub fn new(input: &mut &[u8]) -> Result<AXML, AXMLError> {
        // basic sanity check
        if input.len() < 8 {
            return Err(AXMLError::TooSmall);
        }

        // parse header
        let header = ResChunkHeader::parse(input).map_err(|_| AXMLError::Header)?;

        // header size must be 8 bytes, otherwise is non valid axml
        if header.header_size != 8 {
            return Err(AXMLError::HeaderSize);
        }

        let mut is_tampered = false;
        if header.type_ != ResourceType::Xml {
            is_tampered = true;
        }

        // parse string pool
        let string_pool = StringPool::parse(input).map_err(|_| AXMLError::StringPool)?;

        // parse resource map
        let xml_resource = XMLResourceMap::parse(input).map_err(|_| AXMLError::ResourceMap)?;

        // parse xml tree
        let elements = Self::parse_xml_tree(input).map_err(|_| AXMLError::XmlTree)?;

        // create xml treee
        let root = Self::get_xml_tree(&elements, &string_pool, &xml_resource);

        Ok(AXML {
            header,
            is_tampered,
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

            // some junk malware tries tamper axml
            if chunk_header.type_ < ResourceType::XmlStartNamespace
                || chunk_header.type_ > ResourceType::XmlLastChunk
            {
                // TODO: show warning or just silently ignore, idk for now
                eprintln!("not a xml resource chunk: {:?}", chunk_header);
                let _ = take::<u32, &[u8], ContextError>(chunk_header.size - 8).parse_next(input);
                continue;
            };

            // another junk malware techniques
            if chunk_header.header_size != 0x10 {
                eprintln!(
                    "xml resource chunk header size is not 16: {:?}",
                    chunk_header
                );
                let _ = take::<u32, &[u8], ContextError>(chunk_header.size - 8).parse_next(input);
                continue;
            }

            let xml_header = match XMLHeader::parse(input, chunk_header) {
                Ok(v) => v,
                Err(_) => return Ok(elements),
            };

            let element = match xml_header.header.type_ {
                ResourceType::XmlStartNamespace => {
                    let e = XmlStartNamespace::parse(input, xml_header)?;
                    XmlNodeElements::XmlStartNamespace(e)
                }
                ResourceType::XmlEndNamespace => {
                    let e = XmlEndNamespace::parse(input, xml_header)?;
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
    ) -> Element {
        let mut stack: Vec<Element> = vec![];

        for node in elements {
            match node {
                XmlNodeElements::XmlStartElement(node) => {
                    let Some(name) = string_pool.get(node.name) else {
                        continue;
                    };

                    let mut element = Element::builder(name, "android");

                    if name == "manifest" {
                        element = element.attr(
                            "xmlns:android",
                            "http://schemas.android.com/apk/res/android",
                        );
                    }

                    for attribute in &node.attributes {
                        let attribute_name =
                            match Self::get_attribute_name(attribute, string_pool, xml_resource) {
                                Some(name) => name,
                                None => continue,
                            };

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
                    stack.last_mut().unwrap().append_text(data);
                }
                _ => continue,
            }
        }

        stack.remove(0)
    }

    fn get_attribute_name<'a>(
        attribute: &XmlAttributeElement,
        string_pool: &'a StringPool,
        xml_resource: &'a XMLResourceMap,
    ) -> Option<&'a String> {
        if let Some(v) = string_pool.get(attribute.name) {
            if !v.is_empty() {
                return Some(v);
            }
        }
        xml_resource
            .resource_ids
            .get(attribute.name as usize)
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
    ) -> Box<dyn Iterator<Item = &'a str> + 'a> {
        Box::new(self.walk_and_collect(&self.root, tag, name))
    }

    // TODO: some fucked up method, i don't like it
    fn walk_and_collect<'a>(
        &'a self,
        elem: &'a Element,
        tag: &'a str,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = &'a str> + 'a> {
        // Collect attribute values from the current element if it matches the tag
        let current = if elem.name() == tag {
            Box::new(
                elem.attrs()
                    .filter(move |(attr_name, _)| attr_name == &name)
                    .map(|(_, attr_value)| attr_value),
            ) as Box<dyn Iterator<Item = &'a str> + 'a>
        } else {
            Box::new(std::iter::empty()) as Box<dyn Iterator<Item = &'a str> + 'a>
        };

        // Recursively collect from children
        let children = elem
            .children()
            .flat_map(move |child| self.walk_and_collect(child, tag, name));

        Box::new(current.chain(children))
    }

    pub fn get_main_activities<'a>(&'a self) -> Box<dyn Iterator<Item = &'a str> + 'a> {
        Box::new(
            self.root
                .children()
                .filter(|c| c.name() == "application")
                .flat_map(|app| {
                    app.children().filter(|c| {
                        (c.name() == "activity" || c.name() == "activity-alias")
                            && c.attr("enabled") != Some("false")
                    })
                })
                .filter_map(|activity| {
                    let has_matching_intent = activity.children().any(|intent_filter| {
                        if intent_filter.name() != "intent-filter" {
                            return false;
                        }

                        let has_main_action = intent_filter.children().any(|child| {
                            child.name() == "action"
                                && child.attr("name") == Some("android.intent.action.MAIN")
                        });

                        // TODO: need research this moment, how android actually launch itself
                        // let has_launcher_category = intent_filter.children().any(|child| {
                        //     child.name() == "category"
                        //         && child.attr("name") == Some("android.intent.category.LAUNCHER")
                        // });

                        // has_main_action && has_launcher_category
                        has_main_action
                    });

                    if has_matching_intent {
                        activity.attr("name")
                    } else {
                        None
                    }
                }),
        )
    }
}
