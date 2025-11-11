//! A small library that allows you to build an XML DOM tree.

/// Represents a single XML attribute, including an optional namespace prefix.
///
/// This struct models attributes like `id="123"` or `android:name="..."`.
/// It is typically owned by an [`Element`].
///
/// # Examples
/// ```
/// use apk_info_xml::Attribute;
///
/// let attr = Attribute::new(None, "id", "123");
/// assert_eq!(attr.name(), "id");
/// assert_eq!(attr.value(), "123");
///
/// let prefixed = Attribute::new(Some("android"), "name", "android.intent.action.PACKAGE_REMOVED");
/// assert_eq!(prefixed.to_string(), "android:name=\"android.intent.action.PACKAGE_REMOVED\"");
/// ```
#[derive(Default, Debug, PartialEq, Eq, Hash)]
pub struct Attribute {
    prefix: Option<String>,
    name: String,
    value: String,
}

impl Attribute {
    /// Creates a new [`Attribute`] with an optional namespace prefix.
    ///
    /// # Examples
    /// ```
    /// use apk_info_xml::Attribute;
    ///
    /// let attr = Attribute::new(Some("xml"), "lang", "en");
    /// assert_eq!(attr.to_string(), "xml:lang=\"en\"");
    /// ```
    pub fn new(prefix: Option<&str>, name: &str, value: &str) -> Attribute {
        Self {
            prefix: prefix.map(String::from),
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    /// Returns the local name of the attribute
    #[inline(always)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the local name of the attribute
    #[inline(always)]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(prefix) = &self.prefix {
            write!(f, "{}:{}=\"{}\"", prefix, self.name, self.value)
        } else {
            write!(f, "{}=\"{}\"", self.name, self.value)
        }
    }
}

/// Represents an XML element, including its name, attributes, and child elements.
///
/// This is the core abstraction over an XML DOM node.
/// It provides methods for building and formatting XML trees programmatically.
///
/// # Examples
/// ```
/// use apk_info_xml::Element;
///
/// let mut root = Element::new("root");
///
/// root.set_attribute("version", "1.0");
/// root.set_attribute_with_prefix(Some("xml"), "lang", "en");
///
/// let mut child = Element::new("child");
/// child.append_child(Element::new("grandchild"));
///
/// println!("{}", root);
/// ```
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Element {
    name: String,
    attributes: Vec<Attribute>,
    childrens: Vec<Element>,
}

impl Element {
    /// Creates a new [`Element`] with the specified tag name and no attributes or children.
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let e = Element::new("root");
    /// assert_eq!(e.name(), "root");
    /// ```
    pub fn new(name: &str) -> Element {
        Element {
            name: name.to_owned(),
            ..Default::default()
        }
    }

    /// Creates a new [`Element`] with the specified tag name and preallocated space for attributes
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let e = Element::with_capacity("root", 16);
    /// assert_eq!(e.name(), "root");
    /// ```
    pub fn with_capacity(name: &str, capacity: usize) -> Element {
        Element {
            name: name.to_owned(),
            attributes: Vec::with_capacity(capacity),
            ..Default::default()
        }
    }

    /// Adds a new attribute without a namespace prefix to the element.
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let e = Element::new("node").set_attribute("id", "42");
    /// ```
    pub fn set_attribute(&mut self, name: &str, value: &str) {
        // if attribute with same already exists - do nothing
        if self.attributes.iter().any(|a| a.name() == name) {
            return;
        }

        self.attributes.push(Attribute::new(None, name, value));
    }

    /// Adds a new attribute with an optional namespace prefix to the element.
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let mut e = Element::new("svg");
    /// e.set_attribute_with_prefix(Some("xlink"), "href", "image.png");
    ///
    /// assert!(e.attributes().collect::<Vec<_>>().len() > 0)
    /// ```
    pub fn set_attribute_with_prefix(&mut self, prefix: Option<&str>, name: &str, value: &str) {
        // if attribute with same already exists - do nothing
        if self
            .attributes
            .iter()
            .any(|a| a.name() == name && a.prefix.as_deref() == prefix)
        {
            return;
        }

        self.attributes.push(Attribute::new(prefix, name, value));
    }

    /// Appends a new child [`Element`] to this element.
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let mut root = Element::new("root");
    /// root.append_child(Element::new("child"));
    /// ```
    #[inline]
    pub fn append_child(&mut self, child: Element) {
        self.childrens.push(child);
    }

    /// Returns an iterator over all child elements.
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let mut root = Element::new("root");
    /// root.append_child(Element::new("child"));
    ///
    /// assert_eq!(root.childrens().count(), 1);
    /// ```
    #[inline]
    pub fn childrens(&self) -> impl Iterator<Item = &Element> {
        self.childrens.iter()
    }

    /// Return an iterator over all [Element]'s from the current root
    ///
    /// # Example
    ///
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let mut root = Element::new("root");
    /// let mut child = Element::new("child");
    /// child.append_child(Element::new("subchild"));
    /// root.append_child(child);
    ///
    /// assert_eq!(root.descendants().count(), 2);
    /// ```
    #[inline]
    pub fn descendants(&self) -> Descendants<'_> {
        Descendants::new(self)
    }

    /// Returns an iterator over the element's attributes.
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let mut e = Element::new("node");
    /// e.set_attribute("id", "42");
    /// assert_eq!(e.attributes().count(), 1);
    /// ```
    #[inline]
    pub fn attributes(&self) -> impl Iterator<Item = &Attribute> {
        self.attributes.iter()
    }

    /// Returns the element's tag name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Retrieves the value of an attribute by name, if present.
    ///
    /// # Example
    /// ```
    /// use apk_info_xml::Element;
    ///
    /// let mut e = Element::new("node");
    /// e.set_attribute("id", "42");
    /// assert_eq!(e.attr("id"), Some("42"));
    /// assert_eq!(e.attr("missing"), None);
    /// ```
    #[inline]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|x| x.name() == name)
            .map(|x| x.value())
    }

    pub(crate) fn fmt_with_indent(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        indent: usize,
    ) -> std::fmt::Result {
        let indent_str = "  ".repeat(indent);

        write!(f, "{}<{}", indent_str, self.name)?;

        if self.attributes.len() > 1 {
            let indent_str = "  ".repeat(indent + 1);

            write!(f, "\n{}", indent_str)?;

            for (idx, attr) in self.attributes.iter().enumerate() {
                write!(f, "{}", attr)?;

                if idx != self.attributes.len() - 1 {
                    write!(f, "\n{}", indent_str)?;
                }
            }
        } else if self.attributes.len() == 1 {
            // safe unwrap, checked that contains at least 1 item
            write!(f, " {}", self.attributes().next().unwrap())?;
        }

        if self.childrens.is_empty() {
            writeln!(f, "/>")?;
        } else {
            writeln!(f, ">")?;

            for child in &self.childrens {
                child.fmt_with_indent(f, indent + 1)?;
            }

            writeln!(f, "{}</{}>", indent_str, self.name)?;
        }

        Ok(())
    }
}

impl std::fmt::Display for Element {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // default xml header
        writeln!(f, "<?xml version=\"1.0\" encoding=\"utf-8\"?>")?;

        // pretty print
        self.fmt_with_indent(f, 0)
    }
}

pub struct Descendants<'a> {
    stack: Vec<std::slice::Iter<'a, Element>>,
}

impl<'a> Descendants<'a> {
    fn new(root: &'a Element) -> Descendants<'a> {
        Descendants {
            stack: vec![root.childrens.iter()],
        }
    }
}

impl<'a> Iterator for Descendants<'a> {
    type Item = &'a Element;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(top_iter) = self.stack.last_mut() {
            if let Some(next_elem) = top_iter.next() {
                if !next_elem.childrens.is_empty() {
                    self.stack.push(next_elem.childrens.iter());
                }
                return Some(next_elem);
            } else {
                self.stack.pop();
            }
        }

        None
    }
}
