//! A small library that allows you to build an XML DOM tree.

use std::fmt::{Display as _, Write as _};

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
        // attribute value may contain characters that break XML output:
        // - control chars (except \t \n \r) are invalid in XML entirely
        // - newlines would break the pretty-printed structure
        // - &, <, >, ", ' need to be escaped for valid XML
        if let Some(prefix) = &self.prefix {
            f.write_str(prefix)?;
            f.write_char(':')?;
        }
        f.write_str(&self.name)?;
        f.write_str("=\"")?;
        write_attr_value(f, &self.value)?; // empty -> writes nothing here
        f.write_str("\"")
    }
}

/// Returns whether `ch` is a code point permitted in XML 1.0 attribute values.
///
/// The allowed ranges are `#x20`–`#xD7FF`, `#xE000`–`#xFFFD` and
/// `#x10000`–`#x10FFFF`. Everything outside them (control characters below
/// `#x20` except `\t`/`\n`/`\r`, surrogates, and `#xFFFE`/`#xFFFF`) is not
/// representable in a well-formed XML 1.0 document.
#[inline]
fn is_valid_xml_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

/// Writes `value` to `f` escaped for use inside an XML attribute value.
///
/// The written output is always well-formed XML 1.0:
///
/// * `\t`, `\n`, `\r` are replaced with a single space (` `), so multi-line and
///   tab-indented values cannot break the pretty-printed element layout.
/// * `&`, `<`, `>`, `"` and `'` are escaped as `&amp;`, `&lt;`, `&gt;`,
///   `&quot;` and `&apos;` respectively.
/// * Code points that are not valid in XML 1.0 (see [`is_valid_xml_char`]) are
///   dropped entirely.
/// * A value that contains no valid characters writes nothing.
///
/// # Examples
///
/// Escaping of the XML-special characters (newlines become spaces):
///
/// ```
/// use apk_info_xml::Attribute;
///
/// let attr = Attribute::new(None, "label", "AVG Antivirus & Security\n<pro>\"v1\"");
/// assert_eq!(attr.to_string(), "label=\"AVG Antivirus &amp; Security &lt;pro&gt;&quot;v1&quot;\"");
/// ```
///
/// A value made up only of invalid characters renders as an empty attribute:
///
/// ```
/// use apk_info_xml::Attribute;
///
/// let attr = Attribute::new(None, "a", "\u{1}\u{FFFF}");
/// assert_eq!(attr.to_string(), "a=\"\"");
/// ```
#[inline]
fn write_attr_value(f: &mut std::fmt::Formatter<'_>, value: &str) -> std::fmt::Result {
    let bytes = value.as_bytes();
    let mut run_start = 0;
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        // Fast path: batch a run of already-safe ASCII bytes into one write_str.
        let ascii_safe =
            (0x20..0x80).contains(&b) && !matches!(b, b'&' | b'<' | b'>' | b'"' | b'\'');
        if ascii_safe {
            i += 1;
            continue;
        }

        if run_start < i {
            f.write_str(&value[run_start..i])?;
        }

        // `i` is always on a char boundary here.
        let ch = value[i..].chars().next().unwrap();
        match ch {
            '\t' | '\n' | '\r' => f.write_char(' ')?,
            '&' => f.write_str("&amp;")?,
            '<' => f.write_str("&lt;")?,
            '>' => f.write_str("&gt;")?,
            '"' => f.write_str("&quot;")?,
            '\'' => f.write_str("&apos;")?,
            c if is_valid_xml_char(c) => f.write_char(c)?, // non-ASCII valid char
            _ => {} // invalid XML char, drop it (same as before)
        }

        i += ch.len_utf8();
        run_start = i;
    }

    if run_start < i {
        f.write_str(&value[run_start..i])?;
    }
    Ok(())
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
        write_indent(f, indent)?;
        f.write_char('<')?;
        f.write_str(&self.name)?;

        match self.attributes.len() {
            0 => {}
            1 => {
                f.write_char(' ')?;
                self.attributes[0].fmt(f)?;
            }
            n => {
                let child_indent = indent + 1;
                f.write_char('\n')?;
                write_indent(f, child_indent)?;
                for (idx, attr) in self.attributes.iter().enumerate() {
                    attr.fmt(f)?;
                    if idx + 1 != n {
                        f.write_char('\n')?;
                        write_indent(f, child_indent)?;
                    }
                }
            }
        }

        if self.childrens.is_empty() {
            f.write_str("/>")?;
            f.write_char('\n')?;
        } else {
            f.write_char('>')?;
            f.write_char('\n')?;
            for child in &self.childrens {
                child.fmt_with_indent(f, indent + 1)?;
            }
            write_indent(f, indent)?;
            f.write_str("</")?;
            f.write_str(&self.name)?;
            f.write_str(">\n")?;
        }
        Ok(())
    }
}

/// Writes `indent` levels of two-space indentation into `f` without allocating.
#[inline]
fn write_indent(f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
    for _ in 0..indent {
        f.write_str("  ")?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_plain_renders_quoted() {
        assert_eq!(Attribute::new(None, "id", "123").to_string(), "id=\"123\"");
    }

    #[test]
    fn attribute_prefixed_renders() {
        assert_eq!(
            Attribute::new(Some("android"), "name", "x").to_string(),
            "android:name=\"x\""
        );
    }

    #[test]
    fn attribute_escapes_specials() {
        assert_eq!(
            Attribute::new(None, "a", "&\n<>\"'").to_string(),
            "a=\"&amp; &lt;&gt;&quot;&apos;\""
        );
    }

    #[test]
    fn attribute_tabs_cr_to_space() {
        assert_eq!(
            Attribute::new(None, "a", "x\ty\r").to_string(),
            "a=\"x y \""
        );
    }

    #[test]
    fn attribute_all_invalid_renders_empty() {
        assert_eq!(
            Attribute::new(None, "a", "\u{1}\u{FFFF}\u{FFFE}").to_string(),
            "a=\"\""
        );
    }

    #[test]
    fn attribute_non_ascii_preserved() {
        assert_eq!(
            Attribute::new(None, "a", "café 😀").to_string(),
            "a=\"café 😀\""
        );
    }

    #[test]
    fn element_render_golden() {
        let mut root = Element::new("root");
        root.set_attribute("a", "1");
        root.set_attribute("b", "2");

        let mut child = Element::new("child");
        child.set_attribute("x", "y");
        root.append_child(child);

        let mut ns_kid = Element::new("ns:kid");
        ns_kid.set_attribute("prefix", "p");
        root.append_child(ns_kid);

        let expected = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<root\n  a=\"1\"\n  b=\"2\">\n  <child x=\"y\"/>\n  <ns:kid prefix=\"p\"/>\n</root>\n";
        assert_eq!(root.to_string(), expected);
    }
}
