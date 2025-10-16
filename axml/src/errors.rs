#[derive(Debug)]
pub enum AXMLError {
    Header,
    HeaderSize,
    Parse,
    ResourceMap,
    StringPool,
    TooSmall,
    XmlTree,
}
