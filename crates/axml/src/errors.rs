use thiserror::Error;

#[derive(Error, Debug)]
pub enum AXMLError {
    /// Provided file too small to be manifest
    #[error("file size too small for manifest")]
    TooSmallError,

    /// Invalid header
    #[error("got error while parsing header")]
    HeaderError,

    /// Invalid header
    #[error("got invalid header size, expected - 8")]
    HeaderSizeError(u16),

    /// Got error while parsing resource map
    #[error("got error while parsing resource map")]
    ResourceMapError,

    /// Got error while parsing string pool
    #[error("got error while parsing string pool")]
    StringPoolError,

    /// Got error while parsing xml tree
    #[error("got error while parsing xml tree")]
    XmlTreeError,

    /// Got error while parsing manifest
    #[error("got error while parsing manifest")]
    ParseError,
}
