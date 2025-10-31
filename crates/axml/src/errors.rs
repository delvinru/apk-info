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

    #[error("can't get root for xml tree")]
    MissingRoot,

    /// Got error while parsing manifest
    #[error("got error while parsing manifest")]
    ParseError,
}

#[derive(Error, Debug)]
pub enum ARCSError {
    /// Provided file too smal to be resources.arsc
    #[error("file size too small for resources file")]
    TooSmallError,

    /// Invalid header
    #[error("got error while parsing header")]
    HeaderError,

    /// Got error while parsing string pool
    #[error("got error while parsing string pool")]
    StringPoolError,

    /// Got error while parsing resource table package
    #[error("got error while parsing resource table package")]
    ResourceTableError,
}
