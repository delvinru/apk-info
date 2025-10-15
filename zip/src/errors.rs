#[derive(Debug)]
pub enum ZipError {
    DecompressionError,
    EOF,
    FileNotFound,
    NotFoundEOCD,
    ParseError,
}

#[derive(Debug)]
pub enum FileCompressionType {
    Stored,
    Deflated,
    StoredTampered,
    DeflatedTampered,
}
