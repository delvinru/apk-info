//! The lazy byte source behind every [`ZipEntry`](crate::ZipEntry).
//!
//! A [`Source`] wraps one seekable reader behind a mutex and serves bounded
//! `read_exact_at` calls, so an archive never occupies more memory than the
//! regions actually requested.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Mutex, PoisonError};

use crate::ZipError;

/// A seekable byte source that a [`ZipEntry`](crate::ZipEntry) reads lazily from.
///
/// In-memory buffers, files on disk and arbitrary streams all go through
/// this single interface; the whole archive is never held in memory.
pub trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// A seekable byte source with its length resolved once at construction.
///
/// Reads are bounded `seek` + `read_exact` calls behind a mutex, so
/// [`ZipEntry`](crate::ZipEntry) can share the source through `&self` and only
/// hold the requested region. The trait object is boxed once, at the
/// [`ZipEntry::from_reader`](crate::ZipEntry::from_reader) boundary.
pub(crate) struct Source {
    inner: Mutex<Box<dyn ReadSeek>>,

    /// Total length of the backing stream.
    len: usize,
}

impl Source {
    /// Resolves the stream length by seeking to the end.
    pub(crate) fn new(mut inner: Box<dyn ReadSeek>) -> Result<Source, ZipError> {
        let len =
            usize::try_from(inner.seek(SeekFrom::End(0))?).map_err(|_| ZipError::ParseError)?;

        Ok(Source {
            inner: Mutex::new(inner),
            len,
        })
    }

    /// Total length of the backing stream.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Reads exactly `buf.len()` bytes at `offset`, bounds-checked against the
    /// stream length.
    pub(crate) fn read_exact_at(&self, offset: usize, buf: &mut [u8]) -> Result<(), ZipError> {
        let end = offset.checked_add(buf.len()).ok_or(ZipError::EOF)?;
        if end > self.len {
            return Err(ZipError::EOF);
        }

        let mut src = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        src.seek(SeekFrom::Start(offset as u64))?;
        src.read_exact(buf)?;
        Ok(())
    }

    /// Reads `len` bytes at `offset` into a fresh buffer.
    pub(crate) fn read_bytes_at(&self, offset: usize, len: usize) -> Result<Vec<u8>, ZipError> {
        let mut buf = vec![0u8; len];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn source(data: &[u8]) -> Source {
        Source::new(Box::new(Cursor::new(data.to_vec()))).unwrap()
    }

    #[test]
    fn read_exact_at_returns_requested_region() {
        let src = source(b"hello world");
        let mut buf = [0u8; 5];
        src.read_exact_at(6, &mut buf).unwrap();
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn read_past_end_is_eof() {
        let src = source(b"abc");
        let mut buf = [0u8; 2];
        assert_eq!(src.read_exact_at(2, &mut buf).unwrap_err(), ZipError::EOF);
    }

    #[test]
    fn offset_overflow_is_eof_not_panic() {
        let src = source(b"abc");
        let mut buf = [0u8; 8];
        assert_eq!(
            src.read_exact_at(usize::MAX, &mut buf).unwrap_err(),
            ZipError::EOF
        );
    }

    #[test]
    fn len_is_resolved_once() {
        assert_eq!(source(b"abcdef").len(), 6);
    }
}
