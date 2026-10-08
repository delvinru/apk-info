//! The lazy byte source behind every [`ZipEntry`](crate::ZipEntry).
//!
//! A [`Source`] wraps one seekable reader behind a mutex and serves bounded
//! `read_exact_at` calls, so an archive never occupies more memory than the
//! regions actually requested.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex, PoisonError};

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
///
/// A source is a window `[base, base + len)` over the shared stream.
/// [`Source::slice`] carves out a sub-window, so a stored archive nested in a
/// `xapk`/`apkm` parses in place with no copy into memory.
#[derive(Clone)]
pub(crate) struct Source {
    inner: Arc<Mutex<Box<dyn ReadSeek>>>,

    /// Absolute offset of this window in the backing stream.
    base: usize,

    /// Length of this window.
    len: usize,
}

impl Source {
    /// Resolves the stream length by seeking to the end.
    pub(crate) fn new(mut inner: Box<dyn ReadSeek>) -> Result<Source, ZipError> {
        let len =
            usize::try_from(inner.seek(SeekFrom::End(0))?).map_err(|_| ZipError::ParseError)?;

        Ok(Source {
            inner: Arc::new(Mutex::new(inner)),
            base: 0,
            len,
        })
    }

    /// Total length of this window.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Returns a window of `len` bytes at `offset` sharing the same stream,
    /// bounds-checked against this window.
    pub(crate) fn slice(&self, offset: usize, len: usize) -> Result<Source, ZipError> {
        let end = offset.checked_add(len).ok_or(ZipError::EOF)?;
        if end > self.len {
            return Err(ZipError::EOF);
        }

        Ok(Source {
            inner: Arc::clone(&self.inner),
            base: self.base + offset,
            len,
        })
    }

    /// Reads exactly `buf.len()` bytes at `offset`, bounds-checked against the
    /// window length.
    pub(crate) fn read_exact_at(&self, offset: usize, buf: &mut [u8]) -> Result<(), ZipError> {
        let end = offset.checked_add(buf.len()).ok_or(ZipError::EOF)?;
        if end > self.len {
            return Err(ZipError::EOF);
        }

        let mut src = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        src.seek(SeekFrom::Start((self.base + offset) as u64))?;
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
    fn slice_reads_relative_to_its_window() {
        let src = source(b"hello world");
        let sub = src.slice(6, 5).unwrap();
        let mut buf = [0u8; 3];
        sub.read_exact_at(1, &mut buf).unwrap();
        assert_eq!(&buf, b"orl");
        assert_eq!(sub.len(), 5);
    }

    #[test]
    fn slice_is_bounded_by_its_window() {
        let sub = source(b"hello world").slice(6, 5).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(sub.read_exact_at(4, &mut buf).unwrap_err(), ZipError::EOF);
        assert!(matches!(sub.slice(3, 3), Err(ZipError::EOF)));
    }

    #[test]
    fn len_is_resolved_once() {
        assert_eq!(source(b"abcdef").len(), 6);
    }

    #[test]
    fn read_ending_at_last_byte_succeeds() {
        let src = source(b"abcdef");
        let mut buf = [0u8; 2];
        src.read_exact_at(4, &mut buf).unwrap();
        assert_eq!(&buf, b"ef");
    }

    #[test]
    fn zero_length_read_at_end_is_ok() {
        let src = source(b"abc");
        src.read_exact_at(3, &mut []).unwrap();
        assert_eq!(src.read_exact_at(4, &mut []).unwrap_err(), ZipError::EOF);
    }

    #[test]
    fn read_bytes_at_returns_requested_region() {
        let src = source(b"hello world");
        assert_eq!(src.read_bytes_at(0, 5).unwrap(), b"hello");
        assert_eq!(src.read_bytes_at(11, 0).unwrap(), b"");
        assert_eq!(src.read_bytes_at(8, 4).unwrap_err(), ZipError::EOF);
    }

    #[test]
    fn nested_slices_compose_offsets() {
        let src = source(b"0123456789");
        let outer = src.slice(2, 7).unwrap(); // "2345678"
        let inner = outer.slice(3, 3).unwrap(); // "567"

        assert_eq!(inner.len(), 3);
        assert_eq!(inner.read_bytes_at(0, 3).unwrap(), b"567");
        assert!(matches!(inner.slice(1, 3), Err(ZipError::EOF)));
    }

    #[test]
    fn slice_offset_overflow_is_eof_not_panic() {
        let src = source(b"abc");
        assert!(matches!(src.slice(usize::MAX, 2), Err(ZipError::EOF)));
        assert!(matches!(src.slice(1, usize::MAX), Err(ZipError::EOF)));
    }

    #[test]
    fn empty_slice_at_end_is_valid() {
        let sub = source(b"abc").slice(3, 0).unwrap();
        assert_eq!(sub.len(), 0);
        assert_eq!(sub.read_bytes_at(0, 0).unwrap(), b"");
        assert_eq!(sub.read_bytes_at(0, 1).unwrap_err(), ZipError::EOF);
    }

    #[test]
    fn interleaved_parent_and_slice_reads_do_not_disturb_each_other() {
        // every read seeks first, so the shared cursor position left by one
        // window must not leak into the next read of another window
        let src = source(b"hello world");
        let sub = src.slice(6, 5).unwrap();

        assert_eq!(sub.read_bytes_at(0, 2).unwrap(), b"wo");
        assert_eq!(src.read_bytes_at(0, 2).unwrap(), b"he");
        assert_eq!(sub.read_bytes_at(2, 3).unwrap(), b"rld");
        assert_eq!(src.read_bytes_at(2, 3).unwrap(), b"llo");
    }

    #[test]
    fn slice_outlives_its_parent() {
        let sub = {
            let src = source(b"hello world");
            src.slice(6, 5).unwrap()
        };
        assert_eq!(sub.read_bytes_at(0, 5).unwrap(), b"world");
    }

    #[test]
    fn initial_reader_position_is_ignored() {
        let mut cursor = Cursor::new(b"hello world".to_vec());
        cursor.set_position(6);

        let src = Source::new(Box::new(cursor)).unwrap();
        assert_eq!(src.len(), 11);
        assert_eq!(src.read_bytes_at(0, 5).unwrap(), b"hello");
    }

    /// A stream that reports a longer length than it can deliver, like a file
    /// truncated after the archive was opened.
    struct Truncated(Cursor<Vec<u8>>);

    impl Read for Truncated {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Seek for Truncated {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            match pos {
                SeekFrom::End(_) => Ok(self.0.get_ref().len() as u64 * 2),
                other => self.0.seek(other),
            }
        }
    }

    #[test]
    fn short_stream_reports_io_error() {
        let src = Source::new(Box::new(Truncated(Cursor::new(b"abc".to_vec())))).unwrap();
        assert_eq!(src.len(), 6);

        let mut buf = [0u8; 4];
        assert_eq!(
            src.read_exact_at(1, &mut buf).unwrap_err(),
            ZipError::IoError(std::io::ErrorKind::UnexpectedEof)
        );
    }

    /// A stream whose first read panics, poisoning the source mutex.
    struct PanicsOnce {
        inner: Cursor<Vec<u8>>,
        panicked: bool,
    }

    impl Read for PanicsOnce {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.panicked {
                self.panicked = true;
                panic!("reader failure");
            }
            self.inner.read(buf)
        }
    }

    impl Seek for PanicsOnce {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn poisoned_lock_does_not_block_later_reads() {
        let src = Source::new(Box::new(PanicsOnce {
            inner: Cursor::new(b"hello".to_vec()),
            panicked: false,
        }))
        .unwrap();

        let mut buf = [0u8; 5];
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            src.read_exact_at(0, &mut buf)
        }));
        assert!(first.is_err(), "the first read should panic");

        src.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn concurrent_reads_get_their_own_regions() {
        let data: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
        let src = source(&data);

        std::thread::scope(|scope| {
            for t in 0..8usize {
                let (src, data) = (&src, &data);
                scope.spawn(move || {
                    // each thread reads its own window through a slice, many
                    // times, so racing seek + read pairs would show up
                    let start = t * 8 * 1024;
                    let sub = src.slice(start, 8 * 1024).unwrap();
                    for i in 0..200 {
                        let off = (i * 37) % (8 * 1024 - 64);
                        let got = sub.read_bytes_at(off, 64).unwrap();
                        assert_eq!(got, data[start + off..start + off + 64]);
                    }
                });
            }
        });
    }
}
