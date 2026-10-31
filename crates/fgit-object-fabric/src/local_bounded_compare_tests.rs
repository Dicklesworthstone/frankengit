//! Read-instrumented bounds and exactness checks independent of filesystem timing.

use super::*;

struct Observed<R> {
    inner: R,
    consumed: u64,
    largest_request: usize,
}

impl<R> Observed<R> {
    const fn new(inner: R) -> Self {
        Self {
            inner,
            consumed: 0,
            largest_request: 0,
        }
    }
}

impl<R: Read> Read for Observed<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.largest_request = self.largest_request.max(buffer.len());
        let count = self.inner.read(buffer)?;
        self.consumed += count as u64;
        Ok(count)
    }
}

struct ShortReads<'a> {
    remaining: &'a [u8],
    maximum: usize,
    interrupted: bool,
}

impl Read for ShortReads<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.interrupted = !self.interrupted;
        if self.interrupted {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = buffer.len().min(self.maximum);
        self.remaining.read(&mut buffer[..count])
    }
}

struct NeverRead;

impl Read for NeverRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("metadata refusal must precede every body read")
    }
}

struct FailureAfter {
    remaining: usize,
}

impl Read for FailureAfter {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let count = buffer.len().min(self.remaining);
        buffer[..count].fill(0);
        self.remaining -= count;
        Ok(count)
    }
}

#[test]
fn exact_bytes_are_compared_across_chunks_and_independent_short_reads() {
    for length in [
        0,
        1,
        COMPARE_CHUNK_BYTES - 1,
        COMPARE_CHUNK_BYTES,
        COMPARE_CHUNK_BYTES + 1,
        COMPARE_CHUNK_BYTES * 3 + 7,
    ] {
        let bytes: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        let mut left = Observed::new(ShortReads {
            remaining: &bytes,
            maximum: 7,
            interrupted: false,
        });
        let mut right = Observed::new(ShortReads {
            remaining: &bytes,
            maximum: 31,
            interrupted: false,
        });
        assert_eq!(
            equal_streams(
                &mut left,
                length as u64,
                &mut right,
                length as u64,
                length as u64
            ),
            Ok(true)
        );
        assert_eq!(left.consumed, length as u64);
        assert_eq!(right.consumed, length as u64);
        assert!(left.largest_request <= COMPARE_CHUNK_BYTES);
        assert!(right.largest_request <= COMPARE_CHUNK_BYTES);
    }
}

#[test]
fn matching_lengths_do_not_hide_any_different_byte() {
    let length = COMPARE_CHUNK_BYTES * 2 + 11;
    let original = vec![17; length];
    for changed in [0, COMPARE_CHUNK_BYTES - 1, COMPARE_CHUNK_BYTES, length - 1] {
        let mut different = original.clone();
        different[changed] ^= 1;
        assert_eq!(
            equal_streams(
                &mut original.as_slice(),
                length as u64,
                &mut different.as_slice(),
                length as u64,
                length as u64,
            ),
            Ok(false)
        );
    }
}

#[test]
fn both_metadata_lengths_are_bounded_before_any_read_or_length_comparison() {
    for (left, right) in [(17, 4), (4, 17), (17, 17)] {
        assert_eq!(
            equal_streams(&mut NeverRead, left, &mut NeverRead, right, 16),
            Err(StoreRefusal::StoredObjectTooLarge {
                offered: 17,
                maximum: 16,
            })
        );
    }
    assert_eq!(
        equal_streams(&mut NeverRead, 4, &mut NeverRead, 5, 16),
        Ok(false)
    );
    assert_eq!(
        equal_streams(
            &mut NeverRead,
            u64::MAX,
            &mut NeverRead,
            u64::MAX - 1,
            u64::MAX
        ),
        Ok(false)
    );
}

#[test]
fn growing_streams_never_exceed_checked_length_plus_one_byte() {
    for length in [0, 1, (COMPARE_CHUNK_BYTES * 2 + 3) as u64] {
        for maximum in [length, length + 7] {
            let expected = if maximum == length {
                StoreRefusal::StoredObjectTooLarge {
                    offered: length + 1,
                    maximum,
                }
            } else {
                StoreRefusal::MalformedStoredObject
            };
            let mut left = Observed::new(io::repeat(0));
            let mut right = Observed::new(io::repeat(0));
            assert_eq!(
                equal_streams(&mut left, length, &mut right, length, maximum),
                Err(expected.clone())
            );
            assert_eq!(left.consumed, length + 1);
            assert_eq!(right.consumed, length);
            assert!(left.largest_request <= COMPARE_CHUNK_BYTES);
            assert!(right.largest_request <= COMPARE_CHUNK_BYTES);

            let mut left = Observed::new(io::repeat(0).take(length));
            let mut right = Observed::new(io::repeat(0));
            assert_eq!(
                equal_streams(&mut left, length, &mut right, length, maximum),
                Err(expected)
            );
            assert_eq!(left.consumed, length);
            assert_eq!(right.consumed, length + 1);
            assert!(right.largest_request <= COMPARE_CHUNK_BYTES);
        }
    }
}

#[test]
fn shrinkage_is_refused_even_when_both_files_shrink_identically() {
    for (left, right) in [(3, 4), (4, 3), (3, 3)] {
        assert_eq!(
            equal_streams(
                &mut io::repeat(0).take(left),
                4,
                &mut io::repeat(0).take(right),
                4,
                16,
            ),
            Err(StoreRefusal::MalformedStoredObject)
        );
    }
}

#[test]
fn read_and_eof_probe_errors_keep_the_publication_operation() {
    let length = COMPARE_CHUNK_BYTES + 5;
    for failure_after in [0, COMPARE_CHUNK_BYTES / 2, length] {
        for failing_left in [false, true] {
            let mut failing = FailureAfter {
                remaining: failure_after,
            };
            let mut complete = io::repeat(0).take(length as u64);
            let result = if failing_left {
                equal_streams(
                    &mut failing,
                    length as u64,
                    &mut complete,
                    length as u64,
                    length as u64,
                )
            } else {
                equal_streams(
                    &mut complete,
                    length as u64,
                    &mut failing,
                    length as u64,
                    length as u64,
                )
            };
            assert_eq!(
                result,
                Err(StoreRefusal::StorageIo {
                    operation: StorageOperation::PublishImmutableBody,
                    kind: io::ErrorKind::PermissionDenied,
                })
            );
        }
    }
}
