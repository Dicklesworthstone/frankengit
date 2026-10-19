#![forbid(unsafe_code)]
//! Hard byte bounds for local immutable bodies, including files that grow.
//!
//! A metadata length is only an early refusal, never the read budget. The
//! open handle is used for metadata and every read; one extra byte is probed
//! without adding it to the returned allocation. This does not turn an
//! operator-owned directory into a hostile-filesystem sandbox.

use std::fs::{self, File};
use std::io::{self, Read, Seek};
use std::path::Path;

use crate::fabric::{StorageOperation, StoreRefusal};

const READ_CHUNK_BYTES: usize = 64 * 1024;

fn read_error(error: io::Error) -> StoreRefusal {
    if error.kind() == io::ErrorKind::NotFound {
        StoreRefusal::ObjectAbsent
    } else {
        StoreRefusal::StorageIo {
            operation: StorageOperation::ReadBody,
            kind: error.kind(),
        }
    }
}

fn non_regular_file() -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation: StorageOperation::ReadBody,
        kind: io::ErrorKind::InvalidInput,
    }
}

fn open_regular(path: &Path) -> Result<(File, u64), StoreRefusal> {
    // Reject persistent symlinks, directories and special files before open.
    // No claim is made about adversarial replacement of path components.
    let path_metadata = fs::symlink_metadata(path).map_err(read_error)?;
    if !path_metadata.file_type().is_file() {
        return Err(non_regular_file());
    }
    let file = File::open(path).map_err(read_error)?;
    let metadata = file.metadata().map_err(read_error)?;
    if !metadata.is_file() {
        return Err(non_regular_file());
    }
    Ok((file, metadata.len()))
}

pub(super) fn read(path: &Path, maximum: u64) -> Result<Vec<u8>, StoreRefusal> {
    let (mut file, length) = open_regular(path)?;
    read_stream(&mut file, length, maximum)
}

/// Bound the payload before reserving a buffer for a stored FGOB body. Read
/// only the fixed prefix first; its envelope length is bounded independently.
/// The exact-key owner still verifies the envelope, payload and native identity.
pub(super) fn read_object(
    path: &Path,
    maximum_stored: u64,
    maximum_envelope: usize,
    maximum_payload: u64,
) -> Result<Vec<u8>, StoreRefusal> {
    let (mut file, length) = open_regular(path)?;
    if length > maximum_stored {
        return Err(StoreRefusal::StoredObjectTooLarge {
            offered: length,
            maximum: maximum_stored,
        });
    }
    if length < 8 {
        return Err(StoreRefusal::MalformedStoredObject);
    }
    let mut prefix = [0; 8];
    file.read_exact(&mut prefix).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            StoreRefusal::MalformedStoredObject
        } else {
            read_error(error)
        }
    })?;
    if &prefix[..4] != super::OBJECT_MAGIC {
        return Err(StoreRefusal::MalformedStoredObject);
    }
    let envelope = u32::from_be_bytes(
        prefix[4..]
            .try_into()
            .map_err(|_| StoreRefusal::MalformedStoredObject)?,
    );
    if u64::from(envelope) > maximum_envelope as u64 {
        return Err(crate::FabricError::EnvelopeTooLarge.into());
    }
    let payload_start = 8 + u64::from(envelope);
    let offered = length
        .checked_sub(payload_start)
        .ok_or(StoreRefusal::MalformedStoredObject)?;
    if offered > maximum_payload {
        return Err(StoreRefusal::StreamingBudgetExceeded {
            offered,
            maximum: maximum_payload,
        });
    }
    // Reuse this same descriptor and the growth-resistant stream reader. A
    // changing envelope can alter the payload boundary, so load_object_within
    // also checks the decoded payload length before copying or verification.
    file.rewind().map_err(read_error)?;
    let maximum = maximum_stored.min(payload_start.saturating_add(maximum_payload));
    read_stream(&mut file, length, maximum).map_err(|error| match error {
        StoreRefusal::StoredObjectTooLarge { offered, .. } if maximum < maximum_stored => {
            StoreRefusal::StreamingBudgetExceeded {
                offered: offered.saturating_sub(payload_start),
                maximum: maximum_payload,
            }
        }
        other => other,
    })
}

fn read_stream<R: Read>(
    reader: &mut R,
    offered: u64,
    maximum: u64,
) -> Result<Vec<u8>, StoreRefusal> {
    if offered > maximum {
        return Err(StoreRefusal::StoredObjectTooLarge { offered, maximum });
    }
    let initial = usize::try_from(offered).map_err(|_| StoreRefusal::LengthOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(initial)
        .map_err(|_| StoreRefusal::StorageIo {
            operation: StorageOperation::ReadBody,
            kind: io::ErrorKind::OutOfMemory,
        })?;
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    loop {
        let consumed = u64::try_from(bytes.len()).map_err(|_| StoreRefusal::LengthOverflow)?;
        let remaining = maximum
            .checked_sub(consumed)
            .ok_or(StoreRefusal::LengthOverflow)?;
        // Even maximum == u64::MAX never requires maximum + 1 arithmetic.
        // With no budget left, a one-byte probe distinguishes exact EOF from
        // growth. The probe is never appended to `bytes`.
        let request = usize::try_from(remaining.min(READ_CHUNK_BYTES as u64))
            .map_err(|_| StoreRefusal::LengthOverflow)?
            .max(1);
        let count = match reader.read(&mut buffer[..request]) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(read_error(error)),
        };
        if count == 0 {
            if consumed != offered {
                return Err(StoreRefusal::MalformedStoredObject);
            }
            return Ok(bytes);
        }
        if remaining == 0 {
            return Err(StoreRefusal::StoredObjectTooLarge {
                offered: consumed
                    .checked_add(1)
                    .ok_or(StoreRefusal::LengthOverflow)?,
                maximum,
            });
        }
        bytes
            .try_reserve_exact(count)
            .map_err(|_| StoreRefusal::StorageIo {
                operation: StorageOperation::ReadBody,
                kind: io::ErrorKind::OutOfMemory,
            })?;
        bytes.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            loop {
                let path = std::env::temp_dir().join(format!(
                    "frankengit-bounded-read-{}-{}",
                    std::process::id(),
                    NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create isolated test directory: {error}"),
                }
            }
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exact_limit_and_empty_bodies_are_read_byte_for_byte() {
        for body in [
            Vec::new(),
            vec![0, 255, 1, 0],
            vec![93; READ_CHUNK_BYTES * 2 + 7],
        ] {
            let size = body.len() as u64;
            assert_eq!(
                read_stream(&mut Cursor::new(&body), size, size).unwrap(),
                body
            );
        }
    }

    #[test]
    fn static_oversize_is_refused_before_any_read() {
        struct NeverRead;
        impl Read for NeverRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("oversized metadata must be refused before reading");
            }
        }
        assert_eq!(
            read_stream(&mut NeverRead, 17, 16),
            Err(StoreRefusal::StoredObjectTooLarge {
                offered: 17,
                maximum: 16,
            })
        );
    }

    #[test]
    fn growing_stream_consumes_at_most_the_limit_plus_one_byte() {
        struct Growing {
            consumed: usize,
        }
        impl Read for Growing {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer.fill(42);
                self.consumed += buffer.len();
                Ok(buffer.len())
            }
        }
        for maximum in [0, 1, READ_CHUNK_BYTES as u64, READ_CHUNK_BYTES as u64 + 17] {
            let mut source = Growing { consumed: 0 };
            assert_eq!(
                read_stream(&mut source, 0, maximum),
                Err(StoreRefusal::StoredObjectTooLarge {
                    offered: maximum + 1,
                    maximum,
                })
            );
            assert_eq!(source.consumed as u64, maximum + 1);
        }
    }

    #[test]
    fn shrinkage_and_growth_within_the_budget_are_not_accepted_as_immutable() {
        assert_eq!(
            read_stream(&mut Cursor::new(b"abc"), 4, 16),
            Err(StoreRefusal::MalformedStoredObject)
        );
        assert_eq!(
            read_stream(&mut Cursor::new(b"abcde"), 4, 16),
            Err(StoreRefusal::MalformedStoredObject)
        );
    }

    #[test]
    fn interrupted_read_is_retried_but_other_io_errors_are_returned() {
        struct InterruptedOnce {
            inner: Cursor<Vec<u8>>,
            interrupted: bool,
        }
        impl Read for InterruptedOnce {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.inner.read(buffer)
            }
        }
        let mut source = InterruptedOnce {
            inner: Cursor::new(vec![0, 255]),
            interrupted: false,
        };
        assert_eq!(read_stream(&mut source, 2, 2).unwrap(), vec![0, 255]);
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }
        assert_eq!(
            read_stream(&mut Broken, 0, 8),
            Err(StoreRefusal::StorageIo {
                operation: StorageOperation::ReadBody,
                kind: io::ErrorKind::PermissionDenied,
            })
        );
    }

    #[test]
    fn filesystem_read_preserves_bytes_and_typed_missing_refusal() {
        let directory = Directory::new();
        let path = directory.0.join("body");
        assert_eq!(read(&path, 16), Err(StoreRefusal::ObjectAbsent));
        fs::write(&path, [0, 1, 255, 0]).unwrap();
        assert_eq!(read(&path, 4).unwrap(), [0, 1, 255, 0]);
        assert_eq!(
            read(&path, 3),
            Err(StoreRefusal::StoredObjectTooLarge {
                offered: 4,
                maximum: 3
            })
        );
    }

    #[test]
    fn sparse_oversize_is_refused_without_materializing_the_file() {
        let directory = Directory::new();
        let path = directory.0.join("sparse");
        File::create(&path)
            .unwrap()
            .set_len(4 * 1024 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            read(&path, 16),
            Err(StoreRefusal::StoredObjectTooLarge {
                offered: 4 * 1024 * 1024 * 1024,
                maximum: 16,
            })
        );
    }

    #[test]
    fn directories_are_not_object_bodies() {
        let directory = Directory::new();
        assert_eq!(read(&directory.0, 1_024), Err(non_regular_file()));
    }

    #[cfg(unix)]
    #[test]
    fn persistent_symlinks_are_refused_without_changing_the_target() {
        let directory = Directory::new();
        let target = directory.0.join("target");
        let link = directory.0.join("link");
        fs::write(&target, b"outside-body").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(read(&link, 1_024), Err(non_regular_file()));
        assert_eq!(fs::read(&target).unwrap(), b"outside-body");
    }
}
