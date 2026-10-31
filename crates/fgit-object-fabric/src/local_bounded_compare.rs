#![forbid(unsafe_code)]
//! Exact comparison of a synced stage and an existing immutable body.
//!
//! No object-sized allocation is made. Both handle lengths must fit the
//! storage profile before any body is read. Comparison consumes at most each
//! checked length plus one EOF-probe byte, even if a file keeps growing.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use super::{StorageOperation, StoreRefusal, storage_error};

const COMPARE_CHUNK_BYTES: usize = 16 * 1024;

fn comparison_error(error: io::Error) -> StoreRefusal {
    storage_error(StorageOperation::PublishImmutableBody, error)
}

const fn non_regular_file() -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation: StorageOperation::PublishImmutableBody,
        kind: io::ErrorKind::InvalidInput,
    }
}

fn open_regular(path: &Path) -> Result<(File, u64), StoreRefusal> {
    // Match the bounded readers: reject persistent symlinks, directories and
    // special files before open, then check the same handle used for reading.
    // The operator must still keep the storage root and ancestors stable.
    let path_metadata = fs::symlink_metadata(path).map_err(comparison_error)?;
    if !path_metadata.file_type().is_file() {
        return Err(non_regular_file());
    }
    let file = File::open(path).map_err(comparison_error)?;
    let metadata = file.metadata().map_err(comparison_error)?;
    if !metadata.is_file() {
        return Err(non_regular_file());
    }
    Ok((file, metadata.len()))
}

pub(super) fn equal(left: &Path, right: &Path, maximum: u64) -> Result<bool, StoreRefusal> {
    let (mut left, left_length) = open_regular(left)?;
    let (mut right, right_length) = open_regular(right)?;
    equal_streams(&mut left, left_length, &mut right, right_length, maximum)
}

fn equal_streams<L: Read, R: Read>(
    left: &mut L,
    left_length: u64,
    right: &mut R,
    right_length: u64,
    maximum: u64,
) -> Result<bool, StoreRefusal> {
    for offered in [left_length, right_length] {
        if offered > maximum {
            return Err(StoreRefusal::StoredObjectTooLarge { offered, maximum });
        }
    }
    if left_length != right_length {
        return Ok(false);
    }
    let mut left_buffer = [0; COMPARE_CHUNK_BYTES];
    let mut right_buffer = [0; COMPARE_CHUNK_BYTES];
    let mut remaining = left_length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(COMPARE_CHUNK_BYTES as u64))
            .map_err(|_| StoreRefusal::LengthOverflow)?;
        left.read_exact(&mut left_buffer[..count])
            .map_err(eof_is_malformed)?;
        right
            .read_exact(&mut right_buffer[..count])
            .map_err(eof_is_malformed)?;
        if left_buffer[..count] != right_buffer[..count] {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    // A matching prefix or matching metadata is never sufficient. Probe
    // each handle once, without following growth to an unbounded new EOF.
    require_eof(left, left_length, maximum)?;
    require_eof(right, right_length, maximum)?;
    Ok(true)
}

fn eof_is_malformed(error: io::Error) -> StoreRefusal {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        StoreRefusal::MalformedStoredObject
    } else {
        comparison_error(error)
    }
}

fn require_eof<R: Read>(reader: &mut R, length: u64, maximum: u64) -> Result<(), StoreRefusal> {
    let mut probe = [0; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                let offered = length.checked_add(1).ok_or(StoreRefusal::LengthOverflow)?;
                return Err(if offered > maximum {
                    StoreRefusal::StoredObjectTooLarge { offered, maximum }
                } else {
                    StoreRefusal::MalformedStoredObject
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(comparison_error(error)),
        }
    }
}

#[cfg(test)]
#[path = "local_bounded_compare_tests.rs"]
mod tests;
