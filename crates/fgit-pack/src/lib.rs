#![forbid(unsafe_code)]

//! Safe, bounded parsing and reconstruction primitives for Git pack v2 and
//! idx v2 files. This crate deliberately does not implement DEFLATE or Git
//! hashing: callers supply those dependency-owned operations at the
//! quarantine boundary.

mod delta;
mod idx;
mod pack;

pub use delta::{
    DeltaBase, DeltaObject, ExternalBaseLookup, PackObject, ScalarResolver, apply_delta,
};
pub use fgit_types::native::{GitHashAlgorithm as ObjectFormat, GitOid as ObjectId};
pub use idx::{IdxEntry, IdxV2};
pub use pack::{
    EntryKind, PackEntryHeader, PackHeader, PackTrailerVerifier, ParsedDeltaBase,
    decode_entry_header, decode_ofs_delta_base, parse_delta_base, parse_pack_header,
    split_pack_trailer, validate_pack_trailer,
};

use std::error::Error;
use std::fmt;

pub(crate) fn object_id_from_bytes(
    format: ObjectFormat,
    bytes: &[u8],
) -> Result<ObjectId, PackError> {
    use fgit_types::native::{GitOidSha1, GitOidSha256};

    match format {
        ObjectFormat::Sha1 => {
            let array: [u8; 20] = bytes.try_into().map_err(|_| PackError::ObjectIdLength {
                expected: 20,
                actual: bytes.len(),
            })?;
            Ok(GitOidSha1::from_bytes(array).into())
        }
        ObjectFormat::Sha256 => {
            let array: [u8; 32] = bytes.try_into().map_err(|_| PackError::ObjectIdLength {
                expected: 32,
                actual: bytes.len(),
            })?;
            Ok(GitOidSha256::from_bytes(array).into())
        }
    }
}

/// Limits that must be selected by the quarantine caller before parsing or
/// resolving untrusted pack material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackLimits {
    pub max_input_bytes: usize,
    pub max_entries: u32,
    pub max_object_bytes: usize,
    pub max_delta_depth: usize,
    pub max_delta_fanout: usize,
    pub max_total_expanded_bytes: usize,
    pub max_expansion_ratio: usize,
    pub max_delta_work: usize,
    pub max_index_entries: usize,
}

impl Default for PackLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_entries: 1_000_000,
            max_object_bytes: 32 * 1024 * 1024,
            max_delta_depth: 64,
            max_delta_fanout: 4096,
            max_total_expanded_bytes: 128 * 1024 * 1024,
            max_expansion_ratio: 128,
            max_delta_work: 256 * 1024 * 1024,
            max_index_entries: 1_000_000,
        }
    }
}

impl PackLimits {
    pub(crate) fn input(&self, actual: usize) -> Result<(), PackError> {
        if actual > self.max_input_bytes {
            return Err(PackError::InputLimit {
                actual,
                limit: self.max_input_bytes,
            });
        }
        Ok(())
    }

    pub(crate) fn object_size(&self, actual: usize) -> Result<(), PackError> {
        if actual > self.max_object_bytes {
            return Err(PackError::ObjectSizeLimit {
                actual,
                limit: self.max_object_bytes,
            });
        }
        Ok(())
    }

    pub(crate) fn checked_ratio(&self, expanded: usize, source: usize) -> Result<(), PackError> {
        let permitted = source
            .checked_mul(self.max_expansion_ratio)
            .unwrap_or(usize::MAX);
        if expanded > permitted {
            return Err(PackError::ExpansionRatioLimit {
                expanded,
                source,
                ratio: self.max_expansion_ratio,
            });
        }
        Ok(())
    }
}

/// Caller-owned time/cancellation boundary. Parsers call this before each
/// allocation and bounded unit of work; an expired deadline becomes a stable
/// typed refusal rather than an ambient timeout.
pub trait Deadline {
    fn checkpoint(&mut self) -> bool;
}

impl<F> Deadline for F
where
    F: FnMut() -> bool,
{
    fn checkpoint(&mut self) -> bool {
        self()
    }
}

pub(crate) fn checkpoint(deadline: &mut impl Deadline) -> Result<(), PackError> {
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(PackError::DeadlineExceeded)
    }
}

/// Typed refusal/error results for all supported pack and index boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    InputLimit {
        actual: usize,
        limit: usize,
    },
    EntryCountLimit {
        actual: u32,
        limit: u32,
    },
    ObjectSizeLimit {
        actual: usize,
        limit: usize,
    },
    TotalExpandedLimit {
        actual: usize,
        limit: usize,
    },
    ObjectIdLength {
        expected: usize,
        actual: usize,
    },
    Truncated {
        context: &'static str,
    },
    InvalidPackSignature,
    UnsupportedPackVersion(u32),
    InvalidEntryType(u8),
    InvalidVarint {
        context: &'static str,
    },
    IntegerOverflow {
        context: &'static str,
    },
    InvalidOfsDelta,
    InvalidDeltaInstruction,
    DeltaBaseSizeMismatch {
        declared: usize,
        actual: usize,
    },
    DeltaResultSizeLimit {
        declared: usize,
        limit: usize,
    },
    DeltaResultSizeMismatch {
        declared: usize,
        actual: usize,
    },
    DeltaCopyOutOfRange {
        offset: usize,
        length: usize,
        base_len: usize,
    },
    DeltaDepthLimit {
        depth: usize,
        limit: usize,
    },
    DeltaFanoutLimit {
        fanout: usize,
        limit: usize,
    },
    DeltaCycle,
    MissingDeltaBase,
    DuplicateObjectOffset(u64),
    DuplicateObjectId,
    ExpansionRatioLimit {
        expanded: usize,
        source: usize,
        ratio: usize,
    },
    DeltaWorkLimit {
        attempted: usize,
        limit: usize,
    },
    TrailerChecksumMismatch,
    ObjectCountMismatch {
        declared: u32,
        actual: u32,
    },
    AllocationFailed {
        requested: usize,
    },
    DeadlineExceeded,
    InvalidIndexSignature,
    UnsupportedIndexVersion(u32),
    InvalidIndexFanout,
    InvalidIndexOrdering,
    InvalidLargeOffset {
        index: usize,
    },
    TrailingIndexBytes,
}

impl fmt::Display for PackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PackError {}
