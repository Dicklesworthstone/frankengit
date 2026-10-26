//! Bounded grouping of independent immutable writes.
//!
//! Grouping amortizes a backend's durable transaction without changing any
//! key, body or create-if-absent decision. It is never repository publication:
//! only the exact-predecessor authority-head operation can publish state.
//! The portable implementation may complete a prefix before interruption;
//! callers retry the same complete batch or read its exact keys to recover.

use crate::{AuthorityFailure, AuthorityLimits, ImmutableKey};

/// Maximum independent immutable writes in one backend call.
pub const MAX_IMMUTABLE_BATCH_ITEMS: usize = 64;
/// Maximum combined key and body bytes in one backend call.
pub const MAX_IMMUTABLE_BATCH_BYTES: usize = 1024 * 1024;

/// A request bound rejected before any batch entry is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImmutableBatchRefusal {
    /// The batch contains too many entries.
    TooManyItems {
        /// Supplied entry count.
        observed: usize,
        /// Maximum entry count.
        limit: usize,
    },
    /// The combined key and body bytes exceed the finite batch allowance.
    BytesExceeded {
        /// Combined bytes, saturated on arithmetic overflow.
        observed: usize,
        /// Maximum combined bytes.
        limit: usize,
    },
    /// An entry exceeds this backend's independently configured body limit.
    BodyTooLarge {
        /// Zero-based input position.
        index: usize,
        /// Offered body length.
        observed: usize,
        /// Backend body bound.
        limit: usize,
    },
}

impl core::fmt::Display for ImmutableBatchRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::TooManyItems { observed, limit } => write!(
                formatter,
                "immutable batch contains {observed} entries; limit is {limit}"
            ),
            Self::BytesExceeded { observed, limit } => write!(
                formatter,
                "immutable batch contains {observed} key/body bytes; limit is {limit}"
            ),
            Self::BodyTooLarge {
                index,
                observed,
                limit,
            } => write!(
                formatter,
                "immutable batch entry {index} has {observed} body bytes; backend limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for ImmutableBatchRefusal {}

/// Failure of a group of independent create-if-absent operations.
///
/// This deliberately does not reuse `AuthorityFailure` directly: a definite
/// refusal of a later portable operation cannot erase already completed
/// writes. No partial success vector is returned. Every entry not proved by a
/// complete successful response is recovered by retry or exact-key read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImmutableBatchFailure {
    /// Complete request preflight failed, before any entry was transmitted.
    Bounds(ImmutableBatchRefusal),
    /// A backend operation failed or became ambiguous.
    Interrupted {
        /// Number of earlier per-item operations completed by a sequential
        /// implementation. A transactional backend reports zero when the
        /// transaction rolled back or its commit response is ambiguous.
        completed: usize,
        /// The exact failure of the interrupted operation or transaction.
        source: AuthorityFailure,
    },
}

impl ImmutableBatchFailure {
    /// Whether this failure proves that this entire call applied no effect.
    #[must_use]
    pub const fn proves_no_effect(&self) -> bool {
        match self {
            Self::Bounds(_) => true,
            Self::Interrupted { completed, source } => *completed == 0 && source.proves_no_effect(),
        }
    }
}

impl core::fmt::Display for ImmutableBatchFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bounds(refusal) => write!(formatter, "{refusal}"),
            Self::Interrupted { completed, source } => write!(
                formatter,
                "immutable batch interrupted after {completed} completed item operations: {source}; recover entries by exact key or identical retry"
            ),
        }
    }
}

impl std::error::Error for ImmutableBatchFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Bounds(refusal) => refusal,
            Self::Interrupted { source, .. } => source,
        })
    }
}

/// Check every batch bound before any entry is transmitted.
///
/// Input order is retained, including repeated keys. A duplicate key with the
/// same bytes therefore yields an identical retry after its first creation;
/// a duplicate with different bytes conflicts. Neither input is overwritten.
/// Backends call this before taking the write path, even when every entry
/// appears in an immutable cache. Empty batches are valid and have no effect.
pub fn validate_immutable_batch(
    entries: &[(ImmutableKey, Vec<u8>)],
    limits: AuthorityLimits,
) -> Result<(), ImmutableBatchFailure> {
    if entries.len() > MAX_IMMUTABLE_BATCH_ITEMS {
        return Err(ImmutableBatchFailure::Bounds(
            ImmutableBatchRefusal::TooManyItems {
                observed: entries.len(),
                limit: MAX_IMMUTABLE_BATCH_ITEMS,
            },
        ));
    }
    let mut bytes = 0usize;
    for (index, (key, body)) in entries.iter().enumerate() {
        if body.len() > limits.body_bytes {
            return Err(ImmutableBatchFailure::Bounds(
                ImmutableBatchRefusal::BodyTooLarge {
                    index,
                    observed: body.len(),
                    limit: limits.body_bytes,
                },
            ));
        }
        bytes = bytes
            .saturating_add(key.as_bytes().len())
            .saturating_add(body.len());
        if bytes > MAX_IMMUTABLE_BATCH_BYTES {
            return Err(ImmutableBatchFailure::Bounds(
                ImmutableBatchRefusal::BytesExceeded {
                    observed: bytes,
                    limit: MAX_IMMUTABLE_BATCH_BYTES,
                },
            ));
        }
    }
    Ok(())
}
