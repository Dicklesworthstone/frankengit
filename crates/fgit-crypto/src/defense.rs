//! SHA-1 collision-defense hook point (plan section 11.6).
//!
//! `FrankenGit` must be able to compute a native SHA-1 Git identity through a
//! collision-detecting profile and fail closed on suspicious evidence. The
//! detector contract here is deliberately shaped around what a real
//! disturbance-vector / unavoidable-bit-condition check consumes: for every
//! 64-byte compression block it receives the chaining value entering the
//! block and the complete 80-word expanded message schedule. A production
//! `sha1dc`-class detector can therefore be installed behind this trait
//! without changing a single caller.
//!
//! Wave-1 status, stated plainly: **no detector ships**. There is no default
//! implementation and no silently-clean fallback, because a detector that
//! always answers "clean" would be collision defense in name only. A caller
//! that needs section 11.6 screening either supplies a detector or receives
//! [`CollisionDefenseError::DetectorUnavailable`]. Selecting a real
//! collision-detecting SHA-1 is a dependency-registry decision that will be
//! recorded in `registries/dependency_policy.tsv` when it is made.

use core::fmt;

/// The state a collision detector observes for one SHA-1 compression block.
///
/// `chaining_value` is the five-word intermediate hash value *before* the
/// block is applied; `schedule` is the fully expanded `W[0..80]` message
/// schedule for the block. Together these are sufficient to evaluate the
/// published disturbance vectors and to recompute the near-collision block
/// candidates that a detecting profile checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Sha1BlockContext<'a> {
    /// Zero-based index of this block within the message.
    pub block_index: u64,
    /// Intermediate hash value entering the block.
    pub chaining_value: [u32; 5],
    /// Expanded message schedule for the block.
    pub schedule: &'a [u32; 80],
}

/// Evidence that a message looks like one half of a SHA-1 collision pair.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CollisionEvidence {
    /// Block at which the evidence was observed.
    pub block_index: u64,
    /// Identifier of the matched disturbance vector, when the detector
    /// attributes the evidence to a specific one.
    pub disturbance_vector: Option<u16>,
    /// Short, stable description of the detector's finding.
    pub detail: &'static str,
}

impl fmt::Display for CollisionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "suspected SHA-1 collision evidence at block {}: {}",
            self.block_index, self.detail
        )
    }
}

/// Per-block detector verdict.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BlockVerdict {
    /// The block carries no collision evidence.
    Clean,
    /// The block carries collision evidence; hashing must fail closed.
    Suspected(CollisionEvidence),
}

/// Whole-message detector verdict, reported after the final block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CollisionVerdict {
    /// No block carried collision evidence.
    Clean,
    /// At least one block carried collision evidence.
    Suspected(CollisionEvidence),
}

/// A collision-detecting profile for native SHA-1 Git identity.
pub trait Sha1CollisionDetector {
    /// Inspect one compression block before it is applied.
    fn inspect_block(&mut self, context: &Sha1BlockContext<'_>) -> BlockVerdict;

    /// Report the whole-message verdict after the padded message is consumed.
    fn finish(&mut self) -> CollisionVerdict;
}

/// Refusal produced by a screened SHA-1 identity computation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CollisionDefenseError {
    /// No collision-detecting profile is installed. Screening was requested
    /// and cannot be honoured, so the identity is refused rather than
    /// returned as if it had been screened.
    DetectorUnavailable,
    /// The detector reported collision evidence; the identity is refused.
    Suspected(CollisionEvidence),
}

impl fmt::Display for CollisionDefenseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DetectorUnavailable => formatter
                .write_str("no SHA-1 collision-detecting profile is installed; identity refused"),
            Self::Suspected(evidence) => write!(formatter, "{evidence}"),
        }
    }
}

impl std::error::Error for CollisionDefenseError {}

/// Internal per-block observer used by the SHA-1 core.
///
/// Monomorphising over this trait keeps the unscreened path free of dynamic
/// dispatch while letting the screened path see real internal state.
pub trait BlockObserver {
    fn observe(&mut self, context: &Sha1BlockContext<'_>) -> BlockVerdict;
}

/// Observer used when no collision detector is installed.
pub struct UnobservedBlocks;

impl BlockObserver for UnobservedBlocks {
    #[inline]
    fn observe(&mut self, _context: &Sha1BlockContext<'_>) -> BlockVerdict {
        BlockVerdict::Clean
    }
}

/// Observer that forwards every block to an installed detector.
pub struct DetectorObserver<'d> {
    pub detector: &'d mut dyn Sha1CollisionDetector,
}

impl BlockObserver for DetectorObserver<'_> {
    #[inline]
    fn observe(&mut self, context: &Sha1BlockContext<'_>) -> BlockVerdict {
        self.detector.inspect_block(context)
    }
}
