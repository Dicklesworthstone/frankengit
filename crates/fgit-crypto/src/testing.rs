//! Collision-detector doubles for tests.
//!
//! These are doubles, not detectors: none of them evaluates a disturbance
//! vector. They exist to prove that the hook point in the `defense` module
//! carries real internal state and that the screened path fails closed, and
//! they are gated behind the non-default `test-double` feature so they cannot
//! drift into a production feature graph.

use crate::defense::{
    BlockVerdict, CollisionEvidence, CollisionVerdict, Sha1BlockContext, Sha1CollisionDetector,
};

/// A double that reports every block clean and counts what it saw.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CleanDouble {
    blocks: u64,
    finished: bool,
}

impl CleanDouble {
    /// A fresh double.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            blocks: 0,
            finished: false,
        }
    }

    /// How many compression blocks were inspected.
    #[must_use]
    pub const fn blocks(&self) -> u64 {
        self.blocks
    }

    /// Whether the whole-message verdict was requested.
    #[must_use]
    pub const fn finished(&self) -> bool {
        self.finished
    }
}

impl Sha1CollisionDetector for CleanDouble {
    fn inspect_block(&mut self, _context: &Sha1BlockContext<'_>) -> BlockVerdict {
        self.blocks += 1;
        BlockVerdict::Clean
    }

    fn finish(&mut self) -> CollisionVerdict {
        self.finished = true;
        CollisionVerdict::Clean
    }
}

/// A double that reports evidence at one chosen block index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspectAtBlock {
    target: u64,
    seen: u64,
}

impl SuspectAtBlock {
    /// Report evidence when the block at `target` is inspected.
    #[must_use]
    pub const fn new(target: u64) -> Self {
        Self { target, seen: 0 }
    }
}

impl Sha1CollisionDetector for SuspectAtBlock {
    fn inspect_block(&mut self, context: &Sha1BlockContext<'_>) -> BlockVerdict {
        self.seen += 1;
        if context.block_index == self.target {
            BlockVerdict::Suspected(CollisionEvidence {
                block_index: context.block_index,
                disturbance_vector: Some(0),
                detail: "test double: evidence at the configured block",
            })
        } else {
            BlockVerdict::Clean
        }
    }

    fn finish(&mut self) -> CollisionVerdict {
        CollisionVerdict::Clean
    }
}

/// A double that reports clean per block but flags the whole message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SuspectAtFinish {
    blocks: u64,
}

impl SuspectAtFinish {
    /// A fresh double.
    #[must_use]
    pub const fn new() -> Self {
        Self { blocks: 0 }
    }
}

impl Sha1CollisionDetector for SuspectAtFinish {
    fn inspect_block(&mut self, _context: &Sha1BlockContext<'_>) -> BlockVerdict {
        self.blocks += 1;
        BlockVerdict::Clean
    }

    fn finish(&mut self) -> CollisionVerdict {
        CollisionVerdict::Suspected(CollisionEvidence {
            block_index: self.blocks.saturating_sub(1),
            disturbance_vector: None,
            detail: "test double: whole-message evidence",
        })
    }
}

/// One compression block exactly as the detector observed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedBlock {
    /// Zero-based block index.
    pub block_index: u64,
    /// Intermediate hash value entering the block.
    pub chaining_value: [u32; 5],
    /// Expanded message schedule for the block.
    pub schedule: [u32; 80],
}

/// A double that records everything it is shown.
///
/// Recording the real chaining values and schedules is how the tests
/// demonstrate that the hook exposes genuine FIPS 180-4 internal state rather
/// than a placeholder summary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordingDouble {
    observed: Vec<ObservedBlock>,
}

impl RecordingDouble {
    /// A fresh double.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            observed: Vec::new(),
        }
    }

    /// Every block the detector was shown, in order.
    #[must_use]
    pub fn observed(&self) -> &[ObservedBlock] {
        &self.observed
    }
}

impl Sha1CollisionDetector for RecordingDouble {
    fn inspect_block(&mut self, context: &Sha1BlockContext<'_>) -> BlockVerdict {
        self.observed.push(ObservedBlock {
            block_index: context.block_index,
            chaining_value: context.chaining_value,
            schedule: *context.schedule,
        });
        BlockVerdict::Clean
    }

    fn finish(&mut self) -> CollisionVerdict {
        CollisionVerdict::Clean
    }
}
