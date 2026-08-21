#![forbid(unsafe_code)]
//! Canonical decision-log and segment compaction.
//!
//! A compaction generation is an immutable re-encoding record, not a second
//! authority source. Its visibility is established only by the ordinary
//! decision batch whose authority-head replacement binds the generation as
//! evidence; local layout indexes are deliberately absent from this crate's
//! authority decisions.

mod protocol;
mod record;

pub use protocol::{
    CompactionExecution, CompactionPublicationRefusal, DurabilityReceipt, DurabilityRefusal,
    DurableCompaction, IndeterminateCompaction, OutputStageReceipt, RetentionRefusal,
    SourceDeletionPermit, StagedCompaction, UnpublishedCompaction, VisibleCompaction,
};
pub use record::{
    CompactionAlgorithm, CompactionOutputs, CompactionProfile, CompactionRecord, CompactionRefusal,
    DecisionRange, LogicalEquivalenceProof, OutputDisposition, SourceEntry,
    SourceOutputTotalityMap, TotalityEntry,
};
