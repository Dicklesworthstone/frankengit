//! Merge admission, with an explicit native durable path and unchanged legacy
//! contracts. Legacy Digest-valued merge events are not converted into Git OIDs.
//!
//! Use [`native::NativeMergeIntent`] and [`native::admit_native_merge_async`]
//! with a real [`native::NativeMergeProjection`] for durable ref/forge publication.
//! The legacy callbacks remain available for existing integrations; their
//! synchronous staging contract does not establish durable node capability.

mod legacy;

pub use legacy::{
    ForgeBodyStore, ForgeEventBatch, MergeStaleness, SealedMerge, admit_merge,
    admit_merge_async, check_against_snapshot, seal_attempt_for,
};

// Preserve the crate-internal legacy planning seam while its implementation
// and historical contracts live together in the legacy module.
#[allow(unused_imports)]
pub(crate) use legacy::{MergePlan, decide_from_snapshot, outcomes_match_basis, plan_attempt};

pub mod native;
