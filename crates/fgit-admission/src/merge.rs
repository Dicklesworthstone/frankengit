//! Merge admission with byte-preserving legacy event contracts and a native
//! durable Ref + Forge + Outbox path. No internal Digest is cast to a Git OID.
//!
//! Native publication derives one complete transaction, stages every immutable
//! dependency through awaited authority calls, and publishes one RCR/head CAS.
//! Enqueueing a delivery never claims that a downstream consumer acknowledged it.

mod legacy;
mod prepare;
mod staging;

pub use legacy::{
    AsyncMergeMaterializer, ForgeBodyStore, ForgeEventBatch, MergeStaleness, SealedMerge,
    admit_merge, admit_merge_async, check_against_snapshot, seal_attempt_for,
};
pub use prepare::{NativeMergeBasis, PreparedNativeMerge, prepare_native_merge};

#[allow(unused_imports)]
pub(crate) use legacy::{MergePlan, decide_from_snapshot, outcomes_match_basis, plan_attempt};

pub mod native;
