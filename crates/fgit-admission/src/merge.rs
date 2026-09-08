//! Merge admission with byte-preserving legacy event contracts and a native
//! durable Ref + Forge + Outbox path. No internal Digest is cast to a Git OID.
//!
//! Both asynchronous native APIs derive one complete transaction, await all
//! immutable dependencies, and publish one RCR/head CAS. The sealed-package API
//! retains its original workspace-bound request identity. Enqueueing a delivery
//! never claims that a downstream consumer has acknowledged it.

mod legacy;
mod prepare;
mod publication;
mod staging;

pub use legacy::{
    AsyncMergeMaterializer, ForgeBodyStore, ForgeEventBatch, MergeStaleness, SealedMerge,
    admit_merge, check_against_snapshot, seal_attempt_for,
};
pub use publication::admit_merge_async;
pub use prepare::{NativeMergeBasis, PreparedNativeMerge, prepare_native_merge};

#[allow(unused_imports)]
pub(crate) use legacy::{MergePlan, decide_from_snapshot, outcomes_match_basis, plan_attempt};

pub mod native;
