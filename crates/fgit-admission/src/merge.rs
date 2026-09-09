//! Merge admission with byte-preserving legacy event contracts and a native
//! durable Ref + Forge + Outbox path. No internal Digest is cast to a Git OID.
//!
//! The native APIs require a native projection and share one publication driver
//! in [`native`]. The native sealed-package API retains its original request
//! identity. The legacy sync/async APIs refuse native packages before acquiring
//! a seal; a legacy materializer does not grant native validation capability.
//! Enqueueing a delivery never claims downstream acknowledgement.

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
