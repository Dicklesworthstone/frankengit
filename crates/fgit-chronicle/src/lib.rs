#![forbid(unsafe_code)]
//! Construction and verification of repository decision batches and heads.
//!
//! `fgit-authority` owns the store protocol — staging bodies, one conditional
//! head replacement, the outcome accelerator. `fgit-codec` owns what a batch
//! and a head *are* on the wire. Neither owns the question this crate answers:
//! **is this particular pair well formed enough to be allowed near the head?**
//!
//! Today nothing refuses to build one that is not. A batch can carry a
//! decision-sequence gap, claim a predecessor it was not prepared against,
//! name a tail that is not the batch being published, or — worst — commit
//! nothing while advancing the committed state that only a commit may move.
//! The codec encodes it, the store publishes it, and the reference model
//! notices afterwards. Afterwards is too late: the conditional replacement is
//! the linearization point, so an ill-formed pair that reaches it is canonical.
//!
//! # The two halves
//!
//! **Correct by construction, for the path you own.** [`PublicationPlan`]
//! assigns decision and repository sequence itself. A caller cannot choose
//! them, so a gap is not something the builder rejects — it is something the
//! builder cannot express. A refusal records no commit record because the
//! method that records one is not on the refusal path.
//!
//! **Total verification, for a pair that arrives as data.** Replay, crash
//! recovery, and a batch read back out of the store all produce a pair nobody
//! constructed here. [`verify_pair`] is a total function over such a pair and
//! returns the same [`ChronicleRefusal`] vocabulary the builder enforces. The
//! builder runs it on its own output, so the two halves cannot drift.
//!
//! This is the same split `fgit-resource` uses for obligations, for the same
//! reason: type-state is stronger where you hold the value, and useless where
//! you only hold a record of it.
//!
//! # Non-claims
//!
//! This crate does not compute roots, evaluate intents, decide policy, or
//! choose which transactions belong in a batch. It does not talk to a store —
//! publication is delegated to `fgit_authority::publish_decisions`, which
//! already implements the body-first, head-last order. Being well formed is
//! necessary for a pair to be publishable and nowhere near sufficient: the
//! roots it carries are still only as good as the evaluation that produced
//! them.

/// Every refusal that leaves this crate stays small enough to travel in a
/// `Result` without boxing.
///
/// The bound is the one the workspace lint set enforces for an error payload.
/// `fgit_authority::OutcomeFailure` is asserted here too even though
/// `fgit-authority` owns it: it is the error half of this crate's
/// [`publish`](publish::publish), so its width is this crate's problem. It
/// once exceeded the bound and this path boxed it; `fgit-authority` has since
/// brought it inside, the box is gone, and this assertion is what will say so
/// if it ever widens again.
const _: () = {
    const LIMIT: usize = 128;
    assert!(size_of::<refusal::ChronicleRefusal>() <= LIMIT);
    assert!(size_of::<fgit_authority::OutcomeFailure>() <= LIMIT);
};

pub mod archive;
pub mod assemble;
pub mod audit;
pub mod capsule;
mod evidence;
pub mod origin;
pub mod publish;
pub mod recovery;
pub mod refusal;
pub mod verify;

pub use archive::{BackupExportBundleBody, RestoreReportBody};
pub use assemble::{PublicationPlan, VerifiedPublication};
pub use audit::{batch_identity, repository_commit_identity, verify_pair};
pub use capsule::{
    BackupProfile, CapsulePointer, RepositoryCapsuleBody, advance_pointer_root_last,
    advance_pointer_root_last_async, capsule_identity,
};
pub use evidence::batch_evidence_root;
pub use origin::{PublicationBasis, ResultingRoots};
pub use publish::{
    CanonicalBatchReceipt, LostCandidate, PublicationVerdict, publish, publish_async,
};
pub use recovery::{AuditedRestore, CapsuleVerification, HaltReason, RecoveryPlan, plan_recovery};
pub use refusal::ChronicleRefusal;
pub use verify::{CapsuleDefect, MAX_REPORTED_DEFECTS, RestoreClassification, RestoreOutcome};
