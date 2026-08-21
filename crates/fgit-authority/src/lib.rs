#![forbid(unsafe_code)]
//! Canonical authority storage: the `AuthorityStore` contract and its reference profile.
//!
//! A `FrankenGit` repository mutation becomes canonical at exactly one instant:
//! the successful conditional replacement of the exact predecessor repository
//! authority head (`NORMATIVE_PROTOCOL_CONTRACTS.md` §8.3).  Everything else —
//! staged bodies, routing hints, gossip, local projections, outcome
//! accelerators — is derived.  This crate owns the storage side of that
//! instant, and nothing else.
//!
//! # The contract
//!
//! [`AuthorityStore`] is a small, synchronous, byte-oriented surface:
//!
//! * [`put_if_absent`](AuthorityStore::put_if_absent) writes immutable bodies
//!   complete or not at all, and returns one of three typed outcomes;
//! * [`read_head`](AuthorityStore::read_head) returns the current head bytes,
//!   its generation, and the opaque token needed to replace it;
//! * [`compare_exchange_head`](AuthorityStore::compare_exchange_head) publishes
//!   if and only if the head still carries that exact token;
//! * [`authenticate_head_receipt`](AuthorityStore::authenticate_head_receipt)
//!   lets the store confirm that a receipt is one it actually issued.
//!
//! There is no listing, scan, or delete operation, because recovery follows
//! known roots and must never depend on enumeration.
//!
//! # Why tokens are opaque and unique per write
//!
//! An [`AuthorityVersionToken`] is minted fresh on every write and is never
//! derived from the stored body.  Writing state A, then state B, then restoring
//! a byte-identical A therefore yields three distinct tokens, so a writer still
//! holding the first one loses.  A store that derived tokens from content, or
//! that reused them, would silently admit exactly the ABA rollback the head
//! generation exists to prevent; [`run_authority_conformance`] fails such a
//! backend by name.
//!
//! # Ambiguity
//!
//! A caller that observes [`AuthorityFailure::Ambiguous`] has learned nothing
//! about whether the effect occurred, and no API in this crate converts that
//! into a negative result.  The store-level resolution is an exact-key read
//! ([`resolve_ambiguous_cas`], [`resolve_ambiguous_put`]); when even that is
//! inconclusive, the answer lives in the authenticated outcome index, reached
//! by `TxId` (`NORMATIVE_PROTOCOL_CONTRACTS.md` §14).
//!
//! # The reference profile is not durable storage
//!
//! [`MemoryAuthorityStore`] is a reference and laboratory backend.  It states
//! what the contract means, it can be driven through deterministic fault
//! scripts, and it keeps the ground truth that a fault campaign needs.  It has
//! no durability, no placement, and no repair, and it must never be described
//! as canonical storage for a deployment.
//!
//! # Where the runtime enters
//!
//! This crate stays synchronous and free of any runtime.  The Asupersync
//! adapter (FG-011a, `fgit-runtime`) wraps each operation in a `&Cx`-taking
//! async surface and owns budget admission, request-drain-finalize
//! cancellation, and deadlines.  A cancellation observed after transmission
//! maps to [`AmbiguityReason::Cancelled`] and a deadline to
//! [`AmbiguityReason::Timeout`]; neither may ever be reported as a refusal,
//! because neither proves non-commit.

mod contract;
pub mod history;
mod injection;
mod keys;
pub mod lincheck;
mod reference;
mod schedule;
mod suite;
mod tokens;
mod vocabulary;

pub use crate::contract::{
    AuthorityLimits, AuthorityStore, CasResolution, FaultableAuthorityStore, PutResolution,
    ambiguity_of, refusal_of, resolve_ambiguous_cas, resolve_ambiguous_put,
};
pub use crate::injection::{
    DuplicateDelivery, EffectLog, EffectRecord, FaultDirective, FaultKind, FaultLog, FaultPlan,
    FaultPosition, FaultRecord, OpIndex, SplitMix64,
};
pub use crate::keys::{HeadKey, ImmutableKey, KeyError, MAX_KEY_BYTES};
pub use crate::reference::{MemoryAuthorityStore, MemoryStoreConfig};
pub use crate::schedule::{
    AuthorityClient, AuthorityObserver, ClientId, DriveSummary, Interleaving, NoObserver, drive,
};
pub use crate::suite::{
    ConformanceCheck, ConformanceReport, run_authority_conformance, run_fault_conformance,
};
pub use crate::tokens::{
    AuthorityVersionToken, HeadGeneration, StoreInstanceId, VERSION_TOKEN_BYTES,
};
pub use crate::vocabulary::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityOp, AuthorityOpKind,
    AuthorityRefusal, AuthorityResponse, CasOutcome, EffectKnowledge, HeadInit, HeadRead,
    HeadReadReceipt, ImmutableRead, PutOutcome,
};
