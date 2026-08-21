//! The asynchronous sibling of [`AuthorityStore`], for production backends.
//!
//! # Why two traits, permanently
//!
//! [`AuthorityStore`] is synchronous because it is the **deterministic
//! verification surface**: the linearizability checker and the conformance
//! suite must call it with no runtime present, and the in-memory reference is
//! where deterministic fault injection lives. Making it async would drag both,
//! and `fgit-admission`'s ambiguity and crash coverage depends on that
//! genericity.
//!
//! [`AsyncAuthorityStore`] is asynchronous because it is the **production
//! surface**: a durable backend owns a connection it cannot block on, and
//! per-request cancellation and budget have to reach the operation.
//!
//! Neither is deprecated and neither is a migration target. They describe the
//! same semantics for two different callers, which is exactly why the semantics
//! must live in **one** place — see [`crate::publish`], the shared core both
//! sides delegate to.
//!
//! # The context is an associated type, and it is per-call
//!
//! Two constraints learned the hard way while building the `FrankenSQLite`
//! backend, recorded here so they are not rediscovered:
//!
//! **It must be associated, not concrete.** `fgit-authority` must never depend
//! on `fsqlite`, so it cannot name `fsqlite_types::cx::Cx`. That type is also
//! *not* `asupersync`'s `Cx` — they are distinct types bridged by
//! `set_native_cx`, which has already surprised one consumer.
//!
//! **It must be per-call, never stored on the store.** A single context held
//! for the store's lifetime breaks per-request budget and cancellation
//! propagation, which is most of what the integration profile wants from
//! threading it at all. A backend that stashes one context in its struct has
//! satisfied the type and lost the property.
//!
//! # What an implementor may not do
//!
//! An implementation may not satisfy this trait by blocking on the synchronous
//! one. Blocking adapters are `cfg(test)`-only by standing ruling: a
//! `block_on`-per-operation bridge cannot deliver a cancel *during* an
//! operation, so it would present a production surface that silently cannot
//! honour cancellation.

use crate::contract::AuthorityLimits;
use crate::keys::{HeadKey, ImmutableKey};
use crate::tokens::{AuthorityVersionToken, StoreInstanceId};
use crate::vocabulary::{
    AuthenticatedHead, AuthorityFailure, CasOutcome, HeadInit, HeadRead, HeadReadReceipt,
    ImmutableRead, PutOutcome,
};
use fgit_types::HeadGeneration;

/// The production authority contract.
///
/// Every method mirrors its [`AuthorityStore`] counterpart exactly, including
/// the failure vocabulary, so that a single set of semantics can serve both.
/// The only additions are `Context` and the `async`.
///
/// [`AuthorityStore`]: crate::AuthorityStore
pub trait AsyncAuthorityStore: Sync {
    /// The runtime-owned context threaded through every operation.
    ///
    /// Deliberately associated: this crate cannot name any backend's context
    /// type without depending on that backend.
    ///
    /// `Sync` because every operation borrows it and the resulting futures must
    /// be `Send` — a production surface whose futures cannot cross threads
    /// cannot be spawned on a multi-threaded runtime, which is most of the
    /// point of being async at all.
    type Context: Sync + ?Sized;

    /// Identity of this endpoint and credential scope.
    fn instance_id(&self) -> StoreInstanceId;

    /// The declared bounds this instance enforces.
    fn limits(&self) -> AuthorityLimits;

    /// Write an immutable body if and only if the slot is empty.
    ///
    /// The write is complete or absent: a partially written body is never
    /// observable, so a retry after an ambiguous response either finds the
    /// exact bytes or finds nothing.
    fn put_if_absent(
        &self,
        cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send;

    /// Read one immutable body by exact key.
    fn read_immutable(
        &self,
        cx: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send;

    /// Create the repository head slot if and only if it is empty.
    fn initialize_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send;

    /// Read the current head, its token, and its generation.
    fn read_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send;

    /// Replace the head if and only if it still carries `expected`.
    ///
    /// A successful call is the linearization point of the repository mutation
    /// whose decision batch the new body commits to. The store additionally
    /// refuses a proposal whose generation does not strictly increase, so a
    /// stale candidate cannot roll the head backwards even if it somehow held a
    /// current token.
    fn compare_exchange_head(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send;

    /// Confirm that this store issued `receipt` exactly as presented.
    ///
    /// Success proves authenticity, never currency: a genuine receipt for a
    /// superseded head still authenticates, and still loses the exchange.
    fn authenticate_head_receipt(
        &self,
        cx: &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send;
}
