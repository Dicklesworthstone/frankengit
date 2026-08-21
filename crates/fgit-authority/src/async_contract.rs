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

/// Proof that an authenticated stream walk found no existing terminal decision,
/// bound to the head token the walk was performed against.
///
/// # Why this type exists
///
/// [`AsyncAuthorityStore::publish_head_with_outcomes`] is sound only when the
/// caller's duplicate check was performed against the same head token the CAS
/// conditions on. That is a rule, and *"the caller is supposed to have
/// checked"* is exactly the kind of rule this project refuses to rely on — the
/// §5.2 defect that produced this whole design existed because a check read
/// something the CAS token did not cover.
///
/// So the obligation is structural instead. A caller cannot invoke the atomic
/// publish without a witness, and a witness cannot be built except by the walk
/// that mints it. Forgetting the check becomes a compile error rather than a
/// race nobody sees until it costs a duplicate terminal decision.
///
/// The field is private and there is no public constructor: only this crate's
/// duplicate-detection walk can produce one, and the primitive checks that
/// [`Self::bound_to`] equals the `expected` token it was handed. A witness
/// minted against one head cannot be replayed against another.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DuplicateAbsenceWitness {
    bound_to: AuthorityVersionToken,
}

impl DuplicateAbsenceWitness {
    /// Mint a witness for a walk performed against `bound_to`.
    ///
    /// Deliberately `pub(crate)`: minting belongs to the duplicate-detection
    /// walk, not to callers. A public constructor would make the witness a
    /// token anyone can forge, which is the documented obligation again wearing
    /// a type.
    pub(crate) const fn minted_against(bound_to: AuthorityVersionToken) -> Self {
        Self { bound_to }
    }

    /// The head token this walk was performed against.
    #[must_use]
    pub const fn bound_to(&self) -> AuthorityVersionToken {
        self.bound_to
    }
}

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

    /// Publish terminal outcome entries **and** replace the head in ONE
    /// linearization point.
    ///
    /// This is the primitive GoldLotus's §5.2 atomicity ruling requires, and it
    /// exists because the obvious composition of the other two operations is
    /// unsound.
    ///
    /// # The defect this replaces
    ///
    /// Publishing by `compare_exchange_head` followed by `put_if_absent` for
    /// each outcome leaves a window: the head moves first, so a publisher whose
    /// response is lost after the CAS but before indexing leaves a transaction
    /// **genuinely decided with no accelerator row**. A second publisher then
    /// reads the new head, finds no accelerator entry, infers "undecided", and
    /// publishes a *different* terminal decision for the same `TxId`. NPC §5.3
    /// says a sealed transaction appears at most once in the authenticated
    /// decision history; that composition cannot enforce it, and detects the
    /// violation only after it is already canonical.
    ///
    /// # The contract
    ///
    /// All-or-nothing. Either every entry in `outcomes` is durable **and** the
    /// head carries `new_body`, or neither is and the head still carries
    /// `expected`. **If a caller can observe the new head, the outcome records
    /// are necessarily observable** — that is the whole point, and it is what
    /// makes the lost-response window unrepresentable rather than merely
    /// narrow.
    ///
    /// A pre-existing outcome key holding **different** bytes aborts the entire
    /// publication and leaves the head untouched. Failing closed here is
    /// deliberate: a partially applied publication is precisely the state this
    /// operation exists to make impossible.
    ///
    /// # What this operation is NOT for
    ///
    /// It does **not** perform duplicate detection. Per the ruling, whether a
    /// `TxId` already has a terminal decision is answered from the
    /// **authenticated decision stream** reachable from the current head, never
    /// from an accelerator row's presence or absence — a missing row means
    /// "resolve it authoritatively", never "no decision exists". That inference
    /// is the TOCTOU, and treating a derived index as authority is the
    /// constitutional category error (§5.1, §4) underneath the whole defect.
    /// Callers detect duplicates upstream; this operation makes the winner's
    /// publication indivisible.
    ///
    /// # The ordering a caller must not break
    ///
    /// Upstream detection is sound **only** when the stream walk and this call
    /// are bound to the same head token:
    ///
    /// ```text
    /// 1. read head -> H1, token T1
    /// 2. walk the AUTHENTICATED stream from H1   (never the accelerator)
    /// 3. call this with expected = T1
    /// ```
    ///
    /// Step 2's check is validated by step 3's condition: an interleaving
    /// publisher moves the head, this call returns
    /// [`CasOutcome::PredecessorMismatch`], nothing is written, and the retry
    /// walks from the new head and finds the decision. That is what
    /// compare-and-swap is for.
    ///
    /// **A caller that walks the stream and then re-reads the head before
    /// calling this silently reintroduces the window**, because the token it
    /// passes would no longer be the one its check was performed against.
    ///
    /// That is why `witness` exists. An implementation MUST refuse when
    /// `witness.bound_to() != expected`: the witness makes the binding
    /// checkable rather than assumed, so the ordering above is enforced by the
    /// type system and one equality check instead of by a caller remembering
    /// this paragraph.
    ///
    /// The defect was never that detection lived upstream — it was that
    /// detection read a derived index the CAS token does not cover. Requirement
    /// 2 of the ruling is about *what is read*, not about *where the reading
    /// happens*.
    ///
    /// # Errors
    ///
    /// [`CasOutcome::PredecessorMismatch`] when the head no longer carries
    /// `expected` — an ordinary lost race, with nothing written. Any refusal
    /// leaves the store exactly as it was.
    fn publish_head_with_outcomes(
        &self,
        cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
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
