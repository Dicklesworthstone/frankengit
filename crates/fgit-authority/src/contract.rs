//! The `AuthorityStore` contract and the ambiguity-resolution helpers.
//!
//! # What the contract deliberately omits
//!
//! There is no listing, enumeration, scan, or delete operation.  Recovery
//! follows canonical roots from known keys and never depends on listing order
//! or completeness (`NORMATIVE_PROTOCOL_CONTRACTS.md` §4 and
//! `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md` §13.8).  Omitting the
//! capability outright is stronger than refusing it, so no backend can grow a
//! listing-based recovery path by accident.
//!
//! # Where `Cx` enters
//!
//! This trait is synchronous and deterministic on purpose: it is the semantic
//! core that the reference backend, the linearizability checker, and the fault
//! campaign all share, and none of them wants a runtime in the loop.  The
//! Asupersync surface (FG-011a, `fgit-runtime`) wraps each method in a
//! `&Cx`-taking async operation and owns exactly three additional concerns:
//!
//! * budget and capability admission before transmission;
//! * request-drain-finalize cancellation, where a cancellation observed after
//!   transmission maps to [`AmbiguityReason::Cancelled`] and never to a
//!   refusal;
//! * deadline expiry, which maps to [`AmbiguityReason::Timeout`].
//!
//! No cancellation path may synthesise [`AuthorityRefusal::Unavailable`] for an
//! in-flight request; that value is reserved for a request the endpoint
//! demonstrably never processed.

use crate::injection::{EffectLog, FaultLog, FaultPlan};
use crate::keys::{HeadKey, ImmutableKey};
use fgit_types::HeadGeneration;

use crate::async_contract::DuplicateAbsenceWitness;
use crate::tokens::{AuthorityVersionToken, StoreInstanceId};
use crate::vocabulary::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityOp, AuthorityRefusal,
    AuthorityResponse, CasOutcome, HeadInit, HeadRead, HeadReadReceipt, ImmutableRead, PutOutcome,
};

/// The declared resource bounds of one backend profile.
///
/// Bounds are contract, not implementation detail: refusal behaviour at the
/// boundary is part of what a conforming backend must reproduce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityLimits {
    /// Largest admissible body in bytes.
    pub body_bytes: usize,
    /// Largest number of occupied immutable slots.
    pub immutable_slots: usize,
    /// Largest number of occupied head slots.
    pub head_slots: usize,
    /// Largest number of version tokens one instance may issue.
    pub version_tokens: usize,
}

impl Default for AuthorityLimits {
    fn default() -> Self {
        Self {
            body_bytes: 1 << 20,
            immutable_slots: 1 << 16,
            head_slots: 1 << 12,
            version_tokens: 1 << 20,
        }
    }
}

/// A backend that can carry canonical repository authority.
///
/// The obligations restated from `NORMATIVE_PROTOCOL_CONTRACTS.md` §4 are:
///
/// 1. strong put-if-absent for immutable bodies, with complete-or-absent writes;
/// 2. read-after-write consistency for known keys;
/// 3. linearizable conditional replacement of one head key;
/// 4. no lost updates through gateways, proxies, failover, or replication;
/// 5. version tokens that are unique per write and never content-derived;
/// 6. a head read whose authenticity the store itself can confirm;
/// 7. bounded, typed errors;
/// 8. an endpoint and credential scope that another endpoint's tokens cannot cross;
/// 9. recovery from a known root without listing.
///
/// Every one of these is exercised by [`crate::run_authority_conformance`], and
/// a backend that stores bytes durably but fails any of them cannot carry
/// canonical mutation.
///
/// # This is the deterministic verification surface
///
/// Synchronous on purpose, and **permanent**. It is not a legacy shape awaiting
/// migration to [`AsyncAuthorityStore`], and it is not deprecated. Two things
/// depend on its being synchronous and neither is incidental: the
/// linearizability checker calls it without a runtime, and all deterministic
/// fault injection lives behind [`FaultableAuthorityStore`], which extends it.
/// Making this trait async would drag both into a runtime and damage the
/// verification machinery in order to feed production — which is why the t7ip
/// ruling added a sibling rather than converting this one.
///
/// The production counterpart is [`AsyncAuthorityStore`]. **Both are permanent,
/// neither is deprecated**, and they share one delegated decision core, so they
/// cannot conclude differently about the same state — only wait differently.
/// Do not reach for this trait in a node because its signature is simpler; that
/// was the architectural mistake t7ip exists to correct.
///
/// [`AsyncAuthorityStore`]: crate::AsyncAuthorityStore
pub trait AuthorityStore {
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
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure>;

    /// Read one immutable body by exact key.
    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure>;

    /// Create the repository head slot if and only if it is empty.
    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure>;

    /// Read the current head, its token, and its generation.
    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure>;

    /// Replace the head if and only if it still carries `expected`.
    ///
    /// A successful call is the linearization point of the repository mutation
    /// whose decision batch the new body commits to.  The store additionally
    /// refuses a proposal whose generation does not strictly increase, so a
    /// stale candidate cannot roll the head backwards even if it somehow held a
    /// current token.
    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure>;

    /// Publish terminal outcome entries **and** replace the head in ONE
    /// linearization point.
    ///
    /// The synchronous mirror of
    /// [`AsyncAuthorityStore::publish_head_with_outcomes`], with identical
    /// semantics. It exists on this surface too because the deterministic
    /// verification lane drives *this* trait: the linearizability checker and
    /// the seal-race campaign run against the in-memory reference, so a fix
    /// that landed only on the production surface would leave the backend we
    /// verify with still carrying the §5.2 race — and the acceptance tests for
    /// that defect could never pass.
    ///
    /// All-or-nothing: either every entry in `outcomes` is written **and** the
    /// head carries `new_body`, or neither is. An implementation MUST refuse
    /// when `witness.bound_to() != expected`.
    ///
    /// **"Written" is the §5.4 *visible* epoch, not the *durable* one.** It
    /// means the entries and the head became canonically observable as one
    /// indivisible store transaction. It does **not** mean the selected
    /// durability profile has completed — this operation neither drives that
    /// nor reports it, and a caller must not read a successful return as an
    /// acknowledgement of durability. See [`PublicationOutcome::Published`].
    ///
    /// [`PublicationOutcome::Published`]: crate::PublicationOutcome::Published
    ///
    /// # Default
    ///
    /// Refuses with [`AuthorityRefusal::OperationUnsupported`]. A backend that
    /// cannot publish atomically says so honestly rather than failing to
    /// compile; one that delegated to a separate CAS-then-writes path would
    /// satisfy this signature while providing none of the atomicity, which is
    /// worse than refusing because a test could pass against it.
    ///
    /// # Errors
    ///
    /// [`CasOutcome::PredecessorMismatch`] when the head no longer carries
    /// `expected`, with nothing written.
    fn publish_head_with_outcomes(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        let _ = (key, expected, new_generation, new_body, outcomes, witness);
        Err(AuthorityFailure::Refused(
            AuthorityRefusal::OperationUnsupported,
        ))
    }

    /// Confirm that this store issued `receipt` exactly as presented.
    ///
    /// A receipt bearing a token the store never minted is refused with
    /// [`AuthorityRefusal::UnknownVersionToken`]; a receipt whose bytes or
    /// generation were altered after issuance is refused with
    /// [`AuthorityRefusal::TokenBodyMismatch`] or
    /// [`AuthorityRefusal::TokenGenerationMismatch`].  Success proves
    /// authenticity, never currency.
    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure>;

    /// Execute one operation in the uniform vocabulary.
    ///
    /// This is the entry point the linearizability checker and the fault
    /// campaign drive; it is a total function from [`AuthorityOp`] to
    /// [`AuthorityResponse`] with no panicking path.
    #[must_use]
    fn execute(&self, op: &AuthorityOp) -> AuthorityResponse {
        match op {
            AuthorityOp::PutIfAbsent { key, body } => self.put_if_absent(key, body).map_or_else(
                AuthorityFailure::into_response,
                AuthorityResponse::PutIfAbsent,
            ),
            AuthorityOp::ReadImmutable { key } => self.read_immutable(key).map_or_else(
                AuthorityFailure::into_response,
                AuthorityResponse::ReadImmutable,
            ),
            AuthorityOp::InitializeHead {
                key,
                generation,
                body,
            } => self.initialize_head(key, *generation, body).map_or_else(
                AuthorityFailure::into_response,
                AuthorityResponse::InitializeHead,
            ),
            AuthorityOp::ReadHead { key } => self
                .read_head(key)
                .map_or_else(AuthorityFailure::into_response, AuthorityResponse::ReadHead),
            AuthorityOp::CompareExchangeHead {
                key,
                expected,
                new_generation,
                new_body,
            } => self
                .compare_exchange_head(key, *expected, *new_generation, new_body)
                .map_or_else(
                    AuthorityFailure::into_response,
                    AuthorityResponse::CompareExchangeHead,
                ),
            AuthorityOp::AuthenticateHeadReceipt { receipt } => {
                self.authenticate_head_receipt(receipt).map_or_else(
                    AuthorityFailure::into_response,
                    AuthorityResponse::AuthenticateHeadReceipt,
                )
            }
        }
    }
}

/// A backend that can be driven through a deterministic fault script.
///
/// This is a reference and laboratory capability, not a production one: the
/// campaigns in FG-004c and the lab core in FG-013a program a backend through
/// this trait so that ambiguity, duplication, delay, and crash are reproducible
/// from a seed rather than hoped for under load.
pub trait FaultableAuthorityStore: AuthorityStore {
    /// Replace the active fault plan and start a fresh script run.
    ///
    /// The operation counter the plan indexes, the logical clock, and both logs
    /// reset; stored bodies, heads, and the issuance record persist, because a
    /// new script is a new experiment against the same accumulated state.
    fn install_fault_plan(&self, plan: FaultPlan);

    /// Every fault the store has injected, in injection order.
    fn fault_log(&self) -> FaultLog;

    /// Every effect the store has reached, in application order.
    ///
    /// This is the ground truth a caller cannot see.  It exists so a campaign
    /// can assert that an ambiguous response really did or really did not carry
    /// an effect.
    fn effect_log(&self) -> EffectLog;

    /// Whether the store is currently refusing because of an injected crash.
    fn is_crashed(&self) -> bool;

    /// Bring a crashed endpoint back up.
    fn restart(&self);
}

/// What an exact-key read taught us about an ambiguous conditional replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CasResolution {
    /// The exact proposed generation and bytes are published.
    ///
    /// The caller's attempt, or a byte-identical one, linearized.
    Applied(HeadReadReceipt),
    /// The head is older than the proposal, so the attempt did not linearize.
    NotApplied(HeadReadReceipt),
    /// The head has moved past the proposal.
    ///
    /// Storage cannot say whether the attempt linearized and was then
    /// superseded, or never linearized at all.  This is exactly the case
    /// `NORMATIVE_PROTOCOL_CONTRACTS.md` §14 sends to a `TxId` lookup against
    /// the authenticated outcome index.
    Superseded(HeadReadReceipt),
    /// The head slot does not exist, so nothing was published.
    HeadAbsent,
}

/// What an exact-key read taught us about an ambiguous put-if-absent.
///
/// Immutable slots make this resolution complete, unlike [`CasResolution`]:
/// a body either is or is not published, and it can never change afterwards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PutResolution {
    /// The exact body is published; the attempt, or an equivalent one, applied.
    PresentIdentical,
    /// A different body occupies the slot; the attempt cannot have applied.
    PresentConflicting(Vec<u8>),
    /// The slot is empty; the attempt did not apply.
    Absent,
}

/// Resolve an ambiguous conditional replacement by exact-key read.
///
/// This is the storage half of the resolution protocol.  It never guesses: when
/// the head has moved past the proposal it reports [`CasResolution::Superseded`]
/// and leaves the decision to the outcome index.
pub fn resolve_ambiguous_cas<S>(
    store: &S,
    key: &HeadKey,
    proposed_generation: HeadGeneration,
    proposed_body: &[u8],
) -> Result<CasResolution, AuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    Ok(classify_cas_resolution(
        store.read_head(key)?,
        proposed_generation,
        proposed_body,
    ))
}

/// What an observed head means for a proposal whose outcome was ambiguous.
///
/// The shared decision core. §5.2 says client cancellation never proves
/// non-commit, so this is the rule that decides whether it committed — and a
/// second copy of it, one per runtime, is the way a node ends up concluding
/// "not applied" about a transaction that did apply.
///
/// It never guesses: a head past the proposal reports
/// [`CasResolution::Superseded`] and leaves the decision to the outcome index.
fn classify_cas_resolution(
    read: HeadRead,
    proposed_generation: HeadGeneration,
    proposed_body: &[u8],
) -> CasResolution {
    let HeadRead::Present(receipt) = read else {
        return CasResolution::HeadAbsent;
    };
    let current = receipt.generation();
    if current == proposed_generation && receipt.body() == proposed_body {
        CasResolution::Applied(receipt)
    } else if current < proposed_generation {
        CasResolution::NotApplied(receipt)
    } else {
        CasResolution::Superseded(receipt)
    }
}

/// Resolve an ambiguous put-if-absent by exact-key read.
pub fn resolve_ambiguous_put<S>(
    store: &S,
    key: &ImmutableKey,
    proposed_body: &[u8],
) -> Result<PutResolution, AuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    Ok(classify_put_resolution(
        store.read_immutable(key)?,
        proposed_body,
    ))
}

/// What an observed slot means for a put whose outcome was ambiguous.
///
/// The shared decision core, for the same reason as
/// [`classify_cas_resolution`]: an ambiguous write is resolved by reading, and
/// the reading must mean the same thing on both surfaces.
fn classify_put_resolution(read: ImmutableRead, proposed_body: &[u8]) -> PutResolution {
    let ImmutableRead::Present(body) = read else {
        return PutResolution::Absent;
    };
    if body == proposed_body {
        PutResolution::PresentIdentical
    } else {
        PutResolution::PresentConflicting(body)
    }
}

// --- the production surface -------------------------------------------------
//
// §5.2: "Client cancellation/disconnect never proves non-commit." A node over a
// durable backend meets `AuthorityFailure::Ambiguous` on any timeout, and until
// now the resolution protocol existed only over `AuthorityStore`.
// `FsqliteAuthorityStore` implements `AsyncAuthorityStore` only, so the one
// place the rule is most needed — a real network or database timeout in
// production — had no published way to apply it.
//
// Both surfaces call the same classifier above. Only the read differs.

/// Resolve an ambiguous conditional replacement by exact-key read, asynchronously.
///
/// The asynchronous twin of [`resolve_ambiguous_cas`]. Same classification, same
/// refusal to guess: a head past the proposal is [`CasResolution::Superseded`]
/// and the decision belongs to the outcome index.
///
/// # Errors
///
/// Whatever the store's head read refuses.
pub async fn resolve_ambiguous_cas_async<S>(
    store: &S,
    cx: &S::Context,
    key: &HeadKey,
    proposed_generation: HeadGeneration,
    proposed_body: &[u8],
) -> Result<CasResolution, AuthorityFailure>
where
    S: crate::async_contract::AsyncAuthorityStore + ?Sized,
{
    Ok(classify_cas_resolution(
        store.read_head(cx, key).await?,
        proposed_generation,
        proposed_body,
    ))
}

/// Resolve an ambiguous put-if-absent by exact-key read, asynchronously.
///
/// The asynchronous twin of [`resolve_ambiguous_put`].
///
/// # Errors
///
/// Whatever the store's immutable read refuses.
pub async fn resolve_ambiguous_put_async<S>(
    store: &S,
    cx: &S::Context,
    key: &ImmutableKey,
    proposed_body: &[u8],
) -> Result<PutResolution, AuthorityFailure>
where
    S: crate::async_contract::AsyncAuthorityStore + ?Sized,
{
    Ok(classify_put_resolution(
        store.read_immutable(cx, key).await?,
        proposed_body,
    ))
}

/// Convenience re-statement used by the conformance suite and by callers that
/// want the refusal without matching two levels of enumeration.
#[must_use]
pub const fn refusal_of(failure: AuthorityFailure) -> Option<AuthorityRefusal> {
    match failure {
        AuthorityFailure::Refused(refusal) => Some(refusal),
        AuthorityFailure::Ambiguous(_) => None,
    }
}

/// The ambiguity reason, when the failure was ambiguous.
#[must_use]
pub const fn ambiguity_of(failure: AuthorityFailure) -> Option<AmbiguityReason> {
    match failure {
        AuthorityFailure::Ambiguous(reason) => Some(reason),
        AuthorityFailure::Refused(_) => None,
    }
}
