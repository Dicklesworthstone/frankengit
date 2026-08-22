#![forbid(unsafe_code)]
//! Admission-materialization refusals that only a store double can reach
//! (`frankengit-t5x3`).
//!
//! `AdmissionMaterializationRefusal` has 25 variants. **Fourteen are named by
//! nothing** — not by this crate's 28 inline tests, not by any `tests/` file in
//! the workspace. This file takes the ones that are genuinely reachable.
//!
//! # Why a store double, and why that is not a shortcut
//!
//! Several of these refusals cannot be provoked through well-formed caller
//! input, but *are* reachable because every entry point is generic over the
//! store:
//!
//! ```text
//! pub async fn stage_ref_state_in<Authority>(..) where Authority: AsyncAuthorityStore
//! ```
//!
//! A test supplies the `Authority`. That is the same mechanism the workspace
//! already uses for exactly this purpose, and it pins what the materializer
//! does when the object store reports something the happy path never produces.
//!
//! # `ImmutableConflict`, and why the real path cannot reach it
//!
//! `stage_ref_state_in` stages under
//! `admission_immutable_key(PREFIX, repository_id, root)` where `root` is the
//! **digest of the frame being staged**. So the same key implies the same bytes,
//! and a real store answers `IdenticalRetry` — never `Conflict`. Content
//! addressing is what makes the conflict arm unreachable in production, and
//! that is precisely why it needs a probe: it is the arm that says what happens
//! if that property is ever violated, and nothing else in the tree exercises it.
//!
//! The permitted twins below establish the other side: a first stage is
//! `Created` and a second stage of the **same** state is `IdenticalRetry`, both
//! proceeding. Without them a `Conflict` refusal could be the materializer
//! refusing every stage.
//!
//! # Non-claims
//!
//! This covers the staging path's conflict arm and its accepted twins. It does
//! not verify admission materialization end to end, and it does not cover the
//! variants recorded on the bead as unreachable against well-formed input —
//! `CanonicalFrame` (subsumed by `CanonicalRoot` one line above, since
//! `canonical_body_root` encodes), `CanonicalRoot` (needs an entry count past
//! `u32::MAX`), and the identity-domain halves (`body_id` derives the identity
//! from the body's own `DOMAIN`, so the domain always matches). Those are
//! measured nulls, not gaps. Nothing here modifies `crates/fgit-node/src/**`.

use core::future::Future;

use fgit_admission::CanonicalRefState;
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome,
    StoreInstanceId,
};
use fgit_node::{AdmissionMaterializationRefusal, DurableAdmissionMaterializer};
use fgit_resource::{CacheScope, OpaqueHandle};
use fgit_types::{HeadGeneration, OPAQUE_ID_LEN, RepositoryId};

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x71; OPAQUE_ID_LEN])
}

fn materializer() -> DurableAdmissionMaterializer {
    let handle = OpaqueHandle::new(&[0x5a; 16]).expect("a short opaque scope handle is valid");
    DurableAdmissionMaterializer::new(CacheScope::new(handle))
}

/// The empty canonical ref state, which is what node initialization stages.
fn ref_state() -> CanonicalRefState {
    CanonicalRefState::default()
}

/// Drive an already-resolved future to its value. No runtime is involved and
/// none is needed: every delegate below resolves synchronously.
fn poll_ready<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("an in-memory delegate must never suspend"),
    }
}

/// A **complete** delegate over `MemoryAuthorityStore` with one armed fault.
///
/// Completeness matters: `AsyncAuthorityStore` has a defaulted method that
/// refuses with `OperationUnsupported`, so a double that merely *omitted* a
/// method would fail for a reason the test did not choose and would look like
/// evidence while proving nothing. Every method is forwarded; only
/// `put_if_absent` is armed, and only when `conflict` is set.
struct StagingStore {
    inner: MemoryAuthorityStore,
    conflict: bool,
}

impl StagingStore {
    fn real() -> Self {
        Self {
            inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x91)),
            conflict: false,
        }
    }

    fn always_conflicts() -> Self {
        Self {
            inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x92)),
            conflict: true,
        }
    }
}

impl AsyncAuthorityStore for StagingStore {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        fgit_authority::AuthorityStore::instance_id(&self.inner)
    }

    fn limits(&self) -> AuthorityLimits {
        fgit_authority::AuthorityStore::limits(&self.inner)
    }

    fn put_if_absent(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        let resolved = if self.conflict {
            Ok(PutOutcome::Conflict)
        } else {
            fgit_authority::AuthorityStore::put_if_absent(&self.inner, key, body)
        };
        async move { resolved }
    }

    fn read_immutable(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        let resolved = fgit_authority::AuthorityStore::read_immutable(&self.inner, key);
        async move { resolved }
    }

    fn initialize_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        let resolved =
            fgit_authority::AuthorityStore::initialize_head(&self.inner, key, generation, body);
        async move { resolved }
    }

    fn read_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        let resolved = fgit_authority::AuthorityStore::read_head(&self.inner, key);
        async move { resolved }
    }

    fn compare_exchange_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        let resolved = fgit_authority::AuthorityStore::compare_exchange_head(
            &self.inner,
            key,
            expected,
            new_generation,
            new_body,
        );
        async move { resolved }
    }

    fn publish_head_with_outcomes(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        let resolved = fgit_authority::AuthorityStore::publish_head_with_outcomes(
            &self.inner,
            key,
            expected,
            new_generation,
            new_body,
            outcomes,
            witness,
        );
        async move { resolved }
    }

    fn authenticate_head_receipt(
        &self,
        _cx: &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        let resolved =
            fgit_authority::AuthorityStore::authenticate_head_receipt(&self.inner, receipt);
        async move { resolved }
    }
}

// ---------------------------------------------------------------------------
// The permitted directions, built first
// ---------------------------------------------------------------------------

/// A first stage of the canonical ref state succeeds and returns its root.
#[test]
fn staging_a_canonical_ref_state_returns_its_root() {
    let store = StagingStore::real();
    let root =
        poll_ready(materializer().stage_ref_state_in(&store, &(), repository(), ref_state()))
            .expect("staging the canonical empty ref state must succeed");
    assert_ne!(
        format!("{root:?}"),
        String::new(),
        "the staged root is returned to the caller"
    );
}

/// **Content addressing, stated as a test.** Staging the same state twice is
/// idempotent and returns the *same* root — the store answers `IdenticalRetry`
/// rather than `Conflict`, which is exactly why the conflict arm is
/// unreachable through this path in production.
#[test]
fn staging_the_same_ref_state_twice_is_idempotent_and_returns_one_root() {
    let store = StagingStore::real();
    let first =
        poll_ready(materializer().stage_ref_state_in(&store, &(), repository(), ref_state()))
            .expect("first stage succeeds");
    let second =
        poll_ready(materializer().stage_ref_state_in(&store, &(), repository(), ref_state()))
            .expect("re-staging identical bytes must not refuse");
    assert_eq!(
        first, second,
        "the key is derived from the frame's own digest, so a repeat is the same root"
    );
}

// ---------------------------------------------------------------------------
// ImmutableConflict — the arm content addressing is supposed to make impossible
// ---------------------------------------------------------------------------

/// A store reporting a same-key-different-bytes collision is refused as
/// `ImmutableConflict`.
///
/// Reached with a store double because the production path cannot produce it:
/// the key is the digest of the very bytes being staged. The arm exists for the
/// case where that property is violated — a store that answers `Conflict` for a
/// content-addressed key is reporting something the caller must not treat as a
/// successful stage — and this is the only test in the tree that exercises it.
#[test]
fn a_store_reporting_a_conflict_on_a_content_addressed_key_is_refused() {
    let store = StagingStore::always_conflicts();
    let refusal =
        poll_ready(materializer().stage_ref_state_in(&store, &(), repository(), ref_state()))
            .expect_err("a conflicting immutable key must refuse rather than report a stage");
    assert!(
        matches!(refusal, AdmissionMaterializationRefusal::ImmutableConflict),
        "expected ImmutableConflict, got {refusal:?}"
    );
}

/// The refusal is **not** the materializer refusing every stage.
///
/// The same call against a real store proceeds, so the probe above is
/// attributable to the store's answer and to nothing else. Asserted here rather
/// than relying on the twins above, because this pairs the identical call
/// one-switch apart.
#[test]
fn the_conflict_refusal_is_attributable_to_the_store_and_not_to_the_input() {
    let conflicting = StagingStore::always_conflicts();
    let real = StagingStore::real();

    assert!(
        poll_ready(materializer().stage_ref_state_in(&conflicting, &(), repository(), ref_state()))
            .is_err(),
        "the conflicting store refuses"
    );
    assert!(
        poll_ready(materializer().stage_ref_state_in(&real, &(), repository(), ref_state()))
            .is_ok(),
        "the same call against a real store proceeds, so the input is not what refused"
    );
}

// ---------------------------------------------------------------------------
// frankengit-sfr9: the materialization path's opening chain
//
//   1  read_head                  -> Authority(_) / HeadAbsent
//   2  authenticate_head_receipt  -> Authority(_)
//   3  authenticated.body()       -> HeadBody
//
// HeadAbsent and HeadBody are the two ends of that chain and nothing in the
// tree told them apart. Both mean "materialization cannot proceed"; they mean
// different things to an operator, which is the whole reason they are separate
// variants — nothing is written yet, versus something IS written that this
// build cannot decode.
// ---------------------------------------------------------------------------

fn head_key() -> HeadKey {
    HeadKey::new(b"sfr9/head".to_vec()).expect("bounded head key")
}

fn never_cancelled() -> impl Fn() -> bool + Sync {
    || false
}

/// **Stage 1.** An empty head slot is `HeadAbsent`, not an authority failure.
#[test]
fn an_uninitialized_head_slot_is_head_absent() {
    let store = StagingStore::real();
    let refusal = poll_ready(materializer().materialize_current_in(
        &store,
        &(),
        &head_key(),
        repository(),
        &never_cancelled(),
    ))
    .expect_err("materializing a slot that was never written must refuse");
    assert!(
        matches!(refusal, AdmissionMaterializationRefusal::HeadAbsent),
        "expected HeadAbsent, got {refusal:?}"
    );
}

/// **Stage 3.** A head slot holding bytes this build cannot decode is
/// `HeadBody` — a *different* refusal from an empty slot.
///
/// Driven through the real store: `initialize_head` takes arbitrary bytes, so
/// planting a non-canonical head body needs no fault injection. This is the
/// cross-version case §6 cares about — the authority holds a head, and this
/// build cannot read it. Saying "absent" there would be wrong and dangerous:
/// absent invites initialization, which would overwrite a head that exists.
#[test]
fn a_head_slot_holding_undecodable_bytes_is_head_body_and_not_head_absent() {
    let store = StagingStore::real();
    poll_ready(store.initialize_head(&(), &head_key(), HeadGeneration::FIRST, b"not-a-head-body"))
        .expect("the store accepts arbitrary head bytes");

    let refusal = poll_ready(materializer().materialize_current_in(
        &store,
        &(),
        &head_key(),
        repository(),
        &never_cancelled(),
    ))
    .expect_err("a head this build cannot decode must refuse");

    assert!(
        matches!(refusal, AdmissionMaterializationRefusal::HeadBody(_)),
        "expected HeadBody, got {refusal:?}"
    );
    assert!(
        !matches!(refusal, AdmissionMaterializationRefusal::HeadAbsent),
        "a head that EXISTS but does not decode must never be reported as absent: \
         absent invites initialization, which would overwrite it"
    );
}

/// **The ordering.** With the slot empty, stage 1 owns the refusal even though
/// a later stage would also have refused.
///
/// Paired with the probe above: that one keeps stage 1 satisfied and reaches
/// stage 3, this one fails stage 1 and never gets there. Either alone would be
/// satisfied by an arbitrary order.
#[test]
fn the_absent_head_is_reported_before_anything_downstream_is_attempted() {
    let store = StagingStore::real();
    // A repository id unrelated to anything staged, so a later stage would have
    // something to complain about too — but the slot is empty, so stage 1 wins.
    let refusal = poll_ready(materializer().materialize_current_in(
        &store,
        &(),
        &head_key(),
        RepositoryId::from_bytes([0x99; OPAQUE_ID_LEN]),
        &never_cancelled(),
    ))
    .expect_err("an empty slot refuses");
    assert!(
        matches!(refusal, AdmissionMaterializationRefusal::HeadAbsent),
        "the first stage of the chain owns the refusal, got {refusal:?}"
    );
}

/// **§5.1 — an inconsistent authority chain is refused, not walked.**
///
/// A head that names a predecessor but carries no decision tail is
/// structurally broken: it claims to succeed something while providing no
/// decisions that could have produced it. `DecisionHistoryUnbound` is that
/// refusal, and nothing named it before.
///
/// Planted through the real store rather than a double — `initialize_head`
/// takes arbitrary bytes, so a head that DECODES CLEANLY but is internally
/// inconsistent is exactly what this plants. That distinction matters: this is
/// not the undecodable-bytes case above, it is a well-formed head whose
/// *content* cannot be reconciled, which is a different failure and a different
/// variant.
#[test]
fn a_head_claiming_a_predecessor_without_a_decision_tail_is_unbound() {
    let store = StagingStore::real();

    // The materializer resolves the head's ref state by root BEFORE it walks
    // the decision history, so an unstaged frame refuses as `ImmutableAbsent`
    // first. Measured, not assumed: the first draft of this test hit exactly
    // that and named the stage for me. Stage the frame so the walk is reached.
    let ref_root =
        poll_ready(materializer().stage_ref_state_in(&store, &(), repository(), ref_state()))
            .expect("staging the canonical ref state succeeds");

    let mut head = genesis_head_body();
    head.ref_root = ref_root;
    head.predecessor_head_id = Some(fgit_types::RepositoryAuthorityHeadId::from_digest(
        fgit_types::DigestAlgorithmId::try_new(2).expect("a nonzero algorithm slot"),
        fgit_types::CANONICAL_CODEC_VERSION,
        fgit_types::DigestBytes::try_new(&[0x5b; 32]).expect("32-byte digest body"),
    ));
    head.decision_tail_id = None;

    let bytes = fgit_codec::wire::encode_body(&head).expect("the inconsistent head still encodes");
    poll_ready(store.initialize_head(&(), &head_key(), HeadGeneration::FIRST, &bytes))
        .expect("the store accepts the planted head");

    let refusal = poll_ready(materializer().materialize_current_in(
        &store,
        &(),
        &head_key(),
        repository(),
        &never_cancelled(),
    ))
    .expect_err("a head that names a predecessor with no decision tail must refuse");

    assert!(
        matches!(
            refusal,
            AdmissionMaterializationRefusal::DecisionHistoryUnbound
        ),
        "expected DecisionHistoryUnbound, got {refusal:?}"
    );
    assert!(
        !matches!(refusal, AdmissionMaterializationRefusal::HeadBody(_)),
        "this head DECODES; refusing it as HeadBody would confuse an unreadable \
         head with a well-formed but inconsistent one"
    );
}

/// A canonical genesis head body, used to plant both well-formed and
/// deliberately inconsistent heads.
fn genesis_head_body() -> fgit_codec::RepositoryAuthorityHeadBody {
    fn digest(tag: u8) -> fgit_types::Digest {
        fgit_types::Digest::new(
            fgit_types::DigestAlgorithmId::try_new(2).expect("a nonzero algorithm slot"),
            fgit_types::DigestBytes::try_new(&[tag; 32]).expect("32-byte digest body"),
        )
    }
    fgit_codec::RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: fgit_types::PolicyEpoch::FIRST,
        format_registry_epoch: fgit_types::RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

// ---------------------------------------------------------------------------
// frankengit-nhpp: cancellation outranks the refusal that would otherwise fire
//
// materialize_current_in opens with a catch-up checkpoint BEFORE it reads the
// head:
//
//     ensure_materializer_catch_up_live(is_cancelled)?;      <- notch 0
//     let HeadRead::Present(receipt) = authority.read_head(..) else {
//         return Err(AdmissionMaterializationRefusal::HeadAbsent);
//     };
//
// `is_cancelled` is caller-supplied, so which of the two a caller sees is a
// precedence question, and §3.2 answers it: cancellation is a protocol, not an
// error code, and a cancelled request must not be told its head is absent —
// absent invites initialization.
//
// The deeper notches of that dial (the cache scope, and `CacheContainment`)
// need `OneNode`'s PRIVATE fields — `authority`, `admission_materializer`,
// `head_key`, `runtime` are all private with no public accessor — so they are
// an in-crate experiment, not a gap reachable from here. Recorded on the bead.
// ---------------------------------------------------------------------------

/// An `is_cancelled` that reports cancellation from the very first poll.
fn cancelled_immediately() -> impl Fn() -> bool + Sync {
    || true
}

/// **§3.2 outranks §5.1 here.** A caller cancelled before the head is read is
/// told `Cancelled`, not `HeadAbsent` — against the very same empty slot that
/// `an_uninitialized_head_slot_is_head_absent` shows refuses as absent.
///
/// Asserted as a difference rather than in isolation: the two tests drive an
/// identical store and head key and differ only in the cancellation closure, so
/// the outcome is attributable to that one switch.
#[test]
fn cancellation_outranks_the_absent_head_it_would_otherwise_report() {
    let store = StagingStore::real();
    let refusal = poll_ready(materializer().materialize_current_in(
        &store,
        &(),
        &head_key(),
        repository(),
        &cancelled_immediately(),
    ))
    .expect_err("a cancelled materialization must refuse");

    assert!(
        matches!(refusal, AdmissionMaterializationRefusal::Cancelled),
        "expected Cancelled, got {refusal:?}"
    );
    assert!(
        !matches!(refusal, AdmissionMaterializationRefusal::HeadAbsent),
        "a cancelled caller must never be told the head is absent: absent invites \
         initialization, and this caller asked to stop rather than to discover an empty slot"
    );
}

/// The permitted twin for the switch above: the same call with a closure that
/// never fires reaches the head read and reports `HeadAbsent`.
///
/// Without this the probe above could be the materializer refusing everything
/// once a closure is supplied at all.
#[test]
fn a_closure_that_never_cancels_leaves_the_underlying_refusal_intact() {
    let store = StagingStore::real();
    let refusal = poll_ready(materializer().materialize_current_in(
        &store,
        &(),
        &head_key(),
        repository(),
        &never_cancelled(),
    ))
    .expect_err("an empty slot still refuses");
    assert!(
        matches!(refusal, AdmissionMaterializationRefusal::HeadAbsent),
        "with no cancellation the head read owns the refusal, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// frankengit-dp70: the two NodeRefusal cleanup variants report the CAUSE
//
// Both are §3.2 containment-failure reports — an operation failed AND the
// mandatory teardown failed, so both failures are carried rather than one being
// discarded:
//
//     AuthorityInitializationCleanup { initialization: Box<Self>, cleanup: Box<Self> }
//     ExistingOpenCleanup            { opening: Box<Self>,        cleanup: Box<Self> }
//
// Driving either end to end needs an operation failure and a cleanup failure at
// the same moment, which this crate has no fault injection for. What is pinned
// here is what they REPORT — `source()` and `Display`, both pure functions over
// a constructed value — so these are covered BY CONSTRUCTION, and no test below
// implies it drove a paired failure.
//
// The claim: `source()` returns the ORIGINAL failure, not the cleanup. The
// cleanup failure is the second thing that went wrong, and a caller walking the
// error chain should reach the cause, not the consequence.
// ---------------------------------------------------------------------------

use std::error::Error as _;

use fgit_node::NodeRefusal;

/// Two distinguishable inner refusals, so a probe can tell which one came back
/// rather than merely that something did.
const CAUSE: NodeRefusal = NodeRefusal::AuthorityHeadAbsent;
const CONSEQUENCE: NodeRefusal = NodeRefusal::EmptyStorageRoot;

/// **The cause, not the consequence.** Both variants expose the failure that
/// happened *first*.
#[test]
fn both_cleanup_variants_report_the_original_failure_as_their_source() {
    let initialization = NodeRefusal::AuthorityInitializationCleanup {
        initialization: Box::new(CAUSE),
        cleanup: Box::new(CONSEQUENCE),
    };
    assert_eq!(
        initialization
            .source()
            .expect("AuthorityInitializationCleanup has a source")
            .to_string(),
        CAUSE.to_string(),
        "the initialization failure is the cause; the cleanup failure is what followed it"
    );

    let opening = NodeRefusal::ExistingOpenCleanup {
        opening: Box::new(CAUSE),
        cleanup: Box::new(CONSEQUENCE),
    };
    assert_eq!(
        opening
            .source()
            .expect("ExistingOpenCleanup has a source")
            .to_string(),
        CAUSE.to_string(),
        "the opening failure is the cause"
    );
}

/// **Asserted as a difference, which is what makes it a claim.**
///
/// The same two inner refusals, swapped, must produce different `source()`
/// answers. A probe that only checked `source().is_some()` would pass against a
/// variant that returned the cleanup — which is precisely the refactor this
/// test exists to catch.
#[test]
fn swapping_the_two_inner_failures_changes_which_one_source_reports() {
    let normal = NodeRefusal::AuthorityInitializationCleanup {
        initialization: Box::new(CAUSE),
        cleanup: Box::new(CONSEQUENCE),
    };
    let swapped = NodeRefusal::AuthorityInitializationCleanup {
        initialization: Box::new(CONSEQUENCE),
        cleanup: Box::new(CAUSE),
    };

    let from_normal = normal.source().expect("has a source").to_string();
    let from_swapped = swapped.source().expect("has a source").to_string();

    assert_ne!(
        from_normal, from_swapped,
        "source() must track the initialization slot, not return a fixed member"
    );
    assert_eq!(from_normal, CAUSE.to_string());
    assert_eq!(from_swapped, CONSEQUENCE.to_string());
}

/// Each message names **both** failures, so neither is discarded.
///
/// Asserted by the property the docs claim — each inner refusal's own rendering
/// appears — rather than by exact string, which would be brittle and close to
/// tautological.
#[test]
fn each_cleanup_message_names_both_failures() {
    let initialization = NodeRefusal::AuthorityInitializationCleanup {
        initialization: Box::new(CAUSE),
        cleanup: Box::new(CONSEQUENCE),
    }
    .to_string();
    assert!(
        initialization.contains(&CAUSE.to_string())
            && initialization.contains(&CONSEQUENCE.to_string()),
        "AuthorityInitializationCleanup must render both failures, got {initialization:?}"
    );

    let opening = NodeRefusal::ExistingOpenCleanup {
        opening: Box::new(CAUSE),
        cleanup: Box::new(CONSEQUENCE),
    }
    .to_string();
    assert!(
        opening.contains(&CAUSE.to_string()) && opening.contains(&CONSEQUENCE.to_string()),
        "ExistingOpenCleanup must render both failures, got {opening:?}"
    );

    // The two are distinguishable from each other, not just from their parts:
    // one names initialization, the other a non-initializing open.
    assert_ne!(
        initialization, opening,
        "the two containment reports must not render identically"
    );
}
