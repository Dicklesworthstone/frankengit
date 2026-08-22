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

fn repository() -> RepositoryId {
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
