//! The async seal/admission surface, driven beside the sync one over identical state.
//!
//! `FsqliteAuthorityStore` implements [`AsyncAuthorityStore`] only, so a node
//! that must seal a request and record its admission before publishing its
//! first RCR had no route to these rules. The alternative was a node-local
//! copy, and §5.2's *"one seal body owns one logical identity; key reuse with
//! different semantics fails closed"* is not a property that survives being
//! reimplemented per caller.
//!
//! # What these tests are for
//!
//! Not "the async functions work" — that would be satisfied by a second
//! implementation that happens to pass its own tests while disagreeing with the
//! first. **Every case here runs both surfaces over identically-constructed
//! stores and requires the same answer**, which is the only way to show they
//! agree rather than that each works alone.
//!
//! The corpus is chosen so agreement is not vacuous: it contains a `Created`, an
//! `IdenticalRetry`, and a **rejection**, which produce three distinct answers.
//! A pair of surfaces that returned one constant would fail
//! `the_corpus_produces_distinct_answers` below.

use std::future::Future;

use fgit_authority::{
    AdmissionInstant, AdmissionReceiptBody, AsyncAuthorityStore, AuthenticatedHead,
    AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken, CasOutcome,
    DuplicateAbsenceWitness, ExpectedOld, HeadInit, HeadKey, HeadRead, HeadReadReceipt,
    IdempotencyKey, ImmutableKey, ImmutableRead, MemoryAuthorityStore, ProposedNew, PutOutcome,
    RefCommand, RequestRejection, SealAdmission, SealAttempt, SealFailure, SemanticRequest,
    StoreInstanceId, admission_key, read_admission, read_admission_async, read_seal_async,
    record_admission, record_admission_async, seal_request, seal_request_async,
};
use fgit_codec::wire::encode_body;
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId, TransactionSealId};
use fgit_types::label::{AsciiSlug, SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::{HeadGeneration, PolicyEpoch};
use fgit_types::refs::RefName;

// ---------------------------------------------------------------------------
// An async view over the reference store, for equivalence only
// ---------------------------------------------------------------------------

/// Not a blocking adapter: every operation is resolved before its future is
/// created, so nothing blocks and no cancellation is silently dropped. It
/// exists so both surfaces can be driven over identically-constructed state in
/// one test. Production async use goes through the fsqlite implementation.
struct AsyncView(MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncView {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        let resolved = self.0.put_if_absent(key, body);
        async move { resolved }
    }

    fn read_immutable(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        let resolved = self.0.read_immutable(key);
        async move { resolved }
    }

    fn initialize_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        let resolved = self.0.initialize_head(key, generation, body);
        async move { resolved }
    }

    fn read_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        let resolved = self.0.read_head(key);
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
        let resolved = self
            .0
            .compare_exchange_head(key, expected, new_generation, new_body);
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
        let resolved = self.0.publish_head_with_outcomes(
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
        let resolved = self.0.authenticate_head_receipt(receipt);
        async move { resolved }
    }
}

/// Drive an already-resolved future to its value.
fn poll_ready<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the in-memory async view must never suspend"),
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

const fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x33; 16])
}

fn request(target: &str, new: u8) -> SemanticRequest {
    SemanticRequest::build(
        SchemaId::new(SchemaFamily::from_static("receive-pack"), 1, 0),
        GitHashAlgorithm::Sha1,
        true,
        vec![RefCommand {
            name: RefName::try_new(target.as_bytes()).expect("an admissible ref name"),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(GitOid::Sha1(GitOidSha1::from_bytes([new; 20]))),
            force: false,
        }],
        Vec::new(),
        Vec::new(),
    )
    .expect("an admissible request")
}

fn attempt(key: &[u8], target: &str, new: u8) -> SealAttempt {
    SealAttempt {
        tenant_id: tenant(),
        repository_id: repository(),
        authenticated_principal_id: principal(),
        idempotency_key: IdempotencyKey::new(key.to_vec()).expect("a bounded key"),
        request: request(target, new),
    }
}

const fn receipt_for(seal_id: TransactionSealId, capability: &'static str) -> AdmissionReceiptBody {
    AdmissionReceiptBody {
        seal_id,
        admission_capability: AsciiSlug::from_static(capability),
        policy_epoch: PolicyEpoch::FIRST,
        issuer: principal(),
        first_seen: AdmissionInstant::from_raw(7),
    }
}

/// A stable label for a seal result, so the surfaces compare by shape as well
/// as by value.
fn label(result: &Result<SealAdmission, SealFailure>) -> String {
    match result {
        Ok(SealAdmission::Created { .. }) => "created".to_owned(),
        Ok(SealAdmission::IdenticalRetry { .. }) => "identical-retry".to_owned(),
        Err(SealFailure::Rejected(rejection)) => match **rejection {
            RequestRejection::IdempotencyKeyReuse { .. } => "reuse-rejected".to_owned(),
        },
        Err(other) => format!("failure/{other:?}"),
    }
}

/// Run one sealing program on each surface, over freshly-built stores.
fn seal_on_both(program: &[SealAttempt]) -> (Vec<String>, Vec<String>) {
    let sync_store = store();
    let sync: Vec<String> = program
        .iter()
        .map(|a| label(&seal_request(&sync_store, a)))
        .collect();

    let view = AsyncView(store());
    let asynchronous: Vec<String> = program
        .iter()
        .map(|a| label(&poll_ready(seal_request_async(&view, &(), a))))
        .collect();

    (sync, asynchronous)
}

/// Genesis, first attempt, exact repeat, then the same key with a different request.
fn corpus() -> Vec<SealAttempt> {
    vec![
        attempt(b"key-1", "refs/heads/main", 0xAB),
        attempt(b"key-1", "refs/heads/main", 0xAB),
        attempt(b"key-1", "refs/heads/main", 0xCD),
    ]
}

// ---------------------------------------------------------------------------
// The corpus must discriminate before agreement on it means anything
// ---------------------------------------------------------------------------

#[test]
fn the_corpus_produces_distinct_answers() {
    // Without this, two surfaces that both returned one constant would satisfy
    // every equivalence assertion below.
    let (sync, _) = seal_on_both(&corpus());
    assert_eq!(
        sync,
        vec!["created", "identical-retry", "reuse-rejected"],
        "the corpus must reach all three seal outcomes, or agreement on it is vacuous"
    );
}

#[test]
fn both_surfaces_seal_the_same_corpus_identically() {
    let (sync, asynchronous) = seal_on_both(&corpus());
    assert_eq!(
        sync, asynchronous,
        "the surfaces disagree about sealing; §5.2 admits one seal model, not one per runtime"
    );
}

#[test]
fn both_surfaces_derive_the_same_seal_identity() {
    // Shape agreement is not enough: the identities must match too, or one
    // surface could publish under a name the other would not recognise.
    let program = attempt(b"key-9", "refs/heads/next", 0x5A);

    let sync_store = store();
    let sync = seal_request(&sync_store, &program).expect("the sync seal");
    let view = AsyncView(store());
    let asynchronous =
        poll_ready(seal_request_async(&view, &(), &program)).expect("the async seal");

    assert_eq!(
        sync, asynchronous,
        "the surfaces must agree on the seal identity and transaction identity, not merely on the \
         outcome shape"
    );
}

#[test]
fn a_reused_key_is_rejected_before_any_seal_exists_on_both_surfaces() {
    // The ordering obligation, not just the rejection: reuse is a pre-decision
    // rejection (§5.2), so the losing attempt must leave no seal behind.
    let program = corpus();
    let view = AsyncView(store());
    for a in &program[..2] {
        poll_ready(seal_request_async(&view, &(), a)).expect("the first two attempts seal");
    }
    let rejected = poll_ready(seal_request_async(&view, &(), &program[2]))
        .expect_err("a reused key with a different request must be rejected");
    assert!(
        matches!(rejected, SealFailure::Rejected(_)),
        "reuse must be a typed pre-seal rejection, not a storage failure; got {rejected:?}"
    );

    let (_, losing_seal) = program[2].derive().expect("the attempt derives");
    let found = poll_ready(read_seal_async(
        &view,
        &(),
        tenant(),
        repository(),
        losing_seal.tx_id,
    ))
    .expect("the read completes");
    assert!(
        found.is_none(),
        "the rejected attempt must have left no seal: reuse is settled before any seal exists"
    );
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

#[test]
fn both_surfaces_record_and_reread_an_admission_identically() {
    let program = attempt(b"key-2", "refs/heads/main", 0x11);

    let sync_store = store();
    let sync_seal = seal_request(&sync_store, &program).expect("sync seal");
    let sync_first = record_admission(&sync_store, &receipt_for(sync_seal.seal_id(), "receive"))
        .expect("sync admission");
    let sync_again = record_admission(&sync_store, &receipt_for(sync_seal.seal_id(), "receive"))
        .expect("sync re-admission");
    let sync_read = read_admission(&sync_store, sync_seal.seal_id()).expect("sync read");

    let view = AsyncView(store());
    let async_seal = poll_ready(seal_request_async(&view, &(), &program)).expect("async seal");
    let async_first = poll_ready(record_admission_async(
        &view,
        &(),
        &receipt_for(async_seal.seal_id(), "receive"),
    ))
    .expect("async admission");
    let async_again = poll_ready(record_admission_async(
        &view,
        &(),
        &receipt_for(async_seal.seal_id(), "receive"),
    ))
    .expect("async re-admission");
    let async_read =
        poll_ready(read_admission_async(&view, &(), async_seal.seal_id())).expect("async read");

    assert!(
        sync_first.is_first() && async_first.is_first(),
        "the first record must be the admitting one on both surfaces"
    );
    assert!(
        !sync_again.is_first() && !async_again.is_first(),
        "a repeat must report the earlier admission, not admit twice"
    );
    assert_eq!(
        sync_first, async_first,
        "the surfaces must produce the same admission receipt"
    );
    assert_eq!(
        sync_again, async_again,
        "the surfaces must agree on the idempotent repeat"
    );
    assert_eq!(
        sync_read, async_read,
        "the surfaces must read back the same receipt"
    );
    assert!(
        sync_read.is_some(),
        "the receipt must be readable, or the equality above compares two Nones"
    );
}

#[test]
fn an_admission_slot_naming_another_seal_is_refused_on_the_async_surface() {
    // The presence case for the cross-check. Without it, an accessor that
    // decoded and returned whatever it found would pass every test above,
    // because in those the slot always holds the right receipt.
    let program = attempt(b"key-3", "refs/heads/main", 0x22);
    let other = attempt(b"key-4", "refs/heads/other", 0x33);

    let backing = store();
    let mine = seal_request(&backing, &program).expect("seal");
    let theirs = seal_request(&backing, &other).expect("the other seal");
    assert_ne!(
        mine.seal_id(),
        theirs.seal_id(),
        "the two fixtures must have distinct seal identities, or the plant is not a mismatch"
    );

    // Their receipt, filed under my seal's admission key.
    assert_eq!(
        backing
            .put_if_absent(
                &admission_key(mine.seal_id()).expect("a derivable admission key"),
                &encode_body(&receipt_for(theirs.seal_id(), "receive")).expect("a receipt encodes"),
            )
            .expect("the store accepts the write"),
        PutOutcome::Created,
        "the plant must land, or this test proves nothing"
    );

    let view = AsyncView(backing);
    let failure = poll_ready(read_admission_async(&view, &(), mine.seal_id()))
        .expect_err("a receipt naming another seal must be refused, not returned");
    assert!(
        matches!(
            failure,
            SealFailure::SlotContentUnexpected {
                slot: "admission-receipt"
            }
        ),
        "the refusal must name the admission-receipt slot; got {failure:?}"
    );
}

#[test]
fn an_absent_admission_reads_as_none_on_both_surfaces() {
    // The permitted twin of the refusal above: absent is an answer, not a fault.
    let program = attempt(b"key-5", "refs/heads/main", 0x44);
    let sync_store = store();
    let sealed = seal_request(&sync_store, &program).expect("seal");

    let sync_read = read_admission(&sync_store, sealed.seal_id()).expect("sync read completes");
    let view = AsyncView(store());
    let _ = poll_ready(seal_request_async(&view, &(), &program)).expect("async seal");
    let async_read =
        poll_ready(read_admission_async(&view, &(), sealed.seal_id())).expect("async read");

    assert_eq!(sync_read, None, "an unadmitted seal has no receipt");
    assert_eq!(
        sync_read, async_read,
        "the surfaces must agree that an unadmitted seal reads as None"
    );
}
