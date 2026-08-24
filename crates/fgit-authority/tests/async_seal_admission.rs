//! The async-surface equivalence suite: seal, admission, and ambiguity resolution.
//!
//! One `AsyncView` fixture serves all three. A second or third copy of a
//! delegating view would be free to drift from the first, which is the defect
//! class these tests exist to prevent -- so the file's scope is "the async
//! surface" rather than any one module of it, despite the name it was created
//! under.
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
    CasResolution, DuplicateAbsenceWitness, ExpectedOld, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, IdempotencyKey, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    OutcomeFailure, ProposedNew, PutOutcome, PutResolution, RefCommand, RequestRejection,
    SealAdmission, SealAttempt, SealFailure, SemanticRequest, StoreInstanceId, admission_key,
    head_selected_ref_state_absence_proof, head_selected_ref_state_absence_proof_async,
    read_admission, read_admission_async, read_seal_async, record_admission,
    record_admission_async, resolve_ambiguous_cas, resolve_ambiguous_cas_async,
    resolve_ambiguous_put, resolve_ambiguous_put_async, root_layout_for_proof_async,
    root_layout_for_verification, root_layout_for_verification_async, seal_request,
    seal_request_async, stage_repository_configuration, stage_repository_configuration_async,
};
use fgit_codec::RepositoryConfigurationBody;
use fgit_codec::wire::encode_body;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId, TransactionSealId};
use fgit_types::label::{AsciiSlug, SchemaFamily, SchemaId};
use fgit_types::layout::RootLayoutVersion;
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

// ---------------------------------------------------------------------------
// Ambiguity resolution (frankengit-08gg)
// ---------------------------------------------------------------------------
//
// §5.2: "Client cancellation/disconnect never proves non-commit." A node over a
// durable backend meets `AuthorityFailure::Ambiguous` on any timeout, and the
// resolution protocol existed only over `AuthorityStore` — so the one place the
// rule is most needed had no published way to apply it.
//
// The corpus below reaches four distinct CAS answers and three put answers, so
// agreement between the surfaces is not satisfied by a pair that returns one
// constant.

fn head_slot() -> HeadKey {
    HeadKey::new(b"fg/head/v1/ambiguity".to_vec()).expect("an admissible head key")
}

fn immutable_slot() -> ImmutableKey {
    ImmutableKey::new(b"fg/body/v1/ambiguity".to_vec()).expect("an admissible immutable key")
}

/// A store with a head at `generation` carrying `body`.
fn store_with_head(generation: u64, body: &[u8]) -> MemoryAuthorityStore {
    let backing = store();
    backing
        .initialize_head(
            &head_slot(),
            HeadGeneration::try_new(generation).expect("a positive generation"),
            body,
        )
        .expect("the head initializes");
    backing
}

/// A stable label for a CAS resolution, so the surfaces compare by shape.
const fn cas_label(r: &CasResolution) -> &'static str {
    match r {
        CasResolution::Applied(_) => "applied",
        CasResolution::NotApplied(_) => "not-applied",
        CasResolution::Superseded(_) => "superseded",
        CasResolution::HeadAbsent => "head-absent",
    }
}

const fn put_label(r: &PutResolution) -> &'static str {
    match r {
        PutResolution::PresentIdentical => "present-identical",
        PutResolution::PresentConflicting(_) => "present-conflicting",
        PutResolution::Absent => "absent",
    }
}

/// One ambiguous-put case: a label, the slot's seed (if any), the proposal, and
/// the resolution it must reach.
type PutCase = (
    &'static str,
    Option<&'static [u8]>,
    &'static [u8],
    &'static str,
);

/// One ambiguous-CAS case: a label, the head to seed (if any), and the proposal.
type CasCase = (
    &'static str,
    Option<(u64, &'static [u8])>,
    u64,
    &'static [u8],
);

/// The four CAS cases: absent head, exact match, head behind, head ahead.
fn cas_corpus() -> Vec<CasCase> {
    vec![
        ("no head at all", None, 4, b"proposed"),
        ("exact match", Some((4, b"proposed")), 4, b"proposed"),
        (
            "head behind the proposal",
            Some((3, b"older")),
            4,
            b"proposed",
        ),
        (
            "head past the proposal",
            Some((7, b"newer")),
            4,
            b"proposed",
        ),
    ]
}

#[test]
fn the_cas_corpus_reaches_every_resolution() {
    // Non-vacuity: without four distinct answers, agreement below is satisfied
    // by two surfaces that always say the same thing.
    let labels: Vec<&str> = cas_corpus()
        .into_iter()
        .map(|(_, seeded, generation, body)| {
            let backing = seeded.map_or_else(store, |(g, b)| store_with_head(g, b));
            let resolved = resolve_ambiguous_cas(
                &backing,
                &head_slot(),
                HeadGeneration::try_new(generation).expect("positive"),
                body,
            )
            .expect("the resolution completes");
            cas_label(&resolved)
        })
        .collect();
    assert_eq!(
        labels,
        vec!["head-absent", "applied", "not-applied", "superseded"],
        "the corpus must reach all four CAS resolutions, or agreement on it proves nothing"
    );
}

#[test]
fn both_surfaces_resolve_an_ambiguous_cas_identically() {
    for (case, seeded, generation, body) in cas_corpus() {
        let sync_backing = seeded.map_or_else(store, |(g, b)| store_with_head(g, b));
        let sync = resolve_ambiguous_cas(
            &sync_backing,
            &head_slot(),
            HeadGeneration::try_new(generation).expect("positive"),
            body,
        )
        .expect("the sync resolution completes");

        let view = AsyncView(seeded.map_or_else(store, |(g, b)| store_with_head(g, b)));
        let asynchronous = poll_ready(resolve_ambiguous_cas_async(
            &view,
            &(),
            &head_slot(),
            HeadGeneration::try_new(generation).expect("positive"),
            body,
        ))
        .expect("the async resolution completes");

        assert_eq!(
            cas_label(&sync),
            cas_label(&asynchronous),
            "{case}: the surfaces disagree about whether an ambiguous CAS applied. §5.2 admits one \
             resolution protocol, not one per runtime"
        );
    }
}

#[test]
fn a_head_past_the_proposal_is_superseded_and_not_guessed_on_either_surface() {
    // The case that matters most, called out separately because it is the one a
    // reimplementation gets wrong: storage CANNOT say whether the attempt
    // linearized and was then superseded, or never linearized. Reporting
    // NotApplied here would assert non-commit — exactly what §5.2 forbids.
    let seeded = || store_with_head(7, b"newer");
    let proposed = HeadGeneration::try_new(4).expect("positive");

    let sync = resolve_ambiguous_cas(&seeded(), &head_slot(), proposed, b"proposed")
        .expect("sync resolution");
    let view = AsyncView(seeded());
    let asynchronous = poll_ready(resolve_ambiguous_cas_async(
        &view,
        &(),
        &head_slot(),
        proposed,
        b"proposed",
    ))
    .expect("async resolution");

    assert!(
        matches!(sync, CasResolution::Superseded(_)),
        "a head past the proposal must be Superseded, never NotApplied: storage cannot prove \
         non-commit and §5.2 sends this to the outcome index"
    );
    assert_eq!(
        cas_label(&sync),
        cas_label(&asynchronous),
        "and the production surface must not guess where the verification surface refuses to"
    );
}

#[test]
fn both_surfaces_resolve_an_ambiguous_put_identically() {
    let cases: Vec<PutCase> = vec![
        ("empty slot", None, b"proposed", "absent"),
        (
            "same bytes",
            Some(b"proposed"),
            b"proposed",
            "present-identical",
        ),
        (
            "other bytes",
            Some(b"somebody else"),
            b"proposed",
            "present-conflicting",
        ),
    ];
    let mut seen = Vec::new();
    for (case, seeded, proposed, expected) in cases {
        let build = || {
            let backing = store();
            if let Some(bytes) = seeded {
                backing
                    .put_if_absent(&immutable_slot(), bytes)
                    .expect("the seed write lands");
            }
            backing
        };
        let sync =
            resolve_ambiguous_put(&build(), &immutable_slot(), proposed).expect("sync resolution");
        let view = AsyncView(build());
        let asynchronous = poll_ready(resolve_ambiguous_put_async(
            &view,
            &(),
            &immutable_slot(),
            proposed,
        ))
        .expect("async resolution");

        assert_eq!(
            put_label(&sync),
            expected,
            "{case}: unexpected sync resolution"
        );
        assert_eq!(
            put_label(&sync),
            put_label(&asynchronous),
            "{case}: the surfaces disagree about whether an ambiguous put applied"
        );
        seen.push(put_label(&sync));
    }
    assert_eq!(
        seen,
        vec!["absent", "present-identical", "present-conflicting"],
        "the put corpus must reach all three resolutions, or the agreement above is vacuous"
    );
}

#[test]
fn a_conflicting_put_hands_back_the_bytes_that_are_actually_there() {
    // Shape agreement is not enough: PresentConflicting carries the observed
    // body, and a caller diagnosing an ambiguous write needs the real bytes
    // rather than an empty vector that happens to match on shape.
    let build = || {
        let backing = store();
        backing
            .put_if_absent(&immutable_slot(), b"somebody else")
            .expect("the seed write lands");
        backing
    };
    let view = AsyncView(build());
    let asynchronous = poll_ready(resolve_ambiguous_put_async(
        &view,
        &(),
        &immutable_slot(),
        b"proposed",
    ))
    .expect("async resolution");

    let PutResolution::PresentConflicting(found) = asynchronous else {
        panic!("a different body must resolve as PresentConflicting; got {asynchronous:?}");
    };
    assert_eq!(
        found, b"somebody else",
        "the resolution must carry the bytes the slot actually holds"
    );
}

// ---------------------------------------------------------------------------
// The head-selected root layout, on the production surface (frankengit-m01t)
// ---------------------------------------------------------------------------
//
// `ls44` published the carrier — a head selects its root layout through the
// existing `configuration_root` — over `AuthorityStore` only. Every other
// AuthorityStore function in that module has an async twin, and
// `FsqliteAuthorityStore` implements `AsyncAuthorityStore` only, so without
// these a production node could not resolve its own layout and a verified read
// could not learn whether a membership proof is admissible at all.
//
// These cases live here rather than beside the sync ones because this is where
// the crate's only `AsyncAuthorityStore` fixture is. A second delegating view
// would be free to drift from the first, which is the defect class the shared
// decision core exists to prevent.

const fn configuration(layout: RootLayoutVersion) -> RepositoryConfigurationBody {
    // Every field is named rather than defaulted. These cases assert equality of
    // canonical digests, and a digest test that lets a field arrive implicitly
    // silently changes what is being hashed the next time the body grows one.
    // Naming them makes that a compile error instead, which is the failure mode
    // a canonical-bytes test wants.
    RepositoryConfigurationBody {
        root_layout: layout,
        object_format: GitHashAlgorithm::Sha1,
    }
}

#[test]
fn both_surfaces_stage_a_configuration_to_the_same_root() {
    // If the two staged to different digests, a head published by one surface
    // would name a configuration the other could not find — and would then be
    // read as legacy v0, silently losing the layout it meant to select.
    for layout in RootLayoutVersion::ALL {
        let sync_store = store();
        let sync_root = stage_repository_configuration(&sync_store, &configuration(*layout))
            .expect("the sync surface stages");

        let view = AsyncView(store());
        let async_root = poll_ready(stage_repository_configuration_async(
            &view,
            &(),
            &configuration(*layout),
        ))
        .expect("the async surface stages");

        assert_eq!(
            sync_root, async_root,
            "{layout:?}: the surfaces must agree on the root a head selects the configuration by"
        );
    }
}

#[test]
fn both_surfaces_resolve_the_layout_a_head_selects() {
    for layout in RootLayoutVersion::ALL {
        let sync_store = store();
        let root =
            stage_repository_configuration(&sync_store, &configuration(*layout)).expect("stages");
        let sync = root_layout_for_verification(&sync_store, &root).expect("resolves");

        let backing = store();
        let async_root =
            stage_repository_configuration(&backing, &configuration(*layout)).expect("stages");
        let view = AsyncView(backing);
        let asynchronous = poll_ready(root_layout_for_verification_async(&view, &(), &async_root))
            .expect("resolves");

        assert_eq!(sync, asynchronous, "{layout:?}: the surfaces disagree");
        assert_eq!(
            sync, *layout,
            "and the answer must be the layout that was staged"
        );
    }
}

#[test]
fn the_asymmetry_holds_on_the_production_surface_too() {
    // The rule that matters most: an unresolvable configuration_root is v0 for
    // VERIFICATION and a typed refusal for PROOF GENERATION. A production node
    // that silently assumed v0 on the proof path would emit a path through a
    // tree that does not exist, and the caller would verify it vacuously.
    let view = AsyncView(store());
    let unresolvable = Digest::new(
        fgit_crypto::IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[0xEE; 32]).expect("a bounded digest"),
    );

    assert_eq!(
        poll_ready(root_layout_for_verification_async(
            &view,
            &(),
            &unresolvable
        ))
        .expect("verification resolves"),
        RootLayoutVersion::LegacyWholeBody,
        "an older head must still verify on the production surface, not be refused"
    );

    assert!(
        matches!(
            poll_ready(root_layout_for_proof_async(&view, &(), &unresolvable)),
            Err(OutcomeFailure::ConfigurationUnresolvable)
        ),
        "proof generation must refuse on the production surface exactly as it does on the \
         verification surface"
    );

    // The permitted twin: once the configuration IS resolvable, the proof path
    // stops refusing. Without this the assertion above is satisfied by an async
    // resolver that refuses every configuration.
    let backing = store();
    let root = stage_repository_configuration(
        &backing,
        &configuration(RootLayoutVersion::RefStateMerkleV1),
    )
    .expect("stages");
    let resolvable = AsyncView(backing);
    assert_eq!(
        poll_ready(root_layout_for_proof_async(&resolvable, &(), &root)).expect("resolves"),
        RootLayoutVersion::RefStateMerkleV1
    );
}

#[test]
fn both_surfaces_emit_the_same_absence_proof_and_refuse_together() {
    // frankengit-56i4. A serving node runs on `AsyncAuthorityStore`, so an
    // absence proof that only the synchronous surface could emit would be a
    // proof no production reader could obtain.
    let entries = vec![
        (
            fgit_types::refs::RefName::try_new(b"refs/heads/main").expect("a name"),
            GitOid::Sha1(GitOidSha1::from_bytes([0x11; GitOidSha1::LEN])),
        ),
        (
            fgit_types::refs::RefName::try_new(b"refs/tags/v1").expect("a name"),
            GitOid::Sha1(GitOidSha1::from_bytes([0x33; GitOidSha1::LEN])),
        ),
    ];
    let absent = fgit_types::refs::RefName::try_new(b"refs/heads/other").expect("a name");

    for layout in RootLayoutVersion::ALL {
        let sync_store = store();
        let root =
            stage_repository_configuration(&sync_store, &configuration(*layout)).expect("stages");
        let sync = head_selected_ref_state_absence_proof(&sync_store, &root, &entries, &absent);

        let backing = store();
        let async_root =
            stage_repository_configuration(&backing, &configuration(*layout)).expect("stages");
        let view = AsyncView(backing);
        let asynchronous = poll_ready(head_selected_ref_state_absence_proof_async(
            &view,
            &(),
            &async_root,
            &entries,
            &absent,
        ));

        match (sync, asynchronous) {
            (Ok(left), Ok(right)) => assert_eq!(
                left, right,
                "{layout:?}: the surfaces must emit the same proof, not merely both succeed"
            ),
            (Err(left), Err(right)) => assert_eq!(
                format!("{left:?}"),
                format!("{right:?}"),
                "{layout:?}: the surfaces must refuse for the same reason"
            ),
            (left, right) => panic!(
                "{layout:?}: the surfaces disagreed about whether a proof exists: \
                 sync={left:?} async={right:?}"
            ),
        }
    }
}
