#![forbid(unsafe_code)]
//! The async admission surface, held against the blocking one it must agree
//! with (`frankengit-z21g`).
//!
//! `FsqliteAuthorityStore` implements [`AsyncAuthorityStore`] only, so a node
//! that must admit a receive session against it had no route to
//! `fgit-admission`'s protocol. The alternative was a node-local copy of the
//! CAS replan loop, and §5.2's rules — *one sealed transaction has at most one
//! terminal decision*, *CAS losers reuse and revalidate without changing the
//! sealed request* — are not properties that survive being reimplemented per
//! caller.
//!
//! # What these tests are for
//!
//! Not "the async functions work". That bar is met by a second implementation
//! which passes its own tests while quietly disagreeing with the first, and
//! disagreement is the defect this suite exists to catch. **Every case below
//! runs both surfaces over identically-constructed stores and requires the same
//! answer**, which is the only way to show they agree rather than that each
//! works alone.
//!
//! The corpus is chosen so that agreement is not vacuous. Its three cases
//! produce three *distinct* answers — a commit, a refusal on a stale expected
//! predecessor, and a refusal on unresolvable evidence — and
//! [`the_corpus_produces_distinct_answers`] fails if they ever collapse. A pair
//! of surfaces that returned one constant would pass a naive agreement test and
//! fail that one.
//!
//! # Why agreement is structural here, and what still needs measuring
//!
//! The two surfaces are not independent implementations: both delegate every
//! decision to one shared core in `fgit-admission` — `plan_session`,
//! `plan_publication`, `prepare_commit_publication`, `prepare_refusal_record`,
//! `seal_refusal_publication`, `assemble_result` — and differ only in how they
//! wait for the store. So agreement is *entailed* by the structure.
//!
//! That entailment is exactly why these tests are still needed rather than
//! redundant: an entailment argument shows the property holds today, never that
//! a test would notice it breaking. The discriminating experiment is stated on
//! `frankengit-z21g`: mutate one branch of `plan_publication` and **both**
//! [`the_two_surfaces_agree_on_every_case`] and the blocking corpus must fail.
//! A mutation that breaks only one surface would prove the core is not actually
//! shared. That experiment belongs to the central batch verify; nothing in this
//! file claims it has been observed.
//!
//! # Fixtures
//!
//! The fixtures here are close cousins of the ones in
//! `receive_disconnect_and_race.rs`, deliberately rebuilt rather than shared:
//! that file is scoped as an independent adversary over a crate it does not
//! own, and this one verifies a change its author made. Keeping them apart
//! keeps that stance honest. What must not be duplicated is the protocol, and
//! it is not — both surfaces call one core.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use std::sync::{Arc, Mutex};

use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionEvidence, AdmissionLimits, AdmissionProjection,
    AdmissionResult, AdmissionSnapshot, AdmissionSnapshotProjection, AsyncAdmissionProjection,
    AsyncProjectionFailure, CanonicalAdmissionProjection, CanonicalAdmissionStore,
    CanonicalRefState, CommitEvidence, CommitMaterialization, PermittedObjectClosure,
    QuarantineValidator, RefusalMaterialization, ValidatedClosure, ValidatedReceive,
    admit_validated_receive, admit_validated_receive_async, canonical_ref_state_root,
    permitted_object_closure_root, validate_receive,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, IdempotencyKey, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    OutcomeLookup, PutOutcome, StoreInstanceId, initialize_repository, resolve_outcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_reference::intent::TransactionRequest;
use fgit_types::native::GitHashAlgorithm;
use fgit_types::{
    DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes, GitOid, HeadGeneration, PolicyEpoch,
    PrincipalId, PrincipalSnapshotId, RefName, RefusalCode, RegistryEpoch, RepositoryId, TenantId,
    TxId,
};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveEvent, ReceiveLimits, ReceivePack, ReceiveRequest,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const MAIN_OID: &str = "2222222222222222222222222222222222222222";
/// A predecessor the session does **not** name, used to force a stale
/// expected-old refusal.
const OTHER_OID: &str = "3333333333333333333333333333333333333333";
const MAIN_REF: &[u8] = b"refs/heads/main";

/// A corpus-reserved digest algorithm slot, as every fixture in this workspace
/// uses. Never a real algorithm identifier.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

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

    /// Forwarded, and load-bearing.
    ///
    /// This is the trait's **only** defaulted method: a backend that has not
    /// implemented atomic publication inherits a typed
    /// `OperationUnsupported` refusal rather than a compile error, so that a
    /// store which cannot publish says so honestly instead of silently
    /// providing a non-atomic imitation.
    ///
    /// A test view must therefore forward it explicitly. Leaving it on the
    /// default made this fixture refuse every commit while the blocking
    /// surface committed — which read as the two surfaces disagreeing about
    /// the shared core when in fact the fixture never reached it.
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
///
/// The view above resolves every operation before handing back a future, so a
/// `Pending` here means the surface acquired a suspension point this suite
/// cannot model — which is a finding, not something to wait out.
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

fn digest(seed: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[seed; 32]).expect("32-byte corpus fixture body"),
    )
}

fn principal_snapshot() -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        fgit_types::CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[15; 32]).expect("32-byte corpus fixture body"),
    )
}

fn oid(hex: &str) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha1, hex).expect("fixture oid")
}

fn context(session: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"fg/head/z21g-async-equivalence".to_vec()).expect("valid head key"),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(session.to_vec()).expect("bounded key"),
        object_format: GitObjectFormat::Sha1,
    }
}

fn genesis(context: &AdmissionContext) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: context.repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(1),
        forge_position_root: digest(16),
        outcome_index_root: digest(17),
        retention_root: digest(18),
        outbox_root: digest(19),
        configuration_root: digest(20),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

/// A validator that reports the closure it was told to.
///
/// Every session here is delete-only, so the closure is legitimately empty. The
/// root must be the *canonical* root of that empty set: `materialize_commit`
/// recomputes it and refuses `ObjectClosureIncomplete` when the two disagree.
struct DeleteOnlyValidator;

impl QuarantineValidator for DeleteOnlyValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
    ) -> Result<ValidatedClosure, RefusalCode> {
        let objects = BTreeSet::new();
        let object_closure_root =
            permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone()))?;
        Ok(ValidatedClosure {
            object_closure_root,
            objects,
        })
    }
}

fn wire_context() -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"delete-refs report-status atomic", &WireLimits::default())
            .expect("fixture capabilities"),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("fixture receive context")
}

/// A delete of `refs/heads/main` naming `MAIN_OID` as its expected predecessor,
/// parsed by the real wire state machine.
fn delete_main() -> ValidatedReceive {
    let mut line = format!("{MAIN_OID} {ZERO} {}", String::from_utf8_lossy(MAIN_REF)).into_bytes();
    line.push(0);
    line.extend_from_slice(b"report-status delete-refs atomic");

    let mut machine = ReceivePack::new(wire_context()).expect("machine");
    machine
        .push_packet(Packet::Data(line))
        .expect("delete command must parse");
    let transition = machine.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("the command flush must expose a parsed request");
    };
    let request = (**request).clone();

    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    validate_receive(&request, None, &receipt, &DeleteOnlyValidator)
        .expect("a delete-only receive is admissible without a pack")
}

/// Interior mutability behind a mutex rather than a `RefCell`: the async
/// surface requires `Projection: Sync` so its futures are `Send` and can be
/// spawned on a multi-threaded runtime, and a `RefCell` fixture would not be a
/// legal projection for it.
struct CommitmentStore {
    refs: Mutex<BTreeMap<Digest, CanonicalRefState>>,
    closures: Mutex<BTreeMap<Digest, PermittedObjectClosure>>,
}

#[derive(Clone, Default)]
struct StagingStore(Arc<CommitmentStore>);

impl Default for CommitmentStore {
    fn default() -> Self {
        Self {
            refs: Mutex::new(BTreeMap::new()),
            closures: Mutex::new(BTreeMap::new()),
        }
    }
}

impl CanonicalAdmissionStore for StagingStore {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.0
            .refs
            .lock()
            .expect("fixture staging mutex")
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        self.0
            .refs
            .lock()
            .expect("fixture staging mutex")
            .insert(root, state);
        Ok(())
    }

    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        self.0
            .closures
            .lock()
            .expect("fixture staging mutex")
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        self.0
            .closures
            .lock()
            .expect("fixture staging mutex")
            .insert(root, closure);
        Ok(())
    }
}

struct StubEvidence;

impl AdmissionEvidence for StubEvidence {
    fn commit_evidence(
        &self,
        _basis: &PublicationBasis,
        _request: &TransactionRequest,
        _fold: &fgit_txn::TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode> {
        Ok(CommitEvidence {
            principal_snapshot_id: principal_snapshot(),
            forge_event_batch_root: digest(8),
            policy_decision_root: digest(9),
            invariant_evidence_root: digest(10),
            outbox_effect_root: digest(11),
            retention_delta_root: digest(12),
        })
    }

    fn refusal_evidence(
        &self,
        basis: &PublicationBasis,
        _tx_id: TxId,
        _code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: "z21g async equivalence corpus".to_owned(),
            evidence_root: digest(13),
        })
    }
}

/// Projection fixture with no synchronous materialization capability.
///
/// Its async capability delegates to the otherwise identical canonical
/// projection.  The type deliberately cannot satisfy [`AdmissionProjection`],
/// so the blocking entrypoint rejects this projection at compile time rather
/// than publishing a terminal refusal for a caller's entrypoint mistake.
struct AsyncMaterializingProjection {
    inner: CanonicalAdmissionProjection<StagingStore, StubEvidence>,
}

impl AdmissionSnapshotProjection for AsyncMaterializingProjection {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<fgit_admission::AdmissionSnapshot, RefusalCode> {
        self.inner.snapshot(basis, authenticated)
    }
}

impl AsyncAdmissionProjection<AsyncView> for AsyncMaterializingProjection {
    fn snapshot_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a <AsyncView as AsyncAuthorityStore>::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, AsyncProjectionFailure>> + Send + 'a {
        std::future::ready(
            self.inner
                .snapshot(basis, authenticated)
                .map_err(AsyncProjectionFailure::Refuse),
        )
    }

    fn materialize_commit_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a <AsyncView as AsyncAuthorityStore>::Context,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, AsyncProjectionFailure>> + Send + 'a
    {
        std::future::ready(self.inner.materialize_commit(basis, request, fold, closure))
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a <AsyncView as AsyncAuthorityStore>::Context,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, AsyncProjectionFailure>> + Send + 'a
    {
        std::future::ready(
            self.inner
                .materialize_refusal(basis, tx_id, code)
                .map_err(AsyncProjectionFailure::Refuse),
        )
    }
}

/// Projection that reaches the post-fold durable boundary but cannot obtain
/// the required material. The driver must return this as an undecided error;
/// publishing it as a refusal would permanently decide a retryable request.
struct UnavailableCommitProjection {
    inner: CanonicalAdmissionProjection<StagingStore, StubEvidence>,
}

impl AsyncAdmissionProjection<AsyncView> for UnavailableCommitProjection {
    fn snapshot_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a <AsyncView as AsyncAuthorityStore>::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, AsyncProjectionFailure>> + Send + 'a {
        std::future::ready(
            self.inner
                .snapshot(basis, authenticated)
                .map_err(AsyncProjectionFailure::Refuse),
        )
    }

    fn materialize_commit_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a <AsyncView as AsyncAuthorityStore>::Context,
        _basis: &'a PublicationBasis,
        _request: &'a TransactionRequest,
        _fold: &'a fgit_txn::TransactionFoldReport,
        _closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, AsyncProjectionFailure>> + Send + 'a
    {
        std::future::ready(Err(AsyncProjectionFailure::Unavailable(
            RefusalCode::EvidenceMissing,
        )))
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        _authority: &'a AsyncView,
        _cx: &'a <AsyncView as AsyncAuthorityStore>::Context,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, AsyncProjectionFailure>> + Send + 'a
    {
        std::future::ready(
            self.inner
                .materialize_refusal(basis, tx_id, code)
                .map_err(AsyncProjectionFailure::Refuse),
        )
    }
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// What the repository's genesis basis holds, which is what separates the three
/// answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Basis {
    /// `refs/heads/main` stands at exactly the predecessor the session names.
    /// The delete applies.
    NamedPredecessor,
    /// `refs/heads/main` stands at a different commit than the session names,
    /// so the expected-old check refuses.
    OtherPredecessor,
    /// The head's `ref_root` resolves to nothing the projection can read, so
    /// the snapshot refuses before any fold happens.
    UnresolvableRefRoot,
}

const CORPUS: [Basis; 3] = [
    Basis::NamedPredecessor,
    Basis::OtherPredecessor,
    Basis::UnresolvableRefRoot,
];

/// Build an authority store and the production projection rooted in it.
///
/// Two calls with the same arguments produce two independent stores holding
/// identical state, which is what lets one surface run against each.
fn setup(
    context: &AdmissionContext,
    basis: Basis,
) -> (
    MemoryAuthorityStore,
    CanonicalAdmissionProjection<StagingStore, StubEvidence>,
) {
    let staging = StagingStore::default();
    let body = match basis {
        Basis::UnresolvableRefRoot => genesis(context),
        Basis::NamedPredecessor | Basis::OtherPredecessor => {
            let standing = if basis == Basis::NamedPredecessor {
                oid(MAIN_OID)
            } else {
                oid(OTHER_OID)
            };
            let mut refs = BTreeMap::new();
            refs.insert(
                RefName::try_new(MAIN_REF).expect("fixture ref name"),
                standing,
            );
            let state = CanonicalRefState::new(refs);
            let ref_root =
                canonical_ref_state_root(&state).expect("genesis ref state has a canonical root");
            staging
                .stage_ref_state(ref_root, state)
                .expect("genesis ref state stages");
            RepositoryAuthorityHeadBody {
                ref_root,
                ..genesis(context)
            }
        }
    };

    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(41));
    initialize_repository(&store, &context.head_key, &body).expect("genesis head initializes");
    (
        store,
        CanonicalAdmissionProjection::new(staging, StubEvidence),
    )
}

/// Reduce an admission to a comparable answer.
///
/// Deliberately coarse enough to compare across surfaces and specific enough
/// that the three corpus cases cannot collapse into one another: the refusal
/// code is part of the answer, not just the fact of refusing.
fn label(result: &Result<AdmissionResult, AdmissionError>) -> String {
    match result {
        Ok(admission) => admission.commands.first().map_or_else(
            || "ok:no-commands".to_owned(),
            |command| match command.terminal.outcome {
                DecisionOutcome::Committed { .. } => "committed".to_owned(),
                DecisionOutcome::Refused { code, .. } => format!("refused:{code:?}"),
            },
        ),
        Err(error) => format!("error:{error:?}"),
    }
}

/// Run the blocking surface over a freshly built store.
fn blocking_answer(session: &[u8], basis: Basis) -> String {
    let context = context(session);
    let validated = delete_main();
    let (store, projection) = setup(&context, basis);
    label(&admit_validated_receive(
        &store,
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    ))
}

/// Run the asynchronous surface over an identically built store.
fn asynchronous_answer(session: &[u8], basis: Basis) -> String {
    let context = context(session);
    let validated = delete_main();
    let (store, projection) = setup(&context, basis);
    let view = AsyncView(store);
    label(&poll_ready(admit_validated_receive_async(
        &view,
        &(),
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    )))
}

// ---------------------------------------------------------------------------
// Equivalence
// ---------------------------------------------------------------------------

/// Both surfaces reach the same answer on every case in the corpus.
///
/// This is the claim the port exists to support: `fgit-node` may drive the
/// asynchronous surface and receive what the blocking one would have decided.
#[test]
fn the_two_surfaces_agree_on_every_case() {
    for basis in CORPUS {
        let session = format!("z21g-agree-{basis:?}");
        let blocking = blocking_answer(session.as_bytes(), basis);
        let asynchronous = asynchronous_answer(session.as_bytes(), basis);
        assert_eq!(
            blocking, asynchronous,
            "the two admission surfaces disagreed about {basis:?}: the blocking one \
             answered {blocking}, the asynchronous one {asynchronous}. They delegate \
             every decision to one core, so a disagreement means the core is not \
             actually shared"
        );
    }
}

/// The async driver accepts an asynchronous-only materialization boundary for
/// both the committing and refusing branches.
///
/// The wrapper has no synchronous materialization implementation at all, so
/// the blocking entrypoint cannot publish a permanent typed refusal if a
/// caller selects it accidentally.  Its async methods delegate to the
/// canonical projection, exercising the commit and fold-refusal branches.
#[test]
fn async_driver_uses_the_async_materialization_boundary() {
    for basis in [Basis::NamedPredecessor, Basis::OtherPredecessor] {
        let session = format!("600m-async-materialization-{basis:?}");
        let expected = blocking_answer(session.as_bytes(), basis);
        let context = context(session.as_bytes());
        let validated = delete_main();
        let (store, inner) = setup(&context, basis);
        let projection = AsyncMaterializingProjection { inner };
        let view = AsyncView(store);

        let observed = label(&poll_ready(admit_validated_receive_async(
            &view,
            &(),
            &context,
            &validated,
            AdmissionLimits::default(),
            &projection,
        )));
        assert_eq!(
            observed, expected,
            "the async driver used the synchronous materialization method for {basis:?}: \
             expected {expected}, observed {observed}"
        );
    }
}

/// An unavailable durable materialization leaves the sealed request undecided.
///
/// This is the negative companion to the committing async boundary. A failure
/// after a fold but before durable successor staging is not a policy result;
/// converting it to a terminal refusal would violate the retry rule in §5.2.
#[test]
fn unavailable_async_materialization_never_publishes_a_terminal_refusal() {
    let context = context(b"600m-unavailable-durable-materialization");
    let validated = delete_main();
    let (store, inner) = setup(&context, Basis::NamedPredecessor);
    let before = store
        .read_head(&context.head_key)
        .expect("fixture authority head reads before admission");
    let projection = UnavailableCommitProjection { inner };
    let view = AsyncView(store);

    let result = poll_ready(admit_validated_receive_async(
        &view,
        &(),
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    ));
    assert!(
        matches!(
            &result,
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceMissing
            ))
        ),
        "an unavailable durable materialization must return before publication, got {result:?}"
    );
    let after = view
        .0
        .read_head(&context.head_key)
        .expect("fixture authority head reads after admission");
    assert_eq!(
        after, before,
        "the unavailable materializer advanced the authority head and therefore published a terminal decision"
    );
}

/// The corpus produces three distinct answers.
///
/// Without this, [`the_two_surfaces_agree_on_every_case`] is vacuous in the way
/// that matters: two surfaces that both returned one constant — or a fixture in
/// which every case refuses for the same reason — would agree perfectly and
/// demonstrate nothing. This is the presence case for that agreement.
#[test]
fn the_corpus_produces_distinct_answers() {
    let answers: Vec<String> = CORPUS
        .iter()
        .map(|basis| blocking_answer(format!("z21g-distinct-{basis:?}").as_bytes(), *basis))
        .collect();
    let unique: BTreeSet<&String> = answers.iter().collect();
    assert_eq!(
        unique.len(),
        CORPUS.len(),
        "the corpus collapsed to {} distinct answers ({answers:?}), so agreement \
         between the surfaces would be satisfied by a pair that always returns the \
         same thing",
        unique.len()
    );
    assert!(
        answers.contains(&"committed".to_owned()),
        "no case in the corpus commits ({answers:?}), so the agreement test could \
         not notice a surface that never commits at all"
    );
}

/// A commit reached through the asynchronous surface is authenticated in the
/// decision stream, not merely reported by the call.
///
/// §5.1 forbids inferring commitment from a response: the outcome is read back
/// through `resolve_outcome` over the same store the async surface published
/// to.
#[test]
fn an_async_commit_is_authenticated_in_the_decision_stream() {
    let context = context(b"z21g-async-commit-authenticated");
    let validated = delete_main();
    let (store, projection) = setup(&context, Basis::NamedPredecessor);
    let view = AsyncView(store);

    let result = poll_ready(admit_validated_receive_async(
        &view,
        &(),
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    ))
    .expect("an uncontended delete against a resolvable genesis basis reaches a decision");

    let tx_id = result.session.tx_ids[0];
    let resolved = resolve_outcome(
        &view.0,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .unwrap_or_else(|error| panic!("{tx_id:?} must resolve, got {error}"));

    let OutcomeLookup::Decided(terminal) = resolved else {
        panic!("an uncontended async delete left {tx_id:?} undecided: {resolved:?}");
    };
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "an uncontended async delete of a ref present in the genesis state did not \
         commit ({:?})",
        terminal.outcome
    );
}

/// Re-admitting a decided transaction through the asynchronous surface returns
/// the decision that already stands.
///
/// §5.2: one sealed transaction has at most one terminal decision. The second
/// admission re-derives the same identity from the same idempotency key, finds
/// the transaction already terminal, and must report that outcome rather than
/// publishing a second one.
#[test]
fn an_async_retry_of_a_decided_transaction_returns_the_standing_decision() {
    let context = context(b"z21g-async-idempotent-retry");
    let validated = delete_main();
    let (store, projection) = setup(&context, Basis::NamedPredecessor);
    let view = AsyncView(store);

    let first = poll_ready(admit_validated_receive_async(
        &view,
        &(),
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    ))
    .expect("the first admission decides");
    let second = poll_ready(admit_validated_receive_async(
        &view,
        &(),
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    ))
    .expect("the retry resolves rather than failing");

    assert_eq!(
        first.session.tx_ids, second.session.tx_ids,
        "the retry re-derived a different transaction identity from the same \
         idempotency key, so the seal is not stable across attempts"
    );
    assert_eq!(
        label(&Ok(first)),
        label(&Ok(second)),
        "the retry reported a different outcome than the decision that already \
         stood, which is a second terminal decision for one sealed transaction"
    );
}

/// The asynchronous surface refuses a malformed session before it contacts the
/// store at all.
///
/// Both surfaces plan a session through the same `plan_session`, so an input
/// the blocking surface rejects without touching the authority must be rejected
/// here on the same terms. The store is left with no head, so any code path
/// that reached it would fail differently and loudly.
#[test]
fn an_input_refusal_needs_no_authority_contact_on_either_surface() {
    let context = context(b"z21g-input-refusal");
    let validated = delete_main();
    let mismatched = AdmissionContext {
        object_format: GitObjectFormat::Sha256,
        ..context.clone()
    };

    let headless = MemoryAuthorityStore::new(StoreInstanceId::from_raw(42));
    let (_, projection) = setup(&context, Basis::NamedPredecessor);

    let blocking = admit_validated_receive(
        &headless,
        &mismatched,
        &validated,
        AdmissionLimits::default(),
        &projection,
    );
    let view = AsyncView(MemoryAuthorityStore::new(StoreInstanceId::from_raw(43)));
    let asynchronous = poll_ready(admit_validated_receive_async(
        &view,
        &(),
        &mismatched,
        &validated,
        AdmissionLimits::default(),
        &projection,
    ));

    assert!(
        matches!(blocking, Err(AdmissionError::ObjectFormatMismatch)),
        "the blocking surface admitted a session whose object format disagrees with \
         its receipt: {blocking:?}"
    );
    assert_eq!(
        label(&blocking),
        label(&asynchronous),
        "the two surfaces disagreed about a session that fails validation before \
         any store contact"
    );
}

/// The admission crate reaches the store by awaiting it, never by blocking on
/// it.
///
/// §3.2 makes Asupersync the sole runtime and forbids a production path that
/// parks a runtime thread to wait for I/O. The asynchronous surface exists
/// precisely so `fgit-node` need not wrap the blocking one in such a call, so
/// the absence is the point of the bead rather than incidental hygiene.
///
/// Reading the source is a blunt instrument, and deliberately so: it also
/// catches a `block_on` reintroduced inside a helper this suite never drives.
#[test]
fn the_admission_surface_never_blocks_on_a_future() {
    let source = include_str!("../src/lib.rs");
    let offenders: Vec<usize> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("block_on"))
        .map(|(index, _)| index + 1)
        .collect();
    assert!(
        offenders.is_empty(),
        "crates/fgit-admission/src/lib.rs blocks on a future at lines {offenders:?}; \
         the asynchronous surface exists so callers never need to"
    );

    // The presence case for the check above: a scan that cannot find the token
    // it is looking for would report an empty list forever.
    let planted = "let value = runtime.block_on(future);";
    assert!(
        planted.contains("block_on"),
        "the scan cannot detect a blocking call at all, so its clean result on the \
         real source proves nothing"
    );
}
