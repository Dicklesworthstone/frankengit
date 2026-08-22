#![forbid(unsafe_code)]
//! FG-008 acceptance line 3, at the layer that can actually answer it:
//! *"policy evaluates one pinned snapshot plus the exact candidate effect root,
//! no TOCTOU."*
//!
//! Independent adversary over `fgit-admission`, which this file does not own.
//! Nothing here modifies `crates/fgit-admission/src/**`; every probe drives the
//! public API.
//!
//! ## Why this line had no test, and what had to change to give it one
//!
//! The behaviour lives in `admit_one`: it reads a basis **once**, snapshots the
//! projection against *that* authenticated head, folds the request against
//! *that* snapshot, and then publishes carrying `receipt.token()` — the token
//! from the same read. A writer who moves the head in between loses the
//! compare-exchange and the attempt replans against the new basis.
//!
//! The existing corpus could not test this, and the reason is instructive. The
//! adapters in `receive_disconnect_and_race.rs` **ignore the basis they are
//! handed** — that file says so itself, and it is right to. A projection whose
//! snapshot does not depend on the head cannot demonstrate that the snapshot is
//! pinned *to* the head: every basis produces the same answer, so a race is
//! invisible by construction. The property is untestable through a
//! basis-ignoring adapter no matter how the race is injected.
//!
//! So the production [`CanonicalAdmissionProjection`] is **basis-derived**:
//! its ref table is resolved from `basis.body().ref_root`. Two different heads
//! therefore produce two different snapshots, which is exactly the sensitivity
//! a TOCTOU probe needs. [`PinnedProjection`] below is only the race injector
//! around that production implementation.
//!
//! ## The race is real, not simulated
//!
//! `FaultKind` has no "concurrent modification" variant, so the fault plan
//! cannot express this. The injection here is a genuine competing writer:
//! [`PinnedProjection::race_the_head`] calls the public `publish_decisions`
//! immediately after the production `snapshot()` returns — precisely the
//! window between the basis read and the publication. Nothing is stubbed; the
//! head really does advance underneath an in-flight admission.
//!
//! ## Every claim here carries a presence case
//!
//! A race test passes vacuously if the race never fires, and that failure is
//! silent — the assertions still hold, they just hold about nothing. Three
//! guards prevent it, and each fails loudly rather than passing quietly:
//!
//! 1. `the_injected_race_actually_lands` asserts the competing write really did
//!    advance the head generation, so the "refused" result cannot be credited
//!    to an injection that no-opped.
//! 2. Every racing drill asserts the projection was snapshotted **more than
//!    once**, which is the observable signature of a replan. One snapshot means
//!    no CAS was lost, and therefore nothing was proven.
//! 3. `a_permitted_twin_proceeds_without_the_race` is the paired positive: the
//!    identical request, identical projection, no race, commits on the first
//!    pass. Without it, "refused" would be indistinguishable from a fixture
//!    that refuses everything.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use fgit_admission::{
    AdmissionContext, AdmissionEvidence, AdmissionLimits, AdmissionProjection, AdmissionSnapshot,
    CanonicalAdmissionProjection, CanonicalAdmissionStore, CanonicalRefState, CommitEvidence,
    CommitMaterialization, PermittedObjectClosure, QuarantineValidator, RefusalMaterialization,
    ValidatedClosure, ValidatedReceive, admit_validated_receive, canonical_ref_state_root,
    initialize_canonical_repository, permitted_object_closure_root, validate_receive,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, HeadKey, HeadRead, IdempotencyKey, MemoryAuthorityStore,
    OutcomeLookup, StoreInstanceId, publish_decisions, resolve_outcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody, decode_body, encode_body,
};
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fgit_types::native::GitHashAlgorithm;
use fgit_types::{
    DecisionOutcome, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes, GitOid,
    HeadGeneration, PolicyEpoch, PrincipalId, PrincipalSnapshotId, RefName, RefusalCode,
    RegistryEpoch, RepositoryId, TenantId, TxId,
};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveEvent, ReceiveLimits, ReceivePack, ReceiveRequest,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const MAIN_OID: &str = "2222222222222222222222222222222222222222";
const MAIN_REF: &[u8] = b"refs/heads/main";

type RefMap = BTreeMap<RefName, GitOid>;

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

fn context() -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"fg/head/fg008-toctou".to_vec()).expect("valid head key"),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"fg008-toctou-session".to_vec())
            .expect("bounded key"),
        object_format: GitObjectFormat::Sha1,
    }
}

fn genesis(context: &AdmissionContext, ref_root: Digest) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: context.repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root,
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

struct DeleteOnlyValidator;

impl QuarantineValidator for DeleteOnlyValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
    ) -> Result<ValidatedClosure, RefusalCode> {
        let closure = PermittedObjectClosure::default();
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&closure)
                .expect("empty closure has a registered canonical root"),
            objects: BTreeSet::new(),
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

/// A delete of `refs/heads/main`, parsed by the real wire state machine.
///
/// Delete-only is the documented path that needs no pack, which keeps a
/// fabricated pack out of a corpus about authority sequencing.
fn delete_main_request() -> ReceiveRequest {
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
    (**request).clone()
}

fn delete_main() -> ValidatedReceive {
    let request = delete_main_request();
    let receipt = QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    validate_receive(&request, None, &receipt, &DeleteOnlyValidator)
        .expect("a delete-only receive is admissible without a pack")
}

// ---------------------------------------------------------------------------
// The basis-derived projection
// ---------------------------------------------------------------------------

/// A tiny immutable commitment store used only to drive the production
/// projection through its public storage contract.
#[derive(Default)]
struct TestCommitmentStore {
    refs: RefCell<BTreeMap<Digest, CanonicalRefState>>,
    closures: RefCell<BTreeMap<Digest, PermittedObjectClosure>>,
}

#[derive(Clone, Default)]
struct TestStore(Rc<TestCommitmentStore>);

impl CanonicalAdmissionStore for TestStore {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.0
            .refs
            .borrow()
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        self.0.refs.borrow_mut().insert(root, state);
        Ok(())
    }

    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        self.0
            .closures
            .borrow()
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        self.0.closures.borrow_mut().insert(root, closure);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TestEvidence;

impl AdmissionEvidence for TestEvidence {
    fn commit_evidence(
        &self,
        _basis: &PublicationBasis,
        _request: &TransactionRequest,
        _fold: &fgit_txn::TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode> {
        Ok(CommitEvidence {
            principal_snapshot_id: principal_snapshot(),
            forge_event_batch_root: digest(8),
            outcome_index_root: digest(4),
            policy_decision_root: digest(9),
            invariant_evidence_root: digest(10),
            outbox_effect_root: digest(11),
            retention_delta_root: digest(12),
            batch_evidence_root: digest(6),
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
            detail: "fg008 toctou probe refusal".to_owned(),
            evidence_root: digest(13),
        })
    }
}

type ProductionProjection = CanonicalAdmissionProjection<TestStore, TestEvidence>;

/// A race injector around the production projection.
///
/// The wrapper has no ref-state behavior of its own: it delegates every
/// projection decision and materialization to [`CanonicalAdmissionProjection`]
/// and only moves the authority head after the production snapshot has been
/// opened.  This keeps the race real without turning test scaffolding into a
/// second projection implementation.
struct PinnedProjection {
    production: ProductionProjection,
    commitments: TestStore,
    store: Rc<MemoryAuthorityStore>,
    head_key: HeadKey,
    repository_id: RepositoryId,
    tenant_id: TenantId,
    genesis_ref_root: Digest,
    rival_ref_root: Digest,

    /// Whether to run a competing writer inside the first `snapshot`.
    race: bool,
    /// Every `ref_root` this projection was asked to snapshot, in order.
    observed: RefCell<Vec<Digest>>,
    /// Set once the competing write has been attempted.
    raced: Cell<bool>,
    /// Set only if the competing write actually moved the head.
    race_landed: Cell<bool>,
    /// Head generation before and after the competing write.
    generation_before: Cell<u64>,
    generation_after: Cell<u64>,
}

impl PinnedProjection {
    fn new(
        production: ProductionProjection,
        commitments: TestStore,
        store: Rc<MemoryAuthorityStore>,
        context: &AdmissionContext,
        genesis_ref_root: Digest,
        rival_ref_root: Digest,
        race: bool,
    ) -> Self {
        Self {
            production,
            commitments,
            store,
            head_key: context.head_key.clone(),
            repository_id: context.repository_id,
            tenant_id: context.tenant_id,
            genesis_ref_root,
            rival_ref_root,
            race,
            observed: RefCell::new(Vec::new()),
            raced: Cell::new(false),
            race_landed: Cell::new(false),
            generation_before: Cell::new(0),
            generation_after: Cell::new(0),
        }
    }

    fn snapshot_count(&self) -> usize {
        self.observed.borrow().len()
    }

    fn observed_roots(&self) -> Vec<Digest> {
        self.observed.borrow().clone()
    }

    /// The competing writer: advance the head while an admission is in flight.
    ///
    /// This runs inside `snapshot`, which is exactly the window between
    /// `read_basis` and `publish_commit`. It uses the public `publish_decisions`
    /// with an empty decision batch — the point is to move the head and its
    /// token, not to publish a meaningful decision.
    fn race_the_head(&self, basis: &PublicationBasis) {
        let HeadRead::Present(read) = self
            .store
            .read_head(&self.head_key)
            .expect("the head is readable mid-admission")
        else {
            panic!("the head exists while an admission is in flight");
        };
        self.generation_before.set(read.generation().get());

        let next_generation = read
            .generation()
            .next()
            .expect("generation has room to advance");

        let mut rival = basis.body().clone();
        rival.generation = next_generation;
        rival.predecessor_head_id = Some(basis.id());
        rival.ref_root = self.rival_ref_root;

        let batch = RepositoryDecisionBatchBody {
            repository_id: self.repository_id,
            predecessor_head_id: basis.id(),
            predecessor_head_generation: basis.generation(),
            first_decision_sequence: DecisionSequence::FIRST,
            decisions: Vec::new(),
            committed_rcrs: Vec::new(),
            resulting_ref_root: rival.ref_root,
            resulting_forge_position_root: rival.forge_position_root,
            resulting_outcome_index_root: rival.outcome_index_root,
            resulting_retention_root: rival.retention_root,
            resulting_outbox_root: rival.outbox_root,
            resulting_policy_epoch: rival.policy_epoch,
            batch_evidence_root: digest(21),
        };

        let landed = publish_decisions(
            self.store.as_ref(),
            &self.head_key,
            read.token(),
            &batch,
            &rival,
            self.tenant_id,
        )
        .is_ok();

        let HeadRead::Present(after_read) = self
            .store
            .read_head(&self.head_key)
            .expect("the head is readable after the race")
        else {
            panic!("the head does not vanish");
        };
        let after = after_read.generation().get();
        self.generation_after.set(after);
        self.race_landed
            .set(landed && after > self.generation_before.get());
    }
}

impl AdmissionProjection for PinnedProjection {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        let root = basis.body().ref_root;
        self.observed.borrow_mut().push(root);
        let snapshot = self.production.snapshot(basis, authenticated)?;

        // Race only on the first snapshot: the replan must be allowed to
        // succeed, or the drill would measure the replan limit instead of the
        // TOCTOU refusal.
        if self.race && !self.raced.get() {
            self.raced.set(true);
            self.race_the_head(basis);
        }

        Ok(snapshot)
    }

    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, RefusalCode> {
        self.production
            .materialize_commit(basis, request, fold, closure)
    }

    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        self.production.materialize_refusal(basis, tx_id, code)
    }
}

fn store_with_genesis(
    context: &AdmissionContext,
    race: bool,
) -> (Rc<MemoryAuthorityStore>, PinnedProjection) {
    let commitments = TestStore::default();
    let production = CanonicalAdmissionProjection::new(commitments.clone(), TestEvidence);
    let mut refs = RefMap::new();
    refs.insert(
        RefName::try_new(MAIN_REF).expect("fixture ref name"),
        oid(MAIN_OID),
    );
    let store = Rc::new(MemoryAuthorityStore::new(StoreInstanceId::from_raw(31)));
    let canonical_genesis = initialize_canonical_repository(
        store.as_ref(),
        &context.head_key,
        genesis(context, digest(1)),
        &production,
        CanonicalRefState::new(refs),
        PermittedObjectClosure::default(),
    )
    .expect("genesis head publishes the production-computed ref root");
    let rival_ref_root = canonical_ref_state_root(&CanonicalRefState::default())
        .expect("empty rival state has a canonical root");
    commitments
        .stage_ref_state(rival_ref_root, CanonicalRefState::default())
        .expect("rival state stages canonically");

    let projection = PinnedProjection::new(
        production,
        commitments,
        Rc::clone(&store),
        context,
        canonical_genesis.commitments.ref_root,
        rival_ref_root,
        race,
    );
    (store, projection)
}

// ---------------------------------------------------------------------------
// Drills
// ---------------------------------------------------------------------------

/// The ref-state commitment names the same state regardless of insertion
/// order.  This proves the explicit codec ordering rather than relying on the
/// map implementation's traversal as a hidden protocol rule.
#[test]
fn canonical_ref_state_root_is_independent_of_input_insertion_order() {
    let main = RefName::try_new(MAIN_REF).expect("fixture main ref");
    let dev = RefName::try_new(b"refs/heads/dev").expect("fixture dev ref");

    let mut first = RefMap::new();
    first.insert(main.clone(), oid(MAIN_OID));
    first.insert(dev.clone(), oid("3333333333333333333333333333333333333333"));
    let mut second = RefMap::new();
    second.insert(dev, oid("3333333333333333333333333333333333333333"));
    second.insert(main, oid(MAIN_OID));

    let first = CanonicalRefState::new(first);
    let second = CanonicalRefState::new(second);
    assert_eq!(
        canonical_ref_state_root(&first),
        canonical_ref_state_root(&second),
        "canonical map encoding must erase construction order while retaining exact ref/OID pairs"
    );
    let decoded: CanonicalRefState = decode_body(
        &encode_body(&first).expect("canonical ref state encodes"),
        fgit_codec::DecodeLimits::DEFAULT,
    )
    .expect("canonical ref state decodes");
    assert_eq!(
        decoded, first,
        "the root names a reconstructable ref state body"
    );
}

/// PRESENCE CASE for the projection itself: the snapshot really does change
/// with the head, observed through the real admission path.
///
/// If this failed, every racing drill below would be measuring a projection
/// that answers identically for every basis — the exact blind spot that left
/// this acceptance line untested. It is asserted by running the *same request*
/// against the *same projection type* twice, differing only in whether the head
/// moved, and requiring the two to disagree.
#[test]
fn the_snapshot_answer_changes_with_the_head_it_is_pinned_to() {
    let context = context();

    let (unraced_store, unraced) = store_with_genesis(&context, false);
    let unraced_result = admit_validated_receive(
        unraced_store.as_ref(),
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &unraced,
    );

    let (raced_store, raced) = store_with_genesis(&context, true);
    let raced_result = admit_validated_receive(
        raced_store.as_ref(),
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &raced,
    );

    assert_eq!(
        unraced.observed_roots(),
        vec![unraced.genesis_ref_root],
        "without a competing writer the basis must never change"
    );
    assert!(
        raced.observed_roots().contains(&raced.rival_ref_root),
        "the raced attempt never saw the head the race installed, so the snapshot \
         is not tracking the head at all"
    );
    assert_ne!(
        unraced.observed_roots(),
        raced.observed_roots(),
        "both runs pinned the same basis sequence, so this projection cannot \
         witness a race and every drill below would be vacuous"
    );

    // The decisions must differ too: a projection that tracked the head but
    // produced the same answer either way would still hide a TOCTOU.
    assert!(
        unraced_result.is_ok(),
        "the unraced control must be admissible"
    );
    let unraced_committed = matches!(
        terminal_for(unraced_store.as_ref(), &context, &unraced_result),
        Some(DecisionOutcome::Committed { .. })
    );
    let raced_committed = matches!(
        terminal_for(raced_store.as_ref(), &context, &raced_result),
        Some(DecisionOutcome::Committed { .. })
    );
    assert!(
        unraced_committed,
        "the unraced control did not commit, so it is not a control"
    );
    assert!(
        !raced_committed,
        "the raced attempt committed a fold computed against a ref table the race \
         had already replaced — that is the TOCTOU this line forbids"
    );
}

/// The authenticated terminal decision for an admission result, if it reached
/// one. `None` covers both an admission error and an undecided transaction,
/// neither of which is a commit.
fn terminal_for(
    store: &MemoryAuthorityStore,
    context: &AdmissionContext,
    result: &Result<fgit_admission::AdmissionResult, fgit_admission::AdmissionError>,
) -> Option<DecisionOutcome> {
    let result = result.as_ref().ok()?;
    let tx_id = *result.session.tx_ids.first()?;
    match resolve_outcome(
        store,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .expect("resolution must be able to answer")
    {
        OutcomeLookup::Decided(terminal) => Some(terminal.outcome),
        OutcomeLookup::Undecided => None,
    }
}

/// PRESENCE CASE for the race: the competing write actually lands.
///
/// Without this, a refusal below could be credited to a race that never fired.
#[test]
fn the_injected_race_actually_lands() {
    let context = context();
    let (store, projection) = store_with_genesis(&context, true);

    let _ = admit_validated_receive(
        store.as_ref(),
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &projection,
    );

    assert!(
        projection.raced.get(),
        "the race was never attempted, so nothing about TOCTOU was exercised"
    );
    assert!(
        projection.race_landed.get(),
        "the competing write did not move the head (generation {} -> {}), \
         so a 'refused' verdict would be unearned",
        projection.generation_before.get(),
        projection.generation_after.get()
    );
    assert!(
        projection.generation_after.get() > projection.generation_before.get(),
        "the head generation must strictly advance for the race to be real"
    );
}

/// The TOCTOU attempt is refused: a decision computed against the pre-race head
/// never becomes the published outcome.
#[test]
fn a_concurrent_head_change_cannot_slip_past_the_pinned_snapshot() {
    let context = context();
    let (store, projection) = store_with_genesis(&context, true);
    let validated = delete_main();

    let result = admit_validated_receive(
        store.as_ref(),
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    );

    // The replan is the observable signature of the lost CAS. One snapshot
    // would mean the publication succeeded against the stale basis.
    assert!(
        projection.snapshot_count() >= 2,
        "only {} snapshot(s): the admission never replanned, so the stale basis \
         was not rejected",
        projection.snapshot_count()
    );

    let observed = projection.observed_roots();
    assert_eq!(
        observed[0], projection.genesis_ref_root,
        "the first snapshot must be pinned to the genesis head"
    );
    assert_eq!(
        observed[observed.len() - 1],
        projection.rival_ref_root,
        "the final snapshot must be pinned to the head the race installed, not the \
         one the attempt started from"
    );

    // Whatever the caller was told, the authenticated stream must agree, and it
    // must not hold a commit that was computed against the pre-race ref table.
    let Ok(result) = result else {
        // Exhausting the replan budget is a permitted outcome; what is
        // forbidden is a commit on the stale basis, and no commit exists here.
        return;
    };
    let tx_id = result.session.tx_ids[0];
    let resolved = resolve_outcome(
        store.as_ref(),
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .expect("resolution must be able to answer");

    if let OutcomeLookup::Decided(terminal) = resolved {
        assert!(
            matches!(terminal.outcome, DecisionOutcome::Refused { .. }),
            "the delete folded against a ref table the race had already invalidated; \
             committing it would be the TOCTOU this line forbids, but the stream holds \
             {:?}",
            terminal.outcome
        );
        assert_eq!(
            result.commands[0].terminal, terminal,
            "the caller was told a decision the authenticated stream does not hold"
        );
    }
}

/// The permitted twin: the identical request, with no race, commits.
///
/// This is what makes the refusal above evidence. A fixture that refused every
/// push would satisfy the drill above and prove nothing.
#[test]
fn a_permitted_twin_proceeds_without_the_race() {
    let context = context();
    let (store, projection) = store_with_genesis(&context, false);
    let validated = delete_main();

    let result = admit_validated_receive(
        store.as_ref(),
        &context,
        &validated,
        AdmissionLimits::default(),
        &projection,
    )
    .expect("an unraced delete must be admissible");

    assert_eq!(
        projection.snapshot_count(),
        1,
        "with no competing writer the admission must not replan at all"
    );
    assert_eq!(
        projection.observed_roots()[0],
        projection.genesis_ref_root,
        "the single snapshot is pinned to the genesis head"
    );
    assert!(
        !projection.race_landed.get(),
        "no race was configured, so none may have landed"
    );

    let tx_id = result.session.tx_ids[0];
    let resolved = resolve_outcome(
        store.as_ref(),
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .expect("resolution must be able to answer");

    let OutcomeLookup::Decided(terminal) = resolved else {
        panic!("the unraced twin must reach a terminal decision");
    };
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "the twin is the positive control: if it cannot commit, the raced drill's \
         refusal says nothing about TOCTOU, but the stream holds {:?}",
        terminal.outcome
    );
    assert_eq!(
        result.commands[0].terminal, terminal,
        "the caller was told a decision the authenticated stream does not hold"
    );
}

/// The successor root returned by the production materializer is resolvable
/// through the same immutable commitment store, and a missing root refuses.
#[test]
fn production_successor_ref_root_round_trips_and_missing_root_refuses() {
    let context = context();
    let (store, projection) = store_with_genesis(&context, false);

    let result = admit_validated_receive(
        store.as_ref(),
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &projection,
    )
    .expect("the production projection commits the permitted control");
    let tx_id = result.session.tx_ids[0];
    let terminal = resolve_outcome(
        store.as_ref(),
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .expect("the terminal outcome resolves");
    assert!(
        matches!(terminal, OutcomeLookup::Decided(ref outcome) if matches!(outcome.outcome, DecisionOutcome::Committed { .. })),
        "the round-trip requires a real production commit, not an uncommitted candidate"
    );

    let HeadRead::Present(head) = store
        .read_head(&context.head_key)
        .expect("the committed head is readable")
    else {
        panic!("the committed repository head must exist");
    };
    let authenticated = store
        .authenticate_head_receipt(&head)
        .expect("the committed head authenticates");
    let body = authenticated
        .body()
        .expect("the committed head body decodes");
    let resolved = projection
        .commitments
        .resolve_ref_state(body.ref_root)
        .expect("the authority-selected successor root resolves");
    assert!(
        resolved.refs().is_empty(),
        "deleting the only ref must be reflected by the state named in the successor root"
    );
    assert_eq!(
        projection.commitments.resolve_ref_state(digest(255)),
        Err(RefusalCode::EvidenceMissing),
        "a root absent from immutable storage must refuse rather than fall back to a local map"
    );
    let closure_root = permitted_object_closure_root(&PermittedObjectClosure::default())
        .expect("the delete-only closure has a canonical root");
    assert_eq!(
        projection
            .commitments
            .resolve_permitted_object_closure(closure_root),
        Ok(PermittedObjectClosure::default()),
        "the RCR-validated closure commitment must resolve from the same immutable store"
    );
}

#[test]
fn fixture_algorithm_slot_is_reserved_and_unregistered() {
    let fixture_algorithm = DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
        .expect("corpus fixture code point is nonzero");
    assert!(
        fgit_crypto::CORPUS_RESERVED_CODE_POINTS.contains(&FIXTURE_ALGORITHM_CODE_POINT),
        "fixture algorithm slot {FIXTURE_ALGORITHM_CODE_POINT:#06x} escaped the corpus-reserved range"
    );
    assert!(
        fgit_crypto::DigestAlgorithm::from_id(fixture_algorithm).is_none(),
        "fixture algorithm slot must never resolve to a registered construction"
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
