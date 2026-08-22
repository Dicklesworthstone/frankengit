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
//! So [`PinnedProjection`] is **basis-derived**: its ref table is a function of
//! `basis.body().ref_root`. Two different heads therefore produce two different
//! snapshots, which is exactly the sensitivity a TOCTOU probe needs.
//!
//! ## The race is real, not simulated
//!
//! `FaultKind` has no "concurrent modification" variant, so the fault plan
//! cannot express this. The injection here is a genuine competing writer:
//! [`PinnedProjection::race_the_head`] calls the public `publish_decisions`
//! from inside `snapshot()` — which is, precisely, the window between the basis
//! read and the publication. Nothing is stubbed; the head really does advance
//! underneath an in-flight admission.
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

use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionProjection, AdmissionSnapshot,
    CommitMaterialization, QuarantineValidator, RefusalMaterialization, ValidatedClosure,
    ValidatedReceive, admit_validated_receive, validate_receive,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, HeadKey, HeadRead, IdempotencyKey, MemoryAuthorityStore,
    OutcomeLookup, StoreInstanceId, initialize_repository, publish_decisions, resolve_outcome,
};
use fgit_chronicle::{PublicationBasis, ResultingRoots};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecisionBatchBody,
};
use fgit_reference::effect::FoldOutcome;
use fgit_reference::intent::{
    ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey, RetentionRoot, TransactionRequest,
};
use fgit_txn::TransactionFoldReport;
use fgit_types::native::GitHashAlgorithm;
use fgit_types::{
    DecisionOutcome, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes, GitOid,
    HeadGeneration, PolicyEpoch, PrincipalId, PrincipalSnapshotId, RefName, RefusalCode,
    RegistryEpoch, RepositoryId, RepositorySequence, TenantId, TxId,
};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveEvent, ReceiveLimits, ReceivePack, ReceiveRequest,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const MAIN_OID: &str = "2222222222222222222222222222222222222222";
const MAIN_REF: &[u8] = b"refs/heads/main";

/// The `ref_root` the genesis head carries.
const GENESIS_REF_ROOT: u8 = 1;
/// The `ref_root` the competing writer installs. Distinct from genesis, which
/// is what makes the projection's answer change under the race.
const RIVAL_REF_ROOT: u8 = 200;

type ForgeMap = BTreeMap<ForgeStreamId, ForgeStreamPosition>;
type OutboxMap = BTreeMap<OutboxDeliveryKey, Digest>;
type RetentionSet = BTreeSet<RetentionRoot>;
type RefMap = BTreeMap<RefName, GitOid>;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn digest(seed: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("non-zero algorithm id"),
        DigestBytes::try_new(&[seed; 32]).expect("32-byte test digest"),
    )
}

fn principal_snapshot() -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_digest(
        DigestAlgorithmId::try_new(1).expect("non-zero algorithm id"),
        fgit_types::CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[15; 32]).expect("32-byte test digest"),
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

fn genesis(context: &AdmissionContext) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: context.repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(GENESIS_REF_ROOT),
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

fn store_with_genesis(context: &AdmissionContext) -> MemoryAuthorityStore {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(31));
    initialize_repository(&store, &context.head_key, &genesis(context))
        .expect("genesis head initializes");
    store
}

struct DeleteOnlyValidator;

impl QuarantineValidator for DeleteOnlyValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
    ) -> Result<ValidatedClosure, RefusalCode> {
        Ok(ValidatedClosure {
            object_closure_root: digest(14),
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

/// A projection whose snapshot is a **function of the authenticated head**.
///
/// This is the whole point of the file. The ref table it exposes is chosen by
/// `basis.body().ref_root`: the genesis root yields a table carrying
/// `refs/heads/main`, and any other root yields an empty table. A delete of
/// `main` therefore folds cleanly against the genesis basis and becomes a
/// stale-ref refusal against any successor — so the decision *observably*
/// depends on which head was pinned, and a race that slipped through would
/// change the answer.
struct PinnedProjection<'s> {
    store: &'s MemoryAuthorityStore,
    head_key: HeadKey,
    repository_id: RepositoryId,
    tenant_id: TenantId,

    /// Ref table returned for the genesis basis.
    refs_at_genesis: RefMap,
    /// Ref table returned for any other basis.
    refs_after_race: RefMap,
    forge_positions: ForgeMap,
    retention: RetentionSet,
    outbox: OutboxMap,

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

impl<'s> PinnedProjection<'s> {
    fn new(store: &'s MemoryAuthorityStore, context: &AdmissionContext, race: bool) -> Self {
        let mut refs_at_genesis = RefMap::new();
        refs_at_genesis.insert(
            RefName::try_new(MAIN_REF).expect("fixture ref name"),
            oid(MAIN_OID),
        );

        Self {
            store,
            head_key: context.head_key.clone(),
            repository_id: context.repository_id,
            tenant_id: context.tenant_id,
            refs_at_genesis,
            refs_after_race: RefMap::new(),
            forge_positions: ForgeMap::new(),
            retention: RetentionSet::new(),
            outbox: OutboxMap::new(),
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
        rival.ref_root = digest(RIVAL_REF_ROOT);

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
            self.store,
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

impl AdmissionProjection for PinnedProjection<'_> {
    fn snapshot<'a>(
        &'a self,
        basis: &PublicationBasis,
        _authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot<'a>, RefusalCode> {
        let root = basis.body().ref_root;
        self.observed.borrow_mut().push(root);

        // The refs are chosen by the head we were handed, never by a cached
        // local table. That is the property under test.
        let refs = if root == digest(GENESIS_REF_ROOT) {
            &self.refs_at_genesis
        } else {
            &self.refs_after_race
        };

        // Race only on the first snapshot: the replan must be allowed to
        // succeed, or the drill would measure the replan limit instead of the
        // TOCTOU refusal.
        if self.race && !self.raced.get() {
            self.raced.set(true);
            self.race_the_head(basis);
        }

        Ok(AdmissionSnapshot {
            refs,
            forge_positions: &self.forge_positions,
            retention: &self.retention,
            outbox: &self.outbox,
        })
    }

    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, RefusalCode> {
        if !matches!(fold.outcome, FoldOutcome::Folded(_)) {
            return Err(RefusalCode::ConflictingSemanticEffects);
        }
        let roots = ResultingRoots {
            ref_root: digest(2),
            forge_position_root: digest(3),
            outcome_index_root: digest(4),
            retention_root: basis.body().retention_root,
            outbox_root: digest(5),
            policy_epoch: basis.body().policy_epoch,
            batch_evidence_root: digest(6),
        };
        Ok(CommitMaterialization {
            record: RepositoryCommitRecord {
                repository_id: request.repository,
                repository_sequence: RepositorySequence::FIRST,
                parent_rcr_id: None,
                tx_id: request.tx_id,
                principal_snapshot_id: principal_snapshot(),
                canonical_request_digest: request.canonical_request_digest,
                ref_delta_root: digest(7),
                resulting_ref_root: roots.ref_root,
                object_closure_root: closure.object_closure_root,
                forge_event_batch_root: digest(8),
                resulting_forge_position_root: roots.forge_position_root,
                policy_epoch: roots.policy_epoch,
                policy_decision_root: digest(9),
                invariant_evidence_root: digest(10),
                outbox_effect_root: digest(11),
                retention_delta_root: digest(12),
            },
            roots,
        })
    }

    fn materialize_refusal(
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

// ---------------------------------------------------------------------------
// Drills
// ---------------------------------------------------------------------------

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

    let unraced_store = store_with_genesis(&context);
    let unraced = PinnedProjection::new(&unraced_store, &context, false);
    let unraced_result = admit_validated_receive(
        &unraced_store,
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &unraced,
    );

    let raced_store = store_with_genesis(&context);
    let raced = PinnedProjection::new(&raced_store, &context, true);
    let raced_result = admit_validated_receive(
        &raced_store,
        &context,
        &delete_main(),
        AdmissionLimits::default(),
        &raced,
    );

    assert_eq!(
        unraced.observed_roots(),
        vec![digest(GENESIS_REF_ROOT)],
        "without a competing writer the basis must never change"
    );
    assert!(
        raced.observed_roots().contains(&digest(RIVAL_REF_ROOT)),
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
        terminal_for(&unraced_store, &context, &unraced_result),
        Some(DecisionOutcome::Committed { .. })
    );
    let raced_committed = matches!(
        terminal_for(&raced_store, &context, &raced_result),
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
    let store = store_with_genesis(&context);
    let projection = PinnedProjection::new(&store, &context, true);

    let _ = admit_validated_receive(
        &store,
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
    let store = store_with_genesis(&context);
    let projection = PinnedProjection::new(&store, &context, true);
    let validated = delete_main();

    let result = admit_validated_receive(
        &store,
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
        observed[0],
        digest(GENESIS_REF_ROOT),
        "the first snapshot must be pinned to the genesis head"
    );
    assert_eq!(
        observed[observed.len() - 1],
        digest(RIVAL_REF_ROOT),
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
        &store,
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
    let store = store_with_genesis(&context);
    let projection = PinnedProjection::new(&store, &context, false);
    let validated = delete_main();

    let result = admit_validated_receive(
        &store,
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
        digest(GENESIS_REF_ROOT),
        "the single snapshot is pinned to the genesis head"
    );
    assert!(
        !projection.race_landed.get(),
        "no race was configured, so none may have landed"
    );

    let tx_id = result.session.tx_ids[0];
    let resolved = resolve_outcome(
        &store,
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
