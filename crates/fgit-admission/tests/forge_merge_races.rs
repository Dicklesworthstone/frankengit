//! A controlled merge-admission race against the real authority path.
//!
//! This drives `fgit-admission`'s public merge API, `MemoryAuthorityStore`,
//! and `CanonicalAdmissionProjection` from the product layer. The L2 lab is a
//! downward test-only dependency that controls the real boundary between
//! candidate A's authenticated snapshot and its head CAS; it is not a
//! test-local merge state machine.
//!
//! The campaign establishes one race schedule only.  It does not claim forge
//! position advancement, outbox redelivery, or projection rebuild: the current
//! admission route explicitly carries those roots forward pending their owning
//! production paths.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use fgit_admission::merge::{ForgeBodyStore, SealedMerge, admit_merge};
use fgit_admission::{
    AdmissionContext, AdmissionEvidence, AdmissionLimits, AdmissionProjection, AdmissionSnapshot,
    AdmissionSnapshotProjection, CanonicalAdmissionProjection, CanonicalAdmissionStore,
    CanonicalRefState, CommitEvidence, PermittedObjectClosure, ProjectionFailure,
    RefusalMaterialization, ValidatedClosure, canonical_ref_state_root,
    initialize_canonical_repository,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityOpKind, AuthorityStore, FaultDirective, FaultKind, FaultPlan,
    FaultPosition, FaultableAuthorityStore, HeadKey, HeadRead, IdempotencyKey,
    MemoryAuthorityStore, StoreInstanceId,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_forge::event::{ForgeEvent, ForgeEventBatch};
use fgit_forge::{
    AggregateVersion, ForgeEventPayload, MergeAttempt, MergeEffectPackage, PullRequestNumber,
    RefIntent, WorkspaceEpoch,
};
use fgit_lab::{LabSchedule, StepCursor, StepId};
use fgit_reference::intent::TransactionRequest;
use fgit_types::native::GitHashAlgorithm;
use fgit_types::{
    DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes, GitOid, HeadGeneration, PolicyEpoch,
    PrincipalId, PrincipalSnapshotId, RefName, RefusalCode, RegistryEpoch, RepositoryId, TenantId,
    TxId,
};
use fgit_wire::GitObjectFormat;

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

const MAIN_REF: &[u8] = b"refs/heads/main";
const FEATURE_REF: &[u8] = b"refs/heads/feature";
const TARGET_OID: &str = "2222222222222222222222222222222222222222";
const SOURCE_OID: &str = "3333333333333333333333333333333333333333";
const BASE_OID: &str = "1111111111111111111111111111111111111111";
const FIRST_MERGE_OID: &str = "4444444444444444444444444444444444444444";
const RIVAL_MERGE_OID: &str = "5555555555555555555555555555555555555555";
const THIRD_MERGE_OID: &str = "6666666666666666666666666666666666666666";
const THREE_WAY_SCHEDULE_SEED: u64 = 0x168;

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

fn context_for(key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"fg/head/lab-forge-merge-race".to_vec()).expect("valid head key"),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(key.to_vec()).expect("bounded key"),
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

#[derive(Default)]
struct Commitments {
    refs: RefCell<BTreeMap<Digest, CanonicalRefState>>,
    closures: RefCell<BTreeMap<Digest, PermittedObjectClosure>>,
    forge_events: RefCell<BTreeMap<Digest, ForgeEventBatch>>,
}

#[derive(Clone, Default)]
struct Store(Rc<Commitments>);

impl CanonicalAdmissionStore for Store {
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

// Added by RainyLotus (cc_8) under frankengit-asa3, 2026-08-24, so this suite
// keeps compiling after admit_merge gained its ForgeBodyStore bound. The merge
// path now stages the forge event body it commits a root to; a caller has to
// offer somewhere to put it. Assertions in this file are untouched.
impl ForgeBodyStore for Store {
    fn stage_forge_event_batch(
        &self,
        root: Digest,
        batch: ForgeEventBatch,
    ) -> Result<(), RefusalCode> {
        self.0.forge_events.borrow_mut().insert(root, batch);
        Ok(())
    }

    fn resolve_forge_event_batch(&self, root: Digest) -> Result<ForgeEventBatch, RefusalCode> {
        self.0
            .forge_events
            .borrow()
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }
}

struct Evidence;

impl AdmissionEvidence for Evidence {
    fn commit_evidence(
        &self,
        _basis: &PublicationBasis,
        _request: &TransactionRequest,
        _fold: &fgit_txn::TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode> {
        Ok(commit_evidence())
    }

    fn refusal_evidence(
        &self,
        basis: &PublicationBasis,
        _tx_id: TxId,
        _code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: "lab forge merge race refusal".to_owned(),
            evidence_root: digest(13),
        })
    }
}

fn commit_evidence() -> CommitEvidence {
    CommitEvidence {
        principal_snapshot_id: principal_snapshot(),
        forge_event_batch_root: digest(8),
        policy_decision_root: digest(9),
        invariant_evidence_root: digest(10),
        outbox_effect_root: digest(11),
        retention_delta_root: digest(12),
    }
}

fn package(merge_commit: &str) -> MergeEffectPackage {
    MergeEffectPackage {
        objects: vec![oid(merge_commit)],
        ref_intent: RefIntent {
            name: MAIN_REF.to_vec(),
            expected_tip: oid(TARGET_OID),
            new_tip: oid(merge_commit),
        },
        event: ForgeEvent {
            aggregate: PullRequestNumber::try_new(41)
                .expect("a nonzero pull request number")
                .into(),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::MergeCommitted {
                merge_commit: digest(0x51),
                target_ref: MAIN_REF.to_vec(),
                target_tip_before: digest(0x40),
                target_tip_after: digest(0x51),
            },
        },
    }
}

fn attempt() -> MergeAttempt {
    MergeAttempt {
        pull_request: PullRequestNumber::try_new(41).expect("a nonzero pull request number"),
        source_ref: FEATURE_REF.to_vec(),
        target_ref: MAIN_REF.to_vec(),
        source_tip: oid(SOURCE_OID),
        target_tip: oid(TARGET_OID),
        base_tip: oid(BASE_OID),
        workspace_epoch: WorkspaceEpoch::from_u64(9),
    }
}

fn closure(merge_commit: &str) -> ValidatedClosure {
    let objects: BTreeSet<GitOid> = std::iter::once(oid(merge_commit)).collect();
    let permitted = PermittedObjectClosure::new(objects.clone());
    ValidatedClosure {
        object_closure_root: fgit_admission::permitted_object_closure_root(&permitted)
            .expect("closure root"),
        objects,
    }
}

type ProductionProjection = CanonicalAdmissionProjection<Store, Evidence>;

fn repository() -> (
    AdmissionContext,
    Rc<MemoryAuthorityStore>,
    ProductionProjection,
    Store,
) {
    let context = context_for(b"lab-merge-a");
    let commitments = Store::default();
    let projection = CanonicalAdmissionProjection::new(commitments.clone(), Evidence);
    let refs = BTreeMap::from([
        (
            RefName::try_new(MAIN_REF).expect("fixture ref name"),
            oid(TARGET_OID),
        ),
        (
            RefName::try_new(FEATURE_REF).expect("fixture ref name"),
            oid(SOURCE_OID),
        ),
    ]);
    let store = Rc::new(MemoryAuthorityStore::new(StoreInstanceId::from_raw(61)));
    let state = CanonicalRefState::new(refs);
    let ref_root = canonical_ref_state_root(&state).expect("genesis ref root");
    initialize_canonical_repository(
        store.as_ref(),
        &context.head_key,
        genesis(&context, ref_root),
        &projection,
        state,
        PermittedObjectClosure::default(),
    )
    .expect("genesis head publishes");
    (context, store, projection, commitments)
}

fn sealed<'a>(
    package: &'a MergeEffectPackage,
    attempt: &'a MergeAttempt,
    closure: &'a ValidatedClosure,
) -> SealedMerge<'a> {
    SealedMerge {
        package,
        attempt,
        closure,
        evidence: commit_evidence(),
        workspace_epoch_now: WorkspaceEpoch::from_u64(9),
    }
}

/// The campaign boundary between a scenario and its admission driver.
///
/// The scenarios below do not call the synchronous production entry point
/// directly.  The current adapter drives `admit_merge`; a durable adapter can
/// implement this same test-only boundary when asa3 lands without changing the
/// race, retry, and publication-fault assertions.
trait MergeAdmissionPath {
    fn admit(
        &self,
        context: &AdmissionContext,
        sealed: &SealedMerge<'_>,
    ) -> Result<fgit_authority::TerminalOutcome, fgit_admission::AdmissionError>;
}

struct SyncMergeAdmissionPath<'a, Authority: ?Sized, Projection: ?Sized, CommitmentStore: ?Sized> {
    store: &'a Authority,
    projection: &'a Projection,
    commitments: &'a CommitmentStore,
}

impl<Authority, Projection, CommitmentStore> MergeAdmissionPath
    for SyncMergeAdmissionPath<'_, Authority, Projection, CommitmentStore>
where
    Authority: AuthorityStore + ?Sized,
    Projection: AdmissionProjection + ?Sized,
    CommitmentStore: CanonicalAdmissionStore + ForgeBodyStore + ?Sized,
{
    fn admit(
        &self,
        context: &AdmissionContext,
        sealed: &SealedMerge<'_>,
    ) -> Result<fgit_authority::TerminalOutcome, fgit_admission::AdmissionError> {
        admit_merge(
            self.store,
            context,
            sealed,
            AdmissionLimits::default(),
            self.projection,
            self.commitments,
        )
    }
}

struct Rival<'a> {
    context: AdmissionContext,
    sealed: SealedMerge<'a>,
}

/// A schedule gate around the production projection.
///
/// Candidate A has already read its authenticated basis when this projection's
/// `snapshot` runs.  The first schedule gate lets A obtain that snapshot; the
/// second lets candidate B complete its real admission; and the final gate
/// releases A to issue its CAS against the now-stale token.  On A's replan no
/// gate runs, so the production projection observes B's new ref state and the
/// real staleness check determines the terminal refusal.
struct ScheduledProjection<'schedule, 'rival> {
    production: ProductionProjection,
    cursor: RefCell<StepCursor<'schedule>>,
    raced: Cell<bool>,
    rival: Rival<'rival>,
    store: Rc<MemoryAuthorityStore>,
    commitments: Store,
    rival_terminal: RefCell<Option<fgit_authority::TerminalOutcome>>,
}

impl ScheduledProjection<'_, '_> {
    fn step(&self, expected_actor: &str) {
        let mut cursor = self.cursor.borrow_mut();
        let actual = cursor
            .next_step()
            .expect("the lab schedule declares every race boundary");
        assert_eq!(
            actual.as_str(),
            expected_actor,
            "lab schedule drifted at a merge-admission boundary"
        );
    }

    fn schedule_exhausted(&self) -> bool {
        self.cursor.borrow().is_exhausted()
    }

    fn rival_terminal(&self) -> fgit_authority::TerminalOutcome {
        self.rival_terminal
            .borrow_mut()
            .take()
            .expect("scheduled rival must reach a terminal decision")
    }
}

impl AdmissionSnapshotProjection for ScheduledProjection<'_, '_> {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        let first_snapshot = !self.raced.replace(true);
        if first_snapshot {
            self.step("merge-a");
        }
        let snapshot = self.production.snapshot(basis, authenticated)?;
        if first_snapshot {
            self.step("merge-b");
            let path = SyncMergeAdmissionPath {
                store: self.store.as_ref(),
                projection: &self.production,
                commitments: &self.commitments,
            };
            let terminal = path
                .admit(&self.rival.context, &self.rival.sealed)
                .expect("scheduled rival reaches one terminal decision");
            self.rival_terminal.borrow_mut().replace(terminal);
            self.step("merge-a");
        }
        Ok(snapshot)
    }
}

/// A re-entrant schedule gate for a seeded N-way race.
///
/// Each candidate pauses only after reading its real authenticated snapshot.
/// The next candidate is then admitted through its own adapter, so the final
/// candidate reaches the authority CAS first and every earlier candidate must
/// replan against that real publication.
struct NestedScheduledProjection<'schedule, 'trigger> {
    production: ProductionProjection,
    cursor: Rc<RefCell<StepCursor<'schedule>>>,
    raced: Cell<bool>,
    snapshot_actor: &'static str,
    cas_actor: &'static str,
    after_snapshot: Option<Box<dyn Fn() + 'trigger>>,
}

impl NestedScheduledProjection<'_, '_> {
    fn step(&self, expected_actor: &str) {
        let mut cursor = self.cursor.borrow_mut();
        let actual = cursor
            .next_step()
            .expect("the seeded schedule declares every three-way race boundary");
        assert_eq!(
            actual.as_str(),
            expected_actor,
            "seeded three-way merge schedule drifted at an admission boundary"
        );
    }

    fn schedule_exhausted(&self) -> bool {
        self.cursor.borrow().is_exhausted()
    }
}

impl AdmissionSnapshotProjection for NestedScheduledProjection<'_, '_> {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        let first_snapshot = !self.raced.replace(true);
        if first_snapshot {
            self.step(self.snapshot_actor);
        }
        let snapshot = self.production.snapshot(basis, authenticated)?;
        if first_snapshot {
            if let Some(after_snapshot) = &self.after_snapshot {
                after_snapshot();
            }
            self.step(self.cas_actor);
        }
        Ok(snapshot)
    }
}

impl AdmissionProjection for NestedScheduledProjection<'_, '_> {
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<fgit_admission::CommitMaterialization, ProjectionFailure> {
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

impl AdmissionProjection for ScheduledProjection<'_, '_> {
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<fgit_admission::CommitMaterialization, ProjectionFailure> {
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

#[test]
fn scheduled_merge_race_has_one_winner_and_no_half_merged_ref_state() {
    let schedule = LabSchedule::explicit(
        vec![StepId::new("merge-a"), StepId::new("merge-b")],
        vec![
            StepId::new("merge-a"),
            StepId::new("merge-b"),
            StepId::new("merge-a"),
        ],
    )
    .expect("a declared three-boundary race schedule");

    let (first_context, store, production, commitments) = repository();
    let attempt = attempt();
    let first_package = package(FIRST_MERGE_OID);
    let first_closure = closure(FIRST_MERGE_OID);
    let rival_package = package(RIVAL_MERGE_OID);
    let rival_closure = closure(RIVAL_MERGE_OID);
    let rival = Rival {
        context: context_for(b"lab-merge-b"),
        sealed: sealed(&rival_package, &attempt, &rival_closure),
    };
    let scheduled = ScheduledProjection {
        production,
        cursor: RefCell::new(schedule.cursor()),
        raced: Cell::new(false),
        rival,
        store: Rc::clone(&store),
        commitments: commitments.clone(),
        rival_terminal: RefCell::new(None),
    };

    let path = SyncMergeAdmissionPath {
        store: store.as_ref(),
        projection: &scheduled,
        commitments: &commitments,
    };
    let loser = path
        .admit(
            &first_context,
            &sealed(&first_package, &attempt, &first_closure),
        )
        .expect("the candidate that loses its CAS still gets a terminal decision");
    let winner = scheduled.rival_terminal();

    assert!(
        scheduled.schedule_exhausted(),
        "every declared boundary ran"
    );
    assert_eq!(
        schedule.canonical_line(),
        "fgit-lab-schedule-v1|seed=none|participants=merge-a,merge-b|steps=3|order=merge-a,merge-b,merge-a",
        "the schedule is a stable replay input, not an ambient thread race"
    );
    assert!(
        matches!(winner.outcome, DecisionOutcome::Committed { .. }),
        "the intervening candidate must win the actual head CAS"
    );
    match loser.outcome {
        DecisionOutcome::Refused { code, .. } => assert_eq!(
            code,
            RefusalCode::TargetRefMoved,
            "the stale candidate must be refused, not recomputed or silently committed"
        ),
        committed @ DecisionOutcome::Committed { .. } => {
            panic!("only one candidate may commit, got {committed:?}")
        }
    }

    let HeadRead::Present(head) = store
        .read_head(&first_context.head_key)
        .expect("authority head remains readable")
    else {
        panic!("authority head cannot vanish during a merge race");
    };
    let body: RepositoryAuthorityHeadBody =
        fgit_codec::decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT)
            .expect("committed authority head decodes");
    let refs = commitments
        .resolve_ref_state(body.ref_root)
        .expect("published ref root names staged canonical state");
    assert_eq!(
        refs.refs()
            .get(&RefName::try_new(MAIN_REF).expect("fixture ref name")),
        Some(&oid(RIVAL_MERGE_OID)),
        "the final head names the complete winner, never candidate A's partial ref movement"
    );
}

#[test]
fn seeded_three_way_merge_race_has_exactly_one_winner_for_one_pull_request() {
    let schedule = LabSchedule::seeded(
        vec![
            StepId::new("merge-a"),
            StepId::new("merge-b"),
            StepId::new("merge-c"),
        ],
        6,
        THREE_WAY_SCHEDULE_SEED,
    )
    .expect("the three-way participants are unique");
    assert_eq!(
        schedule.canonical_line(),
        "fgit-lab-schedule-v1|seed=360|participants=merge-a,merge-b,merge-c|steps=6|order=merge-a,merge-b,merge-c,merge-c,merge-b,merge-a",
        "the chosen seed must reproduce the intended nested schedule"
    );

    let (first_context, store, production, commitments) = repository();
    let attempt = attempt();
    let first_package = package(FIRST_MERGE_OID);
    let first_closure = closure(FIRST_MERGE_OID);
    let first_sealed = sealed(&first_package, &attempt, &first_closure);
    let second_context = context_for(b"lab-merge-b");
    let second_package = package(RIVAL_MERGE_OID);
    let second_closure = closure(RIVAL_MERGE_OID);
    let second_sealed = sealed(&second_package, &attempt, &second_closure);
    let third_context = context_for(b"lab-merge-c");
    let third_package = package(THIRD_MERGE_OID);
    let third_closure = closure(THIRD_MERGE_OID);
    let third_sealed = sealed(&third_package, &attempt, &third_closure);
    let cursor = Rc::new(RefCell::new(schedule.cursor()));
    let second_terminal = Rc::new(RefCell::new(None));
    let third_terminal = Rc::new(RefCell::new(None));

    let third_projection = NestedScheduledProjection {
        production: CanonicalAdmissionProjection::new(commitments.clone(), Evidence),
        cursor: Rc::clone(&cursor),
        raced: Cell::new(false),
        snapshot_actor: "merge-c",
        cas_actor: "merge-c",
        after_snapshot: None,
    };
    let third_path = SyncMergeAdmissionPath {
        store: store.as_ref(),
        projection: &third_projection,
        commitments: &commitments,
    };
    let second_projection = NestedScheduledProjection {
        production: CanonicalAdmissionProjection::new(commitments.clone(), Evidence),
        cursor: Rc::clone(&cursor),
        raced: Cell::new(false),
        snapshot_actor: "merge-b",
        cas_actor: "merge-b",
        after_snapshot: Some(Box::new(|| {
            let terminal = third_path
                .admit(&third_context, &third_sealed)
                .expect("third contender reaches a terminal decision");
            third_terminal.borrow_mut().replace(terminal);
        })),
    };
    let second_path = SyncMergeAdmissionPath {
        store: store.as_ref(),
        projection: &second_projection,
        commitments: &commitments,
    };
    let first_projection = NestedScheduledProjection {
        production,
        cursor,
        raced: Cell::new(false),
        snapshot_actor: "merge-a",
        cas_actor: "merge-a",
        after_snapshot: Some(Box::new(|| {
            let terminal = second_path
                .admit(&second_context, &second_sealed)
                .expect("second contender reaches a terminal decision");
            second_terminal.borrow_mut().replace(terminal);
        })),
    };
    let first_path = SyncMergeAdmissionPath {
        store: store.as_ref(),
        projection: &first_projection,
        commitments: &commitments,
    };

    let first_terminal = first_path
        .admit(&first_context, &first_sealed)
        .expect("first contender reaches a terminal decision");
    let second_terminal = second_terminal
        .borrow_mut()
        .take()
        .expect("second contender was scheduled");
    let third_terminal = third_terminal
        .borrow_mut()
        .take()
        .expect("third contender was scheduled");

    assert!(
        first_projection.schedule_exhausted(),
        "every boundary in the seeded N-way schedule ran"
    );
    let terminals = [first_terminal, second_terminal, third_terminal];
    assert_eq!(
        terminals
            .iter()
            .filter(|terminal| matches!(terminal.outcome, DecisionOutcome::Committed { .. }))
            .count(),
        1,
        "N contenders for one pull request must leave exactly one committed terminal"
    );
    assert!(
        matches!(third_terminal.outcome, DecisionOutcome::Committed { .. }),
        "the last nested contender reaches the one real authority CAS first"
    );
    for terminal in [first_terminal, second_terminal] {
        assert!(
            matches!(
                terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::TargetRefMoved,
                    ..
                }
            ),
            "every stale contender receives the typed target-moved terminal"
        );
    }
    let HeadRead::Present(head) = store
        .read_head(&first_context.head_key)
        .expect("authority head remains readable after the N-way race")
    else {
        panic!("authority head cannot vanish during the N-way merge race");
    };
    let body: RepositoryAuthorityHeadBody =
        fgit_codec::decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT)
            .expect("N-way winner head decodes");
    let refs = commitments
        .resolve_ref_state(body.ref_root)
        .expect("N-way winner names staged canonical refs");
    assert_eq!(
        refs.refs()
            .get(&RefName::try_new(MAIN_REF).expect("fixture ref name")),
        Some(&oid(THIRD_MERGE_OID)),
        "the published ref state belongs wholly to the one winning contender"
    );
}

#[test]
fn lost_merge_response_retries_to_the_one_committed_terminal() {
    let (context, store, production, commitments) = repository();
    let package = package(FIRST_MERGE_OID);
    let attempt = attempt();
    let closure = closure(FIRST_MERGE_OID);
    let sealed = sealed(&package, &attempt, &closure);
    let path = SyncMergeAdmissionPath {
        store: store.as_ref(),
        projection: &production,
        commitments: &commitments,
    };

    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseResponse,
    )]));
    let interrupted = path.admit(&context, &sealed);
    assert!(
        interrupted.is_err(),
        "a lost post-CAS response must not invent a terminal result: {interrupted:?}"
    );
    assert!(
        !store.is_crashed(),
        "lost delivery is distinct from a crash and leaves the authority available"
    );
    let fired = store
        .fault_log()
        .records()
        .first()
        .copied()
        .expect("the planned lost response must be recorded");
    assert_eq!(fired.op_kind, AuthorityOpKind::CompareExchangeHead);
    assert!(
        fired.effect_reached,
        "the lost response drill only proves retry convergence when the CAS did publish"
    );

    store.install_fault_plan(FaultPlan::default());
    let recovered = path
        .admit(&context, &sealed)
        .expect("retry must resolve the terminal decision that survived the lost response");
    let replayed = path
        .admit(&context, &sealed)
        .expect("a second retry must recover the same one terminal decision");
    assert_eq!(
        recovered, replayed,
        "lost-response retries converge on one exact terminal outcome"
    );
    assert!(
        matches!(recovered.outcome, DecisionOutcome::Committed { .. }),
        "the recovered terminal is the one committed merge"
    );
    let HeadRead::Present(head) = store
        .read_head(&context.head_key)
        .expect("authority head remains readable after lost-response recovery")
    else {
        panic!("lost-response recovery cannot erase the authority head");
    };
    let body: RepositoryAuthorityHeadBody =
        fgit_codec::decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT)
            .expect("recovered authority head decodes");
    let refs = commitments
        .resolve_ref_state(body.ref_root)
        .expect("recovered head root names staged canonical refs");
    assert_eq!(
        refs.refs()
            .get(&RefName::try_new(MAIN_REF).expect("fixture ref name")),
        Some(&oid(FIRST_MERGE_OID)),
        "a lost response cannot expose a partial merge ref state"
    );
}

/// The synchronous merge seam has one authority publication operation.  This
/// test drills its before-effect crash point; the paired after-effect point is
/// below.  Durable staging and outbox publication are deliberately not claimed
/// until asa3 owns and exposes those publication points.
#[test]
fn crash_before_merge_cas_leaves_the_sealed_merge_undecided_for_retry() {
    let (context, store, production, commitments) = repository();
    let package = package(FIRST_MERGE_OID);
    let attempt = attempt();
    let closure = closure(FIRST_MERGE_OID);
    let sealed = sealed(&package, &attempt, &closure);
    let path = SyncMergeAdmissionPath {
        store: store.as_ref(),
        projection: &production,
        commitments: &commitments,
    };

    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::Crash {
            position: FaultPosition::BeforeEffect,
        },
    )]));
    let interrupted = path.admit(&context, &sealed);
    assert!(
        interrupted.is_err(),
        "a pre-effect crash cannot return a terminal result: {interrupted:?}"
    );
    assert!(store.is_crashed(), "the planned pre-CAS crash must fire");
    let fired = store
        .fault_log()
        .records()
        .first()
        .copied()
        .expect("the planned pre-CAS crash must be recorded");
    assert_eq!(fired.op_kind, AuthorityOpKind::CompareExchangeHead);
    assert!(
        !fired.effect_reached,
        "the before-effect counterpart must prove no authority publication happened"
    );

    store.restart();
    let HeadRead::Present(head) = store
        .read_head(&context.head_key)
        .expect("restarted authority head remains readable")
    else {
        panic!("a pre-effect crash cannot erase the authority head");
    };
    assert_eq!(
        head.generation(),
        HeadGeneration::FIRST,
        "the pre-effect crash leaves the authority head at genesis"
    );

    store.install_fault_plan(FaultPlan::default());
    let recovered = path
        .admit(&context, &sealed)
        .expect("the exact sealed merge remains retryable after a pre-CAS crash");
    assert!(
        matches!(recovered.outcome, DecisionOutcome::Committed { .. }),
        "the retry publishes the one complete merge terminal"
    );
}

/// A crash after the merge CAS applied leaves an ambiguous caller, not a
/// half-publication.
///
/// The fault uses an operation-kind ordinal, not an absolute operation index:
/// sealing and snapshot reads may gain implementation detail without moving
/// the semantic point under test.  `CompareExchangeHead` is the authority
/// publication boundary, and the fault log below proves that the chosen fault
/// actually landed after that effect.
#[test]
fn crash_after_merge_cas_recovers_the_same_terminal_and_complete_ref_state() {
    let (context, store, production, commitments) = repository();
    let package = package(FIRST_MERGE_OID);
    let attempt = attempt();
    let closure = closure(FIRST_MERGE_OID);
    let sealed = sealed(&package, &attempt, &closure);
    let path = SyncMergeAdmissionPath {
        store: store.as_ref(),
        projection: &production,
        commitments: &commitments,
    };

    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::Crash {
            position: FaultPosition::AfterEffect,
        },
    )]));
    let interrupted = path.admit(&context, &sealed);
    assert!(
        interrupted.is_err(),
        "a post-effect crash must hide the terminal response from its caller: {interrupted:?}"
    );
    assert!(
        store.is_crashed(),
        "the planned publication crash must fire"
    );
    let fired = store
        .fault_log()
        .records()
        .first()
        .copied()
        .expect("the planned crash must be recorded");
    assert!(
        fired.effect_reached,
        "the crash drill is only meaningful after the head CAS applied"
    );

    store.restart();
    store.install_fault_plan(FaultPlan::default());
    let recovered = path
        .admit(&context, &sealed)
        .expect("retry after restart resolves the already-published terminal decision");
    let replayed = path
        .admit(&context, &sealed)
        .expect("a second retry recovers the same already-published terminal decision");
    assert_eq!(
        recovered, replayed,
        "post-effect crash recovery converges on one exact terminal outcome"
    );
    assert!(
        matches!(recovered.outcome, DecisionOutcome::Committed { .. }),
        "the post-effect crash must recover the committed merge, not publish a second decision"
    );

    let HeadRead::Present(head) = store
        .read_head(&context.head_key)
        .expect("restarted authority head remains readable")
    else {
        panic!("a crash cannot erase the published authority head");
    };
    let body: RepositoryAuthorityHeadBody =
        fgit_codec::decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT)
            .expect("recovered authority head decodes");
    let refs = commitments
        .resolve_ref_state(body.ref_root)
        .expect("recovered head root names staged canonical state");
    assert_eq!(
        refs.refs()
            .get(&RefName::try_new(MAIN_REF).expect("fixture ref name")),
        Some(&oid(FIRST_MERGE_OID)),
        "recovery exposes the complete committed ref movement, never a half merge"
    );
}
