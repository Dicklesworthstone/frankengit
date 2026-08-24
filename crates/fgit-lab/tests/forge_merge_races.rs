//! A controlled merge-admission race against the real authority path.
//!
//! This is deliberately a consumer of `fgit-admission`'s public merge API,
//! `MemoryAuthorityStore`, and `CanonicalAdmissionProjection`.  The schedule
//! controls the real boundary between candidate A's authenticated snapshot and
//! its head CAS; it is not a test-local merge state machine.
//!
//! The campaign establishes one race schedule only.  It does not claim forge
//! position advancement, outbox redelivery, crash recovery, or projection
//! rebuild: the current admission route explicitly carries those roots forward
//! pending their owning production paths.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use fgit_admission::merge::{SealedMerge, admit_merge};
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
use fgit_forge::event::ForgeEvent;
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
            let terminal = admit_merge(
                self.store.as_ref(),
                &self.rival.context,
                &self.rival.sealed,
                AdmissionLimits::default(),
                &self.production,
                &self.commitments,
            )
            .expect("scheduled rival reaches one terminal decision");
            self.rival_terminal.borrow_mut().replace(terminal);
            self.step("merge-a");
        }
        Ok(snapshot)
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

    let loser = admit_merge(
        store.as_ref(),
        &first_context,
        &sealed(&first_package, &attempt, &first_closure),
        AdmissionLimits::default(),
        &scheduled,
        &commitments,
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

    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::Crash {
            position: FaultPosition::AfterEffect,
        },
    )]));
    let interrupted = admit_merge(
        store.as_ref(),
        &context,
        &sealed,
        AdmissionLimits::default(),
        &production,
        &commitments,
    );
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
    let recovered = admit_merge(
        store.as_ref(),
        &context,
        &sealed,
        AdmissionLimits::default(),
        &production,
        &commitments,
    )
    .expect("retry after restart resolves the already-published terminal decision");
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
