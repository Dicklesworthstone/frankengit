//! Two merges race for one head, and exactly one wins.
//!
//! # Why this drives the real store and the real projection
//!
//! `MemoryAuthorityStore` is the reference profile of `AuthorityStore`, and its
//! contract note says the linearizability checker and the seal-race campaign run
//! against it. `CanonicalAdmissionProjection` is the production projection.
//! Driving both means the exactly-one-winner property is observed on the surface
//! the swarm already verifies with, rather than on a private imitation — which
//! is the objection that justified this bead existing: a test-local state machine
//! would only simulate the production path, and `AGENTS.md` forbids that as
//! evidence.
//!
//! # What makes these two attempts a race rather than a retry
//!
//! Both merges are computed against the same target tip, and they produce
//! *different* merge commits. That gives them different ref commands, so
//! different sealed transactions and different `TxId`s. Two attempts sharing one
//! sealed request would be a retry, and the idempotency probe would return the
//! first one's outcome — which is correct behaviour and a different test.

use std::collections::{BTreeMap, BTreeSet};

use std::cell::RefCell;
use std::rc::Rc;

use fgit_admission::merge::{ForgeBodyStore, SealedMerge, admit_merge};
use fgit_admission::{
    AdmissionContext, AdmissionEvidence, AdmissionLimits, CanonicalAdmissionProjection,
    CanonicalAdmissionStore, CanonicalRefState, CommitEvidence, PermittedObjectClosure,
    RefusalMaterialization, ValidatedClosure, canonical_ref_state_root,
    initialize_canonical_repository,
};
use fgit_authority::{
    AuthorityOpKind, AuthorityStore, FaultDirective, FaultKind, FaultPlan, FaultableAuthorityStore,
    HeadKey, HeadRead, IdempotencyKey, MemoryAuthorityStore, StoreInstanceId,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_forge::event::{ForgeEvent, ForgeEventBatch};
use fgit_forge::{
    AggregateVersion, ForgeEventPayload, MergeAttempt, MergeEffectPackage, PullRequestNumber,
    RefIntent, WorkspaceEpoch,
};
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

// ---------------------------------------------------------------------------
// Fixtures, mirroring pinned_snapshot_toctou.rs rather than importing from it:
// a test binary cannot import another test binary's items.
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
    context_for(b"asa3-merge-session")
}

/// One admission session.
///
/// The key is a parameter because two concurrent merges are two SESSIONS, not
/// one session retried. Sharing a key across requests that seal to different
/// transactions is refused as `IdempotencyKeyReuse`, and rightly: section 5.2
/// says key reuse with different semantics fails closed. This test learned that
/// from the seal path rather than assuming it.
fn context_for(key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"fg/head/asa3-merge-race".to_vec()).expect("valid head key"),
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
            detail: "asa3 merge race refusal".to_owned(),
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

// ---------------------------------------------------------------------------
// The merge under test
// ---------------------------------------------------------------------------

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
    let mut objects = BTreeSet::new();
    objects.insert(oid(merge_commit));
    let permitted = PermittedObjectClosure::new(objects.clone());
    ValidatedClosure {
        object_closure_root: fgit_admission::permitted_object_closure_root(&permitted)
            .expect("closure root"),
        objects,
    }
}

/// A repository whose `main` holds the tip both merges were computed against.
fn repository() -> (
    AdmissionContext,
    Rc<MemoryAuthorityStore>,
    Projection,
    Store,
) {
    let context = context();
    let commitments = Store::default();
    let projection = CanonicalAdmissionProjection::new(commitments.clone(), Evidence);
    let mut refs = BTreeMap::new();
    refs.insert(
        RefName::try_new(MAIN_REF).expect("fixture ref name"),
        oid(TARGET_OID),
    );
    refs.insert(
        RefName::try_new(FEATURE_REF).expect("fixture ref name"),
        oid(SOURCE_OID),
    );
    let store = Rc::new(MemoryAuthorityStore::new(StoreInstanceId::from_raw(41)));
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

type Projection = CanonicalAdmissionProjection<Store, Evidence>;

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

// ---------------------------------------------------------------------------
// Drills
// ---------------------------------------------------------------------------

/// The permitted case, and FG-029a's acceptance line 1 observed end to end.
///
/// Until this bead the claim "the merge RCR carries both the ref delta and the
/// `MergeCommitted` event" was a structural property of a record built inside a
/// test. Here the record goes through the real seal, the real projection and a
/// real head CAS, and the property is read back off the committed decision.
#[test]
fn a_single_merge_attempt_commits_and_its_record_carries_both_roots() {
    let (context, store, projection, commitments) = repository();
    let package = package(FIRST_MERGE_OID);
    let attempt = attempt();
    let closure = closure(FIRST_MERGE_OID);

    let terminal = admit_merge(
        store.as_ref(),
        &context,
        &sealed(&package, &attempt, &closure),
        AdmissionLimits::default(),
        &projection,
        &commitments,
    )
    .expect("a fresh merge is admitted");

    match terminal.outcome {
        DecisionOutcome::Committed { .. } => {}
        refused @ DecisionOutcome::Refused { .. } => {
            panic!("a fresh merge must commit, got {refused:?}")
        }
    }

    // The head moved to the merge commit, which is the ref delta having been
    // published rather than merely proposed.
    let HeadRead::Present(head) = store.read_head(&context.head_key).expect("head reads") else {
        panic!("the repository head must exist after genesis");
    };
    let body: RepositoryAuthorityHeadBody =
        fgit_codec::decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT)
            .expect("head body decodes");
    assert!(
        body.generation > HeadGeneration::FIRST,
        "a committed merge must advance the head generation"
    );

    // THE FORGE HALF, read back off the committed decision rather than assumed.
    //
    // CobaltForest's third finding on this bead was that the head-generation
    // assertion above establishes the ref delta by EFFECT while the
    // MergeCommitted event was asserted nowhere -- the drill closed on
    // `Committed { .. }` and discarded the payload, and `MergeCommitted` appeared
    // in this file only in the fixture that built it. That was accurate. So the
    // event now has to survive the same round trip the ref delta does.
    let tail = body
        .decision_tail_id
        .expect("a committed decision leaves a decision tail on the head");
    let batch = fgit_authority::read_decision_batch_body(store.as_ref(), tail)
        .expect("the decision batch the head points at is readable");
    let [record] = batch.committed_rcrs.as_slice() else {
        panic!(
            "one merge commits one record, got {}",
            batch.committed_rcrs.len()
        )
    };

    // The record's root is the package's own canonical event-batch root, so the
    // record commits to the author's bytes rather than to a reconstruction.
    let expected = package
        .roots(&fgit_codec::CryptoBodyIdentity)
        .expect("the package has canonical roots");
    assert_eq!(
        record.forge_event_batch_root, expected.forge_event_batch_root,
        "the committed record must commit to the package's own event batch"
    );

    // And the bytes under that root must actually be resolvable. Before the
    // event body was staged this resolve returned EvidenceMissing: the record
    // named an identity nothing had put anywhere, which is the same defect the
    // race drill caught on the ref side.
    let staged = commitments
        .resolve_forge_event_batch(record.forge_event_batch_root)
        .expect("the committed event batch resolves from what admission staged");
    assert_eq!(
        staged,
        ForgeEventBatch::of_one(package.event.clone()),
        "the staged batch must be the MergeCommitted event the author sealed"
    );
    assert!(
        matches!(
            package.event.payload,
            ForgeEventPayload::MergeCommitted { .. }
        ),
        "and the drill is only meaningful if that event is a merge commit"
    );
}

/// Two merges, one head, exactly one winner — and the loser is typed.
///
/// The loser does not spin and does not retry against a state its merge was
/// never computed for: it loses the CAS, replans, re-reads the basis, finds the
/// target holding the winner's merge commit, and publishes `TargetRefMoved` as
/// its own terminal decision.
#[test]
fn two_merges_race_for_one_head_and_exactly_one_wins() {
    let (context, store, projection, commitments) = repository();

    let winner_package = package(FIRST_MERGE_OID);
    let winner_closure = closure(FIRST_MERGE_OID);
    let attempt = attempt();
    let winner = admit_merge(
        store.as_ref(),
        &context,
        &sealed(&winner_package, &attempt, &winner_closure),
        AdmissionLimits::default(),
        &projection,
        &commitments,
    )
    .expect("the first merge is admitted");
    assert!(
        matches!(winner.outcome, DecisionOutcome::Committed { .. }),
        "the first merge must win the head"
    );

    // The rival was computed against the SAME target tip and produces a
    // different merge commit, so it is a different sealed transaction rather
    // than a retry of the first.
    let rival_package = package(RIVAL_MERGE_OID);
    let rival_closure = closure(RIVAL_MERGE_OID);
    // A different session: see context_for. Reusing the winner's key here is
    // refused as IdempotencyKeyReuse, which is the seal path enforcing 5.2 on
    // the merge route too -- correct behaviour, and a retry rather than a race.
    let rival_context = context_for(b"asa3-merge-rival-session");
    let loser = admit_merge(
        store.as_ref(),
        &rival_context,
        &sealed(&rival_package, &attempt, &rival_closure),
        AdmissionLimits::default(),
        &projection,
        &commitments,
    )
    .expect("the losing merge still reaches a terminal decision");

    match loser.outcome {
        DecisionOutcome::Refused { code, .. } => assert_eq!(
            code,
            RefusalCode::TargetRefMoved,
            "the loser must be refused for the reason it actually lost"
        ),
        committed @ DecisionOutcome::Committed { .. } => {
            panic!("only one merge may commit, got {committed:?} for the second")
        }
    }

    assert_ne!(
        winner.decision_sequence, loser.decision_sequence,
        "both attempts consume decision sequence; a refusal is a decision"
    );
}

/// A merge whose workspace advanced is refused before it can publish.
///
/// The two ref tips are exactly where the merge was computed against, so the
/// ref axes pass and only the workspace has moved. That isolation is the point:
/// a case that also moved a tip would pass on a build that ignored the epoch.
#[test]
fn a_merge_whose_workspace_advanced_is_refused_and_the_same_one_at_its_epoch_is_not() {
    let (context, store, projection, commitments) = repository();
    let package = package(FIRST_MERGE_OID);
    let attempt = attempt();
    let closure = closure(FIRST_MERGE_OID);

    let mut stale = sealed(&package, &attempt, &closure);
    stale.workspace_epoch_now = WorkspaceEpoch::from_u64(10);
    let refused = admit_merge(
        store.as_ref(),
        &context,
        &stale,
        AdmissionLimits::default(),
        &projection,
        &commitments,
    )
    .expect("a stale merge still reaches a terminal decision");
    match refused.outcome {
        DecisionOutcome::Refused { code, .. } => assert_eq!(
            code,
            RefusalCode::EvidenceStale,
            "a tree computed in a workspace that has since advanced names superseded evidence"
        ),
        committed @ DecisionOutcome::Committed { .. } => {
            panic!("an advanced workspace must be refused, got {committed:?}")
        }
    }

    // The head did not move: a refusal consumes decision sequence and nothing
    // else, so the merge that was refused left no half-published state.
    let HeadRead::Present(head) = store.read_head(&context.head_key).expect("head reads") else {
        panic!("the repository head must exist after genesis");
    };
    let body: RepositoryAuthorityHeadBody =
        fgit_codec::decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT)
            .expect("head body decodes");
    assert_eq!(
        body.ref_root,
        canonical_ref_state_root(&{
            let mut refs = BTreeMap::new();
            refs.insert(
                RefName::try_new(MAIN_REF).expect("fixture ref name"),
                oid(TARGET_OID),
            );
            refs.insert(
                RefName::try_new(FEATURE_REF).expect("fixture ref name"),
                oid(SOURCE_OID),
            );
            CanonicalRefState::new(refs)
        })
        .expect("original ref root"),
        "a refused merge must leave the ref state exactly as it found it"
    );
}

/// A lost response at the head CAS leaves no half-merged state.
///
/// This is the crash-matrix shape for a merge: the compare-and-exchange is
/// attempted and the caller never learns what happened. §5.2 is explicit that a
/// client's cancellation or disconnect never proves non-commit, so the property
/// under test is not "the merge did not happen" — it is that the repository is
/// in ONE of two consistent states and never between them, and that the same
/// sealed merge retried resolves to the SAME decision rather than merging twice.
///
/// The fault is addressed by operation KIND rather than by absolute index.
/// Aiming a crash drill by index at whichever operation happens to be third
/// gives a drill that passes while testing something else entirely.
#[test]
fn a_lost_response_at_the_cas_leaves_no_half_merged_state() {
    let (context, store, projection, commitments) = repository();
    let package = package(FIRST_MERGE_OID);
    let attempt = attempt();
    let closure = closure(FIRST_MERGE_OID);

    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        0,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseResponse,
    )]));
    let ambiguous = admit_merge(
        store.as_ref(),
        &context,
        &sealed(&package, &attempt, &closure),
        AdmissionLimits::default(),
        &projection,
        &commitments,
    );

    // The fault must actually have fired. A crash drill whose injection never
    // reached the operation it named would pass trivially -- the merge would
    // simply commit, the retry would resolve through the idempotency probe, and
    // every assertion below would hold while testing nothing at all.
    let injected = store.fault_log();
    assert!(
        !injected.records().is_empty(),
        "the lost-response fault never fired, so this drill exercised no crash"
    );

    // The head is either where genesis left it or exactly one generation on.
    // Anything else is a half-published merge.
    store.install_fault_plan(FaultPlan::none());
    let HeadRead::Present(head) = store.read_head(&context.head_key).expect("head reads") else {
        panic!("the repository head must still exist after an ambiguous response");
    };
    let after_crash = head.generation();
    assert!(
        after_crash == HeadGeneration::FIRST
            || after_crash
                == HeadGeneration::FIRST
                    .next()
                    .expect("a successor generation"),
        "an ambiguous CAS left the head at neither its old nor its next generation: {after_crash:?}"
    );

    // The retry is the same sealed merge: same session key, so the same TxId.
    // Whatever the first attempt did, this must agree with it rather than
    // publish a second merge.
    let retried = admit_merge(
        store.as_ref(),
        &context,
        &sealed(&package, &attempt, &closure),
        AdmissionLimits::default(),
        &projection,
        &commitments,
    )
    .expect("the retry of a sealed merge reaches a terminal decision");

    if let Ok(first) = ambiguous {
        assert_eq!(
            first, retried,
            "a retry after a lost response must resolve to the decision already made, \
             not make a new one"
        );
    }

    let HeadRead::Present(head) = store.read_head(&context.head_key).expect("head reads") else {
        panic!("the repository head must exist after the retry");
    };
    assert_eq!(
        head.generation(),
        HeadGeneration::FIRST
            .next()
            .expect("a successor generation"),
        "the merge published exactly once across the crash and the retry"
    );
}
