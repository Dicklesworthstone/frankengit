//! FG-007b logical seal/outcome race coverage over the frozen authority surface.
//!
//! `MemoryAuthorityStore` is the authority reference/laboratory profile, not a
//! durable deployment backend.  The schedules below therefore establish only
//! the documented logical-store and fault-injection properties.  In
//! particular, the synchronous authority API exposes cancellation as a typed
//! ambiguous caller result; native request-drain-finalize behaviour belongs to
//! the runtime adapter's own campaign.

use fgit_authority::{
    AmbiguityReason, AuthorityFailure, AuthorityOpKind, AuthorityStore, ExpectedOld,
    FaultDirective, FaultKind, FaultPlan, FaultPosition, FaultableAuthorityStore, HeadKey,
    HeadRead, IdempotencyKey, MemoryAuthorityStore, OpIndex, OutcomeLookup, ProposedNew,
    PublicationOutcome, RefCommand, RequestRejection, SealAdmission, SealAttempt, SealFailure,
    SemanticRequest, StoreInstanceId, TerminalOutcome, canonical_body_id, indexed_outcome,
    initialize_repository, publish_decisions, read_seal, replay_outcome, resolve_outcome,
    seal_request,
};
use fgit_codec::{RepositoryAuthorityHeadBody, RepositoryDecision, RepositoryDecisionBatchBody};
use fgit_crypto::IdentityDomain;
use fgit_lab::commute::{OwnedEvent, ProtocolEvent};
use fgit_lab::{Dpor, ExplorationBudget, LabSchedule, Program, StepId};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{
    PrincipalId, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, TenantId, TxId,
};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::{DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::DecisionOutcome;

const DEFAULT_RACE_SEED: u64 = 0xF007_B001;
const DPOR_BUDGET: ExplorationBudget = ExplorationBudget::new(32, 256);

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

fn race_seed() -> u64 {
    let supplied = std::env::var("FGIT_SEAL_RACE_SEED").unwrap_or_default();
    let raw = supplied.trim();
    if raw.is_empty() {
        return DEFAULT_RACE_SEED;
    }
    let (digits, radix) = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .map_or((raw, 10), |hex| (hex, 16));
    u64::from_str_radix(digits, radix)
        .unwrap_or_else(|_| panic!("FGIT_SEAL_RACE_SEED must be a u64, observed {raw:?}"))
}

fn authority_head_key() -> HeadKey {
    HeadKey::new(b"fg/head/v1/seal-races/repo-22".to_vec()).expect("an admissible head key")
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn commit_id(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn genesis_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0),
        forge_position_root: digest(0),
        outcome_index_root: digest(0),
        retention_root: digest(0),
        outbox_root: digest(0),
        configuration_root: digest(0),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn head_id_of(head: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_internal_object_id(
        canonical_body_id(
            IdentityDomain::RepositoryAuthorityHead,
            CANONICAL_CODEC_VERSION,
            head,
        )
        .expect("a derivable head identity"),
    )
    .expect("the authority-head domain")
}

fn batch_id_of(batch: &RepositoryDecisionBatchBody) -> RepositoryDecisionBatchId {
    RepositoryDecisionBatchId::from_internal_object_id(
        canonical_body_id(
            IdentityDomain::RepositoryDecisionBatch,
            CANONICAL_CODEC_VERSION,
            batch,
        )
        .expect("a derivable batch identity"),
    )
    .expect("the decision-batch domain")
}

fn committed(tx_id: TxId, sequence: u64, commit: u8) -> RepositoryDecision {
    RepositoryDecision {
        tx_id,
        decision_sequence: DecisionSequence::try_new(sequence).expect("positive sequence"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: commit_id(commit),
        },
    }
}

fn batch(
    predecessor: &RepositoryAuthorityHeadBody,
    tx_id: TxId,
    sequence: u64,
    commit: u8,
) -> RepositoryDecisionBatchBody {
    RepositoryDecisionBatchBody {
        repository_id: repository(),
        predecessor_head_id: head_id_of(predecessor),
        predecessor_head_generation: predecessor.generation,
        first_decision_sequence: DecisionSequence::try_new(sequence).expect("positive sequence"),
        decisions: vec![committed(tx_id, sequence, commit)],
        committed_rcrs: Vec::new(),
        resulting_ref_root: digest(1),
        resulting_forge_position_root: digest(1),
        resulting_outcome_index_root: digest(1),
        resulting_retention_root: digest(1),
        resulting_outbox_root: digest(1),
        resulting_policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest(1),
    }
}

fn successor_head(
    predecessor: &RepositoryAuthorityHeadBody,
    tail: RepositoryDecisionBatchId,
    sequence: u64,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        generation: HeadGeneration::try_new(predecessor.generation.get() + 1)
            .expect("positive generation"),
        predecessor_head_id: Some(head_id_of(predecessor)),
        decision_tail_id: Some(tail),
        latest_decision_sequence: Some(DecisionSequence::try_new(sequence).expect("positive")),
        ..predecessor.clone()
    }
}

fn prepare_publication(
    store: &MemoryAuthorityStore,
    tx_id: TxId,
) -> (
    fgit_authority::AuthorityVersionToken,
    RepositoryDecisionBatchBody,
    RepositoryAuthorityHeadBody,
) {
    let genesis = genesis_head();
    initialize_repository(store, &authority_head_key(), &genesis).expect("genesis publication");
    let HeadRead::Present(receipt) = store
        .read_head(&authority_head_key())
        .expect("a readable genesis head")
    else {
        panic!("genesis must be visible");
    };
    let decision_batch = batch(&genesis, tx_id, 1, 0x51);
    let decision_head = successor_head(&genesis, batch_id_of(&decision_batch), 1);
    (receipt.token(), decision_batch, decision_head)
}

fn expected_commit(sequence: u64, commit: u8) -> OutcomeLookup {
    OutcomeLookup::Decided(TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(sequence).expect("positive sequence"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: commit_id(commit),
        },
    })
}

fn is_lost_authority_response(failure: &fgit_authority::OutcomeFailure) -> bool {
    matches!(
        failure,
        fgit_authority::OutcomeFailure::Seal(boxed)
            if matches!(boxed.as_ref(), SealFailure::Store(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse)))
    )
}

fn attempt(key: &[u8], oid: u8) -> SealAttempt {
    SealAttempt {
        tenant_id: tenant(),
        repository_id: repository(),
        authenticated_principal_id: PrincipalId::from_bytes([0x33; 16]),
        idempotency_key: IdempotencyKey::new(key.to_vec()).expect("bounded key"),
        request: SemanticRequest::build(
            SchemaId::new(SchemaFamily::from_static("receive-pack"), 1, 0),
            GitHashAlgorithm::Sha1,
            true,
            vec![RefCommand {
                name: RefName::try_new(b"refs/heads/main").expect("ref"),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(GitOid::Sha1(GitOidSha1::from_bytes([oid; 20]))),
                force: false,
            }],
            Vec::new(),
            Vec::new(),
        )
        .expect("request"),
    }
}

#[test]
fn dpor_explores_every_duplicate_seal_race_class() {
    // This is the authority-visible projection of two gateway submissions. The
    // real seal operation first binds the key and then creates the seal; both
    // submissions therefore conflict on the same immutable identity slot.
    let program = Program::new(vec![
        (
            StepId::new("gateway-a"),
            vec![ProtocolEvent::SealPut {
                key: "fg/idem/v1/same-key".to_owned(),
            }],
        ),
        (
            StepId::new("gateway-b"),
            vec![ProtocolEvent::SealPut {
                key: "fg/idem/v1/same-key".to_owned(),
            }],
        ),
    ])
    .expect("distinct gateways form a program");

    let outcome = Dpor::new().explore(
        &program,
        DPOR_BUDGET,
        "one_seal_identity_per_idempotency_key",
        |sequence: &[OwnedEvent]| {
            let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7007));
            let first = attempt(b"same-key", 0xA1);
            let second = first.clone();
            let mut created = 0_usize;
            let mut identity = None;
            for step in sequence {
                let request = match step.actor.as_str() {
                    "gateway-a" => &first,
                    "gateway-b" => &second,
                    unexpected => return Err(format!("unexpected participant {unexpected}")),
                };
                match seal_request(&store, request).map_err(|failure| failure.to_string())? {
                    SealAdmission::Created { tx_id, .. } => {
                        created += 1;
                        identity = Some(tx_id);
                    }
                    SealAdmission::IdenticalRetry { tx_id, .. } if Some(tx_id) == identity => {}
                    SealAdmission::IdenticalRetry { tx_id, .. } => {
                        return Err(format!("retry returned a different identity {tx_id:?}"));
                    }
                }
            }
            if created != 1 {
                return Err(format!("observed {created} created seals"));
            }
            let tx_id = identity.ok_or_else(|| "no created seal".to_owned())?;
            if read_seal(&store, tenant(), repository(), tx_id)
                .map_err(|failure| failure.to_string())?
                .is_none()
            {
                return Err("the sole admitted identity was not readable".to_owned());
            }
            Ok(())
        },
    );

    assert!(
        outcome.is_exhaustive(),
        "same-key seal submissions conflict, so DPOR must explore both orders: {outcome:?}"
    );
    assert_eq!(
        outcome.classes(),
        2,
        "the two conflicting submissions order"
    );
}

#[test]
fn retry_storm_under_a_logged_seed_has_one_identity() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7007));
    let seed = race_seed();
    println!("fgit.seal-race.seed={seed}");
    let schedule = LabSchedule::seeded(
        vec![StepId::new("gateway-a"), StepId::new("gateway-b")],
        32,
        seed,
    )
    .expect("schedule");
    assert!(
        schedule.canonical_line().contains(&format!("seed={seed}")),
        "the receipt must preserve the replay seed"
    );
    let first = attempt(b"same-key", 0xA1);
    let second = first.clone();
    let mut created = 0;
    let mut tx = None;
    for step in schedule.order() {
        let request = if step.as_str() == "gateway-a" {
            &first
        } else {
            &second
        };
        match seal_request(&store, request).expect("identical retry is admissible") {
            SealAdmission::Created { tx_id, .. } => {
                created += 1;
                tx = Some(tx_id);
            }
            SealAdmission::IdenticalRetry { tx_id, .. } => assert_eq!(Some(tx_id), tx),
        }
    }
    assert_eq!(created, 1, "one seal body owns the logical identity");
}

#[test]
fn tampered_retry_is_a_predecision_refusal_not_a_second_identity() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7008));
    let original = attempt(b"same-key", 0xA1);
    let tampered = attempt(b"same-key", 0xB2);
    let admitted = seal_request(&store, &original).expect("first seal");
    let SealFailure::Rejected(rejection) = seal_request(&store, &tampered).expect_err("reuse")
    else {
        panic!("expected rejection");
    };
    let RequestRejection::IdempotencyKeyReuse { bound, attempted } = *rejection;
    assert_eq!(bound, admitted.tx_id());
    assert_ne!(bound, attempted);
    assert!(
        read_seal(&store, tenant(), repository(), attempted)
            .expect("tampered transaction lookup")
            .is_none(),
        "the rejected body must not leave a second seal"
    );
}

#[test]
fn crash_after_seal_before_decision_preserves_a_retryable_undecided_transaction() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7009));
    let request = attempt(b"crash-between-seal-and-decision", 0xA1);
    let admitted = seal_request(&store, &request).expect("seal before the crash");
    let genesis = genesis_head();
    initialize_repository(&store, &authority_head_key(), &genesis).expect("genesis publication");

    store.install_fault_plan(FaultPlan::explicit(vec![FaultDirective::new(
        OpIndex::ZERO,
        FaultKind::Crash {
            position: FaultPosition::BeforeEffect,
        },
    )]));
    let failure = read_seal(&store, tenant(), repository(), admitted.tx_id())
        .expect_err("the endpoint crashes before the first post-seal operation");
    assert!(matches!(
        failure,
        SealFailure::Store(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse))
    ));
    assert!(store.is_crashed());
    assert_eq!(
        store.fault_log().records().len(),
        1,
        "the fault transcript carries the crash receipt"
    );

    store.restart();
    store.install_fault_plan(FaultPlan::none());
    assert!(
        read_seal(&store, tenant(), repository(), admitted.tx_id())
            .expect("the complete seal survives the process crash")
            .is_some()
    );
    assert_eq!(
        resolve_outcome(
            &store,
            &authority_head_key(),
            tenant(),
            repository(),
            admitted.tx_id(),
        )
        .expect("the undecided answer is queryable after restart"),
        OutcomeLookup::Undecided,
        "sealing alone must not fabricate a terminal decision"
    );
}

#[test]
fn lost_cas_response_retries_to_the_same_replayed_terminal_outcome() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7010));
    let request = attempt(b"lost-cas-response", 0xA1);
    let admitted = seal_request(&store, &request).expect("seal");
    let (expected, decision_batch, decision_head) = prepare_publication(&store, admitted.tx_id());

    // `publish_decisions` has two immutable stages followed by the authority
    // CAS.  This injects the loss *after* that third operation's effect.
    store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::from_raw(2), FaultKind::LoseResponse)
            .only_for(AuthorityOpKind::CompareExchangeHead),
    ]));
    let failure = publish_decisions(
        &store,
        &authority_head_key(),
        expected,
        &decision_batch,
        &decision_head,
        tenant(),
    )
    .expect_err("a CAS response is deliberately lost");
    assert!(is_lost_authority_response(&failure));
    let fault = store
        .fault_log()
        .records()
        .first()
        .copied()
        .expect("the planned loss fires");
    assert_eq!(fault.kind, FaultKind::LoseResponse);
    assert!(
        fault.effect_reached,
        "the CAS reached its linearization point"
    );

    // The error exits before accelerator indexing.  This is the recovery
    // shape of a wiped/behind accelerator: absence is repairable, never proof
    // of a non-commit.
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), admitted.tx_id()).expect("index lookup"),
        OutcomeLookup::Undecided
    );
    let recovered = resolve_outcome(
        &store,
        &authority_head_key(),
        tenant(),
        repository(),
        admitted.tx_id(),
    )
    .expect("replay must recover the authority-stream outcome");
    assert_eq!(recovered, expected_commit(1, 0x51));

    // The old predecessor token cannot make another decision.  A retry learns
    // that its publication raced, then converges by TxId lookup on the same
    // already-terminal answer.
    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        publish_decisions(
            &store,
            &authority_head_key(),
            expected,
            &decision_batch,
            &decision_head,
            tenant(),
        )
        .expect("a stale retry has a typed loss outcome"),
        PublicationOutcome::PredecessorMismatch
    );
    assert_eq!(
        replay_outcome(&store, &authority_head_key(), admitted.tx_id()).expect("stream replay"),
        recovered
    );
    assert_eq!(
        resolve_outcome(
            &store,
            &authority_head_key(),
            tenant(),
            repository(),
            admitted.tx_id(),
        )
        .expect("retry converges by TxId"),
        recovered
    );
}

#[test]
fn crash_after_cas_restarts_to_the_same_terminal_outcome_without_an_index_entry() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7011));
    let request = attempt(b"crash-after-cas", 0xA1);
    let admitted = seal_request(&store, &request).expect("seal");
    let (expected, decision_batch, decision_head) = prepare_publication(&store, admitted.tx_id());

    store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(
            OpIndex::from_raw(2),
            FaultKind::Crash {
                position: FaultPosition::AfterEffect,
            },
        )
        .only_for(AuthorityOpKind::CompareExchangeHead),
    ]));
    let failure = publish_decisions(
        &store,
        &authority_head_key(),
        expected,
        &decision_batch,
        &decision_head,
        tenant(),
    )
    .expect_err("crash after CAS hides the outcome from the caller");
    assert!(is_lost_authority_response(&failure));
    assert!(store.is_crashed());
    let fault = store
        .fault_log()
        .records()
        .first()
        .copied()
        .expect("the planned crash fires");
    assert!(fault.effect_reached, "the crash lands after the CAS effect");

    store.restart();
    store.install_fault_plan(FaultPlan::none());
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), admitted.tx_id())
            .expect("behind index lookup"),
        OutcomeLookup::Undecided,
        "the crash leaves no accelerator entry to trust"
    );
    assert_eq!(
        resolve_outcome(
            &store,
            &authority_head_key(),
            tenant(),
            repository(),
            admitted.tx_id(),
        )
        .expect("restart recovers through the authority stream"),
        expected_commit(1, 0x51)
    );
}

#[test]
fn rejected_second_terminal_decision_never_becomes_canonical() {
    // EXPECTED-RED (FG-007b): this documents a confirmed authority invariant
    // violation. Keep the assertion failing until publication atomically binds
    // outcome entries with the successor-head CAS; a pre-CAS lookup is TOCTOU.
    // A conflict response alone is insufficient: because the authority head is
    // the only publication point, an attempted duplicate must leave both the
    // current head and authenticated replay on the first terminal outcome.
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7015));
    let request = attempt(b"one-terminal-decision", 0xA1);
    let admitted = seal_request(&store, &request).expect("seal");
    let (expected, first_batch, first_head) = prepare_publication(&store, admitted.tx_id());
    assert!(matches!(
        publish_decisions(
            &store,
            &authority_head_key(),
            expected,
            &first_batch,
            &first_head,
            tenant(),
        )
        .expect("first terminal decision"),
        PublicationOutcome::Published(_)
    ));

    let HeadRead::Present(receipt) = store
        .read_head(&authority_head_key())
        .expect("the first successor is readable")
    else {
        panic!("first successor must be visible");
    };
    let duplicate_batch = batch(&first_head, admitted.tx_id(), 2, 0x52);
    let duplicate_head = successor_head(&first_head, batch_id_of(&duplicate_batch), 2);
    let duplicate = publish_decisions(
        &store,
        &authority_head_key(),
        receipt.token(),
        &duplicate_batch,
        &duplicate_head,
        tenant(),
    );
    assert!(
        duplicate.is_err(),
        "a second terminal decision for one TxId must be refused"
    );
    assert_eq!(
        replay_outcome(&store, &authority_head_key(), admitted.tx_id())
            .expect("the authority stream remains unambiguous"),
        expected_commit(1, 0x51),
        "a rejected duplicate must not have crossed the head-CAS boundary"
    );
    assert_eq!(
        resolve_outcome(
            &store,
            &authority_head_key(),
            tenant(),
            repository(),
            admitted.tx_id(),
        )
        .expect("the terminal answer stays resolvable"),
        expected_commit(1, 0x51)
    );
}

#[test]
fn missing_accelerator_after_a_lost_response_cannot_admit_a_second_terminal() {
    // EXPECTED-RED (FG-007b): this is intentionally failing against the known
    // non-atomic authority transition. Do not weaken it or make it pass with
    // an accelerator precheck; only the atomic publication fix closes the race.
    // This is the race a read-before-CAS check cannot close.  Publisher B's
    // CAS linearizes its decision, but its response is lost before the derived
    // accelerator write.  Publisher A then sees B's new head and an absent
    // accelerator; a non-atomic precheck would admit A's different decision
    // and create a second terminal decision in authenticated history.
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7016));
    let request = attempt(b"lost-response-then-duplicate", 0xA1);
    let admitted = seal_request(&store, &request).expect("seal");
    let (first_expected, first_batch, first_head) = prepare_publication(&store, admitted.tx_id());

    store.install_fault_plan(FaultPlan::explicit(vec![
        FaultDirective::new(OpIndex::from_raw(2), FaultKind::LoseResponse)
            .only_for(AuthorityOpKind::CompareExchangeHead),
    ]));
    let first_failure = publish_decisions(
        &store,
        &authority_head_key(),
        first_expected,
        &first_batch,
        &first_head,
        tenant(),
    )
    .expect_err("the first caller loses its post-CAS response");
    assert!(is_lost_authority_response(&first_failure));

    store.install_fault_plan(FaultPlan::none());
    let HeadRead::Present(receipt) = store
        .read_head(&authority_head_key())
        .expect("B's committed successor is readable")
    else {
        panic!("B's CAS must have linearized");
    };
    assert_eq!(
        receipt.body(),
        fgit_codec::wire::encode_body(&first_head).expect("head bytes")
    );
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), admitted.tx_id())
            .expect("B's behind accelerator is readable"),
        OutcomeLookup::Undecided,
        "the precheck window is real: accelerator absence does not prove B did not commit"
    );

    let duplicate_batch = batch(&first_head, admitted.tx_id(), 2, 0x52);
    let duplicate_head = successor_head(&first_head, batch_id_of(&duplicate_batch), 2);
    let duplicate = publish_decisions(
        &store,
        &authority_head_key(),
        receipt.token(),
        &duplicate_batch,
        &duplicate_head,
        tenant(),
    );
    assert!(
        duplicate.is_err(),
        "a missing derived accelerator must not admit a second terminal decision"
    );
    assert_eq!(
        replay_outcome(&store, &authority_head_key(), admitted.tx_id())
            .expect("authenticated replay remains singular"),
        expected_commit(1, 0x51),
        "the second candidate must never become reachable from the authority head"
    );
}

#[test]
fn cancellation_never_fabricates_a_noncommit_at_any_authority_phase() {
    // The synchronous authority contract does not inject runtime cancellation;
    // it supplies this explicit ambiguous result to the runtime adapter.  Pair
    // the caller-visible result with real authority states from before sealing,
    // after sealing, and after the decision CAS so no phase can turn an
    // unobserved cancellation into a fabricated negative answer.
    let cancelled = AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled);
    assert!(!cancelled.proves_no_effect());

    let before_seal = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7012));
    let genesis = genesis_head();
    initialize_repository(&before_seal, &authority_head_key(), &genesis).expect("genesis");
    let before_tx = attempt(b"cancel-before-seal", 0xA1)
        .derive()
        .expect("identity derivation")
        .0;
    assert_eq!(
        resolve_outcome(
            &before_seal,
            &authority_head_key(),
            tenant(),
            repository(),
            before_tx,
        )
        .expect("before-seal answer"),
        OutcomeLookup::Undecided
    );

    let after_seal = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7013));
    let sealed_request = attempt(b"cancel-after-seal", 0xA1);
    let sealed = seal_request(&after_seal, &sealed_request).expect("seal");
    initialize_repository(&after_seal, &authority_head_key(), &genesis).expect("genesis");
    assert_eq!(
        resolve_outcome(
            &after_seal,
            &authority_head_key(),
            tenant(),
            repository(),
            sealed.tx_id(),
        )
        .expect("after-seal answer"),
        OutcomeLookup::Undecided,
        "a cancellation after sealing cannot call the transaction non-committed"
    );

    let after_cas = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7014));
    let decided_request = attempt(b"cancel-after-cas", 0xA1);
    let decided = seal_request(&after_cas, &decided_request).expect("seal");
    let (expected, decision_batch, decision_head) =
        prepare_publication(&after_cas, decided.tx_id());
    assert!(matches!(
        publish_decisions(
            &after_cas,
            &authority_head_key(),
            expected,
            &decision_batch,
            &decision_head,
            tenant(),
        )
        .expect("decision publication"),
        PublicationOutcome::Published(_)
    ));
    assert_eq!(
        resolve_outcome(
            &after_cas,
            &authority_head_key(),
            tenant(),
            repository(),
            decided.tx_id(),
        )
        .expect("after-CAS answer"),
        expected_commit(1, 0x51),
        "the same cancellation result cannot erase a canonical decision"
    );
}
