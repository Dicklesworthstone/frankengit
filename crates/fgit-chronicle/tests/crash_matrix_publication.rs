//! FG-009b: the publication crash matrix.
//!
//! Written by a pane that did not implement `fgit-chronicle`, deliberately —
//! a campaign written beside its implementation tends to test the shape the
//! implementer already had in mind. Nothing here edits `fgit-chronicle/src`.
//!
//! # What a crash point means here
//!
//! `publish_decisions` performs its store operations in a fixed order, and
//! that order is the whole protocol:
//!
//! ```text
//!   op +0   put_if_absent  batch body        staged, unreferenced
//!   op +1   put_if_absent  head body         staged, unreferenced
//!   op +2   compare_exchange_head            THE LINEARIZATION POINT
//!   op +3.. put_if_absent  accelerator entry one per decision, repairable
//! ```
//!
//! A crash before op +2 must publish nothing. A crash after op +2 must leave
//! every decision canonical even though the accelerator is incomplete —
//! because the head is the authority and the accelerator is a rebuildable
//! hint. Those two sentences are the invariant this file exists to hold.
//!
//! Each crash pins BOTH an operation index taken from the store and the
//! operation KIND it must land on. Either alone is unsafe: a hard-coded index
//! drifts when setup grows, and a kind alone would fire on the first matching
//! operation rather than the intended one. Pinned together, a drifted index
//! simply fails to match, the crash never fires, and the assertions that
//! depend on it fail loudly instead of the test passing while measuring
//! nothing.

use fgit_authority::{
    AuthorityOpKind, AuthorityStore, FaultDirective, FaultKind, FaultPlan, HeadInit, HeadKey,
    HeadRead, MemoryAuthorityStore, OutcomeLookup, StoreInstanceId, canonical_body_id,
    indexed_outcome, initialize_repository, replay_outcome, resolve_outcome,
};
use fgit_chronicle::{
    LostCandidate, PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots,
    VerifiedPublication, publish, verify_pair,
};
use fgit_codec::CryptoBodyIdentity;
use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryCommitRecord};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    PolicyEpoch, PrincipalSnapshotId, RefusalCode, RefusalRecordId, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId, RepositorySequence, TenantId,
    TxId,
};

// ---------------------------------------------------------------- fixtures

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(1).expect("code point one is valid"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("thirty-two bytes is a valid digest"),
        )
    };
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([3; OPAQUE_ID_LEN])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

fn head_key() -> HeadKey {
    HeadKey::new(b"head/frankengit/crash-matrix".to_vec()).expect("a valid head key")
}

fn genesis() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn record(tag: u8) -> RepositoryCommitRecord {
    RepositoryCommitRecord {
        repository_id: repository(),
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, tag),
        principal_snapshot_id: derived!(PrincipalSnapshotId, tag),
        canonical_request_digest: digest(tag),
        ref_delta_root: digest(tag),
        resulting_ref_root: digest(0x30),
        object_closure_root: digest(tag),
        forge_event_batch_root: digest(tag),
        resulting_forge_position_root: digest(0x31),
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: digest(tag),
        invariant_evidence_root: digest(tag),
        outbox_effect_root: digest(tag),
        retention_delta_root: digest(tag),
    }
}

fn committed_roots() -> ResultingRoots {
    ResultingRoots {
        ref_root: digest(0x30),
        forge_position_root: digest(0x31),
        outcome_index_root: digest(0x32),
        retention_root: digest(0x33),
        outbox_root: digest(0x34),
        policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest(0x35),
    }
}

/// Roots for a refusal-only batch: the source and forge roots are the ones the
/// basis already published, because a refusal moves neither.
fn refusal_only_roots(previous: &RepositoryAuthorityHeadBody) -> ResultingRoots {
    ResultingRoots {
        ref_root: previous.ref_root,
        forge_position_root: previous.forge_position_root,
        outcome_index_root: digest(0x42),
        retention_root: previous.retention_root,
        outbox_root: previous.outbox_root,
        policy_epoch: previous.policy_epoch,
        batch_evidence_root: digest(0x45),
    }
}

fn identity_of(head: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_internal_object_id(
        canonical_body_id(
            IdentityDomain::RepositoryAuthorityHead,
            CANONICAL_CODEC_VERSION,
            head,
        )
        .expect("a head body has an identity"),
    )
    .expect("the identity carries the authority-head domain")
}

/// A store whose head holds genesis, plus the basis over it.
///
/// `plan` is installed at construction because the store takes its fault plan
/// there and nowhere else, which is why every crash index below is absolute.
fn opened(plan: FaultPlan) -> (MemoryAuthorityStore, PublicationBasis) {
    let store = MemoryAuthorityStore::with_fault_plan(StoreInstanceId::from_raw(1), plan);
    let head = genesis();
    match initialize_repository(&store, &head_key(), &head).expect("genesis initializes") {
        HeadInit::Created(_) | HeadInit::IdenticalRetry(_) => {}
        HeadInit::Conflict => panic!("a fresh store cannot conflict on genesis"),
    }
    (store, PublicationBasis::new(identity_of(&head), head))
}

fn commit_candidate(basis: &PublicationBasis, tag: u8) -> VerifiedPublication {
    let mut plan = PublicationPlan::open(basis.clone()).expect("the basis opens");
    plan.commit(derived!(RepositoryCommitId, tag), record(tag));
    plan.seal(&CryptoBodyIdentity, committed_roots())
        .expect("the plan is well formed")
}

fn current_token(store: &MemoryAuthorityStore) -> fgit_authority::AuthorityVersionToken {
    match store.read_head(&head_key()).expect("the head reads") {
        HeadRead::Present(receipt) => receipt.token(),
        HeadRead::Absent => panic!("the head was initialized"),
    }
}

fn current_head(store: &MemoryAuthorityStore) -> RepositoryAuthorityHeadBody {
    match store.read_head(&head_key()).expect("the head reads") {
        HeadRead::Present(receipt) => {
            fgit_codec::decode_body(receipt.body(), fgit_codec::DecodeLimits::DEFAULT)
                .expect("the stored head decodes")
        }
        HeadRead::Absent => panic!("the head was initialized"),
    }
}

/// Arms a store so one publication step meets one fault, and hands back the
/// token the caller will publish with.
///
/// `offset` is relative to the first operation `publish` performs:
///
/// ```text
///   0  put_if_absent  batch body
///   1  put_if_absent  head body
///   2  compare_exchange_head          the linearization point
///   3  put_if_absent  first accelerator entry
/// ```
///
/// The absolute index is measured from a probe store that performs the
/// identical setup, including the token read, so the two counters agree. The
/// directive also pins the operation KIND, which is what makes a mis-measured
/// index fail loudly: it simply does not match, the fault never fires, and the
/// assertions that depend on it fail rather than the test passing while
/// measuring nothing. That is not hypothetical — the first version of this
/// file was off by one because the token read was counted in one run and not
/// the other, and the kind pin is what surfaced it.
///
/// The faults are `LoseRequest` and `LoseResponse` rather than `Crash`.
/// A crashed endpoint refuses every later request, including the reads these
/// tests need to inspect the state the crash left behind. Losing a request or
/// a response models the same two situations — the effect did not happen, or
/// it happened and the caller never learned — while leaving the store
/// readable, which is the difference between asserting on real state and
/// asserting on nothing.
fn armed(
    ordinal: u64,
    kind: AuthorityOpKind,
    fault: FaultKind,
) -> (
    MemoryAuthorityStore,
    PublicationBasis,
    fgit_authority::AuthorityVersionToken,
) {
    let (store, basis) = opened(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
        ordinal, kind, fault,
    )]));
    let token = current_token(&store);
    (store, basis, token)
}

/// Which occurrence of an operation KIND to interrupt, not which absolute
/// operation.
///
/// These were absolute offsets from `operations_started()`, which coupled the
/// plan to the publication's operation *count*. The atomic-publication change
/// added a duplicate-detection stream walk before the CAS, and that coupling
/// broke silently: `only_for(CompareExchangeHead)` is a filter, not a counting
/// mode, so a shifted index does not fire on the wrong operation - it fires on
/// NONE. The publication then completes untouched and the test truthfully
/// reports that a publication it expected to interrupt was not interrupted,
/// which reads as an assertion problem and is a targeting problem.
///
/// An ordinal within kind says what the test means - "the first head
/// replacement" - and is invariant under operations of other kinds appearing
/// before it.
const FIRST_HEAD_REPLACEMENT: u64 = 0;
const FIRST_ACCELERATOR_WRITE: u64 = 2;

// ------------------------------------------- crash before the head moves

#[test]
fn a_publication_whose_head_replacement_never_applies_publishes_nothing() {
    // The request is lost before the compare-exchange takes effect, so both
    // bodies are staged and the head is untouched. Nothing may be canonical.
    let (store, basis, token) = armed(
        FIRST_HEAD_REPLACEMENT,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseRequest,
    );
    let candidate = commit_candidate(&basis, 0xa1);
    let tx = candidate.batch().decisions[0].tx_id;

    let outcome = publish(&store, &head_key(), token, &candidate, tenant());
    assert!(
        outcome.is_err(),
        "a lost head replacement is ambiguous and must never be reported as a publication"
    );

    let head = current_head(&store);
    assert_eq!(
        head.generation,
        HeadGeneration::FIRST,
        "the head must still be the basis the candidate was prepared against"
    );
    assert!(
        head.decision_tail_id.is_none(),
        "no batch may be referenced when the replacement did not apply"
    );
    assert_eq!(
        replay_outcome(&store, &head_key(), tx).expect("replay runs"),
        OutcomeLookup::Undecided,
        "no decision may be canonical when the head did not move"
    );
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), tx).expect("the index reads"),
        OutcomeLookup::Undecided,
        "and the accelerator must not have run ahead of the head"
    );
}

// -------------------------------- crash after the head moves (the window)

#[test]
fn a_head_that_moved_without_answering_still_makes_its_decision_canonical() {
    // THE WINDOW THE AUDIT NAMED. The replacement applied and the answer was
    // lost, so the decision is canonical while the accelerator is empty. An
    // accelerator-only reader would call this undecided and let the same
    // sealed transaction be decided a second time.
    //
    // Regression guard: green because RainyLotus fixed loss classification at
    // 06b65dc. It turns red if resolution ever stops replaying the stream.
    let (store, basis, token) = armed(
        FIRST_HEAD_REPLACEMENT,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseResponse,
    );
    let candidate = commit_candidate(&basis, 0xb2);
    let tx = candidate.batch().decisions[0].tx_id;

    let answer = publish(&store, &head_key(), token, &candidate, tenant());
    assert!(
        answer.is_err(),
        "a lost response is ambiguous: the caller must not be told it published"
    );

    let head = current_head(&store);
    assert_ne!(
        head.generation,
        HeadGeneration::FIRST,
        "the replacement applied, so the head must have advanced"
    );

    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), tx).expect("the index reads"),
        OutcomeLookup::Undecided,
        "the fixture only means something while the accelerator is genuinely empty"
    );
    assert!(
        matches!(
            replay_outcome(&store, &head_key(), tx).expect("replay runs"),
            OutcomeLookup::Decided(_)
        ),
        "replaying the head chain must find the decision the accelerator lacks"
    );
    assert!(
        matches!(
            resolve_outcome(&store, &head_key(), tenant(), repository(), tx).expect("resolve runs"),
            OutcomeLookup::Decided(_)
        ),
        "resolution must prefer the stream over an accelerator miss, or a transaction \
         decided in this window would be replanned and decided twice"
    );
}

#[test]
fn a_publication_interrupted_inside_the_accelerator_leaves_every_decision_canonical() {
    // Two decisions; the first accelerator write applies and its answer is
    // lost, so the second never happens. One transaction is indexed and one is
    // not, and both must still resolve as decided, because the head is the
    // authority and the index is a hint.
    let (store, basis, token) = armed(
        FIRST_ACCELERATOR_WRITE,
        AuthorityOpKind::PutIfAbsent,
        FaultKind::LoseResponse,
    );

    let mut plan = PublicationPlan::open(basis).expect("the basis opens");
    plan.refuse(
        derived!(TxId, 0xc1),
        RefusalCode::ExpectedOldRefMismatch,
        derived!(RefusalRecordId, 0xc1),
    );
    plan.refuse(
        derived!(TxId, 0xc2),
        RefusalCode::NonFastForwardRefused,
        derived!(RefusalRecordId, 0xc2),
    );
    let candidate = plan
        .seal(&CryptoBodyIdentity, refusal_only_roots(&genesis()))
        .expect("a refusal-only plan is well formed");

    let _ = publish(&store, &head_key(), token, &candidate, tenant());

    assert_ne!(
        current_head(&store).generation,
        HeadGeneration::FIRST,
        "the head advanced, so both refusals are canonical"
    );
    for tag in [0xc1_u8, 0xc2] {
        let tx = derived!(TxId, tag);
        assert!(
            matches!(
                replay_outcome(&store, &head_key(), tx).expect("replay runs"),
                OutcomeLookup::Decided(_)
            ),
            "decision {tag:#04x} is in the published batch, so it must replay as decided \
             however far the accelerator got"
        );
    }
}

// ------------------------------------------------------- anti-rollback

#[test]
fn an_older_valid_head_never_silently_replaces_a_newer_one() {
    // Two slots: a token captured at generation one, used after generation two
    // has been published. The old token is authentic — it was really issued —
    // which is exactly why authenticity is not currency.
    let (store, basis) = opened(FaultPlan::none());
    let stale_token = current_token(&store);

    let first = commit_candidate(&basis, 0xd1);
    let verdict = publish(&store, &head_key(), stale_token, &first, tenant())
        .expect("the first publication runs");
    let PublicationVerdict::Published(receipt) = verdict else {
        panic!("an uncontested publication wins");
    };
    let advanced = current_head(&store);
    assert_ne!(advanced.generation, HeadGeneration::FIRST);

    // A second candidate prepared against the ORIGINAL basis, replayed with
    // the ORIGINAL token: the rollback attempt.
    let rollback = commit_candidate(&basis, 0xd2);
    let verdict = publish(&store, &head_key(), stale_token, &rollback, tenant())
        .expect("the attempt is answered rather than erroring");
    assert!(
        matches!(verdict, PublicationVerdict::Lost(_)),
        "a stale token must lose, however genuine it is"
    );

    let after = current_head(&store);
    assert_eq!(
        after.generation, advanced.generation,
        "the head must not retreat to the older generation"
    );
    assert_eq!(
        after.decision_tail_id,
        Some(receipt.batch),
        "the winner's batch must still be the tail after the rollback attempt"
    );
}

#[test]
fn a_generation_may_only_move_forward_across_a_publication() {
    let (store, basis) = opened(FaultPlan::none());
    let before = current_head(&store).generation;
    let candidate = commit_candidate(&basis, 0xe1);
    let token = current_token(&store);
    let verdict =
        publish(&store, &head_key(), token, &candidate, tenant()).expect("publication runs");
    assert!(
        matches!(verdict, PublicationVerdict::Published(_)),
        "an uncontested publication must win, or the generation claim below means nothing"
    );
    let after = current_head(&store).generation;
    assert!(
        after > before,
        "a published head must carry a strictly greater generation"
    );
}

// -------------------------------------------- resume after interruption

#[test]
fn an_interrupted_publication_resumes_without_deciding_twice() {
    // Crash in the accelerator window, then re-drive the same sealed
    // publication. The one-terminal-decision rule says the retry must not
    // produce a second decision for the same transaction.
    let (store, basis, token) = armed(
        FIRST_HEAD_REPLACEMENT,
        AuthorityOpKind::CompareExchangeHead,
        FaultKind::LoseResponse,
    );
    let candidate = commit_candidate(&basis, 0xf1);
    let tx = candidate.batch().decisions[0].tx_id;
    let _ = publish(&store, &head_key(), token, &candidate, tenant());

    let after_crash = current_head(&store);
    let tail_after_crash = after_crash.decision_tail_id;

    // Resume: a fresh reader asks what happened, and must be told the truth.
    let resolved = resolve_outcome(&store, &head_key(), tenant(), repository(), tx)
        .expect("resolution runs after the interruption");
    assert!(
        matches!(resolved, OutcomeLookup::Decided(_)),
        "a resumed reader must see the decision the interrupted run made canonical"
    );

    // Re-publishing the same candidate against the now-stale token must lose
    // rather than re-decide.
    let verdict =
        publish(&store, &head_key(), token, &candidate, tenant()).expect("the retry is answered");
    match verdict {
        PublicationVerdict::Lost(LostCandidate::Superseded { decided }) => {
            assert!(
                decided.iter().any(|(id, _)| *id == tx),
                "the retry must name the transaction that is already decided"
            );
        }
        PublicationVerdict::Lost(LostCandidate::Replannable) => panic!(
            "a transaction decided in the crash window must never be reported replannable: \
             replanning it would decide it a second time"
        ),
        PublicationVerdict::Published(_) => {
            panic!("a stale token cannot publish, and this one is stale")
        }
        PublicationVerdict::AlreadyDecided { .. } => panic!(
            "this retry presents a STALE token, so the head has already moved: the \
             answer is a lost race carrying the superseded decisions, not a \
             pre-CAS AlreadyDecided. Reporting it as AlreadyDecided would tell the \
             caller its basis is still current when the winner has consumed it"
        ),
    }
    assert_eq!(
        current_head(&store).decision_tail_id,
        tail_after_crash,
        "the retry must not have moved the head"
    );
}

// ------------------------------------------ CAS loser reprepares its seal

#[test]
fn a_cas_loser_replans_the_same_sealed_transaction_against_the_new_head() {
    // The sealed request survives the loss; only the positions it chose are
    // stale. So the same TxId must be replannable against the winner's head
    // and land with the next sequence, not the one it originally took.
    let (store, basis) = opened(FaultPlan::none());
    let token = current_token(&store);

    let loser_tx = derived!(TxId, 0x9b);
    let mut loser_plan = PublicationPlan::open(basis.clone()).expect("the basis opens");
    let mut loser_record = record(0x9b);
    loser_record.tx_id = loser_tx;
    loser_plan.commit(derived!(RepositoryCommitId, 0x9b), loser_record.clone());
    let loser = loser_plan
        .seal(&CryptoBodyIdentity, committed_roots())
        .expect("the loser's plan is well formed");
    let original_sequence = loser.batch().decisions[0].decision_sequence;

    // The winner publishes first, using the same token.
    let winner = commit_candidate(&basis, 0x8a);
    let verdict =
        publish(&store, &head_key(), token, &winner, tenant()).expect("the winner publishes");
    assert!(
        matches!(verdict, PublicationVerdict::Published(_)),
        "the winner must actually win, or the loser is not losing a race"
    );
    let winner_head = current_head(&store);

    // The loser now loses, and must be told it may replan.
    let verdict =
        publish(&store, &head_key(), token, &loser, tenant()).expect("the loser is answered");
    assert!(
        matches!(
            verdict,
            PublicationVerdict::Lost(LostCandidate::Replannable)
        ),
        "an undecided sealed request may replan; it was never decided"
    );

    // Replan the SAME seal against the winner's head.
    let new_basis = PublicationBasis::new(identity_of(&winner_head), winner_head);
    let mut replan = PublicationPlan::open(new_basis).expect("the new basis opens");
    replan.commit(derived!(RepositoryCommitId, 0x9b), loser_record);
    let replanned = replan
        .seal(&CryptoBodyIdentity, committed_roots())
        .expect("the replanned plan is well formed");

    assert_eq!(
        replanned.batch().decisions[0].tx_id,
        loser_tx,
        "a replan carries the same sealed transaction identity"
    );
    assert!(
        replanned.batch().decisions[0].decision_sequence > original_sequence,
        "the replan must take a fresh position: the winner consumed the original"
    );

    let verdict = publish(
        &store,
        &head_key(),
        current_token(&store),
        &replanned,
        tenant(),
    )
    .expect("the replan publishes");
    assert!(
        matches!(verdict, PublicationVerdict::Published(_)),
        "a correctly replanned candidate wins against the head it was prepared on"
    );
}

// ------------------------------------------ refusal-only sequence effects

#[test]
fn a_refusal_only_batch_consumes_decision_sequence_and_moves_no_source_state() {
    let (store, basis) = opened(FaultPlan::none());
    let before = current_head(&store);

    let mut plan = PublicationPlan::open(basis).expect("the basis opens");
    plan.refuse(
        derived!(TxId, 0x71),
        RefusalCode::PublicationPolicyRefused,
        derived!(RefusalRecordId, 0x71),
    );
    let candidate = plan
        .seal(&CryptoBodyIdentity, refusal_only_roots(&before))
        .expect("a refusal-only plan is well formed");

    let token = current_token(&store);
    let verdict =
        publish(&store, &head_key(), token, &candidate, tenant()).expect("the refusal publishes");
    assert!(
        matches!(verdict, PublicationVerdict::Published(_)),
        "the refusal-only batch must publish, or the sequence claims below are vacuous"
    );

    let after = current_head(&store);
    assert!(
        after.latest_decision_sequence > before.latest_decision_sequence,
        "a refusal consumes decision sequence"
    );
    assert_eq!(
        after.latest_repository_sequence, before.latest_repository_sequence,
        "a refusal must not advance repository sequence"
    );
    assert_eq!(
        after.latest_committed_rcr_id, before.latest_committed_rcr_id,
        "a refusal commits no record"
    );
    assert_eq!(
        after.ref_root, before.ref_root,
        "a refusal moves no ref state"
    );
    assert_eq!(
        after.forge_position_root, before.forge_position_root,
        "a refusal moves no forge state"
    );
}

// ------------------------- regression guards for the two audited defects

#[test]
fn a_duplicate_transaction_cannot_be_assembled() {
    // Audited defect 1, assembly half. Fixed at 06b65dc; this holds it fixed.
    let (_, basis) = opened(FaultPlan::none());
    let tx = derived!(TxId, 0x55);

    let mut plan = PublicationPlan::open(basis).expect("the basis opens");
    plan.refuse(
        tx,
        RefusalCode::ExpectedOldRefMismatch,
        derived!(RefusalRecordId, 0x55),
    );
    let mut duplicate = record(0x55);
    duplicate.tx_id = tx;
    plan.commit(derived!(RepositoryCommitId, 0x55), duplicate);

    let refusal = plan
        .seal(&CryptoBodyIdentity, committed_roots())
        .expect_err("one sealed transaction may not take two terminal decisions");
    assert!(
        format!("{refusal:?}").contains("DuplicateTransaction"),
        "the refusal must name the duplicate rather than fail for some other reason: {refusal:?}"
    );
}

#[test]
fn a_duplicate_transaction_cannot_pass_the_audit_either() {
    // Audited defect 1, audit half. A batch that reached an auditor as DATA —
    // from replay, recovery, or a peer — must be rejected even though no
    // builder on this machine could have produced it.
    let (_, basis) = opened(FaultPlan::none());
    let tx = derived!(TxId, 0x66);

    let mut plan = PublicationPlan::open(basis.clone()).expect("the basis opens");
    plan.refuse(
        tx,
        RefusalCode::ExpectedOldRefMismatch,
        derived!(RefusalRecordId, 0x66),
    );
    let sound = plan
        .seal(&CryptoBodyIdentity, refusal_only_roots(&genesis()))
        .expect("a single refusal is well formed");

    // Forge the duplicate directly in the body, bypassing the builder. The
    // copy takes the NEXT decision sequence: a naive clone repeats sequence
    // one, the contiguity check fires first, and the test would pass while
    // proving nothing about uniqueness. The forgery has to be well formed in
    // every respect except the one under test.
    let mut batch = sound.batch().clone();
    let mut repeated = batch.decisions[0].clone();
    repeated.decision_sequence = repeated
        .decision_sequence
        .next()
        .expect("a second sequence exists");
    batch.decisions.push(repeated);

    let refusal = verify_pair(&CryptoBodyIdentity, &basis, &batch, sound.head())
        .expect_err("the auditor must reject a duplicated transaction");
    assert!(
        format!("{refusal:?}").contains("DuplicateTransaction"),
        "the auditor must name the duplicate: {refusal:?}"
    );

    // Permitted counterpart: the unforged pair still verifies, so the test
    // above is rejecting the duplicate rather than something incidental.
    verify_pair(&CryptoBodyIdentity, &basis, sound.batch(), sound.head())
        .expect("the sound pair verifies");
}
