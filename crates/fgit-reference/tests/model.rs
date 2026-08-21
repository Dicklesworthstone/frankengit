//! Integration tests for the repository reference model.
//!
//! Everything lives in one test target on purpose. The suites share one
//! scenario fixture, and splitting them across binaries would either duplicate
//! that fixture or force a `tests/common` include whose helpers a sibling
//! binary would report as dead code.
//!
//! Two disciplines run through the whole file:
//!
//! * **Every forbidden case is paired with a near-identical permitted case.**
//!   A test that only shows a refusal cannot distinguish "the model correctly
//!   refuses this" from "the model cannot do this at all". Each refusal test
//!   below therefore also proves the same shape succeeds one small change away.
//! * **Failures name their inputs.** Assertions carry the ref, the code, or the
//!   sequence that produced them, so a regression report is actionable without
//!   re-deriving the scenario.

use std::collections::{BTreeMap, BTreeSet};

use fgit_reference::capsule::{PreparedVerdict, WitnessGranularity};
use fgit_reference::decision::{DecisionBatchDraft, PublishedDecision};
use fgit_reference::effect::{
    AbsorptionReason, FoldBasis, IntentDisposition, NetEffectFolder, RefEffect, ReferenceFolder,
};
use fgit_reference::harness::{IdentityMint, PublishReport, RequestBuilder, label, publish};
use fgit_reference::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey, Intent, OutboxDeliveryKey, OutboxIntent, RefIntent,
    RetentionClass, RetentionIntent, RetentionRoot, TransactionRequest,
};
use fgit_reference::machine::{
    CancellationPhase, CancellationRequest, ModelInput, ModelOutput, step,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_reference::refusal::{MODEL_REFUSAL_SURFACE, RefusalClass};
use fgit_reference::state::{
    GenesisConfiguration, InvariantBreach, PolicySnapshot, PrincipalCapabilities,
    QuarantinedObject, RepositoryState,
};
use fgit_reference::transition::{
    CasOutcome, CasRequest, ConfigurationOutcome, ConfigurationRequest, DecisionBodyIdentity,
    DecisionVerdict, PrepareRequest, QuarantineRequest, REPREPARATION_BUDGET, RepreparationReason,
    SealOutcome, SealRequest, StageOutcome, StageRequest, compare_and_swap, decide, prepare,
    publish_configuration, seal, stage, stage_objects,
};
use fgit_types::identity::{
    PreparedTxnCapsuleId, PrincipalId, RepositoryDecisionBatchId, RepositoryId, TenantId, TxId,
};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::{
    DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositorySequence,
};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::{DecisionOutcome, MismatchPolicy, RefusalCode, RequestRejectionCode};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// One scenario repository and the identities it was built from.
struct Fixture {
    mint: IdentityMint,
    state: RepositoryState,
    tenant: TenantId,
    repository: RepositoryId,
    /// May write `refs/heads` and `refs/tags`, may force, forge, and hold.
    author: PrincipalId,
    /// May write `refs/heads` only.
    narrow: PrincipalId,
    /// Unknown to policy: has no capability at all.
    stranger: PrincipalId,
}

const fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("fgit/ref-txn"), 2, 0)
}

const fn unsupported_schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("fgit/ref-txn"), 99, 0)
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

const fn sha256_oid(seed: u8) -> GitOid {
    GitOid::Sha256(fgit_types::native::GitOidSha256::from_bytes(
        [seed; fgit_types::native::GitOidSha256::LEN],
    ))
}

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes())
        .unwrap_or_else(|error| panic!("{text} is not a valid ref name: {error}"))
}

fn object(id: GitOid, parents: &[GitOid]) -> QuarantinedObject {
    QuarantinedObject {
        declared: id,
        recomputed: id,
        parents: parents.to_vec(),
    }
}

/// An object whose recomputed identity disagrees with the declared one.
const fn corrupt_object(declared: GitOid, recomputed: GitOid) -> QuarantinedObject {
    QuarantinedObject {
        declared,
        recomputed,
        parents: Vec::new(),
    }
}

fn key_of(text: &str) -> IdempotencyKey {
    IdempotencyKey::new(label(text))
}

fn update(target: &str, expected: ExpectedRefState, new: GitOid, force: bool) -> Intent {
    Intent::Ref(RefIntent::Update {
        name: name(target),
        expected,
        new,
        force,
    })
}

/// The batch a staging call was expected to produce.
///
/// Asserts the stronger thing the caller means: a batch was staged **and**
/// nothing was deferred for re-preparation, so the scenario is the one the test
/// set up rather than a silently-lost race.
fn expect_batch(staged: &StageOutcome) -> RepositoryDecisionBatchId {
    assert!(
        staged.deferred.is_empty(),
        "staging deferred {:?} when the test expected a full batch",
        staged.deferred
    );
    staged.batch.expect("staging produced no batch")
}

fn delete(target: &str, expected: ExpectedRefState) -> Intent {
    Intent::Ref(RefIntent::Delete {
        name: name(target),
        expected,
    })
}

impl Fixture {
    fn new(seed: u64) -> Self {
        let mut mint = IdentityMint::new(seed);
        let tenant = mint.tenant();
        let repository = mint.repository();
        let author = mint.principal();
        let narrow = mint.principal();
        let stranger = mint.principal();
        let genesis_head_id = mint.head();

        let mut principals = BTreeMap::new();
        principals.insert(
            author,
            PrincipalCapabilities {
                writable_scopes: BTreeSet::from([b"heads".to_vec(), b"tags".to_vec()]),
                may_force: true,
                may_publish_forge: true,
                may_add_legal_hold: true,
            },
        );
        principals.insert(
            narrow,
            PrincipalCapabilities {
                writable_scopes: BTreeSet::from([b"heads".to_vec()]),
                may_force: false,
                may_publish_forge: false,
                may_add_legal_hold: false,
            },
        );
        // `stranger` is deliberately absent from policy: an unknown principal
        // must get the empty capability set, never a default one.

        let policy = PolicySnapshot {
            epoch: PolicyEpoch::FIRST,
            // `refs/tags` is protected and `refs/heads` is not, so every
            // protection denial has a permitted twin one namespace away.
            protected_scopes: BTreeSet::from([b"tags".to_vec()]),
            principals,
            max_intents_per_transaction: 8,
            supported_schemas: BTreeSet::from([schema()]),
            supported_durability: BTreeSet::from([DurabilityProfile::CanonicalSource]),
        };

        let state = RepositoryState::genesis(GenesisConfiguration {
            tenant,
            repository,
            object_format: GitHashAlgorithm::Sha1,
            genesis_head_id,
            policy,
            format_registry_epoch: RegistryEpoch::FIRST,
        });

        Self {
            mint,
            state,
            tenant,
            repository,
            author,
            narrow,
            stranger,
        }
    }

    fn request(&self, principal: PrincipalId, key: &str) -> RequestBuilder {
        RequestBuilder::new(
            self.tenant,
            self.repository,
            principal,
            schema(),
            key_of(key),
        )
    }

    /// Drives one request end to end, asserting only that no invariant broke.
    fn publish(
        &mut self,
        request: &TransactionRequest,
        objects: &[QuarantinedObject],
    ) -> PublishReport {
        let (next, report) = publish(&self.state, &mut self.mint, request, objects, true)
            .unwrap_or_else(|breach| panic!("unexpected invariant breach: {breach}"));
        self.state = next;
        report
    }

    /// Commits one ordinary ref update and returns the report.
    fn commit_ref(
        &mut self,
        key: &str,
        target: &str,
        expected: ExpectedRefState,
        new: GitOid,
        parents: &[GitOid],
    ) -> PublishReport {
        let request = self
            .request(self.author, key)
            .statement(
                MismatchPolicy::TxnAbort,
                vec![update(target, expected, new, false)],
            )
            .promising(new)
            .build(&mut self.mint);
        self.publish(&request, &[object(new, parents)])
    }

    fn assert_structurally_sound(&self) {
        self.state
            .assert_head_chain_continuous()
            .unwrap_or_else(|breach| panic!("head chain broke: {breach}"));
        self.state
            .assert_sequences_gap_free()
            .unwrap_or_else(|breach| panic!("sequences broke: {breach}"));
        self.state
            .assert_no_quarantine_escape()
            .unwrap_or_else(|breach| panic!("quarantine escaped: {breach}"));
    }
}

/// Every refusal code the suites below observed, so the declared surface can be
/// checked against reality rather than against a list someone maintained.
fn observed_refusals() -> BTreeSet<RefusalCode> {
    let mut observed = BTreeSet::new();
    for code in refusal_scenarios() {
        observed.insert(code);
    }
    observed
}

// ---------------------------------------------------------------------------
// The happy path, and the shape of the protocol
// ---------------------------------------------------------------------------

#[test]
fn a_first_commit_advances_both_sequences_and_one_head_generation() {
    let mut fixture = Fixture::new(1);
    let report = fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    assert!(matches!(report.seal, SealOutcome::Created(_)));
    assert!(report.is_committed(), "report was {report:?}");
    assert!(matches!(report.cas, Some(CasOutcome::Won { .. })));

    let head = fixture.state.head();
    assert_eq!(head.body.generation, HeadGeneration::FIRST.next().unwrap());
    assert_eq!(
        head.body.latest_decision_sequence,
        Some(DecisionSequence::FIRST)
    );
    assert_eq!(
        head.body.latest_repository_sequence,
        Some(RepositorySequence::FIRST)
    );
    assert_eq!(
        head.body.roots.refs.get(&name("refs/heads/main")),
        Some(&oid(1))
    );
    assert_eq!(fixture.state.decisions().len(), 1);
    assert_eq!(fixture.state.commits().len(), 1);
    fixture.assert_structurally_sound();
}

#[test]
fn nothing_is_canonical_until_the_head_compare_and_swap_wins() {
    let mut fixture = Fixture::new(2);
    let target = name("refs/heads/main");
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);

    let seal_request = SealRequest {
        seal_id: fixture.mint.seal(),
        request: request.clone(),
    };
    let (state, _) = seal(&fixture.state, &seal_request).expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");

    // Preparing decided nothing: the ref is untouched and the transaction has
    // no outcome.
    assert!(!state.roots().refs.contains_key(&target));
    assert_eq!(state.outcome_of(request.tx_id), None);

    let mut bodies = BTreeMap::new();
    bodies.insert(
        request.tx_id,
        DecisionBodyIdentity {
            commit: fixture.mint.commit(),
            refusal_record: fixture.mint.refusal_record(),
        },
    );
    let (state, staged) = stage(
        &state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect("stage");
    let batch = expect_batch(&staged);

    // Staging published nothing either: the batch exists but no authority root
    // references it, which is §9's staged epoch.
    assert!(state.staged(batch).is_some());
    assert!(state.batch(batch).is_none());
    assert!(!state.roots().refs.contains_key(&target));
    assert_eq!(state.outcome_of(request.tx_id), None);
    assert_eq!(state.head().body.generation, HeadGeneration::FIRST);
    assert_eq!(state.decisions(), &[]);

    // The compare-and-swap is the linearization point.
    let (state, outcome) = compare_and_swap(
        &state,
        CasRequest {
            expected_head: state.head().id,
            expected_generation: state.head().body.generation,
            batch,
        },
    )
    .expect("cas");
    assert!(matches!(outcome, CasOutcome::Won { .. }));
    assert_eq!(state.roots().refs.get(&target), Some(&new));
    assert!(state.outcome_of(request.tx_id).is_some());
    assert!(state.staged(batch).is_none());
    assert!(state.batch(batch).is_some());
}

#[test]
fn a_quarantined_object_is_promoted_only_by_a_winning_compare_and_swap() {
    let mut fixture = Fixture::new(3);
    let new = oid(7);
    assert!(!fixture.state.is_admitted(new));

    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);

    // Staging the object alone promotes nothing.
    let (staged, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let staged = stage_objects(
        &staged,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    assert!(
        !staged.is_admitted(new),
        "quarantined bytes must not be admitted before the transaction commits"
    );
    assert!(staged.quarantine_of(request.tx_id).is_some());
    staged
        .assert_no_quarantine_escape()
        .expect("nothing quarantined is protected by a root yet");

    let report = fixture.publish(&request, &[object(new, &[])]);
    assert!(report.is_committed(), "report was {report:?}");
    assert!(
        fixture.state.is_admitted(new),
        "a committed closure must be promoted out of quarantine"
    );
    assert!(
        fixture.state.quarantine_of(request.tx_id).is_none(),
        "the transaction-scoped quarantine is cleared once terminal"
    );
    fixture.assert_structurally_sound();
}

#[test]
fn a_refused_transaction_does_not_retain_its_staged_objects() {
    let mut fixture = Fixture::new(4);
    // Promise an object that is never staged: the closure is incomplete.
    let promised = oid(9);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                promised,
                false,
            )],
        )
        .promising(promised)
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[]);

    assert_eq!(
        report.refusal_code(),
        Some(RefusalCode::ObjectClosureIncomplete)
    );
    assert!(
        !fixture.state.is_admitted(promised),
        "a refused transaction must not promote anything"
    );
    assert!(fixture.state.roots().refs.is_empty());
    fixture.assert_structurally_sound();
}

// ---------------------------------------------------------------------------
// Acceptance: DecisionSequence and RepositorySequence are structurally distinct
// ---------------------------------------------------------------------------

#[test]
fn a_refusal_consumes_decision_sequence_and_leaves_repository_sequence_alone() {
    let mut fixture = Fixture::new(5);

    // One commit, so both sequences have moved once.
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    let after_commit = fixture.state.head().body.clone();
    assert_eq!(
        after_commit.latest_decision_sequence,
        Some(DecisionSequence::FIRST)
    );
    assert_eq!(
        after_commit.latest_repository_sequence,
        Some(RepositorySequence::FIRST)
    );
    let committed_rcr = after_commit.latest_committed_rcr;

    // Now a refusal: the expected-old precondition does not match.
    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(99)),
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(2), &[oid(1)])]);
    assert_eq!(
        report.refusal_code(),
        Some(RefusalCode::ExpectedOldRefMismatch)
    );

    let after_refusal = fixture.state.head().body.clone();
    assert_eq!(
        after_refusal.latest_decision_sequence,
        Some(DecisionSequence::FIRST.next().unwrap()),
        "a refusal must consume a decision sequence"
    );
    assert_eq!(
        after_refusal.latest_repository_sequence,
        Some(RepositorySequence::FIRST),
        "a refusal must not advance repository sequence"
    );
    assert_eq!(
        after_refusal.latest_committed_rcr, committed_rcr,
        "a refusal must not produce a commit record"
    );
    assert_eq!(fixture.state.decisions().len(), 2);
    assert_eq!(fixture.state.commits().len(), 1);
    assert_eq!(
        fixture.state.roots().refs.get(&name("refs/heads/main")),
        Some(&oid(1)),
        "a refusal must not move a ref"
    );
    fixture.assert_structurally_sound();
}

#[test]
fn the_permitted_twin_of_that_refusal_advances_both_sequences() {
    // Identical to the test above except the expected-old value is the one the
    // basis actually holds.
    let mut fixture = Fixture::new(6);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(1)),
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(2), &[oid(1)])]);

    assert!(report.is_committed(), "report was {report:?}");
    let head = fixture.state.head();
    assert_eq!(
        head.body.latest_decision_sequence,
        Some(DecisionSequence::FIRST.next().unwrap())
    );
    assert_eq!(
        head.body.latest_repository_sequence,
        Some(RepositorySequence::FIRST.next().unwrap())
    );
    assert_eq!(
        head.body.roots.refs.get(&name("refs/heads/main")),
        Some(&oid(2))
    );
    fixture.assert_structurally_sound();
}

#[test]
fn a_refusal_cannot_be_pushed_through_the_commit_path_of_a_batch() {
    // The draft's refusal path never reads the repository sequence, so a
    // committed outcome offered to it is rejected rather than silently
    // consuming one.
    let mut mint = IdentityMint::new(7);
    let mut draft = DecisionBatchDraft::open(
        mint.batch(),
        mint.repository(),
        mint.head(),
        HeadGeneration::FIRST,
        DecisionSequence::FIRST,
        RepositorySequence::FIRST,
        None,
        DurabilityProfile::CanonicalSource,
    );
    let tx = mint.tx();
    let breach = draft
        .push_refusal(
            tx,
            DecisionOutcome::Committed {
                repository_commit_id: mint.commit(),
            },
        )
        .expect_err("a committed outcome is not a refusal");
    assert!(
        matches!(*breach, InvariantBreach::RefusalOutcomeExpected { .. }),
        "breach was {breach:?}"
    );

    // Permitted twin: the same call with an actual refusal succeeds and
    // consumes a decision sequence but no repository sequence.
    let assignment = draft
        .push_refusal(
            tx,
            DecisionOutcome::Refused {
                code: RefusalCode::ExpectedOldRefMismatch,
                refusal_record_id: mint.refusal_record(),
            },
        )
        .expect("a refusal is accepted");
    assert_eq!(assignment.decision_sequence, DecisionSequence::FIRST);
    assert_eq!(assignment.repository_sequence, None);
}

// ---------------------------------------------------------------------------
// Acceptance: at most one terminal decision per sealed transaction
// ---------------------------------------------------------------------------

#[test]
fn a_batch_cannot_hold_two_decisions_for_one_sealed_transaction() {
    let mut mint = IdentityMint::new(8);
    let mut draft = DecisionBatchDraft::open(
        mint.batch(),
        mint.repository(),
        mint.head(),
        HeadGeneration::FIRST,
        DecisionSequence::FIRST,
        RepositorySequence::FIRST,
        None,
        DurabilityProfile::CanonicalSource,
    );
    let tx = mint.tx();
    let refusal = DecisionOutcome::Refused {
        code: RefusalCode::ExpectedOldRefMismatch,
        refusal_record_id: mint.refusal_record(),
    };
    draft.push_refusal(tx, refusal).expect("first decision");
    assert!(draft.holds(tx));

    let breach = draft
        .push_refusal(tx, refusal)
        .expect_err("a second decision for one sealed transaction must be refused");
    assert!(
        matches!(*breach, InvariantBreach::SecondDecisionInBatch { .. }),
        "breach was {breach:?}"
    );

    // Permitted twin: a *different* sealed transaction is accepted, and gets
    // the next decision sequence.
    let other = mint.tx();
    let assignment = draft
        .push_refusal(other, refusal)
        .expect("a different transaction is accepted");
    assert_eq!(
        assignment.decision_sequence,
        DecisionSequence::FIRST.next().unwrap()
    );
    assert_eq!(draft.len(), 2);
}

#[test]
fn staging_a_transaction_that_is_already_terminal_is_an_invariant_breach() {
    let mut fixture = Fixture::new(9);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(new, &[])]);
    assert!(report.is_committed());

    // Prepare the same sealed transaction again against the new head, then try
    // to stage its decision a second time.
    let (state, capsule) = prepare(
        &fixture.state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("re-preparing a terminal transaction is allowed");

    let mut bodies = BTreeMap::new();
    bodies.insert(
        request.tx_id,
        DecisionBodyIdentity {
            commit: fixture.mint.commit(),
            refusal_record: fixture.mint.refusal_record(),
        },
    );
    let breach = stage(
        &state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect_err("a second terminal decision must be refused");
    assert!(
        matches!(*breach, InvariantBreach::SecondTerminalDecision { .. }),
        "breach was {breach:?}"
    );
    assert_eq!(
        breach.kind(),
        "second_terminal_decision",
        "the breach must report itself as itself"
    );
    assert_eq!(
        breach.refusal_code(),
        RefusalCode::InternalInvariantBreach,
        "a boundary reporting this must use the invariant code"
    );
}

#[test]
fn deciding_an_already_terminal_transaction_returns_the_existing_outcome() {
    // §10 step 18: after a lost compare-and-swap, if the transaction is now
    // terminal the existing outcome is returned rather than decided again.
    let mut fixture = Fixture::new(10);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    fixture.publish(&request, &[object(new, &[])]);
    let recorded = fixture.state.outcome_of(request.tx_id).expect("terminal");

    let (state, capsule) = prepare(
        &fixture.state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    let prepared = state.capsule(capsule).expect("capsule is held");

    match decide(&state, prepared) {
        DecisionVerdict::AlreadyTerminal(outcome) => {
            assert_eq!(outcome, recorded);
        }
        other => panic!("expected the existing outcome, got {other:?}"),
    }
}

#[test]
fn one_transaction_appears_at_most_once_in_the_authenticated_decision_stream() {
    let mut fixture = Fixture::new(11);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    fixture.commit_ref(
        "k2",
        "refs/heads/dev",
        ExpectedRefState::Absent,
        oid(2),
        &[],
    );
    fixture.commit_ref(
        "k3",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(3),
        &[oid(1)],
    );

    let mut seen = BTreeSet::new();
    for decision in fixture.state.decisions() {
        assert!(
            seen.insert(decision.tx_id),
            "transaction {} decided twice",
            decision.tx_id
        );
    }
    assert_eq!(seen.len(), fixture.state.decisions().len());
    fixture.assert_structurally_sound();
}

// ---------------------------------------------------------------------------
// Acceptance: head transitions require the exact predecessor
// ---------------------------------------------------------------------------

#[test]
fn a_compare_and_swap_from_a_stale_predecessor_head_loses() {
    let mut fixture = Fixture::new(12);
    let stale_head = fixture.state.head().id;
    let stale_generation = fixture.state.head().body.generation;

    // Stage a batch against the genesis head.
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/dev",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let seal_request = SealRequest {
        seal_id: fixture.mint.seal(),
        request: request.clone(),
    };
    let (state, _) = seal(&fixture.state, &seal_request).expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    let mut bodies = BTreeMap::new();
    bodies.insert(
        request.tx_id,
        DecisionBodyIdentity {
            commit: fixture.mint.commit(),
            refusal_record: fixture.mint.refusal_record(),
        },
    );
    let (state, staged) = stage(
        &state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect("stage");
    let batch = expect_batch(&staged);

    // A competing transaction wins the head first.
    fixture.state = state;
    fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(5),
        &[],
    );
    assert_ne!(fixture.state.head().id, stale_head);

    // The original attempt now names a predecessor that is no longer current.
    let (after, outcome) = compare_and_swap(
        &fixture.state,
        CasRequest {
            expected_head: stale_head,
            expected_generation: stale_generation,
            batch,
        },
    )
    .expect("a lost compare-and-swap is ordinary, not a breach");

    match outcome {
        CasOutcome::Lost {
            current_head,
            current_generation,
        } => {
            assert_eq!(current_head, fixture.state.head().id);
            assert_eq!(current_generation, fixture.state.head().body.generation);
        }
        other => panic!("expected a lost compare-and-swap, got {other:?}"),
    }
    // Losing exposed nothing: the sealed request is still undecided and the
    // batch is still merely staged.
    assert_eq!(after.outcome_of(request.tx_id), None);
    assert!(after.staged(batch).is_some());
    assert!(!after.roots().refs.contains_key(&name("refs/heads/dev")));
    assert_eq!(after.head().id, fixture.state.head().id);
}

#[test]
fn a_compare_and_swap_naming_the_right_head_at_the_wrong_generation_loses() {
    // ABA defence: the identity alone is not enough, because a recycled
    // identity at a different generation is a different state (§4).
    let mut fixture = Fixture::new(13);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let seal_request = SealRequest {
        seal_id: fixture.mint.seal(),
        request: request.clone(),
    };
    let (state, _) = seal(&fixture.state, &seal_request).expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    let mut bodies = BTreeMap::new();
    bodies.insert(
        request.tx_id,
        DecisionBodyIdentity {
            commit: fixture.mint.commit(),
            refusal_record: fixture.mint.refusal_record(),
        },
    );
    let (state, staged) = stage(
        &state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect("stage");
    let batch = expect_batch(&staged);

    let wrong_generation = state.head().body.generation.next().unwrap();
    let (_, outcome) = compare_and_swap(
        &state,
        CasRequest {
            expected_head: state.head().id,
            expected_generation: wrong_generation,
            batch,
        },
    )
    .expect("a generation mismatch loses rather than breaching");
    assert!(
        matches!(outcome, CasOutcome::Lost { .. }),
        "outcome was {outcome:?}"
    );

    // Permitted twin: the same attempt with the exact generation wins.
    let (after, outcome) = compare_and_swap(
        &state,
        CasRequest {
            expected_head: state.head().id,
            expected_generation: state.head().body.generation,
            batch,
        },
    )
    .expect("cas");
    assert!(matches!(outcome, CasOutcome::Won { .. }));
    assert_eq!(after.roots().refs.get(&name("refs/heads/main")), Some(&new));
}

#[test]
fn every_head_names_its_exact_predecessor_across_many_generations() {
    let mut fixture = Fixture::new(14);
    let mut previous = fixture.state.head().id;
    let mut expected_generation = HeadGeneration::FIRST;

    for index in 0_u8..6 {
        let key = format!("k{index}");
        let target = format!("refs/heads/branch-{index}");
        let report =
            fixture.commit_ref(&key, &target, ExpectedRefState::Absent, oid(index + 1), &[]);
        assert!(report.is_committed(), "step {index} report {report:?}");

        expected_generation = expected_generation.next().unwrap();
        let head = fixture.state.head();
        assert_eq!(head.body.predecessor, Some(previous), "step {index}");
        assert_eq!(head.body.generation, expected_generation, "step {index}");
        previous = head.id;
        fixture.assert_structurally_sound();
    }

    assert_eq!(fixture.state.decisions().len(), 6);
    assert_eq!(fixture.state.commits().len(), 6);
}

#[test]
fn a_batch_staged_against_a_superseded_head_cannot_be_swapped_in_later() {
    // A batch that already won is no longer staged, so there is no second path
    // by which its decisions could be replayed into a later head.
    let mut fixture = Fixture::new(15);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    let published = *fixture
        .state
        .head()
        .body
        .decision_tail
        .as_ref()
        .expect("a published head names its batch");
    assert!(fixture.state.batch(published).is_some());
    assert!(fixture.state.staged(published).is_none());

    fixture.commit_ref(
        "k2",
        "refs/heads/dev",
        ExpectedRefState::Absent,
        oid(2),
        &[],
    );

    let breach = compare_and_swap(
        &fixture.state,
        CasRequest {
            expected_head: fixture.state.head().id,
            expected_generation: fixture.state.head().body.generation,
            batch: published,
        },
    )
    .expect_err("an already-published batch is not staged any more");
    assert!(
        matches!(*breach, InvariantBreach::UnstagedBatch { .. }),
        "breach was {breach:?}"
    );
    assert_eq!(fixture.state.decisions().len(), 2);
    fixture.assert_structurally_sound();
}

// ---------------------------------------------------------------------------
// Acceptance: a lost race is re-prepared, not refused (§5.2, §10 step 19)
// ---------------------------------------------------------------------------

/// Builds one forced, unconditional ref update and prepares it.
///
/// Unconditional and forced on purpose: §5.2 forbids changing the sealed
/// request on retry, so the sealed bytes have to be ones that stay applicable
/// after the ref moves. Anything pinned to an exact predecessor would be
/// refused by policy on the retry and would prove nothing about basis staleness.
fn prepared_forced_update(
    fixture: &mut Fixture,
    key: &str,
    new: GitOid,
    parents: &[GitOid],
) -> (RepositoryState, TransactionRequest, PreparedTxnCapsuleId) {
    let request = fixture
        .request(fixture.author, key)
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update("refs/heads/main", ExpectedRefState::Any, new, true)],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, parents)],
        },
    )
    .expect("quarantine");
    let (state, capsule) = reprepare(fixture, &state, &request);
    (state, request, capsule)
}

/// Prepares the **same** sealed request again against `state`.
fn reprepare(
    fixture: &mut Fixture,
    state: &RepositoryState,
    request: &TransactionRequest,
) -> (RepositoryState, PreparedTxnCapsuleId) {
    prepare(
        state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare")
}

/// The decision-body identities one transaction's decision may consume.
fn bodies_for(fixture: &mut Fixture, tx_id: TxId) -> BTreeMap<TxId, DecisionBodyIdentity> {
    let mut bodies = BTreeMap::new();
    bodies.insert(
        tx_id,
        DecisionBodyIdentity {
            commit: fixture.mint.commit(),
            refusal_record: fixture.mint.refusal_record(),
        },
    );
    bodies
}

/// The defect this test exists for: a capsule whose basis moved used to be
/// turned into a **terminal** `BasisCapsuleNotReusable` refusal, so a single
/// lost race permanently refused a request that §5.2 and §10 step 19 both say
/// must be retried. It is now a non-terminal re-preparation, and the retry of
/// the same sealed request commits.
#[test]
fn a_superseded_capsule_is_repreparable_and_the_retry_commits() {
    let mut fixture = Fixture::new(220);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    let (state, request, first) = prepared_forced_update(&mut fixture, "k1", oid(2), &[oid(1)]);
    assert_eq!(
        state.preparations_of(request.tx_id),
        1,
        "one preparation has been charged against the budget"
    );

    // Permitted twin: decided against the basis it read, the same capsule
    // commits.
    assert!(
        matches!(
            decide(&state, state.capsule(first).expect("capsule")),
            DecisionVerdict::Commit(_)
        ),
        "a capsule decided against its own basis must commit"
    );

    // A competing transaction wins the head and moves the very ref this
    // capsule read.
    fixture.state = state;
    let seal_before = *fixture.state.seal_of(request.tx_id).expect("seal");
    fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(8),
        &[oid(1)],
    );

    // The fix: a race, not a verdict.
    let superseded = fixture.state.capsule(first).expect("capsule survives");
    assert_eq!(
        decide(&fixture.state, superseded),
        DecisionVerdict::RequiresRepreparation(RepreparationReason::BasisSuperseded),
        "a superseded basis must not be a terminal decision"
    );
    assert!(
        fixture.state.outcome_of(request.tx_id).is_none(),
        "a lost race must leave the transaction undecided and retryable"
    );
    let seal_after = *fixture.state.seal_of(request.tx_id).expect("seal survives");
    assert_eq!(
        seal_after.fields, seal_before.fields,
        "re-preparation must not change the sealed request"
    );
    assert_eq!(seal_after.seal_id, seal_before.seal_id);

    // §5.2: re-prepare the same sealed request against the new basis.
    let basis = fixture.state.clone();
    let (state, retry) = reprepare(&mut fixture, &basis, &request);
    assert_ne!(retry, first, "the retry is a new capsule body");
    assert_eq!(state.preparations_of(request.tx_id), 2);

    let bodies = bodies_for(&mut fixture, request.tx_id);
    let (state, staged) = stage(
        &state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![retry],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect("stage");
    let batch = expect_batch(&staged);
    let (state, outcome) = compare_and_swap(
        &state,
        CasRequest {
            expected_head: state.head().id,
            expected_generation: state.head().body.generation,
            batch,
        },
    )
    .expect("compare and swap");

    assert!(
        matches!(outcome, CasOutcome::Won { .. }),
        "the retry lost the head as well: {outcome:?}"
    );
    assert!(
        matches!(
            state.outcome_of(request.tx_id),
            Some(DecisionOutcome::Committed { .. })
        ),
        "the retried transaction must commit"
    );
    assert_eq!(
        state.roots().refs.get(&name("refs/heads/main")),
        Some(&oid(2)),
        "the retry published its own effect"
    );
}

/// Staging must leave a superseded capsule out of the batch entirely. Writing
/// a refusal for it would consume decision sequence and make the transaction
/// terminal, which is the same defect one layer up.
#[test]
fn staging_defers_a_superseded_capsule_instead_of_deciding_it() {
    let mut fixture = Fixture::new(221);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    let (state, request, capsule) = prepared_forced_update(&mut fixture, "k1", oid(2), &[oid(1)]);

    fixture.state = state;
    fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(8),
        &[oid(1)],
    );

    let before = fixture.state.clone();
    let bodies = bodies_for(&mut fixture, request.tx_id);
    let (after, staged) = stage(
        &fixture.state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect("stage");

    assert!(
        staged.batch.is_none(),
        "nothing was decidable, so no batch may be staged: {staged:?}"
    );
    assert!(!staged.staged_anything());
    assert_eq!(
        staged.deferred,
        vec![(request.tx_id, RepreparationReason::BasisSuperseded)]
    );
    assert_eq!(
        after, before,
        "deferring must not change the state at all: no sequence consumed, no body introduced"
    );
    assert!(after.outcome_of(request.tx_id).is_none());
}

/// A batch is not all-or-nothing: the capsule that can still be decided is
/// batched, and only the superseded one is handed back.
#[test]
fn a_mixed_batch_stages_the_decidable_capsule_and_defers_the_superseded_one() {
    let mut fixture = Fixture::new(222);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    let (state, stale_request, stale_capsule) =
        prepared_forced_update(&mut fixture, "k1", oid(2), &[oid(1)]);

    // Move the ref the first capsule read, superseding it.
    fixture.state = state;
    fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(8),
        &[oid(1)],
    );

    // A second transaction prepared against the *current* basis, touching a
    // ref the first one never read.
    let fresh_request = fixture
        .request(fixture.author, "k3")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/dev",
                ExpectedRefState::Absent,
                oid(4),
                false,
            )],
        )
        .promising(oid(4))
        .build(&mut fixture.mint);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: fresh_request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: fresh_request.tx_id,
            objects: vec![object(oid(4), &[])],
        },
    )
    .expect("quarantine");
    let (state, fresh_capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: fresh_request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");

    let mut bodies = bodies_for(&mut fixture, stale_request.tx_id);
    bodies.extend(bodies_for(&mut fixture, fresh_request.tx_id));
    let (state, staged) = stage(
        &state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![stale_capsule, fresh_capsule],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect("stage");

    let batch = staged
        .batch
        .expect("the decidable capsule must still batch");
    assert_eq!(
        staged.deferred,
        vec![(stale_request.tx_id, RepreparationReason::BasisSuperseded)]
    );
    let decisions = state
        .staged(batch)
        .expect("staged")
        .batch
        .decisions()
        .to_vec();
    assert_eq!(decisions.len(), 1, "only one capsule was decidable");
    assert_eq!(decisions[0].tx_id, fresh_request.tx_id);
    assert!(
        decisions
            .iter()
            .all(|decision| decision.tx_id != stale_request.tx_id),
        "a deferred capsule must not appear in the authenticated decision stream"
    );
}

/// §16.5: the permission to retry is **bounded**. An unbounded one is a
/// livelock, not fairness — so once the sealed request has spent its
/// re-preparation budget, a capsule that is still stale is refused terminally
/// with the stale-basis code.
#[test]
fn the_repreparation_budget_is_finite_and_a_still_stale_capsule_is_then_refused() {
    let mut fixture = Fixture::new(223);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    let (state, request, first) = prepared_forced_update(&mut fixture, "k1", oid(2), &[oid(1)]);

    fixture.state = state;
    fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(8),
        &[oid(1)],
    );

    // Spend the budget on re-preparations of the same sealed request. Every
    // attempt before the last one is non-terminal.
    let mut state = fixture.state.clone();
    while state.preparations_of(request.tx_id) < REPREPARATION_BUDGET {
        let superseded = state.capsule(first).expect("capsule survives");
        assert_eq!(
            decide(&state, superseded),
            DecisionVerdict::RequiresRepreparation(RepreparationReason::BasisSuperseded),
            "attempt {} of {REPREPARATION_BUDGET} must still be retryable",
            state.preparations_of(request.tx_id)
        );
        let (next, _) = reprepare(&mut fixture, &state, &request);
        state = next;
    }

    assert_eq!(state.preparations_of(request.tx_id), REPREPARATION_BUDGET);
    let superseded = state.capsule(first).expect("capsule survives");
    assert_eq!(
        decide(&state, superseded),
        DecisionVerdict::Refuse(RefusalCode::BasisCapsuleNotReusable),
        "with the budget spent, a still-stale capsule is terminal"
    );
}

/// The budget is spent by re-preparation, not by losing races, so a
/// transaction that keeps winning is never pushed toward a refusal.
#[test]
fn a_transaction_that_never_reprepares_never_approaches_the_budget() {
    let mut fixture = Fixture::new(224);
    for (key, target) in [("k1", "refs/heads/a"), ("k2", "refs/heads/b")] {
        let request = fixture
            .request(fixture.author, key)
            .statement(
                MismatchPolicy::TxnAbort,
                vec![update(target, ExpectedRefState::Absent, oid(1), false)],
            )
            .promising(oid(1))
            .build(&mut fixture.mint);
        let tx_id = request.tx_id;
        let report = fixture.publish(&request, &[object(oid(1), &[])]);
        assert!(report.is_committed(), "{key} was {report:?}");
        assert!(
            report.deferred.is_empty(),
            "an uncontended publish must defer nothing"
        );
        assert!(report.repreparation_reason().is_none());
        assert_eq!(
            fixture.state.preparations_of(tx_id),
            1,
            "one preparation, so the budget is untouched"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance: every refusal in the declared surface, each with a permitted twin
// ---------------------------------------------------------------------------

/// Runs every refusal scenario and returns the codes they produced.
///
/// Each scenario is a pair: the forbidden case, and a near-identical permitted
/// case that must proceed. Keeping them in one function is what lets the
/// surface test below compare *observed* codes against the declared list.
fn refusal_scenarios() -> Vec<RefusalCode> {
    vec![
        refusal_ref_name_invalid(),
        refusal_schema_unsupported(),
        refusal_hash_domain_mismatch(),
        refusal_capability_scope_violation(),
        refusal_expected_old_mismatch(),
        refusal_non_fast_forward(),
        refusal_force_not_permitted(),
        refusal_protected_ref(),
        refusal_object_closure_incomplete(),
        refusal_native_object_id_mismatch(),
        refusal_resource_budget(),
        refusal_retention_hold(),
        refusal_policy_epoch_superseded(),
        refusal_basis_capsule_not_reusable(),
        refusal_forge_transition_invalid(),
        refusal_effect_idempotency_reuse(),
        refusal_conflicting_semantic_effects(),
        refusal_durability_profile_unavailable(),
    ]
}

fn refusal_ref_name_invalid() -> RefusalCode {
    let mut fixture = Fixture::new(100);
    // `HEAD` is a legal one-level ref name but sits outside the canonical
    // `refs/` namespace this slice admits.
    let head_ref = RefName::try_new_one_level(b"HEAD").expect("HEAD is a legal name");
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Ref(RefIntent::Update {
                name: head_ref,
                expected: ExpectedRefState::Absent,
                new,
                force: false,
            })],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(new, &[])]);
    let code = report.refusal_code().expect("HEAD must be refused");
    assert_eq!(code, RefusalCode::RefNameInvalid);

    // Permitted twin: the same update one namespace over proceeds.
    let twin = fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(2),
        &[],
    );
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_schema_unsupported() -> RefusalCode {
    let mut fixture = Fixture::new(101);
    let new = oid(1);

    // Before a seal exists, an unsupported schema is a *rejection*: not
    // repository history, and no seal is left behind.
    let unsealed = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .schema(unsupported_schema())
        .build(&mut fixture.mint);
    let (rejected, outcome) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: unsealed.clone(),
        },
    )
    .expect("a rejection is not a breach");
    assert_eq!(
        outcome,
        SealOutcome::Rejected(RequestRejectionCode::SchemaUnsupported)
    );
    assert!(
        rejected.seal_of(unsealed.tx_id).is_none(),
        "a rejection leaves no canonical trace"
    );

    // After a seal exists, the same dimension is a terminal *refusal*: the
    // repository stops supporting the schema between sealing and preparation.
    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let (state, sealed) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    assert!(matches!(sealed, SealOutcome::Created(_)));
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");

    // Permitted twin first: preparing while the schema is still supported
    // reaches a commit verdict.
    let (permitted, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    assert!(
        permitted
            .capsule(capsule)
            .expect("capsule")
            .verdict
            .is_commit(),
        "a supported schema must reach a commit verdict"
    );

    // Now withdraw the schema through a real configuration head transition.
    let mut narrowed = state.policy().clone();
    narrowed.epoch = narrowed.epoch.next().expect("epoch successor");
    narrowed.supported_schemas = BTreeSet::new();
    let (state, transition) = publish_configuration(
        &state,
        &ConfigurationRequest {
            candidate_head_id: fixture.mint.head(),
            expected_head: state.head().id,
            expected_generation: state.head().body.generation,
            policy: narrowed,
        },
    )
    .expect("configuration transition");
    assert!(matches!(transition, ConfigurationOutcome::Won { .. }));

    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request,
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    let code = state
        .capsule(capsule)
        .expect("capsule")
        .refusal_code()
        .expect("an unsupported schema must refuse after sealing");
    assert_eq!(code, RefusalCode::SchemaUnsupported);
    code
}

fn refusal_hash_domain_mismatch() -> RefusalCode {
    let mut fixture = Fixture::new(104);
    // The repository declares SHA-1. A SHA-256 identity is a different typed
    // domain, not a differently-encoded value of the same one.
    let foreign = sha256_oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                foreign,
                false,
            )],
        )
        .promising(foreign)
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(foreign, &[])]);
    let code = report
        .refusal_code()
        .expect("a cross-domain identity must be refused");
    assert_eq!(code, RefusalCode::HashAlgorithmDomainMismatch);

    // Permitted twin: the same bytes in the repository's declared domain.
    let twin = fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_capability_scope_violation() -> RefusalCode {
    let mut fixture = Fixture::new(105);
    let new = oid(1);
    // `narrow` may write `refs/heads` but not `refs/tags`.
    let request = fixture
        .request(fixture.narrow, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update("refs/tags/v1", ExpectedRefState::Absent, new, false)],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(new, &[])]);
    let code = report
        .refusal_code()
        .expect("writing outside the capability scope must be refused");
    assert_eq!(code, RefusalCode::CapabilityScopeViolation);

    // Permitted twin: the same principal, the same update, inside its scope.
    let permitted = fixture
        .request(fixture.narrow, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &[object(new, &[])]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");

    // And an unknown principal has no capability at all, rather than a default.
    let unknown = fixture
        .request(fixture.stranger, "k3")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/dev",
                ExpectedRefState::Absent,
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let stranger_report = fixture.publish(&unknown, &[object(oid(2), &[])]);
    assert_eq!(
        stranger_report.refusal_code(),
        Some(RefusalCode::CapabilityScopeViolation),
        "an unknown principal must not inherit a default capability"
    );
    code
}

fn refusal_expected_old_mismatch() -> RefusalCode {
    let mut fixture = Fixture::new(106);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(42)),
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(2), &[oid(1)])]);
    let code = report
        .refusal_code()
        .expect("a wrong expected-old value must be refused");
    assert_eq!(code, RefusalCode::ExpectedOldRefMismatch);

    // Permitted twin: the same update asserting the value the basis holds.
    let twin = fixture.commit_ref(
        "k3",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(2),
        &[oid(1)],
    );
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_non_fast_forward() -> RefusalCode {
    let mut fixture = Fixture::new(107);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    // oid(9) has no ancestry to oid(1), so this rewinds history.
    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(1)),
                oid(9),
                false,
            )],
        )
        .promising(oid(9))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(9), &[])]);
    let code = report
        .refusal_code()
        .expect("a non-fast-forward without force must be refused");
    assert_eq!(code, RefusalCode::NonFastForwardRefused);

    // Permitted twin: the identical update where the new commit descends from
    // the old one.
    let twin = fixture.commit_ref(
        "k3",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(9),
        &[oid(1)],
    );
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_force_not_permitted() -> RefusalCode {
    let mut fixture = Fixture::new(108);
    // `narrow` may write `refs/heads` but may not force.
    let first = fixture
        .request(fixture.narrow, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                oid(1),
                false,
            )],
        )
        .promising(oid(1))
        .build(&mut fixture.mint);
    assert!(
        fixture
            .publish(&first, &[object(oid(1), &[])])
            .is_committed()
    );

    let forced = fixture
        .request(fixture.narrow, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(1)),
                oid(9),
                true,
            )],
        )
        .promising(oid(9))
        .build(&mut fixture.mint);
    let report = fixture.publish(&forced, &[object(oid(9), &[])]);
    let code = report
        .refusal_code()
        .expect("forcing without the capability must be refused");
    assert_eq!(code, RefusalCode::ForceNotPermitted);

    // Permitted twin: the identical forced update by a principal that may
    // force.
    let permitted = fixture
        .request(fixture.author, "k3")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(1)),
                oid(9),
                true,
            )],
        )
        .promising(oid(9))
        .build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &[object(oid(9), &[])]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_protected_ref() -> RefusalCode {
    let mut fixture = Fixture::new(109);
    let created = fixture.commit_ref("k1", "refs/tags/v1", ExpectedRefState::Absent, oid(1), &[]);
    assert!(created.is_committed(), "creating a tag must be permitted");

    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![delete("refs/tags/v1", ExpectedRefState::Exact(oid(1)))],
        )
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[]);
    let code = report
        .refusal_code()
        .expect("deleting a protected ref must be refused");
    assert_eq!(code, RefusalCode::ProtectedRefTransitionDenied);

    // Permitted twin: the identical deletion in an unprotected namespace.
    let head_created = fixture.commit_ref(
        "k3",
        "refs/heads/scratch",
        ExpectedRefState::Absent,
        oid(2),
        &[],
    );
    assert!(head_created.is_committed());
    let permitted = fixture
        .request(fixture.author, "k4")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![delete(
                "refs/heads/scratch",
                ExpectedRefState::Exact(oid(2)),
            )],
        )
        .build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &[]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    assert!(
        !fixture
            .state
            .roots()
            .refs
            .contains_key(&name("refs/heads/scratch")),
        "the permitted deletion must actually delete"
    );
    code
}

fn refusal_object_closure_incomplete() -> RefusalCode {
    let mut fixture = Fixture::new(110);
    let promised = oid(3);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                promised,
                false,
            )],
        )
        .promising(promised)
        .build(&mut fixture.mint);
    // No objects staged: the promise cannot be honoured.
    let report = fixture.publish(&request, &[]);
    let code = report
        .refusal_code()
        .expect("an unhonoured promise must be refused");
    assert_eq!(code, RefusalCode::ObjectClosureIncomplete);

    // Permitted twin: the identical request with the object staged.
    let twin = fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Absent,
        promised,
        &[],
    );
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_native_object_id_mismatch() -> RefusalCode {
    let mut fixture = Fixture::new(111);
    let declared = oid(4);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                declared,
                false,
            )],
        )
        .promising(declared)
        .build(&mut fixture.mint);
    // The bytes hash to something else: promotion by verified identity fails.
    let report = fixture.publish(&request, &[corrupt_object(declared, oid(5))]);
    let code = report
        .refusal_code()
        .expect("a declared identity that does not match the bytes must be refused");
    assert_eq!(code, RefusalCode::NativeObjectIdMismatch);
    assert!(
        !fixture.state.is_admitted(declared),
        "an unverified object must never be promoted"
    );

    // Permitted twin: the identical request whose recomputed identity agrees.
    let twin = fixture.commit_ref(
        "k2",
        "refs/heads/main",
        ExpectedRefState::Absent,
        declared,
        &[],
    );
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    assert!(fixture.state.is_admitted(declared));
    code
}

fn refusal_resource_budget() -> RefusalCode {
    let mut fixture = Fixture::new(112);
    // The scenario policy admits 8 intents per transaction.
    let mut intents = Vec::new();
    for index in 0_u8..9 {
        intents.push(update(
            &format!("refs/heads/b{index}"),
            ExpectedRefState::Absent,
            oid(index + 1),
            false,
        ));
    }
    let mut builder = fixture
        .request(fixture.author, "k1")
        .statement(MismatchPolicy::TxnAbort, intents);
    let mut objects = Vec::new();
    for index in 0_u8..9 {
        builder = builder.promising(oid(index + 1));
        objects.push(object(oid(index + 1), &[]));
    }
    let request = builder.build(&mut fixture.mint);
    let report = fixture.publish(&request, &objects);
    let code = report
        .refusal_code()
        .expect("exceeding the intent bound must be refused");
    assert_eq!(code, RefusalCode::ResourceBudgetExceeded);

    // Permitted twin: exactly the bound, which proceeds.
    let mut intents = Vec::new();
    for index in 0_u8..8 {
        intents.push(update(
            &format!("refs/heads/c{index}"),
            ExpectedRefState::Absent,
            oid(index + 1),
            false,
        ));
    }
    let mut builder = fixture
        .request(fixture.author, "k2")
        .statement(MismatchPolicy::TxnAbort, intents);
    for index in 0_u8..8 {
        builder = builder.promising(oid(index + 1));
    }
    let permitted = builder.build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &objects);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_retention_hold() -> RefusalCode {
    let mut fixture = Fixture::new(113);
    let held = RetentionRoot {
        object: oid(1),
        class: RetentionClass::LegalHold,
    };
    let tombstone = RetentionRoot {
        object: oid(2),
        class: RetentionClass::GraceTombstone,
    };

    // Establish both roots first.
    let setup = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                Intent::Retention(RetentionIntent::AddRoot(held)),
                Intent::Retention(RetentionIntent::AddRoot(tombstone)),
            ],
        )
        .promising(oid(1))
        .promising(oid(2))
        .build(&mut fixture.mint);
    let setup_report = fixture.publish(&setup, &[object(oid(1), &[]), object(oid(2), &[])]);
    assert!(setup_report.is_committed(), "setup was {setup_report:?}");

    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Retention(RetentionIntent::RemoveRoot(held))],
        )
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[]);
    let code = report
        .refusal_code()
        .expect("removing a legal hold must be refused");
    assert_eq!(code, RefusalCode::RetentionHoldViolation);
    assert!(
        fixture.state.roots().retention.contains(&held),
        "the held root must survive the refusal"
    );

    // Permitted twin: retiring a grace tombstone, which is ordinarily
    // removable.
    let permitted = fixture
        .request(fixture.author, "k3")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Retention(RetentionIntent::RemoveRoot(tombstone))],
        )
        .build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &[]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    assert!(!fixture.state.roots().retention.contains(&tombstone));
    code
}

fn refusal_policy_epoch_superseded() -> RefusalCode {
    let mut fixture = Fixture::new(114);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");

    // Permitted twin: decided against the epoch it was prepared under, the
    // capsule commits.
    let prepared = state.capsule(capsule).expect("capsule");
    assert!(
        matches!(decide(&state, prepared), DecisionVerdict::Commit(_)),
        "a same-epoch decision must commit"
    );

    // A configuration transition moves the pinned epoch on. §15.9 pins one
    // policy epoch per attempt, so the capsule is no longer decidable.
    let mut moved = state.policy().clone();
    moved.epoch = moved.epoch.next().expect("epoch successor");
    let (superseded, transition) = publish_configuration(
        &state,
        &ConfigurationRequest {
            candidate_head_id: fixture.mint.head(),
            expected_head: state.head().id,
            expected_generation: state.head().body.generation,
            policy: moved,
        },
    )
    .expect("configuration transition");
    assert!(matches!(transition, ConfigurationOutcome::Won { .. }));

    // A moved epoch is a race first: §15.9's remedy is to re-evaluate the same
    // sealed request under the new snapshot, not to refuse it.
    let prepared = superseded.capsule(capsule).expect("capsule survives");
    assert_eq!(
        decide(&superseded, prepared),
        DecisionVerdict::RequiresRepreparation(RepreparationReason::PolicyEpochSuperseded),
        "the first superseded attempt must stay retryable"
    );

    // §16.5 bounds that permission. Once the budget is spent, the capsule
    // pinned to the retired epoch is terminal.
    let mut state = superseded;
    while state.preparations_of(request.tx_id) < REPREPARATION_BUDGET {
        let (next, _) = reprepare(&mut fixture, &state, &request);
        state = next;
    }
    let prepared = state.capsule(capsule).expect("capsule survives");
    let code = match decide(&state, prepared) {
        DecisionVerdict::Refuse(code) => code,
        other => panic!("expected a refusal once the budget was spent, got {other:?}"),
    };
    assert_eq!(code, RefusalCode::PolicyEpochSuperseded);
    code
}

fn refusal_basis_capsule_not_reusable() -> RefusalCode {
    let mut fixture = Fixture::new(115);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    // Prepare against the current head.
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(1)),
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(oid(2), &[oid(1)])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");

    // Permitted twin: a concurrent commit that touches a *different* ref does
    // not invalidate a refined witness.
    fixture.state = state;
    fixture.commit_ref(
        "k2",
        "refs/heads/other",
        ExpectedRefState::Absent,
        oid(7),
        &[],
    );
    let prepared = fixture.state.capsule(capsule).expect("capsule survives");
    assert!(
        matches!(decide(&fixture.state, prepared), DecisionVerdict::Commit(_)),
        "a disjoint concurrent commit must not invalidate a refined witness"
    );

    // Forbidden case: a concurrent commit that moves the very ref the capsule
    // read.
    fixture.commit_ref(
        "k3",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(8),
        &[oid(1)],
    );
    // Non-terminal first: §5.2's CAS loser re-prepares rather than being
    // refused. `a_superseded_capsule_is_repreparable_and_the_retry_commits`
    // carries the successful retry; this scenario carries the bounded end of
    // it.
    let prepared = fixture.state.capsule(capsule).expect("capsule survives");
    assert_eq!(
        decide(&fixture.state, prepared),
        DecisionVerdict::RequiresRepreparation(RepreparationReason::BasisSuperseded),
        "the first superseded attempt must stay retryable"
    );

    let mut state = fixture.state.clone();
    while state.preparations_of(request.tx_id) < REPREPARATION_BUDGET {
        let (next, _) = reprepare(&mut fixture, &state, &request);
        state = next;
    }
    let prepared = state.capsule(capsule).expect("capsule survives");
    let code = match decide(&state, prepared) {
        DecisionVerdict::Refuse(code) => code,
        other => panic!("expected a stale-basis refusal once the budget was spent, got {other:?}"),
    };
    assert_eq!(code, RefusalCode::BasisCapsuleNotReusable);
    code
}

fn refusal_forge_transition_invalid() -> RefusalCode {
    let mut fixture = Fixture::new(116);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    let stream = ForgeStreamId::new(label("pulls"));
    let entity = ForgeEntityId::new(label("pr-1"));

    // §7: a merge event without the ref effect that goes with it.
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::GENESIS,
                event: ForgeEventKind::PullRequestMerged {
                    pull_request: entity,
                    target: name("refs/heads/main"),
                },
            })],
        )
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[]);
    let code = report
        .refusal_code()
        .expect("a merge event without its ref effect must be refused");
    assert_eq!(code, RefusalCode::ForgeTransitionInvalid);

    // Permitted twin: the same event together with the ref update it describes.
    let permitted = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(1)),
                    oid(2),
                    false,
                ),
                Intent::Forge(ForgeIntent {
                    stream,
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: entity,
                        target: name("refs/heads/main"),
                    },
                }),
            ],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &[object(oid(2), &[oid(1)])]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    assert_eq!(
        fixture.state.roots().forge_positions.get(&stream),
        Some(&ForgeStreamPosition::GENESIS.successor()),
        "the forge stream must advance with the ref"
    );

    // And a stale expected position is refused with the same dimension.
    let stale = fixture
        .request(fixture.author, "k3")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::GENESIS,
                event: ForgeEventKind::PullRequestClosed {
                    pull_request: entity,
                },
            })],
        )
        .build(&mut fixture.mint);
    let stale_report = fixture.publish(&stale, &[]);
    assert_eq!(
        stale_report.refusal_code(),
        Some(RefusalCode::ForgeTransitionInvalid)
    );
    code
}

fn refusal_effect_idempotency_reuse() -> RefusalCode {
    let mut fixture = Fixture::new(117);
    let delivery = OutboxDeliveryKey::new(label("webhook-1"));
    let parameters = fixture.mint.digest();
    let different = fixture.mint.digest();

    let first = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Outbox(OutboxIntent {
                delivery_key: delivery,
                parameters,
            })],
        )
        .build(&mut fixture.mint);
    assert!(fixture.publish(&first, &[]).is_committed());

    // Same key, different canonical parameters.
    let conflicting = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Outbox(OutboxIntent {
                delivery_key: delivery,
                parameters: different,
            })],
        )
        .build(&mut fixture.mint);
    let report = fixture.publish(&conflicting, &[]);
    let code = report
        .refusal_code()
        .expect("rebinding a delivery key must be refused");
    assert_eq!(code, RefusalCode::EffectIdempotencyKeyReuse);

    // Permitted twin: same key, *identical* parameters, which is an absorbed
    // no-op rather than a refusal — this is what stops an outbox retry from
    // duplicating a canonical event.
    let retry = fixture
        .request(fixture.author, "k3")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![Intent::Outbox(OutboxIntent {
                delivery_key: delivery,
                parameters,
            })],
        )
        .build(&mut fixture.mint);
    let twin = fixture.publish(&retry, &[]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    assert_eq!(
        fixture.state.roots().outbox.get(&delivery),
        Some(&parameters),
        "the original binding must survive unchanged"
    );
    code
}

fn refusal_conflicting_semantic_effects() -> RefusalCode {
    let mut fixture = Fixture::new(118);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    let stream = ForgeStreamId::new(label("pulls"));
    let entity = ForgeEntityId::new(label("pr-1"));

    // "Merged into this ref" and "this ref is gone", in one record.
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                delete("refs/heads/main", ExpectedRefState::Exact(oid(1))),
                Intent::Forge(ForgeIntent {
                    stream,
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: entity,
                        target: name("refs/heads/main"),
                    },
                }),
            ],
        )
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[]);
    let code = report
        .refusal_code()
        .expect("contradictory effects on one target must be refused");
    assert_eq!(code, RefusalCode::ConflictingSemanticEffects);
    assert_eq!(
        fixture.state.roots().refs.get(&name("refs/heads/main")),
        Some(&oid(1)),
        "the refusal must leave the ref alone"
    );

    // Permitted twin: the same merge event with the ref *moved* rather than
    // deleted.
    let permitted = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(1)),
                    oid(2),
                    false,
                ),
                Intent::Forge(ForgeIntent {
                    stream,
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: entity,
                        target: name("refs/heads/main"),
                    },
                }),
            ],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &[object(oid(2), &[oid(1)])]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

fn refusal_durability_profile_unavailable() -> RefusalCode {
    let mut fixture = Fixture::new(119);
    let new = oid(1);
    // The scenario repository offers only the canonical source profile.
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .durability(DurabilityProfile::DerivedGeneration)
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(new, &[])]);
    let code = report
        .refusal_code()
        .expect("an unofferable durability profile must be refused");
    assert_eq!(code, RefusalCode::DurabilityProfileUnavailable);

    // Permitted twin: the identical request under the profile the repository
    // does offer.
    let permitted = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .durability(DurabilityProfile::CanonicalSource)
        .build(&mut fixture.mint);
    let twin = fixture.publish(&permitted, &[object(new, &[])]);
    assert!(twin.is_committed(), "permitted twin was {twin:?}");
    code
}

// Each refusal scenario gets its own named test, so a failure names the
// dimension rather than only "some refusal changed". The surface test above
// runs the same scenarios again to compare observed codes against the declared
// list; running them twice is cheap because every transition is pure.

#[test]
fn refuses_an_invalid_ref_name_and_permits_a_canonical_one() {
    assert_eq!(refusal_ref_name_invalid(), RefusalCode::RefNameInvalid);
}

#[test]
fn refuses_an_unsupported_schema_and_permits_a_supported_one() {
    assert_eq!(refusal_schema_unsupported(), RefusalCode::SchemaUnsupported);
}

#[test]
fn refuses_a_cross_hash_domain_identity_and_permits_the_declared_domain() {
    assert_eq!(
        refusal_hash_domain_mismatch(),
        RefusalCode::HashAlgorithmDomainMismatch
    );
}

#[test]
fn refuses_a_write_outside_the_capability_scope_and_permits_one_inside_it() {
    assert_eq!(
        refusal_capability_scope_violation(),
        RefusalCode::CapabilityScopeViolation
    );
}

#[test]
fn refuses_a_wrong_expected_old_value_and_permits_the_right_one() {
    assert_eq!(
        refusal_expected_old_mismatch(),
        RefusalCode::ExpectedOldRefMismatch
    );
}

#[test]
fn refuses_a_non_fast_forward_and_permits_a_descendant() {
    assert_eq!(
        refusal_non_fast_forward(),
        RefusalCode::NonFastForwardRefused
    );
}

#[test]
fn refuses_a_force_without_the_capability_and_permits_one_with_it() {
    assert_eq!(
        refusal_force_not_permitted(),
        RefusalCode::ForceNotPermitted
    );
}

#[test]
fn refuses_deleting_a_protected_ref_and_permits_deleting_an_unprotected_one() {
    assert_eq!(
        refusal_protected_ref(),
        RefusalCode::ProtectedRefTransitionDenied
    );
}

#[test]
fn refuses_an_unhonoured_object_promise_and_permits_an_honoured_one() {
    assert_eq!(
        refusal_object_closure_incomplete(),
        RefusalCode::ObjectClosureIncomplete
    );
}

#[test]
fn refuses_an_object_whose_identity_does_not_match_its_bytes() {
    assert_eq!(
        refusal_native_object_id_mismatch(),
        RefusalCode::NativeObjectIdMismatch
    );
}

#[test]
fn refuses_a_transaction_over_the_intent_bound_and_permits_one_at_it() {
    assert_eq!(
        refusal_resource_budget(),
        RefusalCode::ResourceBudgetExceeded
    );
}

#[test]
fn refuses_removing_a_legal_hold_and_permits_retiring_a_tombstone() {
    assert_eq!(
        refusal_retention_hold(),
        RefusalCode::RetentionHoldViolation
    );
}

#[test]
fn refuses_a_capsule_whose_pinned_policy_epoch_moved_on() {
    assert_eq!(
        refusal_policy_epoch_superseded(),
        RefusalCode::PolicyEpochSuperseded
    );
}

#[test]
fn refuses_a_capsule_whose_read_targets_changed_and_permits_a_disjoint_race() {
    assert_eq!(
        refusal_basis_capsule_not_reusable(),
        RefusalCode::BasisCapsuleNotReusable
    );
}

#[test]
fn refuses_a_merge_event_without_its_ref_effect_and_permits_one_with_it() {
    assert_eq!(
        refusal_forge_transition_invalid(),
        RefusalCode::ForgeTransitionInvalid
    );
}

#[test]
fn refuses_rebinding_a_delivery_key_and_permits_an_identical_retry() {
    assert_eq!(
        refusal_effect_idempotency_reuse(),
        RefusalCode::EffectIdempotencyKeyReuse
    );
}

#[test]
fn refuses_a_merge_that_deletes_its_own_target_and_permits_one_that_moves_it() {
    assert_eq!(
        refusal_conflicting_semantic_effects(),
        RefusalCode::ConflictingSemanticEffects
    );
}

#[test]
fn refuses_an_unofferable_durability_profile_and_permits_an_offered_one() {
    assert_eq!(
        refusal_durability_profile_unavailable(),
        RefusalCode::DurabilityProfileUnavailable
    );
}

#[test]
fn every_declared_refusal_is_produced_and_nothing_undeclared_is() {
    let observed = observed_refusals();
    let declared: BTreeSet<RefusalCode> = MODEL_REFUSAL_SURFACE.iter().copied().collect();

    let missing: Vec<&str> = declared
        .difference(&observed)
        .map(|code| code.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "declared but never produced by any scenario: {missing:?}"
    );

    let undeclared: Vec<&str> = observed
        .difference(&declared)
        .map(|code| code.as_str())
        .collect();
    assert!(
        undeclared.is_empty(),
        "produced but not declared in MODEL_REFUSAL_SURFACE: {undeclared:?}"
    );
}

#[test]
fn the_declared_surface_covers_twelve_of_the_thirteen_normative_classes() {
    let covered: BTreeSet<RefusalClass> = MODEL_REFUSAL_SURFACE
        .iter()
        .map(|code| RefusalClass::of(*code))
        .collect();
    let uncovered: Vec<&str> = RefusalClass::ALL
        .iter()
        .filter(|class| !covered.contains(class))
        .map(|class| class.as_str())
        .collect();
    assert_eq!(
        uncovered,
        vec!["InternalInvariant"],
        "the only class the model must not emit as a decision is InternalInvariant"
    );
    assert_eq!(covered.len(), 12);
}

// ---------------------------------------------------------------------------
// Sealing, idempotency, and the identity derivation law
// ---------------------------------------------------------------------------

#[test]
fn an_idempotency_key_reused_with_a_different_digest_is_rejected_before_any_seal() {
    let mut fixture = Fixture::new(20);
    let new = oid(1);
    let first = fixture
        .request(fixture.author, "shared-key")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let (state, outcome) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: first,
        },
    )
    .expect("seal");
    assert!(matches!(outcome, SealOutcome::Created(_)));

    // Same key, different semantics, therefore a different canonical digest
    // and a different transaction identity.
    let second = fixture
        .request(fixture.author, "shared-key")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/dev",
                ExpectedRefState::Absent,
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let (after, outcome) = seal(
        &state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: second.clone(),
        },
    )
    .expect("a rejection is not a breach");

    assert_eq!(
        outcome,
        SealOutcome::Rejected(RequestRejectionCode::IdempotencyKeyReuse)
    );
    // A rejection is not repository history: no seal, no decision, no sequence.
    assert!(after.seal_of(second.tx_id).is_none());
    assert_eq!(after.outcome_of(second.tx_id), None);
    assert_eq!(after.decisions(), &[]);
    assert_eq!(after.head().body.latest_decision_sequence, None);
    assert!(
        !after.is_terminal(second.tx_id),
        "a rejection must not alias the first request"
    );
}

#[test]
fn the_same_request_presented_twice_continues_under_the_existing_seal() {
    // The permitted twin of the rejection above: same key, same digest.
    let mut fixture = Fixture::new(21);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "shared-key")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let (state, first) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let created = match first {
        SealOutcome::Created(id) => id,
        other => panic!("expected a created seal, got {other:?}"),
    };

    let (after, second) = seal(
        &state,
        &SealRequest {
            // A retry may present a different seal-body identity; §5.2 keys on
            // the stable fields, and the existing seal wins.
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    assert_eq!(second, SealOutcome::ExistingRetry(created));
    assert_eq!(
        after.seal_of(request.tx_id).map(|seal| seal.seal_id),
        Some(created),
        "a retry must not replace the seal"
    );
}

#[test]
fn a_transaction_identity_presented_with_two_input_tuples_is_an_invariant_breach() {
    // §3.3's derivation must be injective. Presenting one identity for two
    // different canonical requests means it is not.
    let mut fixture = Fixture::new(22);
    let shared_tx = fixture.mint.tx();
    let digest_one = fixture.mint.digest();
    let digest_two = fixture.mint.digest();
    let new = oid(1);

    let first = fixture
        .request(fixture.author, "key-a")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build_with(shared_tx, digest_one);
    let (state, outcome) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: first,
        },
    )
    .expect("seal");
    assert!(matches!(outcome, SealOutcome::Created(_)));

    // Same identity, different key and digest: the seal's stable fields
    // conflict, which §5.2 makes a rejection.
    let second = fixture
        .request(fixture.author, "key-b")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build_with(shared_tx, digest_two);
    let (_, outcome) = seal(
        &state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: second,
        },
    )
    .expect("a conflicting stable field is a rejection");
    assert_eq!(
        outcome,
        SealOutcome::Rejected(RequestRejectionCode::IdempotencyKeyReuse)
    );
}

#[test]
fn two_requests_with_equal_derivation_inputs_must_carry_the_same_identity() {
    // The other half of the law: §3.3's derivation must be deterministic.
    let mut fixture = Fixture::new(23);
    let digest = fixture.mint.digest();
    let new = oid(1);

    let build = |fixture: &mut Fixture, tx| {
        fixture
            .request(fixture.author, "same-key")
            .statement(
                MismatchPolicy::TxnAbort,
                vec![update(
                    "refs/heads/main",
                    ExpectedRefState::Absent,
                    new,
                    false,
                )],
            )
            .promising(new)
            .build_with(tx, digest)
    };

    let tx_one = fixture.mint.tx();
    let first = build(&mut fixture, tx_one);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: first,
        },
    )
    .expect("seal");

    // Identical derivation inputs, different identity: the ledger catches it.
    let tx_two = fixture.mint.tx();
    let second = build(&mut fixture, tx_two);
    let breach = seal(
        &state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: second,
        },
    )
    .expect_err("a non-deterministic derivation must be caught");
    assert!(
        matches!(*breach, InvariantBreach::TxIdDerivationInconsistent { .. }),
        "breach was {breach:?}"
    );
}

// ---------------------------------------------------------------------------
// Purity and determinism
// ---------------------------------------------------------------------------

#[test]
fn no_transition_mutates_the_state_it_is_given() {
    let mut fixture = Fixture::new(30);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);

    let before = fixture.state.clone();
    let (state, _) = seal(
        &before,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    assert_eq!(before, fixture.state, "seal mutated its input");
    assert_ne!(state, before, "seal produced no change");

    let quarantined = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let checkpoint = state.clone();
    let (prepared_state, capsule) = prepare(
        &quarantined,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    assert_eq!(state, checkpoint, "prepare mutated an unrelated state");

    let mut bodies = BTreeMap::new();
    bodies.insert(
        request.tx_id,
        DecisionBodyIdentity {
            commit: fixture.mint.commit(),
            refusal_record: fixture.mint.refusal_record(),
        },
    );
    let before_stage = prepared_state.clone();
    let (staged_state, staged) = stage(
        &prepared_state,
        &StageRequest {
            batch_id: fixture.mint.batch(),
            candidate_head_id: fixture.mint.head(),
            capsules: vec![capsule],
            bodies,
            durability_satisfied: true,
        },
    )
    .expect("stage");
    let batch = expect_batch(&staged);
    assert_eq!(prepared_state, before_stage, "stage mutated its input");

    let before_cas = staged_state.clone();
    let (_, outcome) = compare_and_swap(
        &staged_state,
        CasRequest {
            expected_head: staged_state.head().id,
            expected_generation: staged_state.head().body.generation,
            batch,
        },
    )
    .expect("cas");
    assert!(matches!(outcome, CasOutcome::Won { .. }));
    assert_eq!(
        staged_state, before_cas,
        "the compare-and-swap mutated its input"
    );
}

#[test]
fn the_same_input_sequence_always_produces_an_identical_state() {
    let run = |seed: u64| {
        let mut fixture = Fixture::new(seed);
        fixture.commit_ref(
            "k1",
            "refs/heads/main",
            ExpectedRefState::Absent,
            oid(1),
            &[],
        );
        fixture.commit_ref(
            "k2",
            "refs/heads/dev",
            ExpectedRefState::Absent,
            oid(2),
            &[],
        );
        // A refusal in the middle, so the divergence surface includes the
        // decision stream and not only the commit stream.
        let refused = fixture
            .request(fixture.author, "k3")
            .statement(
                MismatchPolicy::TxnAbort,
                vec![update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(99)),
                    oid(3),
                    false,
                )],
            )
            .promising(oid(3))
            .build(&mut fixture.mint);
        fixture.publish(&refused, &[object(oid(3), &[oid(1)])]);
        fixture.commit_ref(
            "k4",
            "refs/heads/main",
            ExpectedRefState::Exact(oid(1)),
            oid(4),
            &[oid(1)],
        );
        fixture.state
    };

    let first = run(31);
    let second = run(31);
    assert_eq!(first, second, "the same input sequence diverged");
    assert_eq!(first.decisions(), second.decisions());
    assert_eq!(first.commits(), second.commits());
    assert_eq!(first.head(), second.head());
    assert_ne!(run(31), run(32), "different seeds must not collide");
}

#[test]
fn batch_admission_order_does_not_depend_on_the_order_capsules_are_listed() {
    // §16.3 requires a declared, replayable tie-break policy and forbids
    // iteration order from being publication semantics. The model admits in
    // ascending transaction-identity order, so any permutation of the same
    // capsule set produces the same batch.
    let build = |listed_forwards: bool| {
        let mut fixture = Fixture::new(33);
        let mut capsules = Vec::new();
        let mut bodies = BTreeMap::new();
        let mut state = fixture.state.clone();

        for index in 0_u8..3 {
            let new = oid(index + 1);
            let request = fixture
                .request(fixture.author, &format!("k{index}"))
                .statement(
                    MismatchPolicy::TxnAbort,
                    vec![update(
                        &format!("refs/heads/b{index}"),
                        ExpectedRefState::Absent,
                        new,
                        false,
                    )],
                )
                .promising(new)
                .build(&mut fixture.mint);
            let (next, _) = seal(
                &state,
                &SealRequest {
                    seal_id: fixture.mint.seal(),
                    request: request.clone(),
                },
            )
            .expect("seal");
            let next = stage_objects(
                &next,
                &QuarantineRequest {
                    tx_id: request.tx_id,
                    objects: vec![object(new, &[])],
                },
            )
            .expect("quarantine");
            let (next, capsule) = prepare(
                &next,
                &PrepareRequest {
                    capsule_id: fixture.mint.capsule(),
                    request: request.clone(),
                    principal_snapshot: fixture.mint.principal_snapshot(),
                    profile: IdentityMint::preparation_profile(),
                    granularity: WitnessGranularity::Refined,
                },
            )
            .expect("prepare");
            bodies.insert(
                request.tx_id,
                DecisionBodyIdentity {
                    commit: fixture.mint.commit(),
                    refusal_record: fixture.mint.refusal_record(),
                },
            );
            capsules.push(capsule);
            state = next;
        }

        if !listed_forwards {
            capsules.reverse();
        }
        let (staged_state, staged) = stage(
            &state,
            &StageRequest {
                batch_id: fixture.mint.batch(),
                candidate_head_id: fixture.mint.head(),
                capsules,
                bodies,
                durability_satisfied: true,
            },
        )
        .expect("stage");
        let batch = expect_batch(&staged);
        let decisions: Vec<PublishedDecision> = staged_state
            .staged(batch)
            .expect("staged")
            .batch
            .decisions()
            .to_vec();
        decisions
    };

    let forwards = build(true);
    let backwards = build(false);
    assert_eq!(
        forwards, backwards,
        "listing capsules in a different order changed the batch"
    );
    assert_eq!(forwards.len(), 3);
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

#[test]
fn cancellation_never_reports_non_commit_in_any_phase() {
    let mut fixture = Fixture::new(40);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);

    // Phase 1: before any seal exists.
    let before = step(
        &fixture.state,
        &ModelInput::Cancel(CancellationRequest {
            tx_id: request.tx_id,
            phase: CancellationPhase::BeforeSeal,
        }),
    )
    .expect("cancel");
    match before.output {
        ModelOutput::Cancelled(report) => {
            assert!(!report.seal_survives);
            assert!(!report.is_decided());
            assert!(!report.is_retryable());
        }
        other => panic!("expected a cancellation report, got {other:?}"),
    }
    assert_eq!(
        before.next, fixture.state,
        "a pre-seal cancel changes nothing"
    );

    // Phase 2: after sealing and preparing, before the compare-and-swap.
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    assert!(state.capsule(capsule).is_some());

    let drained = step(
        &state,
        &ModelInput::Cancel(CancellationRequest {
            tx_id: request.tx_id,
            phase: CancellationPhase::AfterSealBeforeCas,
        }),
    )
    .expect("cancel");
    match drained.output {
        ModelOutput::Cancelled(report) => {
            assert!(report.seal_survives, "the seal must survive the drain");
            assert!(!report.is_decided(), "cancelling does not decide");
            assert!(
                report.is_retryable(),
                "the same sealed request must remain retryable"
            );
        }
        other => panic!("expected a cancellation report, got {other:?}"),
    }
    assert!(
        drained.next.capsule(capsule).is_none(),
        "the drain must abandon prepared candidates"
    );
    assert!(
        drained.next.seal_of(request.tx_id).is_some(),
        "the drain must not remove the seal"
    );
    assert_eq!(drained.next.outcome_of(request.tx_id), None);

    // The retry continues the same logical transaction rather than starting a
    // second one.
    let (retried, outcome) = seal(
        &drained.next,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    assert!(matches!(outcome, SealOutcome::ExistingRetry(_)));
    assert!(retried.seal_of(request.tx_id).is_some());

    // Phase 3: after the compare-and-swap, the decision stands.
    fixture.state = fixture.state.clone();
    let committed = fixture.commit_ref(
        "k2",
        "refs/heads/other",
        ExpectedRefState::Absent,
        oid(5),
        &[],
    );
    assert!(committed.is_committed());
    let decided_tx = fixture
        .state
        .decisions()
        .last()
        .expect("one decision")
        .tx_id;
    let after = step(
        &fixture.state,
        &ModelInput::Cancel(CancellationRequest {
            tx_id: decided_tx,
            phase: CancellationPhase::AfterCas,
        }),
    )
    .expect("cancel");
    match after.output {
        ModelOutput::Cancelled(report) => {
            assert!(report.is_decided(), "the decision must stand");
            assert!(!report.is_retryable());
            assert!(matches!(
                report.outcome,
                Some(DecisionOutcome::Committed { .. })
            ));
        }
        other => panic!("expected a cancellation report, got {other:?}"),
    }
    assert_eq!(
        after.next.outcome_of(decided_tx),
        fixture.state.outcome_of(decided_tx),
        "cancelling after the compare-and-swap must not change the outcome"
    );
}

// ---------------------------------------------------------------------------
// The net-effect normal form
// ---------------------------------------------------------------------------

#[test]
fn every_source_intent_maps_to_exactly_one_disposition() {
    let mut fixture = Fixture::new(50);
    let refs = BTreeMap::new();
    let forge = BTreeMap::new();
    let retention = BTreeSet::new();
    let outbox = BTreeMap::new();
    let basis = FoldBasis {
        refs: &refs,
        forge_positions: &forge,
        retention: &retention,
        outbox: &outbox,
    };

    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                update("refs/heads/main", ExpectedRefState::Absent, oid(1), false),
                update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(1)),
                    oid(2),
                    false,
                ),
                update("refs/heads/dev", ExpectedRefState::Absent, oid(3), false),
            ],
        )
        .build(&mut fixture.mint);

    let report = ReferenceFolder.fold(basis, &request);
    assert!(
        report.is_total_for(&request),
        "the intent map must be total: {} mappings for {} intents",
        report.mappings.len(),
        request.intent_count()
    );

    let effects = report.effects().expect("the fold did not abort");
    // Target-disjointness is structural: one entry per ref, not one per intent.
    assert_eq!(effects.refs.len(), 2);
    assert_eq!(
        effects.refs.get(&name("refs/heads/main")),
        Some(&RefEffect::Set(oid(2))),
        "the last write to a target wins"
    );

    // The overwritten intent is absorbed with a named reason, not dropped.
    let dispositions: Vec<&IntentDisposition> = report
        .mappings
        .iter()
        .map(|mapping| &mapping.disposition)
        .collect();
    assert!(
        matches!(
            dispositions[0],
            IntentDisposition::Absorbed(AbsorptionReason::OverwrittenBySucceedingIntent)
        ),
        "first intent was {:?}",
        dispositions[0]
    );
    assert!(matches!(dispositions[1], IntentDisposition::Surviving(_)));
    assert!(matches!(dispositions[2], IntentDisposition::Surviving(_)));
}

#[test]
fn an_intent_and_its_inverse_cancel_to_a_named_absorption() {
    let mut fixture = Fixture::new(51);
    let mut refs = BTreeMap::new();
    refs.insert(name("refs/heads/main"), oid(1));
    let forge = BTreeMap::new();
    let retention = BTreeSet::new();
    let outbox = BTreeMap::new();
    let basis = FoldBasis {
        refs: &refs,
        forge_positions: &forge,
        retention: &retention,
        outbox: &outbox,
    };

    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(1)),
                    oid(2),
                    false,
                ),
                update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(2)),
                    oid(1),
                    false,
                ),
            ],
        )
        .build(&mut fixture.mint);

    let report = ReferenceFolder.fold(basis, &request);
    assert!(report.is_total_for(&request));
    let effects = report.effects().expect("folded");
    assert!(
        effects.is_empty(),
        "moving a ref and moving it back publishes nothing: {effects:?}"
    );
    assert!(
        report.mappings.iter().all(|mapping| matches!(
            mapping.disposition,
            IntentDisposition::Absorbed(
                AbsorptionReason::InverseCancelled | AbsorptionReason::IdentityEffect
            )
        )),
        "both intents must absorb with a named reason: {:?}",
        report.mappings
    );
}

#[test]
fn a_no_op_mismatch_policy_absorbs_where_an_abort_would_refuse() {
    let mut fixture = Fixture::new(52);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    // Under TxnAbort this is a refusal, as an earlier test shows. Under NoOp
    // the statement is absorbed and the transaction commits with no effect.
    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::NoOp,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(77)),
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(2), &[oid(1)])]);

    assert!(
        report.is_committed(),
        "a NoOp mismatch commits rather than refusing: {report:?}"
    );
    assert_eq!(
        fixture.state.roots().refs.get(&name("refs/heads/main")),
        Some(&oid(1)),
        "the absorbed intent must publish nothing"
    );
    // The decision consumed both sequences even though nothing changed: a
    // committed no-op is a commit.
    assert_eq!(fixture.state.commits().len(), 2);
    fixture.assert_structurally_sound();
}

#[test]
fn a_statement_error_fails_locally_and_leaves_its_siblings_alone() {
    let mut fixture = Fixture::new(53);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::StatementError,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(77)),
                oid(2),
                false,
            )],
        )
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/dev",
                ExpectedRefState::Absent,
                oid(3),
                false,
            )],
        )
        .promising(oid(2))
        .promising(oid(3))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(2), &[oid(1)]), object(oid(3), &[])]);

    assert!(report.is_committed(), "report was {report:?}");
    assert_eq!(
        fixture.state.roots().refs.get(&name("refs/heads/main")),
        Some(&oid(1)),
        "the failing statement must publish nothing"
    );
    assert_eq!(
        fixture.state.roots().refs.get(&name("refs/heads/dev")),
        Some(&oid(3)),
        "the sibling statement must still publish"
    );
}

#[test]
fn a_transaction_abort_publishes_nothing_at_all() {
    let mut fixture = Fixture::new(54);
    fixture.commit_ref(
        "k1",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    let request = fixture
        .request(fixture.author, "k2")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                update("refs/heads/dev", ExpectedRefState::Absent, oid(3), false),
                update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(77)),
                    oid(2),
                    false,
                ),
            ],
        )
        .promising(oid(2))
        .promising(oid(3))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(2), &[oid(1)]), object(oid(3), &[])]);

    assert_eq!(
        report.refusal_code(),
        Some(RefusalCode::ExpectedOldRefMismatch)
    );
    assert!(
        !fixture
            .state
            .roots()
            .refs
            .contains_key(&name("refs/heads/dev")),
        "the earlier intent in an aborted transaction must publish nothing"
    );
}

// ---------------------------------------------------------------------------
// Witnesses
// ---------------------------------------------------------------------------

#[test]
fn a_coarse_witness_that_reports_reusable_is_never_contradicted_by_the_refined_one() {
    // `INV-010`: refinement can only remove a false conflict, never admit a
    // true one. The coarse answer is the refined one conjoined with an
    // unchanged head generation, so this direction holds by construction — and
    // is asserted here so a future edit cannot quietly break it.
    let mut fixture = Fixture::new(60);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );

    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(1)),
                oid(2),
                false,
            )],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(oid(2), &[oid(1)])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request,
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");
    let witness = &state.capsule(capsule).expect("capsule").witness;
    let generation = state.head().body.generation;
    let epoch = state.policy().epoch;

    // Unchanged head: both granularities agree it is reusable.
    let coarse = witness.coarsened();
    let refined = witness.refined();
    assert!(coarse.is_reusable_against(state.roots(), generation, epoch));
    assert!(refined.is_reusable_against(state.roots(), generation, epoch));

    // Head moved but nothing this transaction read changed: the coarse witness
    // gives up, the refined one correctly does not. That is refinement
    // *removing a false conflict*.
    fixture.state = state;
    fixture.commit_ref(
        "k2",
        "refs/heads/unrelated",
        ExpectedRefState::Absent,
        oid(9),
        &[],
    );
    let moved_generation = fixture.state.head().body.generation;
    assert!(
        !coarse.is_reusable_against(fixture.state.roots(), moved_generation, epoch),
        "the coarse witness must be conservative once the head moves"
    );
    assert!(
        refined.is_reusable_against(fixture.state.roots(), moved_generation, epoch),
        "the refined witness must survive a disjoint concurrent commit"
    );

    // And when a true conflict happens, neither reports reusable.
    fixture.commit_ref(
        "k3",
        "refs/heads/main",
        ExpectedRefState::Exact(oid(1)),
        oid(8),
        &[oid(1)],
    );
    let conflicted_generation = fixture.state.head().body.generation;
    assert!(!coarse.is_reusable_against(fixture.state.roots(), conflicted_generation, epoch));
    assert!(
        !refined.is_reusable_against(fixture.state.roots(), conflicted_generation, epoch),
        "refinement must never admit a true conflict"
    );
}

// ---------------------------------------------------------------------------
// Durability
// ---------------------------------------------------------------------------

#[test]
fn an_unsatisfied_durability_predicate_leaves_the_batch_staged_and_retryable() {
    let mut fixture = Fixture::new(70);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);

    let (state, report) = publish(
        &fixture.state,
        &mut fixture.mint,
        &request,
        &[object(new, &[])],
        // The declared placement predicate has not been met yet.
        false,
    )
    .expect("publish");

    let batch = report.batch.expect("staged");
    assert!(
        matches!(report.cas, Some(CasOutcome::DurabilityUnsatisfied { .. })),
        "cas was {:?}",
        report.cas
    );
    // Not a refusal: the transaction is undecided, not rejected.
    assert_eq!(report.outcome, None);
    assert_eq!(report.refusal_code(), None);
    assert!(state.staged(batch).is_some(), "the batch must stay staged");
    assert!(state.roots().refs.is_empty(), "nothing became visible");
    assert_eq!(state.head().body.generation, HeadGeneration::FIRST);

    // Permitted twin: the same batch once the predicate is satisfied. The
    // model represents that as a batch staged with durability satisfied.
    let (after, second) = publish(
        &fixture.state,
        &mut fixture.mint,
        &request,
        &[object(new, &[])],
        true,
    )
    .expect("publish");
    assert!(second.is_committed(), "report was {second:?}");
    assert_eq!(after.roots().refs.get(&name("refs/heads/main")), Some(&new));
}

// ---------------------------------------------------------------------------
// Ref and forge effects publish together
// ---------------------------------------------------------------------------

#[test]
fn a_merge_moves_the_ref_and_advances_the_forge_stream_in_one_record() {
    // `INV-002`: one head compare-and-swap publishes ref and forge effects
    // atomically. In this model they live in one `NetEffects` on one record, so
    // "or neither does" is structural.
    let mut fixture = Fixture::new(80);
    fixture.commit_ref(
        "k0",
        "refs/heads/main",
        ExpectedRefState::Absent,
        oid(1),
        &[],
    );
    let stream = ForgeStreamId::new(label("pulls"));
    let entity = ForgeEntityId::new(label("pr-7"));

    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![
                update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(1)),
                    oid(2),
                    false,
                ),
                Intent::Forge(ForgeIntent {
                    stream,
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: ForgeEventKind::PullRequestMerged {
                        pull_request: entity,
                        target: name("refs/heads/main"),
                    },
                }),
            ],
        )
        .promising(oid(2))
        .build(&mut fixture.mint);
    let report = fixture.publish(&request, &[object(oid(2), &[oid(1)])]);
    assert!(report.is_committed(), "report was {report:?}");

    let record = fixture.state.commits().last().expect("one commit");
    assert_eq!(
        record.effects.refs.get(&name("refs/heads/main")),
        Some(&RefEffect::Set(oid(2))),
        "the ref effect must be on the record"
    );
    assert_eq!(
        record.effects.forge.get(&stream).map(Vec::len),
        Some(1),
        "the forge event must be on the same record"
    );
    assert_eq!(
        record.resulting_forge_positions.get(&stream),
        Some(&ForgeStreamPosition::GENESIS.successor())
    );
    fixture.assert_structurally_sound();
}

// ---------------------------------------------------------------------------
// The step function
// ---------------------------------------------------------------------------

#[test]
fn the_step_function_drives_the_same_transitions_as_calling_them_directly() {
    let mut fixture = Fixture::new(90);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let seal_id = fixture.mint.seal();

    let direct = seal(
        &fixture.state,
        &SealRequest {
            seal_id,
            request: request.clone(),
        },
    )
    .expect("seal");

    let stepped = step(
        &fixture.state,
        &ModelInput::Seal(Box::new(SealRequest { seal_id, request })),
    )
    .expect("step");

    assert_eq!(stepped.next, direct.0);
    assert_eq!(stepped.output, ModelOutput::Sealed(direct.1));
}

#[test]
fn deciding_through_the_step_function_changes_nothing() {
    let mut fixture = Fixture::new(91);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request,
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");

    let stepped = step(&state, &ModelInput::Decide { capsule }).expect("step");
    assert_eq!(stepped.next, state, "deciding must not change state");
    assert!(matches!(stepped.output, ModelOutput::Decided(_)));
}

#[test]
fn a_prepared_verdict_carries_no_sequence_and_cannot_publish_by_itself() {
    let mut fixture = Fixture::new(92);
    let new = oid(1);
    let request = fixture
        .request(fixture.author, "k1")
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/main",
                ExpectedRefState::Absent,
                new,
                false,
            )],
        )
        .promising(new)
        .build(&mut fixture.mint);
    let (state, _) = seal(
        &fixture.state,
        &SealRequest {
            seal_id: fixture.mint.seal(),
            request: request.clone(),
        },
    )
    .expect("seal");
    let state = stage_objects(
        &state,
        &QuarantineRequest {
            tx_id: request.tx_id,
            objects: vec![object(new, &[])],
        },
    )
    .expect("quarantine");
    let (state, capsule) = prepare(
        &state,
        &PrepareRequest {
            capsule_id: fixture.mint.capsule(),
            request: request.clone(),
            principal_snapshot: fixture.mint.principal_snapshot(),
            profile: IdentityMint::preparation_profile(),
            granularity: WitnessGranularity::Refined,
        },
    )
    .expect("prepare");

    let prepared = state.capsule(capsule).expect("capsule");
    assert!(matches!(prepared.verdict, PreparedVerdict::Commit(_)));
    assert_eq!(prepared.basis_head, state.head().id);
    assert_eq!(prepared.basis_generation, state.head().body.generation);
    assert!(
        prepared.intent_map.len() == request.intent_count(),
        "the capsule must carry the total intent map"
    );
    // The capsule decided nothing on its own.
    assert_eq!(state.outcome_of(request.tx_id), None);
    assert_eq!(state.decisions(), &[]);
    assert_eq!(state.head().body.generation, HeadGeneration::FIRST);
}
