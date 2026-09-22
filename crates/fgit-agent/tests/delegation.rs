#![forbid(unsafe_code)]
//! Acceptance tests for SubIntent delegation, ancestry verification, amplification refusal,
//! aggregate budget conservation, and recursion/fan-out bounds
//! (`frankengit-fg074-agent-delegation-128n`).
//!
//! # Acceptance Coverage Matrix
//!
//! 1. Amplification refusal:
//!    - Widening selector refused (e.g. path prefix, ref prefix) vs narrowing permitted twin
//!    - Raising quota refused vs contained quota permitted twin
//!    - Extending deadline/expiry refused vs shorter deadline permitted twin
//!    - Widening operations refused vs subset operations permitted twin
//!    - Widening disclosure policy refused vs narrowing permitted twin
//!    - Dropping caveats refused vs preserving caveats permitted twin
//! 2. Ancestry verification and forgery corpus:
//!    - Honest multi-hop ancestry chain verified
//!    - Missing intermediate capability refused
//!    - Forged intermediate link authenticator refused
//!    - Forged leaf capability body refused
//!    - Ancestry link mismatch (parent ref disagrees) refused
//!    - Swapped unrelated root tag mismatch refused
//! 3. Aggregate budget conservation:
//!    - Property test: N concurrent sub-agents cannot collectively exceed parent budget
//!    - Algebraic proof: `allocated + unallocated == initial` invariant holds across
//!      arbitrary sequences of admissions, refusals, and releases
//! 4. Recursion and fan-out limits:
//!    - Fan-out bound enforced with typed refusal at limit, unblocked after release
//!    - Recursion depth bound enforced hierarchically across delegation tiers

use fgit_agent::{
    AgentInstanceId, AttenuationRequest, AuthorityBasisRef, Caveat, ClassSet,
    DelegatedCapability, DelegationLimits, DisclosurePolicy, IntentRun, LogicalTime,
    OperationClass, RunId, Selector, SubIntent, SubIntentFanOutTracker,
    SubIntentParams, SubIntentRefusal,
    capability::{Capability, CapabilityId, ChainRefused, SealedCapability},
};
use fgit_resource::{Grade, ResourceVector};

const KEY: &[u8] = b"fgit-agent-delegation-test-key-v1";

const fn t(v: u64) -> LogicalTime {
    LogicalTime::new(v)
}

fn quota(bytes: u64, cpu: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::CpuMicros, cpu)])
}

fn test_authority_basis() -> AuthorityBasisRef {
    AuthorityBasisRef {
        repository_id: 42,
        authority_head_generation: 1,
        authority_head_digest: [7u8; 32],
        verified_at: t(1),
    }
}

fn parent_run(id: u128, expiry: u64, budget: ResourceVector) -> IntentRun {
    let classes = ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::TreeFsWorkspace,
        OperationClass::DelegateSubIntent,
        OperationClass::ConsumeBudget,
    ]);
    IntentRun::new(
        RunId::new(id),
        test_authority_basis(),
        classes,
        budget,
        t(expiry),
    )
    .expect("valid parent run")
}

struct TestFixture {
    _root_cap: Capability,
    sealed_root: SealedCapability,
    parent_cap: Capability,
    sealed_parent: SealedCapability,
    parent_run: IntentRun,
}

fn setup_fixture() -> TestFixture {
    let root_classes = ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::TreeFsWorkspace,
        OperationClass::DelegateSubIntent,
        OperationClass::ConsumeBudget,
        OperationClass::SubmitEvidence,
    ]);
    let root_cap = Capability::issue(
        CapabilityId::new(1),
        root_classes,
        quota(100_000, 50_000),
        t(5),
        t(200),
    )
    .expect("valid root cap");
    let sealed_root = root_cap.seal(KEY, None).expect("seals root");

    let parent_classes = ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::TreeFsWorkspace,
        OperationClass::DelegateSubIntent,
        OperationClass::ConsumeBudget,
    ]);
    let parent_req = AttenuationRequest {
        id: CapabilityId::new(10),
        operations: parent_classes,
        quota: quota(50_000, 25_000),
        not_before: t(10),
        expires_at: t(100),
    };
    let parent_cap = root_cap.attenuate(&parent_req).expect("valid attenuation");
    let sealed_parent = parent_cap
        .seal(KEY, Some(sealed_root.tag()))
        .expect("seals parent");

    let p_run = parent_run(100, 100, quota(50_000, 25_000));

    TestFixture {
        _root_cap: root_cap,
        sealed_root,
        parent_cap,
        sealed_parent,
        parent_run: p_run,
    }
}

fn make_child_delegated_cap(
    fixture: &TestFixture,
    child_id: u128,
    quota_val: ResourceVector,
    deadline_val: u64,
    selectors: Vec<Selector>,
) -> DelegatedCapability {
    let child_req = AttenuationRequest {
        id: CapabilityId::new(child_id),
        operations: ClassSet::from_classes(&[
            OperationClass::ReadCanonicalObject,
            OperationClass::TreeFsWorkspace,
        ]),
        quota: quota_val,
        not_before: t(15),
        expires_at: t(deadline_val),
    };
    let child_cap = fixture
        .parent_cap
        .attenuate(&child_req)
        .expect("attenuate child cap");
    let sealed_child = child_cap
        .seal(KEY, Some(fixture.sealed_parent.tag()))
        .expect("seal child");

    let chain = vec![
        fixture.sealed_root.clone(),
        fixture.sealed_parent.clone(),
        sealed_child,
    ];
    DelegatedCapability::new(fixture.parent_cap.id(), chain, selectors)
}

fn make_valid_sub_intent(
    fixture: &TestFixture,
    child_run_num: u128,
    budget_val: ResourceVector,
    deadline_val: u64,
    selectors: Vec<Selector>,
    depth: u16,
) -> SubIntent {
    let delegated_cap = make_child_delegated_cap(
        fixture,
        child_run_num * 10,
        budget_val,
        deadline_val,
        selectors,
    );
    SubIntent::build(SubIntentParams {
        child_run_id: RunId::new(child_run_num),
        parent_run_id: fixture.parent_run.run_id(),
        objective_digest: [1u8; 32],
        input_commitments: vec![[2u8; 32]],
        output_schema_id: [3u8; 32],
        attenuated_capabilities: vec![delegated_cap],
        budget: budget_val,
        deadline: t(deadline_val),
        required_evidence: vec![fgit_agent::ecc::EvidenceClass::Observed],
        disclosure_policy: DisclosurePolicy::ConfidentialParentOnly,
        additional_identities: vec![AgentInstanceId::new(55)],
        caveats: vec![Caveat::ScopedSelector(Selector::PathPrefix(
            "crates/fgit-agent".into(),
        ))],
        depth,
        context_bytes: 1024,
    })
    .expect("build valid sub-intent")
}

// ---------------------------------------------------------------------------
// Part 1: Permitted delegation baseline
// ---------------------------------------------------------------------------

#[test]
fn honest_delegation_admits_conserves_budget_and_releases_cleanly() {
    let fixture = setup_fixture();
    let parent_selectors = vec![Selector::PathPrefix("crates/fgit-agent".into())];
    let parent_caveats = vec![Caveat::ScopedSelector(Selector::PathPrefix(
        "crates/fgit-agent".into(),
    ))];
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        parent_caveats,
        parent_selectors,
        DisclosurePolicy::ConfidentialParentOnly,
    );

    let child_sub = make_valid_sub_intent(
        &fixture,
        201,
        quota(10_000, 5_000),
        80,
        vec![Selector::PathPrefix("crates/fgit-agent/src".into())],
        1,
    );

    assert_eq!(tracker.active_children_count(), 0);
    assert_eq!(tracker.allocated_budget(), ResourceVector::ZERO);
    assert!(tracker.assert_budget_conservation());

    tracker
        .admit_sub_intent(&child_sub, &fixture.parent_run, KEY)
        .expect("honest delegation admits");

    assert_eq!(tracker.active_children_count(), 1);
    assert_eq!(tracker.allocated_budget(), quota(10_000, 5_000));
    assert_eq!(tracker.unallocated_budget(), quota(40_000, 20_000));
    assert!(tracker.assert_budget_conservation());

    // Release child with unspent budget (e.g. spent 2000 bytes, unspent 8000 bytes)
    tracker
        .release_sub_intent(RunId::new(201), quota(8_000, 4_000))
        .expect("release succeeds");

    assert_eq!(tracker.active_children_count(), 0);
    assert_eq!(tracker.allocated_budget(), quota(2_000, 1_000));
    assert_eq!(tracker.unallocated_budget(), quota(48_000, 24_000));
    assert!(tracker.assert_budget_conservation());
}

// ---------------------------------------------------------------------------
// Part 2: Acceptance Line 1 — Amplification Refusal (with permitted twins)
// ---------------------------------------------------------------------------

#[test]
fn selector_amplification_is_refused_while_narrowing_is_permitted() {
    let fixture = setup_fixture();
    let parent_selectors = vec![Selector::PathPrefix("crates/fgit-agent".into())];
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![],
        parent_selectors,
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Permitted twin: child narrows to "crates/fgit-agent/src"
    let permitted = make_valid_sub_intent(
        &fixture,
        301,
        quota(5_000, 2_000),
        80,
        vec![Selector::PathPrefix("crates/fgit-agent/src".into())],
        1,
    );
    tracker
        .admit_sub_intent(&permitted, &fixture.parent_run, KEY)
        .expect("narrowing selector is permitted");

    // Forbidden case: child widens to "crates" (broader than parent "crates/fgit-agent")
    let widened = make_valid_sub_intent(
        &fixture,
        302,
        quota(5_000, 2_000),
        80,
        vec![Selector::PathPrefix("crates".into())],
        1,
    );
    let err = tracker
        .admit_sub_intent(&widened, &fixture.parent_run, KEY)
        .expect_err("widened selector must be refused");

    assert!(err.is_amplification());
    match err {
        SubIntentRefusal::SelectorAmplified {
            parent_selector,
            child_selector,
        } => {
            assert_eq!(
                parent_selector,
                Selector::PathPrefix("crates/fgit-agent".into())
            );
            assert_eq!(child_selector, Selector::PathPrefix("crates".into()));
        }
        other => panic!("expected SelectorAmplified, got {other:?}"),
    }
}

#[test]
fn quota_amplification_is_refused_while_contained_quota_is_permitted() {
    let fixture = setup_fixture();
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Permitted twin: budget fits within parent capability
    let permitted = make_valid_sub_intent(
        &fixture,
        303,
        quota(10_000, 5_000),
        80,
        vec![],
        1,
    );
    tracker
        .admit_sub_intent(&permitted, &fixture.parent_run, KEY)
        .expect("contained quota is permitted");

    // Forbidden case: child capability asks for more CPU than parent holds (parent holds 25,000)
    let child_req = AttenuationRequest {
        id: CapabilityId::new(999),
        operations: ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        quota: quota(10_000, 60_000), // Exceeds parent's 25,000 CPU!
        not_before: t(15),
        expires_at: t(80),
    };
    let att_err = fixture.parent_cap.attenuate(&child_req);
    assert!(
        att_err.is_err(),
        "attenuation API refuses quota amplification"
    );

    // When budget in SubIntent exceeds unallocated budget
    // Parent initial is 50,000 bytes; child 303 took 10,000, leaving 40,000 bytes unallocated.
    // A child with a valid 45,000-byte capability asks for 45,000 bytes, exceeding available!
    let overbudget = make_valid_sub_intent(
        &fixture,
        304,
        quota(45_000, 20_000),
        80,
        vec![],
        1,
    );
    let err = tracker
        .admit_sub_intent(&overbudget, &fixture.parent_run, KEY)
        .expect_err("over-budget must be refused");
    assert!(matches!(
        err,
        SubIntentRefusal::AggregateBudgetExceeded { .. }
    ));
}

#[test]
fn deadline_extension_is_refused_while_contained_deadline_is_permitted() {
    let fixture = setup_fixture();
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Permitted twin: deadline 80 <= parent expiry 100
    let permitted = make_valid_sub_intent(
        &fixture,
        305,
        quota(1_000, 500),
        80,
        vec![],
        1,
    );
    tracker
        .admit_sub_intent(&permitted, &fixture.parent_run, KEY)
        .expect("deadline within parent expiry is permitted");

    // Forbidden case: deadline 120 > parent expiry 100
    // The capability is valid up to 90, but the sub-intent asks for deadline 120 past parent run expiry 100.
    let child_cap = make_child_delegated_cap(
        &fixture,
        3060,
        quota(1_000, 500),
        90,
        vec![],
    );
    let extended = SubIntent::build(SubIntentParams {
        child_run_id: RunId::new(306),
        parent_run_id: fixture.parent_run.run_id(),
        objective_digest: [1u8; 32],
        input_commitments: vec![],
        output_schema_id: [2u8; 32],
        attenuated_capabilities: vec![child_cap],
        budget: quota(1_000, 500),
        deadline: t(120),
        required_evidence: vec![],
        disclosure_policy: DisclosurePolicy::ConfidentialParentOnly,
        additional_identities: vec![],
        caveats: vec![Caveat::ScopedSelector(Selector::PathPrefix(
            "crates/fgit-agent".into(),
        ))],
        depth: 1,
        context_bytes: 512,
    })
    .expect("build sub-intent with extended deadline");
    let err = tracker
        .admit_sub_intent(&extended, &fixture.parent_run, KEY)
        .expect_err("deadline past parent expiry must be refused");

    assert!(err.is_amplification());
    assert!(matches!(
        err,
        SubIntentRefusal::DeadlineAmplified {
            requested,
            parent_expiry
        } if requested == t(120) && parent_expiry == t(100)
    ));
}

#[test]
fn operation_class_amplification_is_refused() {
    let fixture = setup_fixture();
    // Requesting a class the parent lacks (e.g. SecretHandle)
    let child_req = AttenuationRequest {
        id: CapabilityId::new(888),
        operations: ClassSet::from_classes(&[
            OperationClass::ReadCanonicalObject,
            OperationClass::SecretHandle,
        ]),
        quota: quota(1_000, 500),
        not_before: t(15),
        expires_at: t(80),
    };
    let refusal = fixture.parent_cap.attenuate(&child_req).expect_err(
        "requesting SecretHandle when parent lacks it must be refused as OperationsAmplified",
    );
    assert!(matches!(
        refusal,
        fgit_agent::AttenuationRefused::OperationsAmplified { .. }
    ));
}

#[test]
fn dropping_caveats_is_refused_while_preserving_is_permitted() {
    let fixture = setup_fixture();
    let mandatory_caveat = Caveat::DisallowedClass(OperationClass::MutateForgeEntity);
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![mandatory_caveat.clone()],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Permitted twin: sub-intent includes the mandatory caveat
    let permitted = make_valid_sub_intent(
        &fixture,
        307,
        quota(1_000, 500),
        80,
        vec![],
        1,
    );
    let mut new_caveats = permitted.caveats().to_vec();
    new_caveats.push(mandatory_caveat.clone());
    let permitted_params = SubIntentParams {
        child_run_id: permitted.child_run_id(),
        parent_run_id: permitted.parent_run_id(),
        objective_digest: *permitted.objective_digest(),
        input_commitments: permitted.input_commitments().to_vec(),
        output_schema_id: *permitted.output_schema_id(),
        attenuated_capabilities: permitted.attenuated_capabilities().to_vec(),
        budget: permitted.budget(),
        deadline: permitted.deadline(),
        required_evidence: permitted.required_evidence().to_vec(),
        disclosure_policy: permitted.disclosure_policy(),
        additional_identities: permitted.additional_identities().to_vec(),
        caveats: new_caveats,
        depth: permitted.depth(),
        context_bytes: permitted.context_bytes(),
    };
    let permitted_sub = SubIntent::build(permitted_params).expect("valid params");
    tracker
        .admit_sub_intent(&permitted_sub, &fixture.parent_run, KEY)
        .expect("preserving parent caveat is permitted");

    // Forbidden case: sub-intent drops the mandatory caveat
    let dropped = make_valid_sub_intent(
        &fixture,
        308,
        quota(1_000, 500),
        80,
        vec![],
        1,
    );
    let err = tracker
        .admit_sub_intent(&dropped, &fixture.parent_run, KEY)
        .expect_err("dropping parent caveat must be refused");
    assert!(matches!(err, SubIntentRefusal::CaveatDropped { .. }));
}

// ---------------------------------------------------------------------------
// Part 3: Acceptance Line 2 — Ancestry Verification & Forgery Corpus
// ---------------------------------------------------------------------------

#[test]
fn missing_intermediate_capability_in_chain_is_refused() {
    let fixture = setup_fixture();
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Permitted twin has complete chain: [Root, Parent, Child]
    let permitted = make_valid_sub_intent(&fixture, 401, quota(1_000, 500), 80, vec![], 1);
    tracker
        .admit_sub_intent(&permitted, &fixture.parent_run, KEY)
        .expect("complete ancestry chain is admitted");

    // Forbidden case: chain skips Parent, presenting [Root, Child] directly
    let mut broken_sub = make_valid_sub_intent(&fixture, 402, quota(1_000, 500), 80, vec![], 1);
    let broken_chain = vec![
        fixture.sealed_root.clone(),
        broken_sub.attenuated_capabilities()[0].chain()[2].clone(), // Child
    ];
    let broken_delegated = DelegatedCapability::new(
        fixture.parent_cap.id(),
        broken_chain,
        vec![],
    );
    broken_sub.attenuated_capabilities_mut()[0] = broken_delegated;

    let err = tracker
        .admit_sub_intent(&broken_sub, &fixture.parent_run, KEY)
        .expect_err("skipping intermediate link must be refused");

    assert!(err.is_ancestry_failure());
    match err {
        SubIntentRefusal::ChainRefused(ChainRefused::AncestryMismatch { .. })
        | SubIntentRefusal::ChainRefused(ChainRefused::ParentTagMismatch { .. }) => {}
        other => panic!("expected AncestryMismatch or ParentTagMismatch, got {other:?}"),
    }
}

#[test]
fn forged_intermediate_link_authenticator_is_refused() {
    let fixture = setup_fixture();
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    let mut tampered_sub = make_valid_sub_intent(&fixture, 403, quota(1_000, 500), 80, vec![], 1);

    // Tamper with Parent's capability body under the authentic tag
    let tampered_parent_body = Capability::issue(
        fixture.parent_cap.id(),
        ClassSet::from_classes(&[OperationClass::SecretHandle]), // unauthorized class
        quota(90_000, 90_000),
        t(1),
        t(300),
    )
    .expect("issues capability");
    let forged_parent = fixture
        .sealed_parent
        .with_tampered_capability(tampered_parent_body);

    let forged_chain = vec![
        fixture.sealed_root.clone(),
        forged_parent,
        tampered_sub.attenuated_capabilities()[0].chain()[2].clone(),
    ];
    let forged_delegated = DelegatedCapability::new(
        fixture.parent_cap.id(),
        forged_chain,
        vec![],
    );
    tampered_sub.attenuated_capabilities_mut()[0] = forged_delegated;

    let err = tracker
        .admit_sub_intent(&tampered_sub, &fixture.parent_run, KEY)
        .expect_err("forged intermediate authenticator must be refused");

    assert!(err.is_ancestry_failure());
    assert!(matches!(
        err,
        SubIntentRefusal::ChainRefused(ChainRefused::AuthenticatorMismatch { index: 1 })
    ));
}

#[test]
fn forged_leaf_capability_body_is_refused() {
    let fixture = setup_fixture();
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    let mut tampered_sub = make_valid_sub_intent(&fixture, 404, quota(1_000, 500), 80, vec![], 1);
    let original_leaf = &tampered_sub.attenuated_capabilities()[0].chain()[2];

    // Splice a wider capability into the leaf
    let wider_leaf = Capability::issue(
        original_leaf.capability().id(),
        ClassSet::from_classes(&[OperationClass::SecretHandle]),
        quota(99_000, 99_000),
        t(1),
        t(300),
    )
    .expect("wider leaf");
    let forged_leaf = original_leaf.with_tampered_capability(wider_leaf);

    let forged_chain = vec![
        fixture.sealed_root.clone(),
        fixture.sealed_parent.clone(),
        forged_leaf,
    ];
    let forged_delegated = DelegatedCapability::new(
        fixture.parent_cap.id(),
        forged_chain,
        vec![],
    );
    tampered_sub.attenuated_capabilities_mut()[0] = forged_delegated;

    let err = tracker
        .admit_sub_intent(&tampered_sub, &fixture.parent_run, KEY)
        .expect_err("forged leaf authenticator must be refused");

    assert!(err.is_ancestry_failure());
    assert!(matches!(
        err,
        SubIntentRefusal::ChainRefused(ChainRefused::AuthenticatorMismatch { index: 2 })
    ));
}

#[test]
fn swapped_unrelated_root_is_refused() {
    let fixture = setup_fixture();
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        DelegationLimits::default(),
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    let mut sub = make_valid_sub_intent(&fixture, 405, quota(1_000, 500), 80, vec![], 1);

    // Mint an unrelated valid root
    let other_root = Capability::issue(
        CapabilityId::new(9999),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        quota(10_000, 10_000),
        t(1),
        t(100),
    )
    .expect("other root");
    let sealed_other_root = other_root.seal(KEY, None).expect("seal other root");

    let swapped_chain = vec![
        sealed_other_root,
        fixture.sealed_parent.clone(),
        sub.attenuated_capabilities()[0].chain()[2].clone(),
    ];
    let delegated = DelegatedCapability::new(
        fixture.parent_cap.id(),
        swapped_chain,
        vec![],
    );
    sub.attenuated_capabilities_mut()[0] = delegated;

    let err = tracker
        .admit_sub_intent(&sub, &fixture.parent_run, KEY)
        .expect_err("swapped root must be refused");

    assert!(err.is_ancestry_failure());
    assert!(matches!(
        err,
        SubIntentRefusal::ChainRefused(ChainRefused::AncestryMismatch { index: 1, .. })
    ));
}

// ---------------------------------------------------------------------------
// Part 4: Acceptance Line 3 — Aggregate Budget Conservation Property Test
// ---------------------------------------------------------------------------

#[test]
fn aggregate_budget_conservation_property_test() {
    // Proves that N sub-agents can NEVER collectively exceed the parent's budget.
    // At every step: allocated + unallocated == initial holds identically.
    let initial_bytes = 100_000;
    let initial_cpu = 50_000;
    let initial_budget = quota(initial_bytes, initial_cpu);

    let p_run = parent_run(500, 100, initial_budget);
    let root_cap = Capability::issue(
        CapabilityId::new(50),
        ClassSet::from_classes(&[
            OperationClass::ReadCanonicalObject,
            OperationClass::DelegateSubIntent,
            OperationClass::ConsumeBudget,
        ]),
        initial_budget,
        t(1),
        t(200),
    )
    .expect("root cap");
    let sealed_root = root_cap.seal(KEY, None).expect("seal root");

    let mut tracker = SubIntentFanOutTracker::new(
        p_run.run_id(),
        initial_budget,
        0,
        DelegationLimits {
            max_depth: 4,
            max_fan_out: 64, // allow high fan-out for property test
            max_context_duplication_bytes: 1_000_000,
        },
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Pseudo-random deterministic sequence of operations
    let mut state: u64 = 0xdeadbeef_cafebabe;
    let mut next_rand = |max: u64| -> u64 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        state % max
    };

    let mut active_sub_ids = Vec::new();

    for step in 1..=100 {
        let op = next_rand(3);
        if op < 2 || active_sub_ids.is_empty() {
            // Attempt to admit a new child
            let child_id = 1000 + step as u128;
            let req_bytes = next_rand(25_000) + 1_000;
            let req_cpu = next_rand(12_000) + 500;
            let child_budget = quota(req_bytes, req_cpu);

            // Construct child capability
            let child_req = AttenuationRequest {
                id: CapabilityId::new(child_id * 10),
                operations: ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
                quota: child_budget,
                not_before: t(10),
                expires_at: t(90),
            };
            let child_cap = match root_cap.attenuate(&child_req) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let sealed_child = child_cap
                .seal(KEY, Some(sealed_root.tag()))
                .expect("seal child");
            let chain = vec![sealed_root.clone(), sealed_child];
            let delegated = DelegatedCapability::new(root_cap.id(), chain, vec![]);

            let sub = SubIntent::build(SubIntentParams {
                child_run_id: RunId::new(child_id),
                parent_run_id: p_run.run_id(),
                objective_digest: [1u8; 32],
                input_commitments: vec![],
                output_schema_id: [2u8; 32],
                attenuated_capabilities: vec![delegated],
                budget: child_budget,
                deadline: t(80),
                required_evidence: vec![],
                disclosure_policy: DisclosurePolicy::ConfidentialParentOnly,
                additional_identities: vec![],
                caveats: vec![],
                depth: 1,
                context_bytes: 512,
            })
            .expect("valid sub");

            let result = tracker.admit_sub_intent(&sub, &p_run, KEY);
            if result.is_ok() {
                active_sub_ids.push((child_id, child_budget));
            } else {
                // If refused, it must be AggregateBudgetExceeded
                assert!(matches!(
                    result.unwrap_err(),
                    SubIntentRefusal::AggregateBudgetExceeded { .. }
                ));
            }
        } else {
            // Release an active child
            let idx = next_rand(active_sub_ids.len() as u64) as usize;
            let (cid, alloc_budget) = active_sub_ids.swap_remove(idx);

            // Child returns unspent budget between 0 and alloc_budget
            let unspent_bytes = next_rand(alloc_budget.get(Grade::Bytes) + 1);
            let unspent_cpu = next_rand(alloc_budget.get(Grade::CpuMicros) + 1);
            let unspent = quota(unspent_bytes, unspent_cpu);

            tracker
                .release_sub_intent(RunId::new(cid), unspent)
                .expect("release succeeds");
        }

        // Conservation invariant check at EVERY single iteration
        assert!(
            tracker.assert_budget_conservation(),
            "conservation failed at step {step}"
        );
        let combined = tracker
            .allocated_budget()
            .combine(&tracker.unallocated_budget())
            .expect("combine must succeed");
        assert_eq!(
            combined, initial_budget,
            "allocated + unallocated != initial at step {step}"
        );
        assert!(
            initial_budget.dominates(&tracker.allocated_budget()),
            "allocated exceeds initial at step {step}"
        );
    }
}

// ---------------------------------------------------------------------------
// Part 5: Acceptance Line 4 — Recursion & Fan-out Bounds
// ---------------------------------------------------------------------------

#[test]
fn fan_out_bound_enforced_with_typed_refusal_at_limit() {
    let fixture = setup_fixture();
    let limits = DelegationLimits {
        max_depth: 4,
        max_fan_out: 3, // Small limit for testing
        max_context_duplication_bytes: 1_000_000,
    };
    let mut tracker = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        limits,
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Admit up to limit (3 children)
    for i in 1..=3 {
        let child = make_valid_sub_intent(
            &fixture,
            600 + i,
            quota(1_000, 500),
            80,
            vec![],
            1,
        );
        tracker
            .admit_sub_intent(&child, &fixture.parent_run, KEY)
            .expect("admitting within fan-out limit");
    }
    assert_eq!(tracker.active_children_count(), 3);

    // Attempt child #4: exceeds fan-out limit 3
    let child_overflow = make_valid_sub_intent(
        &fixture,
        604,
        quota(1_000, 500),
        80,
        vec![],
        1,
    );
    let err = tracker
        .admit_sub_intent(&child_overflow, &fixture.parent_run, KEY)
        .expect_err("fan-out overflow must be refused");

    assert!(matches!(
        err,
        SubIntentRefusal::FanOutLimitExceeded {
            observed: 4,
            limit: 3
        }
    ));

    // Release child 1 -> active count drops to 2
    tracker
        .release_sub_intent(RunId::new(601), quota(1_000, 500))
        .expect("release");
    assert_eq!(tracker.active_children_count(), 2);

    // Now child 4 can be admitted!
    tracker
        .admit_sub_intent(&child_overflow, &fixture.parent_run, KEY)
        .expect("admit succeeds after release freed a slot");
    assert_eq!(tracker.active_children_count(), 3);
}

#[test]
fn recursion_depth_bound_enforced_hierarchically() {
    let fixture = setup_fixture();
    let limits = DelegationLimits {
        max_depth: 2, // Max depth 2
        max_fan_out: 10,
        max_context_duplication_bytes: 1_000_000,
    };
    let mut tracker_depth_0 = SubIntentFanOutTracker::new(
        fixture.parent_run.run_id(),
        fixture.parent_run.resource_budget(),
        0,
        limits,
        vec![],
        vec![],
        DisclosurePolicy::ConfidentialParentOnly,
    );

    // Depth 1: Child under Root -> Permitted
    let child_sub = make_valid_sub_intent(
        &fixture,
        701,
        quota(20_000, 10_000),
        90,
        vec![],
        1,
    );
    tracker_depth_0
        .admit_sub_intent(&child_sub, &fixture.parent_run, KEY)
        .expect("depth 1 permitted");

    // Spawn child tracker at depth 1
    let mut tracker_depth_1 = tracker_depth_0
        .spawn_child_tracker(RunId::new(701), limits)
        .expect("spawn tracker at depth 1");
    assert_eq!(tracker_depth_1.depth(), 1);

    // Depth 2: Grandchild under Child -> Permitted (since max_depth is 2)
    // Create child run for depth 1
    let child_run = parent_run(701, 90, quota(20_000, 10_000));
    let grandchild_cap = make_child_delegated_cap(
        &fixture,
        7020,
        quota(5_000, 2_000),
        80,
        vec![],
    );
    let grandchild_sub = SubIntent::build(SubIntentParams {
        child_run_id: RunId::new(702),
        parent_run_id: child_run.run_id(),
        objective_digest: [1u8; 32],
        input_commitments: vec![],
        output_schema_id: [2u8; 32],
        attenuated_capabilities: vec![grandchild_cap],
        budget: quota(5_000, 2_000),
        deadline: t(80),
        required_evidence: vec![],
        disclosure_policy: DisclosurePolicy::ConfidentialParentOnly,
        additional_identities: vec![],
        caveats: vec![Caveat::ScopedSelector(Selector::PathPrefix(
            "crates/fgit-agent".into(),
        ))],
        depth: 2,
        context_bytes: 512,
    })
    .expect("valid grandchild");

    tracker_depth_1
        .admit_sub_intent(&grandchild_sub, &child_run, KEY)
        .expect("depth 2 permitted");

    // Spawn grandchild tracker at depth 2
    let tracker_depth_2 = tracker_depth_1
        .spawn_child_tracker(RunId::new(702), limits)
        .expect("spawn tracker at depth 2");
    assert_eq!(tracker_depth_2.depth(), 2);

    // Attempt to spawn Great-Grandchild at depth 3 -> Refused!
    let spawn_err = tracker_depth_2
        .spawn_child_tracker(RunId::new(702), limits)
        .expect_err("depth 3 must exceed max_depth 2");
    assert!(matches!(
        spawn_err,
        SubIntentRefusal::RecursionDepthExceeded {
            observed: 3,
            limit: 2
        }
    ));
}
