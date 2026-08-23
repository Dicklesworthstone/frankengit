#![forbid(unsafe_code)]
//! Acceptance line 1: delegation widening is unrepresentable or refused, tested
//! through both the API and a tampered serialized token
//! (`frankengit-fg030a-agent-intentrun-a8h`).
//!
//! The two halves are tested separately because they fail separately. Through
//! the API there is no call that produces a widened child, so what is tested is
//! that an attempt is *refused and named*. Through bytes the type system is
//! absent, so what is tested is that the verifier rejects the edit.
//!
//! Every refusal here has a permitted twin. A capability system that refused
//! everything would satisfy a refusal-only corpus perfectly, and the twins are
//! what distinguish "narrowing works and widening does not" from "nothing
//! works".

use fgit_agent::{
    AttenuationRefused, AttenuationRequest, Capability, CapabilityId, ChainRefused, ClassSet,
    LogicalTime, OperationClass, SealedCapability, verify_chain,
};
use fgit_resource::{ResourceVector, algebra::Grade};

const KEY: &[u8] = b"issuer-key-for-tests-only";

const fn t(value: u64) -> LogicalTime {
    LogicalTime::new(value)
}

fn parent_classes() -> ClassSet {
    ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::TreeFsWorkspace,
        OperationClass::ExecuteSandboxedProcess,
    ])
}

fn quota(bytes: u64, cpu: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::CpuMicros, cpu)])
}

fn root() -> Capability {
    Capability::issue(
        CapabilityId::new(1),
        parent_classes(),
        quota(1_000, 500),
        t(10),
        t(100),
    )
    .expect("a root with a non-empty scope and a real window is issuable")
}

/// A request that narrows on every axis, used as the permitted twin.
fn narrowing_request() -> AttenuationRequest {
    AttenuationRequest {
        id: CapabilityId::new(2),
        operations: ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        quota: quota(400, 200),
        not_before: t(20),
        expires_at: t(90),
    }
}

// ---------------------------------------------------------------------------
// The permitted path, built first
// ---------------------------------------------------------------------------

#[test]
fn a_genuine_narrowing_delegates_and_records_its_parent() {
    let parent = root();
    let child = parent
        .attenuate(&narrowing_request())
        .expect("narrowing on every axis is exactly what attenuation is for");

    assert_eq!(child.parent(), Some(parent.id()));
    assert_eq!(child.depth(), parent.depth() + 1);
    assert!(child.operations().is_subset_of(parent.operations()));
    assert!(parent.quota().dominates(&child.quota()));
    assert!(child.not_before() >= parent.not_before());
    assert!(child.expires_at() <= parent.expires_at());
}

// ---------------------------------------------------------------------------
// API half: an amplification attempt is refused, and named
// ---------------------------------------------------------------------------

#[test]
fn requesting_a_class_the_parent_lacks_is_refused_and_names_exactly_that_class() {
    let parent = root();
    let mut request = narrowing_request();
    // The parent holds ReadCanonicalObject but not SecretHandle.
    request.operations = ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::SecretHandle,
    ]);

    let refusal = parent
        .attenuate(&request)
        .expect_err("a class outside the parent is amplification, not narrowing");

    match refusal {
        AttenuationRefused::OperationsAmplified {
            added,
            parent: held,
        } => {
            // Naming the difference, not merely reporting that one existed.
            assert_eq!(
                added,
                ClassSet::from_classes(&[OperationClass::SecretHandle])
            );
            assert!(!added.contains(OperationClass::ReadCanonicalObject));
            assert_eq!(held, parent_classes());
        }
        other => panic!("expected OperationsAmplified, got {other:?}"),
    }
}

#[test]
fn silently_intersecting_is_not_what_happens() {
    // The distinction this test exists for: intersection would have produced a
    // valid narrower child and hidden the caller's mistake. §6.2 requires the
    // attempt to be refused, so no child may come back at all.
    let parent = root();
    let mut request = narrowing_request();
    request.operations = ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::MutateForgeEntity,
    ]);

    assert!(
        parent.attenuate(&request).is_err(),
        "an amplifying request must be refused outright, not quietly narrowed to the intersection"
    );
}

#[test]
fn requesting_more_of_a_grade_than_the_parent_holds_is_refused_with_the_algebra_deficit() {
    let parent = root();
    let mut request = narrowing_request();
    request.quota = quota(400, 900); // parent holds 500 CpuMicros

    let refusal = parent
        .attenuate(&request)
        .expect_err("more CPU than the parent holds is amplification");

    match refusal {
        AttenuationRefused::QuotaAmplified { deficit } => {
            let rendered = deficit.to_string();
            assert!(
                rendered.contains("cpu") || rendered.contains("Cpu"),
                "the deficit must name the grade that fell short, got {rendered}"
            );
        }
        other => panic!("expected QuotaAmplified, got {other:?}"),
    }
}

#[test]
fn a_window_reaching_past_the_parent_is_refused_at_either_end() {
    let parent = root();

    let mut early = narrowing_request();
    early.not_before = t(5); // parent starts at 10
    assert!(matches!(
        parent.attenuate(&early),
        Err(AttenuationRefused::WindowWidened { .. })
    ));

    let mut late = narrowing_request();
    late.expires_at = t(150); // parent ends at 100
    assert!(matches!(
        parent.attenuate(&late),
        Err(AttenuationRefused::WindowWidened { .. })
    ));
}

#[test]
fn the_exact_parent_window_and_scope_are_still_a_legal_delegation() {
    // The inclusive boundary. Attenuation permits equality on every axis; only
    // exceeding is refused. Without this, a guard that demanded strict
    // narrowing would pass every refusal test above.
    let parent = root();
    let request = AttenuationRequest {
        id: CapabilityId::new(3),
        operations: parent.operations(),
        quota: parent.quota(),
        not_before: parent.not_before(),
        expires_at: parent.expires_at(),
    };

    let child = parent
        .attenuate(&request)
        .expect("equality on every axis is narrowing's inclusive boundary, not amplification");
    assert_eq!(child.operations(), parent.operations());
    assert_eq!(child.quota(), parent.quota());
}

#[test]
fn a_delegation_authorizing_nothing_is_refused() {
    let parent = root();
    let mut request = narrowing_request();
    request.operations = ClassSet::EMPTY;
    assert_eq!(
        parent.attenuate(&request),
        Err(AttenuationRefused::EmptyScope)
    );
}

// ---------------------------------------------------------------------------
// Serialized half: the verifier checks bytes it did not produce
// ---------------------------------------------------------------------------

fn sealed_chain() -> [SealedCapability; 2] {
    let parent = root();
    let child = parent
        .attenuate(&narrowing_request())
        .expect("the permitted twin delegates");
    let sealed_parent = parent
        .seal(KEY, None)
        .expect("a root seals without a parent tag");
    let sealed_child = child
        .seal(KEY, Some(sealed_parent.tag()))
        .expect("a delegation seals against its parent's tag");
    [sealed_parent, sealed_child]
}

#[test]
fn an_untampered_chain_verifies_and_returns_the_leaf() {
    let chain = sealed_chain();
    let leaf = verify_chain(&chain, KEY).expect("an honest chain verifies");
    assert_eq!(leaf.id(), CapabilityId::new(2));
}

#[test]
fn widening_the_serialized_scope_is_refused_by_the_authenticator() {
    let [parent, child] = sealed_chain();

    // The attacker splices a wider body under a tag issued over a narrower one.
    // Note what is NOT needed to write this test: any API that widens a
    // capability. There is none, which is the point — the wider body here is an
    // ordinary, legitimately issued capability, and the attack is presenting it
    // with someone else's authenticator.
    let wider = Capability::issue(
        CapabilityId::new(2),
        parent_classes(),
        quota(1_000, 500),
        t(10),
        t(100),
    )
    .expect("a wide capability is perfectly legal to issue; splicing it is not");
    assert!(
        !wider
            .operations()
            .is_subset_of(child.capability().operations()),
        "the spliced body must really be wider, or this proves nothing"
    );

    let forged = child.with_tampered_capability(wider);
    let refusal = verify_chain(&[parent, forged], KEY)
        .expect_err("a substituted body no longer matches the tag issued over the original");
    assert!(
        matches!(refusal, ChainRefused::AuthenticatorMismatch { index: 1 }),
        "expected the tag check to fire at the spliced link, got {refusal:?}"
    );
}

#[test]
fn a_chain_presented_without_its_root_is_refused_as_missing_ancestry() {
    let [_, child] = sealed_chain();
    let refusal = verify_chain(&[child], KEY)
        .expect_err("a delegated capability presented alone has no ancestry to check");
    assert!(
        matches!(refusal, ChainRefused::MissingAncestry { index: 0, .. }),
        "got {refusal:?}"
    );
}

#[test]
fn an_empty_chain_is_refused_rather_than_trivially_valid() {
    let empty: [SealedCapability; 0] = [];
    assert_eq!(verify_chain(&empty, KEY), Err(ChainRefused::EmptyChain));
}

#[test]
fn a_chain_verified_under_the_wrong_key_is_refused_at_its_root() {
    let chain = sealed_chain();
    let refusal = verify_chain(&chain, b"a-different-issuer-key")
        .expect_err("tags issued under one key must not verify under another");
    assert!(
        matches!(refusal, ChainRefused::AuthenticatorMismatch { index: 0 }),
        "got {refusal:?}"
    );
}

#[test]
fn swapping_in_an_unrelated_root_breaks_the_parent_tag_binding() {
    let [_, child] = sealed_chain();
    let other_root = Capability::issue(
        CapabilityId::new(99),
        parent_classes(),
        quota(1_000, 500),
        t(10),
        t(100),
    )
    .expect("a second root issues");
    let sealed_other = other_root.seal(KEY, None).expect("it seals");

    let refusal = verify_chain(&[sealed_other, child], KEY)
        .expect_err("the child commits to its real parent's tag, not to any valid root");
    // It names a different parent, so ancestry is checked before the tag binding.
    assert!(
        matches!(refusal, ChainRefused::AncestryMismatch { index: 1, .. }),
        "got {refusal:?}"
    );
}
