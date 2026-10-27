use super::*;
use crate::evidence::{DecisionEvidenceBodies, tests::fixture};
use fgit_codec::harness::digest_of;
use fgit_reference::effect::FoldBasis;
use fgit_reference::intent::{Intent, RefIntent, Statement, TransactionRequest};
use fgit_reference::refs::ExpectedRefState;
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, MismatchPolicy};
use std::collections::{BTreeMap, BTreeSet};

fn name(bytes: &[u8]) -> RefName {
    RefName::try_new(bytes).unwrap()
}
fn oid(algorithm: GitHashAlgorithm, byte: u8) -> GitOid {
    match algorithm {
        GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([byte; 20])),
        GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([byte; 32])),
    }
}

fn folded(
    algorithm: GitHashAlgorithm,
    target: RefName,
    head: RefName,
    previous: Option<GitOid>,
    next: Option<GitOid>,
) -> (
    AdmissionContext,
    PublicationBasis,
    CanonicalRefState,
    TransactionRequest,
    TransactionFoldReport,
) {
    let (mut context, basis, mut request, _) = fixture();
    context.object_format = algorithm;
    let refs = previous.map_or_else(BTreeMap::new, |oid| BTreeMap::from([(target.clone(), oid)]));
    let current = CanonicalRefState::new_with_head_target(refs, head).unwrap();
    let expected = previous.map_or(ExpectedRefState::Absent, ExpectedRefState::Exact);
    let intent = match next {
        Some(new) => RefIntent::Update {
            name: target,
            expected,
            new,
            force: false,
        },
        None => RefIntent::Delete {
            name: target,
            expected,
        },
    };
    request.statements = vec![Statement {
        intents: vec![Intent::Ref(intent)],
        mismatch_policy: MismatchPolicy::TxnAbort,
    }];
    let empty_map = BTreeMap::new();
    let empty_set = BTreeSet::new();
    let empty_outbox = BTreeMap::new();
    let fold = fgit_txn::IntentEvaluator::new().evaluate(
        FoldBasis {
            refs: current.refs(),
            forge_positions: &empty_map,
            retention: &empty_set,
            outbox: &empty_outbox,
        },
        &request,
    );
    (context, basis, current, request, fold)
}

fn recorded(
    fixture: &(
        AdmissionContext,
        PublicationBasis,
        CanonicalRefState,
        TransactionRequest,
        TransactionFoldReport,
    ),
    branches: Vec<RefName>,
) -> Result<DecisionEvidenceBodies, RefusalCode> {
    let (context, basis, current, request, fold) = fixture;
    let mut bodies = DecisionEvidenceBodies::derive(context, basis, request, fold)?;
    bodies.record_ref_policies(
        context,
        basis,
        current,
        RootLayoutVersion::LegacyWholeBody,
        fold,
        branches,
    )?;
    Ok(bodies)
}

fn evaluated(bodies: &DecisionEvidenceBodies) -> &EvaluatedPolicyDecisionEvidence {
    let PolicyDecisionRecord::Evaluated(value) = bodies.policy_decision() else {
        panic!("evaluated record")
    };
    value
}

#[test]
fn historical_v1_0_keeps_exact_frame_root_and_requires_explicit_version_dispatch() {
    let (context, basis, request, fold) = fixture();
    let bodies = DecisionEvidenceBodies::derive(&context, &basis, &request, &fold).unwrap();
    let legacy = bodies.policy_decision().base();
    let original_frame = encode_body(legacy).unwrap();
    let original_root = evidence_root(legacy).unwrap();
    assert_eq!(bodies.policy_decision().encode().unwrap(), original_frame);
    assert_eq!(bodies.policy_decision().root().unwrap(), original_root);
    let decoded = PolicyDecisionRecord::decode(&original_frame, DecodeLimits::DEFAULT).unwrap();
    assert!(matches!(decoded, PolicyDecisionRecord::Legacy(_)));
    assert_eq!(decoded.encode().unwrap(), original_frame);
    assert_eq!(decoded.root().unwrap(), original_root);
    assert!(
        decode_body::<EvaluatedPolicyDecisionEvidence>(&original_frame, DecodeLimits::DEFAULT)
            .is_err()
    );
}

#[test]
fn admitted_head_updates_bind_actual_snapshot_verdict_inputs_and_deterministic_trace() {
    for algorithm in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let target = name(b"refs/heads/main");
        let setup = folded(
            algorithm,
            target.clone(),
            target,
            Some(oid(algorithm, 1)),
            Some(oid(algorithm, 2)),
        );
        let bodies = recorded(&setup, vec![]).unwrap();
        let again = recorded(&setup, vec![]).unwrap();
        assert_eq!(bodies, again);
        let value = evaluated(&bodies);
        assert_eq!(value.basis(), setup.1.id());
        assert_eq!(value.inputs()[0].previous(), Some(&oid(algorithm, 1)));
        assert_eq!(value.inputs()[0].next(), Some(&oid(algorithm, 2)));
        assert_eq!(value.evaluations().len(), 2);
        for evaluation in value.evaluations() {
            assert_eq!(evaluation.decision(), Decision::Allow);
            assert_eq!(evaluation.snapshot_id(), evaluation.snapshot().id());
            assert!(evaluation.trace().starts_with(&format!(
                "policy {}\ndecision allow\n",
                evaluation.snapshot().policy().name()
            )));
        }
        assert!(
            value.evaluations()[0]
                .trace()
                .contains("update_unclassified")
        );
        assert!(!value.evaluations()[0].trace().contains("fast_forward"));
        assert_ne!(
            bodies.policy_decision().root().unwrap(),
            evidence_root(bodies.policy_decision().base()).unwrap()
        );
        let frame = bodies.policy_decision().encode().unwrap();
        assert_eq!(
            PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).unwrap(),
            *bodies.policy_decision()
        );
        assert!(decode_body::<PolicyDecisionEvidence>(&frame, DecodeLimits::DEFAULT).is_err());
        bodies
            .verify_decision(&setup.0, &setup.1, &setup.3, &setup.4)
            .unwrap();
        value
            .verify_provenance(&setup.1, &setup.2, RootLayoutVersion::LegacyWholeBody, &[])
            .unwrap();
    }
}

#[test]
fn native_default_branch_selector_denies_deletion_and_admits_its_unrelated_twin() {
    for target in [
        name(b"refs/heads/main"),
        name(b"refs/heads/raw-\xff"),
        name(b"refs/heads/quote\"then-deny"),
    ] {
        let prohibited = folded(
            GitHashAlgorithm::Sha1,
            target.clone(),
            target.clone(),
            Some(oid(GitHashAlgorithm::Sha1, 1)),
            None,
        );
        assert_eq!(
            recorded(&prohibited, vec![]),
            Err(RefusalCode::ProtectedRefTransitionDenied)
        );
        let unrelated = folded(
            GitHashAlgorithm::Sha1,
            name(b"refs/heads/topic"),
            target.clone(),
            Some(oid(GitHashAlgorithm::Sha1, 1)),
            None,
        );
        let permitted = recorded(&unrelated, vec![]).unwrap();
        evaluated(&permitted).replay().unwrap();
        let update = folded(
            GitHashAlgorithm::Sha1,
            target.clone(),
            target,
            Some(oid(GitHashAlgorithm::Sha1, 1)),
            Some(oid(GitHashAlgorithm::Sha1, 2)),
        );
        recorded(&update, vec![]).unwrap();
    }
}

#[test]
fn native_review_selector_cannot_be_bypassed_or_replaced_by_an_unrelated_branch() {
    let protected = name(b"refs/heads/review-\xff");
    let setup = folded(
        GitHashAlgorithm::Sha256,
        protected.clone(),
        name(b"refs/heads/main"),
        None,
        Some(oid(GitHashAlgorithm::Sha256, 2)),
    );
    assert_eq!(
        recorded(&setup, vec![protected.clone()]),
        Err(RefusalCode::ProtectedRefTransitionDenied)
    );
    let permitted = recorded(&setup, vec![name(b"refs/heads/other")]).unwrap();
    assert_eq!(
        evaluated(&permitted).verify_provenance(
            &setup.1,
            &setup.2,
            RootLayoutVersion::LegacyWholeBody,
            &[protected]
        ),
        Err(RefusalCode::EvidenceInvalid)
    );
    evaluated(&permitted)
        .verify_provenance(
            &setup.1,
            &setup.2,
            RootLayoutVersion::LegacyWholeBody,
            &[name(b"refs/heads/other")],
        )
        .unwrap();
}

#[test]
fn replay_refuses_a_different_valid_snapshot_a_fabricated_trace_and_missing_evaluations() {
    let target = name(b"refs/heads/main");
    let setup = folded(
        GitHashAlgorithm::Sha1,
        target.clone(),
        target,
        None,
        Some(oid(GitHashAlgorithm::Sha1, 2)),
    );
    let bodies = recorded(&setup, vec![]).unwrap();
    let good = evaluated(&bodies);
    let mut substituted = good.clone();
    substituted.evaluations[0].snapshot =
        fgit_policy::compile_and_seal("policy substituted { default allow }").unwrap();
    assert_eq!(substituted.replay(), Err(RefusalCode::EvidenceInvalid));
    assert!(
        PolicyDecisionRecord::decode(&encode_body(&substituted).unwrap(), DecodeLimits::DEFAULT)
            .is_err()
    );
    let mut fabricated = good.clone();
    fabricated.evaluations[0].trace.push_str("forged");
    assert_eq!(fabricated.replay(), Err(RefusalCode::EvidenceInvalid));
    let mut omitted = good.clone();
    omitted.evaluations.pop();
    assert_eq!(omitted.replay(), Err(RefusalCode::EvidenceInvalid));
    let mut false_verdict = good.clone();
    false_verdict.evaluations[0].decision = Decision::Deny;
    assert_eq!(false_verdict.replay(), Err(RefusalCode::EvidenceInvalid));
    good.replay().unwrap();
}

#[test]
fn recorded_overlay_cannot_replay_against_another_old_value_or_resulting_effect() {
    let target = name(b"refs/heads/main");
    let setup = folded(
        GitHashAlgorithm::Sha1,
        target.clone(),
        target.clone(),
        Some(oid(GitHashAlgorithm::Sha1, 2)),
        Some(oid(GitHashAlgorithm::Sha1, 3)),
    );
    let bodies = recorded(&setup, vec![]).unwrap();
    let original = CanonicalRefState::new_with_head_target(
        BTreeMap::from([(target.clone(), oid(GitHashAlgorithm::Sha1, 1))]),
        target.clone(),
    )
    .unwrap();
    assert_eq!(
        evaluated(&bodies).verify_provenance(
            &setup.1,
            &original,
            RootLayoutVersion::LegacyWholeBody,
            &[]
        ),
        Err(RefusalCode::EvidenceInvalid)
    );
    evaluated(&bodies)
        .verify_provenance(&setup.1, &setup.2, RootLayoutVersion::LegacyWholeBody, &[])
        .unwrap();
    let changed = folded(
        GitHashAlgorithm::Sha1,
        target.clone(),
        target,
        Some(oid(GitHashAlgorithm::Sha1, 2)),
        Some(oid(GitHashAlgorithm::Sha1, 4)),
    );
    assert_eq!(
        bodies.verify_decision(&setup.0, &setup.1, &setup.3, &changed.4),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn another_principal_epoch_or_authority_head_cannot_reuse_the_record() {
    let target = name(b"refs/heads/main");
    let setup = folded(
        GitHashAlgorithm::Sha1,
        target.clone(),
        target,
        None,
        Some(oid(GitHashAlgorithm::Sha1, 2)),
    );
    let bodies = recorded(&setup, vec![]).unwrap();
    let mut context = setup.0.clone();
    context.principal_id = PrincipalId::from_bytes([99; 16]);
    assert_eq!(
        bodies.verify_decision(&context, &setup.1, &setup.3, &setup.4),
        Err(RefusalCode::EvidenceInvalid)
    );
    let mut head = setup.1.body().clone();
    head.policy_epoch = fgit_types::PolicyEpoch::try_new(2).unwrap();
    let changed = PublicationBasis::new(setup.1.id(), head);
    assert_eq!(
        bodies.verify_decision(&setup.0, &changed, &setup.3, &setup.4),
        Err(RefusalCode::EvidenceInvalid)
    );
    let identity = fgit_codec::body_id(&fgit_codec::CryptoBodyIdentity, setup.1.body()).unwrap();
    let changed = PublicationBasis::new(
        RepositoryAuthorityHeadId::from_internal_object_id(identity).unwrap(),
        setup.1.body().clone(),
    );
    assert_eq!(
        bodies.verify_decision(&setup.0, &changed, &setup.3, &setup.4),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn exact_minor_dispatch_refuses_future_schema_truncation_suffix_and_tight_bounds() {
    let setup = folded(
        GitHashAlgorithm::Sha1,
        name(b"refs/heads/main"),
        name(b"refs/heads/main"),
        None,
        Some(oid(GitHashAlgorithm::Sha1, 2)),
    );
    let bodies = recorded(&setup, vec![]).unwrap();
    let frame = bodies.policy_decision().encode().unwrap();
    assert!(PolicyDecisionRecord::decode(&frame, DecodeLimits::MINIMAL).is_err());
    for length in [0, 1, frame.len() / 2, frame.len() - 1] {
        assert!(PolicyDecisionRecord::decode(&frame[..length], DecodeLimits::DEFAULT).is_err());
    }
    let mut suffix = frame.clone();
    suffix.push(0);
    assert!(PolicyDecisionRecord::decode(&suffix, DecodeLimits::DEFAULT).is_err());
    let mut future = frame.clone();
    let (_, header) = read_frame_header(&future, DecodeLimits::DEFAULT).unwrap();
    let minor = header.offset() as usize - 2;
    future[minor..minor + 2].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        PolicyDecisionRecord::decode(&future, DecodeLimits::DEFAULT),
        Err(CodecRefusal::SchemaMinorUnsupported { observed: 2, .. })
    ));
    PolicyDecisionRecord::decode(&frame, DecodeLimits::DEFAULT).unwrap();
}

#[test]
fn profile_and_record_limits_are_finite_without_truncating_or_forging_success() {
    let setup = folded(
        GitHashAlgorithm::Sha1,
        name(b"refs/heads/main"),
        name(b"refs/heads/main"),
        None,
        Some(oid(GitHashAlgorithm::Sha1, 2)),
    );
    let bodies = recorded(&setup, vec![]).unwrap();
    let mut over = evaluated(&bodies).clone();
    over.inputs = vec![over.inputs[0].clone(); MAX_SUBJECTS + 1];
    assert_eq!(over.replay(), Err(RefusalCode::EvidenceInvalid));
    let mut wrong = evaluated(&bodies).clone();
    wrong.ref_basis_root = digest_of(0xff);
    assert_eq!(
        wrong.verify_provenance(&setup.1, &setup.2, RootLayoutVersion::LegacyWholeBody, &[]),
        Err(RefusalCode::EvidenceInvalid)
    );
    evaluated(&bodies).replay().unwrap();
}
