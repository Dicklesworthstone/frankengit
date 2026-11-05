//! Exact closure reuse against ordinary canonical preparation.

use super::*;
use fgit_types::layout::RootLayoutVersion;

fn closure(format: GitHashAlgorithm, count: u32) -> ValidatedClosure {
    let objects = (0..count)
        .map(|index| {
            let mut bytes = [0x5a; 32];
            bytes[..4].copy_from_slice(&index.to_be_bytes());
            match format {
                GitHashAlgorithm::Sha1 => GitOid::Sha1(fgit_types::GitOidSha1::from_bytes(
                    bytes[..20].try_into().unwrap(),
                )),
                GitHashAlgorithm::Sha256 => {
                    GitOid::Sha256(fgit_types::GitOidSha256::from_bytes(bytes))
                }
            }
        })
        .collect();
    let body = PermittedObjectClosure::new(objects);
    ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&body).unwrap(),
        objects: body.objects,
    }
}

fn prepared(
    context: &AdmissionContext,
    basis: &PublicationBasis,
    current: CanonicalRefState,
    closure: &ValidatedClosure,
    layout: RootLayoutVersion,
    ordinal: u8,
    reusable: Option<PreparedCanonicalClosure>,
) -> Result<PreparedCanonicalCommit, RefusalCode> {
    let target = *closure.objects.iter().next().unwrap();
    let semantic = fgit_authority::SemanticRequest::build(
        RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        false,
        vec![fgit_authority::RefCommand {
            name: RefName::try_new(format!("refs/tags/closure-{ordinal}").as_bytes()).unwrap(),
            expected_old: fgit_authority::ExpectedOld::Absent,
            proposed_new: fgit_authority::ProposedNew::Update(target),
            force: false,
        }],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let lowered = LoweredRequest {
        semantic,
        idempotency_key: IdempotencyKey::new(vec![ordinal]).unwrap(),
    };
    let request = model_request(
        context,
        &lowered.semantic,
        derive_tx_id(context, &lowered).unwrap(),
        closure,
    )
    .unwrap();
    let snapshot = AdmissionSnapshot {
        refs: current.refs().clone(),
        head_target: current.head_target().cloned(),
        ..AdmissionSnapshot::default()
    };
    let fold = IntentEvaluator::new().evaluate(snapshot.as_fold_basis(), &request);
    let mut evidence = CanonicalFixtureEvidence
        .commit_evidence(basis, &request, &fold)
        .unwrap();
    evidence.policy_decision_root = digest(ordinal);
    prepare_canonical_commit_reusing_closure(
        basis, &request, &fold, closure, current, layout, evidence, reusable,
    )
}

#[test]
fn exact_reuse_preserves_every_record_field_ref_state_and_canonical_frame() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut context = context();
        context.object_format = format;
        let (store, _, _) = canonical_store_with_genesis(&context);
        let (basis, _, _) = read_basis(&store, &context.head_key).unwrap();
        let closure = closure(format, 257);
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV1,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        ] {
            let mut current = CanonicalRefState::default();
            let mut reuse = None;
            let mut frame_allocation = None;
            let mut previous_record = None;
            for ordinal in 1..=8 {
                let cold = prepared(
                    &context,
                    &basis,
                    current.clone(),
                    &closure,
                    layout,
                    ordinal,
                    None,
                )
                .unwrap();
                let mut warm =
                    prepared(&context, &basis, current, &closure, layout, ordinal, reuse).unwrap();
                assert_eq!(warm, cold);
                let encoded = encode_body(cold.object_closure()).unwrap();
                let frame = warm.object_closure_frame().unwrap();
                assert_eq!(frame, encoded);
                if let Some(allocation) = frame_allocation {
                    assert_eq!(
                        frame.as_ptr(),
                        allocation,
                        "reuse keeps the owned frame allocation"
                    );
                }
                frame_allocation = Some(frame.as_ptr());
                assert_eq!(
                    warm, cold,
                    "encoding derived bytes changes no semantic field"
                );
                assert_eq!(
                    decode_body::<PermittedObjectClosure>(
                        &encoded,
                        fgit_codec::DecodeLimits::DEFAULT
                    )
                    .unwrap(),
                    *warm.object_closure()
                );
                current = warm.next_ref_state().clone();
                let (materialization, proof) = warm.into_materialization_and_closure();
                assert_eq!(materialization, cold.into_materialization());
                assert_eq!(materialization.record.policy_decision_root, digest(ordinal));
                if let Some(previous) = previous_record {
                    assert_ne!(
                        materialization.record, previous,
                        "each command keeps its own RCR"
                    );
                }
                previous_record = Some(materialization.record);
                reuse = Some(proof);
            }
            assert_eq!(current.refs().len(), 8);
        }
    }
}

#[test]
fn changed_digest_or_same_count_changed_members_cannot_reuse_a_verified_closure() {
    let context = context();
    let (store, _, _) = canonical_store_with_genesis(&context);
    let (basis, _, _) = read_basis(&store, &context.head_key).unwrap();
    let original = closure(context.object_format, 257);
    let layout = RootLayoutVersion::LegacyWholeBody;
    for change_members in [false, true] {
        let mut first = prepared(
            &context,
            &basis,
            CanonicalRefState::default(),
            &original,
            layout,
            1,
            None,
        )
        .unwrap();
        first.object_closure_frame().unwrap();
        let (_, reuse) = first.into_materialization_and_closure();
        let mut altered = original.clone();
        if change_members {
            let removed = *altered.objects.iter().next_back().unwrap();
            altered.objects.remove(&removed);
            altered.objects.insert(oid(0xf0));
            assert_eq!(altered.objects.len(), original.objects.len());
            assert_eq!(altered.object_closure_root, original.object_closure_root);
        } else {
            altered.object_closure_root = digest(0xf0);
        }
        let cold = prepared(
            &context,
            &basis,
            CanonicalRefState::default(),
            &altered,
            layout,
            2,
            None,
        );
        let warm = prepared(
            &context,
            &basis,
            CanonicalRefState::default(),
            &altered,
            layout,
            2,
            Some(reuse),
        );
        assert_eq!(warm, cold);
        assert_eq!(warm, Err(RefusalCode::ObjectClosureIncomplete));
    }
}

#[test]
fn a_different_valid_closure_replaces_both_the_proof_and_encoded_frame() {
    let context = context();
    let (store, _, _) = canonical_store_with_genesis(&context);
    let (basis, _, _) = read_basis(&store, &context.head_key).unwrap();
    let original = closure(context.object_format, 3);
    let replacement = closure(context.object_format, 5);
    let layout = RootLayoutVersion::LegacyWholeBody;
    let mut first = prepared(
        &context,
        &basis,
        CanonicalRefState::default(),
        &original,
        layout,
        1,
        None,
    )
    .unwrap();
    let previous_frame = first.object_closure_frame().unwrap().to_vec();
    let (_, reuse) = first.into_materialization_and_closure();
    let cold = prepared(
        &context,
        &basis,
        CanonicalRefState::default(),
        &replacement,
        layout,
        2,
        None,
    )
    .unwrap();
    let mut warm = prepared(
        &context,
        &basis,
        CanonicalRefState::default(),
        &replacement,
        layout,
        2,
        Some(reuse),
    )
    .unwrap();
    assert_eq!(warm, cold);
    assert_eq!(
        warm.object_closure_frame().unwrap(),
        encode_body(cold.object_closure()).unwrap()
    );
    assert_ne!(warm.object_closure_frame().unwrap(), previous_frame);
}

#[test]
fn ref_namespace_refusal_still_precedes_invalid_closure_with_reuse() {
    let context = context();
    let (store, _, _) = canonical_store_with_genesis(&context);
    let (basis, _, _) = read_basis(&store, &context.head_key).unwrap();
    let original = closure(context.object_format, 3);
    let layout = RootLayoutVersion::LegacyWholeBody;
    let (_, reuse) = prepared(
        &context,
        &basis,
        CanonicalRefState::default(),
        &original,
        layout,
        1,
        None,
    )
    .unwrap()
    .into_materialization_and_closure();
    let mut altered = original;
    altered.object_closure_root = digest(0xf0);
    let current = CanonicalRefState::new(BTreeMap::from([(
        RefName::try_new(b"refs/tags/closure-2/child").unwrap(),
        oid(8),
    )]));
    let cold = prepared(&context, &basis, current.clone(), &altered, layout, 2, None);
    let warm = prepared(&context, &basis, current, &altered, layout, 2, Some(reuse));
    assert_eq!(warm, cold);
    assert_eq!(warm, Err(RefusalCode::RefNameConflict));
}
