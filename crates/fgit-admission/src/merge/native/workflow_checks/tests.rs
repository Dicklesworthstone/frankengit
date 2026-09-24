//! Pure preparation fixtures: these do not authenticate a producer or verify
//! native object storage. The node integration exercises those boundaries.
use super::*;
use crate::merge::prepare::prepare_event;
use crate::{CanonicalRefState, PermittedObjectClosure, permitted_object_closure_root};
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, RepositoryAuthorityHeadBody};
use fgit_forge::event::workflow_check::{MAX_CHECK_EVIDENCE_BYTES, WorkflowCheckConclusion};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch,
    PrincipalId, RefName, RegistryEpoch, RepositoryId, RootLayoutVersion, TenantId,
};
use std::collections::{BTreeMap, BTreeSet};

fn digest(value: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&[value; 32]).unwrap(),
    )
}
fn fixture(
    format: GitHashAlgorithm,
) -> (
    AdmissionContext,
    WorkflowCheckRecord,
    NativeMergeBasis,
    PublicationBasis,
    ValidatedClosure,
) {
    let context = AdmissionContext {
        head_key: HeadKey::new(b"workflow-test/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"workflow-one".to_vec()).unwrap(),
        object_format: format,
    };
    let record = WorkflowCheckRecord {
        source_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_commit: GitOid::from_hex(format, &"ab".repeat(format.digest_len())).unwrap(),
        run_id: [4; 32],
        attempt_id: [5; 32],
        graph_root: [6; 32],
        job: "build".into(),
        conclusion: WorkflowCheckConclusion::ActionRequired,
        evidence: b"unit fixture only".to_vec(),
    };
    let resolved = NativeMergeBasis {
        refs: CanonicalRefState::new(BTreeMap::from([(
            record.source_ref.clone(),
            record.source_commit,
        )])),
        root_layout: RootLayoutVersion::LegacyWholeBody,
        forge: CanonicalForgePositionState::try_new(context.repository_id, Vec::new()).unwrap(),
        outbox: CanonicalOutboxState::try_new(context.repository_id, Vec::new()).unwrap(),
    };
    let head = RepositoryAuthorityHeadBody {
        repository_id: context.repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: crate::ref_state_root(resolved.root_layout, &resolved.refs).unwrap(),
        forge_position_root: storage::root(&resolved.forge).unwrap(),
        outcome_index_root: digest(10),
        retention_root: digest(11),
        outbox_root: storage::root(&resolved.outbox).unwrap(),
        configuration_root: digest(12),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    );
    let objects = BTreeSet::from([record.source_commit]);
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    (context, record, resolved, basis, closure)
}

#[test]
fn actual_fold_couples_observation_inline_evidence_and_outbox_without_ref_or_policy_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, record, resolved, basis, closure) = fixture(format);
        let (event, seal) = proposal(&context, &record).unwrap();
        let tx = seal.derive().unwrap().0;
        let prepared =
            prepare_event(&context, &event, &closure, tx, &seal, &basis, &resolved).unwrap();
        assert_eq!(prepared.refs, resolved.refs);
        assert_eq!(
            prepared.materialization.roots.ref_root,
            basis.body().ref_root
        );
        assert_eq!(
            prepared.materialization.roots.policy_epoch,
            basis.body().policy_epoch
        );
        assert_eq!(
            prepared.materialization.roots.retention_root,
            basis.body().retention_root
        );
        assert!(prepared.fold.effects().unwrap().refs.is_empty());
        assert!(prepared.fold.effects().unwrap().retention.is_empty());
        assert_eq!(prepared.event.events, vec![event.clone()]);
        assert_eq!(prepared.forge.entries().len(), 1);
        assert_eq!(prepared.outbox.entries().len(), 1);
        let entry = &prepared.outbox.entries()[0];
        assert_eq!(entry.tx_id(), tx);
        assert_eq!(
            entry.payload_root(),
            storage::root(&prepared.event).unwrap()
        );
        assert_eq!(
            prepared.materialization.record.forge_event_batch_root,
            entry.payload_root()
        );
        let bytes = fgit_codec::encode_body(&prepared.event).unwrap();
        let decoded: ForgeEventBatch =
            fgit_codec::decode_body(&bytes, fgit_codec::DecodeLimits::DEFAULT).unwrap();
        assert_eq!(decoded, prepared.event);
    }
}

#[test]
fn exact_retry_identity_is_stable_but_changed_result_does_not_alias_the_original_seal() {
    let (context, record, _, _, _) = fixture(GitHashAlgorithm::Sha1);
    let (event, seal) = proposal(&context, &record).unwrap();
    assert_eq!(
        proposal(&context, &record).unwrap(),
        (event.clone(), seal.clone())
    );
    for variant in 0..4 {
        let mut changed = record.clone();
        match variant {
            0 => changed.evidence.push(0),
            1 => changed.conclusion = WorkflowCheckConclusion::Failure,
            2 => changed.graph_root[0] ^= 1,
            _ => changed.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
        }
        let (other, other_seal) = proposal(&context, &changed).unwrap();
        assert_eq!(
            other.aggregate, event.aggregate,
            "one immutable publisher/run/attempt/job"
        );
        assert_ne!(other_seal.derive().unwrap().0, seal.derive().unwrap().0);
    }
    let mut other_actor = context.clone();
    other_actor.principal_id = PrincipalId::from_bytes([7; 16]);
    assert_ne!(
        proposal(&other_actor, &record).unwrap().0.aggregate,
        event.aggregate
    );
}

#[test]
fn modified_observation_cannot_be_prepared_under_a_valid_but_different_seal() {
    let (context, record, resolved, basis, closure) = fixture(GitHashAlgorithm::Sha1);
    let (event, seal) = proposal(&context, &record).unwrap();
    let mut changed = record;
    changed.evidence.push(b'!');
    let changed_event = proposal(&context, &changed).unwrap().0;
    assert!(matches!(
        prepare_event(
            &context,
            &changed_event,
            &closure,
            seal.derive().unwrap().0,
            &seal,
            &basis,
            &resolved
        ),
        Err(RefusalCode::EvidenceInvalid)
    ));
    let mut bad = event;
    bad.version = AggregateVersion::try_new(2).unwrap();
    assert!(matches!(
        prepare_event(
            &context,
            &bad,
            &closure,
            seal.derive().unwrap().0,
            &seal,
            &basis,
            &resolved
        ),
        Err(RefusalCode::EvidenceInvalid)
    ));
}

#[test]
fn subject_movement_refuses_new_preparation_and_not_a_phantom_ref_update() {
    let (context, record, mut resolved, basis, closure) = fixture(GitHashAlgorithm::Sha1);
    let (event, seal) = proposal(&context, &record).unwrap();
    resolved.refs = CanonicalRefState::new(BTreeMap::new());
    let mut head = basis.body().clone();
    head.ref_root = crate::ref_state_root(resolved.root_layout, &resolved.refs).unwrap();
    let moved = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    );
    assert!(matches!(
        prepare_event(
            &context,
            &event,
            &closure,
            seal.derive().unwrap().0,
            &seal,
            &moved,
            &resolved
        ),
        Err(RefusalCode::TargetRefMoved)
    ));
}

#[test]
fn missing_subject_or_false_closure_root_refuses() {
    let (context, record, resolved, basis, mut closure) = fixture(GitHashAlgorithm::Sha256);
    let (event, seal) = proposal(&context, &record).unwrap();
    closure.object_closure_root = digest(99);
    assert!(matches!(
        prepare_event(
            &context,
            &event,
            &closure,
            seal.derive().unwrap().0,
            &seal,
            &basis,
            &resolved
        ),
        Err(RefusalCode::ObjectClosureIncomplete)
    ));
    closure.objects.clear();
    closure.object_closure_root =
        permitted_object_closure_root(&PermittedObjectClosure::new(BTreeSet::new())).unwrap();
    assert!(matches!(
        prepare_event(
            &context,
            &event,
            &closure,
            seal.derive().unwrap().0,
            &seal,
            &basis,
            &resolved
        ),
        Err(RefusalCode::ObjectClosureIncomplete)
    ));
}

#[test]
fn a_different_request_cannot_overwrite_an_already_reported_job() {
    let (mut context, record, mut resolved, basis, closure) = fixture(GitHashAlgorithm::Sha1);
    let (event, seal) = proposal(&context, &record).unwrap();
    let first = prepare_event(
        &context,
        &event,
        &closure,
        seal.derive().unwrap().0,
        &seal,
        &basis,
        &resolved,
    )
    .unwrap();
    resolved.forge = first.forge;
    resolved.outbox = first.outbox;
    context.idempotency_key = IdempotencyKey::new(b"different-key".to_vec()).unwrap();
    let (event, seal) = proposal(&context, &record).unwrap();
    assert!(matches!(
        prepare_event(
            &context,
            &event,
            &closure,
            seal.derive().unwrap().0,
            &seal,
            &basis,
            &resolved
        ),
        Err(RefusalCode::EvidenceStale)
    ));
}

#[test]
fn wrong_native_domain_empty_and_oversized_evidence_refuse_before_sealing() {
    let (context, mut record, _, _, _) = fixture(GitHashAlgorithm::Sha1);
    record.source_commit = GitOid::from_hex(GitHashAlgorithm::Sha256, &"ab".repeat(32)).unwrap();
    assert!(proposal(&context, &record).is_err());
    let (context, mut record, _, _, _) = fixture(GitHashAlgorithm::Sha1);
    record.evidence.clear();
    assert!(proposal(&context, &record).is_err());
    record.evidence.resize(MAX_CHECK_EVIDENCE_BYTES + 1, 0);
    assert!(proposal(&context, &record).is_err());
}
