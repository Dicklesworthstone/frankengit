//! Selection uses real native publications and an independent full-history
//! oracle. Faults measure the authenticated read boundary, not throughput.

use super::super::Selection;
use super::*;
use fgit_authority::body_key_for_id;
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, activate_frozen_capsule_async, freeze_capsule_async,
};
use fgit_types::GitHashAlgorithm;
use std::sync::atomic::Ordering;

mod support;
use support::{Fault, ReadProbe, Scratch, apply, fixture, oracle, reference, select, selected};

const TOPIC: &str = "refs/heads/topic";

fn assert_watch(node: &crate::OneNode, tip: GitOid, expected: &LatestRefChange) {
    let request = node.request_context();
    let selection = node
        .runtime()
        .block_on(node.select_ref_workflow_event(&request, &reference(TOPIC)))
        .unwrap();
    let Selection::Ready(actual) = selection else {
        panic!("a visible committed branch must select its net event");
    };
    assert_eq!(actual.commit, tip);
    assert_eq!(actual.previous_commit, expected.previous_tip);
    assert_eq!(actual.batch, expected.batch_id);
    assert_eq!(actual.event_head, expected.resulting_head_id);
    assert_eq!(actual.head, selected(node).basis().id());
}

fn activate_checkpoint(node: &crate::OneNode) {
    let request = node.request_context();
    let state = selected(node);
    let frozen = node
        .runtime()
        .block_on(freeze_capsule_async(
            &node.authority,
            request.authority(),
            &fgit_codec::CryptoBodyIdentity,
            state.authenticated().receipt(),
            None,
            CapsuleClosure {
                object_closure_root: crate::permitted_object_closure_root(
                    state.selected_closure().closure(),
                )
                .unwrap(),
                // This fixed external segment commitment only covers the
                // reduced decision-history capsule profile.
                segment_manifest_root: fgit_codec::harness::digest_of(0xc4),
                backup_profile: BackupProfile::DecisionHistoryOnly,
            },
        ))
        .unwrap();
    node.runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            state.authenticated().receipt(),
            &frozen,
        ))
        .unwrap();
}

#[test]
fn net_ref_event_matches_history_through_noop_recreation_checkpoint_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, base, child) = fixture(&scratch, format);
        apply(&node, "topic-create", TOPIC, None, Some(base));
        let created = select(&node, TOPIC, base);
        assert_eq!(created, oracle(&node, TOPIC));
        assert_eq!(created.previous_tip, None);
        assert_watch(&node, base, &created);

        apply(&node, "topic-advance", TOPIC, Some(base), Some(child));
        let advanced = select(&node, TOPIC, child);
        assert_eq!(advanced, oracle(&node, TOPIC));
        assert_eq!(advanced.previous_tip, Some(base));
        assert_ne!(advanced.batch_id, created.batch_id);

        apply(&node, "other-create", "refs/heads/other", None, Some(base));
        apply(&node, "topic-noop", TOPIC, Some(child), Some(child));
        assert_eq!(select(&node, TOPIC, child), advanced);
        assert_eq!(oracle(&node, TOPIC), advanced);
        assert_watch(&node, child, &advanced);

        activate_checkpoint(&node);
        assert_ne!(selected(&node).basis().id(), advanced.resulting_head_id);
        assert_eq!(select(&node, TOPIC, child), advanced);
        assert_eq!(oracle(&node, TOPIC), advanced);
        assert_watch(&node, child, &advanced);

        apply(&node, "topic-delete", TOPIC, Some(child), None);
        let request = node.request_context();
        assert!(matches!(
            node.runtime()
                .block_on(node.select_ref_workflow_event(&request, &reference(TOPIC)))
                .unwrap(),
            Selection::Absent
        ));
        apply(&node, "topic-recreate", TOPIC, None, Some(child));
        let recreated = select(&node, TOPIC, child);
        assert_eq!(recreated, oracle(&node, TOPIC));
        assert_eq!(recreated.previous_tip, None);
        assert_ne!(recreated.batch_id, advanced.batch_id);
        assert_watch(&node, child, &recreated);
        node.shutdown().unwrap();

        let reopened = crate::OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(select(&reopened, TOPIC, child), recreated);
        assert_eq!(oracle(&reopened, TOPIC), recreated);
        assert_watch(&reopened, child, &recreated);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn recent_event_does_not_read_earlier_batch_but_requires_its_own_proof_and_predecessor_refs() {
    let scratch = Scratch::new();
    let (node, base, child) = fixture(&scratch, GitHashAlgorithm::Sha256);
    let before = selected(&node);
    let old_batch = body_key_for_id(
        before
            .basis()
            .body()
            .decision_tail_id
            .unwrap()
            .as_internal_object_id(),
    )
    .unwrap();
    let predecessor_refs = crate::admission_immutable_key(
        crate::ADMISSION_REF_STATE_KEY_PREFIX,
        node.repository_id(),
        before.basis().body().ref_root,
    )
    .unwrap();
    apply(&node, "recent-topic", TOPIC, None, Some(base));
    let state = selected(&node);
    let expected = oracle(&node, TOPIC);
    let current_batch = body_key_for_id(
        state
            .basis()
            .body()
            .decision_tail_id
            .unwrap()
            .as_internal_object_id(),
    )
    .unwrap();
    let request = node.request_context();

    for fault in [Fault::Absent, Fault::Corrupt] {
        let old_probe = ReadProbe::new(&node, Some((old_batch.clone(), fault)));
        let actual = node
            .runtime()
            .block_on(latest_change_at(
                &old_probe,
                request.authority(),
                state.basis(),
                &reference(TOPIC),
                base,
                1,
                &|| false,
            ))
            .unwrap();
        assert_eq!(actual, expected);
        assert!(
            !old_probe.fired.load(Ordering::SeqCst),
            "the decision batch before the selected net event is outside its proof"
        );

        for required_key in [&current_batch, &predecessor_refs] {
            let required_probe = ReadProbe::new(&node, Some((required_key.clone(), fault)));
            assert!(
                node.runtime()
                    .block_on(latest_change_at(
                        &required_probe,
                        request.authority(),
                        state.basis(),
                        &reference(TOPIC),
                        base,
                        1,
                        &|| false,
                    ))
                    .is_err(),
                "a missing or corrupt selected proof must refuse"
            );
            assert!(required_probe.fired.load(Ordering::SeqCst));
        }
    }

    assert_eq!(
        select(&node, TOPIC, base),
        expected,
        "the valid twin selects"
    );
    assert!(matches!(
        node.runtime().block_on(latest_change_at(
            &node.authority,
            request.authority(),
            state.basis(),
            &reference(TOPIC),
            child,
            MAX_REPLAY_BATCHES,
            &|| false,
        )),
        Err(AdmissionMaterializationRefusal::ExactBasisMismatch)
    ));
    let mismatched = PublicationBasis::new(before.basis().id(), state.basis().body().clone());
    let mismatch_probe = ReadProbe::new(&node, None);
    assert!(matches!(
        node.runtime().block_on(latest_change_at(
            &mismatch_probe,
            request.authority(),
            &mismatched,
            &reference(TOPIC),
            base,
            MAX_REPLAY_BATCHES,
            &|| false,
        )),
        Err(AdmissionMaterializationRefusal::ExactBasisMismatch)
    ));
    assert_eq!(mismatch_probe.reads.load(Ordering::SeqCst), 0);
    node.shutdown().unwrap();
}

#[test]
fn suffix_bound_and_cancellation_refuse_without_an_unverified_event() {
    let scratch = Scratch::new();
    let (node, base, _) = fixture(&scratch, GitHashAlgorithm::Sha1);
    apply(&node, "bounded-topic", TOPIC, None, Some(base));
    apply(&node, "bounded-other", "refs/heads/other", None, Some(base));
    let state = selected(&node);
    let expected = oracle(&node, TOPIC);
    let request = node.request_context();

    for limit in [0, 1, MAX_REPLAY_BATCHES + 1] {
        let result = node.runtime().block_on(latest_change_at(
            &node.authority,
            request.authority(),
            state.basis(),
            &reference(TOPIC),
            base,
            limit,
            &|| false,
        ));
        assert!(matches!(
            result,
            Err(AdmissionMaterializationRefusal::DecisionHistory(error))
                if matches!(
                    *error,
                    OutcomeFailure::ReplayBoundExceeded { limit: actual } if actual == limit
                )
        ));
    }
    assert_eq!(
        node.runtime()
            .block_on(latest_change_at(
                &node.authority,
                request.authority(),
                state.basis(),
                &reference(TOPIC),
                base,
                2,
                &|| false,
            ))
            .unwrap(),
        expected
    );

    let probe = ReadProbe::new(&node, None);
    assert!(matches!(
        node.runtime().block_on(latest_change_at(
            &probe,
            request.authority(),
            state.basis(),
            &reference(TOPIC),
            base,
            MAX_REPLAY_BATCHES,
            &|| true,
        )),
        Err(AdmissionMaterializationRefusal::Cancelled)
    ));
    assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
    let reads = &probe.reads;
    assert!(matches!(
        node.runtime().block_on(latest_change_at(
            &probe,
            request.authority(),
            state.basis(),
            &reference(TOPIC),
            base,
            MAX_REPLAY_BATCHES,
            &|| reads.load(Ordering::SeqCst) > 0,
        )),
        Err(AdmissionMaterializationRefusal::Cancelled)
    ));
    assert!(probe.reads.load(Ordering::SeqCst) > 0);
    assert_eq!(select(&node, TOPIC, base), expected);
    node.shutdown().unwrap();
}
