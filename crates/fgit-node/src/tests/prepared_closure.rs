//! Reused closure computation still stages through the current real authority.

use super::*;
use crate::{
    AsyncProjectionFailure, CommitMaterialization, DurableAsyncAdmissionProjection,
    FsqliteAuthorityStore, MaterializedAdmission,
};
use fgit_authority::{ImmutableKey, PutOutcome};

fn stored_closure(node: &OneNode) -> ValidatedClosure {
    let object = node
        .put_git_object(ObjectType::Blob, b"reusable canonical closure".to_vec())
        .unwrap();
    let objects = BTreeSet::from([object.identity()]);
    ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    }
}

fn selected(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
}

fn key(node: &OneNode, closure: &ValidatedClosure) -> ImmutableKey {
    admission_immutable_key(
        ADMISSION_CLOSURE_KEY_PREFIX,
        node.repository_id(),
        closure.object_closure_root,
    )
    .unwrap()
}

fn read(node: &OneNode, key: &ImmutableKey) -> ImmutableRead {
    node.runtime()
        .block_on(AsyncAuthorityStore::read_immutable(
            &node.authority,
            node.request_context().authority(),
            key,
        ))
        .unwrap()
}

fn stage(
    node: &OneNode,
    projection: &DurableAsyncAdmissionProjection<'_>,
    authority: &FsqliteAuthorityStore,
    cx: &FsqliteCx,
    selected: &MaterializedAdmission,
    closure: &ValidatedClosure,
) -> Result<CommitMaterialization, AsyncProjectionFailure> {
    let (_, mut request, fold) = evidence_request(node);
    request.promised_closure = closure.objects.clone();
    let snapshot = selected.snapshot();
    let current = match &snapshot.head_target {
        Some(target) => {
            CanonicalRefState::new_with_head_target(snapshot.refs.clone(), target.clone()).unwrap()
        }
        None => CanonicalRefState::new(snapshot.refs.clone()),
    };
    node.runtime().block_on(projection.stage_ref_commit(
        authority,
        cx,
        selected.basis(),
        current,
        selected.root_layout(),
        &request,
        &fold,
        closure,
    ))
}

#[test]
fn a_cached_closure_is_still_written_to_a_different_store_with_the_same_instance_id() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let left_scratch = ScratchDirectory::new();
        let right_scratch = ScratchDirectory::new();
        let (left, _) = OneNode::init(
            test_config(left_scratch.path().to_path_buf()).with_object_format(format),
        )
        .unwrap();
        let (right, _) = OneNode::init(
            test_config(right_scratch.path().to_path_buf()).with_object_format(format),
        )
        .unwrap();
        assert_eq!(left.authority.instance_id(), right.authority.instance_id());
        let closure = stored_closure(&left);
        assert_eq!(stored_closure(&right), closure);
        let selected = selected(&left);
        let (context, _, _) = evidence_request(&left);
        let projection = left.durable_admission_projection(&context).unwrap();
        let closure_key = key(&left, &closure);
        let first = stage(
            &left,
            &projection,
            &left.authority,
            left.request_context().authority(),
            &selected,
            &closure,
        )
        .unwrap();
        assert!(projection.prepared_closure.lock().unwrap().is_some());
        assert_eq!(read(&right, &closure_key), ImmutableRead::Absent);
        let second = stage(
            &right,
            &projection,
            &right.authority,
            right.request_context().authority(),
            &selected,
            &closure,
        )
        .unwrap();
        assert_eq!(second, first);
        let expected = crate::encode_body(&PermittedObjectClosure::new(closure.objects)).unwrap();
        assert_eq!(
            read(&left, &closure_key),
            ImmutableRead::Present(expected.clone())
        );
        assert_eq!(read(&right, &closure_key), ImmutableRead::Present(expected));
        for node in [&left, &right] {
            assert_eq!(
                node.runtime()
                    .block_on(node.authenticate_authority_head())
                    .unwrap()
                    .body()
                    .unwrap(),
                *selected.basis().body(),
                "staged cached bytes never publish repository state"
            );
        }
        drop(projection);
        left.shutdown().unwrap();
        right.shutdown().unwrap();
    }
}

#[test]
fn cached_preparation_cannot_hide_an_immutable_conflict_and_retry_remains_valid() {
    let left_scratch = ScratchDirectory::new();
    let right_scratch = ScratchDirectory::new();
    let (left, _) = OneNode::init(test_config(left_scratch.path().to_path_buf())).unwrap();
    let (right, _) = OneNode::init(test_config(right_scratch.path().to_path_buf())).unwrap();
    let closure = stored_closure(&left);
    assert_eq!(stored_closure(&right), closure);
    let selected = selected(&left);
    let (context, _, _) = evidence_request(&left);
    let projection = left.durable_admission_projection(&context).unwrap();
    let closure_key = key(&left, &closure);
    let first = stage(
        &left,
        &projection,
        &left.authority,
        left.request_context().authority(),
        &selected,
        &closure,
    )
    .unwrap();
    assert!(projection.prepared_closure.lock().unwrap().is_some());
    assert_eq!(
        right
            .runtime()
            .block_on(AsyncAuthorityStore::put_if_absent(
                &right.authority,
                right.request_context().authority(),
                &closure_key,
                b"conflicting immutable bytes",
            ))
            .unwrap(),
        PutOutcome::Created
    );
    assert!(matches!(
        stage(
            &right,
            &projection,
            &right.authority,
            right.request_context().authority(),
            &selected,
            &closure,
        ),
        Err(AsyncProjectionFailure::Unavailable(
            RefusalCode::EvidenceMissing
        ))
    ));
    assert_eq!(
        read(&right, &closure_key),
        ImmutableRead::Present(b"conflicting immutable bytes".to_vec())
    );
    assert!(projection.prepared_closure.lock().unwrap().is_none());
    let retried = stage(
        &left,
        &projection,
        &left.authority,
        left.request_context().authority(),
        &selected,
        &closure,
    )
    .unwrap();
    assert_eq!(retried, first);
    drop(projection);
    left.shutdown().unwrap();
    right.shutdown().unwrap();
}

#[test]
fn a_warm_closure_never_masks_cancellation_and_a_live_retry_keeps_exact_bytes() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let closure = stored_closure(&node);
    let selected = selected(&node);
    let (context, _, _) = evidence_request(&node);
    let projection = node.durable_admission_projection(&context).unwrap();
    let closure_key = key(&node, &closure);
    let first = stage(
        &node,
        &projection,
        &node.authority,
        node.request_context().authority(),
        &selected,
        &closure,
    )
    .unwrap();
    let before = read(&node, &closure_key);
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(matches!(
        stage(
            &node,
            &projection,
            &node.authority,
            cancelled.authority(),
            &selected,
            &closure
        ),
        Err(AsyncProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    assert_eq!(read(&node, &closure_key), before);
    let retried = stage(
        &node,
        &projection,
        &node.authority,
        node.request_context().authority(),
        &selected,
        &closure,
    )
    .unwrap();
    assert_eq!(retried, first);
    assert_eq!(read(&node, &closure_key), before);
    drop(projection);
    node.shutdown().unwrap();
}
