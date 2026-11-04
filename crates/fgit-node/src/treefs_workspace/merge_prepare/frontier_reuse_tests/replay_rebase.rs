//! Actual cherry-pick and linear rebase preparation beside an admitted blob
//! larger than both the body-read ceiling and the default frontier allowance.
use super::*;
use super::super::commit_replay::ReplayPreparationRefusal;
use super::super::rebase::RebasePreparationRefusal;
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, RebaseCommitter, RebasePreparation, RebaseRequest,
};
use fgit_forge::preparation::replay::{ReplayDirection, ReplayPreparation, ReplayRequest};

fn only_parent(node: &OneNode, id: GitOid) -> GitOid {
    let object = node.read_git_object(id).unwrap();
    let ParsedObject::Commit(commit) = parse_object_body(
        ObjectType::Commit,
        object.payload(),
        AcceptanceProfile::GitCompatibleImport,
        &ParseLimits {
            max_object_bytes: METADATA_BYTES,
            tree_reference_bytes: id.algorithm().digest_len(),
            ..ParseLimits::default()
        },
    )
    .unwrap()
    else {
        panic!("fixture source must be a native commit");
    };
    let mut parents = commit.parent_references();
    let parent = parents.next().unwrap();
    assert!(parents.next().is_none());
    GitOid::from_hex(id.algorithm(), std::str::from_utf8(parent).unwrap()).unwrap()
}

#[test]
fn native_replay_and_rebase_prepare_with_configured_large_blob_frontiers() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let blob_bytes = 32 * 1024 * 1024 + 17;
        let payload = vec![b'k'; blob_bytes];
        let inherited = git_object_id(format, ObjectType::Blob, &payload);
        let (_scratch, mut node, target, incoming) =
            tests::fixture_with_preserved(format, false, false, payload, 64 * 1024 * 1024);
        let upstream = only_parent(&node, incoming);
        let target_ref = RefName::try_new(b"refs/heads/main").unwrap();
        let source_ref = RefName::try_new(b"refs/heads/topic").unwrap();
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let mut unpublished = Vec::new();
        let expected_text = b"A\nb\nc\nd\nE\n";
        let expected_blob = git_object_id(format, ObjectType::Blob, expected_text);
        let assert_generated = |objects: &[PlannedMergeObject]| {
            assert!(objects.iter().all(|object| {
                object.body.len() < METADATA_BYTES && object.id != inherited
            }));
            assert!(objects.iter().any(|object| {
                object.id == expected_blob
                    && object.kind == ObjectType::Blob
                    && object.body.as_slice() == expected_text
            }));
        };
        for maximum in [blob_bytes, blob_bytes - 1] {
            node = reopen(node, format, Some(maximum));
            let permitted = maximum == blob_bytes;
            assert!(
                node.read_git_object(inherited).is_err(),
                "preparation must succeed without widening the 64 KiB body ceiling"
            );
            let request = node.request_context();
            let replay = node.runtime().block_on(node.prepare_replay_bundle_in(
                &request,
                &target_ref,
                &source_ref,
                ReplayRequest {
                    target,
                    source_tip: incoming,
                    selected_commit: incoming,
                    direction: ReplayDirection::CherryPick,
                    mainline: None,
                },
                &RefVisibility::new(),
                Some(before.basis().id()),
                &tests::metadata(),
                PreparationLimits::default(),
            ));
            let replay_tree = match replay {
                Ok(prepared) => {
                    assert!(permitted, "cherry-pick ignored the configured blob limit");
                    assert_eq!(prepared.source_head, before.basis().id());
                    let ReplayPreparation::Clean(plan) = prepared.outcome else {
                        panic!("the source change must produce a clean, nonempty cherry-pick");
                    };
                    assert_eq!(plan.coordinates.request.target, target);
                    assert_eq!(plan.coordinates.request.selected_commit, incoming);
                    assert_generated(&plan.objects);
                    let bundle = prepared.bundle.expect("clean replay must retain its bundle");
                    let inspected = node
                        .runtime()
                        .block_on(node.inspect_workspace_bundle_in(
                            &request,
                            &target_ref,
                            target,
                            plan.commit,
                            &bundle,
                            &RefVisibility::new(),
                            Some(before.basis().id()),
                            &ReviewOptions::default(),
                        ))
                        .unwrap();
                    assert_eq!(inspected.parents, [target]);
                    assert_eq!(inspected.review.comparison.entries.len(), 1);
                    assert_eq!(inspected.review.comparison.entries[0].path, b"text");
                    unpublished.extend(plan.objects.iter().map(|object| object.id));
                    Some(plan.tree)
                }
                Err(error) => {
                    assert!(!permitted, "permitted cherry-pick refused: {error:?}");
                    assert!(error.is_resource_refusal());
                    assert!(matches!(
                        error,
                        ReplayPreparationRefusal::Source(MergeSourceError::BudgetExceeded)
                    ));
                    None
                }
            };
            let rebase = node.runtime().block_on(node.prepare_rebase_bundle_in(
                &request,
                &source_ref,
                &target_ref,
                RebaseRequest {
                    source_tip: incoming,
                    upstream,
                    onto: target,
                    empty: EmptyCommitPolicy::Stop,
                },
                &RefVisibility::new(),
                Some(before.basis().id()),
                &RebaseCommitter {
                    identity: "Rebaser <rebaser@example.invalid>".into(),
                    timestamp: 2,
                },
                PreparationLimits::default(),
            ));
            match rebase {
                Ok(prepared) => {
                    assert!(permitted, "rebase ignored the configured blob limit");
                    assert_eq!(prepared.source_head, before.basis().id());
                    let RebasePreparation::Clean(plan) = prepared.outcome else {
                        panic!("the source change must produce a clean, nonempty rebase");
                    };
                    assert_eq!(plan.steps.len(), 1);
                    assert_eq!(plan.steps[0].original, incoming);
                    assert_eq!(plan.steps[0].rewritten, plan.commit);
                    assert_eq!(Some(plan.tree), replay_tree);
                    assert_generated(&plan.objects);
                    let bundle = prepared.bundle.expect("clean rebase must retain its bundle");
                    let inspected = node
                        .runtime()
                        .block_on(node.inspect_rebase_bundle_in(
                            &request,
                            &source_ref,
                            &target_ref,
                            incoming,
                            target,
                            plan.commit,
                            &bundle,
                            &RefVisibility::new(),
                            Some(before.basis().id()),
                            &ReviewOptions::default(),
                        ))
                        .unwrap();
                    assert_eq!(inspected.commits.len(), 1);
                    assert_eq!(inspected.commits[0].id, plan.commit);
                    assert_eq!(inspected.commits[0].parent, target);
                    assert_eq!(inspected.comparisons.len(), 2);
                    assert_eq!(inspected.comparisons[0].requested_before, incoming);
                    assert_eq!(inspected.comparisons[1].requested_before, target);
                    for comparison in inspected.comparisons {
                        assert_eq!(comparison.entries.len(), 1);
                        assert_eq!(comparison.entries[0].path, b"text");
                    }
                    unpublished.extend(plan.objects.iter().map(|object| object.id));
                }
                Err(error) => {
                    assert!(!permitted, "permitted rebase refused: {error:?}");
                    assert!(error.is_resource_refusal());
                    assert!(matches!(
                        error,
                        RebasePreparationRefusal::Source(MergeSourceError::BudgetExceeded)
                    ));
                }
            }
            let after = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            assert_eq!(after.basis(), before.basis());
            assert_eq!(after.snapshot().refs, before.snapshot().refs);
            assert_staging_empty(&node);
            for id in &unpublished {
                assert!(
                    node.read_git_object(*id).is_err(),
                    "preparation stored unpublished object {id}"
                );
            }
        }
        node.shutdown().unwrap();
    }
}
