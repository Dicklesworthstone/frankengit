//! Real embedded admission consumes the same verified metadata owner as merge
//! preparation. Direct provider cases below isolate its refusal boundaries.

use super::*;
use crate::NodeRequestContext;
use fgit_git_object::ObjectType;

fn reopened(node: OneNode, cache_bytes: Option<usize>) -> OneNode {
    let mut config = node.service_config.clone();
    if let Some(bytes) = cache_bytes {
        config = config.with_ancestry_metadata_cache_bytes(bytes);
    }
    node.shutdown().unwrap();
    let mut node = OneNode::open_existing(config).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}

fn validate_native(node: &OneNode, f: &Fixture) -> ValidatedClosure {
    let request = node.request_context();
    let selected = snapshot(node);
    let authenticated = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .unwrap();
    let session = session(b"ancestry-publication");
    let projection = NodeNativeMergeProjection::metadata(
        node,
        &context(node, b"ancestry-publication"),
        session.authenticated_session().unwrap(),
    )
    .unwrap();
    node.runtime()
        .block_on(projection.validate_merge_async(
            &node.authority,
            request.authority(),
            selected.basis(),
            &authenticated,
            &intent(f, 1, f.target, f.candidate),
        ))
        .unwrap()
}

#[test]
fn cold_warm_reopened_and_disabled_metadata_keep_native_publication_and_retry_identical() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut expected = None;
        for cache_bytes in [0, 16 * 1024 * 1024] {
            let scratch = Scratch::new();
            let node = reopened(new_node(&scratch, format), Some(cache_bytes));
            let f = fixture(&node, &scratch, true);
            assert_eq!(node.ancestry_metadata_cache().test_counts(), (0, 0));
            let cold = validate_native(&node, &f);
            let cold_counts = node.ancestry_metadata_cache().test_counts();
            assert!(cold_counts.0 > 0);
            let node = reopened(node, None);
            let warm = validate_native(&node, &f);
            let warm_counts = node.ancestry_metadata_cache().test_counts();
            assert_eq!(cold.objects, warm.objects);
            assert_eq!(cold.object_closure_root, warm.object_closure_root);
            if cache_bytes == 0 {
                assert!(warm_counts.0 > cold_counts.0);
                assert_eq!(warm_counts.1, 0);
            } else {
                assert_eq!(warm_counts.0, cold_counts.0);
                assert!(warm_counts.1 > cold_counts.1);
            }
            let admission = || {
                node.runtime()
                    .block_on(node.admit_native_merge_durable_in(
                        &node.request_context(),
                        &session(b"ancestry-publication"),
                        &intent(&f, 1, f.target, f.candidate),
                        AdmissionLimits::default(),
                        MergeObjectLimits::default(),
                    ))
                    .unwrap()
            };
            let terminal = committed(admission());
            let published_counts = node.ancestry_metadata_cache().test_counts();
            if cache_bytes != 0 {
                assert_eq!(published_counts.0, warm_counts.0);
                assert!(published_counts.1 > warm_counts.1);
            }
            let after = snapshot(&node);
            assert_eq!(after.snapshot().refs[&target_ref()], f.candidate);
            assert_eq!(after.snapshot().refs[&source_ref()], f.source);
            let result = (
                after.snapshot().refs.clone(),
                after.selected_closure().closure().objects().clone(),
                warm.object_closure_root,
            );
            if let Some(expected) = &expected {
                assert_eq!(&result, expected);
            } else {
                expected = Some(result);
            }
            assert_eq!(
                admission(),
                terminal,
                "same seal resolves its original decision"
            );
            assert_eq!(
                node.ancestry_metadata_cache().test_counts(),
                published_counts
            );
            assert_eq!(snapshot(&node).basis(), after.basis());
            node.shutdown().unwrap();
        }
    }
}

fn with_headers<T>(
    node: &OneNode,
    request: &NodeRequestContext,
    selected: &BTreeSet<GitOid>,
    staging: &ReceiveStaging,
    maximum_object_bytes: usize,
    action: impl FnOnce(&NativeFrontierHeaders<'_, '_, '_>) -> T,
) -> T {
    let exhaustion = Cell::new(None);
    let headers = NativeFrontierHeaders {
        source: VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: node.object_format,
            maximum_object_bytes,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        },
        ancestry: AncestryMetadataAccess::for_node(node),
        selected,
        staging,
        maximum_blob_bytes: maximum_object_bytes,
    };
    action(&headers)
}

#[test]
fn admission_metadata_rechecks_membership_parser_limits_and_request_cancellation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = new_node(&scratch, format);
        let f = fixture(&node, &scratch, true);
        let selected = snapshot(&node);
        let ids = selected.selected_closure().closure().objects();
        let request = node.request_context();
        let staging = ReceiveStaging::default();
        let body = node.read_git_object(f.target).unwrap().payload().to_vec();
        let limits = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        with_headers(&node, &request, ids, &staging, body.len(), |headers| {
            assert_eq!(
                headers.load_commit_metadata(&f.target, &limits).unwrap(),
                None
            );
            headers.remember_commit_metadata(&f.target, &body, &limits);
            let warm = headers
                .load_commit_metadata(&f.target, &limits)
                .unwrap()
                .unwrap();
            assert_eq!(warm.id(), f.target);
            assert_eq!(warm.parents(), vec![f.base]);
            assert_eq!(warm.body_bytes(), body.len());
            for narrowed in [
                ParseLimits {
                    max_object_bytes: body.len() - 1,
                    ..limits.clone()
                },
                ParseLimits {
                    max_header_lines: 1,
                    ..limits.clone()
                },
                ParseLimits {
                    max_header_line_bytes: 1,
                    ..limits.clone()
                },
            ] {
                assert_eq!(
                    headers
                        .load_commit_metadata(&f.target, &narrowed)
                        .unwrap_err(),
                    ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded),
                );
            }
        });
        with_headers(&node, &request, ids, &staging, body.len() - 1, |headers| {
            assert_eq!(
                headers
                    .load_commit_metadata(&f.target, &limits)
                    .unwrap_err(),
                ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded),
            );
        });
        let before = node.ancestry_metadata_cache().test_counts();
        let mut narrower = ids.clone();
        narrower.remove(&f.target);
        with_headers(
            &node,
            &request,
            &narrower,
            &staging,
            body.len(),
            |headers| {
                assert_eq!(
                    headers
                        .load_commit_metadata(&f.target, &limits)
                        .unwrap_err(),
                    ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete),
                );
            },
        );
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        with_headers(&node, &cancelled, ids, &staging, body.len(), |headers| {
            assert_eq!(
                headers
                    .load_commit_metadata(&f.target, &limits)
                    .unwrap_err(),
                ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress),
            );
        });
        assert_eq!(node.ancestry_metadata_cache().test_counts(), before);
        with_headers(&node, &request, ids, &staging, body.len(), |headers| {
            assert!(
                headers
                    .load_commit_metadata(&f.target, &limits)
                    .unwrap()
                    .is_some()
            );
        });
        node.shutdown().unwrap();
    }
}

#[test]
fn cached_permanent_commit_never_shadows_supplied_staged_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = new_node(&scratch, format);
        let f = fixture(&node, &scratch, true);
        let selected = snapshot(&node);
        let ids = selected.selected_closure().closure().objects();
        let request = node.request_context();
        let empty = ReceiveStaging::default();
        let body = node.read_git_object(f.target).unwrap().payload().to_vec();
        let limits = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        with_headers(&node, &request, ids, &empty, 4096, |headers| {
            headers.remember_commit_metadata(&f.target, &body, &limits);
            assert!(
                headers
                    .load_commit_metadata(&f.target, &limits)
                    .unwrap()
                    .is_some()
            );
        });
        let staging = ReceiveStaging::default();
        staging
            .stage(
                &node,
                &[node
                    .verified_git_object(ObjectType::Commit, body.clone())
                    .unwrap()],
                &mut || true,
            )
            .unwrap();
        with_headers(&node, &request, ids, &staging, 4096, |headers| {
            assert_eq!(
                headers.load_commit_metadata(&f.target, &limits).unwrap(),
                None
            );
            assert_eq!(headers.load_header(&f.target).unwrap(), None);
        });
        let exhaustion = Cell::new(None);
        let source = VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: 4096,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        let staged = source.with_staging(&staging);
        assert_eq!(staged.read_object(&f.target).unwrap().1, body);
        let private = fs::read_dir(node.storage_root().join("staging"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(private, b"corrupt staged commit framing").unwrap();
        with_headers(&node, &request, ids, &staging, 4096, |headers| {
            assert_eq!(
                headers.load_commit_metadata(&f.target, &limits).unwrap(),
                None
            );
        });
        assert!(staged.read_object(&f.target).is_err());
        assert_eq!(node.read_git_object(f.target).unwrap().payload(), body);
        drop(staging);
        node.shutdown().unwrap();
    }
}

#[test]
fn stricter_cache_parse_does_not_narrow_historical_ancestry_acceptance() {
    // This provider fixture supplies its selected set explicitly. It exercises
    // the historical parser contract, not new authority admission of the set.
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = new_node(&scratch, format);
        let tree = node
            .put_git_object(ObjectType::Tree, Vec::new())
            .unwrap()
            .identity();
        let body = format!("tree {tree}\ntree {tree}\ncommitter unusual 123 bad-zone\n\nold\n");
        let base = node
            .put_git_object(ObjectType::Commit, body.into_bytes())
            .unwrap()
            .identity();
        let tip = node
            .put_git_object(ObjectType::Commit, commit_body(tree, &[base], "tip\n"))
            .unwrap()
            .identity();
        let ids = BTreeSet::from([tree, base, tip]);
        let request = node.request_context();
        let staging = ReceiveStaging::default();
        let merge = NativeMerge {
            source_ref: source_ref(),
            source_tip: tip,
            base_tip: base,
            target_ref: target_ref(),
            target_tip_before: base,
            merge_commit: tip,
        };
        with_headers(&node, &request, &ids, &staging, 4096, |headers| {
            let cold = validate_fast_forward_objects_above(
                &headers.source,
                &merge,
                &ids,
                MergeObjectLimits::default(),
                &mut || true,
            )
            .unwrap();
            for _ in 0..2 {
                let cached = validate_fast_forward_objects_above(
                    &headers.source,
                    &merge,
                    ObjectFrontier::with_headers(&ids, headers),
                    MergeObjectLimits::default(),
                    &mut || true,
                )
                .unwrap();
                assert_eq!(cached.objects, cold.objects);
                assert_eq!(cached.object_closure_root, cold.object_closure_root);
                assert_eq!(
                    headers
                        .load_commit_metadata(&base, &ParseLimits::default())
                        .unwrap(),
                    None
                );
            }
        });
        node.shutdown().unwrap();
    }
}
