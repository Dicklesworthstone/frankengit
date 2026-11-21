//! Native object-type filters retain provided roots and walk omitted metadata.
use super::*;

#[test]
fn object_type_selection_preserves_explicit_tag_chains_and_all_matching_descendants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let old_blob = source.put(ObjectType::Blob, b"old content".to_vec());
        let old_tree = source.tree(&[(b"100644", b"old", old_blob)]);
        let ancestor = source.commit(old_tree, &[]);
        let blob = source.put(ObjectType::Blob, b"new content".to_vec());
        let nested = source.tree(&[(b"100644", b"file", blob)]);
        let tree = source.tree(&[(b"40000", b"nested", nested)]);
        let commit = source.commit(tree, &[ancestor]);
        let tag = source.put(ObjectType::Tag, tag_bytes(commit, "commit"));
        let outer = source.put(ObjectType::Tag, tag_bytes(tag, "tag"));
        let graph = graph(&source, &[outer]);
        let all = graph.closure.objects().iter().copied().collect::<Vec<_>>();
        source.reads.borrow_mut().clear();
        for (kind, expected) in [
            (
                ObjectType::Commit,
                BTreeSet::from([outer, tag, commit, ancestor]),
            ),
            (
                ObjectType::Tree,
                BTreeSet::from([outer, tag, commit, old_tree, tree, nested]),
            ),
            (
                ObjectType::Blob,
                BTreeSet::from([outer, tag, commit, old_blob, blob]),
            ),
            (ObjectType::Tag, BTreeSet::from([outer, tag, commit])),
        ] {
            assert_eq!(
                apply(
                    &graph,
                    &all,
                    &request(vec![outer], vec![], Some(ObjectFilter::ObjectType(kind))),
                )
                .into_iter()
                .collect::<BTreeSet<_>>(),
                expected,
                "{format:?} {kind:?}",
            );
        }
        assert!(
            source.reads.borrow().is_empty(),
            "type selection needs no object bodies"
        );
        let contradictory = Some(ObjectFilter::Combine(vec![
            ObjectFilter::ObjectType(ObjectType::Blob),
            ObjectFilter::ObjectType(ObjectType::Tree),
        ]));
        assert_eq!(
            apply(
                &graph,
                &all,
                &request(vec![outer], vec![], contradictory.clone())
            )
            .into_iter()
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([outer, tag, commit]),
        );
        assert_eq!(
            apply(
                &graph,
                &[outer],
                &request(vec![outer], vec![tag], contradictory.clone())
            ),
            vec![outer],
            "a held intermediate tag cuts provided-object propagation",
        );
        assert_eq!(
            apply(
                &graph,
                &[outer, tag],
                &request(vec![outer], vec![commit], contradictory)
            )
            .into_iter()
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([outer, tag]),
            "a held terminal commit remains excluded",
        );
    }
}

#[test]
fn object_type_filters_intersect_sparse_size_and_depth_without_losing_lazy_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let small = source.put(ObjectType::Blob, b"a".to_vec());
        let large = source.put(ObjectType::Blob, b"large".to_vec());
        let skipped = source.put(ObjectType::Blob, b"s".to_vec());
        let patterns = source.put(ObjectType::Blob, b"/keep/\n".to_vec());
        let kept_tree = source.tree(&[(b"100644", b"large", large), (b"100644", b"small", small)]);
        let root = source.tree(&[
            (b"100644", b".sparse", patterns),
            (b"40000", b"keep", kept_tree),
            (b"100644", b"skip", skipped),
        ]);
        let commit = source.commit(root, &[]);
        let graph = graph(&source, &[commit]);
        let all = graph.closure.objects().iter().copied().collect::<Vec<_>>();
        for (depth, expected) in [
            (2, BTreeSet::from([commit])),
            (3, BTreeSet::from([commit, small])),
        ] {
            let filter = ObjectFilter::Combine(vec![
                ObjectFilter::ObjectType(ObjectType::Blob),
                ObjectFilter::SparseObject(patterns),
                ObjectFilter::BlobLimit(5),
                ObjectFilter::TreeDepth(depth),
            ]);
            let mut ids = all.clone();
            engine::apply_selection_with_sparse(
                &graph.objects,
                &graph.facts,
                &mut ids,
                &request(vec![commit], vec![], Some(filter)),
                &PackLimits::default(),
                &mut |id, maximum| {
                    assert_eq!(id, patterns);
                    assert!(source.objects[&id].1.len() <= maximum);
                    source.load(id)
                },
                &mut || true,
            )
            .unwrap();
            assert_eq!(ids.into_iter().collect::<BTreeSet<_>>(), expected);
        }
        assert_eq!(
            apply(
                &graph,
                &[],
                &request(
                    vec![small],
                    vec![commit],
                    Some(ObjectFilter::ObjectType(ObjectType::Commit))
                ),
            ),
            vec![small],
            "explicit blob wants bypass a type filter despite a have-commit",
        );
        assert_eq!(
            apply(
                &graph,
                &[],
                &request(
                    vec![kept_tree],
                    vec![commit],
                    Some(ObjectFilter::ObjectType(ObjectType::Blob))
                ),
            )
            .into_iter()
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([kept_tree, small, large]),
            "an explicit tree is retained while its descendants are type-filtered",
        );
        assert!(
            apply(
                &graph,
                &[],
                &request(
                    vec![small],
                    vec![small],
                    Some(ObjectFilter::ObjectType(ObjectType::Commit))
                ),
            )
            .is_empty(),
            "an explicit have of the requested object still wins",
        );
    }
}

#[test]
fn object_type_selection_is_atomic_under_every_cancellation_and_resource_stop() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha256);
    let blob = source.put(ObjectType::Blob, b"body".to_vec());
    let tree = source.tree(&[(b"100644", b"file", blob)]);
    let commit = source.commit(tree, &[]);
    let tag = source.put(ObjectType::Tag, tag_bytes(commit, "commit"));
    let graph = graph(&source, &[tag]);
    let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
    let request = request(
        vec![tag],
        vec![],
        Some(ObjectFilter::ObjectType(ObjectType::Blob)),
    );
    let mut polls = 0;
    let mut ids = original.clone();
    engine::apply_selection(
        &graph.objects,
        &mut ids,
        &request,
        &PackLimits::default(),
        &mut || {
            polls += 1;
            true
        },
    )
    .unwrap();
    assert_eq!(
        ids.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([tag, commit, blob])
    );
    for stop in 1..=polls {
        let mut count = 0;
        let mut ids = original.clone();
        assert!(matches!(
            engine::apply_selection(
                &graph.objects,
                &mut ids,
                &request,
                &PackLimits::default(),
                &mut || {
                    count += 1;
                    count < stop
                },
            ),
            Err(NodePackMaterializationRefusal::Pack(error))
                if matches!(*error, PackWriteError::Pack(PackError::DeadlineExceeded)),
        ));
        assert_eq!(ids, original);
    }
    for limits in [
        PackLimits {
            max_entries: 3,
            ..PackLimits::default()
        },
        PackLimits {
            max_delta_work: 1,
            ..PackLimits::default()
        },
    ] {
        let mut ids = original.clone();
        expect_code(
            engine::apply_selection(&graph.objects, &mut ids, &request, &limits, &mut || true),
            RefusalCode::ResourceBudgetExceeded,
        );
        assert_eq!(ids, original);
    }
}

#[test]
fn object_type_fetches_serve_exact_native_packs_over_daemon_and_http_after_reopen() {
    use fgit_object_fabric::ObjectKind;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            config,
            public,
            private,
            private_blob,
            ancestor,
            visible,
        } = fixture(format);
        delete_private(&node, private);
        let (tag, outer, _) = publish_tag_fixture(&node, public);
        let metadata = visible
            .iter()
            .map(|id| {
                let object = node.read_git_object(*id).unwrap();
                (
                    *id,
                    (object.envelope().object_kind(), object.payload().to_vec()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let tag_bodies =
            [tag, outer].map(|id| node.read_git_object(id).unwrap().payload().to_vec());
        let common_blob = git_object_id(format, GitObjectKind::Blob, b"common ancestor body");
        let ancestor_tree = tree_bytes(&[(b"100644", b"common", common_blob)]);
        let context = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap();
        let retained = before.selected_closure().closure().objects().clone();
        node.shutdown().unwrap();
        node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        for version in [0, 1, 2] {
            for (filter, selected_kind) in [
                ("object:type=commit", ObjectKind::Commit),
                ("object:type=tree", ObjectKind::Tree),
                ("object:type=blob", ObjectKind::Blob),
                ("object:type=tag", ObjectKind::Tag),
            ] {
                let expected = metadata
                    .iter()
                    .filter_map(|(id, (kind, body))| {
                        (*id == public || *kind == selected_kind).then(|| body.clone())
                    })
                    .collect::<BTreeSet<_>>();
                let (returned, result, response) =
                    exchange_filtered(node, version, &[public], None, Some(filter), false);
                node = returned;
                assert!(
                    matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                    "{format:?} v{version} {filter}: {result:?}"
                );
                assert_eq!(
                    bodies(&response, version, format),
                    expected,
                    "daemon {format:?} v{version} {filter}"
                );
                let http = super::sparse::http_fetch(&node, version, public, filter, None).unwrap();
                assert_eq!(
                    bodies(&http, version, format),
                    expected,
                    "HTTP {format:?} v{version} {filter}"
                );

                let (returned, result, response) =
                    exchange_filtered(node, version, &[outer], None, Some(filter), false);
                node = returned;
                assert!(matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))));
                let mut tagged = expected;
                tagged.extend(tag_bodies.clone());
                assert_eq!(
                    bodies(&response, version, format),
                    tagged,
                    "provided tag chain {format:?} v{version} {filter}"
                );
            }
            // History clipping precedes type omission. Depth two reaches the
            // ancestor's blob through its omitted commit/tree; depth one must
            // not restore that blob or any object beyond the shallow cut.
            for (depth, boundary, expected) in [
                (
                    1,
                    public,
                    BTreeSet::from([
                        metadata[&public].1.clone(),
                        b"current public content".to_vec(),
                    ]),
                ),
                (
                    2,
                    ancestor,
                    BTreeSet::from([
                        metadata[&public].1.clone(),
                        b"current public content".to_vec(),
                        b"common ancestor body".to_vec(),
                    ]),
                ),
            ] {
                let http = super::sparse::http_fetch(
                    &node,
                    version,
                    public,
                    "object:type=blob",
                    Some(depth),
                )
                .unwrap();
                assert_eq!(
                    bodies(&http, version, format),
                    expected,
                    "shallow object-type selection {format:?} v{version} depth {depth}",
                );
                let shallow = format!("shallow {boundary}\n");
                assert!(
                    http.windows(shallow.len())
                        .any(|bytes| bytes == shallow.as_bytes())
                );
            }
            // Git's promisor fetch disables have negotiation. An ancestor
            // commit omitted by object:type=blob is retrievable through that
            // ordinary no-have path, including its blobless tree closure.
            let (returned, result, response) =
                exchange_filtered(node, version, &[ancestor], None, Some("blob:none"), false);
            node = returned;
            assert!(matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))));
            assert_eq!(
                bodies(&response, version, format),
                BTreeSet::from([metadata[&ancestor].1.clone(), ancestor_tree.clone()]),
                "promised ancestor hydration {format:?} v{version}",
            );
            // Automatic tag following remains a post-filter expansion and
            // can retain visible tags that point to a selected commit.
            let (returned, result, response) = exchange_filtered(
                node,
                version,
                &[public],
                None,
                Some("object:type=commit"),
                true,
            );
            node = returned;
            assert!(matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))));
            let mut expected = metadata
                .values()
                .filter(|(kind, _)| *kind == ObjectKind::Commit)
                .map(|(_, body)| body.clone())
                .collect::<BTreeSet<_>>();
            expected.extend(tag_bodies.clone());
            assert_eq!(bodies(&response, version, format), expected);
            let public_blob = git_object_id(format, GitObjectKind::Blob, b"current public content");
            let (returned, result, response) = exchange_filtered(
                node,
                version,
                &[public_blob],
                Some(public),
                Some("object:type=commit"),
                false,
            );
            node = returned;
            assert!(matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))));
            assert_eq!(
                bodies(&response, version, format),
                BTreeSet::from([b"current public content".to_vec()])
            );
            for forbidden in [private, private_blob] {
                let (returned, result, response) = exchange_filtered(
                    node,
                    version,
                    &[forbidden],
                    None,
                    Some("object:type=blob"),
                    false,
                );
                node = returned;
                assert!(result.is_err());
                assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
            }
        }
        let context = node.request_context();
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap();
        assert_eq!(before.basis(), after.basis());
        assert_eq!(after.selected_closure().closure().objects(), &retained);
        node.shutdown().unwrap();
    }
}
