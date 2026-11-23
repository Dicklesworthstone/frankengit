//! Symbolic sparse patterns use the authenticated advertisement and verified trees.
use super::*;
use fgit_wire::AdvertisedRef;

fn advertised(name: &[u8], oid: GitOid) -> AdvertisedRef {
    AdvertisedRef::new(oid, name, &WireLimits::default()).unwrap()
}

fn select(
    source: &MemorySource,
    graph: &VisibleGraph,
    refs: &[AdvertisedRef],
    ids: &mut Vec<GitOid>,
    request: &PackRequest,
    limits: &PackLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), NodePackMaterializationRefusal> {
    engine::apply_selection_with_sparse(
        &graph.objects,
        &graph.facts,
        refs,
        ids,
        request,
        limits,
        &mut |id, maximum| {
            assert!(source.objects[&id].1.len() <= maximum);
            source.load(id)
        },
        live,
    )
}

#[test]
fn sparse_names_resolve_visible_aliases_tags_trees_and_raw_paths_like_exact_oids() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let pattern = source.put(ObjectType::Blob, b"/selected\n".to_vec());
        let kept = source.put(ObjectType::Blob, b"selected body".to_vec());
        let omitted = source.put(ObjectType::Blob, b"omitted body".to_vec());
        let directory = source.tree(&[(b"100644", b"patterns\xff", pattern)]);
        let root = source.tree(&[
            (b"100644", b".sparse", pattern),
            (b"40000", b"dir", directory),
            (b"100644", b"omitted", omitted),
            (b"100644", b"selected", kept),
        ]);
        let commit = source.commit(root, &[]);
        let inner = source.put(ObjectType::Tag, tag_bytes(commit, "commit"));
        let outer = source.put(ObjectType::Tag, tag_bytes(inner, "tag"));
        let tree_tag = source.put(ObjectType::Tag, tag_bytes(root, "tree"));
        let graph = graph(&source, &[commit, outer, tree_tag]);
        let refs = [
            advertised(b"HEAD", commit),
            advertised(b"refs/heads/main", commit),
            advertised(b"refs/heads/feature/topic", commit),
            advertised(b"refs/tags/release", outer),
            advertised(b"refs/tags/tree", tree_tag),
            advertised(b"refs/meta/config", root),
        ];
        let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
        for extra in [
            None,
            Some(ObjectFilter::BlobNone),
            Some(ObjectFilter::ObjectType(ObjectType::Blob)),
        ] {
            let filtered = |filter: ObjectFilter| match &extra {
                None => filter,
                Some(extra) => ObjectFilter::Combine(vec![filter, extra.clone()]),
            };
            let mut expected = original.clone();
            select(
                &source,
                &graph,
                &refs,
                &mut expected,
                &request(
                    vec![commit],
                    vec![],
                    Some(filtered(ObjectFilter::SparseObject(pattern))),
                ),
                &PackLimits::default(),
                &mut || true,
            )
            .unwrap();
            assert!(!expected.contains(&omitted));
            assert!(!expected.contains(&pattern));
            assert_eq!(
                expected.contains(&kept),
                extra != Some(ObjectFilter::BlobNone)
            );
            for name in [
                &b"HEAD:.sparse"[..],
                b"main:.sparse",
                b"refs/heads/main:.sparse",
                b"feature/topic:.sparse",
                b"release:.sparse",
                b"refs/tags/release:.sparse",
                b"tree:.sparse",
                b"refs/meta/config:.sparse",
                b"main:dir/patterns\xff",
            ] {
                source.reads.borrow_mut().clear();
                let mut selected = original.clone();
                select(
                    &source,
                    &graph,
                    &refs,
                    &mut selected,
                    &request(
                        vec![commit],
                        vec![],
                        Some(filtered(ObjectFilter::SparseObjectName(name.to_vec()))),
                    ),
                    &PackLimits::default(),
                    &mut || true,
                )
                .unwrap();
                assert_eq!(selected, expected, "{format:?} {name:?} {extra:?}");
                assert_eq!(
                    *source.reads.borrow(),
                    vec![pattern],
                    "resolution never reads a ref, tag or tree body again"
                );
            }
        }
    }
}

#[test]
fn sparse_names_hidden_missing_ambiguous_nonblob_and_gitlink_paths_refuse_before_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let pattern = source.put(ObjectType::Blob, b"*\n".to_vec());
        let private_root = source.tree(&[(b"100644", b".sparse", pattern)]);
        let private = source.commit(private_root, &[]);
        let directory = source.tree(&[]);
        let root = source.tree(&[
            (b"100644", b".sparse", pattern),
            (b"40000", b"directory", directory),
            (b"160000", b"submodule", private),
        ]);
        let commit = source.commit(root, &[]);
        let graph = graph(&source, &[commit]);
        let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
        let refs = [advertised(b"refs/heads/main", commit)];
        for name in [
            &b"private:.sparse"[..],
            b"missing:.sparse",
            b"main:missing",
            b"main:directory",
            b"main:.sparse/child",
            b"main:submodule/.sparse",
        ] {
            source.reads.borrow_mut().clear();
            let mut selected = original.clone();
            let result = select(
                &source,
                &graph,
                &refs,
                &mut selected,
                &request(
                    vec![commit],
                    vec![],
                    Some(ObjectFilter::Combine(vec![
                        ObjectFilter::SparseObject(pattern),
                        ObjectFilter::SparseObjectName(name.to_vec()),
                    ])),
                ),
                &PackLimits::default(),
                &mut || true,
            );
            assert!(
                matches!(
                    result,
                    Err(NodePackMaterializationRefusal::UnsupportedFetch(
                        "sparse filter requires a visible ref:path blob"
                    ))
                ),
                "{name:?}: {result:?}"
            );
            assert_eq!(selected, original);
            assert!(
                source.reads.borrow().is_empty(),
                "all pattern identities precede body reads"
            );
        }
        let ambiguous = [
            advertised(b"refs/heads/main", commit),
            advertised(b"refs/tags/main", commit),
        ];
        for (name, permitted) in [
            (&b"main:.sparse"[..], false),
            (&b"refs/heads/main:.sparse"[..], true),
            (&b"refs/tags/main:.sparse"[..], true),
        ] {
            source.reads.borrow_mut().clear();
            let mut selected = original.clone();
            let result = select(
                &source,
                &graph,
                &ambiguous,
                &mut selected,
                &request(
                    vec![commit],
                    vec![],
                    Some(ObjectFilter::SparseObjectName(name.to_vec())),
                ),
                &PackLimits::default(),
                &mut || true,
            );
            if permitted {
                result.unwrap();
                assert_eq!(*source.reads.borrow(), vec![pattern]);
            } else {
                assert!(matches!(
                    result,
                    Err(NodePackMaterializationRefusal::UnsupportedFetch(
                        "sparse filter requires a visible ref:path blob"
                    ))
                ));
                assert_eq!(selected, original);
                assert!(source.reads.borrow().is_empty());
            }
        }
    }
}

#[test]
fn sparse_names_every_resolution_cancellation_and_work_limit_preserves_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let pattern = source.put(ObjectType::Blob, b"/kept\n".to_vec());
        let kept = source.put(ObjectType::Blob, b"kept".to_vec());
        let directory = source.tree(&[(b"100644", b"pattern", pattern)]);
        let root = source.tree(&[(b"40000", b"dir", directory), (b"100644", b"kept", kept)]);
        let commit = source.commit(root, &[]);
        let tag = source.put(ObjectType::Tag, tag_bytes(commit, "commit"));
        let graph = graph(&source, &[tag]);
        let refs = [advertised(b"refs/tags/release", tag)];
        let request = request(
            vec![commit],
            vec![],
            Some(ObjectFilter::SparseObjectName(
                b"release:dir/pattern".to_vec(),
            )),
        );
        let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
        let mut polls = 0;
        let mut expected = original.clone();
        select(
            &source,
            &graph,
            &refs,
            &mut expected,
            &request,
            &PackLimits::default(),
            &mut || {
                polls += 1;
                true
            },
        )
        .unwrap();
        for stop in 1..=polls {
            let mut count = 0;
            let mut selected = original.clone();
            let result = select(
                &source,
                &graph,
                &refs,
                &mut selected,
                &request,
                &PackLimits::default(),
                &mut || {
                    count += 1;
                    count != stop
                },
            );
            assert!(
                matches!(result, Err(NodePackMaterializationRefusal::Pack(error))
                if matches!(*error, PackWriteError::Pack(PackError::DeadlineExceeded))),
                "stop={stop}"
            );
            assert_eq!(selected, original);
        }
        for (maximum, permitted) in [(polls - 1, false), (polls, true)] {
            let mut selected = original.clone();
            let result = select(
                &source,
                &graph,
                &refs,
                &mut selected,
                &request,
                &PackLimits {
                    max_delta_work: maximum,
                    ..PackLimits::default()
                },
                &mut || true,
            );
            if permitted {
                result.unwrap();
                assert_eq!(selected, expected);
            } else {
                expect_code(result, RefusalCode::ResourceBudgetExceeded);
                assert_eq!(selected, original);
            }
        }
    }
}

#[test]
fn sparse_names_syntax_is_bounded_and_does_not_accept_revision_or_host_path_grammar() {
    for name in [
        &b"HEAD~1:patterns"[..],
        b"HEAD^:patterns",
        b"main@{1}:patterns",
        b"main:",
        b":patterns",
        b"main:/etc/passwd",
        b"main:../patterns",
        b"main:dir//patterns",
        b"main:dir/./patterns",
        b"main:pattern\0suffix",
        b"main:pattern\nsuffix",
        b"main:pattern\rsuffix",
    ]
    .into_iter()
    .map(<[u8]>::to_vec)
    .chain([{
        let mut name = b"main:".to_vec();
        name.extend(std::iter::repeat_n(b'x', 4097));
        name
    }]) {
        assert_eq!(
            engine::unserved_filter_name(&ObjectFilter::SparseObjectName(name)),
            Some("sparse:oid")
        );
    }
}

#[test]
fn sparse_names_native_git_and_http_match_exact_oid_filter_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            config,
            public,
            private,
            ..
        } = fixture_with_public_body(format, b"public\n".to_vec());
        delete_private(&node, private);
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let pattern = git_object_id(format, GitObjectKind::Blob, b"public\n");
        for version in [0, 1, 2] {
            let exact = sparse::http_fetch(
                &node,
                version,
                public,
                &format!("sparse:oid={pattern}"),
                None,
            )
            .unwrap();
            let expected = bodies(&exact, version, format);
            for expression in ["public:public", "refs/heads/public:public"] {
                let filter = format!("sparse:oid={expression}");
                let http = sparse::http_fetch(&node, version, public, &filter, None).unwrap();
                assert_eq!(bodies(&http, version, format), expected);
                let (returned, result, response) =
                    exchange_filtered(node, version, &[public], None, Some(&filter), false);
                node = returned;
                assert!(
                    result.is_ok(),
                    "{format:?} v{version} {expression}: {result:?}"
                );
                assert_eq!(bodies(&response, version, format), expected);
                let combined = format!("combine:sparse%3Aoid%3D{expression}+object%3Atype%3Dblob");
                let http = sparse::http_fetch(&node, version, public, &combined, Some(1)).unwrap();
                let expected: BTreeSet<Vec<u8>> = [public, pattern]
                    .into_iter()
                    .map(|id| node.read_git_object(id).unwrap().payload().to_vec())
                    .collect();
                assert_eq!(bodies(&http, version, format), expected);
            }
        }
        for version in [0, 2] {
            for expression in [
                "private:private",
                "missing:private",
                "public:submodule/private",
            ] {
                let (returned, result, response) = exchange_filtered(
                    node,
                    version,
                    &[public],
                    None,
                    Some(&format!("sparse:oid={expression}")),
                    false,
                );
                node = returned;
                assert!(matches!(result, Err(NodeGitDaemonServeRefusal::Pack(error))
                if matches!(*error, NodePackMaterializationRefusal::UnsupportedFetch(
                    "sparse filter requires a visible ref:path blob"
                ))));
                assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
                let text = String::from_utf8_lossy(&response);
                assert!(text.contains("ERR unsupported fetch feature:"));
                assert!(!text.contains(expression));
                assert!(!text.contains(&private.to_string()));
            }
        }
        let after = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(after.basis(), before.basis());
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure()
        );
        node.shutdown().unwrap();
    }
}
