//! Native sparse fetches: patterns are visible Git blobs, never host paths.
use super::*;
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits, parse_head};
use std::io::Cursor;

fn sparse_apply(
    source: &MemorySource,
    graph: &VisibleGraph,
    ids: &mut Vec<GitOid>,
    request: &PackRequest,
    limits: &PackLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), NodePackMaterializationRefusal> {
    engine::apply_selection_with_sparse(
        &graph.objects,
        &graph.facts,
        ids,
        request,
        limits,
        &mut |id, maximum| {
            assert!(
                source.objects[&id].1.len() <= maximum,
                "loader receives a bounded pattern request"
            );
            source.load(id)
        },
        live,
    )
}

#[test]
fn sparse_shared_subtrees_revisit_paths_and_compound_filters_intersect_blob_unions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let patterns = source.put(ObjectType::Blob, b"/z/\n!/z/private\n".to_vec());
        let other_patterns = source.put(ObjectType::Blob, b"/a/file\n".to_vec());
        let kept = source.put(ObjectType::Blob, b"shared selected bytes".to_vec());
        let omitted = source.put(ObjectType::Blob, b"excluded bytes".to_vec());
        let shared = source.tree(&[(b"100644", b"file", kept), (b"100644", b"private", omitted)]);
        let root = source.tree(&[
            (b"40000", b"a", shared),
            (b"100644", b"other-patterns", other_patterns),
            (b"100644", b"patterns", patterns),
            (b"40000", b"z", shared),
        ]);
        let commit = source.commit(root, &[]);
        let graph = graph(&source, &[commit]);
        let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
        for filter in [
            ObjectFilter::SparseObject(patterns),
            ObjectFilter::Combine(vec![
                ObjectFilter::SparseObject(patterns),
                ObjectFilter::SparseObject(other_patterns),
            ]),
            ObjectFilter::Combine(vec![
                ObjectFilter::SparseObject(patterns),
                ObjectFilter::TreeDepth(3),
            ]),
        ] {
            let mut ids = original.clone();
            source.reads.borrow_mut().clear();
            sparse_apply(
                &source,
                &graph,
                &mut ids,
                &request(vec![commit], vec![], Some(filter)),
                &PackLimits::default(),
                &mut || true,
            )
            .unwrap();
            assert_eq!(
                ids.into_iter().collect::<BTreeSet<_>>(),
                BTreeSet::from([commit, root, shared, kept])
            );
            assert!(
                source
                    .reads
                    .borrow()
                    .iter()
                    .all(|id| *id == patterns || *id == other_patterns)
            );
        }
        let mut ids = original.clone();
        sparse_apply(
            &source,
            &graph,
            &mut ids,
            &request(
                vec![commit],
                vec![],
                Some(ObjectFilter::Combine(vec![
                    ObjectFilter::SparseObject(patterns),
                    ObjectFilter::BlobLimit(1),
                ])),
            ),
            &PackLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(
            ids.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([commit, root, shared])
        );
        // An explicit promised object bypasses omission even with a have-commit;
        // the same object explicitly declared present is still excluded.
        for (have, expected) in [(commit, vec![omitted]), (omitted, vec![])] {
            let mut ids = Vec::new();
            sparse_apply(
                &source,
                &graph,
                &mut ids,
                &request(
                    vec![omitted],
                    vec![have],
                    Some(ObjectFilter::SparseObject(patterns)),
                ),
                &PackLimits::default(),
                &mut || true,
            )
            .unwrap();
            assert_eq!(ids, expected);
        }
    }
}

#[test]
fn sparse_pattern_authorization_and_aggregate_limits_precede_every_pattern_read() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha256);
    let visible = source.put(ObjectType::Blob, b"*\n".to_vec());
    let hidden = source.put(ObjectType::Blob, b"private/**\n".to_vec());
    let large = source.put(ObjectType::Blob, vec![b'x'; 1024 * 1024 + 1]);
    let medium_a = source.put(ObjectType::Blob, vec![b'a'; 600 * 1024]);
    let medium_b = source.put(ObjectType::Blob, vec![b'b'; 600 * 1024]);
    let root = source.tree(&[
        (b"100644", b"large", large),
        (b"100644", b"medium-a", medium_a),
        (b"100644", b"medium-b", medium_b),
        (b"100644", b"patterns", visible),
    ]);
    let commit = source.commit(root, &[]);
    let graph = graph(&source, &[commit]);
    let missing = git_object_id(source.format, GitObjectKind::Blob, b"never stored");
    let foreign = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"*\n");
    let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
    for pattern in [hidden, missing, foreign, commit, large] {
        let mut ids = original.clone();
        source.reads.borrow_mut().clear();
        let result = sparse_apply(
            &source,
            &graph,
            &mut ids,
            &request(
                vec![commit],
                vec![],
                Some(ObjectFilter::Combine(vec![
                    ObjectFilter::SparseObject(visible),
                    ObjectFilter::SparseObject(pattern),
                ])),
            ),
            &PackLimits::default(),
            &mut || true,
        );
        assert!(result.is_err());
        assert_eq!(ids, original);
        assert!(
            source.reads.borrow().is_empty(),
            "all pattern metadata must pass before any body read"
        );
    }
    let mut ids = original.clone();
    source.reads.borrow_mut().clear();
    expect_code(
        sparse_apply(
            &source,
            &graph,
            &mut ids,
            &request(
                vec![commit],
                vec![],
                Some(ObjectFilter::Combine(vec![
                    ObjectFilter::SparseObject(medium_a),
                    ObjectFilter::SparseObject(medium_b),
                ])),
            ),
            &PackLimits::default(),
            &mut || true,
        ),
        RefusalCode::ResourceBudgetExceeded,
    );
    assert_eq!(ids, original);
    assert!(
        source.reads.borrow().is_empty(),
        "the aggregate pattern-byte bound precedes reads"
    );
    let mut ids = original.clone();
    sparse_apply(
        &source,
        &graph,
        &mut ids,
        &request(
            vec![commit],
            vec![],
            Some(ObjectFilter::SparseObject(visible)),
        ),
        &PackLimits::default(),
        &mut || true,
    )
    .unwrap();
    assert_eq!(ids, original);
    assert_eq!(
        *source.reads.borrow(),
        vec![visible],
        "successful twin reads only the authorized pattern"
    );
}

#[test]
fn explicitly_wanted_tags_preserve_terminal_objects_without_unfiltering_descendants_or_haves() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let pattern = source.put(ObjectType::Blob, Vec::new());
        let blob = source.put(ObjectType::Blob, b"tagged blob".to_vec());
        let tree = source.tree(&[
            (b"100644", b"file", blob),
            (b"100644", b"patterns", pattern),
        ]);
        let commit = source.commit(tree, &[]);
        let inner = source.put(ObjectType::Tag, tag_bytes(blob, "blob"));
        let outer = source.put(ObjectType::Tag, tag_bytes(inner, "tag"));
        let tree_tag = source.put(ObjectType::Tag, tag_bytes(tree, "tree"));
        let graph = graph(&source, &[commit, outer, tree_tag]);
        for (want, have, initial, filter, expected) in [
            (
                outer,
                vec![commit],
                vec![inner, outer],
                ObjectFilter::SparseObject(pattern),
                BTreeSet::from([inner, outer, blob]),
            ),
            (
                outer,
                vec![blob],
                vec![inner, outer],
                ObjectFilter::SparseObject(pattern),
                BTreeSet::from([inner, outer]),
            ),
            (
                outer,
                vec![outer],
                vec![],
                ObjectFilter::SparseObject(pattern),
                BTreeSet::new(),
            ),
            (
                outer,
                vec![inner],
                vec![outer],
                ObjectFilter::SparseObject(pattern),
                BTreeSet::from([outer]),
            ),
            (
                tree_tag,
                vec![],
                vec![tree_tag, tree, blob, pattern],
                ObjectFilter::SparseObject(pattern),
                BTreeSet::from([tree_tag, tree]),
            ),
            (
                tree_tag,
                vec![],
                vec![tree_tag, tree, blob, pattern],
                ObjectFilter::TreeDepth(0),
                BTreeSet::from([tree_tag, tree]),
            ),
        ] {
            let mut ids = initial;
            sparse_apply(
                &source,
                &graph,
                &mut ids,
                &request(vec![want], have, Some(filter)),
                &PackLimits::default(),
                &mut || true,
            )
            .unwrap();
            assert_eq!(ids.into_iter().collect::<BTreeSet<_>>(), expected);
        }
    }
}

#[test]
fn sparse_every_work_stop_preserves_original_selection_and_bad_loader_metadata_refuses() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let pattern = source.put(ObjectType::Blob, b"**/kept\n".to_vec());
    let kept = source.put(ObjectType::Blob, b"kept".to_vec());
    let tree = source.tree(&[(b"100644", b"kept", kept), (b"100644", b"pattern", pattern)]);
    let commit = source.commit(tree, &[]);
    let graph = graph(&source, &[commit]);
    let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
    let request = request(
        vec![commit],
        vec![],
        Some(ObjectFilter::SparseObject(pattern)),
    );
    let mut polls = 0;
    sparse_apply(
        &source,
        &graph,
        &mut original.clone(),
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
        let mut ids = original.clone();
        let result = sparse_apply(
            &source,
            &graph,
            &mut ids,
            &request,
            &PackLimits::default(),
            &mut || {
                count += 1;
                count != stop
            },
        );
        assert!(
            matches!(result, Err(NodePackMaterializationRefusal::Pack(error)) if matches!(*error, PackWriteError::Pack(PackError::DeadlineExceeded)))
        );
        assert_eq!(
            ids, original,
            "checkpoint {stop} cannot partially install selection"
        );
    }
    let mut ids = original.clone();
    expect_code(
        sparse_apply(
            &source,
            &graph,
            &mut ids,
            &request,
            &PackLimits {
                max_delta_work: polls - 1,
                ..PackLimits::default()
            },
            &mut || true,
        ),
        RefusalCode::ResourceBudgetExceeded,
    );
    assert_eq!(ids, original);
    for (kind, bytes) in [
        (ObjectType::Blob, b"short".to_vec()),
        (ObjectType::Tree, b"**/kept\n".to_vec()),
    ] {
        expect_code(
            engine::apply_selection_with_sparse(
                &graph.objects,
                &graph.facts,
                &mut ids,
                &request,
                &PackLimits::default(),
                &mut |_, _| Ok((kind, bytes.clone())),
                &mut || true,
            ),
            RefusalCode::EvidenceInvalid,
        );
        assert_eq!(ids, original);
    }
}

#[test]
fn sparse_native_git_fetch_lazy_recovery_and_retention_survive_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            config,
            public,
            private,
            ancestor,
            visible,
            ..
        } = fixture_with_public_body(format, b"public\n".to_vec());
        delete_private(&node, private);
        let pattern = git_object_id(format, GitObjectKind::Blob, b"public\n");
        let common = git_object_id(format, GitObjectKind::Blob, b"common ancestor body");
        let ancestor_tree = git_object_id(
            format,
            GitObjectKind::Tree,
            &tree_bytes(&[(b"100644", b"common", common)]),
        );
        let expected = visible
            .iter()
            .filter(|id| **id != common)
            .map(|id| node.read_git_object(*id).unwrap().payload().to_vec())
            .collect::<BTreeSet<_>>();
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let filter = format!("sparse:oid={pattern}");
        for version in [0, 1, 2] {
            let (returned, result, response) =
                exchange_filtered(node, version, &[public], None, Some(&filter), false);
            node = returned;
            assert!(result.is_ok(), "{format:?} v{version}: {result:?}");
            assert_eq!(bodies(&response, version, format), expected);
            let incremental = visible
                .iter()
                .filter(|id| ![common, ancestor, ancestor_tree].contains(id))
                .map(|id| node.read_git_object(*id).unwrap().payload().to_vec())
                .collect::<BTreeSet<_>>();
            let (returned, result, response) = exchange_filtered(
                node,
                version,
                &[public],
                Some(ancestor),
                Some(&filter),
                false,
            );
            node = returned;
            assert!(result.is_ok(), "incremental {result:?}");
            assert_eq!(bodies(&response, version, format), incremental);
            let (returned, result, response) =
                exchange_filtered(node, version, &[common], Some(public), Some(&filter), false);
            node = returned;
            assert!(result.is_ok(), "lazy {result:?}");
            assert_eq!(
                bodies(&response, version, format),
                BTreeSet::from([b"common ancestor body".to_vec()])
            );
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

#[test]
fn sparse_native_fetch_of_annotated_blob_tag_keeps_its_user_given_target() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            private,
            ..
        } = fixture_with_public_body(format, Vec::new());
        delete_private(&node, private);
        let pattern = git_object_id(format, GitObjectKind::Blob, b"");
        let blob = git_object_id(format, GitObjectKind::Blob, b"common ancestor body");
        let (inner, outer, _) = publish_typed_tag_fixture(&node, blob, "blob");
        let expected = [inner, outer, blob]
            .into_iter()
            .map(|id| node.read_git_object(id).unwrap().payload().to_vec())
            .collect::<BTreeSet<_>>();
        for version in [0, 1, 2] {
            let (returned, result, response) = exchange_filtered(
                node,
                version,
                &[outer],
                None,
                Some(&format!("sparse:oid={pattern}")),
                false,
            );
            node = returned;
            assert!(result.is_ok(), "{format:?} v{version}: {result:?}");
            assert_eq!(bodies(&response, version, format), expected);
        }
        node.shutdown().unwrap();
    }
}

fn http_fetch(
    node: &OneNode,
    version: u8,
    want: GitOid,
    filter: &str,
    depth: Option<u32>,
) -> Result<Vec<u8>, NodeSmartHttpRefusal> {
    let mut packets = Vec::new();
    if version == 2 {
        packets.extend([
            Packet::Data(b"command=fetch\n".to_vec()),
            Packet::Data(format!("object-format={}\n", node.object_format.as_str()).into_bytes()),
            Packet::Delimiter,
        ]);
    }
    packets.push(Packet::Data(
        format!("want {want}{}\n", if version == 2 { "" } else { " filter" }).into_bytes(),
    ));
    packets.push(Packet::Data(format!("filter {filter}\n").into_bytes()));
    if let Some(depth) = depth {
        packets.push(Packet::Data(format!("deepen {depth}\n").into_bytes()));
    }
    if version != 2 {
        packets.push(Packet::Flush);
    }
    packets.push(Packet::Data(b"done\n".to_vec()));
    if version == 2 {
        packets.push(Packet::Flush);
    }
    let body = encode_packets(&packets, &WireLimits::default()).unwrap();
    let head = format!(
        "POST {}/git-upload-pack HTTP/1.1\r\nHost: loopback\r\nGit-Protocol: version={version}\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\n\r\n",
        String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes()),
        body.len()
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut response = Vec::new();
    node.smart_http_upload_stream_in(
        &request,
        &mut Cursor::new(body),
        WireLimits::default(),
        HttpLimits::default(),
        1024 * 1024,
        &mut || true,
        &mut response,
    )?;
    let boundary = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
    let mut decoded = Vec::new();
    let mut offset = boundary;
    while offset < response.len() {
        let step = decoder.push(&response[offset..]).unwrap();
        assert!(step.consumed > 0);
        offset += step.consumed;
        decoded.extend_from_slice(step.data);
    }
    decoder.finish().unwrap();
    Ok(decoded)
}

#[test]
fn sparse_native_http_shallow_and_combined_requests_use_the_same_selected_graph() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            public,
            private,
            visible,
            ..
        } = fixture_with_public_body(format, b"public\n".to_vec());
        delete_private(&node, private);
        let pattern = git_object_id(format, GitObjectKind::Blob, b"public\n");
        let public_tree = git_object_id(
            format,
            GitObjectKind::Tree,
            &tree_bytes(&[
                (b"100644", b"public", pattern),
                (b"160000", b"submodule", private),
            ]),
        );
        for version in [0, 1, 2] {
            let sparse = format!("sparse:oid={pattern}");
            let shallow = http_fetch(&node, version, public, &sparse, Some(1)).unwrap();
            let expected: BTreeSet<Vec<u8>> = [public, public_tree, pattern]
                .into_iter()
                .map(|id| node.read_git_object(id).unwrap().payload().to_vec())
                .collect();
            assert_eq!(bodies(&shallow, version, format), expected);
            let combined = http_fetch(
                &node,
                version,
                public,
                &format!("combine:{sparse}+blob:none"),
                None,
            )
            .unwrap();
            let expected: BTreeSet<Vec<u8>> = visible
                .iter()
                .filter_map(|id| {
                    let object = node.read_git_object(*id).unwrap();
                    (object.envelope().object_kind() != fgit_object_fabric::ObjectKind::Blob)
                        .then(|| object.payload().to_vec())
                })
                .collect();
            assert_eq!(bodies(&combined, version, format), expected);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn sparse_hidden_missing_nonblob_and_unsupported_patterns_emit_opaque_refusals_without_pack() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            public,
            private,
            private_blob,
            ..
        } = fixture_with_public_body(format, b"[[:alpha:]]\n".to_vec());
        delete_private(&node, private);
        let unsupported = git_object_id(format, GitObjectKind::Blob, b"[[:alpha:]]\n");
        let missing = git_object_id(format, GitObjectKind::Blob, b"unstored pattern");
        for version in [0, 2] {
            for id in [private_blob, missing, public, unsupported] {
                let (returned, result, response) = exchange_filtered(
                    node,
                    version,
                    &[public],
                    None,
                    Some(&format!("sparse:oid={id}")),
                    false,
                );
                node = returned;
                assert!(
                    matches!(result, Err(NodeGitDaemonServeRefusal::Pack(error)) if matches!(*error, NodePackMaterializationRefusal::UnsupportedFetch(_)))
                );
                assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
                let text = String::from_utf8_lossy(&response);
                assert!(text.contains("ERR unsupported fetch feature:"), "{text}");
                assert!(
                    !text.contains(&private_blob.to_string())
                        && !text.contains(&missing.to_string())
                );
                assert!(
                    !text.contains("[[:alpha:]]"),
                    "pattern bytes are not reflected"
                );
            }
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn sparse_preflight_cannot_replace_a_cancelled_original_database_context() {
    let Fixture {
        scratch: _scratch,
        node,
        public,
        private,
        ..
    } = fixture_with_public_body(GitHashAlgorithm::Sha1, b"public\n".to_vec());
    delete_private(&node, private);
    let context = node.request_context();
    let head = node
        .runtime()
        .block_on(node.materialize_admission_in(&context))
        .unwrap();
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::DEFAULT,
    );
    let scope = node
        .prepare_visible_upload_pack(&context, &head, &WireLimits::default(), &deadline)
        .unwrap();
    let pack_context = node.session_pack_materialization_context(&deadline);
    let pattern = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"public\n");
    let fetch = request(
        vec![public],
        vec![],
        Some(ObjectFilter::SparseObject(pattern)),
    );
    context.cancel();
    let result = node.prepare_upload_pack_selection(
        &head,
        &scope,
        &fetch,
        &deadline,
        &pack_context,
        context.authority(),
        &Cell::new(None),
        &mut || true,
    );
    assert!(
        matches!(result, Err(NodePackMaterializationRefusal::Pack(error)) if matches!(*error, PackWriteError::Pack(PackError::DeadlineExceeded)))
    );
    assert_eq!(
        deadline
            .shared
            .selected_upload_bytes
            .load(Ordering::Relaxed),
        0
    );
    node.shutdown().unwrap();
}

#[test]
#[ignore = "requires source/binary-verified Git 2.54.0 and Bubblewrap via FGIT_ORACLE_ROOT"]
fn pinned_git_sparse_clone_records_promisor_and_lazily_recovers_omitted_blob() {
    use super::super::partial_oracle::{checked, command, inventory, live_client};
    let oracle =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/oracle/oracle.sh");
    let run = std::process::Command::new(&oracle)
        .args(["create-run", "git-2.54.0", "sparse-clone-node"])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "pinned oracle unavailable: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let run = String::from_utf8(run.stdout).unwrap().trim().to_owned();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            public: _,
            private,
            visible,
            ..
        } = fixture_with_public_body(format, b"public\n".to_vec());
        delete_private(&node, private);
        let pattern = git_object_id(format, GitObjectKind::Blob, b"public\n");
        let omitted = git_object_id(format, GitObjectKind::Blob, b"common ancestor body");
        let expected = visible
            .iter()
            .filter(|id| **id != omitted)
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let repository =
            String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        for version in ["0", "2"] {
            let client = format!("sparse-{}-{version}", format.as_str());
            let (returned, _) = live_client(
                node,
                &listener,
                command(
                    &run,
                    "clone",
                    &client,
                    &[
                        &endpoint,
                        &repository,
                        version,
                        &format!("sparse:oid={pattern}"),
                    ],
                ),
            );
            node = returned;
            assert_eq!(inventory(&run, &client), expected);
            let packs = PathBuf::from(&run)
                .join("work")
                .join(&client)
                .join(".git/objects/pack");
            assert!(std::fs::read_dir(packs).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "promisor")
            }));
            checked(command(&run, "fsck", &client, &[]));
            let (returned, output) = live_client(
                node,
                &listener,
                command(
                    &run,
                    "read",
                    &client,
                    &[&endpoint, &repository, version, &omitted.to_string()],
                ),
            );
            node = returned;
            assert_eq!(output.stdout, b"common ancestor body");
            assert_eq!(
                inventory(&run, &client),
                visible
                    .iter()
                    .map(ToString::to_string)
                    .collect::<BTreeSet<_>>()
            );
        }
        node.shutdown().unwrap();
    }
}
