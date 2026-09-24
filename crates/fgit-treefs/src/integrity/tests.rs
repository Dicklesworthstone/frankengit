use super::*;
use std::fmt::Write as _;

type Objects = BTreeMap<GitOid, (ObjectKind, Vec<u8>)>;

fn put(
    objects: &mut Objects,
    format: GitHashAlgorithm,
    kind: ObjectKind,
    body: impl Into<Vec<u8>>,
) -> GitOid {
    let body = body.into();
    let id = git_object_id(format, kind, &body);
    objects.insert(id, (kind, body));
    id
}
fn tree_body(entries: &[(&[u8], &[u8], GitOid)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (mode, name, oid) in entries {
        body.extend_from_slice(mode);
        body.push(b' ');
        body.extend_from_slice(name);
        body.push(0);
        body.extend_from_slice(oid.as_bytes());
    }
    body
}
fn commit_body(tree: GitOid, parents: &[GitOid]) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents {
        let _ = writeln!(body, "parent {parent}");
    }
    body.push_str("author A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nmessage\n");
    body.into_bytes()
}
fn tag_body(target: GitOid, kind: &str) -> Vec<u8> {
    format!("object {target}\ntype {kind}\ntag v1\n\nmessage\n").into_bytes()
}
fn refs(name: &[u8], oid: GitOid) -> BTreeMap<RefName, GitOid> {
    BTreeMap::from([(RefName::try_new(name).unwrap(), oid)])
}
fn audit(
    objects: &Objects,
    format: GitHashAlgorithm,
    references: &BTreeMap<RefName, GitOid>,
    limits: GraphLimits,
) -> Result<GraphReport, GraphRefusal> {
    let ids = objects.keys().copied().collect();
    let mut audit = ObjectGraphAudit::new(&ids, format, limits, &mut || true)?;
    for (&id, (kind, bytes)) in objects {
        audit.observe(id, *kind, bytes, &mut || true)?;
    }
    audit.finish(references, &mut || true)
}
fn missing(format: GitHashAlgorithm) -> GitOid {
    git_object_id(format, ObjectKind::Blob, b"deliberately absent")
}

#[test]
fn complete_graph_handles_both_native_domains_tag_chains_and_duplicate_parents() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::new();
        let blob = put(
            &mut objects,
            format,
            ObjectKind::Blob,
            b"binary\0\xff".to_vec(),
        );
        let tree = put(
            &mut objects,
            format,
            ObjectKind::Tree,
            tree_body(&[(b"100644", b"file", blob), (b"120000", b"link", blob)]),
        );
        let parent = put(
            &mut objects,
            format,
            ObjectKind::Commit,
            commit_body(tree, &[]),
        );
        let commit = put(
            &mut objects,
            format,
            ObjectKind::Commit,
            commit_body(tree, &[parent, parent]),
        );
        let tag = put(
            &mut objects,
            format,
            ObjectKind::Tag,
            tag_body(commit, "commit"),
        );
        let outer = put(&mut objects, format, ObjectKind::Tag, tag_body(tag, "tag"));
        let mut references = refs(b"refs/heads/main", commit);
        references.extend(refs(b"refs/tags/v1", outer));
        let result = audit(&objects, format, &references, GraphLimits::default()).unwrap();
        assert_eq!(result.objects, 6);
        assert_eq!(result.local_edges, 8);
        assert_eq!(result.external_gitlinks, 0);
        assert_eq!(result.references, 2);
        assert_eq!(
            result.payload_bytes,
            objects
                .values()
                .map(|(_, body)| body.len() as u64)
                .sum::<u64>()
        );
    }
}

#[test]
fn external_gitlinks_neither_require_nor_typecheck_local_objects_with_the_same_id() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::new();
        let blob = put(&mut objects, format, ObjectKind::Blob, Vec::new());
        let tree = put(
            &mut objects,
            format,
            ObjectKind::Tree,
            tree_body(&[
                (b"0160000", b"outside", missing(format)),
                (b"160000", b"same-id-as-local-blob", blob),
                (b"0100664", b"historical-mode", blob),
            ]),
        );
        let result = audit(
            &objects,
            format,
            &refs(b"refs/tags/tree", tree),
            GraphLimits::default(),
        )
        .unwrap();
        assert_eq!((result.local_edges, result.external_gitlinks), (1, 2));
        assert_eq!(
            audit(
                &objects,
                format,
                &BTreeMap::new(),
                GraphLimits {
                    max_edges: 2,
                    ..Default::default()
                }
            ),
            Err(GraphRefusal::Limit("edges"))
        );
    }
}

#[test]
fn every_kind_of_local_edge_requires_membership_in_the_selected_set() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let absent = missing(format);
        for (kind, body) in [
            (ObjectKind::Commit, commit_body(absent, &[])),
            (ObjectKind::Tree, tree_body(&[(b"100644", b"file", absent)])),
            (ObjectKind::Tree, tree_body(&[(b"40000", b"dir", absent)])),
            (ObjectKind::Tag, tag_body(absent, "blob")),
        ] {
            let mut objects = Objects::new();
            let source = put(&mut objects, format, kind, body);
            assert_eq!(
                audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
                Err(GraphRefusal::MissingTarget {
                    source: Some(source),
                    target: absent
                })
            );
        }
        let mut objects = Objects::new();
        let tree = put(&mut objects, format, ObjectKind::Tree, Vec::new());
        let source = put(
            &mut objects,
            format,
            ObjectKind::Commit,
            commit_body(tree, &[absent]),
        );
        assert_eq!(
            audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
            Err(GraphRefusal::MissingTarget {
                source: Some(source),
                target: absent
            })
        );
    }
}

#[test]
fn all_local_edges_and_branch_roots_require_the_declared_object_kind() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (kind, expected, make) in [
            (ObjectKind::Commit, ObjectKind::Tree, 0),
            (ObjectKind::Tree, ObjectKind::Tree, 1),
            (ObjectKind::Tag, ObjectKind::Commit, 2),
        ] {
            let mut objects = Objects::new();
            let blob = put(&mut objects, format, ObjectKind::Blob, Vec::new());
            let body = match make {
                0 => commit_body(blob, &[]),
                1 => tree_body(&[(b"40000", b"directory", blob)]),
                _ => tag_body(blob, "commit"),
            };
            put(&mut objects, format, kind, body);
            assert_eq!(
                audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
                Err(GraphRefusal::TargetKind {
                    target: blob,
                    expected,
                    actual: ObjectKind::Blob
                })
            );
        }
        let mut objects = Objects::new();
        let tree = put(&mut objects, format, ObjectKind::Tree, Vec::new());
        put(
            &mut objects,
            format,
            ObjectKind::Tree,
            tree_body(&[(b"120000", b"link", tree)]),
        );
        assert_eq!(
            audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
            Err(GraphRefusal::TargetKind {
                target: tree,
                expected: ObjectKind::Blob,
                actual: ObjectKind::Tree
            })
        );
        objects.retain(|id, _| *id == tree);
        let blob = put(&mut objects, format, ObjectKind::Blob, Vec::new());
        put(
            &mut objects,
            format,
            ObjectKind::Commit,
            commit_body(tree, &[blob]),
        );
        assert_eq!(
            audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
            Err(GraphRefusal::TargetKind {
                target: blob,
                expected: ObjectKind::Commit,
                actual: ObjectKind::Blob
            })
        );
        objects.retain(|id, _| *id == blob);
        assert!(
            audit(
                &objects,
                format,
                &refs(b"refs/tags/blob", blob),
                GraphLimits::default()
            )
            .is_ok()
        );
        assert_eq!(
            audit(
                &objects,
                format,
                &refs(b"refs/heads/main", blob),
                GraphLimits::default()
            ),
            Err(GraphRefusal::TargetKind {
                target: blob,
                expected: ObjectKind::Commit,
                actual: ObjectKind::Blob
            })
        );
    }
}

#[test]
fn ambiguous_commit_and_tag_references_cannot_hide_edges() {
    let format = GitHashAlgorithm::Sha1;
    let mut base = Objects::new();
    let tree = put(&mut base, format, ObjectKind::Tree, Vec::new());
    for (kind, body) in [
        (ObjectKind::Commit, b"author A\n\nmissing tree".to_vec()),
        (
            ObjectKind::Commit,
            format!("tree {tree}\ntree {tree}\n\n").into_bytes(),
        ),
        (
            ObjectKind::Commit,
            format!("tree {tree}\n continuation\n\n").into_bytes(),
        ),
        (
            ObjectKind::Commit,
            format!("tree {tree}\nparent {}\n\n", "01".repeat(32)).into_bytes(),
        ),
        (
            ObjectKind::Tag,
            format!("object {tree}\nobject {tree}\ntype tree\n\n").into_bytes(),
        ),
        (
            ObjectKind::Tag,
            format!("object {tree}\ntype tree\ntype blob\n\n").into_bytes(),
        ),
    ] {
        let mut objects = base.clone();
        let id = put(&mut objects, format, kind, body);
        assert!(
            matches!(audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
            Err(GraphRefusal::Malformed { object, .. }) if object == id)
        );
    }
}

#[test]
fn unsupported_tree_modes_and_null_gitlinks_are_refused_not_silently_skipped() {
    let format = GitHashAlgorithm::Sha1;
    for mode in [b"20000".as_slice(), b"170000", b"777777777777777777777"] {
        let mut objects = Objects::new();
        let id = put(
            &mut objects,
            format,
            ObjectKind::Tree,
            tree_body(&[(mode, b"bad", missing(format))]),
        );
        assert_eq!(
            audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
            Err(GraphRefusal::InvalidTreeMode(id))
        );
    }
    let zero = GitOid::from_hex(format, &"0".repeat(40)).unwrap();
    let mut objects = Objects::new();
    put(
        &mut objects,
        format,
        ObjectKind::Tree,
        tree_body(&[(b"160000", b"bad", zero)]),
    );
    assert_eq!(
        audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
        Err(GraphRefusal::ObjectFormat(zero))
    );
}

#[test]
fn old_unordered_trees_and_unusual_nonreference_headers_are_not_normalized() {
    let format = GitHashAlgorithm::Sha1;
    let mut objects = Objects::new();
    let blob = put(&mut objects, format, ObjectKind::Blob, b"text".to_vec());
    let tree = put(
        &mut objects,
        format,
        ObjectKind::Tree,
        tree_body(&[(b"100644", b"z", blob), (b"100644", b"a", blob)]),
    );
    let commit = put(
        &mut objects,
        format,
        ObjectKind::Commit,
        format!("tree {tree}\ngpgsig opaque\n continued signature\n\nmessage\0payload")
            .into_bytes(),
    );
    assert!(
        audit(
            &objects,
            format,
            &refs(b"refs/heads/legacy", commit),
            GraphLimits::default()
        )
        .is_ok()
    );
}

#[test]
fn observation_order_incomplete_reads_and_ignored_errors_cannot_yield_a_report() {
    let format = GitHashAlgorithm::Sha1;
    let mut objects = Objects::new();
    let id = put(&mut objects, format, ObjectKind::Blob, b"real".to_vec());
    let ids = objects.keys().copied().collect();
    let mut state =
        ObjectGraphAudit::new(&ids, format, GraphLimits::default(), &mut || true).unwrap();
    assert_eq!(
        state.observe(id, ObjectKind::Blob, b"wrong", &mut || true),
        Err(GraphRefusal::IdentityMismatch(id))
    );
    assert_eq!(
        state.observe(id, ObjectKind::Blob, b"real", &mut || true),
        Err(GraphRefusal::Failed)
    );
    assert_eq!(
        state.finish(&BTreeMap::new(), &mut || true),
        Err(GraphRefusal::Failed)
    );
    let state = ObjectGraphAudit::new(&ids, format, GraphLimits::default(), &mut || true).unwrap();
    assert_eq!(
        state.finish(&BTreeMap::new(), &mut || true),
        Err(GraphRefusal::Incomplete)
    );
    let mut state =
        ObjectGraphAudit::new(&ids, format, GraphLimits::default(), &mut || true).unwrap();
    assert_eq!(
        state.observe(missing(format), ObjectKind::Blob, b"real", &mut || true),
        Err(GraphRefusal::ObjectOrder)
    );
}

#[test]
fn missing_root_and_cross_format_selections_are_not_authorized_by_storage_existence() {
    let format = GitHashAlgorithm::Sha1;
    assert_eq!(
        audit(
            &Objects::new(),
            format,
            &refs(b"refs/tags/missing", missing(format)),
            GraphLimits::default()
        ),
        Err(GraphRefusal::MissingTarget {
            source: None,
            target: missing(format)
        })
    );
    let foreign = missing(GitHashAlgorithm::Sha256);
    assert!(
        matches!(ObjectGraphAudit::new(&BTreeSet::from([foreign]), format, GraphLimits::default(), &mut || true),
        Err(GraphRefusal::ObjectFormat(id)) if id == foreign)
    );
}

#[test]
fn exact_object_edge_reference_and_byte_limits_have_n_plus_one_refusal_twins() {
    let format = GitHashAlgorithm::Sha1;
    let mut objects = Objects::new();
    let blob = put(&mut objects, format, ObjectKind::Blob, vec![1; 8]);
    let tree = put(
        &mut objects,
        format,
        ObjectKind::Tree,
        tree_body(&[(b"100644", b"a", blob)]),
    );
    let references = refs(b"refs/tags/tree", tree);
    let payload = objects.values().map(|(_, b)| b.len() as u64).sum::<u64>();
    let largest = objects.values().map(|(_, b)| b.len()).max().unwrap();
    let limits = GraphLimits {
        max_objects: 2,
        max_edges: 1,
        max_references: 1,
        max_payload_bytes: payload,
        max_object_bytes: largest,
    };
    audit(&objects, format, &references, limits).unwrap();
    for bounded in [
        GraphLimits {
            max_objects: 1,
            ..limits
        },
        GraphLimits {
            max_edges: 0,
            ..limits
        },
        GraphLimits {
            max_references: 0,
            ..limits
        },
        GraphLimits {
            max_payload_bytes: payload - 1,
            ..limits
        },
        GraphLimits {
            max_object_bytes: largest - 1,
            ..limits
        },
    ] {
        assert!(audit(&objects, format, &references, bounded).is_err());
    }
}

#[test]
fn cancellation_at_every_checkpoint_prevents_completion() {
    let format = GitHashAlgorithm::Sha256;
    let mut objects = Objects::new();
    let blob = put(&mut objects, format, ObjectKind::Blob, b"blob".to_vec());
    let tree = put(
        &mut objects,
        format,
        ObjectKind::Tree,
        tree_body(&[(b"100644", b"file", blob)]),
    );
    let references = refs(b"refs/tags/tree", tree);
    let run = |stop: usize| {
        let mut probes = 0;
        let mut live = || {
            probes += 1;
            probes < stop
        };
        let result = (|| {
            let mut state = ObjectGraphAudit::new(
                &objects.keys().copied().collect(),
                format,
                GraphLimits::default(),
                &mut live,
            )?;
            for (&id, (kind, body)) in &objects {
                state.observe(id, *kind, body, &mut live)?;
            }
            state.finish(&references, &mut live)
        })();
        (result, probes)
    };
    let (result, total) = run(usize::MAX);
    result.unwrap();
    for stop in 1..=total {
        assert_eq!(
            run(stop).0,
            Err(GraphRefusal::Cancelled),
            "checkpoint {stop}"
        );
    }
}

#[test]
fn iterative_cycle_walk_handles_deep_graphs_cycles_and_disconnected_components() {
    // Structural fault seam: cryptographic object identities are independently
    // tested above. Arbitrary cycles cannot be cheaply constructed as real Git
    // bodies, so this exercises the SAME private production walk with ordinals.
    let format = GitHashAlgorithm::Sha1;
    let id = missing(format);
    let count = 20_000;
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for index in 0..count {
        let start = edges.len();
        if index + 1 < count {
            edges.push(Edge {
                target: index + 1,
                expected: ObjectKind::Commit,
            });
        }
        nodes.push(Node {
            id,
            kind: Some(ObjectKind::Commit),
            start,
            end: edges.len(),
        });
    }
    verify_acyclic(&nodes, &edges, &mut || true).unwrap();
    edges.push(Edge {
        target: 0,
        expected: ObjectKind::Commit,
    });
    nodes.last_mut().unwrap().end = edges.len();
    assert_eq!(
        verify_acyclic(&nodes, &edges, &mut || true),
        Err(GraphRefusal::Cycle(id))
    );
    nodes.last_mut().unwrap().end -= 1;
    edges.pop();
    let index = nodes.len();
    nodes.push(Node {
        id,
        kind: Some(ObjectKind::Tree),
        start: edges.len(),
        end: edges.len() + 1,
    });
    edges.push(Edge {
        target: index,
        expected: ObjectKind::Tree,
    });
    assert_eq!(
        verify_acyclic(&nodes, &edges, &mut || true),
        Err(GraphRefusal::Cycle(id))
    );
}

#[test]
fn parser_budget_exhaustion_is_not_reported_as_object_corruption() {
    let format = GitHashAlgorithm::Sha1;
    let mut objects = Objects::new();
    let tree = put(&mut objects, format, ObjectKind::Tree, Vec::new());
    let mut body = format!("tree {tree}\n");
    for _ in 0..=ParseLimits::default().max_header_lines {
        body.push_str("extra value\n");
    }
    body.push_str("\nmessage\n");
    put(&mut objects, format, ObjectKind::Commit, body.into_bytes());
    assert_eq!(
        audit(&objects, format, &BTreeMap::new(), GraphLimits::default()),
        Err(GraphRefusal::Limit("header structure"))
    );
}
