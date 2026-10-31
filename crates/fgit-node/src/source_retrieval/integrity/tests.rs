use super::*;
use crate::NodeConfig;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, TenantId};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-node-graph-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn setup(format: GitHashAlgorithm) -> (Scratch, OneNode) {
    let scratch = Scratch::new();
    let (node, _) = OneNode::init(
        NodeConfig::new(
            scratch.0.join("node"),
            TenantId::from_bytes([0x61; 16]),
            RepositoryId::from_bytes([0x62; 16]),
        )
        .with_object_format(format),
    )
    .unwrap();
    (scratch, node)
}
fn put(node: &OneNode, kind: ObjectKind, body: Vec<u8>) -> GitOid {
    node.put_git_object(kind, body).unwrap().identity()
}
fn commit(tree: GitOid) -> Vec<u8> {
    format!("tree {tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nfixture\n").into_bytes()
}
fn valid(node: &OneNode) -> (GitOid, GitOid, GitOid) {
    let blob = put(node, ObjectKind::Blob, b"verified graph body".to_vec());
    let mut body = b"100644 file\0".to_vec();
    body.extend_from_slice(blob.as_bytes());
    let tree = put(node, ObjectKind::Tree, body);
    (blob, tree, put(node, ObjectKind::Commit, commit(tree)))
}

/// Fault injection at the existing producer-validated admission seam, NOT at
/// the graph checker. This intentionally lets a faulty producer supply a bad
/// graph while all object bytes, authority bodies and commitments stay real.
/// Production imports must do their normal quarantine validation first.
fn publish(node: &OneNode, root: GitOid, objects: BTreeSet<GitOid>) {
    let request = node.request_context();
    let format = node.object_format;
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: u32::try_from(objects.len()).unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old: zero,
            new: root,
            ref_name: b"refs/heads/main".to_vec(),
        }],
        &receipt,
        closure,
    )
    .unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x63; 16]),
        idempotency_key: IdempotencyKey::new(b"graph-integrity-fixture".to_vec()).unwrap(),
        object_format: format,
    };
    let result = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}
fn run(node: &OneNode, query: GraphAuditQuery) -> Result<SelectedGraphAudit, GraphAuditRefusal> {
    node.runtime()
        .block_on(node.audit_selected_object_graph_local_in(&node.request_context(), query))
}

#[test]
fn real_fabric_graphs_and_source_receipts_cover_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut node) = setup(format);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (blob, tree, root) = valid(&node);
        publish(&node, root, BTreeSet::from([blob, tree, root]));
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();
        let report = run(&node, GraphAuditQuery::default()).unwrap();
        assert_eq!(
            (
                report.graph().objects,
                report.graph().references,
                report.graph().local_edges
            ),
            (3, 1, 2)
        );
        assert_eq!(report.graph().external_gitlinks, 0);
        assert_eq!(report.repository_id(), node.repository_id());
        assert_eq!(
            report.repository_incarnation_id(),
            node.repository_incarnation_id()
        );
        let pinned = run(
            &node,
            GraphAuditQuery {
                expected_head: Some(report.head()),
                expected_generation: Some(report.generation()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(pinned.graph(), report.graph());
        assert_eq!(pinned.closure_root(), report.closure_root());
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        fn require_send(value: impl Send) {
            drop(value);
        }
        let request = node.request_context();
        require_send(
            node.audit_selected_object_graph_local_in(&request, GraphAuditQuery::default()),
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn valid_commitment_bytes_do_not_prove_local_connectivity_or_target_kinds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for wrong_kind in [false, true] {
            let (_scratch, mut node) = setup(format);
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let target = put(
                &node,
                if wrong_kind {
                    ObjectKind::Blob
                } else {
                    ObjectKind::Tree
                },
                Vec::new(),
            );
            let root = put(&node, ObjectKind::Commit, commit(target));
            let selected = if wrong_kind {
                BTreeSet::from([target, root])
            } else {
                BTreeSet::from([root])
            };
            publish(&node, root, selected);
            // Both objects independently verify in real storage, including the
            // target excluded from authority's selected set in the missing case.
            node.read_git_object(root).unwrap();
            node.read_git_object(target).unwrap();
            node.runtime().block_on(node.doctor(Some(root))).unwrap();
            let before = node.runtime().block_on(node.read_authority_head()).unwrap();
            // Native commitments can succeed while graph structure fails.
            // Objects-only verification must not silently become a graph parser.
            let integrity = run_objects(&node, GraphAuditQuery::default()).unwrap();
            assert_eq!(integrity.objects(), if wrong_kind { 2 } else { 1 });
            let result = run(&node, GraphAuditQuery::default());
            if wrong_kind {
                assert!(
                    matches!(result, Err(GraphAuditRefusal::Graph(GraphRefusal::TargetKind {
                    target: id, expected: ObjectKind::Tree, actual: ObjectKind::Blob,
                })) if id == target)
                );
            } else {
                assert!(
                    matches!(result, Err(GraphAuditRefusal::Graph(GraphRefusal::MissingTarget {
                    source: Some(source), target: id,
                })) if source == root && id == target)
                );
            }
            assert_eq!(
                node.runtime().block_on(node.read_authority_head()).unwrap(),
                before
            );
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn unreachable_admitted_objects_are_not_skipped_by_a_current_ref_walk() {
    let (_scratch, mut node) = setup(GitHashAlgorithm::Sha1);
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let (blob, tree, root) = valid(&node);
    let bad_history = put(&node, ObjectKind::Commit, commit(blob));
    publish(&node, root, BTreeSet::from([blob, tree, root, bad_history]));
    assert!(matches!(run(&node, GraphAuditQuery::default()),
        Err(GraphAuditRefusal::Graph(GraphRefusal::TargetKind { target, expected: ObjectKind::Tree, .. })) if target == blob));
    node.shutdown().unwrap();
}

#[test]
fn source_fences_precede_a_faulty_graph_and_runtime_cancellation_precedes_reads() {
    let (_scratch, mut node) = setup(GitHashAlgorithm::Sha1);
    assert!(matches!(
        run(&node, GraphAuditQuery::default()),
        Err(GraphAuditRefusal::Cell(_))
    ));
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let genesis = run(&node, GraphAuditQuery::default()).unwrap();
    let blob = put(&node, ObjectKind::Blob, Vec::new());
    let root = put(&node, ObjectKind::Commit, commit(blob));
    publish(&node, root, BTreeSet::from([blob, root]));
    assert!(matches!(
        run(
            &node,
            GraphAuditQuery {
                expected_head: Some(genesis.head()),
                ..Default::default()
            }
        ),
        Err(GraphAuditRefusal::ExpectedHead)
    ));
    assert!(matches!(
        run(
            &node,
            GraphAuditQuery {
                expected_generation: Some(genesis.generation()),
                ..Default::default()
            }
        ),
        Err(GraphAuditRefusal::ExpectedGeneration { .. })
    ));
    let request = node.request_context();
    request.cancel();
    assert!(matches!(
        node.runtime().block_on(
            node.audit_selected_object_graph_local_in(&request, GraphAuditQuery::default())
        ),
        Err(GraphAuditRefusal::Cancelled { .. })
    ));
    node.shutdown().unwrap();
}

#[test]
fn exact_graph_limits_and_invalid_timeouts_never_turn_into_partial_success() {
    let (_scratch, mut node) = setup(GitHashAlgorithm::Sha256);
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let (blob, tree, root) = valid(&node);
    publish(&node, root, BTreeSet::from([blob, tree, root]));
    let report = run(&node, GraphAuditQuery::default()).unwrap();
    let limits = GraphLimits {
        max_objects: 3,
        max_references: 1,
        max_edges: 2,
        max_payload_bytes: report.graph().payload_bytes,
        ..Default::default()
    };
    run(
        &node,
        GraphAuditQuery {
            limits,
            ..Default::default()
        },
    )
    .unwrap();
    for limits in [
        GraphLimits {
            max_objects: 2,
            ..limits
        },
        GraphLimits {
            max_references: 0,
            ..limits
        },
        GraphLimits {
            max_edges: 1,
            ..limits
        },
        GraphLimits {
            max_payload_bytes: report.graph().payload_bytes - 1,
            ..limits
        },
    ] {
        assert!(
            run(
                &node,
                GraphAuditQuery {
                    limits,
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
    for timeout in [Duration::ZERO, Duration::from_secs(3601)] {
        assert!(matches!(
            run(
                &node,
                GraphAuditQuery {
                    timeout,
                    ..Default::default()
                }
            ),
            Err(GraphAuditRefusal::InvalidTimeout)
        ));
    }
    node.shutdown().unwrap();
}

#[test]
fn final_revalidation_rejects_a_real_authority_successor() {
    let (_scratch, mut node) = setup(GitHashAlgorithm::Sha1);
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let before = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    revalidate_head(&before, &before).unwrap();
    let (blob, tree, root) = valid(&node);
    publish(&node, root, BTreeSet::from([blob, tree, root]));
    let after = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    assert!(matches!(
        revalidate_head(&before, &after),
        Err(GraphAuditRefusal::SnapshotChanged)
    ));
    revalidate_head(&after, &after).unwrap();
    node.shutdown().unwrap();
}

const STREAMED_BLOB_BYTES: usize = 5 * 64 * 1024 + 17;

fn large_graph(node: &OneNode, message_padding: usize) -> (GitOid, GitOid, GitOid) {
    let blob = put(
        node,
        ObjectKind::Blob,
        (0..STREAMED_BLOB_BYTES)
            .map(|index| (index % 251) as u8)
            .collect(),
    );
    let mut body = b"100644 large\0".to_vec();
    body.extend_from_slice(blob.as_bytes());
    let tree = put(node, ObjectKind::Tree, body);
    let mut body = commit(tree);
    body.resize(body.len() + message_padding, b'x');
    (blob, tree, put(node, ObjectKind::Commit, body))
}

fn run_objects(
    node: &OneNode,
    query: GraphAuditQuery,
) -> Result<SelectedObjectIntegrityAudit, GraphAuditRefusal> {
    node.runtime()
        .block_on(node.audit_selected_object_integrity_local_in(&node.request_context(), query))
}

fn run_mode(
    node: &OneNode,
    query: GraphAuditQuery,
    verify_graph: bool,
) -> Result<(usize, u64), GraphAuditRefusal> {
    if verify_graph {
        run(node, query).map(|report| (report.graph().objects, report.graph().payload_bytes))
    } else {
        run_objects(node, query).map(|report| (report.objects(), report.payload_bytes()))
    }
}

fn streaming_query() -> GraphAuditQuery {
    GraphAuditQuery {
        max_blob_bytes: Some(STREAMED_BLOB_BYTES as u64),
        limits: GraphLimits {
            max_object_bytes: 2048,
            ..Default::default()
        },
        ..Default::default()
    }
}

// Test-only fault location. Production inspection uses exactly the selected
// native IDs, never a filesystem scan as a membership or retention decision.
fn body_path(root: &std::path::Path, oid: GitOid) -> PathBuf {
    let mut pending = vec![root.to_owned()];
    let mut found = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name().to_str() == Some(oid.to_string().as_str())
            {
                assert!(fs::read(entry.path()).unwrap().starts_with(b"FGOB"));
                found.push(entry.path());
            }
        }
    }
    assert_eq!(found.len(), 1, "expected one actual native body");
    found.pop().unwrap()
}

fn assert_fabric_refusal(
    result: Result<(usize, u64), GraphAuditRefusal>,
    expected_oid: GitOid,
    expected: impl FnOnce(&StoreRefusal) -> bool,
) {
    match result {
        Err(GraphAuditRefusal::Object { oid, cause }) => {
            assert_eq!(oid, expected_oid);
            match cause.as_ref() {
                NodeRefusal::Fabric(error) => assert!(expected(error), "{error:?}"),
                error => panic!("expected fabric refusal, got {error:?}"),
            }
        }
        result => panic!("expected object refusal, got {result:?}"),
    }
}

#[test]
fn streamed_graph_and_object_receipts_keep_metadata_small_and_total_bytes_exact() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, mut node) = setup(format);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (blob, tree, root) = large_graph(&node, 0);
        publish(&node, root, BTreeSet::from([blob, tree, root]));
        let baseline = run(&node, GraphAuditQuery::default()).unwrap();
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();
        let path = body_path(&scratch.0, blob);
        let original = fs::read(&path).unwrap();
        let config = node
            .service_config
            .clone()
            .with_max_object_bytes(2048)
            .with_selected_pack_blob_limit(STREAMED_BLOB_BYTES);
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        // The new allowance does not turn the ordinary buffered read into a
        // whole-blob allocation path.
        assert!(node.read_git_object(blob).is_err());
        let query = GraphAuditQuery {
            expected_head: Some(baseline.head()),
            expected_generation: Some(baseline.generation()),
            limits: GraphLimits {
                max_payload_bytes: baseline.graph().payload_bytes,
                ..streaming_query().limits
            },
            ..streaming_query()
        };
        let graph = run(&node, query).unwrap();
        assert_eq!(graph.graph(), baseline.graph());
        assert_eq!(graph.closure_root(), baseline.closure_root());
        let objects = run_objects(&node, query).unwrap();
        assert_eq!(objects.repository_id(), node.repository_id());
        assert_eq!(
            objects.repository_incarnation_id(),
            node.repository_incarnation_id()
        );
        assert_eq!(objects.head(), graph.head());
        assert_eq!(objects.generation(), graph.generation());
        assert_eq!(objects.closure_root(), graph.closure_root());
        assert_eq!(objects.objects(), graph.graph().objects);
        assert_eq!(objects.references(), graph.graph().references);
        assert_eq!(objects.payload_bytes(), graph.graph().payload_bytes);

        for verify_graph in [false, true] {
            for (limited, expected) in [
                (
                    GraphAuditQuery {
                        max_blob_bytes: None,
                        ..query
                    },
                    "object bytes",
                ),
                (
                    GraphAuditQuery {
                        max_blob_bytes: Some(STREAMED_BLOB_BYTES as u64 - 1),
                        ..query
                    },
                    "blob bytes",
                ),
                (
                    GraphAuditQuery {
                        limits: GraphLimits {
                            max_payload_bytes: graph.graph().payload_bytes - 1,
                            ..query.limits
                        },
                        ..query
                    },
                    "payload bytes",
                ),
            ] {
                let result = run_mode(&node, limited, verify_graph);
                assert!(
                    matches!(result, Err(GraphAuditRefusal::Graph(GraphRefusal::Limit(name))) if name == expected),
                    "{verify_graph}: {expected}: {result:?}"
                );
            }
        }
        fn require_send(value: impl Send) {
            drop(value);
        }
        let request = node.request_context();
        require_send(node.audit_selected_object_graph_local_in(&request, query));
        require_send(node.audit_selected_object_integrity_local_in(&request, query));
        assert_eq!(fs::read(path).unwrap(), original);
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn a_blob_allowance_never_widens_metadata_or_the_nodes_selected_blob_policy() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut node) = setup(format);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (blob, tree, root) = large_graph(&node, 8192);
        publish(&node, root, BTreeSet::from([blob, tree, root]));
        let baseline = run(&node, GraphAuditQuery::default()).unwrap();
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();
        let config = node
            .service_config
            .clone()
            .with_selected_pack_blob_limit(STREAMED_BLOB_BYTES);
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(config.clone().with_max_object_bytes(2048)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let query = GraphAuditQuery {
            limits: GraphLimits {
                max_object_bytes: 16 * 1024,
                ..Default::default()
            },
            ..streaming_query()
        };
        for verify_graph in [false, true] {
            assert!(matches!(
                run_mode(&node, query, verify_graph),
                Err(GraphAuditRefusal::Graph(GraphRefusal::Limit(
                    "object bytes"
                )))
            ));
        }
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        node.shutdown().unwrap();

        let mut node =
            OneNode::open_existing(config.clone().with_max_object_bytes(16 * 1024)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        for verify_graph in [false, true] {
            assert_eq!(
                run_mode(&node, query, verify_graph).unwrap(),
                (3, baseline.graph().payload_bytes)
            );
            assert!(matches!(
                run_mode(&node, streaming_query(), verify_graph),
                Err(GraphAuditRefusal::Graph(GraphRefusal::Limit(
                    "object bytes"
                )))
            ));
        }
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(
            config
                .with_max_object_bytes(16 * 1024)
                .with_selected_pack_blob_limit(STREAMED_BLOB_BYTES - 1),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        // This envelope fits the independent stored-file policy, but its body
        // is one byte above the node's selected-blob allowance.
        node.git_object_header(blob).unwrap();
        for verify_graph in [false, true] {
            assert!(matches!(
                run_mode(&node, query, verify_graph),
                Err(GraphAuditRefusal::Graph(GraphRefusal::Limit("blob bytes")))
            ));
        }
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn streaming_limits_precede_corrupt_body_work_and_exact_framing_still_refuses() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, mut node) = setup(format);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (blob, tree, root) = large_graph(&node, 0);
        publish(&node, root, BTreeSet::from([blob, tree, root]));
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();
        let path = body_path(&scratch.0, blob);
        let original = fs::read(&path).unwrap();
        let config = node
            .service_config
            .clone()
            .with_max_object_bytes(2048)
            .with_selected_pack_blob_limit(STREAMED_BLOB_BYTES);
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();

        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&path, &damaged).unwrap();
        for verify_graph in [false, true] {
            for (limited, expected) in [
                (
                    GraphAuditQuery {
                        max_blob_bytes: Some(STREAMED_BLOB_BYTES as u64 - 1),
                        ..streaming_query()
                    },
                    "blob bytes",
                ),
                (
                    GraphAuditQuery {
                        limits: GraphLimits {
                            max_payload_bytes: STREAMED_BLOB_BYTES as u64 - 1,
                            ..streaming_query().limits
                        },
                        ..streaming_query()
                    },
                    "payload bytes",
                ),
            ] {
                let result = run_mode(&node, limited, verify_graph);
                assert!(
                    matches!(result, Err(GraphAuditRefusal::Graph(GraphRefusal::Limit(name))) if name == expected),
                    "{verify_graph}: {expected}: {result:?}"
                );
            }
            assert_fabric_refusal(
                run_mode(&node, streaming_query(), verify_graph),
                blob,
                |error| matches!(error, StoreRefusal::PayloadCommitmentMismatch),
            );
        }
        assert_eq!(fs::read(&path).unwrap(), damaged);

        for altered in [
            original[..original.len() - 1].to_vec(),
            [original.as_slice(), b"x"].concat(),
        ] {
            fs::write(&path, &altered).unwrap();
            for verify_graph in [false, true] {
                assert_fabric_refusal(
                    run_mode(&node, streaming_query(), verify_graph),
                    blob,
                    |error| matches!(error, StoreRefusal::MalformedStoredObject),
                );
            }
            assert_eq!(fs::read(&path).unwrap(), altered);
        }
        fs::write(&path, &original).unwrap();
        for verify_graph in [false, true] {
            assert_eq!(
                run_mode(&node, streaming_query(), verify_graph).unwrap().0,
                3
            );
        }
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn checked_stream_progress_keeps_exact_cancellation_and_deadline_causes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut node) = setup(format);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (blob, tree, root) = large_graph(&node, 0);
        publish(&node, root, BTreeSet::from([blob, tree, root]));
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();

        for stop in 0..3 {
            let request = node.request_context();
            let mut checkpoints =
                AuditCheckpoints::new(&request, Instant::now(), Duration::from_secs(5));
            let mut stream = node
                .open_git_blob_stream(blob, STREAMED_BLOB_BYTES as u64)
                .unwrap();
            let mut buffer = vec![0; 64 * 1024];
            let count = read_audit_blob(&mut stream, &mut buffer, &checkpoints).unwrap();
            assert!((1..=buffer.len()).contains(&count));
            assert!(!stream.is_verified());
            if stop == 0 {
                request.cancel();
            } else if stop == 1 {
                // Inject the runtime's typed quota stop after actual file
                // progress, without replacing or renewing this request.
                request
                    .authority()
                    .attached_native_cx()
                    .unwrap()
                    .set_cancel_reason(asupersync::types::CancelReason::poll_quota());
            } else {
                checkpoints.started = Instant::now()
                    .checked_sub(Duration::from_secs(6))
                    .expect("test clock supports a past deadline");
            }
            assert!(matches!(
                read_audit_blob(&mut stream, &mut buffer, &checkpoints),
                Err(StoreRefusal::RuntimeCheckpointRejected)
            ));
            if stop == 1 {
                // A later local cancellation must not erase the first precise
                // runtime cause latched by the chunk reader.
                request.cancel();
            }
            let result = checkpoints.check();
            assert!(
                matches!(
                    (stop, &result),
                    (0, Err(GraphAuditRefusal::Cancelled { exhaustion: None }))
                        | (
                            1,
                            Err(GraphAuditRefusal::Cancelled {
                                exhaustion: Some(Exhaustion::PollQuota)
                            })
                        )
                        | (2, Err(GraphAuditRefusal::Deadline))
                ),
                "{stop}: {result:?}"
            );
            assert!(!stream.is_verified());
        }
        for verify_graph in [false, true] {
            assert_eq!(
                run_mode(&node, streaming_query(), verify_graph).unwrap().0,
                3
            );
        }
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn reference_membership_is_checked_before_body_work_in_both_audit_modes() {
    let (scratch, mut node) = setup(GitHashAlgorithm::Sha256);
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let (blob, tree, root) = valid(&node);
    publish(&node, root, BTreeSet::from([blob, tree, root]));
    let before = node.runtime().block_on(node.read_authority_head()).unwrap();
    let path = body_path(&scratch.0, blob);
    let mut damaged = fs::read(&path).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&path, damaged).unwrap();
    let references = BTreeMap::from([(RefName::try_new(b"refs/heads/main").unwrap(), root)]);
    for verify_graph in [false, true] {
        let result = node.audit_selected_payloads(
            &node.request_context(),
            &BTreeSet::from([blob]),
            &references,
            GraphAuditQuery::default(),
            Instant::now(),
            verify_graph,
        );
        assert!(
            matches!(result, Err(GraphAuditRefusal::Graph(GraphRefusal::MissingTarget {
                source: None, target
            })) if target == root),
            "{verify_graph}: {result:?}"
        );
    }
    assert_eq!(
        node.runtime().block_on(node.read_authority_head()).unwrap(),
        before
    );
    node.shutdown().unwrap();
}
