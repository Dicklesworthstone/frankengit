use super::*;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use fgit_admission::{AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root, validate_source_import};
use fgit_authority::IdempotencyKey;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, TenantId};
use crate::NodeConfig;

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-node-graph-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn setup(format: GitHashAlgorithm) -> (Scratch, OneNode) {
    let scratch = Scratch::new();
    let (node, _) = OneNode::init(NodeConfig::new(scratch.0.join("node"),
        TenantId::from_bytes([0x61; 16]), RepositoryId::from_bytes([0x62; 16]))
        .with_object_format(format)).unwrap();
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
    let receipt = SourceImportReceipt { object_format: format, object_count: u32::try_from(objects.len()).unwrap(),
        delete_only: false, origin: SourceImportOrigin::LocalGitDirectory };
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(objects.clone())).unwrap(),
        objects,
    };
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let validated = validate_source_import(&[SourceRefUpdate {
        old: zero, new: root, ref_name: b"refs/heads/main".to_vec(),
    }], &receipt, closure).unwrap();
    let context = AdmissionContext { head_key: node.head_key.clone(), tenant_id: node.tenant_id(),
        repository_id: node.repository_id(), principal_id: PrincipalId::from_bytes([0x63; 16]),
        idempotency_key: IdempotencyKey::new(b"graph-integrity-fixture".to_vec()).unwrap(), object_format: format };
    let result = node.runtime().block_on(node.admit_validated_source_import_durable_in(
        &request, &context, &validated, AdmissionLimits::default())).unwrap();
    assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
}
fn run(node: &OneNode, query: GraphAuditQuery) -> Result<SelectedGraphAudit, GraphAuditRefusal> {
    node.runtime().block_on(node.audit_selected_object_graph_local_in(&node.request_context(), query))
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
        assert_eq!((report.graph().objects, report.graph().references, report.graph().local_edges), (3, 1, 2));
        assert_eq!(report.graph().external_gitlinks, 0);
        assert_eq!(report.repository_id(), node.repository_id());
        assert_eq!(report.repository_incarnation_id(), node.repository_incarnation_id());
        let pinned = run(&node, GraphAuditQuery { expected_head: Some(report.head()),
            expected_generation: Some(report.generation()), ..Default::default() }).unwrap();
        assert_eq!(pinned.graph(), report.graph());
        assert_eq!(pinned.closure_root(), report.closure_root());
        assert_eq!(node.runtime().block_on(node.read_authority_head()).unwrap(), before);
        fn require_send(value: impl Send) { drop(value); }
        let request = node.request_context();
        require_send(node.audit_selected_object_graph_local_in(&request, GraphAuditQuery::default()));
        node.shutdown().unwrap();
    }
}

#[test]
fn valid_commitment_bytes_do_not_prove_local_connectivity_or_target_kinds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for wrong_kind in [false, true] {
            let (_scratch, mut node) = setup(format);
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let target = put(&node, if wrong_kind { ObjectKind::Blob } else { ObjectKind::Tree }, Vec::new());
            let root = put(&node, ObjectKind::Commit, commit(target));
            let selected = if wrong_kind { BTreeSet::from([target, root]) } else { BTreeSet::from([root]) };
            publish(&node, root, selected);
            // Both objects independently verify in real storage, including the
            // target excluded from authority's selected set in the missing case.
            node.read_git_object(root).unwrap();
            node.read_git_object(target).unwrap();
            node.runtime().block_on(node.doctor(Some(root))).unwrap();
            let before = node.runtime().block_on(node.read_authority_head()).unwrap();
            let result = run(&node, GraphAuditQuery::default());
            if wrong_kind {
                assert!(matches!(result, Err(GraphAuditRefusal::Graph(GraphRefusal::TargetKind {
                    target: id, expected: ObjectKind::Tree, actual: ObjectKind::Blob,
                })) if id == target));
            } else {
                assert!(matches!(result, Err(GraphAuditRefusal::Graph(GraphRefusal::MissingTarget {
                    source: Some(source), target: id,
                })) if source == root && id == target));
            }
            assert_eq!(node.runtime().block_on(node.read_authority_head()).unwrap(), before);
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
    assert!(matches!(run(&node, GraphAuditQuery::default()), Err(GraphAuditRefusal::Cell(_))));
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let genesis = run(&node, GraphAuditQuery::default()).unwrap();
    let blob = put(&node, ObjectKind::Blob, Vec::new());
    let root = put(&node, ObjectKind::Commit, commit(blob));
    publish(&node, root, BTreeSet::from([blob, root]));
    assert!(matches!(run(&node, GraphAuditQuery { expected_head: Some(genesis.head()), ..Default::default() }),
        Err(GraphAuditRefusal::ExpectedHead)));
    assert!(matches!(run(&node, GraphAuditQuery { expected_generation: Some(genesis.generation()), ..Default::default() }),
        Err(GraphAuditRefusal::ExpectedGeneration { .. })));
    let request = node.request_context();
    request.cancel();
    assert!(matches!(node.runtime().block_on(node.audit_selected_object_graph_local_in(&request, GraphAuditQuery::default())),
        Err(GraphAuditRefusal::Cancelled { .. })));
    node.shutdown().unwrap();
}

#[test]
fn exact_graph_limits_and_invalid_timeouts_never_turn_into_partial_success() {
    let (_scratch, mut node) = setup(GitHashAlgorithm::Sha256);
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let (blob, tree, root) = valid(&node);
    publish(&node, root, BTreeSet::from([blob, tree, root]));
    let report = run(&node, GraphAuditQuery::default()).unwrap();
    let limits = GraphLimits { max_objects: 3, max_references: 1, max_edges: 2,
        max_payload_bytes: report.graph().payload_bytes, ..Default::default() };
    run(&node, GraphAuditQuery { limits, ..Default::default() }).unwrap();
    for limits in [GraphLimits { max_objects: 2, ..limits }, GraphLimits { max_references: 0, ..limits },
        GraphLimits { max_edges: 1, ..limits }, GraphLimits { max_payload_bytes: report.graph().payload_bytes - 1, ..limits }]
    { assert!(run(&node, GraphAuditQuery { limits, ..Default::default() }).is_err()); }
    for timeout in [Duration::ZERO, Duration::from_secs(3601)] {
        assert!(matches!(run(&node, GraphAuditQuery { timeout, ..Default::default() }), Err(GraphAuditRefusal::InvalidTimeout)));
    }
    node.shutdown().unwrap();
}

#[test]
fn final_revalidation_rejects_a_real_authority_successor() {
    let (_scratch, mut node) = setup(GitHashAlgorithm::Sha1);
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let before = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    revalidate_head(&before, &before).unwrap();
    let (blob, tree, root) = valid(&node);
    publish(&node, root, BTreeSet::from([blob, tree, root]));
    let after = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    assert!(matches!(revalidate_head(&before, &after), Err(GraphAuditRefusal::SnapshotChanged)));
    revalidate_head(&after, &after).unwrap();
    node.shutdown().unwrap();
}
