use super::*;
use crate::NodeConfig;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_treefs::integrity::ObjectKind as GitKind;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, TenantId};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
pub(super) struct Scratch(pub(super) PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-native-scrub-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x61; 16]),
            RepositoryId::from_bytes([0x62; 16]),
        )
        .with_object_format(format)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub(super) fn setup(format: GitHashAlgorithm) -> (Scratch, OneNode) {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    (scratch, node)
}
pub(super) fn run(node: &OneNode, query: &ScrubQuery) -> Result<SelectedObjectScrub, ScrubRefusal> {
    node.runtime()
        .block_on(node.scrub_selected_objects_local_in(&node.request_context(), *query))
}
fn put(node: &OneNode, kind: GitKind, payload: Vec<u8>) -> GitOid {
    node.put_git_object(kind, payload).unwrap().identity()
}
pub(super) fn publish(node: &OneNode) -> (BTreeSet<GitOid>, Vec<GitOid>) {
    publish_ref(node, b"refs/heads/main", b"native-scrub-fixture")
}
pub(super) fn publish_ref(
    node: &OneNode,
    reference: &[u8],
    key: &[u8],
) -> (BTreeSet<GitOid>, Vec<GitOid>) {
    publish_ref_with_payloads(
        node,
        reference,
        key,
        (0..4).map(|i| format!("admitted history payload {i}\n").into_bytes()),
    )
}
pub(super) fn publish_ref_with_payloads(
    node: &OneNode,
    reference: &[u8],
    key: &[u8],
    payloads: impl IntoIterator<Item = Vec<u8>>,
) -> (BTreeSet<GitOid>, Vec<GitOid>) {
    let blob = put(node, GitKind::Blob, b"live content\n".to_vec());
    let mut body = b"100644 file\0".to_vec();
    body.extend_from_slice(blob.as_bytes());
    let tree = put(node, GitKind::Tree, body);
    let root = put(node, GitKind::Commit, format!(
        "tree {tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nfixture\n"
    ).into_bytes());
    let extra = payloads
        .into_iter()
        .map(|payload| put(node, GitKind::Blob, payload))
        .collect::<Vec<_>>();
    let mut objects = BTreeSet::from([blob, tree, root]);
    objects.extend(extra.iter().copied());
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects: objects.clone(),
    };
    let receipt = SourceImportReceipt {
        object_format: node.object_format,
        object_count: objects.len() as u32,
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let zero = GitOid::from_hex(
        node.object_format,
        &"0".repeat(node.object_format.digest_len() * 2),
    )
    .unwrap();
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old: zero,
            new: root,
            ref_name: reference.to_vec(),
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
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        object_format: node.object_format,
    };
    let result = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &node.request_context(),
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    (objects, extra)
}

// Test-only fault location: inspect the fixture directory, assert its unique
// existing native body, then damage those actual bytes. Production never scans
// a directory for membership or uses a stand-in fabric/authority implementation.
pub(super) fn body_path(root: &Path, oid: GitOid) -> PathBuf {
    let mut pending = vec![root.to_owned()];
    let mut matches = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name().to_str() == Some(oid.to_string().as_str())
            {
                let bytes = fs::read(entry.path()).unwrap();
                if bytes.starts_with(b"FGOB") {
                    matches.push(entry.path());
                }
            }
        }
    }
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one real native object body"
    );
    matches.pop().unwrap()
}

#[test]
fn fresh_complete_inventory_is_deterministic_in_both_domains_and_does_not_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node) = setup(format);
        let (objects, _) = publish(&node);
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();
        let report = run(&node, &ScrubQuery::default()).unwrap();
        assert!(report.entire_selection_verified());
        assert_eq!(report.selected_objects(), objects.len());
        assert_eq!(report.checked_objects(), objects.len());
        assert_eq!(report.verified_objects(), objects.len());
        assert_eq!(report.read_attempts(), objects.len());
        assert!(report.findings().is_empty());
        assert_eq!(report.stop(), ScrubStop::SelectionExhausted);
        assert_eq!(report.repository_id(), node.repository_id());
        assert_eq!(
            report.repository_incarnation_id(),
            node.repository_incarnation_id()
        );
        assert_eq!(
            format!("{report:?}"),
            format!("{:?}", run(&node, &ScrubQuery::default()).unwrap())
        );
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_and_corrupt_history_are_both_reported_but_unselected_residue_is_not_read() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node) = setup(format);
        let (objects, extra) = publish(&node);
        let outsider = put(&node, GitKind::Blob, b"not selected\n".to_vec());
        let outsider_path = body_path(&scratch.0, outsider);
        fs::write(&outsider_path, b"unselected damaged residue").unwrap();
        fs::write(body_path(&scratch.0, extra[0]), b"damaged native body").unwrap();
        fs::remove_file(body_path(&scratch.0, extra[1])).unwrap();
        let before = node.runtime().block_on(node.read_authority_head()).unwrap();
        let report = run(&node, &ScrubQuery::default()).unwrap();
        assert!(report.entire_selection_checked());
        assert!(!report.entire_selection_verified());
        assert_eq!(report.checked_objects(), objects.len());
        assert_eq!(report.verified_objects(), objects.len() - 2);
        let mut expected = vec![extra[0], extra[1]];
        expected.sort();
        assert_eq!(
            report
                .findings()
                .iter()
                .map(|finding| finding.oid)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            report
                .findings()
                .iter()
                .all(|finding| matches!(&finding.cause, ScrubFindingCause::ObjectRead(_)))
        );
        assert_eq!(
            fs::read(outsider_path).unwrap(),
            b"unselected damaged residue"
        );
        // The pre-existing strict graph audit still refuses, not a weakened
        // success result or implicit fallback to this inventory API.
        assert!(
            node.runtime()
                .block_on(node.audit_selected_object_graph_local_in(
                    &node.request_context(),
                    super::super::GraphAuditQuery::default(),
                ))
                .is_err()
        );
        assert_eq!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            before
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn cursor_pages_resume_across_real_reopen_without_skips_duplicates_or_health_inflation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, mut node) = setup(format);
        let (objects, _) = publish(&node);
        let ordered = objects.iter().copied().collect::<Vec<_>>();
        let mut cursor = None;
        let mut checked = 0;
        let mut verified = 0;
        loop {
            let report = run(
                &node,
                &ScrubQuery {
                    cursor,
                    max_page_objects: 2,
                    max_findings: 2,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(report.start_after(), cursor.map(ScrubCursor::after));
            assert!(!report.entire_selection_checked());
            assert!(!report.entire_selection_verified());
            assert!(report.findings().is_empty());
            assert!(report.checked_objects() <= 2);
            checked += report.checked_objects();
            verified += report.verified_objects();
            cursor = report.next_cursor();
            if let Some(next) = cursor {
                assert_eq!(next.after(), ordered[checked - 1]);
            }
            node.shutdown().unwrap();
            if cursor.is_none() {
                break;
            }
            node = OneNode::open_existing(scratch.config(format)).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
        }
        assert_eq!(checked, objects.len());
        assert_eq!(verified, objects.len());
    }
}

#[test]
fn a_finding_limit_continues_after_the_observed_failure_not_after_an_unread_object() {
    let (scratch, node) = setup(GitHashAlgorithm::Sha256);
    let (objects, extra) = publish(&node);
    for oid in &extra[..2] {
        fs::remove_file(body_path(&scratch.0, *oid)).unwrap();
    }
    let mut cursor = None;
    let mut checked = 0;
    let mut findings = Vec::new();
    loop {
        let report = run(
            &node,
            &ScrubQuery {
                cursor,
                max_findings: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(report.findings().len() <= 1);
        checked += report.checked_objects();
        findings.extend(report.findings().iter().map(|finding| finding.oid));
        cursor = report.next_cursor();
        if cursor.is_none() {
            break;
        }
        assert!(report.checked_objects() > 0);
        assert_eq!(report.stop(), ScrubStop::FindingLimit);
    }
    let mut expected = extra[..2].to_vec();
    expected.sort();
    assert_eq!(findings, expected);
    assert_eq!(checked, objects.len());
    node.shutdown().unwrap();
}

#[test]
fn payload_pages_account_exactly_and_never_advance_past_the_boundary_read() {
    let (_scratch, node) = setup(GitHashAlgorithm::Sha1);
    let (objects, _) = publish(&node);
    let sizes = objects
        .iter()
        .map(|oid| node.read_git_object(*oid).unwrap().payload().len() as u64)
        .collect::<Vec<_>>();
    let budget = *sizes.iter().max().unwrap();
    let mut cursor = None;
    let mut total = 0;
    let mut checked = 0;
    let mut boundary_seen = false;
    loop {
        let report = run(
            &node,
            &ScrubQuery {
                cursor,
                max_payload_bytes: budget,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(report.payload_bytes() <= budget);
        assert!(report.checked_objects() > 0);
        assert!(report.findings().is_empty());
        total += report.payload_bytes();
        checked += report.checked_objects();
        if report.next_cursor().is_some() {
            assert_eq!(report.stop(), ScrubStop::PayloadLimit);
            assert_eq!(report.read_attempts(), report.checked_objects() + 1);
            boundary_seen = true;
        }
        cursor = report.next_cursor();
        if cursor.is_none() {
            break;
        }
    }
    assert!(boundary_seen);
    assert_eq!(total, sizes.iter().sum::<u64>());
    assert_eq!(checked, objects.len());
    assert!(matches!(
        run(
            &node,
            &ScrubQuery {
                max_payload_bytes: 1,
                ..Default::default()
            }
        ),
        Err(ScrubRefusal::ObjectExceedsPage { .. })
    ));
    assert!(
        run(&node, &ScrubQuery::default())
            .unwrap()
            .entire_selection_verified()
    );
    node.shutdown().unwrap();
}

#[test]
fn stale_or_nonmember_cursors_refuse_and_an_end_cursor_cannot_forge_completeness() {
    let (_scratch, node) = setup(GitHashAlgorithm::Sha1);
    let genesis = run(&node, &ScrubQuery::default()).unwrap();
    assert!(genesis.entire_selection_verified());
    assert_eq!(genesis.checked_objects(), 0);
    let (objects, _) = publish(&node);
    let current = run(&node, &ScrubQuery::default()).unwrap();
    let first = *objects.first().unwrap();
    let last = *objects.last().unwrap();
    assert!(matches!(
        run(
            &node,
            &ScrubQuery {
                cursor: Some(ScrubCursor::new(genesis.head(), first)),
                ..Default::default()
            }
        ),
        Err(ScrubRefusal::CursorHeadMismatch)
    ));
    let outsider = put(&node, GitKind::Blob, b"nonmember\n".to_vec());
    assert!(matches!(
        run(
            &node,
            &ScrubQuery {
                cursor: Some(ScrubCursor::new(current.head(), outsider)),
                ..Default::default()
            }
        ),
        Err(ScrubRefusal::CursorNotSelected)
    ));
    assert!(matches!(
        run(
            &node,
            &ScrubQuery {
                expected_head: Some(genesis.head()),
                cursor: Some(ScrubCursor::new(current.head(), first)),
                ..Default::default()
            }
        ),
        Err(ScrubRefusal::CursorHeadMismatch)
    ));
    assert!(matches!(
        run(
            &node,
            &ScrubQuery {
                expected_generation: Some(genesis.generation()),
                ..Default::default()
            }
        ),
        Err(ScrubRefusal::Audit(
            GraphAuditRefusal::ExpectedGeneration { .. }
        ))
    ));
    let empty_suffix = run(
        &node,
        &ScrubQuery {
            cursor: Some(ScrubCursor::new(current.head(), last)),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(empty_suffix.checked_objects(), 0);
    assert_eq!(empty_suffix.stop(), ScrubStop::SelectionExhausted);
    assert!(!empty_suffix.entire_selection_checked());
    assert!(!empty_suffix.entire_selection_verified());
    node.shutdown().unwrap();
}

#[test]
fn limits_and_cancelled_requests_are_not_object_findings_or_success_pages() {
    let (_scratch, node) = setup(GitHashAlgorithm::Sha1);
    let (objects, _) = publish(&node);
    for query in [
        ScrubQuery {
            max_page_objects: 0,
            ..Default::default()
        },
        ScrubQuery {
            max_findings: 0,
            ..Default::default()
        },
        ScrubQuery {
            max_findings: 1001,
            max_page_objects: 1001,
            ..Default::default()
        },
        ScrubQuery {
            max_payload_bytes: 0,
            ..Default::default()
        },
        ScrubQuery {
            timeout: Duration::ZERO,
            ..Default::default()
        },
        ScrubQuery {
            timeout: Duration::from_secs(3601),
            ..Default::default()
        },
    ] {
        assert!(run(&node, &query).is_err());
    }
    assert!(matches!(
        run(
            &node,
            &ScrubQuery {
                max_selected_objects: 1,
                max_page_objects: 1,
                max_findings: 1,
                ..Default::default()
            }
        ),
        Err(ScrubRefusal::SelectionLimit { .. })
    ));
    assert!(
        run(
            &node,
            &ScrubQuery {
                max_selected_objects: objects.len(),
                max_page_objects: objects.len(),
                max_findings: objects.len(),
                ..Default::default()
            }
        )
        .unwrap()
        .entire_selection_verified()
    );
    let request = node.request_context();
    request.cancel();
    assert!(matches!(
        node.runtime()
            .block_on(node.scrub_selected_objects_local_in(&request, ScrubQuery::default())),
        Err(ScrubRefusal::Audit(GraphAuditRefusal::Cancelled { .. }))
    ));
    fn require_send(value: impl Send) {
        drop(value);
    }
    require_send(
        node.scrub_selected_objects_local_in(&node.request_context(), ScrubQuery::default()),
    );
    node.shutdown().unwrap();
}
