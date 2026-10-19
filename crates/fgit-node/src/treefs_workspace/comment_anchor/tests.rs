//! Real object fabric and persisted authority, sharing the native source-review
//! fixture. These tests exercise canonical publication rather than a UI precheck.

use super::super::tests::{fixture, metadata};
use super::*;
use crate::{LoopbackReceiveSession, MaterializedAdmission, NodeConfig, OneNode};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::pull_request_comment::{
    PullRequestCommentCommand, SourceCommentComparison, SourceCommentSide, SourceCommentStatus,
};
use fgit_forge::event::{ForgeEventPayload, NativeMerge};
use fgit_forge::review::{ComparisonMode, ReviewOptions, ReviewSelection};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, TxId};
use fgit_wire::visibility::RefVisibility;

fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x73; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
}
fn unchanged(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(
        before.basis().body().ref_root,
        after.basis().body().ref_root
    );
    assert_eq!(
        before.basis().body().retention_root,
        after.basis().body().retention_root
    );
    assert_eq!(
        before.basis().body().policy_epoch,
        after.basis().body().policy_epoch
    );
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
}
fn accepted(value: &(TxId, TerminalOutcome)) {
    assert!(
        matches!(value.1.outcome, DecisionOutcome::Committed { .. }),
        "{value:?}"
    );
}
fn pr(
    node: &OneNode,
    data: &PullRequestData,
    previous: Option<AggregateVersion>,
    action: PullRequestAction,
    key: &str,
) -> (TxId, TerminalOutcome) {
    node.runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session(key),
            &PullRequestCommand {
                number: PullRequestNumber::FIRST,
                expected_version:
                    previous.map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
                action,
                data: data.clone(),
            },
            Default::default(),
        ))
        .unwrap()
}
fn open(
    node: &OneNode,
    target_tip: GitOid,
    source_tip: GitOid,
) -> (PullRequestData, SourceCommentAnchor) {
    let data = PullRequestData {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip,
        target_tip,
        title: "Review exact source".into(),
        body: "Source review fixture".into(),
    };
    accepted(&pr(
        node,
        &data,
        None,
        PullRequestAction::Open,
        "source-comment-open",
    ));
    let result = node
        .runtime()
        .block_on(node.review_source_in(
            &node.request_context(),
            &ReviewSelection::PullRequest {
                number: PullRequestNumber::FIRST,
                expected_version: Some(AggregateVersion::FIRST),
            },
            &RefVisibility::new(),
            None,
            &ReviewOptions {
                mode: ComparisonMode::MergeBase,
                ..ReviewOptions::default()
            },
        ))
        .unwrap();
    let entry = result
        .comparison
        .entries
        .iter()
        .find(|entry| entry.path == b"text")
        .unwrap();
    let selected = entry.after.unwrap();
    let anchor = SourceCommentAnchor {
        pull_request_version: AggregateVersion::FIRST,
        source_ref: data.source_ref.clone(),
        target_ref: data.target_ref.clone(),
        source_tip,
        target_tip,
        compared_base: result.comparison.compared_before,
        comparison: SourceCommentComparison::MergeBase,
        path: b"text".to_vec(),
        side: SourceCommentSide::After,
        blob: selected.oid,
        mode: selected.mode,
        byte_start: 8,
        byte_end: 10,
        line_start: 4,
        line_count: 1,
    };
    (data, anchor)
}
fn command(anchor: Option<SourceCommentAnchor>, previous: u64) -> PullRequestCommentCommand {
    PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: AggregateVersion::try_new(previous)
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        body: "Please preserve this exact final line.\n".into(),
        anchor,
    }
}
fn append(
    node: &OneNode,
    command: &PullRequestCommentCommand,
    key: &str,
) -> Result<(TxId, TerminalOutcome), crate::NodeReceiveTransportRefusal> {
    node.runtime()
        .block_on(node.admit_pull_request_comment_durable_in(
            &node.request_context(),
            &session(key),
            command,
            Default::default(),
        ))
}
fn page(
    node: &OneNode,
    expected_head: Option<fgit_types::RepositoryAuthorityHeadId>,
) -> fgit_admission::merge::native::pull_request::comments::PullRequestCommentsPage {
    node.runtime()
        .block_on(node.read_pull_request_comments_in(
            &node.request_context(),
            &RefVisibility::new(),
            PullRequestNumber::FIRST,
            0,
            100,
            expected_head,
        ))
        .unwrap()
        .unwrap()
}
fn reopen(node: OneNode) -> OneNode {
    let config = NodeConfig::new(
        node.storage_root().to_owned(),
        node.tenant_id,
        node.repository_id,
    )
    .with_object_format(node.object_format)
    .with_worker_threads(2);
    node.shutdown().unwrap();
    let mut reopened = OneNode::open_existing(config).unwrap();
    let generation = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    reopened.bring_into_service(generation).unwrap();
    reopened
}

#[test]
fn anchored_comments_are_atomic_persisted_and_original_retries_survive_pr_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, source) = fixture(format, false);
        let (mut data, anchor) = open(&node, target, source);
        let before = snapshot(&node);
        let first = command(Some(anchor.clone()), 0);
        let terminal = append(&node, &first, "source-comment-first").unwrap();
        accepted(&terminal);
        let published = snapshot(&node);
        unchanged(&before, &published);
        assert_ne!(
            before.basis().body().forge_position_root,
            published.basis().body().forge_position_root
        );
        assert_ne!(
            before.basis().body().outbox_root,
            published.basis().body().outbox_root
        );
        assert_eq!(
            published.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        let old_page = page(&node, None);
        assert_eq!(old_page.comments.len(), 1);
        assert_eq!(old_page.comments[0].anchor.as_ref(), Some(&anchor));
        assert_eq!(
            old_page.comments[0].anchor_status,
            Some(SourceCommentStatus::Exact)
        );
        let node = reopen(node);
        assert_eq!(page(&node, Some(old_page.source_head)), old_page);
        assert_eq!(
            append(&node, &first, "source-comment-first").unwrap(),
            terminal
        );
        data.title.push_str(" updated");
        accepted(&pr(
            &node,
            &data,
            Some(AggregateVersion::FIRST),
            PullRequestAction::Update,
            "source-comment-pr-update",
        ));
        let fresh = page(&node, None);
        assert_eq!(
            fresh.comments[0].anchor_status,
            Some(SourceCommentStatus::Outdated)
        );
        assert_eq!(fresh.comments[0].anchor.as_ref(), Some(&anchor));
        assert_eq!(page(&node, Some(old_page.source_head)), old_page);
        let settled = snapshot(&node);
        assert_eq!(
            append(&node, &first, "source-comment-first").unwrap(),
            terminal
        );
        assert_eq!(snapshot(&node).basis(), settled.basis());
        let stale = command(Some(anchor.clone()), 1);
        let refused = append(&node, &stale, "source-comment-stale").unwrap();
        assert!(matches!(
            refused.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        assert_eq!(page(&node, None).comments.len(), 1);
        let mut current = anchor;
        current.pull_request_version = AggregateVersion::try_new(2).unwrap();
        accepted(&append(&node, &command(Some(current), 1), "source-comment-current").unwrap());
        accepted(&append(&node, &command(None, 2), "source-comment-plain").unwrap());
        let node = reopen(node);
        let result = page(&node, None);
        assert_eq!(result.comments.len(), 3);
        assert_eq!(
            result.comments[0].anchor_status,
            Some(SourceCommentStatus::Outdated)
        );
        assert_eq!(
            result.comments[1].anchor_status,
            Some(SourceCommentStatus::Exact)
        );
        assert_eq!(result.comments[2].anchor, None);
        assert_eq!(result.comments[2].anchor_status, None);
        for hidden in [data.source_ref, data.target_ref] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            assert!(
                node.runtime()
                    .block_on(node.read_pull_request_comments_in(
                        &node.request_context(),
                        &visibility,
                        PullRequestNumber::FIRST,
                        0,
                        1,
                        Some(old_page.source_head)
                    ))
                    .unwrap()
                    .is_none()
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn admitted_anchor_rejects_forged_object_path_side_base_and_line_coordinates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, source) = fixture(format, false);
        let (_, anchor) = open(&node, target, source);
        let before = snapshot(&node);
        for mutation in 0..9 {
            let mut forged = anchor.clone();
            match mutation {
                0 => forged.blob = source,
                1 => forged.side = SourceCommentSide::Before,
                2 => forged.mode = 0o100755,
                3 => forged.path = b"keep".to_vec(),
                4 => forged.path = b"missing".to_vec(),
                5 => forged.compared_base = target,
                6 => forged.byte_end -= 1,
                7 => {
                    forged.byte_start = 9;
                    forged.line_start = 5;
                }
                _ => forged.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
            }
            let denied = append(
                &node,
                &command(Some(forged), 0),
                &format!("source-comment-forged-{mutation}"),
            )
            .unwrap();
            assert!(
                matches!(denied.1.outcome, DecisionOutcome::Refused { .. }),
                "mutation {mutation}: {denied:?}"
            );
            assert!(page(&node, None).comments.is_empty());
            unchanged(&before, &snapshot(&node));
        }
        accepted(
            &append(
                &node,
                &command(Some(anchor), 0),
                "source-comment-valid-twin",
            )
            .unwrap(),
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn cancellation_recovery_and_closed_or_merged_source_comments_keep_their_basis() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, source) = fixture(format, false);
        let (data, mut anchor) = open(&node, target, source);
        let first = command(Some(anchor.clone()), 0);
        let before = snapshot(&node);
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_pull_request_comment_durable_in(
                    &cancelled,
                    &session("source-comment-cancelled"),
                    &first,
                    Default::default()
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        let first_terminal = append(&node, &first, "source-comment-cancelled").unwrap();
        accepted(&first_terminal);
        accepted(&pr(
            &node,
            &data,
            Some(AggregateVersion::FIRST),
            PullRequestAction::Close,
            "source-comment-close",
        ));
        anchor.pull_request_version = AggregateVersion::try_new(2).unwrap();
        accepted(
            &append(
                &node,
                &command(Some(anchor.clone()), 1),
                "source-comment-closed",
            )
            .unwrap(),
        );
        accepted(&pr(
            &node,
            &data,
            Some(AggregateVersion::try_new(2).unwrap()),
            PullRequestAction::Reopen,
            "source-comment-reopen",
        ));
        let prepared = node
            .runtime()
            .block_on(node.prepare_merge_bundle_in(
                &node.request_context(),
                &data.target_ref,
                &data.source_ref,
                &RefVisibility::new(),
                &metadata(),
                Default::default(),
            ))
            .unwrap();
        let fgit_forge::preparation::MergePreparation::Clean(plan) = prepared.outcome else {
            panic!("clean merge");
        };
        let merge = NativeMerge {
            source_ref: data.source_ref.clone(),
            target_ref: data.target_ref.clone(),
            source_tip: source,
            target_tip_before: target,
            base_tip: plan.base,
            merge_commit: plan.commit,
        };
        let terminal = node
            .runtime()
            .block_on(node.apply_merge_bundle_durable_in(
                &node.request_context(),
                PrincipalId::from_bytes([0x73; 16]),
                b"source-comment-merge",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::try_new(3).unwrap()),
                &merge,
                &prepared.bundle.unwrap(),
            ))
            .unwrap();
        accepted(&terminal);
        anchor.pull_request_version = AggregateVersion::try_new(4).unwrap();
        accepted(&append(&node, &command(Some(anchor), 2), "source-comment-merged").unwrap());
        let node = reopen(node);
        let result = page(&node, None);
        assert_eq!(result.comments.len(), 3);
        assert_eq!(
            result.comments[2].anchor_status,
            Some(SourceCommentStatus::Exact)
        );
        let prs = node
            .runtime()
            .block_on(node.read_pull_requests_in(
                &node.request_context(),
                &RefVisibility::new(),
                0,
                1,
                None,
            ))
            .unwrap();
        assert!(matches!(
            prs.pull_requests[0].event.payload,
            ForgeEventPayload::MergeCommittedNative(_)
        ));
        let reviewed = snapshot(&node);
        assert_eq!(
            append(&node, &first, "source-comment-cancelled").unwrap(),
            first_terminal
        );
        assert_eq!(snapshot(&node).basis(), reviewed.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn actual_fabric_read_ceiling_remains_a_resource_refusal_in_the_selected_source() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = fixture(format, false);
        let (_, anchor) = open(&node, target, incoming);
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        for maximum in [10, 9] {
            let exhaustion = Cell::new(None);
            let source = SelectedSource {
                inner: VerifiedFabricPackSource {
                    fabric: &node.fabric,
                    object_format: format,
                    maximum_object_bytes: maximum,
                    database_context: request.authority(),
                    database_exhaustion: &exhaustion,
                    session_is_live: None,
                },
                selected: selected.selected_closure(),
                limits: ParseLimits {
                    tree_reference_bytes: format.digest_len(),
                    max_object_bytes: maximum,
                    ..ParseLimits::default()
                },
                read_bytes: Cell::new(0),
                budget_failed: Cell::new(false),
            };
            if maximum == 10 {
                assert_eq!(source.blob(anchor.blob).unwrap(), b"a\nb\nc\nd\nE\n");
                source.checkpoint().unwrap();
            } else {
                assert_eq!(
                    source.blob(anchor.blob),
                    Err(MergeSourceError::BudgetExceeded)
                );
                assert_eq!(source.checkpoint(), Err(MergeSourceError::BudgetExceeded));
            }
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn actual_commit_and_tree_parser_limits_preserve_resource_refusals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, _, tip) = fixture(format, false);
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let exhaustion = Cell::new(None);
        let source = |limits| SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &node.fabric,
                object_format: format,
                maximum_object_bytes: MAX_SOURCE_COMMENT_BLOB_BYTES as usize,
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected: selected.selected_closure(),
            limits,
            read_bytes: Cell::new(0),
            budget_failed: Cell::new(false),
        };
        let full = ParseLimits {
            tree_reference_bytes: format.digest_len(),
            max_object_bytes: MAX_SOURCE_COMMENT_BLOB_BYTES as usize,
            ..ParseLimits::default()
        };
        let permitted = source(full.clone());
        let commit = permitted.commit(tip).unwrap();
        let (_, body) = permitted.read(tip, None).unwrap();
        let headers: Vec<_> = body
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty())
            .collect();
        let header_width = headers.iter().map(|line| line.len()).max().unwrap();
        let tree_entries = permitted.tree(commit.tree).unwrap().len();
        for (dimension, actual) in [
            (0, body.len()),
            (1, headers.len()),
            (2, header_width),
            (3, tree_entries),
        ] {
            for limit in [actual, actual - 1] {
                let mut limits = full.clone();
                match dimension {
                    0 => limits.max_object_bytes = limit,
                    1 => limits.max_header_lines = limit,
                    2 => limits.max_header_line_bytes = limit,
                    _ => limits.max_tree_entries = limit,
                }
                let selected_source = source(limits);
                let result = if dimension == 3 {
                    selected_source.tree(commit.tree).map(|_| ())
                } else {
                    selected_source.commit(tip).map(|_| ())
                };
                if limit == actual {
                    result.unwrap();
                    selected_source.checkpoint().unwrap();
                } else {
                    assert_eq!(
                        result,
                        Err(MergeSourceError::BudgetExceeded),
                        "parser dimension {dimension} at limit {limit}"
                    );
                    assert_eq!(
                        selected_source.checkpoint(),
                        Err(MergeSourceError::BudgetExceeded)
                    );
                }
            }
        }
        node.shutdown().unwrap();
    }
}
