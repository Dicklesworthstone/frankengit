use super::*;
use fgit_forge::event::pull_request_comment::{
    SourceCommentAnchor, SourceCommentComparison, SourceCommentSide, SourceCommentStatus,
};
use fgit_forge::preparation::MergeMetadata;

fn source_fixture(
    node: &OneNode,
    scratch: &Scratch,
    format: GitHashAlgorithm,
) -> (Fixture, SourceCommentAnchor) {
    let mut fixture = fixture(node, scratch, format);
    let request = node.request_context();
    let prepared = node.runtime().block_on(node.prepare_trusted_patch_in(
        &request,
        &fixture.data.source_ref,
        fixture.data.source_tip,
        [0x75; 16],
        b"diff --git a/reviewed b/reviewed\nnew file mode 100644\n--- /dev/null\n+++ b/reviewed\n@@ -0,0 +1,2 @@\n+first line\n+second line\n",
        &MergeMetadata {
            author: "Author <author@example.invalid>".into(),
            committer: "Committer <committer@example.invalid>".into(),
            timestamp: 2,
            message: b"source lines for review\n".to_vec(),
        },
        Default::default(),
    )).unwrap();
    let publication = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            principal(),
            b"append-anchor-source",
            &fixture.data.source_ref,
            fixture.data.source_tip,
            prepared.candidate_commit,
            prepared.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        publication.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    fixture.data.source_tip = prepared.candidate_commit;
    let anchor = SourceCommentAnchor {
        pull_request_version: AggregateVersion::FIRST,
        source_ref: fixture.data.source_ref.clone(),
        target_ref: fixture.data.target_ref.clone(),
        source_tip: fixture.data.source_tip,
        target_tip: fixture.data.target_tip,
        compared_base: fixture.data.target_tip,
        comparison: SourceCommentComparison::Direct,
        path: b"reviewed".to_vec(),
        side: SourceCommentSide::After,
        blob: git_object_id(format, GitObjectKind::Blob, b"first line\nsecond line\n"),
        mode: 0o100644,
        byte_start: 11,
        byte_end: 23,
        line_start: 1,
        line_count: 1,
    };
    (fixture, anchor)
}

#[test]
fn additive_source_comments_preserve_exact_anchors_and_revalidate_current_pr_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let (fixture, anchor) = source_fixture(&node, &scratch, format);
        let open = command(&fixture, 1);
        accepted(apply(&node, &open, "open"));
        let mut submitted = intent(1, "Please cover this exact second line");
        submitted.anchor = Some(anchor.clone());
        accepted(append(
            &node,
            &intent(1, "Another author spoke first"),
            "plain-first",
        ));
        let original = accepted(append(&node, &submitted, "anchored"));
        let comments = discussion(&node, 1);
        assert_eq!(comments.comments[1].anchor, Some(anchor.clone()));
        assert_eq!(
            comments.comments[1].anchor_status,
            Some(SourceCommentStatus::Exact)
        );
        let settled = snapshot(&node);
        let mut bad = submitted.clone();
        bad.anchor.as_mut().unwrap().byte_start += 1;
        assert!(append(&node, &bad, "anchored").is_err());
        assert_eq!(snapshot(&node).basis(), settled.basis());
        let refused = append(&node, &bad, "invalid-span").unwrap();
        assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { .. }));
        assert_eq!(discussion(&node, 1).comments.len(), 2);
        let mut close = open;
        close.action = PullRequestAction::Close;
        close.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        accepted(apply(&node, &close, "close"));
        assert_eq!(append(&node, &submitted, "anchored").unwrap(), original);
        let stale = append(&node, &submitted, "stale-anchor").unwrap();
        assert!(matches!(
            stale.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        let mut current = submitted.clone();
        current.anchor.as_mut().unwrap().pull_request_version =
            AggregateVersion::try_new(2).unwrap();
        accepted(append(&node, &current, "closed-current-anchor"));
        let final_page = discussion(&node, 1);
        assert_eq!(final_page.comments.len(), 3);
        assert_eq!(final_page.comments[1].anchor, Some(anchor));
        assert_eq!(
            final_page.comments[1].anchor_status,
            Some(SourceCommentStatus::Outdated)
        );
        assert_eq!(
            final_page.comments[2].anchor_status,
            Some(SourceCommentStatus::Exact)
        );
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(append(&reopened, &submitted, "anchored").unwrap(), original);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(discussion(&reopened, 1), final_page);
        reopened.shutdown().unwrap();
    }
}
