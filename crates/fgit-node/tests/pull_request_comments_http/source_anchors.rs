//! Real source publication, HTTP anchor admission, and retained conversation
//! replay. The transport owns neither object verification nor canonical state.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, lowercase_hex};
use fgit_forge::event::pull_request_comment::SourceCommentStatus;
use fgit_forge::preparation::MergeMetadata;
use fgit_types::GitOid;

fn source_fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, PullRequestData, GitOid) {
    let (node, mut data) = fixture(root, format);
    let request = node.request_context();
    let patch = b"diff --git a/reviewed b/reviewed\nnew file mode 100644\n--- /dev/null\n+++ b/reviewed\n@@ -0,0 +1,2 @@\n+first line\n+second line\n";
    let prepared = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            &data.source_ref,
            data.source_tip,
            [0x75; 16],
            patch,
            &MergeMetadata {
                author: "Author <author@example.invalid>".into(),
                committer: "Committer <committer@example.invalid>".into(),
                timestamp: 2,
                message: b"source lines for review\n".to_vec(),
            },
            Default::default(),
        ))
        .unwrap();
    let publication = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            OWNER,
            b"inline-comment-source",
            &data.source_ref,
            data.source_tip,
            prepared.candidate_commit,
            prepared.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        publication.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    data.source_tip = prepared.candidate_commit;
    let blob = git_object_id(format, GitObjectKind::Blob, b"first line\nsecond line\n");
    assert_eq!(
        node.read_git_object(blob).unwrap().payload(),
        b"first line\nsecond line\n"
    );
    native_open(&node, &data);
    (node, data, blob)
}

fn anchored_form(data: &PullRequestData, blob: GitOid) -> String {
    format!(
        "{}&anchor_pull_request_version=1&anchor_source_ref_hex={}&anchor_target_ref_hex={}&anchor_source_tip={}&anchor_target_tip={}&anchor_compared_base={}&anchor_comparison=merge_base&anchor_path_hex=7265766965776564&anchor_side=after&anchor_blob={blob}&anchor_mode=100644&anchor_byte_start=11&anchor_byte_end=23&anchor_line_start=1&anchor_line_count=1",
        comment_form(0, "Please cover this second line."),
        lowercase_hex(data.source_ref.as_bytes()),
        lowercase_hex(data.target_ref.as_bytes()),
        data.source_tip,
        data.target_tip,
        data.target_tip,
    )
}

#[test]
fn exact_source_comments_survive_http_retries_metadata_changes_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data, blob) = source_fixture(&root, format);
        let credentials = root.0.join("credentials");
        grants(&node, &credentials);
        let request = anchored_form(&data, blob);
        let server = Server::start(node, &credentials, 11, true, true);
        let client = &server.client;

        let first = post(
            client,
            1,
            "comments",
            'b',
            "source-comment",
            &request,
            false,
        ); // 1
        comment_committed(&first);
        assert!(first.body.contains("\"anchor\":{"));
        assert!(first.body.contains(&format!("\"blob\":\"{blob}\"")));
        assert!(!first.body.contains("anchor_status"));
        let exact = get(client, COMMENTS, 'a'); // 2
        status(&exact, 200);
        assert!(exact.body.contains("\"anchor_status\":\"exact\""));
        assert!(exact.body.contains("\"byte_start\":11"));
        assert_eq!(
            post(
                client,
                1,
                "comments",
                'b',
                "source-comment",
                &request,
                false
            )
            .body,
            first.body
        ); // 3

        // The same key cannot select a different source line. A fresh key also
        // cannot make a byte interval that starts inside a source line canonical.
        let changed = request.replace("anchor_byte_start=11", "anchor_byte_start=12");
        status(
            &post(
                client,
                1,
                "comments",
                'b',
                "source-comment",
                &changed,
                false,
            ),
            409,
        ); // 4
        let invalid = changed.replace("expected_version=0", "expected_version=1");
        status(
            &post(
                client,
                1,
                "comments",
                'b',
                "invalid-source-line",
                &invalid,
                false,
            ),
            409,
        ); // 5
        let incomplete = format!("{}&anchor_blob={blob}", comment_form(1, "Partial anchor"));
        status(
            &post(
                client,
                1,
                "comments",
                'b',
                "partial-source-line",
                &incomplete,
                false,
            ),
            400,
        ); // 6

        committed(&post(
            client,
            1,
            "close",
            'b',
            "close-inline-pr",
            &form(&data, 1),
            false,
        )); // 7
        let outdated = get(client, COMMENTS, 'a'); // 8
        status(&outdated, 200);
        assert!(outdated.body.contains("\"discussion_version\":1"));
        assert!(outdated.body.contains("\"anchor_status\":\"outdated\""));
        assert!(outdated.body.contains(&format!("\"blob\":\"{blob}\"")));
        // Recover the immutable original result before fresh anchor validation.
        assert_eq!(
            post(
                client,
                1,
                "comments",
                'b',
                "source-comment",
                &request,
                false
            )
            .body,
            first.body
        ); // 9
        comment_committed(&post(
            client,
            1,
            "comments",
            'b',
            "plain-after-inline",
            &comment_form(1, "Plain follow-up"),
            false,
        )); // 10
        let mixed = get(client, COMMENTS, 'a'); // 11
        status(&mixed, 200);
        assert!(mixed.body.contains("\"discussion_version\":2"));
        assert_eq!(mixed.body.matches("\"anchor\":{").count(), 1);
        assert!(mixed.body.contains("Plain follow-up"));
        server.finish();

        let node = reopen(&config);
        let page = node
            .runtime()
            .block_on(node.read_pull_request_comments_in(
                &node.request_context(),
                &RefVisibility::new(),
                PullRequestNumber::FIRST,
                0,
                20,
                None,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(page.comments.len(), 2);
        assert_eq!(page.comments[0].anchor.as_ref().unwrap().blob, blob);
        assert_eq!(
            page.comments[0].anchor_status,
            Some(SourceCommentStatus::Outdated)
        );
        assert!(page.comments[1].anchor.is_none());
        assert!(page.comments[1].anchor_status.is_none());
        node.shutdown().unwrap();
    }
}
