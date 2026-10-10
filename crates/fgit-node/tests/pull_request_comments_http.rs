#![forbid(unsafe_code)]
//! Real persisted PR discussions through the node and bounded HTTP service.

#[path = "pull_request_http/support.rs"]
mod support;

use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::pull_request_comment::PullRequestCommentCommand;
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, TxId};
use fgit_wire::visibility::RefVisibility;
use support::*;

const COMMENTS: &str = "/api/v1/pulls/1/comments";

fn comment_form(version: u64, body: &str) -> String {
    format!(
        "expected_version={version}&body={}",
        encode(body.as_bytes())
    )
}

fn comment_committed(reply: &Reply) {
    status(reply, 200);
    assert!(
        reply
            .body
            .contains("\"type\":\"pull_request_comment_publication\"")
    );
    assert!(reply.body.contains("\"action\":\"comment\""));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert!(reply.body.contains("\"refs_changed\":false"));
    assert!(reply.body.contains("\"delivery_acknowledged\":null"));
}

fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}

fn native_open(node: &OneNode, data: &PullRequestData) {
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: data.clone(),
    };
    let terminal = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session("discussion-open"),
            &command,
            Default::default(),
        ))
        .unwrap()
        .1;
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn native_comment(
    node: &OneNode,
    key: &str,
    version: u64,
    body: &str,
) -> Result<(TxId, TerminalOutcome), fgit_node::NodeReceiveTransportRefusal> {
    let command = PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        body: body.into(),
    };
    node.runtime()
        .block_on(node.admit_pull_request_comment_durable_in(
            &node.request_context(),
            &session(key),
            &command,
            Default::default(),
        ))
}

#[test]
fn comments_have_independent_versions_exact_retries_pinned_pages_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let credentials = root.0.join("credentials");
        grants(&node, &credentials);
        let server = Server::start(node, &credentials, 18, true, true);
        let client = &server.client;
        let original_text = "**Review** 🦀 <script>bad()</script>\nLiteral %2f \"quoted\"";
        let first_form = comment_form(0, original_text);
        status(
            &post(client, 7, "comments", 'b', "missing-pr", &first_form, false),
            409,
        ); // 1
        committed(&post(
            client,
            1,
            "open",
            'b',
            "open",
            &form(&data, 0),
            false,
        )); // 2
        let empty = get(client, COMMENTS, 'a'); // 3
        status(&empty, 200);
        assert!(empty.body.contains("\"found\":true"));
        assert!(empty.body.contains("\"discussion_version\":0"));
        status(
            &post(
                client,
                1,
                "comments",
                'a',
                "reader-write",
                &first_form,
                false,
            ),
            403,
        ); // 4
        status(&get(client, COMMENTS, 'b'), 403); // 5
        status(
            &post(
                client,
                1,
                "comments",
                'd',
                "wrong-grant",
                &first_form,
                false,
            ),
            403,
        ); // 6
        let first = post(
            client,
            1,
            "comments",
            'b',
            "first-comment",
            &first_form,
            false,
        ); // 7
        comment_committed(&first);
        assert!(first.body.contains("\"comment_version\":1"));
        assert_eq!(
            post(
                client,
                1,
                "comments",
                'b',
                "first-comment",
                &first_form,
                false
            )
            .body,
            first.body
        ); // 8
        status(
            &post(
                client,
                1,
                "comments",
                'b',
                "first-comment",
                &comment_form(0, "Changed"),
                false,
            ),
            409,
        ); // 9
        status(
            &post(
                client,
                1,
                "comments",
                'b',
                "stale-discussion",
                &comment_form(0, "Stale"),
                false,
            ),
            409,
        ); // 10
        comment_committed(&post(
            client,
            1,
            "comments",
            'b',
            "second-comment",
            &comment_form(1, "Second comment"),
            true,
        )); // 11
        let first_page = get(client, &format!("{COMMENTS}?limit=1&render=html_safe"), 'a'); // 12
        status(&first_page, 200);
        assert!(first_page.body.contains("\"discussion_version\":2"));
        assert!(first_page.body.contains("\"next_after\":1"));
        assert!(first_page.body.contains("&lt;script&gt;"));
        let pinned = token(&first_page);
        // The PR still has metadata version1 after two comments.
        committed(&post(
            client,
            1,
            "close",
            'b',
            "close",
            &form(&data, 1),
            false,
        )); // 13
        comment_committed(&post(
            client,
            1,
            "comments",
            'b',
            "closed-comment",
            &comment_form(2, "Third comment after close"),
            false,
        )); // 14
        let last_page = get(
            client,
            &format!("{COMMENTS}?after=1&limit=1&expected_head={pinned}&render=html_safe"),
            'a',
        ); // 15
        status(&last_page, 200);
        assert!(last_page.body.contains("Second comment"));
        assert!(!last_page.body.contains("Third comment"));
        assert!(last_page.body.contains("\"discussion_version\":2"));
        assert!(last_page.body.contains("\"next_after\":null"));
        assert_eq!(token(&last_page), pinned);
        let current = get(client, COMMENTS, 'a'); // 16
        status(&current, 200);
        assert!(current.body.contains("\"discussion_version\":3"));
        assert!(current.body.contains("Third comment after close"));
        assert_eq!(
            post(
                client,
                1,
                "comments",
                'b',
                "first-comment",
                &first_form,
                false
            )
            .body,
            first.body
        ); // 17
        let metadata = get(client, "/api/v1/pulls/1", 'a'); // 18
        status(&metadata, 200);
        assert!(metadata.body.contains("\"version\":2"));
        assert!(metadata.body.contains("\"state\":\"closed\""));
        assert_eq!(server.finish().accepted_sessions(), 18);

        let node = reopen(&config);
        let before = generation(&node);
        let server = Server::start(node, &credentials, 2, true, true);
        assert_eq!(
            post(
                &server.client,
                1,
                "comments",
                'b',
                "first-comment",
                &first_form,
                false
            )
            .body,
            first.body
        );
        assert_eq!(get(&server.client, COMMENTS, 'a').body, current.body);
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before,
            "reads and exact retry never republish"
        );
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        assert_eq!(
            materialized.snapshot().refs.get(&data.source_ref),
            Some(&data.source_tip)
        );
        assert_eq!(
            materialized.snapshot().refs.get(&data.target_ref),
            Some(&data.target_tip)
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn hidden_refs_cancellation_and_stopped_intake_preserve_native_discussion_boundaries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        native_open(&node, &data);
        let first = native_comment(&node, "native-first", 0, "Retained comment").unwrap();
        assert!(matches!(first.1.outcome, DecisionOutcome::Committed { .. }));
        let page = node
            .runtime()
            .block_on(node.read_pull_request_comments_in(
                &node.request_context(),
                &RefVisibility::new(),
                PullRequestNumber::FIRST,
                0,
                10,
                None,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(page.comments.len(), 1);
        for hidden in [&data.source_ref, &data.target_ref] {
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
                        10,
                        Some(page.source_head),
                    ))
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            node.runtime()
                .block_on(node.read_pull_request_comments_in(
                    &node.request_context(),
                    &RefVisibility::new(),
                    PullRequestNumber::try_new(99).unwrap(),
                    0,
                    10,
                    None,
                ))
                .unwrap()
                .is_none()
        );
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(
            node.runtime()
                .block_on(node.read_pull_request_comments_in(
                    &cancelled,
                    &RefVisibility::new(),
                    PullRequestNumber::FIRST,
                    0,
                    10,
                    Some(page.source_head),
                ))
                .is_err()
        );
        let next = PullRequestCommentCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            body: "Cancelled comment".into(),
        };
        assert!(
            node.runtime()
                .block_on(node.admit_pull_request_comment_durable_in(
                    &cancelled,
                    &session("cancelled-comment"),
                    &next,
                    Default::default(),
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.read_pull_request_comments_in(
                    &node.request_context(),
                    &RefVisibility::new(),
                    PullRequestNumber::FIRST,
                    1,
                    10,
                    None,
                ))
                .is_err()
        );
        assert_eq!(
            native_comment(&node, "native-first", 0, "Retained comment").unwrap(),
            first
        );
        let before = generation(&node);
        node.shutdown().unwrap();

        let stopped = OneNode::open_existing(config).unwrap();
        assert_eq!(
            native_comment(&stopped, "native-first", 0, "Retained comment").unwrap(),
            first
        );
        assert!(native_comment(&stopped, "new-while-stopped", 1, "New comment").is_err());
        assert!(native_comment(&stopped, "native-first", 0, "Different bytes").is_err());
        assert_eq!(generation(&stopped), before);
        stopped.shutdown().unwrap();
    }
}

#[test]
fn comments_preserve_gateway_ceiling_bearer_only_and_cross_origin_boundaries() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, data) = fixture(&root, GitHashAlgorithm::Sha1);
    native_open(&node, &data);
    let credentials = root.0.join("credentials");
    grants(&node, &credentials);
    let body = comment_form(0, "Explicitly authorized comment");
    let disabled = Server::start(node, &credentials, 2, false, false);
    status(&get(&disabled.client, COMMENTS, 'a'), 403);
    status(
        &post(
            &disabled.client,
            1,
            "comments",
            'b',
            "disabled",
            &body,
            false,
        ),
        403,
    );
    assert_eq!(disabled.finish().accepted_sessions(), 2);

    let server = Server::start(reopen(&config), &credentials, 6, true, true);
    let client = &server.client;
    status(&get(client, COMMENTS, 'a'), 200); // 1
    status(
        &exchange(
            client,
            &request(
                client,
                "GET",
                COMMENTS,
                'a',
                "Idempotency-Key: read-key\r\n",
                &[],
            ),
            true,
        ),
        400,
    ); // 2
    let headers = format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
        body.len()
    );
    status(
        &exchange(
            client,
            &request(client, "POST", COMMENTS, 'b', &headers, body.as_bytes()),
            true,
        ),
        400,
    ); // 3
    let basic = String::from_utf8(request(client, "GET", COMMENTS, 'a', "", &[])).unwrap().replace(
        &format!("Bearer {}", "a".repeat(64)),
        "Basic dXNlcjphYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh",
    );
    status(&exchange(client, basic.as_bytes(), true), 401); // 4
    let cross_site =
        format!("{headers}Idempotency-Key: cross-site\r\nOrigin: https://foreign.invalid\r\n");
    status(
        &exchange(
            client,
            &request(client, "POST", COMMENTS, 'b', &cross_site, body.as_bytes()),
            true,
        ),
        403,
    ); // 5
    comment_committed(&post(client, 1, "comments", 'b', "permitted", &body, false)); // 6
    assert_eq!(server.finish().accepted_sessions(), 6);
}
