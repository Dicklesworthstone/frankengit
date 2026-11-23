#![forbid(unsafe_code)]
//! Authenticated symbolic HEAD administration over the production TCP listener.
//! Real imports, persisted policy, original-key retries and reopen are exercised.

#[path = "source_http/support.rs"]
mod support;

use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::ExpectedVersion;
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use fgit_wire::visibility::RefVisibility;
use support::*;

const PATH: &str = "/api/v1/default-branch";
const RELEASE: &[u8] = b"refs/heads/release\xff";

fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(key.to_vec()).unwrap())
}
fn install_policy(node: &OneNode) {
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: before.policy_epoch,
        protection: ReviewProtection {
            ref_policy: None,
            administrators: vec![OWNER],
            branches: Vec::new(),
        },
    };
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &session(b"default-http-policy"),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}
fn create_release(node: &OneNode, tip: GitOid) {
    let commands = [RefCommand {
        name: RefName::try_new(RELEASE).unwrap(),
        expected_old: ExpectedOld::Absent,
        proposed_new: ProposedNew::Update(tip),
        force: false,
    }];
    let result = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session(b"default-http-branch"),
            &commands,
            Default::default(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
}
fn get(client: &Endpoint, token: char, query: &str) -> Reply {
    exchange(
        client,
        format!(
            "GET {}{PATH}{query} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n\r\n",
            client.route,
            token.to_string().repeat(64),
        )
        .as_bytes(),
        true,
    )
}
fn command(old: &[u8], new: &[u8], tip: GitOid) -> String {
    format!(
        "expected_default_hex={}&reference_hex={}&expected_tip={tip}",
        hex(old),
        hex(new)
    )
}
fn set(client: &Endpoint, token: char, key: Option<&str>, form: &str, extra: &str) -> Reply {
    let key = key.map_or(String::new(), |key| format!("Idempotency-Key: {key}\r\n"));
    let headers = format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{key}{extra}",
        form.len()
    );
    exchange(
        client,
        &request(client, PATH, token, &headers, form.as_bytes()),
        true,
    )
}
fn assert_committed(reply: &Reply) {
    status(reply, 200);
    assert_eq!(text(&reply.body, "type"), "default_branch_publication");
    assert_eq!(text(&reply.body, "outcome"), "committed");
    assert_eq!(text(&reply.body, "authentication"), "http-token");
    assert!(reply.body.contains("\"direct_refs_changed\":false"));
    assert!(reply.body.contains("\"head_changed_by_transaction\":true"));
}

#[test]
fn administrator_changes_clone_head_with_exact_tips_and_recovers_after_later_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format).with_http_default_branch_admin();
        let (node, tip) = fixture_with_config(&root, format, config.clone());
        create_release(&node, tip);
        install_policy(&node);
        let file = root.0.join("credentials");
        let header = credentials(&node, &file);
        replace(
            &file,
            &(header
                + &row('a', OWNER, "read,outcomes-read,default-branch-write")
                + &row('b', FOREIGN, "read,default-branch-write")
                + &row('c', OWNER, "read,receive,protection-write")),
        );
        let server = Server::start(node, &file, 12, true, false);
        let before = get(&server.client, 'a', "");
        status(&before, 200);
        assert_eq!(
            text(&before.body, "default_reference_hex"),
            hex(b"refs/heads/main")
        );
        assert_eq!(text(&before.body, "tip"), tip.to_string());
        assert_eq!(text(&before.body, "principal_id"), OWNER.to_string());
        let body = command(b"refs/heads/main", RELEASE, tip);
        let no_grant = set(
            &server.client,
            'c',
            Some("forbidden"),
            &body,
            "Expect: 100-continue\r\n",
        );
        status(&no_grant, 403);
        assert!(!no_grant.raw.contains("100 Continue"));
        let foreign = set(&server.client, 'b', Some("not-admin"), &body, "");
        status(&foreign, 409);
        assert_eq!(text(&foreign.body, "code"), "PublicationPolicyRefused");
        status(&set(&server.client, 'a', None, &body, ""), 400);
        let headers = format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: truncated\r\n",
            body.len() + 1
        );
        status(
            &exchange(
                &server.client,
                &request(&server.client, PATH, 'a', &headers, body.as_bytes()),
                true,
            ),
            400,
        );
        let changed = set(&server.client, 'a', Some("select-release"), &body, "");
        assert_committed(&changed);
        assert_eq!(text(&changed.body, "default_reference_hex"), hex(RELEASE));
        assert_eq!(
            set(&server.client, 'a', Some("select-release"), &body, "").body,
            changed.body
        );
        let pinned = format!("?expected_head={}", text(&before.body, "snapshot_token"));
        status(&get(&server.client, 'a', &pinned), 409);
        let after = get(&server.client, 'a', "");
        status(&after, 200);
        assert_eq!(text(&after.body, "default_reference_hex"), hex(RELEASE));
        assert_eq!(text(&after.body, "tip"), tip.to_string());
        let back = command(RELEASE, b"refs/heads/main", tip);
        let reused = set(&server.client, 'a', Some("select-release"), &back, "");
        status(&reused, 409);
        assert_eq!(text(&reused.body, "code"), "idempotency_key_reuse");
        assert_committed(&set(&server.client, 'a', Some("restore-main"), &back, ""));
        assert_eq!(
            set(&server.client, 'a', Some("select-release"), &body, "").body,
            changed.body
        );
        assert_eq!(server.finish().accepted_sessions(), 12);
        let node = reopen(&config);
        let (_, target, selected_tip) = node
            .runtime()
            .block_on(node.read_default_branch_in(&node.request_context(), &RefVisibility::new()))
            .unwrap();
        assert_eq!(target.unwrap().as_bytes(), b"refs/heads/main");
        assert_eq!(selected_tip, Some(tip));
        node.shutdown().unwrap();
    }
}

#[test]
fn dedicated_grant_neither_enables_the_gateway_nor_bootstraps_administrator_ownership() {
    for enabled in [false, true] {
        let root = Scratch::new();
        let mut config = root.config(GitHashAlgorithm::Sha256);
        if enabled {
            config = config.with_http_default_branch_admin();
        }
        let (node, tip) = fixture_with_config(&root, GitHashAlgorithm::Sha256, config.clone());
        let before = generation(&node);
        let file = root.0.join("credentials");
        let header = credentials(&node, &file);
        replace(
            &file,
            &(header + &row('a', OWNER, "read,default-branch-write")),
        );
        let server = Server::start(node, &file, 2, true, false);
        status(&get(&server.client, 'a', ""), 200);
        let reply = set(
            &server.client,
            'a',
            Some("cannot-bootstrap"),
            &command(b"refs/heads/main", b"refs/heads/main", tip),
            "",
        );
        status(&reply, if enabled { 409 } else { 403 });
        if enabled {
            assert_eq!(text(&reply.body, "code"), "PublicationPolicyRefused");
        }
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + u64::from(enabled));
        let (_, target, _) = node
            .runtime()
            .block_on(node.read_default_branch_in(&node.request_context(), &RefVisibility::new()))
            .unwrap();
        assert_eq!(target.unwrap().as_bytes(), b"refs/heads/main");
        node.shutdown().unwrap();
    }
}

#[test]
fn unborn_default_is_readable_without_administrator_enablement_or_publication() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (mut node, _) = OneNode::init(config.clone()).unwrap();
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(selected.receipt().generation())
        .unwrap();
    let before = generation(&node);
    let file = root.0.join("credentials");
    credentials(&node, &file);
    let server = Server::start(node, &file, 3, true, false);
    let read = get(&server.client, 'a', "");
    status(&read, 200);
    assert_eq!(
        text(&read.body, "default_reference_hex"),
        hex(b"refs/heads/main")
    );
    assert!(read.body.contains("\"tip\":null,\"unborn\":true"));
    assert!(read.body.contains("\"transaction_created\":false"));
    status(&get(&server.client, 'b', ""), 403);
    status(&get(&server.client, 'a', "?principal_id=forged"), 400);
    server.finish();
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
