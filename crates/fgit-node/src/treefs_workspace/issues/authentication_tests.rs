//! Actual HTTP metadata publication retains credential evidence after restart.
//! Reuse the existing native-object fixture and TCP client, with no substitute
//! projection, authority, HTTP parser, or public evidence-access test hook.

#[path = "../../../tests/pull_request_http/support.rs"]
mod http;

use crate::{GitDaemonServerLimits, LoopbackReceiveSession, OneNode};
use fgit_admission::evidence::{
    AdmissionAuthentication, PolicyDecisionRecord, PrincipalSnapshotRecord,
};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_codec::RepositoryCommitRecord;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection, compile_ref_policy};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_types::{DecisionOutcome, Digest, GitHashAlgorithm, TxId};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

const MFA_POLICY: &str = "policy code_credentials { rule credential { when actor.authentication >= multi_factor then allow } default deny \"MFA required for code publication\" }";
const SCOPES: &str = "issues-read,issues-write,pulls-read,pulls-write,protection-read,protection-write,outcomes-read";
const ISSUE_OPEN_KEY: &str = "metadata-http-issue-open";

fn operator(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        http::OWNER,
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}

fn issue(number: u64, title: &str, body: &str) -> IssueCommand {
    IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: title.into(),
            body: body.into(),
            labels: Vec::new(),
        },
    }
}

fn publish_operator_issue(
    node: &OneNode,
    key: &str,
    command: &IssueCommand,
) -> (TxId, TerminalOutcome) {
    let result = node
        .runtime()
        .block_on(node.admit_issue_durable_in(
            &node.request_context(),
            &operator(key),
            command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    result
}

fn install_ref_policy(node: &OneNode) -> u64 {
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: selected.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![http::OWNER],
            branches: Vec::new(),
            ref_policy: Some(compile_ref_policy(MFA_POLICY).unwrap()),
        },
    };
    let result = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &operator("metadata-policy-bootstrap"),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    selected.policy_epoch.next().unwrap().get()
}

fn serve_batch(
    node: &OneNode,
    credentials: &Path,
    commands: &[(&str, &str, &str, char)],
) -> Vec<http::Reply> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = http::Endpoint {
        address: listener.local_addr().unwrap(),
        route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap(),
    };
    std::thread::scope(|scope| {
        // Keep the node on its owner thread; only the real TCP client is moved.
        let client = scope.spawn(move || {
            commands
                .iter()
                .map(|(path, key, body, token)| {
                    let headers = format!(
                        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n",
                        body.len()
                    );
                    http::exchange(
                        &endpoint,
                        &http::request(&endpoint, "POST", path, *token, &headers, body.as_bytes()),
                        true,
                    )
                })
                .collect::<Vec<_>>()
        });
        let served = node
            .serve_repository_http_with_pull_requests_bounded(
                &listener,
                GitDaemonServerLimits::try_new(commands.len(), 1).unwrap(),
                credentials,
                false,
                true,
                true,
                Duration::from_secs(5),
            )
            .unwrap();
        let replies = client.join().unwrap();
        assert_eq!(served.accepted_sessions(), commands.len());
        replies
    })
}

fn transaction(reply: &http::Reply) -> &str {
    reply
        .body
        .split_once("\"tx_id\":\"")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}

fn records(node: &OneNode) -> BTreeMap<String, RepositoryCommitRecord> {
    node.runtime()
        .block_on(node.snapshot_history_in(&node.request_context()))
        .unwrap()
        .into_iter()
        .flat_map(|batch| batch.batch.committed_rcrs)
        .map(|record| (record.tx_id.to_string(), record))
        .collect()
}

fn assert_authentication(
    node: &OneNode,
    record: &RepositoryCommitRecord,
    authentication: AdmissionAuthentication,
) {
    let request = node.request_context();
    let identity = record.principal_snapshot_id.as_internal_object_id();
    let principal = node
        .runtime()
        .block_on(crate::read_principal_snapshot_in(
            &node.authority,
            request.authority(),
            node.repository_id,
            Digest::new(identity.algorithm(), *identity.digest()),
            &|| false,
        ))
        .unwrap();
    assert!(matches!(
        principal,
        PrincipalSnapshotRecord::Authenticated(_)
    ));
    assert_eq!(principal.authentication(), Some(authentication));
    let policy = node
        .runtime()
        .block_on(crate::read_policy_decision_in(
            &node.authority,
            request.authority(),
            node.repository_id,
            record.policy_decision_root,
            &|| false,
        ))
        .unwrap();
    // Metadata retains its request/principal policy commitment; it must not
    // fabricate an evaluation of the repository's code-publication predicate.
    assert!(matches!(policy, PolicyDecisionRecord::Legacy(_)));
}

#[test]
fn metadata_http_authentication_is_durable_for_all_owners_and_historical_retries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = http::Scratch::new();
        let config = root.config(format).with_http_protection_admin();
        let (node, data) = http::fixture(&root, format);
        node.shutdown().unwrap();
        let node = http::reopen(&config);
        let epoch = install_ref_policy(&node);
        let local = publish_operator_issue(
            &node,
            "metadata-local-before-http",
            &issue(42, "Local issue", "Operator assertion"),
        );
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let original_refs = before.snapshot().refs.clone();
        drop(before);

        let credentials = root.0.join("credentials");
        let header = http::header(&node);
        http::replace(
            &credentials,
            &(header.clone() + &http::row('a', http::OWNER, SCOPES)),
        );
        let issue_body = "expected_version=0&title=Remote+issue&body=Authenticated+metadata";
        let pull_body = http::form(&data, 0);
        let policy_body = format!(
            "expected_version=1&expected_epoch={epoch}&administrator={}&ref_policy_source={}",
            http::OWNER,
            http::encode(MFA_POLICY.as_bytes())
        );
        let commands = [
            ("/api/v1/issues/1/open", ISSUE_OPEN_KEY, issue_body, 'a'),
            (
                "/api/v1/issues/1/comment",
                "metadata-issue-comment",
                "expected_version=1&body=Exact",
                'a',
            ),
            (
                "/api/v1/issues/1/append-comment",
                "metadata-issue-append",
                "body=Append",
                'a',
            ),
            (
                "/api/v1/pulls/1/open",
                "metadata-pull-open",
                pull_body.as_str(),
                'a',
            ),
            (
                "/api/v1/pulls/1/comments",
                "metadata-pull-comment",
                "expected_version=0&body=Exact",
                'a',
            ),
            (
                "/api/v1/pulls/1/comments/append",
                "metadata-pull-append",
                "body=Append",
                'a',
            ),
            (
                "/api/v1/protection",
                "metadata-policy-replace",
                policy_body.as_str(),
                'a',
            ),
            (
                "/api/v1/issues/1/comment",
                "metadata-stale-comment",
                "expected_version=1&body=Stale",
                'a',
            ),
        ];
        let replies = serve_batch(&node, &credentials, &commands);
        for reply in &replies[..7] {
            http::status(reply, 200);
            assert!(
                reply.body.contains("\"outcome\":\"committed\""),
                "{}",
                reply.body
            );
        }
        http::status(&replies[7], 409);
        assert!(replies[7].body.contains("\"outcome\":\"refused\""));
        node.shutdown().unwrap();

        let node = http::reopen(&config);
        let original_records = records(&node);
        assert_authentication(
            &node,
            &original_records[&local.0.to_string()],
            AdmissionAuthentication::OperatorAssertion,
        );
        for reply in &replies[..7] {
            assert_authentication(
                &node,
                &original_records[transaction(reply)],
                AdmissionAuthentication::HttpToken,
            );
        }
        let current = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(current.snapshot().refs, original_refs);
        drop(current);

        // The same principal supplied by an operator recovers the original
        // terminal; it cannot relabel its persisted HTTP authentication fact.
        let before_retry = http::generation(&node);
        let recovered = publish_operator_issue(
            &node,
            ISSUE_OPEN_KEY,
            &issue(1, "Remote issue", "Authenticated metadata"),
        );
        assert_eq!(recovered.0.to_string(), transaction(&replies[0]));
        assert_eq!(http::generation(&node), before_retry);
        http::replace(
            &credentials,
            &(header + &http::row('b', http::OWNER, SCOPES)),
        );
        let retried = serve_batch(
            &node,
            &credentials,
            &[
                ("/api/v1/issues/1/open", ISSUE_OPEN_KEY, issue_body, 'a'),
                ("/api/v1/issues/1/open", ISSUE_OPEN_KEY, issue_body, 'b'),
                (
                    "/api/v1/issues/1/comment",
                    "metadata-stale-comment",
                    "expected_version=1&body=Stale",
                    'b',
                ),
            ],
        );
        http::status(&retried[0], 401);
        assert_eq!(retried[1], replies[0]);
        assert_eq!(retried[2], replies[7]);
        assert_eq!(http::generation(&node), before_retry);

        let fresh = publish_operator_issue(
            &node,
            "metadata-local-after-http",
            &issue(43, "Fresh local issue", "No credential proof"),
        );
        let after = records(&node);
        for reply in &replies[..7] {
            assert_eq!(
                after[transaction(reply)],
                original_records[transaction(reply)]
            );
        }
        assert_authentication(
            &node,
            &after[&fresh.0.to_string()],
            AdmissionAuthentication::OperatorAssertion,
        );
        node.shutdown().unwrap();
    }
}
