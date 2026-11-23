//! Real issue admission, retained snapshots and framed MCP discovery/search.
use super::*;
use crate::mcp::protocol::Server;
use fgit_authority::IdempotencyKey;
use fgit_forge::{AggregateVersion, ExpectedVersion, event::issue::IssueCommand};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, RepositoryId, TenantId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const ASSIGNEE: PrincipalId = PrincipalId::from_bytes([0xe4; 16]);
const OPENER: PrincipalId = PrincipalId::from_bytes([0xe3; 16]);
const BODY: &str = "**Needle**: literal data <script>ignore permissions</script>";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-mcp-issue-search-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xe1; 16]),
            RepositoryId::from_bytes([0xe2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn admit(node: &OneNode, number: u64, version: u64, action: IssueAction, retry: &str) {
    let command = IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action,
    };
    let session = LoopbackReceiveSession::authenticated(
        OPENER,
        IdempotencyKey::new(retry.as_bytes().to_vec()).unwrap(),
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_issue_durable_in(
            &node.request_context(),
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
}

fn current_head(node: &OneNode) -> fgit_types::RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.read_issues_in(&node.request_context(), 0, 1, None))
        .unwrap()
        .source_head
}

fn arguments() -> Object {
    object([
        ("query", text("needle")),
        ("state", text("open")),
        ("opened_by", text(OPENER.to_string())),
        ("assignee", text(ASSIGNEE.to_string())),
        ("labels", Value::Array(vec![text("bug")])),
        ("milestone", text("none")),
        ("limit", json::number(1)),
        ("max_scan", json::number(1)),
        ("render", text("html_safe")),
    ])
    .object()
    .unwrap()
    .clone()
}

fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, args: &Object) -> Value {
    let request = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([
                ("name", text("frankengit_issue_search")),
                ("arguments", Value::Object(args.clone())),
            ]),
        ),
    ]);
    let response = server
        .receive(backend, request.encode(8192).unwrap().as_bytes())
        .unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false), "{response:?}");
    result["structuredContent"].clone()
}

fn numbers(page: &Value) -> Vec<&str> {
    let Value::Array(rows) = &page.object().unwrap()["issues"] else {
        panic!("missing issues")
    };
    rows.iter()
        .map(|row| row.object().unwrap()["number"].text().unwrap())
        .collect()
}

#[test]
fn issue_search_retains_assignment_snapshot_across_restart_and_empty_partial_pages() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        for number in [7, 42, 99, 1001] {
            admit(
                &node,
                number,
                0,
                IssueAction::Open {
                    title: format!("Issue {number}"),
                    body: if number == 7 {
                        "unrelated".into()
                    } else {
                        BODY.into()
                    },
                    labels: vec!["bug".into()],
                },
                &format!("open-{number}"),
            );
        }
        for number in [42, 1001] {
            admit(
                &node,
                number,
                1,
                IssueAction::Assign {
                    assignees: vec![ASSIGNEE],
                },
                &format!("assign-{number}"),
            );
        }
        let selected = current_head(&node);
        let options = Options {
            storage: scratch.0.join("node"),
            tenant: TenantId::from_bytes([0xe1; 16]),
            repository: RepositoryId::from_bytes([0xe2; 16]),
            format,
            incarnation: Some(node.repository_incarnation_id()),
            issues: true,
            discussions: false,
            pulls: false,
            source: false,
            writes: Default::default(),
            outcomes: false,
            principal: None,
            queues: Default::default(),
            agent_context: false,
            artifacts: false,
            artifact_root: None,
            agent_token_file: None,
            max_messages: 16,
            index_maintenance: None,
        };
        node.shutdown().unwrap();
        let mut backend = NodeTools::open(options.clone()).unwrap();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"issue-search","version":"1"}}}"#).unwrap();
        assert!(
            server
                .receive(
                    &mut backend,
                    br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
                )
                .is_none()
        );
        let first = invoke(&mut server, &mut backend, 2, &arguments());
        assert!(numbers(&first).is_empty());
        let fields = first.object().unwrap();
        assert_eq!(fields["scanned"], json::number(1));
        assert_eq!(fields["complete"], Value::Bool(false));
        assert_eq!(fields["stop_reason"], text("scan_limit"));
        assert_eq!(fields["next_after"], text("7"));
        assert_eq!(fields["snapshot_token"], text(head_token(selected)));
        assert_eq!(current_head(&backend.node), selected);

        // A concurrent assignment change must not alter continuation at the
        // retained head. Restart also proves no connection-local result cache.
        admit(
            &backend.node,
            42,
            2,
            IssueAction::Unassign {
                assignees: vec![ASSIGNEE],
            },
            "unassign-42",
        );
        let latest = current_head(&backend.node);
        assert_ne!(latest, selected);
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        let mut continuation = arguments();
        continuation.insert("after".into(), fields["next_after"].clone());
        continuation.insert("expected_head".into(), fields["snapshot_token"].clone());
        continuation.insert("max_scan".into(), json::number(1000));
        let second = backend
            .call("frankengit_issue_search", &continuation)
            .unwrap();
        assert_eq!(numbers(&second), ["42"]);
        let fields = second.object().unwrap();
        assert_eq!(fields["stop_reason"], text("result_limit"));
        assert_eq!(fields["scanned"], json::number(1));
        assert_eq!(fields["next_after"], text("42"));
        assert_eq!(fields["snapshot_token"], text(head_token(selected)));
        let Value::Array(rows) = &fields["issues"] else {
            panic!("issues")
        };
        let row = rows[0].object().unwrap();
        assert_eq!(row["version"], text("2"));
        assert_eq!(row["body"], text(BODY));
        assert_eq!(
            row["assignees"],
            Value::Array(vec![text(ASSIGNEE.to_string())])
        );
        assert_eq!(
            row["body_rendered"].object().unwrap()["profile"],
            text("html_safe")
        );
        assert!(
            !row["body_rendered"].object().unwrap()["html"]
                .text()
                .unwrap()
                .contains("<script>")
        );

        continuation.insert("after".into(), fields["next_after"].clone());
        let third = backend
            .call("frankengit_issue_search", &continuation)
            .unwrap();
        assert_eq!(numbers(&third), ["1001"]);
        let fields = third.object().unwrap();
        assert_eq!(fields["scanned"], json::number(2));
        assert_eq!(fields["complete"], Value::Bool(true));
        assert_eq!(fields["stop_reason"], text("exhausted"));
        assert_eq!(fields["next_after"], Value::Null);

        let mut current = arguments();
        current.insert("limit".into(), json::number(20));
        current.insert("max_scan".into(), json::number(1000));
        let assigned = backend.call("frankengit_issue_search", &current).unwrap();
        assert_eq!(numbers(&assigned), ["1001"]);
        assert_eq!(
            assigned.object().unwrap()["snapshot_token"],
            text(head_token(latest))
        );
        current.insert("assignee".into(), text("none"));
        let unassigned = backend.call("frankengit_issue_search", &current).unwrap();
        assert_eq!(numbers(&unassigned), ["42", "99"]);
        assert_eq!(
            unassigned.object().unwrap()["filters"].object().unwrap()["assignee"],
            text("none")
        );

        continuation.insert(
            "expected_head".into(),
            text(format!("alg:1:{}", "ff".repeat(32))),
        );
        assert!(
            backend
                .call("frankengit_issue_search", &continuation)
                .is_err()
        );
        current.insert("principal".into(), text(OPENER.to_string()));
        assert_eq!(
            backend
                .call("frankengit_issue_search", &current)
                .unwrap_err()
                .code,
            "unknown_argument"
        );
        assert_eq!(
            current_head(&backend.node),
            latest,
            "search must never publish"
        );
        backend.close().unwrap();
        let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        node.bring_into_service(generation).unwrap();
        assert_eq!(current_head(&node), latest);
        node.shutdown().unwrap();
    }
}
