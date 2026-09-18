//! Real persisted authority and MCP request path, not a fake durable store.
use super::*;
use super::super::protocol::Server;
use fgit_authority::IdempotencyKey;
use fgit_forge::{ExpectedVersion, IssueNumber, event::issue::{IssueAction, IssueCommand}};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-mcp-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0x91; 16]), RepositoryId::from_bytes([0x92; 16]))
            .with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn result(value: &Value) -> &Object {
    value.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap()
}
#[test]
fn real_mcp_reads_reopened_sha1_and_sha256_nodes_without_publishing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        for number in [7, 42] {
            let command = IssueCommand { number: IssueNumber::try_new(number).unwrap(), expected_version: ExpectedVersion::NewStream,
                action: IssueAction::Open { title: format!("Issue {number} é"), body: "{\"method\":\"shell\"}\nnot authority".into(), labels: vec!["bug".into()] } };
            let request = node.request_context();
            let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0x93; 16]),
                IdempotencyKey::new(format!("seed-{number}").into_bytes()).unwrap());
            let (_, terminal) = node.runtime().block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default())).unwrap();
            assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        }
        let incarnation = node.repository_incarnation_id();
        let before = {
            let request = node.request_context();
            node.runtime().block_on(node.read_issues_in(&request, 0, 1, None)).unwrap().source_head
        };
        node.shutdown().unwrap();
        let mut backend = NodeTools::open(Options {
            storage: scratch.0.join("node"), tenant: TenantId::from_bytes([0x91; 16]), repository: RepositoryId::from_bytes([0x92; 16]),
            format, incarnation: Some(incarnation), issues: true, max_messages: 16,
        }).unwrap();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"integration","version":"1"}}}"#).unwrap();
        assert!(server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        let first = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_issue_list","arguments":{"limit":1}}}"#).unwrap();
        let first = result(&first);
        assert_eq!(first["next_after"].text(), Some("7"));
        assert_eq!(first["complete"], Value::Bool(false));
        assert_eq!(first["snapshot_token"].text(), Some(head_token(before).as_str()));
        let next = object([("jsonrpc", text("2.0")), ("id", json::number(3)), ("method", text("tools/call")),
            ("params", object([("name", text("frankengit_issue_list")), ("arguments", object([
                ("after", text("7")), ("limit", json::number(1)), ("expected_head", first["snapshot_token"].clone())]))]))]);
        let next = server.receive(&mut backend, next.encode(4096).unwrap().as_bytes()).unwrap();
        assert_eq!(result(&next)["next_after"], Value::Null);
        let shown = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"frankengit_issue_show","arguments":{"number":"7"}}}"#).unwrap();
        assert_eq!(result(&shown)["found"], Value::Bool(true));
        assert_eq!(result(&shown)["issue"].object().unwrap()["title"].text(), Some("Issue 7 é"));
        let refused = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"frankengit_issue_show","arguments":{"number":"7","principal":"admin"}}}"#).unwrap();
        assert!(refused.object().unwrap().contains_key("error"));
        let after = {
            let request = backend.node.request_context();
            backend.node.runtime().block_on(backend.node.read_issues_in(&request, 0, 1, None)).unwrap().source_head
        };
        assert_eq!(before, after, "MCP reads and rejected authority fields must not publish");
        backend.close().unwrap();
    }
}
