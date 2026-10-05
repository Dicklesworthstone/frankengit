use super::*;
use super::super::super::protocol::Server;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

fn fields<const N: usize>(values: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(values) else { unreachable!() };
    fields
}

#[test]
fn cursor_input_is_exact_and_does_not_require_a_snapshot_for_append_polling() {
    let first = parse(&Object::new()).unwrap();
    assert_eq!(first.after, None);
    assert_eq!(first.limit, 20);
    assert_eq!(first.expected_head, None);
    let last = parse(&fields([
        ("after", text("18446744073709551615:4294967295")),
        ("limit", json::number(100)),
    ])).unwrap();
    assert_eq!(last.after, Some((u64::MAX, u32::MAX)));
    assert_eq!(last.limit, 100);
    assert_eq!(cursor(last.after).text(), Some("18446744073709551615:4294967295"));
    assert_eq!(cursor(None), Value::Null);
    for value in [text("01:0"), text("0:0"), text("1:4294967296"), text("1:0:1"),
        text("1e3:0"), text("18446744073709551616:0"), json::number(1), Value::Null]
    {
        assert!(parse(&fields([("after", value)])).is_err());
    }
    assert!(parse(&fields([("after", text("1:0")), ("limit", json::number(1))])).is_ok());
}

#[test]
fn unknown_authority_fields_and_out_of_profile_requests_never_become_options() {
    for name in ["principal", "storage", "tenant_id", "repository_id", "issues_read", "kind", "wait_ms"] {
        assert!(parse(&fields([(name, text("anything"))])).is_err(), "{name}");
    }
    for value in [json::number(0), json::number(101), json::number(u64::MAX), text("20"),
        Value::Number("1.0".into()), Value::Bool(true)]
    {
        assert!(parse(&fields([("limit", value)])).is_err());
    }
    for value in [text("head"), text("alg:01:aa"), text("alg:1:GG"), Value::Null] {
        assert!(parse(&fields([("expected_head", value)])).is_err());
    }
    let valid = fields([
        ("after", text("1:0")),
        ("expected_head", text(format!("alg:1:{}", "ab".repeat(32)))),
    ]);
    assert!(parse(&valid).is_ok());
    let schema = tool().schema;
    assert_eq!(schema.object().unwrap()["additionalProperties"], Value::Bool(false));
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-mcp-events-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"), TenantId::from_bytes([0xb1; 16]), RepositoryId::from_bytes([0xb2; 16]),
        ).with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn actor() -> PrincipalId { PrincipalId::from_bytes([0xb3; 16]) }
fn command(version: u64, body: &str) -> IssueCommand {
    IssueCommand {
        number: IssueNumber::try_new(1).unwrap(),
        expected_version: if version == 0 { ExpectedVersion::NewStream } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action: if version == 0 {
            IssueAction::Open { title: "Event source".into(), body: body.into(), labels: vec![] }
        } else { IssueAction::Comment { body: body.into() } },
    }
}
fn publish(node: &OneNode, command: &IssueCommand, key: &str) {
    let request = fgit_cli::command_request_context(node);
    let session = LoopbackReceiveSession::authenticated(
        actor(), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    );
    let (_, terminal) = node.runtime().block_on(node.admit_issue_durable_in(
        &request, &session, command, Default::default(),
    )).unwrap();
    assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
}
fn open(scratch: &Scratch, format: GitHashAlgorithm, body: &str) -> NodeTools {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    publish(&node, &command(0, body), "open");
    publish(&node, &command(1, "second"), "comment");
    // Retrying identical semantics must not append a second canonical event.
    publish(&node, &command(1, "second"), "comment");
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    NodeTools::open(Options {
        storage: scratch.0.join("node"), tenant: TenantId::from_bytes([0xb1; 16]),
        repository: RepositoryId::from_bytes([0xb2; 16]), format, incarnation: Some(incarnation),
        issues: true, pulls: false, source: false, writes: Default::default(), outcomes: false,
        principal: None, max_messages: 64,
    }).unwrap()
}
fn result(value: &Value) -> &Object {
    value.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap()
}
fn events(value: &Value) -> &[Value] {
    let Value::Array(events) = &value.object().unwrap()["events"] else { unreachable!() };
    events
}

#[test]
fn persisted_protocol_feed_matches_canonical_frames_and_resumes_after_restart_and_append() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut backend = open(&scratch, format, "{\"principal\":\"admin\"} is data");
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"event-test","version":"1"}}}"#).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let first = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_events","arguments":{"limit":1}}}"#).unwrap();
        let first = result(&first);
        let pin = first["snapshot_token"].clone();
        let after = first["next_after"].clone();
        assert_ne!(after, Value::Null);
        assert_eq!(first["read_only"], Value::Bool(true));
        assert!(!backend.is_mutation(NAME));
        let second = backend.call(NAME, &fields([
            ("after", after), ("expected_head", pin.clone()), ("limit", json::number(1)),
        ])).unwrap();
        assert_eq!(events(&second).len(), 1);
        let second_fields = second.object().unwrap();
        assert_eq!(second_fields["next_after"], Value::Null);
        let resume = second_fields["resume_after"].clone();
        let all = backend.call(NAME, &Object::new()).unwrap();
        assert_eq!(events(&all).len(), 2);
        let request = fgit_cli::command_request_context(&backend.node);
        let raw = backend.node.runtime().block_on(backend.node.read_forge_events_in(
            &request, None, 20, Some(parse_head(pin.text().unwrap()).unwrap()),
        )).unwrap();
        for (actual, canonical) in events(&all).iter().zip(&raw.events) {
            assert_eq!(actual.object().unwrap()["event_frame_hex"].text(),
                Some(hex(&fgit_codec::encode_body(&canonical.event).unwrap()).as_str()));
        }
        let shared = backend.node.runtime().block_on(backend.node.read_scoped_forge_events_in(
            &request, None, 20, Some(raw.source_head), true, false,
        )).unwrap();
        // A small fixture lets the request parser compare representations; the
        // production handler never parses a large result with request limits.
        assert_eq!(all, json::parse(shared.to_json().unwrap().as_bytes()).unwrap());
        let options = backend.options.clone();
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        let eof = backend.call(NAME, &fields([("after", resume.clone())])).unwrap();
        assert!(events(&eof).is_empty());
        assert_eq!(eof.object().unwrap()["resume_after"], resume);
        publish(&backend.node, &command(2, "third"), "append");
        let old = fields([("after", resume.clone()), ("expected_head", pin)]);
        assert_eq!(backend.call(NAME, &old).unwrap_err().code, "snapshot_moved");
        let advanced = backend.call(NAME, &fields([("after", resume)])).unwrap();
        assert_eq!(events(&advanced).len(), 1);
        assert_eq!(events(&advanced)[0].object().unwrap()["aggregate_version"].text(), Some("3"));
        let pin = advanced.object().unwrap()["snapshot_token"].clone();
        assert!(backend.call(NAME, &fields([("after", text("999:0"))])).is_err());
        assert!(backend.call(NAME, &fields([("expected_head", pin)])).is_ok(), "reads must not publish");
        backend.close().unwrap();
    }
}

#[test]
fn independent_read_grants_filter_before_disclosure_and_do_not_break_the_full_registry() {
    let scratch = Scratch::new();
    let mut backend = open(&scratch, GitHashAlgorithm::Sha1, "private issue text");
    let visible = backend.call(NAME, &fields([("limit", json::number(1))])).unwrap();
    backend.options.issues = false;
    backend.options.pulls = true;
    let hidden = backend.call(NAME, &fields([("limit", json::number(1))])).unwrap();
    assert!(events(&hidden).is_empty());
    assert_eq!(hidden.object().unwrap()["next_after"], visible.object().unwrap()["next_after"]);
    assert!(!hidden.encode(8192).unwrap().contains(&hex(b"private issue text")));
    let next = backend.call(NAME, &fields([("after", hidden.object().unwrap()["next_after"].clone())])).unwrap();
    assert!(events(&next).is_empty());
    assert_eq!(next.object().unwrap()["next_after"], Value::Null);
    backend.options.pulls = false;
    backend.options.writes.issues = true;
    backend.options.principal = Some(actor());
    assert!(backend.tools().iter().all(|tool| tool.name != NAME));
    assert_eq!(backend.call(NAME, &Object::new()).unwrap_err().code, "tool_not_granted");
    assert_eq!(call(&backend, &fields([("principal", text("admin"))])).unwrap_err().code, "tool_not_granted");
    let request = fgit_cli::command_request_context(&backend.node);
    assert_eq!(backend.node.runtime().block_on(backend.node.read_scoped_forge_events_in(
        &request, Some((0, 0)), 0, None, false, false,
    )).unwrap_err().public_code(), "events_not_granted");
    backend.options.issues = true;
    backend.options.pulls = true;
    backend.options.source = true;
    backend.options.writes.pulls = true;
    backend.options.writes.source = true;
    backend.options.writes.reviews = true;
    backend.options.writes.merges = true;
    backend.options.outcomes = true;
    assert!(backend.options.validate_access().is_ok());
    assert!(Server::new(&backend).is_ok());
    assert_eq!(backend.tools().iter().filter(|tool| tool.name == NAME).count(), 1);
    assert!(backend.call(NAME, &Object::new()).is_ok());
    backend.close().unwrap();
}

#[test]
fn result_frames_larger_than_request_string_limits_do_not_weaken_request_parsing() {
    let scratch = Scratch::new();
    let mut backend = open(&scratch, GitHashAlgorithm::Sha256, &"x".repeat(20 * 1024));
    let page = backend.call(NAME, &fields([("limit", json::number(1))])).unwrap();
    let frame = events(&page)[0].object().unwrap()["event_frame_hex"].text().unwrap();
    assert!(frame.len() > 16 * 1024);
    assert!(page.encode(super::super::super::protocol::MAX_TOOL_RESULT).is_ok());
    let hostile = object([("after", text("x".repeat(20 * 1024)))]).encode(64 * 1024).unwrap();
    assert!(json::parse(hostile.as_bytes()).is_err());
    backend.close().unwrap();
}
