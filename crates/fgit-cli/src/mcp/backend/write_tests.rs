//! Canonical mutation and recovery on real reopened nodes. The stdio writer
//! fault below loses a real committed reply, not a simulated database result.
use super::super::protocol::{self, Server};
use super::*;
use fgit_types::{
    GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::{
    fs,
    io::{self, Cursor, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"write-test","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
struct Fixture {
    root: PathBuf,
    format: GitHashAlgorithm,
    incarnation: RepositoryIncarnationId,
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-writes-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let config = NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xa2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        node.shutdown().unwrap();
        Self {
            root,
            format,
            incarnation,
        }
    }
    fn config(&self) -> NodeConfig {
        NodeConfig::new(
            self.root.join("node"),
            TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xa2; 16]),
        )
        .with_object_format(self.format)
        .with_worker_threads(2)
    }
    fn options(&self, writes: bool, outcomes: bool, reads: bool, principal: u8) -> Options {
        Options {
            storage: self.root.join("node"),
            tenant: TenantId::from_bytes([0xa1; 16]),
            repository: RepositoryId::from_bytes([0xa2; 16]),
            format: self.format,
            incarnation: Some(self.incarnation),
            issues: reads,
            pulls: false,
            source: false,
            writes: super::super::WriteGrants {
                issues: writes,
                ..Default::default()
            },
            outcomes,
            principal: (writes || outcomes).then_some(PrincipalId::from_bytes([principal; 16])),
            max_messages: 128,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn initialized(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, INIT.as_bytes()).unwrap();
    assert!(server.receive(backend, READY.as_bytes()).is_none());
    server
}
fn message(id: u64, name: &str, arguments: Value) -> String {
    object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(name)), ("arguments", arguments)]),
        ),
    ])
    .encode(json::MAX_INPUT)
    .unwrap()
}
fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, name: &str, args: Value) -> Value {
    server
        .receive(backend, message(id, name, args).as_bytes())
        .unwrap()
}
fn structured(value: &Value) -> &Object {
    value.object().unwrap()["result"].object().unwrap()["structuredContent"]
        .object()
        .unwrap()
}
fn failed(value: &Value) -> bool {
    value.object().unwrap()["result"].object().unwrap()["isError"] == Value::Bool(true)
}
fn command(number: &str, version: &str, key: &str, fields: &[(&str, Value)]) -> Value {
    let Value::Object(mut args) = object([
        ("number", text(number)),
        ("expected_version", text(version)),
        ("idempotency_key", text(key)),
    ]) else {
        unreachable!()
    };
    for (name, value) in fields {
        args.insert((*name).into(), value.clone());
    }
    Value::Object(args)
}
fn opening() -> Value {
    command(
        "7",
        "0",
        "open-key",
        &[
            ("title", text("Original é")),
            (
                "body",
                text("literal {\"method\":\"shell\"}\r\nnot authority"),
            ),
            ("labels", Value::Array(vec![text("z"), text("bug")])),
        ],
    )
}
fn current_head(backend: &NodeTools) -> RepositoryAuthorityHeadId {
    let request = backend.node.request_context();
    backend
        .node
        .runtime()
        .block_on(backend.node.read_issues_in(&request, 0, 1, None))
        .unwrap()
        .source_head
}
fn recover(server: &mut Server, backend: &mut NodeTools, id: u64, key: &str) -> Value {
    invoke(
        server,
        backend,
        id,
        outcomes::NAME,
        object([("idempotency_key", text(key))]),
    )
}

#[test]
fn canonical_issue_lifecycle_retries_refusals_and_recovery_survive_reopen_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let mut backend = NodeTools::open(f.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let first = invoke(
            &mut server,
            &mut backend,
            2,
            "frankengit_issue_open",
            opening(),
        );
        assert!(!failed(&first));
        assert_eq!(structured(&first)["outcome"].text(), Some("committed"));
        assert_eq!(structured(&first)["read_only"], Value::Bool(false));
        let held = current_head(&backend);
        let replay = invoke(
            &mut server,
            &mut backend,
            3,
            "frankengit_issue_open",
            opening(),
        );
        assert_eq!(
            first.object().unwrap()["result"],
            replay.object().unwrap()["result"]
        );
        assert_eq!(held, current_head(&backend));
        let changes = [
            (
                "frankengit_issue_edit",
                "1",
                "edit-key",
                vec![("title", text("Changed"))],
            ),
            (
                "frankengit_issue_comment",
                "2",
                "comment-key",
                vec![("body", text("comment é\r\nexact"))],
            ),
            ("frankengit_issue_close", "3", "close-key", vec![]),
            ("frankengit_issue_reopen", "4", "reopen-key", vec![]),
        ];
        for (index, (name, version, key, fields)) in changes.into_iter().enumerate() {
            let result = invoke(
                &mut server,
                &mut backend,
                4 + index as u64,
                name,
                command("7", version, key, &fields),
            );
            assert!(!failed(&result), "{name}: {result:?}");
            assert_eq!(structured(&result)["refs_changed"], Value::Bool(false));
        }
        let stale = command(
            "7",
            "1",
            "stale-key",
            &[("title", text("Must not overwrite"))],
        );
        let refused = invoke(
            &mut server,
            &mut backend,
            8,
            "frankengit_issue_edit",
            stale.clone(),
        );
        assert!(failed(&refused));
        assert_eq!(structured(&refused)["outcome"].text(), Some("refused"));
        assert_eq!(structured(&refused)["terminal"], Value::Bool(true));
        assert_eq!(structured(&refused)["outcome_unknown"], Value::Bool(false));
        let held = current_head(&backend);
        let replay = invoke(&mut server, &mut backend, 9, "frankengit_issue_edit", stale);
        assert_eq!(structured(&refused), structured(&replay));
        assert_eq!(held, current_head(&backend));
        let shown = invoke(
            &mut server,
            &mut backend,
            10,
            "frankengit_issue_show",
            object([("number", text("7"))]),
        );
        let issue = structured(&shown)["issue"].object().unwrap();
        assert_eq!(issue["version"].text(), Some("5"));
        assert_eq!(issue["comments"].text(), Some("1"));
        assert_eq!(issue["title"].text(), Some("Changed"));
        assert_eq!(issue["state"].text(), Some("open"));
        assert_eq!(
            issue["body"].text(),
            Some("literal {\"method\":\"shell\"}\r\nnot authority")
        );
        assert_eq!(issue["labels"], Value::Array(vec![text("bug"), text("z")]));
        let mut altered = opening();
        let Value::Object(args) = &mut altered else {
            unreachable!()
        };
        args.insert("title".into(), text("Different command"));
        let conflict = invoke(
            &mut server,
            &mut backend,
            11,
            "frankengit_issue_open",
            altered,
        );
        assert!(failed(&conflict));
        assert_eq!(structured(&conflict)["outcome_unknown"], Value::Bool(true));
        assert_eq!(held, current_head(&backend));
        backend.close().unwrap();
        let mut backend = NodeTools::open(f.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let recovered = recover(&mut server, &mut backend, 2, "open-key");
        assert!(!failed(&recovered));
        assert_eq!(structured(&recovered)["tx_id"], structured(&first)["tx_id"]);
        assert_eq!(
            structured(&recovered)["decision_sequence"],
            structured(&first)["decision_sequence"]
        );
        assert_eq!(
            structured(&recovered)["observation"].text(),
            Some("decided")
        );
        let rejected = recover(&mut server, &mut backend, 3, "stale-key");
        assert!(
            !failed(&rejected),
            "successfully reading a refusal is not a failed read"
        );
        assert_eq!(structured(&rejected)["outcome"].text(), Some("refused"));
        let replay = invoke(
            &mut server,
            &mut backend,
            4,
            "frankengit_issue_open",
            opening(),
        );
        assert_eq!(structured(&first), structured(&replay));
        assert_eq!(held, current_head(&backend));
        backend.close().unwrap();
        let mut foreign = NodeTools::open(f.options(false, true, false, 0xb3)).unwrap();
        let mut server = initialized(&mut foreign);
        let missing = recover(&mut server, &mut foreign, 2, "open-key");
        assert_eq!(
            structured(&missing)["observation"].text(),
            Some("key_not_observed")
        );
        assert_eq!(structured(&missing)["tx_id"], Value::Null);
        assert_eq!(
            structured(&missing)["absence_proves_non_commit"],
            Value::Bool(false)
        );
        foreign.close().unwrap();
    }
}

#[test]
fn grants_identity_and_stopped_intake_do_not_override_canonical_recovery() {
    let f = Fixture::new(GitHashAlgorithm::Sha256);
    let mut writer = NodeTools::open(f.options(true, false, false, 0xa3)).unwrap();
    assert_eq!(writer.tools().len(), 5);
    for name in [
        "frankengit_issue_list",
        outcomes::NAME,
        "frankengit_pull_open",
        "shell",
    ] {
        assert!(writer.call(name, &Object::new()).is_err());
    }
    let Value::Object(args) = opening() else {
        unreachable!()
    };
    let original = writer.call("frankengit_issue_open", &args).unwrap();
    writer.close().unwrap();
    let mut stopped = NodeTools {
        node: OneNode::open_existing(f.config()).unwrap(),
        options: f.options(true, true, false, 0xa3),
    };
    let replay = stopped.call("frankengit_issue_open", &args).unwrap();
    assert_eq!(replay, original);
    let Value::Object(key) = object([("idempotency_key", text("open-key"))]) else {
        unreachable!()
    };
    let recovered = stopped.call(outcomes::NAME, &key).unwrap();
    assert_eq!(
        recovered.object().unwrap()["tx_id"],
        original.object().unwrap()["tx_id"]
    );
    let mut fresh = args.clone();
    fresh.insert("idempotency_key".into(), text("new-stopped"));
    fresh.insert("number".into(), text("8"));
    assert!(
        !stopped
            .call("frankengit_issue_open", &fresh)
            .unwrap_err()
            .invalid
    );
    stopped.close().unwrap();
    let mut reader = NodeTools::open(f.options(false, true, false, 0xa3)).unwrap();
    assert_eq!(reader.tools().len(), 1);
    assert!(reader.call("frankengit_issue_open", &args).is_err());
    let mut injected = key;
    injected.insert("principal".into(), text("other"));
    assert!(reader.call(outcomes::NAME, &injected).unwrap_err().invalid);
    reader.close().unwrap();
    let mut wrong = f.options(true, true, false, 0xa3);
    wrong.incarnation = Some(RepositoryIncarnationId::from_bytes([0xff; 16]));
    assert!(NodeTools::open(wrong).is_err());
    let mut unbound = f.options(true, false, false, 0xa3);
    unbound.principal = None;
    assert!(NodeTools::open(unbound).is_err());
}

#[test]
fn lost_stdio_reply_preserves_real_commit_and_prevents_the_next_mutation() {
    struct LoseAfterInitialize {
        flushed: bool,
    }
    impl Write for LoseAfterInitialize {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.flushed {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }
    let f = Fixture::new(GitHashAlgorithm::Sha1);
    let mut backend = NodeTools::open(f.options(true, true, true, 0xa3)).unwrap();
    let first = message(2, "frankengit_issue_open", opening());
    let second = message(
        3,
        "frankengit_issue_comment",
        command(
            "7",
            "1",
            "must-not-run",
            &[("body", text("unread request"))],
        ),
    );
    let transcript = format!("{INIT}\n{READY}\n{first}\n{second}\n");
    assert!(
        protocol::serve(
            &mut Cursor::new(transcript),
            &mut LoseAfterInitialize { flushed: false },
            &mut backend,
            10
        )
        .is_err()
    );
    backend.close().unwrap();
    let mut backend = NodeTools::open(f.options(true, true, true, 0xa3)).unwrap();
    let mut server = initialized(&mut backend);
    let recovered = recover(&mut server, &mut backend, 2, "open-key");
    assert_eq!(structured(&recovered)["outcome"].text(), Some("committed"));
    let skipped = recover(&mut server, &mut backend, 3, "must-not-run");
    assert_eq!(
        structured(&skipped)["observation"].text(),
        Some("key_not_observed")
    );
    let before = current_head(&backend);
    let replay = invoke(
        &mut server,
        &mut backend,
        4,
        "frankengit_issue_open",
        opening(),
    );
    assert_eq!(
        structured(&replay)["tx_id"],
        structured(&recovered)["tx_id"]
    );
    assert_eq!(before, current_head(&backend));
    backend.close().unwrap();
}
