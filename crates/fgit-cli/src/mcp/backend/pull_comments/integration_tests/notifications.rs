//! JSON-RPC calls through real reopened nodes. PR metadata, conversations and
//! self-owned notification preferences remain separate canonical streams.
use super::*;
use crate::mcp::protocol::Server;

const LIST: &str = "frankengit_inbox_list";
const SHOW: &str = "frankengit_inbox_show";
const SUBSCRIBE: &str = "frankengit_inbox_subscribe";
const MARK_READ: &str = "frankengit_inbox_read";
const OTHER: PrincipalId = PrincipalId::from_bytes([0xc4; 16]);
const WATCHER: PrincipalId = PrincipalId::from_bytes([0xc5; 16]);

fn options(fixture: &Fixture, principal: PrincipalId, pull_writes: bool) -> Options {
    let mut options = fixture.options.clone();
    options.principal = Some(principal);
    options.outcomes = false;
    options.writes = WriteGrants {
        pulls: pull_writes,
        notifications: true,
        ..Default::default()
    };
    options
}

struct Mcp {
    backend: NodeTools,
    server: Server,
    next: u64,
}
impl Mcp {
    fn open(options: Options) -> Self {
        let mut backend = NodeTools::open(options).unwrap();
        let mut server = Server::new(&backend).unwrap();
        let initialized = server.receive(&mut backend,
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"pr-notification-test","version":"1"}}}"#,
        ).unwrap();
        assert!(initialized.object().unwrap().contains_key("result"));
        assert!(
            server
                .receive(
                    &mut backend,
                    br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                )
                .is_none()
        );
        Self {
            backend,
            server,
            next: 2,
        }
    }

    fn invoke(&mut self, name: &str, arguments: Value) -> Value {
        let request = object([
            ("jsonrpc", text("2.0")),
            ("id", json::number(self.next)),
            ("method", text("tools/call")),
            (
                "params",
                object([("name", text(name)), ("arguments", arguments)]),
            ),
        ])
        .encode(json::MAX_INPUT)
        .unwrap();
        self.next += 1;
        self.server
            .receive(&mut self.backend, request.as_bytes())
            .unwrap()
    }

    fn read(&mut self, name: &str, arguments: Value) -> Object {
        let reply = self.invoke(name, arguments);
        assert!(!failed(&reply), "{name}: {reply:?}");
        structured(&reply).clone()
    }

    fn publish(&mut self, name: &str, arguments: Value) -> Object {
        let result = self.read(name, arguments);
        assert_eq!(result["outcome"], text("committed"), "{name}: {result:?}");
        assert_eq!(result["refs_changed"], Value::Bool(false));
        result
    }

    fn show(&mut self) -> Object {
        let result = self.read(
            SHOW,
            object([("kind", text("pull_request")), ("number", text("1"))]),
        );
        assert_eq!(result["target_kind"], text("pull_request"));
        assert_eq!(result["found"], Value::Bool(true));
        let Value::Array(rows) = &result["threads"] else {
            panic!("notification rows")
        };
        assert_eq!(rows.len(), 1);
        let row = rows[0].object().unwrap().clone();
        for unrelated in [
            "issue_version",
            "discussion_version",
            "pull_request_version",
            "thread_version",
        ] {
            assert!(
                !row.contains_key(unrelated),
                "PR activity is not {unrelated}"
            );
        }
        row
    }

    fn list(&mut self) -> Vec<Value> {
        let result = self.read(LIST, object([("kind", text("pull_request"))]));
        assert_eq!(result["target_kind"], text("pull_request"));
        let Value::Array(rows) = &result["threads"] else {
            panic!("notification rows")
        };
        rows.clone()
    }

    fn append(&mut self, key: &str) {
        self.publish(APPEND, Value::Object(append_args(key, key)));
    }

    fn close(self) {
        self.backend.close().unwrap();
    }
}

fn structured(reply: &Value) -> &Object {
    reply.object().unwrap()["result"].object().unwrap()["structuredContent"]
        .object()
        .unwrap()
}
fn failed(reply: &Value) -> bool {
    let fields = reply.object().unwrap();
    fields.contains_key("error")
        || fields["result"].object().unwrap()["isError"] == Value::Bool(true)
}
fn preference(version: &str, key: &str, through: Option<&str>) -> Value {
    let mut fields = object([
        ("kind", text("pull_request")),
        ("number", text("1")),
        ("expected_version", text(version)),
        ("idempotency_key", text(key)),
    ])
    .object()
    .unwrap()
    .clone();
    if let Some(through) = through {
        fields.insert("read_through".into(), text(through));
    }
    Value::Object(fields)
}
fn lifecycle(fixture: &Fixture, version: &str, key: &str) -> Value {
    object([
        ("number", text("1")),
        ("expected_version", text(version)),
        ("idempotency_key", text(key)),
        ("source_reference", text("refs/heads/topic")),
        ("target_reference", text("refs/heads/main")),
        ("expected_source", text(fixture.source.to_string())),
        ("expected_target", text(fixture.base.to_string())),
        ("title", text("Discuss")),
        ("body", text("Original PR body")),
    ])
}

#[test]
fn pull_request_inbox_counts_independent_activity_and_recovers_exact_read_prefixes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut author = Mcp::open(options(&fixture, ACTOR, true));
        let initial = author.show();
        assert_eq!(initial["activity_version"], text("1"));
        assert_eq!(initial["latest_other_version"], Value::Null);
        assert_eq!(
            initial["reasons"],
            Value::Array(vec![text("author"), text("participant")])
        );
        assert_eq!(initial["unread"], Value::Bool(false));
        assert_eq!(author.list().len(), 1);
        author.append("author-comment");
        let own = author.show();
        assert_eq!(own["activity_version"], text("2"));
        assert_eq!(own["latest_other_version"], Value::Null);
        assert_eq!(own["unread"], Value::Bool(false));
        let metadata = author.read("frankengit_pull_show", Value::Object(read_args()));
        assert_eq!(
            metadata["pull_request"].object().unwrap()["version"],
            text("1")
        );
        let comments = author.read(READ, Value::Object(read_args()));
        assert_eq!(comments["discussion_version"], text("1"));
        author.close();

        let mut other = Mcp::open(options(&fixture, OTHER, true));
        assert!(other.list().is_empty());
        other.append("other-comment");
        let participation = other.show();
        assert_eq!(participation["activity_version"], text("3"));
        assert_eq!(participation["latest_other_version"], text("2"));
        assert_eq!(
            participation["reasons"],
            Value::Array(vec![text("participant")])
        );
        assert_eq!(other.list().len(), 1);
        other.close();

        let mut watcher = Mcp::open(options(&fixture, WATCHER, false));
        assert!(watcher.list().is_empty());
        assert_eq!(watcher.show()["reasons"], Value::Array(Vec::new()));
        let subscribe = preference("0", "watch-pr", None);
        let subscribed = watcher.publish(SUBSCRIBE, subscribe.clone());
        assert_eq!(
            subscribed["type"],
            text("pull_request_notification_publication")
        );
        assert_eq!(
            watcher.show()["reasons"],
            Value::Array(vec![text("subscribed")])
        );
        watcher.close();

        let mut author = Mcp::open(options(&fixture, ACTOR, true));
        assert_eq!(author.show()["latest_other_version"], text("3"));
        let read_prefix = preference("0", "read-three-activities", Some("3"));
        let read_receipt = author.publish(MARK_READ, read_prefix.clone());
        assert_eq!(author.show()["unread"], Value::Bool(false));
        author.publish(
            "frankengit_pull_close",
            lifecycle(&fixture, "1", "close-own-pr"),
        );
        let closed = author.show();
        assert_eq!(closed["activity_version"], text("4"));
        assert_eq!(closed["state"], text("closed"));
        assert_eq!(closed["latest_other_version"], text("3"));
        assert_eq!(closed["unread"], Value::Bool(false));
        author.close();

        let mut other = Mcp::open(options(&fixture, OTHER, true));
        other.append("reply-while-closed");
        assert_eq!(other.show()["activity_version"], text("5"));
        other.close();

        let mut author = Mcp::open(options(&fixture, ACTOR, true));
        author.publish(
            "frankengit_pull_reopen",
            lifecycle(&fixture, "2", "reopen-own-pr"),
        );
        let changed = author.show();
        assert_eq!(changed["activity_version"], text("6"));
        assert_eq!(changed["state"], text("open"));
        assert_eq!(changed["latest_other_version"], text("5"));
        assert_eq!(changed["read_through"], text("3"));
        assert_eq!(changed["preference_version"], text("1"));
        assert_eq!(changed["unread"], Value::Bool(true));
        assert_eq!(author.publish(MARK_READ, read_prefix), read_receipt);
        assert_eq!(
            author.show()["unread"],
            Value::Bool(true),
            "retry must not acknowledge later replies"
        );
        author.publish(
            MARK_READ,
            preference("1", "read-five-activities", Some("5")),
        );
        let read = author.show();
        assert_eq!(read["activity_version"], text("6"));
        assert_eq!(read["read_through"], text("5"));
        assert_eq!(
            read["unread"],
            Value::Bool(false),
            "own later lifecycle activity is not unread"
        );
        let future = author.invoke(MARK_READ, preference("2", "future-read-refused", Some("7")));
        assert!(failed(&future));
        assert_eq!(structured(&future)["outcome"], text("refused"));
        assert_eq!(author.show()["preference_version"], text("2"));
        author.close();

        let mut watcher = Mcp::open(options(&fixture, WATCHER, false));
        assert_eq!(watcher.publish(SUBSCRIBE, subscribe), subscribed);
        let retained = watcher.show();
        assert_eq!(retained["activity_version"], text("6"));
        assert_eq!(retained["latest_other_version"], text("6"));
        assert_eq!(retained["preference_version"], text("1"));
        assert_eq!(retained["reasons"], Value::Array(vec![text("subscribed")]));
        assert_eq!(retained["unread"], Value::Bool(true));
        watcher.close();
    }
}

#[test]
fn pull_request_notifications_require_independent_read_and_preference_grants() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let subscribe = preference("0", "notification-grants", None);
    let mut pull_writer = options(&fixture, ACTOR, true);
    pull_writer.writes.notifications = false;
    let mut pull_writer = Mcp::open(pull_writer);
    assert_eq!(pull_writer.show()["activity_version"], text("1"));
    for (name, args) in [
        (SUBSCRIBE, subscribe.clone()),
        (
            MARK_READ,
            preference("0", "not-a-read-state-grant", Some("1")),
        ),
    ] {
        assert!(
            !pull_writer
                .backend
                .tools()
                .iter()
                .any(|tool| tool.name == name)
        );
        assert!(failed(&pull_writer.invoke(name, args)));
    }
    pull_writer.close();

    let mut preference_writer = Mcp::open(options(&fixture, WATCHER, false));
    preference_writer.publish(SUBSCRIBE, subscribe.clone());
    for (name, args) in [
        (
            APPEND,
            Value::Object(append_args("not-a-comment-grant", "must not publish")),
        ),
        (
            "frankengit_pull_close",
            lifecycle(&fixture, "1", "not-a-lifecycle-grant"),
        ),
    ] {
        assert!(
            !preference_writer
                .backend
                .tools()
                .iter()
                .any(|tool| tool.name == name)
        );
        assert!(
            preference_writer
                .backend
                .call(name, args.object().unwrap())
                .is_err()
        );
        assert!(failed(&preference_writer.invoke(name, args)));
    }
    assert_eq!(preference_writer.show()["activity_version"], text("1"));
    preference_writer.close();

    for discussions in [false, true] {
        let mut unrelated = options(&fixture, ACTOR, false);
        unrelated.pulls = false;
        unrelated.issues = !discussions;
        unrelated.discussions = discussions;
        let mut unrelated = Mcp::open(unrelated);
        for (name, args) in [
            (LIST, object([("kind", text("pull_request"))])),
            (
                SHOW,
                object([("kind", text("pull_request")), ("number", text("1"))]),
            ),
            (SUBSCRIBE, subscribe.clone()),
            (MARK_READ, preference("0", "wrong-kind-read", Some("1"))),
        ] {
            assert!(
                unrelated
                    .backend
                    .tools()
                    .iter()
                    .any(|tool| tool.name == name)
            );
            assert!(
                failed(&unrelated.invoke(name, args)),
                "independent PR read grant required by {name}"
            );
        }
        unrelated.close();
    }
}
