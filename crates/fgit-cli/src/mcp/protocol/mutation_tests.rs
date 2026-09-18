//! Protocol-only oracle: no durable-store or real-publication claim here.
use super::*;
use std::io::Cursor;
#[derive(Default)]
struct Mutating { calls: usize, refuse: bool, fail: bool }
impl ReadTools for Mutating {
    fn tools(&self) -> Vec<Tool> {
        vec![Tool { name: "write", description: "protocol mutation oracle", schema: object([("type", text("object"))]) }]
    }
    fn is_mutation(&self, name: &str) -> bool { name == "write" }
    fn result_is_error(&self, _: &str, value: &Value) -> bool {
        value.object().and_then(|v| v.get("outcome")).and_then(Value::text) == Some("refused")
    }
    fn call(&mut self, _: &str, args: &Object) -> Result<Value, ToolError> {
        if !args.is_empty() { return Err(ToolError::invalid("unknown_argument")); }
        self.calls += 1;
        if self.fail { return Err(ToolError::uncertain("connection_lost")); }
        Ok(terminal(self.refuse))
    }
}
fn terminal(refused: bool) -> Value {
    object([("tx_id", text("test-transaction")), ("decision_sequence", text("7")),
        ("outcome", text(if refused { "refused" } else { "committed" })),
        ("terminal", Value::Bool(true)), ("outcome_unknown", Value::Bool(false)),
        ("command_committed", Value::Bool(!refused)), ("complete", Value::Bool(true))])
}
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const CALL: &[u8] = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write"}}"#;
fn ready(backend: &mut Mutating) -> Server {
    let mut server = Server::new(backend).unwrap(); server.receive(backend, INIT.as_bytes()).unwrap();
    server.receive(backend, READY.as_bytes()); server
}
#[test]
fn annotations_follow_fixed_mutation_classification_and_notifications_never_write() {
    let mut backend = Mutating::default(); let mut server = ready(&mut backend);
    let list = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
    let Value::Array(tools) = &list.object().unwrap()["result"].object().unwrap()["tools"] else { panic!("tools") };
    let hints = tools[0].object().unwrap()["annotations"].object().unwrap();
    assert_eq!(hints["readOnlyHint"], Value::Bool(false)); assert_eq!(hints["destructiveHint"], Value::Bool(true));
    assert_eq!(hints["idempotentHint"], Value::Bool(true));
    assert!(server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"write"}}"#).is_none());
    assert!(server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#).is_none());
    assert_eq!(backend.calls, 0); server.receive(&mut backend, CALL).unwrap(); assert_eq!(backend.calls, 1);
    assert!(server.receive(&mut backend, CALL).unwrap().object().unwrap().contains_key("error"));
    assert_eq!(backend.calls, 1);
}
#[test]
fn canonical_refusal_and_unknown_outcome_have_different_tool_results() {
    let mut backend = Mutating { refuse: true, ..Default::default() }; let mut server = ready(&mut backend);
    let refusal = server.receive(&mut backend, CALL).unwrap();
    let result = refusal.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(true));
    assert_eq!(result["structuredContent"].object().unwrap()["outcome_unknown"], Value::Bool(false));
    assert_eq!(result["structuredContent"].object().unwrap()["outcome"].text(), Some("refused"));
    let mut backend = Mutating { fail: true, ..Default::default() }; let mut server = ready(&mut backend);
    let unknown = server.receive(&mut backend, CALL).unwrap();
    let result = unknown.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(true));
    let body = result["structuredContent"].object().unwrap();
    assert_eq!(body["outcome_unknown"], Value::Bool(true)); assert_eq!(body["terminal"], Value::Bool(false));
    assert!(!body.contains_key("outcome"));
}
#[test]
fn response_overflow_keeps_known_terminal_facts_or_preserves_uncertainty() {
    for refused in [false, true] {
        let mut value = terminal(refused); let Value::Object(fields) = &mut value else { unreachable!() };
        fields.insert("oversized".into(), text("x".repeat(MAX_TOOL_RESULT + 1)));
        let result = encode_tool_result(value, refused, true);
        let body = result.object().unwrap()["structuredContent"].object().unwrap();
        assert_eq!(result.object().unwrap()["isError"], Value::Bool(true));
        assert_eq!(body["tx_id"].text(), Some("test-transaction")); assert_eq!(body["decision_sequence"].text(), Some("7"));
        assert_eq!(body["outcome_unknown"], Value::Bool(false)); assert_eq!(body["terminal"], Value::Bool(true));
        assert_eq!(body["code"].text(), Some("response_limit")); assert!(!body.contains_key("oversized"));
        assert!(result.encode(64 * 1024).is_ok());
    }
    let value = object([("oversized", text("x".repeat(MAX_TOOL_RESULT + 1)))]);
    let result = encode_tool_result(value, false, true);
    assert_eq!(result.object().unwrap()["structuredContent"].object().unwrap()["outcome_unknown"], Value::Bool(true));
}
#[test]
fn broken_mutation_reply_stops_the_session_before_a_second_effect() {
    struct Broken { responses: usize }
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.responses != 0 { Err(io::ErrorKind::BrokenPipe.into()) } else { Ok(bytes.len()) }
        }
        fn flush(&mut self) -> io::Result<()> { self.responses += 1; Ok(()) }
    }
    let call = std::str::from_utf8(CALL).unwrap();
    let next = call.replace("\"id\":3", "\"id\":4");
    let mut backend = Mutating::default();
    assert!(serve(&mut Cursor::new(format!("{INIT}\n{READY}\n{call}\n{next}\n")),
        &mut Broken { responses: 0 }, &mut backend, 10).is_err());
    assert_eq!(backend.calls, 1);
}
