//! The actual serial framing/parser, with a counting tool-boundary fixture.
//! Persisted administrator authorization is exercised in the backend tests.
use super::*;
use std::io::Cursor;

const NAME: &str = "frankengit_protection_set";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"policy-bounds","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn wire(name: &str, field: &str, value: &str, id: u64) -> Value {
    object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([
                ("name", text(name)),
                ("arguments", object([(field, text(value))])),
            ]),
        ),
    ])
}

#[derive(Default)]
struct PolicyBoundary {
    calls: usize,
}
impl ReadTools for PolicyBoundary {
    fn tools(&self) -> Vec<Tool> {
        vec![Tool {
            name: NAME,
            description: "bounded policy transport fixture",
            schema: object([("type", text("object"))]),
        }]
    }
    fn call(&mut self, name: &str, arguments: &Object) -> Result<Value, ToolError> {
        assert_eq!(name, NAME);
        let policy = if let Some(source) = arguments.get("ref_policy_source") {
            fgit_forge::event::protection::compile_ref_policy(source.text().unwrap()).unwrap()
        } else {
            let hex = arguments["ref_policy_frame_hex"].text().unwrap();
            let frame: Vec<u8> = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            fgit_forge::event::protection::decode_ref_policy(&frame).unwrap()
        };
        self.calls += 1;
        Ok(object([("snapshot_id", text(policy.id().to_string()))]))
    }
    fn is_mutation(&self, _: &str) -> bool {
        true
    }
}

#[test]
fn large_canonical_policy_source_and_frame_cross_real_stdio_framing() {
    let mut source = String::from("policy transport { ");
    for index in 0..40 {
        source.push_str(&format!(
            "rule r{index:02} {{ when ref.name == \"{}\" then deny \"retained\" }} ",
            "a".repeat(900),
        ));
    }
    source.push_str("default allow }");
    let snapshot = fgit_forge::event::protection::compile_ref_policy(&source).unwrap();
    let frame = snapshot.encode().unwrap();
    let hex: String = frame.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(source.len() > json::REQUEST_LIMITS.string);
    assert!(hex.len() > json::MAX_INPUT);
    let source_request = wire(NAME, "ref_policy_source", &source, 2)
        .encode(MAX_MESSAGE_BYTES)
        .unwrap();
    let frame_request = wire(NAME, "ref_policy_frame_hex", &hex, 3)
        .encode(MAX_MESSAGE_BYTES)
        .unwrap();
    assert!(json::parse(source_request.as_bytes()).is_err());
    assert!(json::parse(frame_request.as_bytes()).is_err());
    let transcript = format!("{INIT}\n{READY}\n{source_request}\n{frame_request}\n");
    let mut backend = PolicyBoundary::default();
    let mut out = Vec::new();
    serve(&mut Cursor::new(transcript), &mut out, &mut backend, 8).unwrap();
    assert_eq!(backend.calls, 2);
    let output = String::from_utf8(out).unwrap();
    let responses: Vec<Value> = output
        .lines()
        .map(|line| json::parse(line.as_bytes()).unwrap())
        .collect();
    assert_eq!(responses.len(), 3);
    for response in &responses[1..] {
        let result = response.object().unwrap()["result"].object().unwrap();
        assert_eq!(result["isError"], Value::Bool(false));
        assert_eq!(
            result["structuredContent"].object().unwrap()["snapshot_id"].text(),
            Some(snapshot.id().to_string().as_str())
        );
    }
}

#[test]
fn policy_exception_preserves_every_unrelated_request_and_string_bound() {
    let large = "a".repeat(json::REQUEST_LIMITS.string + 1);
    for value in [
        wire("other_tool", "ref_policy_source", &large, 2),
        wire(NAME, "unrelated", &large, 3),
        wire(NAME, "ref_policy_source", &"a".repeat(64 * 1024 + 1), 4),
        wire(NAME, "ref_policy_frame_hex", &"a".repeat(128 * 1024 + 2), 5),
        object([
            ("jsonrpc", text("2.0")),
            ("id", json::number(6)),
            ("method", text("tools/call")),
            (
                "params",
                object([
                    ("name", text(NAME)),
                    (
                        "arguments",
                        object([
                            ("ref_policy_source", text(&large)),
                            ("unrelated", text(&large)),
                        ]),
                    ),
                ]),
            ),
        ]),
    ] {
        let input = value.encode(MAX_MESSAGE_BYTES).unwrap();
        assert!(parse_request(input.as_bytes()).is_err());
    }
    let oversized = vec![b' '; MAX_MESSAGE_BYTES + 1];
    assert!(read_message(&mut Cursor::new(oversized)).is_err());
    let ordinary = format!(
        "{}{}",
        " ".repeat(json::MAX_INPUT),
        wire("other_tool", "small", "x", 7).encode(1024).unwrap()
    );
    assert!(parse_request(ordinary.as_bytes()).is_err());
}
