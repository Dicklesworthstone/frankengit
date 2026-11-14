use super::*;

fn args(values: impl IntoIterator<Item = (&'static str, Value)>) -> Object {
    values
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
}

#[test]
fn search_keeps_exact_cursor_text_and_literal_filters() {
    let raw = b"refs/heads/topic-\xff";
    let (query, request) = parse(&args([
        ("query", text("[a].*é")),
        ("state", text("merged")),
        ("source_ref_hex", text(hex(raw))),
        ("case_sensitive", Value::Bool(true)),
        ("limit", json::number(2)),
        ("max_scan", json::number(3)),
    ]))
    .unwrap();
    assert_eq!(query.query().text.as_deref(), Some("[a].*é"));
    assert_eq!(query.query().source_ref.as_ref().unwrap().as_bytes(), raw);
    assert_eq!((request.limit, request.max_scan), (2, 3));
    let token = format!("alg:1:{}", "ab".repeat(32));
    let (_, request) = parse(&args([
        ("after", text(u64::MAX.to_string())),
        ("expected_head", text(token)),
    ]))
    .unwrap();
    assert_eq!(request.after, u64::MAX);
}

#[test]
fn search_refuses_mutation_arguments_lossy_cursors_and_ambiguous_filters() {
    for values in [
        vec![("principal", text("admin"))],
        vec![("idempotency_key", text("write"))],
        vec![("case_sensitive", Value::Bool(true))],
        vec![("case_sensitive", text("false"))],
        vec![("query", Value::Null)],
        vec![("query", text(""))],
        vec![("query", text("a\0b"))],
        vec![("after", json::number(1))],
        vec![("after", text("1"))],
        vec![("after", text("01"))],
        vec![("max_scan", json::number(0))],
        vec![("max_scan", json::number(1001))],
        vec![("limit", json::number(21))],
        vec![("state", text("approved"))],
        vec![("source_ref", text("refs/tags/v1"))],
        vec![
            ("source_ref", text("refs/heads/x")),
            ("source_ref_hex", text(hex(b"refs/heads/x"))),
        ],
    ] {
        assert!(parse(&args(values)).is_err());
    }
    assert!(parse(&args([("query", text("é".repeat(129)))])).is_err());
}

#[test]
fn search_descriptor_matches_its_bounded_read_grammar() {
    let tool = tool();
    assert_eq!(tool.name, "frankengit_pull_search");
    let schema = tool.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].object().unwrap();
    assert_eq!(
        properties["max_scan"].object().unwrap()["maximum"],
        json::number(1000)
    );
    assert_eq!(
        properties["limit"].object().unwrap()["maximum"],
        json::number(20)
    );
    assert!(!properties.contains_key("principal"));
    assert!(!properties.contains_key("idempotency_key"));
}
