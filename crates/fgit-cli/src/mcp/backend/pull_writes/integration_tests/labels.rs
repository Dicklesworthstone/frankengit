//! Real node, protocol and durable retries; no synthetic label authority.
use super::*;
use super::super::super::pull_labels::{ADD, READ, WRITE};

fn labels(number: &str, version: &str, key: &str, values: &[&str]) -> Value {
    object([("number", text(number)), ("expected_version", text(version)), ("idempotency_key", text(key)), ("labels", Value::Array(values.iter().map(|label| text(*label)).collect()))])
}
fn query(number: &str) -> Value { object([("number", text(number))]) }
fn additions(number: &str, key: &str, values: &[&str]) -> Value {
    object([("number", text(number)), ("idempotency_key", text(key)), ("labels", Value::Array(values.iter().map(|label| text(*label)).collect()))])
}
fn set(mut value: Value, name: &str, field: Value) -> Value {
    let Value::Object(fields) = &mut value else { unreachable!() };
    fields.insert(name.into(), field); value
}
fn committed(value: &Value) { assert_eq!(result(value)["outcome"], text("committed"), "{value:?}"); }

#[test]
fn labels_have_independent_versions_retained_reads_and_exact_historical_retries_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut options = fixture.options.clone(); options.pulls = true;
        let mut backend = NodeTools::open(options.clone()).unwrap(); let mut server = start(&mut backend);
        committed(&invoke(&mut server, &mut backend, 2, OPEN, args(fixture.commit, "0", "open-label-subject", "Original")));
        let unset = invoke(&mut server, &mut backend, 3, READ, query("7"));
        assert_eq!(result(&unset)["labels_version"], text("0"));
        assert_eq!(result(&unset)["labels_actor"], Value::Null);
        assert_eq!(result(&unset)["pull_request_version"], text("1"));
        let original = labels("7", "0", "original-label-key", &["review", "bug"]);
        let first = invoke(&mut server, &mut backend, 4, WRITE, original.clone()); committed(&first);
        assert_eq!(result(&first)["labels_version"], text("1"));
        assert_eq!(result(&first)["pull_request_version_changed"], Value::Bool(false));
        let known_fields: std::collections::BTreeSet<_> = fgit_schema::mcp::find_tool(WRITE).unwrap().output_fields.iter().map(|field| field.name).collect();
        assert_eq!(known_fields, result(&first).keys().map(String::as_str).collect());
        assert!(!first.encode(16384).unwrap().contains("original-label-key"));
        let labeled = invoke(&mut server, &mut backend, 5, READ, query("7"));
        assert_eq!(result(&labeled)["labels"], Value::Array(vec![text("bug"), text("review")]));
        assert_eq!(result(&labeled)["pull_request_version"], text("1"));
        let read_fields: std::collections::BTreeSet<_> = fgit_schema::mcp::find_tool(READ).unwrap().output_fields.iter().map(|field| field.name).collect();
        assert_eq!(read_fields, result(&labeled).keys().map(String::as_str).collect());
        let pinned = result(&labeled)["snapshot_token"].clone();
        let stale = invoke(&mut server, &mut backend, 6, WRITE, labels("7", "0", "stale-label-key", &["wrong"]));
        assert_eq!(result(&stale)["outcome"], text("refused"));
        assert_eq!(result(&stale)["labels_version"], Value::Null);
        committed(&invoke(&mut server, &mut backend, 7, CLOSE, args(fixture.commit, "1", "close-label-subject", "Original")));
        let cleared = invoke(&mut server, &mut backend, 8, WRITE, labels("7", "1", "clear-label-key", &[])); committed(&cleared);
        assert_eq!(result(&cleared)["labels_version"], text("2"));
        let held = head(&backend.node);
        let retry = invoke(&mut server, &mut backend, 9, WRITE, original.clone());
        assert_eq!(result(&retry), result(&first)); assert_eq!(head(&backend.node), held);
        let historical = invoke(&mut server, &mut backend, 10, READ, set(query("7"), "expected_head", pinned));
        assert_eq!(result(&historical)["labels"], Value::Array(vec![text("bug"), text("review")]));
        assert_eq!(result(&historical)["pull_request_version"], text("1"));
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap(); let mut server = start(&mut backend);
        let retry = invoke(&mut server, &mut backend, 2, WRITE, original); assert_eq!(result(&retry), result(&first));
        let current = invoke(&mut server, &mut backend, 3, READ, query("7"));
        assert_eq!(result(&current)["labels_version"], text("2"));
        assert_eq!(result(&current)["labels"], Value::Array(Vec::new()));
        assert_eq!(result(&current)["pull_request_version"], text("2"));
        let missing = invoke(&mut server, &mut backend, 4, READ, query("6"));
        assert_eq!(result(&missing)["found"], Value::Bool(false));
        assert_eq!(result(&missing)["labels_version"], Value::Null);
        assert_eq!(result(&missing)["labels"], Value::Null);
        assert_eq!(head(&backend.node), held);
        backend.close().unwrap();
    }
}

#[test]
fn native_and_filter_precedes_pagination_and_read_write_grants_remain_separate() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut options = fixture.options.clone(); options.pulls = true;
    let mut backend = NodeTools::open(options).unwrap(); let mut server = start(&mut backend);
    for (number, values) in [("1", vec!["bug"]), ("3", vec!["urgent"]), ("5", vec!["bug", "urgent"]), ("7", vec!["bug", "urgent"])] {
        committed(&invoke(&mut server, &mut backend, 2, OPEN, set(args(fixture.commit, "0", &format!("open-{number}"), "Filter subject"), "number", text(number))));
        committed(&invoke(&mut server, &mut backend, 3, WRITE, labels(number, "0", &format!("label-{number}"), &values)));
    }
    let query = object([("labels", Value::Array(vec![text("urgent"), text("bug")])), ("limit", json::number(1))]);
    let first = invoke(&mut server, &mut backend, 4, "frankengit_pull_list", query.clone());
    let Value::Array(rows) = &result(&first)["pull_requests"] else { panic!("rows") };
    assert_eq!(rows.len(), 1); assert_eq!(rows[0].object().unwrap()["number"], text("5"));
    assert_eq!(rows[0].object().unwrap()["labels_version"], text("1"));
    assert_eq!(result(&first)["next_after"], text("5"));
    assert_eq!(result(&first)["label_filter"], Value::Array(vec![text("bug"), text("urgent")]));
    let continued = set(set(query, "after", text("5")), "expected_head", result(&first)["snapshot_token"].clone());
    let next = invoke(&mut server, &mut backend, 5, "frankengit_pull_list", continued);
    let Value::Array(rows) = &result(&next)["pull_requests"] else { panic!("rows") };
    assert_eq!(rows.len(), 1); assert_eq!(rows[0].object().unwrap()["number"], text("7")); assert_eq!(result(&next)["next_after"], Value::Null);
    backend.options.writes.pulls = false;
    for name in [WRITE, ADD] {
        assert!(!backend.tools().iter().any(|tool| tool.name == name));
        assert_eq!(backend.call(name, &Object::new()).unwrap_err().code, "tool_not_granted");
    }
    assert!(backend.tools().iter().any(|tool| tool.name == READ));
    backend.options.writes.pulls = true; backend.options.pulls = false;
    assert_eq!(backend.call(READ, &Object::new()).unwrap_err().code, "tool_not_granted");
    assert!(backend.is_mutation(WRITE));
    assert!(backend.is_mutation(ADD));
    backend.close().unwrap();
}

#[test]
fn additions_preserve_union_and_original_receipts_across_exact_clear_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut options = fixture.options.clone(); options.pulls = true;
        let mut backend = NodeTools::open(options.clone()).unwrap(); let mut server = start(&mut backend);
        committed(&invoke(&mut server, &mut backend, 2, OPEN, args(fixture.commit, "0", "open-additions-subject", "Original")));
        let original = additions("7", "original-private-addition-key", &["bug"]);
        let first = invoke(&mut server, &mut backend, 3, ADD, original.clone()); committed(&first);
        assert_eq!(result(&first)["action"], text("add-labels"));
        assert_eq!(result(&first)["command_profile"], text("pull-request.add-labels.v1"));
        assert_eq!(result(&first)["expected_version"], Value::Null);
        assert_eq!(result(&first)["labels_version"], Value::Null);
        assert_eq!(result(&first)["labels"], Value::Array(vec![text("bug")]));
        assert_eq!(result(&first)["pull_request_version_changed"], Value::Bool(false));
        let known_fields: std::collections::BTreeSet<_> = fgit_schema::mcp::find_tool(ADD).unwrap().output_fields.iter().map(|field| field.name).collect();
        assert_eq!(known_fields, result(&first).keys().map(String::as_str).collect());
        assert!(!first.encode(16384).unwrap().contains("original-private-addition-key"));
        let second = invoke(&mut server, &mut backend, 4, ADD, additions("7", "overlapping-addition-key", &["urgent", "bug"])); committed(&second);
        let selected = invoke(&mut server, &mut backend, 5, READ, query("7"));
        assert_eq!(result(&selected)["labels"], Value::Array(vec![text("bug"), text("urgent")]));
        assert_eq!(result(&selected)["labels_version"], text("2"));
        assert_eq!(result(&selected)["pull_request_version"], text("1"));
        let pin = result(&selected)["snapshot_token"].clone();
        committed(&invoke(&mut server, &mut backend, 6, CLOSE, args(fixture.commit, "1", "close-additions-subject", "Original")));
        let cleared = invoke(&mut server, &mut backend, 7, WRITE, labels("7", "2", "clear-additions-key", &[])); committed(&cleared);
        assert_eq!(result(&cleared)["labels_version"], text("3"));
        let held = head(&backend.node);
        let retry = invoke(&mut server, &mut backend, 8, ADD, original.clone());
        assert_eq!(result(&retry), result(&first)); assert_eq!(head(&backend.node), held);
        let current = invoke(&mut server, &mut backend, 9, READ, query("7"));
        assert_eq!(result(&current)["labels"], Value::Array(Vec::new()));
        assert_eq!(result(&current)["labels_version"], text("3"));
        assert_eq!(result(&current)["pull_request_version"], text("2"));
        let historical = invoke(&mut server, &mut backend, 10, READ, set(query("7"), "expected_head", pin));
        assert_eq!(result(&historical)["labels"], Value::Array(vec![text("bug"), text("urgent")]));
        assert_eq!(result(&historical)["labels_version"], text("2"));
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap(); let mut server = start(&mut backend);
        let retry = invoke(&mut server, &mut backend, 2, ADD, original); assert_eq!(result(&retry), result(&first));
        let current = invoke(&mut server, &mut backend, 3, READ, query("7"));
        assert_eq!(result(&current)["labels"], Value::Array(Vec::new()));
        assert_eq!(result(&current)["labels_version"], text("3"));
        assert_eq!(head(&backend.node), held);
        backend.close().unwrap();
    }
}
