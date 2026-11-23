//! Labels retain the canonical agent's independently revalidated pull scope.
use super::*;
use super::super::super::pull_labels::{ADD, READ, WRITE};
use super::super::super::pull_writes::OPEN;

fn replacement() -> Object {
    object([("number", text("7")), ("expected_version", text("0")), ("idempotency_key", text("agent-label-original")), ("labels", Value::Array(vec![text("bug")]))]).object().unwrap().clone()
}
fn addition() -> Object {
    object([("number", text("7")), ("idempotency_key", text("agent-label-add-original")), ("labels", Value::Array(vec![text("urgent")]))]).object().unwrap().clone()
}

#[test]
fn sponsored_labels_need_the_exact_read_or_write_scope_and_launch_ceiling() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut admin = NodeTools::open(fixture.options.clone()).unwrap();
    committed(&admin.call(OPEN, &pull_opening(&fixture, 7, "agent-label-subject")).unwrap());
    issue(&admin.node, &token(0x71), grant(&admin.node, PULLS_READ), "label-reader");
    let writer_id = issue(&admin.node, &token(0x72), grant(&admin.node, PULLS_WRITE), "label-writer");
    admin.close().unwrap();
    let query = object([("number", text("7"))]).object().unwrap().clone();
    let mut reader = NodeTools::open(fixture.replacement(0x71)).unwrap();
    let unset = reader.call(READ, &query).unwrap();
    assert_eq!(unset.object().unwrap()["labels_version"], text("0"));
    assert_eq!(reader.call(WRITE, &replacement()).unwrap_err().code, "agent_operation_not_granted");
    assert_eq!(reader.call(ADD, &addition()).unwrap_err().code, "agent_operation_not_granted");
    assert!(reader.agent.as_ref().unwrap().request.is_none()); reader.close().unwrap();
    let writer_options = fixture.replacement(0x72);
    let mut writer = NodeTools::open(writer_options.clone()).unwrap();
    assert_eq!(writer.call(READ, &query).unwrap_err().code, "agent_operation_not_granted");
    let first = writer.call(WRITE, &replacement()).unwrap(); committed(&first);
    assert_eq!(first.object().unwrap()["principal_id"], text(AGENT.to_string()));
    let original = provenance(&writer, "agent-label-original");
    assert_eq!(original.agent_provenance().unwrap().credential_id(), writer_id);
    assert_eq!(writer.call(WRITE, &replacement()).unwrap(), first);
    let added = writer.call(ADD, &addition()).unwrap(); committed(&added);
    assert_eq!(added.object().unwrap()["principal_id"], text(AGENT.to_string()));
    assert_eq!(added.object().unwrap()["labels_version"], Value::Null);
    let original = provenance(&writer, "agent-label-add-original");
    assert_eq!(original.agent_provenance().unwrap().credential_id(), writer_id);
    assert_eq!(writer.call(ADD, &addition()).unwrap(), added);
    assert!(writer.agent.as_ref().unwrap().request.is_none()); writer.close().unwrap();
    let mut narrow = writer_options; narrow.writes.pulls = false;
    let mut backend = NodeTools::open(narrow).unwrap();
    assert!(!backend.tools().iter().any(|tool| tool.name == WRITE));
    assert_eq!(backend.call(WRITE, &replacement()).unwrap_err().code, "tool_not_granted");
    assert!(!backend.tools().iter().any(|tool| tool.name == ADD));
    assert_eq!(backend.call(ADD, &addition()).unwrap_err().code, "tool_not_granted");
    backend.close().unwrap();
}
