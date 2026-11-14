use super::*;
use fgit_forge::event::pull_request::{NativePullRequestEvent, PullRequestAction, PullRequestData};
use fgit_forge::{AggregateId, ForgeEvent, ForgeEventPayload};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName};

fn arguments() -> Object {
    object([("number", text("7")), ("expected_version", text("0")), ("idempotency_key", text("private-original-key")), ("labels", Value::Array(vec![text("é"), text(" bug ")]))]).object().unwrap().clone()
}

#[test]
fn complete_set_is_required_bounded_and_preserves_exact_spelling() {
    let mut args = arguments();
    let parsed = command(&args).unwrap();
    assert_eq!(parsed.number.get(), 7);
    assert_eq!(parsed.expected_version, ExpectedVersion::NewStream);
    assert_eq!(parsed.labels, [" bug ", "é"]);
    args.insert("labels".into(), Value::Array(Vec::new()));
    assert!(command(&args).unwrap().labels.is_empty());
    args.remove("labels");
    assert_eq!(command(&args).unwrap_err().code, "labels_required");
    assert!(parse_labels(&args, false).unwrap().is_empty());
    for value in [Value::Null, text("bug"), Value::Array(vec![json::number(1)]), Value::Array(vec![text("a"), text("a")]), Value::Array(vec![text(" \t")]), Value::Array(vec![text("a\0b")]), Value::Array(vec![text("é".repeat(33))]), Value::Array((0..33).map(|n| text(format!("label-{n:02}"))).collect())] {
        let mut args = arguments(); args.insert("labels".into(), value); assert!(command(&args).is_err());
    }
    let mut args = arguments();
    args.insert("labels".into(), Value::Array(vec![text("bug"), text("BUG"), text(" bug "), text("é".repeat(32))]));
    assert!(command(&args).is_ok());
    args.insert("labels".into(), Value::Array((0..32).rev().map(|n| text(format!("label-{n:02}"))).collect()));
    assert_eq!(command(&args).unwrap().labels.len(), 32);
}

#[test]
fn command_versions_and_identity_cannot_be_coerced_or_widened() {
    for (field, value) in [("number", text("0")), ("number", json::number(7)), ("number", text("07")), ("expected_version", text(u64::MAX.to_string())), ("expected_version", text("01")), ("expected_version", json::number(0)), ("principal", text("11".repeat(16))), ("expected_head", text("invented")), ("force", Value::Bool(true))] {
        let mut args = arguments(); args.insert(field.into(), value); assert!(command(&args).is_err(), "{field}");
    }
    let mut args = arguments(); args.insert("expected_version".into(), text("9007199254740993"));
    assert_eq!(command(&args).unwrap().expected_version, ExpectedVersion::Exactly(AggregateVersion::try_new(9_007_199_254_740_993).unwrap()));
    for missing in ["number", "expected_version"] { let mut args = arguments(); args.remove(missing); assert!(command(&args).is_err()); }
    let mut args = arguments(); args.remove("idempotency_key"); assert!(common::key(&args).is_err());
}

fn row() -> PullRequestView {
    let number = PullRequestNumber::FIRST;
    let actor = PrincipalId::from_bytes([3; 16]);
    let data = PullRequestData {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(), target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"11".repeat(20)).unwrap(), target_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"22".repeat(20)).unwrap(),
        title: "Literal title".into(), body: String::new(),
    };
    PullRequestView { number, event: ForgeEvent { aggregate: AggregateId::PullRequest(number), version: AggregateVersion::FIRST, payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent { action: PullRequestAction::Open, actor, data: data.clone() }) }, data: Some(data), opened_by: Some(actor), last_metadata_actor: Some(actor), labels: Vec::new(), labels_version: None, labels_actor: None }
}

#[test]
fn unset_and_cleared_versions_remain_distinct_and_bad_overlay_fails_closed() {
    let mut row = row(); let mut fields = Object::new();
    append_row(&mut fields, &row).unwrap();
    assert_eq!(fields["labels_version"], text("0")); assert_eq!(fields["labels_actor"], Value::Null);
    row.labels_version = Some(AggregateVersion::try_new(9_007_199_254_740_993).unwrap()); row.labels_actor = Some(PrincipalId::from_bytes([4; 16]));
    append_row(&mut fields, &row).unwrap(); assert_eq!(fields["labels_version"], text("9007199254740993")); assert_eq!(fields["labels"], Value::Array(Vec::new()));
    row.labels = vec!["<script>literal</script>".into(), "é".into()]; append_row(&mut fields, &row).unwrap();
    row.labels.reverse(); assert!(append_row(&mut fields, &row).is_err()); row.labels.clear();
    row.labels_actor = None; assert!(append_row(&mut fields, &row).is_err());
    row.labels_actor = Some(PrincipalId::from_bytes([4; 16])); row.data = None; assert!(append_row(&mut fields, &row).is_err());
}

#[test]
fn discovery_requires_a_complete_replacement_and_has_no_actor_override() {
    let schema = write_tool().schema;
    let fields = schema.object().unwrap();
    assert_eq!(fields["additionalProperties"], Value::Bool(false));
    assert_eq!(fields["required"], Value::Array(["number", "expected_version", "idempotency_key", "labels"].into_iter().map(text).collect()));
    let properties = fields["properties"].object().unwrap();
    assert!(!properties.contains_key("principal")); assert!(!properties.contains_key("force"));
    assert_eq!(properties["labels"].object().unwrap()["maxItems"], json::number(32));
    let list = super::super::pulls::tools();
    assert!(list[0].schema.object().unwrap()["properties"].object().unwrap().contains_key("labels"));
    assert!(!list[1].schema.object().unwrap()["properties"].object().unwrap().contains_key("labels"));
}
