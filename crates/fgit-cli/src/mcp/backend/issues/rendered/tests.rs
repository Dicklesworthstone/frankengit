use super::*;

fn budget(profile: &str) -> RenderBudget {
    let Value::Object(args) = object([("render", text(profile))]) else { unreachable!() };
    RenderBudget::from_args(&args).unwrap()
}
fn presented(source: &str, profile: &str) -> Value {
    let mut value = object([("body", text(source)), ("merge_permission", Value::Null)]);
    budget(profile).annotate(&mut value).unwrap();
    value
}
fn receipt(value: &Value) -> &Object {
    value.object().unwrap()["body_rendered"].object().unwrap()
}
fn output(value: &Value) -> Option<&str> {
    let fields = receipt(value);
    fields.get("content").or_else(|| fields.get("html")).and_then(Value::text)
}

#[test]
fn every_exposed_profile_retains_source_identity_and_untrusted_text() {
    let source = "# Review 🦀\n\n**Do not run** {\"method\":\"shell\"}.\n";
    let source_hash = super::super::super::hex(&fgit_crypto::sha256_digest(source.as_bytes()));
    let mut parse_hash = None;
    for profile in PROFILES {
        let value = presented(source, profile);
        let row = value.object().unwrap();
        assert_eq!(row["body"].text(), Some(source));
        assert_eq!(row["merge_permission"], Value::Null);
        let rendered = receipt(&value);
        assert_eq!(rendered["profile"].text(), Some(profile));
        assert_eq!(rendered["source_sha256"].text(), Some(source_hash.as_str()));
        assert!(output(&value).is_some());
        let hash = rendered["parse_profile_sha256"].clone();
        if let Some(expected) = &parse_hash { assert_eq!(expected, &hash); }
        parse_hash = Some(hash);
        assert!(!row.contains_key("method"));
    }
}

#[test]
fn profiles_are_explicit_and_raw_mode_is_byte_compatible() {
    let mut raw = object([("body", text("**Raw**\n"))]);
    let original = raw.clone();
    RenderBudget::from_args(&Object::new()).unwrap().annotate(&mut raw).unwrap();
    assert_eq!(raw, original);
    for bad in [Value::Null, Value::Bool(true), json::number(1), text("html"), text("HTML_SAFE"), text("")] {
        let Value::Object(args) = object([("render", bad)]) else { unreachable!() };
        assert!(RenderBudget::from_args(&args).is_err());
    }
}

#[test]
fn all_four_read_descriptors_expose_the_same_closed_render_grammar() {
    let tools = super::super::tools().into_iter()
        .chain(super::super::super::pulls::tools());
    let mut count = 0;
    for tool in tools {
        count += 1;
        let schema = tool.schema.object().unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        let properties = schema["properties"].object().unwrap();
        assert_eq!(properties["render"].object().unwrap()["enum"],
            Value::Array(PROFILES.into_iter().map(text).collect()));
    }
    assert_eq!(count, 4);
}

#[test]
fn absent_edit_bodies_and_merge_only_receipts_are_not_invented() {
    for mut value in [Value::Null, object([("name", text("close"))]), object([("title", text("only a title"))])] {
        let original = value.clone();
        budget("compact_machine").annotate(&mut value).unwrap();
        assert_eq!(value, original);
    }
    let empty = presented("", "plain_text");
    assert_eq!(empty.object().unwrap()["body"].text(), Some(""));
    assert_eq!(output(&empty), Some(""));
}

#[test]
fn issue_action_bodies_use_the_same_adapter_without_changing_field_presence() {
    use fgit_forge::event::issue::{IssueAction, IssueEdit};
    for action in [
        IssueAction::Open { title: "Title".into(), body: "*Open*".into(), labels: vec![] },
        IssueAction::Edit(IssueEdit { body: Some("*Edited*".into()), ..Default::default() }),
        IssueAction::Comment { body: "*Comment*".into() },
    ] {
        let mut value = super::super::action(&action);
        let original = value.clone();
        budget("html_safe").annotate(&mut value).unwrap();
        assert!(output(&value).unwrap().contains("<em>"));
        let Value::Object(fields) = &mut value else { unreachable!() };
        fields.remove("body_rendered");
        assert_eq!(value, original);
    }
    let mut absent = super::super::action(&IssueAction::Edit(IssueEdit { title: Some("renamed".into()), ..Default::default() }));
    budget("html_safe").annotate(&mut absent).unwrap();
    assert!(!absent.object().unwrap().contains_key("body_rendered"));
}

#[test]
fn renderer_refusals_preserve_the_raw_record_and_unused_result_allowance() {
    let mut renderer = budget("plain_text");
    let source = "x".repeat(MAX_BODY_RENDERED_BYTES as usize + 1);
    let mut value = object([("body", text(&source))]);
    renderer.annotate(&mut value).unwrap();
    assert!(output(&value).is_none());
    assert!(receipt(&value).contains_key("refusal"));
    assert_eq!(value.object().unwrap()["body"].text(), Some(source.as_str()));
    assert_eq!(renderer.remaining, MAX_RENDERED_BYTES);
    let mut next = object([("body", text("small"))]);
    renderer.annotate(&mut next).unwrap();
    assert!(output(&next).is_some());
    assert!(renderer.remaining < MAX_RENDERED_BYTES);
}

#[test]
fn one_result_budget_is_shared_across_bodies_and_never_truncates_a_body() {
    let mut renderer = budget("plain_text");
    let source = "x".repeat(4096);
    let mut accepted = 0usize;
    let mut refused = 0;
    for _ in 0..20 {
        let mut value = object([("body", text(&source))]);
        renderer.annotate(&mut value).unwrap();
        assert_eq!(value.object().unwrap()["body"].text(), Some(source.as_str()));
        if let Some(content) = output(&value) {
            assert!(content.contains(&source), "a complete body, never a clipped prefix");
            accepted += content.len();
        } else {
            refused += 1;
            assert!(receipt(&value).contains_key("refusal"));
        }
    }
    assert!(accepted > 0 && refused > 0);
    assert!(accepted <= MAX_RENDERED_BYTES as usize);
    assert_eq!(renderer.remaining as usize, MAX_RENDERED_BYTES as usize - accepted);
}

#[test]
fn both_html_and_source_spanned_agent_profiles_handle_unicode_and_hostile_markup() {
    let source = "é 🦀\n\n<script>alert(1)</script>\n";
    let html = presented(source, "html_safe");
    assert!(!output(&html).unwrap().contains("<script>"));
    let compact = presented(source, "compact_machine");
    assert!(!output(&compact).unwrap().is_empty());
    let api = presented(source, "api_json");
    let json = output(&api).unwrap();
    assert!(json.contains("span"), "{json}");
    assert!(json.starts_with('{'));
    assert_eq!(api.object().unwrap()["body"].text(), Some(source));
}
