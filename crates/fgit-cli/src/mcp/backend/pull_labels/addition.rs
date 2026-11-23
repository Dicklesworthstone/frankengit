//! Additive label intents retain the original additions and key on every retry.
//! The receipt describes that intent, never a fabricated current label snapshot.

use super::{
    NodeTools, Object, Tool, ToolError, Value, common, json, parse_labels, require_fields, text,
};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::pull_request_labels::PullRequestLabelsIntent;

pub(in crate::mcp::backend) const ADD: &str = "frankengit_pull_add_labels";

pub(in crate::mcp::backend) fn add_tool() -> Tool {
    let mut properties = common::base_properties();
    properties.remove("expected_version");
    let mut labels = super::labels_schema();
    if let Value::Object(fields) = &mut labels {
        fields.insert("minItems".into(), json::number(1));
    }
    properties.insert("labels".into(), labels);
    Tool {
        name: ADD,
        description: "Add 1–32 distinct literal labels to an existing visible native PR without replacing other labels. The exact additions are unioned with the current independent label set during canonical admission, including after a competing writer. The resulting set must fit 32 labels. No expected_version, removal or clear is accepted. Does not change PR lifecycle, refs or review freshness. Retry an uncertain outcome with the identical number, additions and original durable key. Receipt labels echo the requested additions; labels_version is null because the terminal receipt is not a current label snapshot. Read labels separately for current state.",
        schema: common::input_schema(properties, &["number", "idempotency_key", "labels"]),
    }
}

fn intent(args: &Object) -> Result<PullRequestLabelsIntent, ToolError> {
    require_fields(args, &["number", "idempotency_key", "labels"])?;
    let labels = parse_labels(args, true)?;
    if labels.is_empty() {
        return Err(ToolError::invalid("nonempty_label_additions_required"));
    }
    Ok(PullRequestLabelsIntent {
        number: PullRequestNumber::try_new(common::number(args, "number")?)
            .ok_or(ToolError::invalid("positive_pull_number_required"))?,
        labels,
    })
}

pub(in crate::mcp::backend) fn add(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.pulls {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let intent = intent(args)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    let context = backend.command_context();
    let (tx, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_pull_request_add_labels_durable_in(
            &context,
            &session,
            &intent,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.extend(intent_fields(&intent));
    Ok(Value::Object(result))
}

fn intent_fields(intent: &PullRequestLabelsIntent) -> Object {
    [
        ("type", text("pull_request_labels_publication")),
        ("action", text("add-labels")),
        ("command_profile", text("pull-request.add-labels.v1")),
        ("number", text(intent.number.get().to_string())),
        ("expected_version", Value::Null),
        (
            "labels",
            Value::Array(intent.labels.iter().cloned().map(text).collect()),
        ),
        ("labels_version", Value::Null),
        ("refs_changed", Value::Bool(false)),
        ("pull_request_version_changed", Value::Bool(false)),
        ("historical_outcome", Value::Bool(true)),
        ("delivery_acknowledged", Value::Null),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Object {
        [
            ("number", text("7")),
            ("idempotency_key", text("private-original-key")),
            ("labels", Value::Array(vec![text("é"), text(" bug ")])),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
    }

    #[test]
    fn additions_preserve_exact_labels_and_reject_replacement_controls() {
        let args = arguments();
        let parsed = intent(&args).unwrap();
        assert_eq!(parsed.labels, [" bug ", "é"]);
        assert_eq!(parsed.number.get(), 7);
        for (name, value) in [
            ("expected_version", text("0")),
            ("clear_labels", Value::Bool(true)),
            ("principal", text("11".repeat(16))),
            ("force", Value::Bool(true)),
            ("labels", Value::Array(Vec::new())),
            ("labels", Value::Array(vec![text("bug"), text("bug")])),
            ("labels", Value::Array(vec![text("x\ny")])),
            (
                "labels",
                Value::Array((0..33).map(|n| text(format!("label-{n}"))).collect()),
            ),
        ] {
            let mut bad = args.clone();
            bad.insert(name.into(), value);
            assert!(intent(&bad).is_err(), "{name}");
        }
        let mut boundary = args;
        boundary.insert(
            "labels".into(),
            Value::Array((0..32).map(|n| text(format!("label-{n:02}"))).collect()),
        );
        assert_eq!(intent(&boundary).unwrap().labels.len(), 32);
    }

    #[test]
    fn discovery_and_receipts_never_invent_an_exact_version_or_final_set() {
        let schema = add_tool().schema;
        let fields = schema.object().unwrap();
        let properties = fields["properties"].object().unwrap();
        assert_eq!(fields["additionalProperties"], Value::Bool(false));
        assert!(!properties.contains_key("expected_version"));
        assert!(!properties.contains_key("principal"));
        assert_eq!(
            properties["labels"].object().unwrap()["minItems"],
            json::number(1)
        );
        let parsed = intent(&arguments()).unwrap();
        let receipt = intent_fields(&parsed);
        assert_eq!(
            receipt["labels"],
            Value::Array(vec![text(" bug "), text("é")])
        );
        assert_eq!(receipt["expected_version"], Value::Null);
        assert_eq!(receipt["labels_version"], Value::Null);
        assert_eq!(receipt["historical_outcome"], Value::Bool(true));
    }
}
