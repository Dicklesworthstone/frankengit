//! Canonical issue/PR event retrieval through independent launch-time read
//! grants. The node owns filtering, source selection and cursor advancement.
use super::*;

pub(super) const NAME: &str = "frankengit_events";

pub(super) fn tool() -> Tool {
    Tool {
        name: NAME,
        description: "Read canonical issue and PR events under the existing independent read grants. Cursor-paged and read-only. limit bounds scanned events, so an empty page may have next_after. Save resume_after for polling at a later head. Optional expected_head refuses snapshot movement. Cursors reveal repository activity and position gaps; no ungranted event payload is disclosed. No webhook acknowledgement, event append, long-poll or indexed-read claim.",
        schema: object([
            ("type", text("object")),
            ("properties", object([
                ("after", object([
                    ("type", text("string")),
                    ("maxLength", json::number(31)),
                    ("default", text("0")),
                    ("pattern", text("^(?:0|[1-9][0-9]{0,19}:(?:0|[1-9][0-9]{0,9}))$")),
                    ("description", text("Exact repository-sequence:event-index, or 0. Save the cursor with this repository incarnation and grant profile.")),
                ])),
                ("limit", object([
                    ("type", text("integer")),
                    ("minimum", json::number(1)),
                    ("maximum", json::number(100)),
                    ("default", json::number(20)),
                ])),
                ("expected_head", object([
                    ("type", text("string")),
                    ("maxLength", json::number(140)),
                    ("description", text("Optional exact snapshot_token. Omit to resume the append-stable cursor at the current head.")),
                ])),
            ])),
            ("additionalProperties", Value::Bool(false)),
        ]),
    }
}
struct Query {
    after: Option<(u64, u32)>,
    limit: u16,
    expected_head: Option<RepositoryAuthorityHeadId>,
}
fn parse(args: &Object) -> Result<Query, ToolError> {
    require_fields(args, &["after", "limit", "expected_head"])?;
    let after = OneNode::parse_forge_event_feed_cursor(string(args, "after")?.unwrap_or("0"))
        .map_err(|_| ToolError::invalid("invalid_event_cursor"))?;
    let limit = args.get("limit")
        .map(|v| v.unsigned().ok_or(ToolError::invalid("invalid_event_limit")))
        .transpose()?.unwrap_or(20);
    if !(1..=100).contains(&limit) { return Err(ToolError::invalid("invalid_event_limit")); }
    let expected_head = string(args, "expected_head")?.map(parse_head).transpose()?;
    Ok(Query { after, limit: limit as u16, expected_head })
}
fn cursor(cursor: Option<(u64, u32)>) -> Value {
    cursor.map_or(Value::Null, |(sequence, index)| text(format!("{sequence}:{index}")))
}
pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // Direct handler calls have the same guard as registry/dispatch, before
    // parsing or authority I/O. Write or source grants cannot disclose events.
    if !backend.options.issues && !backend.options.pulls {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let query = parse(args)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let page = backend.node.runtime().block_on(backend.node.read_scoped_forge_events_in(
        &request, query.after, query.limit, query.expected_head,
        backend.options.issues, backend.options.pulls,
    )).map_err(|error| match error.public_code() {
        "invalid_event_limit" | "invalid_event_cursor" => ToolError::invalid(error.public_code()),
        _ => ToolError::failed(error.public_code()),
    })?;
    let mut result = backend.header(page.source_head());
    result.extend([
        ("type".into(), text("forge_event_page")),
        ("schema_version".into(), json::number(1)),
        ("source_head".into(), text(page.source_head().to_string())),
        ("disclosure_profile".into(), text("issues-pulls-v1")),
        ("issues_read".into(), Value::Bool(page.issues_read())),
        ("pulls_read".into(), Value::Bool(page.pulls_read())),
        ("omits_other_event_families".into(), Value::Bool(true)),
        ("cursor_discloses_repository_activity".into(), Value::Bool(true)),
        ("events".into(), Value::Array(page.events().iter().map(|event| object([
            ("cursor", cursor(Some(event.cursor()))),
            ("repository_sequence", text(event.cursor().0.to_string())),
            ("event_index", text(event.cursor().1.to_string())),
            ("tx_id", text(event.tx_id().to_string())),
            ("policy_epoch", text(event.policy_epoch().get().to_string())),
            ("aggregate", text(event.aggregate().to_string())),
            ("aggregate_version", text(event.version().get().to_string())),
            ("kind", json::number(u64::from(event.kind()))),
            ("event_frame_hex", text(event.frame_hex())),
        ])).collect())),
        ("next_after".into(), cursor(page.next_after())),
        ("resume_after".into(), cursor(page.resume_after())),
        ("has_more".into(), Value::Bool(page.next_after().is_some())),
        ("complete".into(), Value::Bool(page.next_after().is_none())),
    ]);
    let result = Value::Object(result);
    result.encode(super::super::protocol::MAX_TOOL_RESULT)
        .map_err(|_| ToolError::failed("event_response_limit"))?;
    Ok(result)
}

#[cfg(test)]
mod tests;
