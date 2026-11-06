//! Snapshot-pinned historical reads through a currently visible ref. The
//! selected commit must be reached through that ref's verified parent edges;
//! an object ID alone never grants access to repository objects.

use super::*;

pub(in crate::mcp::backend) const TREE: &str = "frankengit_source_historical_tree";
pub(in crate::mcp::backend) const BLOB: &str = "frankengit_source_historical_blob";

pub(super) fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: TREE,
            description: "List a bounded historical tree through a currently visible ref. Requires expected_head, expected_ref_tip and at_commit; native parent traversal proves the selected commit is reachable. Names use exact hex bytes. Current hidden-ref policy applies; no arbitrary-object access or publication.",
            schema: input_schema(false),
        },
        Tool {
            name: BLOB,
            description: "Read a bounded exact historical file byte range through a currently visible ref. Requires expected_head, expected_ref_tip and at_commit; native parent traversal proves reachability. Continue with the same pins and next_offset. Symlink contents are data, never followed; no checkout or publication.",
            schema: input_schema(true),
        },
    ]
}

struct Query {
    reference: RefName,
    expected_ref_tip: GitOid,
    at_commit: GitOid,
    browse: SourceBrowseQuery,
}

fn commit(args: &Object, name: &str, format: GitHashAlgorithm) -> Result<GitOid, ToolError> {
    let value = string(args, name)?.ok_or(ToolError::invalid("historical_selection_required"))?;
    if value.len() != format.digest_len() * 2 {
        return Err(ToolError::invalid("invalid_historical_commit"));
    }
    unhex(value, format.digest_len())?;
    let id = GitOid::from_hex(format, value)
        .map_err(|_| ToolError::invalid("invalid_historical_commit"))?;
    if id.is_zero() {
        return Err(ToolError::invalid("invalid_historical_commit"));
    }
    Ok(id)
}

fn parse(args: &Object, file: bool, format: GitHashAlgorithm) -> Result<Query, ToolError> {
    require_fields(
        args,
        if file {
            &[
                "reference",
                "path_hex",
                "offset",
                "max_bytes",
                "expected_head",
                "expected_ref_tip",
                "at_commit",
            ]
        } else {
            &[
                "reference",
                "path_hex",
                "after_hex",
                "limit",
                "expected_head",
                "expected_ref_tip",
                "at_commit",
            ]
        },
    )?;
    head(args, 0)?.ok_or(ToolError::invalid("snapshot_required"))?;
    let expected_ref_tip = commit(args, "expected_ref_tip", format)?;
    let at_commit = commit(args, "at_commit", format)?;
    // Reuse the current-source parser's exact path/range ceilings. The outer
    // grammar rejects ambiguous expected_commit and all unrecognized fields.
    let mut browse = args.clone();
    browse.remove("expected_ref_tip");
    browse.remove("at_commit");
    browse.insert("expected_commit".into(), text(at_commit.to_string()));
    let (reference, browse) = super::parse(&browse, file, format)?;
    Ok(Query {
        reference,
        expected_ref_tip,
        at_commit,
        browse,
    })
}

pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source || !matches!(name, TREE | BLOB) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let query = parse(args, name == BLOB, backend.options.format)?;
    let request = backend.command_context();
    let report = backend
        .node
        .runtime()
        .block_on(backend.node.browse_source_ancestor_local_in(
            &request,
            &query.reference,
            query.expected_ref_tip,
            query.at_commit,
            &query.browse,
        ))
        .map_err(read_error)?;
    if report.repository_id != backend.options.repository {
        return Err(ToolError::failed("repository_binding_mismatch"));
    }
    let mut result = backend.header(report.source_head);
    result.extend(render(&query.reference, &query.browse, &report)?);
    result.insert("type".into(), text("historical_source"));
    result.insert("schema_version".into(), json::number(1));
    result.insert("selection".into(), text("visible-ref-ancestor-v1"));
    result.insert(
        "source_ref_tip".into(),
        text(query.expected_ref_tip.to_string()),
    );
    result.insert("at_commit".into(), text(query.at_commit.to_string()));
    result.insert("transaction_created".into(), Value::Bool(false));
    result.insert("published".into(), Value::Bool(false));
    Ok(Value::Object(result))
}

fn input_schema(file: bool) -> Value {
    let Value::Object(mut schema) = super::input_schema(file) else {
        unreachable!()
    };
    let Some(Value::Object(properties)) = schema.get_mut("properties") else {
        unreachable!()
    };
    properties.remove("expected_commit");
    for (name, description) in [
        (
            "expected_ref_tip",
            "Exact current tip of the visible ref at expected_head. A moved ref refuses.",
        ),
        (
            "at_commit",
            "Historical commit reached through verified parent edges from expected_ref_tip. An unrelated object refuses.",
        ),
    ] {
        properties.insert(
            name.into(),
            object([
                ("type", text("string")),
                ("maxLength", json::number(64)),
                ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
                ("description", text(description)),
            ]),
        );
    }
    let Some(Value::Array(required)) = schema.get_mut("required") else {
        unreachable!()
    };
    required.extend([
        text("expected_head"),
        text("expected_ref_tip"),
        text("at_commit"),
    ]);
    Value::Object(schema)
}

#[cfg(test)]
mod tests;
