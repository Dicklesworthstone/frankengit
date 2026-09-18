//! Source-scoped tools read only authority-selected, currently visible refs.
//! Repository paths are byte strings, never paths in the host filesystem.
use super::*;
use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseContent, SourceBrowseError,
    SourceBrowseQuery, SourceBrowseReport};
use fgit_node::NodeWorkspaceRefusal;
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

pub(super) fn tools() -> Vec<Tool> {
    vec![
        Tool { name: "frankengit_source_tree", description: "List immediate children of a visible repository ref and path. Paths and names use exact hex bytes. Snapshot-pinned, read-only; no host filesystem access.", schema: input_schema(false) },
        Tool { name: "frankengit_source_blob", description: "Read a bounded exact file byte range at a visible ref. Symlink contents are data, never followed. Continue with next_offset and snapshot_token; no checkout or arbitrary object lookup.", schema: input_schema(true) },
    ]
}
pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    let file = name == "frankengit_source_blob";
    let (reference, query) = parse(args, file, backend.options.format)?;
    let request = backend.node.request_context();
    let report = backend.node.runtime().block_on(backend.node.browse_source_local_in(&request, &reference, &query))
        .map_err(read_error)?;
    if report.repository_id != backend.options.repository {
        return Err(ToolError::failed("repository_binding_mismatch"));
    }
    let mut result = backend.header(report.source_head);
    result.extend(render(&reference, &query, &report)?);
    Ok(Value::Object(result))
}
fn bounded_number(args: &Object, name: &str, default: u64, maximum: u64) -> Result<u64, ToolError> {
    let value = args.get(name).map(|v| v.unsigned().ok_or(ToolError::invalid("invalid_limit")))
        .transpose()?.unwrap_or(default);
    if value == 0 || value > maximum { return Err(ToolError::invalid("invalid_limit")); }
    Ok(value)
}
fn parse(args: &Object, file: bool, format: GitHashAlgorithm) -> Result<(RefName, SourceBrowseQuery), ToolError> {
    require_fields(args, if file { &["reference", "path_hex", "offset", "max_bytes", "expected_head", "expected_commit"] }
        else { &["reference", "path_hex", "after_hex", "limit", "expected_head", "expected_commit"] })?;
    let reference = string(args, "reference")?.ok_or(ToolError::invalid("reference_required"))?;
    if reference.len() > 4096 || !reference.starts_with("refs/") { return Err(ToolError::invalid("invalid_reference")); }
    let reference = RefName::try_new(reference.as_bytes()).map_err(|_| ToolError::invalid("invalid_reference"))?;
    let path = string(args, "path_hex")?.map(|value| unhex(value, 4096)).transpose()?;
    let expected_head = head(args, 0)?;
    let expected_commit = string(args, "expected_commit")?.map(|value| {
        if !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(ToolError::invalid("invalid_expected_commit"));
        }
        GitOid::from_hex(format, value).map_err(|_| ToolError::invalid("invalid_expected_commit"))
    }).transpose()?;
    let action = if file {
        SourceBrowseAction::Read { offset: decimal(args, "offset", 0)?,
            limit: bounded_number(args, "max_bytes", 16 * 1024, 64 * 1024)? as u32 }
    } else {
        SourceBrowseAction::List { after: string(args, "after_hex")?.map(|value| unhex(value, 4096)).transpose()?,
            limit: bounded_number(args, "limit", 50, 100)? as u16 }
    };
    let query = SourceBrowseQuery { path, expected_head, expected_commit, action };
    query.validate(format).map_err(|_| ToolError::invalid("invalid_source_query"))?;
    Ok((reference, query))
}
fn render(reference: &RefName, query: &SourceBrowseQuery, report: &SourceBrowseReport) -> Result<Object, ToolError> {
    let invalid = || ToolError::failed("invalid_source_report");
    if query.expected_head.is_some_and(|head| head != report.source_head)
        || query.expected_commit.is_some_and(|id| id != report.source_commit)
        || query.path != report.path
        || [report.root_tree, report.object_id].iter().any(|id| id.is_zero() || id.algorithm() != report.source_commit.algorithm()) {
        return Err(invalid());
    }
    let Value::Object(mut result) = object([
        ("reference_hex", text(hex(reference.as_bytes()))), ("source_commit", text(report.source_commit.to_string())),
        ("root_tree", text(report.root_tree.to_string())), ("source_rcr", text(report.source_rcr.to_string())),
        ("object_id", text(report.object_id.to_string())),
        ("path_hex", report.path.as_deref().map_or(Value::Null, |p| text(hex(p)))),
    ]) else { unreachable!() };
    match (&query.action, &report.content) {
        (SourceBrowseAction::List { after, limit }, SourceBrowseContent::Directory { entries, next_after }) => {
            if entries.len() > usize::from(*limit) || entries.windows(2).any(|pair| pair[0].name >= pair[1].name)
                || entries.iter().any(|entry| entry.name.is_empty() || after.as_ref().is_some_and(|n| entry.name <= *n)
                    || entry.oid.is_zero() || entry.oid.algorithm() != report.source_commit.algorithm())
                || next_after.as_ref().is_some_and(|next| entries.len() != usize::from(*limit) || entries.last().map(|entry| &entry.name) != Some(next)) {
                return Err(invalid());
            }
            result.insert("entries".into(), Value::Array(entries.iter().map(|entry| object([
                ("name_hex", text(hex(&entry.name))), ("kind", text(entry.kind.as_str())),
                ("object_id", text(entry.oid.to_string())),
            ])).collect()));
            result.insert("next_after_hex".into(), next_after.as_deref().map_or(Value::Null, |n| text(hex(n))));
            result.insert("complete".into(), Value::Bool(next_after.is_none()));
        }
        (SourceBrowseAction::Read { offset: asked, limit }, SourceBrowseContent::Blob { kind, bytes, total_bytes, offset, next_offset }) => {
            let end = offset.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
            let expected_next = if end < *total_bytes { Some(end) } else { None };
            if asked != offset || end > *total_bytes || bytes.len() > *limit as usize
                || bytes.len() as u64 != total_bytes.saturating_sub(*offset).min(u64::from(*limit))
                || *next_offset != expected_next {
                return Err(invalid());
            }
            result.insert("kind".into(), text(kind.as_str()));
            result.insert("bytes_hex".into(), text(hex(bytes)));
            result.insert("text_utf8".into(), std::str::from_utf8(bytes).ok().map_or(Value::Null, text));
            result.insert("total_bytes".into(), text(total_bytes.to_string()));
            result.insert("offset".into(), text(offset.to_string()));
            result.insert("returned_bytes".into(), text(bytes.len().to_string()));
            result.insert("next_offset".into(), next_offset.map_or(Value::Null, |n| text(n.to_string())));
            result.insert("complete".into(), Value::Bool(next_offset.is_none()));
        }
        _ => return Err(invalid()),
    }
    Ok(result)
}
fn read_error(error: NodeWorkspaceRefusal) -> ToolError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ToolError::failed("reference_unavailable"),
        NodeWorkspaceRefusal::CommitRequired => ToolError::failed("commit_required"),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None } => ToolError::failed("read_cancelled"),
        NodeWorkspaceRefusal::Cancelled { exhaustion: Some(_) } => ToolError::failed("resource_limit"),
        NodeWorkspaceRefusal::SourceBrowse(error) => match *error {
            SourceBrowseError::SnapshotMoved => ToolError::failed("snapshot_moved"),
            SourceBrowseError::CommitMoved => ToolError::failed("source_commit_moved"),
            SourceBrowseError::InvalidRequest(_) => ToolError::invalid("invalid_source_query"),
            SourceBrowseError::RangeOutsideFile => ToolError::invalid("range_outside_file"),
            SourceBrowseError::ExpectedFile => ToolError::failed("file_required"),
            SourceBrowseError::Budget(_) => ToolError::failed("resource_limit"),
            _ => ToolError::failed("source_read_failed"),
        },
        _ => ToolError::failed("source_read_failed"),
    }
}
fn input_schema(file: bool) -> Value {
    let mut properties = Object::new();
    properties.insert("reference".into(), object([("type", text("string")), ("maxLength", json::number(4096)),
        ("description", text("Full currently visible UTF-8 ref, such as refs/heads/main. Never a host path or arbitrary object ID."))]));
    properties.insert("path_hex".into(), object([("type", text("string")), ("maxLength", json::number(8192)),
        ("pattern", text("^(?:[0-9a-f]{2})+$")), ("description", text("Exact relative repository path bytes; omitted only for tree root."))]));
    properties.insert("expected_head".into(), object([("type", text("string")), ("maxLength", json::number(140))]));
    properties.insert("expected_commit".into(), object([("type", text("string")), ("maxLength", json::number(64))]));
    if file {
        properties.insert("offset".into(), decimal_schema());
        properties.insert("max_bytes".into(), object([("type", text("integer")), ("minimum", json::number(1)), ("maximum", json::number(65536)), ("default", json::number(16384))]));
    } else {
        properties.insert("limit".into(), object([("type", text("integer")), ("minimum", json::number(1)), ("maximum", json::number(100)), ("default", json::number(50))]));
        properties.insert("after_hex".into(), object([("type", text("string")), ("maxLength", json::number(8192)), ("description", text("Immediate child name in hex; requires expected_head."))]));
    }
    object([("type", text("object")), ("properties", Value::Object(properties)), ("additionalProperties", Value::Bool(false)),
        ("required", Value::Array(if file { vec![text("reference"), text("path_hex")] } else { vec![text("reference")] }))])
}
#[cfg(test)]
mod tests;
