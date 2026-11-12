//! Validate the native document boundary and preserve exact decimal counters.
//! Native readers/renderers own object, source, generation and span validation.
use super::*;
use fgit_node::source_retrieval::current_index::LexicalChannel;
use fgit_types::GitHashAlgorithm;

pub(super) struct Scope {
    pub tenant: String,
    pub repository: String,
    pub incarnation: String,
    pub format: GitHashAlgorithm,
}
fn invalid() -> ToolError {
    ToolError::failed("invalid_index_report")
}
fn required_text<'a>(fields: &'a Object, name: &str) -> Result<&'a str, ToolError> {
    fields.get(name).and_then(Value::text).ok_or_else(invalid)
}
fn rows(value: Option<&Value>) -> Result<&[Value], ToolError> {
    match value {
        Some(Value::Array(rows)) => Ok(rows),
        _ => Err(invalid()),
    }
}
fn numeric(value: &Value, strings: bool) -> Result<u64, ToolError> {
    if strings {
        value
            .text()
            .and_then(|value| json::decimal(value).ok())
            .ok_or_else(invalid)
    } else {
        value.unsigned().ok_or_else(invalid)
    }
}
fn counter(fields: &mut Object, name: &str, strings: bool, maximum: u64) -> Result<u64, ToolError> {
    let number = numeric(fields.get(name).ok_or_else(invalid)?, strings)?;
    if number > maximum {
        return Err(invalid());
    }
    fields.insert(name.to_owned(), text(number.to_string()));
    Ok(number)
}
fn optional_counter(
    fields: &mut Object,
    name: &str,
    strings: bool,
) -> Result<Option<u64>, ToolError> {
    if fields.get(name) == Some(&Value::Null) {
        return Ok(None);
    }
    let value = counter(fields, name, strings, u64::MAX)?;
    if value == 0 {
        return Err(invalid());
    }
    Ok(Some(value))
}
fn check_scope(fields: &Object, scope: &Scope) -> Result<(), ToolError> {
    if required_text(fields, "tenant_id")? != scope.tenant
        || required_text(fields, "repository_id")? != scope.repository
        || required_text(fields, "repository_incarnation")? != scope.incarnation
        || required_text(fields, "object_format")? != scope.format.as_str()
    {
        return Err(invalid());
    }
    Ok(())
}
fn native_oid(fields: &Object, name: &str, scope: &Scope) -> Result<(), ToolError> {
    let value = required_text(fields, name)?;
    let id = fgit_types::GitOid::from_hex(scope.format, value).map_err(|_| invalid())?;
    if id.is_zero() {
        return Err(invalid());
    }
    Ok(())
}
fn provenance(fields: &Object, query: &input::Query, scope: &Scope) -> Result<(), ToolError> {
    if query.mode == input::Mode::Exact {
        if [
            "source_mode",
            "current_source",
            "indexed_source",
            "distinct_provenance",
        ]
        .iter()
        .any(|name| fields.contains_key(*name))
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if required_text(fields, "source_mode")? != query.mode.label() {
        return Err(invalid());
    }
    let current = fields
        .get("current_source")
        .and_then(Value::object)
        .ok_or_else(invalid)?;
    let indexed = fields
        .get("indexed_source")
        .and_then(Value::object)
        .ok_or_else(invalid)?;
    check_scope(current, scope)?;
    check_scope(indexed, scope)?;
    for name in [
        "ref_hex",
        "source_head",
        "snapshot_token",
        "source_rcr",
        "source_commit",
        "root_tree",
    ] {
        if current.get(name) != fields.get(name) || current.get(name).is_none() {
            return Err(invalid());
        }
    }
    for name in ["ref_hex", "source_commit", "root_tree"] {
        if current.get(name) != indexed.get(name) {
            return Err(invalid());
        }
    }
    if current.get("source_head") == indexed.get("source_head")
        && (current.get("source_rcr") != indexed.get("source_rcr")
            || current.get("forge_position_root") != indexed.get("forge_position_root"))
    {
        return Err(invalid());
    }
    if fields.get("distinct_provenance") != Some(&Value::Bool(current != indexed)) {
        return Err(invalid());
    }
    Ok(())
}
fn coverage(fields: &mut Object) -> Result<(), ToolError> {
    match fields.get("schema_version").and_then(Value::unsigned) {
        Some(1) => {
            for name in [
                "index_profile",
                "coverage_complete",
                "omitted_files",
                "omitted_source_bytes",
                "omissions",
            ] {
                if fields.contains_key(name) {
                    return Err(invalid());
                }
            }
            // The native v1 schema is issued only after complete coverage
            // validation. Expose that fact; never infer it from an empty page.
            fields.insert("index_profile".into(), text("ascii-word-postings-v1"));
            fields.insert("coverage_complete".into(), Value::Bool(true));
            fields.insert("omitted_files".into(), text("0"));
            fields.insert("omitted_source_bytes".into(), text("0"));
            fields.insert("omissions".into(), Value::Array(Vec::new()));
        }
        Some(2) => {
            if fields.get("coverage_complete") != Some(&Value::Bool(false))
                || required_text(fields, "index_profile")? != "ascii-word-postings-omissions-v1"
            {
                return Err(invalid());
            }
            let count = counter(fields, "omitted_files", false, 20_000)?;
            let bytes = counter(fields, "omitted_source_bytes", false, u64::MAX)?;
            let Some(Value::Array(omissions)) = fields.get_mut("omissions") else {
                return Err(invalid());
            };
            if count == 0 || count != omissions.len() as u64 {
                return Err(invalid());
            }
            let mut observed = 0_u64;
            for omission in omissions {
                let Value::Object(row) = omission else {
                    return Err(invalid());
                };
                let source_bytes = counter(row, "source_bytes", false, u64::MAX)?;
                let limit = counter(row, "limit", false, u64::MAX)?;
                if limit == 0
                    || source_bytes <= limit
                    || required_text(row, "reason")? != "file_bytes"
                {
                    return Err(invalid());
                }
                observed = observed.checked_add(source_bytes).ok_or_else(invalid)?;
            }
            if observed != bytes {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

pub(super) fn decode(
    document: &str,
    query: &input::Query,
    scope: &Scope,
) -> Result<Value, ToolError> {
    let mut result = json::parse_with(
        document.as_bytes(),
        json::Limits {
            input: MAX_RESULT_BYTES,
            depth: 16,
            nodes: 1 << 18,
            items: 10_000,
            string: 16 * 1024,
        },
    )
    .map_err(|_| invalid())?;
    let Value::Object(fields) = &mut result else {
        return Err(invalid());
    };
    check_scope(fields, scope)?;
    if required_text(fields, "type")? != query.mode.result_type()
        || required_text(fields, "profile")? != query.mode.profile()
        || fields.get("read_only") != Some(&Value::Bool(true))
        || fields.get("transaction_created") != Some(&Value::Bool(false))
        || fields.get("published") != Some(&Value::Bool(false))
        || fields.get("ref").and_then(Value::text) != Some(query.reference.as_str())
        || required_text(fields, "ref_hex")? != hex(query.reference.as_bytes())
        || query.head.as_ref().is_some_and(|head| {
            fields.get("snapshot_token").and_then(Value::text) != Some(head.as_str())
        })
        || query.commit.is_some_and(|commit| {
            fields.get("source_commit").and_then(Value::text) != Some(commit.to_string().as_str())
        })
    {
        return Err(invalid());
    }
    for (name, maximum) in [
        ("source_head", 256),
        ("source_rcr", 256),
        ("snapshot_token", 140),
        ("index_token", 140),
        ("selected_index_token", 140),
    ] {
        let value = required_text(fields, name)?;
        if value.is_empty() || value.len() > maximum || value.bytes().any(|byte| byte <= 32) {
            return Err(invalid());
        }
    }
    native_oid(fields, "source_commit", scope)?;
    native_oid(fields, "root_tree", scope)?;
    provenance(fields, query, scope)?;
    let channel = match query.query.channel() {
        LexicalChannel::Content => "content",
        LexicalChannel::Path => "path",
    };
    let terms: Vec<_> = query
        .query
        .terms()
        .iter()
        .map(|term| text(hex(term)))
        .collect();
    let prefixes: Vec<_> = query
        .query
        .prefixes()
        .iter()
        .map(|prefix| text(hex(prefix)))
        .collect();
    if required_text(fields, "channel")? != channel
        || rows(fields.get("terms_hex"))? != terms.as_slice()
        || rows(fields.get("path_prefix_hex"))? != prefixes.as_slice()
    {
        return Err(invalid());
    }
    let strings = query.mode == input::Mode::Revalidated;
    let index = counter(fields, "index_number", strings, u64::MAX)?;
    let selected = counter(fields, "selected_index_number", strings, u64::MAX)?;
    if index == 0
        || selected < index
        || query.generation.as_ref().is_some_and(|(token, number)| {
            fields.get("index_token").and_then(Value::text) != Some(token.as_str())
                || index != *number
        })
        || query
            .minimum
            .as_ref()
            .is_some_and(|(_, floor)| selected < *floor)
    {
        return Err(invalid());
    }
    if optional_counter(fields, "after", strings)? != query.after
        || counter(fields, "limit", false, MAX_PAGE)? != query.limit
    {
        return Err(invalid());
    }
    let returned = counter(fields, "returned_hits", false, MAX_PAGE)?;
    let next = optional_counter(fields, "next_after", strings)?;
    let complete = match fields.get("complete") {
        Some(Value::Bool(value)) => *value,
        _ => return Err(invalid()),
    };
    let indexed = counter(fields, "indexed_documents", false, 20_000)?;
    counter(fields, "indexed_source_bytes", false, 64 * 1024 * 1024)?;
    counter(fields, "non_regular_entries", false, 50_000)?;
    counter(fields, "segments_read", false, u64::MAX)?;
    counter(fields, "payload_bytes_read", false, query.max_payload_bytes)?;
    counter(fields, "generation_bytes_read", false, u64::MAX)?;
    counter(fields, "work_units", false, query.max_work)?;
    let Some(Value::Array(hits)) = fields.get_mut("hits") else {
        return Err(invalid());
    };
    if returned != hits.len() as u64 || returned > indexed || returned > query.limit {
        return Err(invalid());
    }
    let mut previous = query.after.unwrap_or(0);
    let mut previous_path = String::new();
    for hit in hits {
        let Value::Object(row) = hit else {
            return Err(invalid());
        };
        let id = counter(row, "document_id", strings, u64::MAX)?;
        let path = required_text(row, "path_hex")?.to_owned();
        let raw_path = unhex(&path, 4096).map_err(|_| invalid())?;
        if id <= previous
            || path <= previous_path
            || (!query.query.prefixes().is_empty()
                && !query.query.prefixes().iter().any(|prefix| {
                    raw_path == *prefix
                        || (raw_path.starts_with(prefix)
                            && raw_path.get(prefix.len()) == Some(&b'/'))
                }))
        {
            return Err(invalid());
        }
        previous = id;
        previous_path = path;
        native_oid(row, "blob", scope)?;
        let content_bytes = counter(row, "content_bytes", false, 8 * 1024 * 1024)?;
        let span_bound = match query.query.channel() {
            LexicalChannel::Content => content_bytes,
            LexicalChannel::Path => raw_path.len() as u64,
        };
        let Some(Value::Array(spans)) = row.get_mut("spans") else {
            return Err(invalid());
        };
        if spans.len() != query.query.terms().len() {
            return Err(invalid());
        }
        for (index, span) in spans.iter_mut().enumerate() {
            let Value::Object(span) = span else {
                return Err(invalid());
            };
            if counter(span, "query_index", false, 31)? != index as u64 {
                return Err(invalid());
            }
            let offset = counter(span, "byte_offset", false, 8 * 1024 * 1024)?;
            let length = counter(span, "byte_length", false, 128)?;
            if length != query.query.terms()[index].len() as u64
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > span_bound)
            {
                return Err(invalid());
            }
        }
    }
    if (complete && next.is_some())
        || (!complete && (returned != query.limit || next != Some(previous)))
    {
        return Err(invalid());
    }
    coverage(fields)?;
    fields.insert("source_mode".into(), text(query.mode.label()));
    fields.insert("counter_encoding".into(), text("decimal-strings-v1"));
    result
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::failed("index_result_limit"))?;
    Ok(result)
}
