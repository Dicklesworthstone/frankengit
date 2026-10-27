//! Authenticated read-only ContextPackets through the same native endpoint as HTTP.
//! The operator's launch grant fixes sponsorship; client text supplies only selectors.
use super::*;

pub(super) const NAME: &str = "frankengit_agent_context";
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const DOCUMENT_LIMITS: json::Limits = json::Limits {
    input: MAX_OUTPUT_BYTES,
    depth: 24,
    nodes: 1 << 18,
    items: 10_000,
    string: MAX_OUTPUT_BYTES,
};

pub(super) fn tool() -> Tool {
    Tool {
        name: NAME,
        description: "Read exact native source excerpts in an authenticated, invocation-only IntentRun and ContextPacket. The launch principal sponsors the read; the caller cannot replace it. Returns authority receipt, run and packet commitments, index generations, deliberate omissions and exact untrusted source bytes. Same native implementation as HTTP /api/v1/source/agent-context and fg agent context. Requires existing indexes and the independent agent-context grant; grants no publication, process execution or durable run.",
        schema: input_schema(),
    }
}

fn fields(args: &Object) -> Result<Vec<(String, String)>, ToolError> {
    if args.contains_key("expected_commit") {
        return Err(ToolError::invalid("unknown_argument"));
    }
    if string(args, "context_selection")?.is_some_and(|selection| selection != "raw-path-prefix") {
        return Err(ToolError::invalid("unsupported_context_selection"));
    }
    let mut selectors = args.clone();
    selectors.remove("expires_after_secs");
    selectors.remove("max_output_bytes");
    let mut mapped = retrieval::fields(&selectors, true)?;
    for (name, ceiling) in [
        ("expires_after_secs", 300),
        ("max_output_bytes", MAX_OUTPUT_BYTES as u64),
    ] {
        if let Some(value) = args.get(name) {
            let number = value
                .unsigned()
                .filter(|number| (1..=ceiling).contains(number))
                .ok_or(ToolError::invalid("invalid_limit"))?;
            mapped.push((name.to_owned(), number.to_string()));
        }
    }
    Ok(mapped)
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.agent_context {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let sponsor = backend
        .options
        .principal
        .ok_or(ToolError::failed("agent_context_sponsor_required"))?;
    if backend.options.incarnation != Some(backend.node.repository_incarnation_id()) {
        return Err(ToolError::failed("agent_context_incarnation_mismatch"));
    }
    let fields = fields(args)?;
    let read = fgit_node::source_retrieval::authorization::SourceReadContext::trusted_local_mcp(
        &backend.node,
    );
    let document = fgit_node::source_agent_context_json(
        &backend.node,
        &read,
        sponsor,
        fields,
        MAX_OUTPUT_BYTES,
    )
    .map_err(refusal)?;
    let value = json::parse_with(document.as_bytes(), DOCUMENT_LIMITS)
        .map_err(|_| ToolError::failed("invalid_agent_context_report"))?;
    validate_report(backend, &value)?;
    Ok(value)
}

fn validate_report(backend: &NodeTools, value: &Value) -> Result<(), ToolError> {
    let invalid = || ToolError::failed("invalid_agent_context_report");
    let report = value.object().ok_or_else(invalid)?;
    let sponsor = report
        .get("sponsor")
        .and_then(Value::object)
        .ok_or_else(invalid)?;
    let evidence = report
        .get("retrieval_evidence")
        .and_then(Value::object)
        .ok_or_else(invalid)?;
    let source = evidence
        .get("source")
        .and_then(Value::object)
        .ok_or_else(invalid)?;
    let run = report
        .get("run")
        .and_then(Value::object)
        .ok_or_else(invalid)?;
    let principal = backend.options.principal.ok_or_else(invalid)?.to_string();
    if report.get("type").and_then(Value::text) != Some("agent_context")
        || report.get("schema_version").and_then(Value::unsigned) != Some(1)
        || report.get("profile").and_then(Value::text) != Some("agent-context-trusted-local-v1")
        || report.get("read_only") != Some(&Value::Bool(true))
        || report.get("publication_authorized") != Some(&Value::Bool(false))
        || report.get("run_persistence").and_then(Value::text) != Some("invocation-only")
        || sponsor.get("principal_id").and_then(Value::text) != Some(principal.as_str())
        || sponsor.get("authentication").and_then(Value::text) != Some("operator-asserted")
        || sponsor.get("authorization_host").and_then(Value::text) != Some("trusted-local-mcp")
        || source.get("tenant_id").and_then(Value::text)
            != Some(backend.options.tenant.to_string().as_str())
        || source.get("repository_id").and_then(Value::text)
            != Some(backend.options.repository.to_string().as_str())
        || source.get("incarnation_id").and_then(Value::text)
            != Some(
                backend
                    .node
                    .repository_incarnation_id()
                    .to_string()
                    .as_str(),
            )
        || source.get("object_format").and_then(Value::text)
            != Some(backend.options.format.as_str())
        || run.get("allowed_operations")
            != Some(&Value::Array(vec![
                text("read_canonical_object"),
                text("read_derived_generation"),
            ]))
    {
        return Err(invalid());
    }
    Ok(())
}

fn refusal(code: &'static str) -> ToolError {
    if code.starts_with("invalid_")
        || code.starts_with("unknown_")
        || code.starts_with("unsupported_")
        || matches!(
            code,
            "missing_initial_field"
                | "duplicate_field"
                | "object_format_mismatch"
                | "symbol_options_without_name"
                | "too_many_symbol_kinds"
                | "unused_initial_field"
        )
    {
        ToolError::invalid(code)
    } else {
        ToolError::failed(code)
    }
}

fn input_schema() -> Value {
    let Value::Object(mut schema) = retrieval::input_schema(true) else {
        unreachable!()
    };
    let Some(Value::Object(properties)) = schema.get_mut("properties") else {
        unreachable!()
    };
    properties.remove("expected_commit");
    properties.insert(
        "context_selection".into(),
        object([
            ("type", text("string")),
            ("enum", Value::Array(vec![text("raw-path-prefix")])),
            (
                "description",
                text("Exact raw-path-prefix selection; ranking cannot alter this agent profile."),
            ),
        ]),
    );
    for (name, default, maximum) in [
        ("expires_after_secs", 30, 300),
        (
            "max_output_bytes",
            MAX_OUTPUT_BYTES as u64,
            MAX_OUTPUT_BYTES as u64,
        ),
    ] {
        properties.insert(
            name.into(),
            object([
                ("type", text("integer")),
                ("minimum", json::number(1)),
                ("maximum", json::number(maximum)),
                ("default", json::number(default)),
            ]),
        );
    }
    Value::Object(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Object {
        let Value::Object(arguments) = object([
            ("reference", text("refs/heads/main")),
            ("terms_hex", Value::Array(vec![text("6167656e74")])),
        ]) else {
            unreachable!()
        };
        arguments
    }

    #[test]
    fn selectors_and_bounds_map_to_the_shared_route_without_identity_overrides() {
        let mut permitted = base();
        permitted.insert("expires_after_secs".into(), json::number(300));
        permitted.insert(
            "max_output_bytes".into(),
            json::number(MAX_OUTPUT_BYTES as u64),
        );
        let mapped = fields(&permitted).unwrap();
        assert!(mapped.contains(&("term_hex".into(), "6167656e74".into())));
        assert!(mapped.contains(&("expires_after_secs".into(), "300".into())));
        for field in [
            "sponsor",
            "principal",
            "run_id",
            "capability",
            "storage_root",
            "expected_commit",
        ] {
            let mut forbidden = permitted.clone();
            forbidden.insert(field.into(), text("caller-selected"));
            assert_eq!(
                fields(&forbidden).unwrap_err().code,
                "unknown_argument",
                "{field}"
            );
        }
        for (field, value) in [
            ("expires_after_secs", 0),
            ("expires_after_secs", 301),
            ("max_output_bytes", 0),
            ("max_output_bytes", MAX_OUTPUT_BYTES as u64 + 1),
        ] {
            let mut forbidden = permitted.clone();
            forbidden.insert(field.into(), json::number(value));
            assert_eq!(fields(&forbidden).unwrap_err().code, "invalid_limit");
        }
        permitted.insert("context_selection".into(), text("raw-path-prefix"));
        assert!(fields(&permitted).is_ok());
        permitted.insert(
            "context_selection".into(),
            text("context-weighted-rrf-q16-v1"),
        );
        assert_eq!(
            fields(&permitted).unwrap_err().code,
            "unsupported_context_selection"
        );
    }

    #[test]
    fn schema_exposes_only_bounded_read_selectors() {
        let schema = input_schema();
        let properties = schema.object().unwrap()["properties"].object().unwrap();
        for field in ["sponsor", "principal", "run_id", "expected_commit"] {
            assert!(!properties.contains_key(field));
        }
        assert_eq!(
            properties["expires_after_secs"].object().unwrap()["maximum"].unsigned(),
            Some(300)
        );
        assert_eq!(
            properties["max_output_bytes"].object().unwrap()["maximum"].unsigned(),
            Some(MAX_OUTPUT_BYTES as u64)
        );
        assert_eq!(
            schema.object().unwrap()["additionalProperties"],
            Value::Bool(false)
        );
    }
}
