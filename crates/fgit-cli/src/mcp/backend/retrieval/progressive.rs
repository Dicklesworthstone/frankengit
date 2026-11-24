//! Buffered MCP delivery of the native two-phase source read. The original
//! Initial answer remains useful when ranked hydration refuses; no phase is
//! reconstructed from a second read, and this adapter never claims streaming.
use super::*;
use fgit_node::source_retrieval::authorization::{self, SourceReadContext};
use fgit_node::source_retrieval::context::ranked;
use std::io::{self, Write};

const PROFILE: &str = "source-context-progressive-mcp-v1";
// The native allowance includes both complete records and their framing. Leave
// room for the fixed MCP wrapper before native work, then check the actual final
// encoding too. The transport's outer text/structured envelope has its own cap.
const ENVELOPE_RESERVE: usize = 512;

pub(super) fn schema(ordinary: Value) -> Value {
    let mut progressive = ordinary.object().expect("context object schema").clone();
    let mut properties = progressive["properties"]
        .object()
        .expect("context properties")
        .clone();
    properties.insert("operation".into(), object([("const", text("progressive"))]));
    let outer_properties = properties.clone();
    properties.insert(
        "context_selection".into(),
        object([
            ("type", text("string")),
            ("const", text(ranked::PROFILE)),
            ("default", text(ranked::PROFILE)),
        ]),
    );
    progressive.insert("properties".into(), Value::Object(properties));
    progressive.insert(
        "required".into(),
        Value::Array(vec![
            text("operation"),
            text("reference"),
            text("terms_hex"),
        ]),
    );
    object([
        ("type", text("object")),
        ("properties", Value::Object(outer_properties)),
        ("additionalProperties", Value::Bool(false)),
        (
            "oneOf",
            Value::Array(vec![ordinary, Value::Object(progressive)]),
        ),
    ])
}

fn selectors(args: &Object) -> Result<Vec<(String, String)>, ToolError> {
    if string(args, "operation")? != Some("progressive") {
        return Err(ToolError::invalid("unsupported_context_operation"));
    }
    if string(args, "context_selection")?.is_some_and(|selection| selection != ranked::PROFILE) {
        return Err(ToolError::invalid("unsupported_context_selection"));
    }
    let mut ordinary = args.clone();
    ordinary.remove("operation");
    fields(&ordinary, true)
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    call_with_maximum(backend, args, MAX_RESULT_BYTES)
}

pub(super) fn call_with_maximum(
    backend: &NodeTools,
    args: &Object,
    maximum: usize,
) -> Result<Value, ToolError> {
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let fields = selectors(args)?;
    let native_maximum = maximum
        .min(MAX_RESULT_BYTES)
        .checked_sub(ENVELOPE_RESERVE)
        .ok_or(ToolError::failed("resource_limit"))?;
    let read = backend.source_read_context()?;
    // Retain one host request throughout buffering, parsing and serialization.
    // Sponsored native reads also retain the credential's original deadline.
    let request = backend.command_context();
    let live = || request.is_live();
    checkpoint(&live)?;
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        maximum: native_maximum,
        live: &live,
    };
    let outcome =
        backend
            .node
            .write_progressive_source_context(&read, fields, native_maximum, &mut output);
    checkpoint(&live)?;
    if output.bytes.is_empty() {
        return Err(outcome.err().map_or_else(invalid_report, refusal));
    }
    let phases = records(&output.bytes)?;
    let initial = answer(&phases[0], "Initial")?;
    validate_report(backend, args, false, initial)?;
    validate_source(backend, &read, initial)?;
    let (complete, refinement_succeeded) = match outcome {
        Ok(complete) => {
            let refined = answer(&phases[1], "Refined")?;
            validate_report(backend, args, true, refined)?;
            let fields = refined.object().ok_or_else(invalid_report)?;
            if fields.get("retrieval") != Some(initial)
                || fields.get("complete") != Some(&Value::Bool(complete))
                || fields.get("source_material_untrusted") != Some(&Value::Bool(true))
                || fields.get("selection").and_then(Value::text) != Some(ranked::PROFILE)
                || fields
                    .get("ranking")
                    .and_then(Value::object)
                    .and_then(|ranking| ranking.get("profile"))
                    .and_then(Value::text)
                    != Some(ranked::PROFILE)
            {
                return Err(invalid_report());
            }
            (complete, true)
        }
        Err(code) => {
            let terminal = phases[1].object().ok_or_else(invalid_report)?;
            if terminal.len() != 2
                || terminal.get("phase").and_then(Value::text) != Some("RefinementFailed")
                || terminal.get("code").and_then(Value::text) != Some(code)
            {
                return Err(invalid_report());
            }
            (false, false)
        }
    };
    checkpoint(&live)?;
    let value = envelope(phases, complete, refinement_succeeded);
    value
        .encode(maximum.min(MAX_RESULT_BYTES))
        .map_err(|_| ToolError::failed("resource_limit"))?;
    checkpoint(&live)?;
    Ok(value)
}

fn invalid_report() -> ToolError {
    ToolError::failed("invalid_progressive_report")
}

fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), ToolError> {
    if live() {
        Ok(())
    } else {
        Err(ToolError::failed("progressive_context_cancelled"))
    }
}

struct BoundedOutput<'a> {
    bytes: Vec<u8>,
    maximum: usize,
    live: &'a dyn Fn() -> bool,
}
impl Write for BoundedOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.flush()?;
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|total| total > self.maximum)
        {
            return Err(io::Error::other("progressive context output limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        // Interrupted is retryable by write_all; expiry must stop the native
        // writer instead of spinning on a permanently cancelled request.
        if (self.live)() {
            Ok(())
        } else {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
}

fn records(bytes: &[u8]) -> Result<Vec<Value>, ToolError> {
    let body = bytes.strip_suffix(b"\n").ok_or_else(invalid_report)?;
    let mut lines = body.split(|byte| *byte == b'\n');
    let mut records = Vec::with_capacity(2);
    for _ in 0..2 {
        let line = lines.next().ok_or_else(invalid_report)?;
        records.push(json::parse_with(line, DOCUMENT_LIMITS).map_err(|_| invalid_report())?);
    }
    if lines.next().is_some() {
        return Err(invalid_report());
    }
    Ok(records)
}

fn answer<'a>(record: &'a Value, phase: &str) -> Result<&'a Value, ToolError> {
    let record = record.object().ok_or_else(invalid_report)?;
    if record.len() != 2 || record.get("phase").and_then(Value::text) != Some(phase) {
        return Err(invalid_report());
    }
    record.get("answer").ok_or_else(invalid_report)
}

fn validate_source(
    backend: &NodeTools,
    read: &SourceReadContext,
    initial: &Value,
) -> Result<(), ToolError> {
    let initial = initial.object().ok_or_else(invalid_report)?;
    let authorization = initial
        .get("authorization")
        .and_then(Value::object)
        .ok_or_else(invalid_report)?;
    let principal = read
        .principal()
        .map_or(Value::Null, |id| text(id.to_string()));
    if initial.get("repository_incarnation").and_then(Value::text)
        != Some(
            backend
                .node
                .repository_incarnation_id()
                .to_string()
                .as_str(),
        )
        || authorization.get("profile").and_then(Value::text) != Some(authorization::PROFILE)
        || authorization.get("host").and_then(Value::text) != Some(read.host())
        || authorization.get("principal") != Some(&principal)
        || authorization.get("scope").and_then(Value::text) != Some("whole-repository")
        || authorization.get("reusable_capability") != Some(&Value::Bool(false))
    {
        return Err(invalid_report());
    }
    Ok(())
}

fn envelope(phases: Vec<Value>, complete: bool, refinement_succeeded: bool) -> Value {
    object([
        ("profile", text(PROFILE)),
        ("operation", text("progressive")),
        ("delivery", text("buffered")),
        ("read_only", Value::Bool(true)),
        ("transaction_created", Value::Bool(false)),
        ("source_material_untrusted", Value::Bool(true)),
        ("complete", Value::Bool(complete)),
        ("refinement_succeeded", Value::Bool(refinement_succeeded)),
        ("phases", Value::Array(phases)),
    ])
}

pub(super) fn result_is_error(value: &Value) -> bool {
    value.object().is_some_and(|result| {
        result.get("profile").and_then(Value::text) == Some(PROFILE)
            && result.get("refinement_succeeded") == Some(&Value::Bool(false))
    })
}

#[cfg(test)]
mod tests;
