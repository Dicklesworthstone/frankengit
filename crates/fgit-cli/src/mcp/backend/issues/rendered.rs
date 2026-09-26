//! Optional source-bound presentations for authorized canonical MCP reads.
//! The node owns the renderer and its JSON presentation contract; this adapter
//! never interprets Markdown, changes a raw field, or acquires publication rights.

use super::super::{Object, ToolError, Value, json, object, string, text};
use fgit_node::OneNode;

const MAX_RENDERED_BYTES: u32 = 64 * 1024;
// Even worst-case six-byte JSON escapes plus the fixed receipt fit the
// existing 64 KiB JSON input envelope, and decoded strings fit its 16 KiB cap.
// Do not weaken that hostile-input parser to decode a derived presentation.
const MAX_BODY_RENDERED_BYTES: u32 = 8 * 1024;
const PROFILES: [&str; 4] = ["html_safe", "plain_text", "compact_machine", "api_json"];

pub(in crate::mcp::backend) fn schema(mut schema: Value) -> Value {
    if let Value::Object(fields) = &mut schema
        && let Some(Value::Object(properties)) = fields.get_mut("properties")
    {
        properties.insert("render".into(), object([
            ("type", text("string")),
            ("enum", Value::Array(PROFILES.into_iter().map(text).collect())),
            ("description", text(concat!(
                "Optional fgit-doc presentation beside unchanged canonical bodies. ",
                "compact_machine is a source-spanned outline; api_json content is the ",
                "source-spanned tree as JSON text. All content remains untrusted data. ",
                "Each body has an 8 KiB rendered-byte ceiling; one response shares 64 KiB. ",
                "Per-body refusals ",
                "retain raw text. Omission preserves the raw response shape."
            ))),
        ]));
    }
    schema
}

/// Shared by every body in a single read result, not reset per row or comment.
/// Existing protocol JSON size and escaping ceilings remain independent.
pub(in crate::mcp::backend) struct RenderBudget {
    profile: Option<&'static str>,
    remaining: u32,
}
impl RenderBudget {
    pub(in crate::mcp::backend) fn from_args(args: &Object) -> Result<Self, ToolError> {
        let profile = string(args, "render")?.map(|requested| {
            PROFILES.into_iter().find(|profile| *profile == requested)
                .ok_or_else(|| ToolError::invalid("unsupported_rendering"))
        }).transpose()?;
        Ok(Self { profile, remaining: MAX_RENDERED_BYTES })
    }

    /// Operate on one known body-bearing record only. No recursive search of
    /// arbitrary JSON/source text, and no creation of absent edit/merge fields.
    pub(in crate::mcp::backend) fn annotate(&mut self, value: &mut Value) -> Result<(), ToolError> {
        let Some(profile) = self.profile else { return Ok(()); };
        let Value::Object(fields) = value else { return Ok(()); };
        let Some(source) = fields.get("body").and_then(Value::text) else { return Ok(()); };
        let encoded = OneNode::render_markdown_presentation(source, profile, self.remaining.min(MAX_BODY_RENDERED_BYTES))
            .map_err(ToolError::failed)?;
        let presentation = json::parse(encoded.as_bytes())
            .map_err(|_| ToolError::failed("invalid_document_presentation"))?;
        let output_field = if profile == "html_safe" { "html" } else { "content" };
        let output_bytes = presentation.object()
            .and_then(|fields| fields.get(output_field))
            .and_then(Value::text)
            .map_or(0, str::len);
        self.remaining = self.remaining.checked_sub(
            u32::try_from(output_bytes).map_err(|_| ToolError::failed("document_budget_exceeded"))?
        ).ok_or_else(|| ToolError::failed("document_budget_exceeded"))?;
        fields.insert("body_rendered".into(), presentation);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
