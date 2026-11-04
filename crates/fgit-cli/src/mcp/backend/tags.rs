//! Native tag reads and ordinary sealed ref admission. Tagger and signature
//! bytes are repository content, never an authenticated principal or approval.
mod input;
#[cfg(test)]
mod integration_tests;
mod output;
#[cfg(test)]
mod tests;

use super::*;
use fgit_forge::tags::{TagReadLimits, TagRefusal};
use fgit_node::NodeWorkspaceRefusal;

pub(super) const INSPECT: &str = "frankengit_tag_inspect";
pub(super) const CREATE: &str = "frankengit_tag_create";
pub(super) const ANNOTATE: &str = "frankengit_tag_annotate";
pub(super) const DELETE: &str = "frankengit_tag_delete";

// The ordinary MCP JSON envelope admits strings of at most 16 KiB. Preserve
// that transport profile and bound hex expansion before native construction.
const MAX_MESSAGE_BYTES: usize = 8 * 1024;
const MAX_OBJECT_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = 512 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

pub(super) fn is_write(name: &str) -> bool {
    matches!(name, CREATE | ANNOTATE | DELETE)
}

pub(super) fn read_tool() -> Tool {
    Tool {
        name: INSPECT,
        description: "Inspect one visible native tag and its exact recursively peeled annotation bytes at a pinned repository snapshot. The expected_object pin compares the outer ref value, never authorizes an arbitrary object. Signature presence is not verification; tagger metadata is not authentication. Read-only; list tags with frankengit_ref_list namespace:tags.",
        schema: input::schema(INSPECT),
    }
}

pub(super) fn write_tools() -> Vec<Tool> {
    [
        (CREATE, "Create an absent lightweight tag at one explicit currently visible native object. No replacement or force. Uses ordinary sealed admission and the original idempotency key; a retry recovers its historical decision, not current tag state."),
        (ANNOTATE, "Create an absent native annotated tag with explicit target kind, tagger, timestamp and exact message_hex bytes (at most 8192 decoded bytes). Native quarantine verifies target visibility and kind. Metadata and signatures grant no authority; original-key recovery remains valid after later deletion."),
        (DELETE, "Delete one tag only at its exact unpeeled expected_object. No implicit latest tip, force or protection bypass. A retry with the identical original key recovers the canonical decision even after the tag has disappeared."),
    ]
    .into_iter()
    .map(|(name, description)| Tool {
        name,
        description,
        schema: input::schema(name),
    })
    .collect()
}

fn default_limits() -> TagReadLimits {
    TagReadLimits {
        max_tags: TagReadLimits::default().max_tags,
        max_object_bytes: MAX_OBJECT_BYTES,
        max_total_bytes: MAX_TOTAL_BYTES,
    }
}

pub(super) fn inspect(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source || backend.options.agent_token_file.is_some() {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let query = input::inspection(args, backend.options.format)?;
    let request = backend.command_context();
    let report = backend
        .node
        .runtime()
        .block_on(backend.node.read_tag_in(
            &request,
            &query.reference,
            &Default::default(),
            query.expected_head,
            query.limits,
        ))
        .map_err(read_error)?;
    if query.expected_object.is_some_and(|id| id != report.tip) {
        return Err(ToolError::failed("tag_object_moved"));
    }
    let mut fields = backend.header(report.head);
    fields.extend(output::inspection(
        backend.options.format,
        &query,
        &report,
        &mut || request.is_live(),
    )?);
    let result = output::bounded_inspection(fields)?;
    if !request.is_live() {
        return Err(ToolError::failed("tag_read_cancelled"));
    }
    Ok(result)
}

pub(super) fn write(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.source
        || !is_write(name)
        || backend.options.agent_token_file.is_some()
    {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let input = input::mutation(name, args, backend.options.format)?;
    let session = mutations::session(backend, input.key)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    let request = backend.command_context();
    // Do not pre-read the tag or substitute a current tip. The native engine
    // recovers decided retries before current visibility and intake checks.
    let admitted = backend
        .node
        .runtime()
        .block_on(backend.node.admit_tag_durable_in(
            &request,
            &session,
            &input.command,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("tag_mutation_outcome_unknown"))?;
    let mut fields = mutations::binding(backend, principal, false);
    // Canonical terminal knowledge survives cancellation after admission.
    fields.extend(output::publication(
        name,
        &input.reference_command,
        &admitted,
    )?);
    let result = Value::Object(fields);
    result
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::uncertain("tag_receipt_output_limit"))?;
    Ok(result)
}

fn read_error(error: NodeWorkspaceRefusal) -> ToolError {
    match error {
        NodeWorkspaceRefusal::RefUnavailable => ToolError::failed("tag_unavailable"),
        NodeWorkspaceRefusal::Tag(TagRefusal::SnapshotMoved) => ToolError::failed("snapshot_moved"),
        NodeWorkspaceRefusal::Tag(TagRefusal::Budget(_)) => ToolError::failed("resource_limit"),
        NodeWorkspaceRefusal::Tag(
            TagRefusal::InvalidName | TagRefusal::InvalidLimits | TagRefusal::ObjectFormat,
        ) => ToolError::invalid("invalid_tag_query"),
        NodeWorkspaceRefusal::Cancelled { .. } => ToolError::failed("tag_read_cancelled"),
        _ => ToolError::failed("tag_read_failed"),
    }
}
