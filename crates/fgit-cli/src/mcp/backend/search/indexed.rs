//! Complete, pinned pages over existing immutable lexical/path index owners.
//! Ordinary source-read grant only; this does not expand the sponsored catalogue.
mod input;
mod output;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod tests;

use super::*;

pub(in super::super) const NAME: &str = "frankengit_source_search_index";
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const MAX_PAGE: u64 = 100;
const MAX_WORK: u64 = 16 * 1024 * 1024;
const DEFAULT_PAYLOAD: u64 = 8 * 1024 * 1024;
const MAX_PAYLOAD: u64 = 32 * 1024 * 1024;

pub(super) fn tool() -> Tool {
    Tool {
        name: NAME,
        description: "Page all matching documents in a persisted native content or path index under an ordinary source-read grant. Continuation requires the original source head, commit and exact index identity/number. Current-source mode preserves original index provenance; exact mode is explicit. Completeness describes the page sequence, while coverage separately identifies omitted source files. Missing, stale, corrupt or over-budget indexes refuse; no implicit build or refresh. Sponsored profiles exclude this tool.",
        schema: input::schema(),
    }
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source || backend.options.agent_token_file.is_some() {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let mut query = input::parse(args, backend.options.format)?;
    let read = backend.source_read_context()?;
    let document = fgit_node::source_index_json(
        &backend.node,
        &read,
        std::mem::take(&mut query.fields),
        MAX_RESULT_BYTES,
    )
    .map_err(refusal)?;
    output::decode(
        &document,
        &query,
        &output::Scope {
            tenant: backend.options.tenant.to_string(),
            repository: backend.options.repository.to_string(),
            incarnation: backend.node.repository_incarnation_id().to_string(),
            format: backend.options.format,
        },
    )
}

fn refusal(code: &'static str) -> ToolError {
    let invalid = code.starts_with("invalid_")
        || code.starts_with("unknown_")
        || code.starts_with("unsupported_")
        || matches!(
            code,
            "tool_not_granted"
                | "missing_index_field"
                | "duplicate_field"
                | "object_format_mismatch"
                | "incomplete_index_generation"
                | "index_continuation_requires_pins"
        );
    if invalid {
        ToolError::invalid(code)
    } else {
        ToolError::failed(code)
    }
}
