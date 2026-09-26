//! Explicit HTTP revalidation over the existing native reader, not a fallback.
//! Authentication, source-read enablement, route binding and idempotency-key
//! refusal remain in the source gateway and run before request body intake.

use super::{
    ApiError, Command, JsonReply, LexicalSource, OneNode, Status, append, check,
    drive_request_while, failure, hex, quote, render_at, token,
};
use crate::NodeRequestContext;
use crate::source_retrieval::current_index::RevalidatedIndexRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceMode {
    Exact,
    Revalidated,
}

impl SourceMode {
    pub(super) fn parse(value: Option<&str>) -> Result<Self, ApiError> {
        match value {
            None | Some("exact") => Ok(Self::Exact),
            Some("revalidated") => Ok(Self::Revalidated),
            _ => Err(ApiError::bad("invalid_index_source_mode")),
        }
    }

    // Retain the existing exact-mode wire shape. The new response profile uses
    // decimal strings for u64 identities/cursors, never lossy JavaScript numbers.
    pub(super) fn counter(self, value: u64) -> String {
        match self {
            Self::Exact => value.to_string(),
            Self::Revalidated => quote(&value.to_string()),
        }
    }

    pub(super) fn optional(self, value: Option<u64>) -> String {
        value.map_or_else(|| "null".to_owned(), |value| self.counter(value))
    }
}

pub(super) fn execute(
    node: &OneNode,
    context: &NodeRequestContext,
    command: &Command,
    maximum: u64,
    live: &mut impl FnMut() -> bool,
) -> Result<JsonReply, ApiError> {
    let report = drive_request_while(
        node,
        context,
        node.search_source_index_revalidated_local_in(
            context,
            RevalidatedIndexRequest {
                reference: &command.selection.reference,
                expected_head: command.selection.expected_head,
                expected_commit: command.selection.expected_commit,
                generation: command.generation.as_ref(),
                minimum: command.minimum.as_ref(),
                query: &command.query,
                after: command.after,
                query_limits: command.limits,
                read_limits: command.reads,
            },
        ),
        live,
    )
    .map_err(failure)?;
    let body = render_at(
        node,
        command,
        report.index(),
        report.current_source(),
        usize::try_from(maximum).unwrap_or(usize::MAX),
        live,
    )?;
    Ok(JsonReply {
        status: Status::Success,
        body,
        terminal: None,
    })
}

// Presentation-side consistency check, not an authorization proof. Both source
// observations must come from the node's private, verified report constructor.
pub(super) fn validate_sources(
    mode: SourceMode,
    indexed: &LexicalSource,
    current: &LexicalSource,
) -> Result<(), ApiError> {
    if (mode == SourceMode::Exact && indexed != current)
        || indexed.namespace != current.namespace
        || indexed.reference != current.reference
        || indexed.commit != current.commit
        || indexed.tree != current.tree
        || (indexed.source_head == current.source_head
            && (indexed.source_rcr != current.source_rcr
                || indexed.forge_position_root != current.forge_position_root))
    {
        return Err(ApiError::unavailable());
    }
    Ok(())
}

fn source_json(source: &LexicalSource) -> String {
    format!(
        concat!(
            "{{\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},",
            "\"object_format\":{},\"ref_hex\":{},\"source_head\":{},\"snapshot_token\":{},",
            "\"source_rcr\":{},\"forge_position_root\":{},\"source_commit\":{},\"root_tree\":{}}}"
        ),
        quote(&source.namespace.tenant.to_string()),
        quote(&source.namespace.repository.to_string()),
        quote(&source.namespace.incarnation.to_string()),
        quote(source.namespace.object_format.as_str()),
        quote(&hex(source.reference.as_bytes())),
        quote(&source.source_head.to_string()),
        quote(&token(source.source_head.as_internal_object_id())),
        quote(&source.source_rcr.to_string()),
        quote(&source.forge_position_root.to_string()),
        quote(&source.commit.to_string()),
        quote(&source.tree.to_string()),
    )
}

pub(super) fn append_sources(
    out: &mut String,
    indexed: &LexicalSource,
    current: &LexicalSource,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    check(live)?;
    append(out, "\"source_mode\":\"revalidated\",\"current_source\":", maximum)?;
    append(out, &source_json(current), maximum)?;
    append(out, ",\"indexed_source\":", maximum)?;
    append(out, &source_json(indexed), maximum)?;
    append(
        out,
        &format!(",\"distinct_provenance\":{},", indexed != current),
        maximum,
    )?;
    check(live)
}

#[cfg(test)]
mod tests;
