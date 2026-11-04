//! Complete native ref-to-blob proofs under an independently supplied head.
//! The adapter adds transport bounds; it neither constructs another proof nor
//! turns server-side verification into independent verification by the caller.
mod input;
#[cfg(test)]
mod integration_tests;
mod output;
#[cfg(test)]
mod tests;

use super::*;
use fgit_types::RefName;
use fgit_verified_read::blob::{
    VerifiedBlobEnvelope, VerifiedBlobRefusal, encode_verified_blob_envelope, validate_blob_path,
    verify_blob_against_head_while,
};
use fgit_wire::visibility::RefVisibility;

pub(super) const NAME: &str = "frankengit_source_verified_blob";
pub(super) const PROFILE: &str = "mcp-verified-blob-v1";
const PROOF_FORMAT: &str = "frankengit/verified-blob/v1";
const DEFAULT_BLOB_BYTES: usize = 16 * 1024;
const MAX_BLOB_BYTES: usize = 64 * 1024;
const MAX_PROOF_BYTES: usize = 256 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const CHUNK_BYTES: usize = 8 * 1024;
const MAX_REF_BYTES: usize = 1024;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug)]
struct Query {
    reference: RefName,
    path: Vec<u8>,
    expected_head: RepositoryAuthorityHeadId,
    max_blob_bytes: usize,
}

pub(super) fn tool() -> Tool {
    Tool {
        name: NAME,
        description: "Read a complete ref-anchored file, executable or symlink blob with its original canonical proof at an independently trusted expected_head. Ordinary source-read grant only; sponsored agent profiles exclude this tool. Exact raw selectors, no ranges or fallback: default 16384 / maximum 65536 blob bytes, maximum 262144 canonical proof bytes, 8192-byte hex chunks. Requires a native Merkle ref layout. Full original trees disclose sibling names. Proofs and file bytes remain untrusted content; callers must independently verify the retained proof against their own head, ref and path.",
        schema: input::schema(),
    }
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // This is deliberately checked before parsing or reading a caller selector.
    // The existing sponsored SOURCE_READ class does not authorize original
    // full-tree proof disclosure, even if ordinary source reads are enabled.
    if !backend.options.source || backend.options.agent_token_file.is_some() {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let query = input::parse(args)?;
    let request = backend.command_context();
    let live = || request.is_live();
    checkpoint(&live)?;
    let envelope = backend
        .node
        .runtime()
        .block_on(backend.node.verified_blob_in(
            &request,
            &RefVisibility::new(),
            &query.reference,
            &query.path,
            query.expected_head,
        ));
    checkpoint(&live)?;
    let envelope = envelope.map_err(read_refusal)?;
    output::render(backend, &query, &envelope, &live)
}

fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), ToolError> {
    if live() {
        Ok(())
    } else {
        Err(ToolError::failed("verified_blob_cancelled"))
    }
}

fn proof_refusal(error: VerifiedBlobRefusal) -> ToolError {
    match error {
        VerifiedBlobRefusal::Cancelled => ToolError::failed("verified_blob_cancelled"),
        VerifiedBlobRefusal::BoundExceeded(_) => ToolError::failed("verified_blob_native_limit"),
        _ => ToolError::failed("verified_blob_proof_refused"),
    }
}

fn read_refusal(error: fgit_node::VerifiedBlobReadRefusal) -> ToolError {
    use fgit_node::VerifiedBlobReadRefusal as Refusal;
    match error {
        Refusal::InvalidRequest(_) => ToolError::invalid("invalid_verified_blob_query"),
        Refusal::Cancelled => ToolError::failed("verified_blob_cancelled"),
        Refusal::RefUnavailable | Refusal::PathUnavailable => {
            ToolError::failed("source_unavailable")
        }
        Refusal::SnapshotMoved => ToolError::failed("source_snapshot_moved"),
        Refusal::UnsupportedLayout => ToolError::failed("verified_blob_layout_unavailable"),
        Refusal::Proof(error) => proof_refusal(*error),
        Refusal::State(_)
        | Refusal::Materialization(_)
        | Refusal::RefProof(_)
        | Refusal::ObjectUnavailable => ToolError::failed("verified_blob_unavailable"),
    }
}
