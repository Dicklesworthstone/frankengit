//! Authorized host adapter over native persisted symbol readers. An index is
//! derived evidence, never a read grant, implicit refresh or scan fallback.
mod input;
#[cfg(test)]
mod integration_tests;
mod output;
#[cfg(test)]
mod tests;

use super::*;
use fgit_forge::source_symbols::index as data;
use fgit_node::source_retrieval::current_index::GenerationActivation;
use fgit_types::{CANONICAL_CODEC_VERSION, GenerationId, HeadGeneration, InternalObjectId};
use input::{Input, Mode};

const DEFAULT_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn schema(properties: Object) -> Value {
    input::schema(properties)
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    // The local native readers rely on the host's checked source authority.
    // Require the retained SOURCE_READ request before parsing or reading when
    // configured as an agent; command_context keeps that same request's original
    // deadline. A completed response or metadata request cannot substitute.
    let _authorization = backend.source_read_context()?;
    let input = input::parse(args, backend.options.format)?;
    let selected = &input.selected;
    let request = backend.command_context();
    let operation = match input.mode {
        Mode::Exact => backend
            .node
            .runtime()
            .block_on(backend.node.search_source_symbols_index_snapshot_local_in(
                &request,
                &selected.reference,
                selected.expected_head,
                selected.expected_commit,
                input.minimum.as_ref(),
                &input.query,
                selected.limits,
                input.maximum_payload_bytes,
            ))
            .map(|report| (report.source.clone(), report)),
        Mode::Current => backend.node.runtime().block_on(
            backend
                .node
                .search_source_symbols_index_revalidated_local_in(
                    &request,
                    &selected.reference,
                    selected.expected_head,
                    selected.expected_commit,
                    input.minimum.as_ref(),
                    &input.query,
                    selected.limits,
                    input.maximum_payload_bytes,
                ),
        ),
    };
    // Cancellation remains authoritative even if a lower storage/generation
    // layer uses an opaque refusal, and the same context covers output work.
    live(&mut || request.is_live())?;
    let (current, report) = operation.map_err(refusal)?;
    let fields = output::render(
        backend.header(current.head),
        &output::Scope {
            tenant: backend.options.tenant,
            repository: backend.options.repository,
            incarnation: backend.node.repository_incarnation_id(),
            format: backend.options.format,
        },
        &input,
        &current,
        &report,
        &mut || request.is_live(),
    )?;
    live(&mut || request.is_live())?;
    let result = bounded_result(fields)?;
    live(&mut || request.is_live())?;
    Ok(result)
}

fn live(is_live: &mut impl FnMut() -> bool) -> Result<(), ToolError> {
    if is_live() {
        Ok(())
    } else {
        Err(ToolError::failed("read_cancelled"))
    }
}

fn refusal<G>(error: data::AccessError<NodeWorkspaceRefusal, G>) -> ToolError {
    match error {
        data::AccessError::Source(error) => read_error(error),
        data::AccessError::Uninitialized => ToolError::failed("symbol_index_uninitialized"),
        data::AccessError::Stale => ToolError::failed("symbol_index_stale"),
        data::AccessError::Index(
            data::Error::Cancelled | data::Error::Table(data::TableError::Cancelled),
        ) => ToolError::failed("read_cancelled"),
        data::AccessError::Index(
            data::Error::Limit(_) | data::Error::Table(data::TableError::Limit(_)),
        ) => ToolError::failed("resource_limit"),
        data::AccessError::Generation(_) => {
            ToolError::failed("symbol_index_generation_unavailable")
        }
        _ => ToolError::failed("symbol_index_unavailable"),
    }
}

fn token(id: &InternalObjectId) -> String {
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

fn valid_generation(id: &InternalObjectId) -> bool {
    let algorithm = fgit_crypto::internal_algorithm_id(fgit_crypto::IdentityDomain::Generation);
    id.domain() == GenerationId::DOMAIN_TAG
        && id.algorithm() == algorithm
        && id.codec_version() == CANONICAL_CODEC_VERSION
        && fgit_crypto::DigestAlgorithm::from_id(algorithm)
            .is_some_and(|algorithm| id.digest().as_bytes().len() == algorithm.digest_len())
        && id.digest().as_bytes().iter().any(|byte| *byte != 0)
}
