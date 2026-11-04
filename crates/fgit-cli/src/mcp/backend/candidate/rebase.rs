//! Whole-series native rebase through the existing preparation and inspection
//! owners. Source read never acquires publication authority or mutable state.
mod input;
mod inspection;
#[cfg(test)]
mod integration_tests;
mod output;
mod resolutions;
#[cfg(test)]
mod tests;

use super::super::{head, head_token};
use super::*;
use fgit_forge::preparation::rebase::resolutions::{RebaseCommitResolution, RebaseResolvedStep};
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, RebaseCommitter, RebaseError, RebasePreparation, RebaseRequest, RebaseStep,
    RebaseStepKind, RebaseStop,
};
use fgit_forge::preparation::resolution::ResolutionError;
use fgit_forge::preparation::{MergeSourceError, PreparationError, PreparationLimits};
use fgit_types::RepositoryAuthorityHeadId;

pub(super) const PREPARE: &str = "prepare_rebase";
pub(super) const RESOLVE: &str = "resolve_rebase";
pub(super) const INSPECT: &str = "inspect_rebase";
const PUBLICATION_TOOL: &str = "frankengit_source_publish_rebase";
const MAX_COMMITS: usize = 256;
const MAX_RESOLUTIONS: usize = 64;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

pub(super) fn schema(operation: &str) -> Value {
    if operation == INSPECT {
        inspection::schema()
    } else {
        input::schema(operation)
    }
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source || backend.options.agent_token_file.is_some() {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    if required(args, "operation")? == INSPECT {
        return inspection::call(backend, args);
    }
    let input = input::parse(args, backend.options.format)?;
    let request = backend.command_context();
    checkpoint(&mut || request.is_live())?;
    let prepared = if let Some(choices) = input.resolutions.as_deref() {
        backend
            .node
            .runtime()
            .block_on(backend.node.prepare_resolved_rebase_bundle_in(
                &request,
                &input.selection.reference,
                &input.selection.onto_reference,
                input.request,
                &Default::default(),
                input.selection.head,
                &input.committer,
                input.limits,
                choices,
            ))
    } else {
        backend
            .node
            .runtime()
            .block_on(backend.node.prepare_rebase_bundle_in(
                &request,
                &input.selection.reference,
                &input.selection.onto_reference,
                input.request,
                &Default::default(),
                input.selection.head,
                &input.committer,
                input.limits,
            ))
            .map(|artifact| (artifact, Vec::new()))
    };
    let (artifact, decisions) = prepared.map_err(|error| {
        if !request.is_live() {
            ToolError::failed("rebase_cancelled")
        } else if error.is_snapshot_moved() {
            ToolError::failed("source_snapshot_moved")
        } else if error.is_tip_moved() {
            ToolError::failed("rebase_tip_moved")
        } else if error.is_unavailable() {
            ToolError::failed("reference_unavailable")
        } else if error.is_invalid_input() {
            ToolError::invalid("invalid_rebase_inputs")
        } else if error.is_resource_refusal() {
            ToolError::failed("resource_limit")
        } else if error.is_cancelled() {
            ToolError::failed("rebase_cancelled")
        } else if let Some(cause) = error.preparation_refusal() {
            rebase_error(cause)
        } else if let Some(cause) = error.source_refusal() {
            source_error(cause)
        } else {
            ToolError::failed("rebase_preparation_failed")
        }
    })?;
    output::render(
        backend,
        &input,
        output::Report {
            head: artifact.source_head,
            outcome: &artifact.outcome,
            bundle: artifact.bundle.as_deref(),
            pack_objects: artifact.pack_objects,
            borrowed_objects: artifact.borrowed_objects,
            resolutions: &decisions,
        },
        &mut || request.is_live(),
    )
}
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ToolError> {
    if live() {
        Ok(())
    } else {
        Err(ToolError::failed("rebase_cancelled"))
    }
}
const fn invalid_report() -> ToolError {
    ToolError::failed("invalid_rebase_report")
}
fn bounded(value: Value, live: &mut impl FnMut() -> bool) -> Result<Value, ToolError> {
    checkpoint(live)?;
    value
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::failed("rebase_result_limit"))?;
    checkpoint(live)?;
    Ok(value)
}
fn source_error(error: &MergeSourceError) -> ToolError {
    match error {
        MergeSourceError::Cancelled => ToolError::failed("rebase_cancelled"),
        MergeSourceError::BudgetExceeded => ToolError::failed("resource_limit"),
        _ => ToolError::failed("rebase_source_unavailable"),
    }
}
fn preparation_error(error: &PreparationError) -> ToolError {
    match error {
        PreparationError::InvalidLimits
        | PreparationError::InvalidMetadata
        | PreparationError::InvalidPrefix
        | PreparationError::ObjectFormat => ToolError::invalid("invalid_rebase_inputs"),
        PreparationError::Budget(_) => ToolError::failed("resource_limit"),
        PreparationError::Source(error) => source_error(error),
        _ => ToolError::failed("rebase_preparation_failed"),
    }
}
fn rebase_error(error: &RebaseError) -> ToolError {
    match error {
        RebaseError::Preparation(error) => preparation_error(error),
        RebaseError::UpstreamOutsideLinearHistory => {
            ToolError::failed("upstream_outside_linear_history")
        }
        RebaseError::MergeCommit { .. } => ToolError::failed("merge_commit_in_rebase_suffix"),
        RebaseError::CyclicHistory(_) => ToolError::failed("invalid_rebase_history"),
        RebaseError::InvalidOriginalMetadata(_) => {
            ToolError::failed("unsupported_original_metadata")
        }
        RebaseError::DuplicateResolutionCommit(_) => {
            ToolError::invalid("duplicate_resolution_commit")
        }
        RebaseError::ResolutionOutsideSuffix(_) => ToolError::invalid("resolution_outside_suffix"),
        RebaseError::Resolution { error, .. } => match error {
            ResolutionError::Unresolved(_) => ToolError::failed("unresolved_conflicts"),
            ResolutionError::NonConflictPath(_) => {
                ToolError::invalid("resolution_path_is_not_a_conflict")
            }
            ResolutionError::MissingSide { .. } => ToolError::invalid("resolution_side_missing"),
            ResolutionError::NoConflicts => ToolError::failed("no_conflicts_to_resolve"),
            ResolutionError::Budget => ToolError::failed("resource_limit"),
            ResolutionError::Preparation(error) => preparation_error(error),
            _ => ToolError::invalid("invalid_resolution_set"),
        },
    }
}
fn publication(
    reference: &RefName,
    source: GitOid,
    onto: GitOid,
    candidate: GitOid,
    bytes: &[u8],
) -> Result<Value, ToolError> {
    handoff(object([
        ("reference_hex", text(hex(reference.as_bytes()))),
        ("expected_source", text(raw_oid(source))),
        ("onto", text(raw_oid(onto))),
        ("expected_candidate", text(raw_oid(candidate))),
        ("bundle_hex_chunks", encoded_chunks(bytes)?),
    ]))
}
fn handoff(arguments: Value) -> Result<Value, ToolError> {
    // Raw refs and exact bytes must fit another actual RPC, including framing
    // and space for the caller's original publication key.
    arguments
        .encode(json::MAX_INPUT - 4096)
        .map_err(|_| ToolError::failed("candidate_arguments_limit"))?;
    Ok(arguments)
}
