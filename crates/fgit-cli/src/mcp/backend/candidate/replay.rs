//! One historical change, through the native replay planner and ordinary
//! single-parent candidate workflow. A replay never admits or stages objects.
mod input;
mod output;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod integration_tests;

use super::super::{head, head_token};
use super::*;
use fgit_forge::preparation::replay::{
    ReplayCoordinates, ReplayDirection, ReplayError, ReplayPreparation, ReplayRequest,
};
use fgit_forge::preparation::resolution::{
    ConflictResolution, ResolutionChoice, ResolutionError, ResolutionKind, ResolvedPath,
};
use fgit_forge::preparation::{MergeMetadata, MergeSourceError, PreparationError, PreparationLimits};
use fgit_types::RepositoryAuthorityHeadId;

pub(super) const PREPARE: &str = "prepare_replay";
pub(super) const RESOLVE: &str = "resolve_replay";
const MAX_RESOLUTIONS: usize = 64;
// Hex paths, complete conflicts, both handoff templates and commit metadata
// share this independent encoded-result limit; the bundle still caps at 24 KiB.
const MAX_RESULT_BYTES: usize = 1024 * 1024;

pub(super) fn schema(resolving: bool) -> Value {
    input::schema(resolving)
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // Keep direct handler calls inside the operator-owned source read profile.
    // This operation is deliberately absent from the sponsored agent allowlist.
    if !backend.options.source || backend.options.agent_token_file.is_some() {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let input = input::parse(args, backend.options.format)?;
    let request = backend.command_context();
    checkpoint(&mut || request.is_live())?;
    let prepared = if let Some(choices) = input.resolutions.as_deref() {
        backend
            .node
            .runtime()
            .block_on(backend.node.prepare_resolved_replay_bundle_in(
                &request,
                &input.reference,
                &input.source,
                input.request,
                &Default::default(),
                input.expected_head,
                choices,
                &input.metadata,
                input.limits,
            ))
            .map(|resolved| (resolved.artifact, resolved.resolutions))
    } else {
        backend
            .node
            .runtime()
            .block_on(backend.node.prepare_replay_bundle_in(
                &request,
                &input.reference,
                &input.source,
                input.request,
                &Default::default(),
                input.expected_head,
                &input.metadata,
                input.limits,
            ))
            .map(|artifact| (artifact, Vec::new()))
    };
    // The node's typed accessors disclose no hidden ref, raw object owner,
    // private error text or arbitrary object ID.
    let (artifact, resolutions) = prepared.map_err(|error| {
        if error.is_snapshot_moved() {
            ToolError::failed("source_snapshot_moved")
        } else if error.is_tip_moved() {
            ToolError::failed("replay_tip_moved")
        } else if error.is_unavailable() {
            ToolError::failed("reference_unavailable")
        } else if error.is_invalid_input() {
            ToolError::invalid("invalid_replay_inputs")
        } else if error.is_resource_refusal() {
            ToolError::failed("resource_limit")
        } else if error.is_cancelled() {
            ToolError::failed("replay_cancelled")
        } else if let Some(cause) = error.preparation_refusal() {
            replay_error(cause)
        } else if let Some(cause) = error.source_refusal() {
            source_error(cause)
        } else {
            ToolError::failed("replay_preparation_failed")
        }
    })?;
    let result = output::render(
        backend,
        &input,
        output::Report {
            head: artifact.source_head,
            outcome: &artifact.outcome,
            bundle: artifact.bundle.as_deref(),
            pack_objects: artifact.pack_objects,
            borrowed_objects: artifact.borrowed_objects,
            resolutions: &resolutions,
        },
        &mut || request.is_live(),
    )?;
    checkpoint(&mut || request.is_live())?;
    Ok(result)
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ToolError> {
    if live() {
        Ok(())
    } else {
        Err(ToolError::failed("replay_cancelled"))
    }
}
const fn invalid_report() -> ToolError {
    ToolError::failed("invalid_replay_report")
}
fn source_error(error: &MergeSourceError) -> ToolError {
    match error {
        MergeSourceError::Cancelled => ToolError::failed("replay_cancelled"),
        MergeSourceError::BudgetExceeded => ToolError::failed("resource_limit"),
        _ => ToolError::failed("replay_preparation_failed"),
    }
}
fn preparation_error(error: &PreparationError) -> ToolError {
    match error {
        PreparationError::InvalidLimits
        | PreparationError::InvalidMetadata
        | PreparationError::InvalidPrefix
        | PreparationError::ObjectFormat => ToolError::invalid("invalid_replay_inputs"),
        PreparationError::Budget(_) => ToolError::failed("resource_limit"),
        PreparationError::Source(error) => source_error(error),
        _ => ToolError::failed("replay_preparation_failed"),
    }
}
fn replay_error(error: &ReplayError) -> ToolError {
    match error {
        ReplayError::MainlineRequired { .. } => ToolError::failed("mainline_required"),
        ReplayError::InvalidMainline { .. } => ToolError::invalid("invalid_mainline"),
        ReplayError::CommitOutsideSourceHistory => ToolError::failed("reference_unavailable"),
        ReplayError::Preparation(error) => preparation_error(error),
        ReplayError::Resolution(error) => match error.as_ref() {
            ResolutionError::Unresolved(_) => ToolError::failed("unresolved_conflicts"),
            ResolutionError::NonConflictPath(_) => {
                ToolError::invalid("resolution_path_is_not_a_conflict")
            }
            ResolutionError::MissingSide { .. } => ToolError::invalid("resolution_side_missing"),
            ResolutionError::NoConflicts => ToolError::failed("no_conflicts_to_resolve"),
            ResolutionError::InvalidInputs
            | ResolutionError::InvalidResolution { .. }
            | ResolutionError::DuplicatePath(_)
            | ResolutionError::OverlappingPaths => ToolError::invalid("invalid_resolution_set"),
            ResolutionError::Budget => ToolError::failed("resource_limit"),
            ResolutionError::Preparation(error) => preparation_error(error),
            _ => ToolError::failed("replay_preparation_failed"),
        },
    }
}
