//! Exact conflict choices feed the native planner, then the native inspector
//! under one request budget and selecting head. Neither stage publishes.
mod input;
#[cfg(test)]
mod tests;

use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::preparation::{MergeSourceError, PreparationError};
use fgit_forge::preparation::resolution::{
    ConflictResolution, ResolutionChoice, ResolutionError, ResolutionKind, ResolvedPath,
};
use fgit_node::NodeWorkspaceRefusal;
use std::collections::BTreeMap;

pub(super) fn schema() -> Value { input::schema() }

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    permitted(backend)?;
    let input = input::parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let artifact = backend.node.runtime().block_on(
        backend.node.prepare_resolved_pull_request_bundle_in(
            &request, &input.selection.subject, input.base, &Default::default(),
            &input.resolutions, &input.metadata, input.limits,
        ),
    ).map_err(|error| {
        if error.is_snapshot_unavailable() {
            ToolError::failed("candidate_snapshot_moved")
        } else if let Some(error) = error.resolution_refusal() {
            resolution_error(error)
        } else {
            match error.source_refusal() {
                Some(NodeWorkspaceRefusal::RefUnavailable) => ToolError::failed("reference_unavailable"),
                Some(NodeWorkspaceRefusal::StaleWorkspaceBase) => ToolError::failed("pull_subject_moved"),
                Some(NodeWorkspaceRefusal::Cancelled { .. }) => ToolError::failed("resolution_cancelled"),
                _ => ToolError::failed("pull_resolution_failed"),
            }
        }
    })?;
    let subject = &input.selection.subject;
    check_selection(&input.selection, subject, artifact.source_head)?;
    let plan = &artifact.resolved.plan;
    if plan.base != input.base || plan.target != subject.target_tip || plan.source != subject.source_tip
        || artifact.bundle_sha256 != sha256_digest(&artifact.bundle)
    {
        return Err(invalid_report());
    }
    let paths = receipts(backend.options.format, &input.resolutions, &artifact.resolved.resolutions)?;
    let candidate = CandidateBinding { merge_base: plan.base, commit: plan.commit };
    let Value::Object(mut inspection) = candidate_arguments(subject, candidate, &artifact.bundle)?
    else { return Err(invalid_report()); };
    inspection.insert("operation".into(), text(INSPECT));
    inspection.insert("expected_head".into(), text(head_token(artifact.source_head)));
    inspection.insert("expected_bundle_sha256".into(), text(hex(&artifact.bundle_sha256)));
    input.inspection_limits(&mut inspection);
    // Drop generated object bodies before expanding the inspection. Its exact
    // head pin prevents merging a preparation with a newer PR or hidden policy.
    drop(artifact);
    let Value::Object(mut result) = inspect::call_in(backend, &inspection, &request)?
    else { return Err(invalid_report()); };
    result.insert("type".into(), text("pull_merge_resolution"));
    result.insert("operation".into(), text(RESOLVE));
    result.insert("resolution_profile".into(), text("path-merge-v1/exact-conflicts"));
    result.insert("resolution_count".into(), text(input.resolutions.len().to_string()));
    result.insert("resolved_paths".into(), paths);
    result.insert("inspection_performed".into(), Value::Bool(true));
    let result = Value::Object(result);
    result.encode(MAX_TOOL_RESULT).map_err(|_| ToolError::failed("candidate_response_limit"))?;
    Ok(result)
}

const fn choice_name(choice: ResolutionKind) -> &'static str {
    match choice {
        ResolutionKind::Base => "base", ResolutionKind::Ours => "ours",
        ResolutionKind::Theirs => "theirs", ResolutionKind::Delete => "delete",
        ResolutionKind::File => "file",
    }
}

// Validate actual per-path planner receipts against the complete submitted set.
// Input order is not authority: native receipts are joined by exact path, and
// duplicate/extra/missing rows refuse before any result is encoded.
fn receipts(
    format: GitHashAlgorithm,
    requested: &[ConflictResolution],
    observed: &[ResolvedPath],
) -> Result<Value, ToolError> {
    let by_path: BTreeMap<_, _> = observed.iter().map(|row| (row.conflict.path.as_slice(), row)).collect();
    if observed.len() != requested.len() || by_path.len() != observed.len() {
        return Err(invalid_report());
    }
    let mut result = Vec::with_capacity(requested.len());
    for request in requested {
        let row = by_path.get(request.path.as_slice()).ok_or_else(invalid_report)?;
        if row.choice != request.choice.kind() { return Err(invalid_report()); }
        match &request.choice {
            ResolutionChoice::Base | ResolutionChoice::Ours | ResolutionChoice::Theirs => {
                let expected = match &request.choice {
                    ResolutionChoice::Base => &row.conflict.base,
                    ResolutionChoice::Ours => &row.conflict.ours,
                    _ => &row.conflict.theirs,
                };
                if expected.is_none() || &row.result != expected { return Err(invalid_report()); }
            }
            ResolutionChoice::Delete => {
                if row.result.is_some() { return Err(invalid_report()); }
            }
            ResolutionChoice::File { mode, bytes } => {
                let value = row.result.as_ref().ok_or_else(invalid_report)?;
                if value.mode != *mode || value.oid != git_object_id(format, GitObjectKind::Blob, bytes) {
                    return Err(invalid_report());
                }
            }
        }
        let entry = if let Some(entry) = &row.result {
            check_oid(entry.oid, format)?;
            if request.path.split(|byte| *byte == b'/').next_back() != Some(entry.name.as_slice())
                || !matches!(entry.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000)
            { return Err(invalid_report()); }
            object([("oid", text(raw_oid(entry.oid))), ("mode", text(format!("{:06o}", entry.mode)))])
        } else { Value::Null };
        result.push(object([
            ("path_hex", text(hex(&request.path))),
            ("choice", text(choice_name(row.choice))),
            ("result", entry),
        ]));
    }
    Ok(Value::Array(result))
}

fn resolution_error(error: &ResolutionError) -> ToolError {
    match error {
        ResolutionError::Unresolved(_) => ToolError::failed("unresolved_conflicts"),
        ResolutionError::NonConflictPath(_) => ToolError::invalid("resolution_path_is_not_a_conflict"),
        ResolutionError::MissingSide { .. } => ToolError::invalid("resolution_side_missing"),
        ResolutionError::BaseMismatch { .. } => ToolError::failed("merge_base_mismatch"),
        ResolutionError::NoConflicts => ToolError::failed("no_conflicts_to_resolve"),
        ResolutionError::Budget | ResolutionError::Preparation(PreparationError::Budget(_))
        | ResolutionError::Preparation(PreparationError::Source(MergeSourceError::BudgetExceeded)) => ToolError::failed("resource_limit"),
        ResolutionError::Preparation(PreparationError::Source(MergeSourceError::Cancelled)) => ToolError::failed("resolution_cancelled"),
        _ => ToolError::failed("pull_resolution_failed"),
    }
}
