//! Exact PR candidate reads. Source disclosure AND PR metadata disclosure are
//! independently required; neither a write grant nor a candidate grants either.
mod prepare;
mod inspect;
mod resolve;
#[cfg(test)]
mod tests;

use super::*;
use super::super::{head, head_token, mutations as common, review_writes as reviews};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{PolicyEpoch, RepositoryAuthorityHeadId};

pub(super) const PREPARE: &str = "prepare_pull_merge";
pub(super) const INSPECT: &str = "inspect_pull_merge";
pub(super) const RESOLVE: &str = "resolve_pull_merge";
const MAX_COMMIT_BYTES: usize = 64 * 1024;
const SUBJECT_FIELDS: &[&str] = &[
    "operation", "number", "expected_version", "source_reference",
    "source_reference_hex", "target_reference", "target_reference_hex",
    "expected_source", "expected_target", "policy_epoch", "expected_head",
];

#[derive(Debug)]
struct Selection {
    subject: ReviewSubject,
    expected_head: Option<RepositoryAuthorityHeadId>,
}

fn permitted(backend: &NodeTools) -> Result<(), ToolError> {
    if backend.options.source && backend.options.pulls {
        Ok(())
    } else {
        Err(ToolError::invalid("tool_not_granted"))
    }
}

fn selection(args: &Object, format: GitHashAlgorithm) -> Result<Selection, ToolError> {
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::try_new(common::number(args, "number")?)
            .ok_or(ToolError::invalid("positive_pull_number_required"))?,
        pull_request_version: AggregateVersion::try_new(common::number(args, "expected_version")?)
            .ok_or(ToolError::invalid("positive_pr_version_required"))?,
        source_ref: branch(args, "source_reference", "source_reference_hex")?,
        target_ref: branch(args, "target_reference", "target_reference_hex")?,
        source_tip: oid(args, "expected_source", format)?,
        target_tip: oid(args, "expected_target", format)?,
        policy_epoch: PolicyEpoch::try_new(common::number(args, "policy_epoch")?)
            .map_err(|_| ToolError::invalid("invalid_policy_epoch"))?,
    };
    subject.validate().map_err(|_| ToolError::invalid("invalid_pull_subject"))?;
    Ok(Selection { subject, expected_head: head(args, 0)? })
}

fn subject_properties(operation: &str) -> Object {
    let mut properties = Object::new();
    properties.insert("operation".into(), object([("const", text(operation))]));
    for name in ["number", "expected_version", "policy_epoch"] {
        properties.insert(name.into(), super::super::decimal_schema());
    }
    for name in ["source_reference", "target_reference"] {
        properties.insert(name.into(), text_schema(fgit_types::refs::MAX_REF_NAME_LEN));
    }
    for name in ["source_reference_hex", "target_reference_hex"] {
        properties.insert(name.into(), hex_schema(fgit_types::refs::MAX_REF_NAME_LEN));
    }
    for name in ["expected_source", "expected_target"] {
        properties.insert(name.into(), oid_schema());
    }
    properties.insert("expected_head".into(), text_schema(140));
    properties
}

fn subject_fields(subject: &ReviewSubject) -> Object {
    let Value::Object(fields) = object([
        ("number", text(subject.pull_request.get().to_string())),
        ("expected_version", text(subject.pull_request_version.get().to_string())),
        ("source_reference_hex", text(hex(subject.source_ref.as_bytes()))),
        ("target_reference_hex", text(hex(subject.target_ref.as_bytes()))),
        ("expected_source", text(raw_oid(subject.source_tip))),
        ("expected_target", text(raw_oid(subject.target_tip))),
        ("policy_epoch", text(subject.policy_epoch.get().to_string())),
    ]) else { unreachable!() };
    fields
}

fn candidate_arguments(
    subject: &ReviewSubject,
    candidate: CandidateBinding,
    bytes: &[u8],
) -> Result<Value, ToolError> {
    candidate.validate(subject).map_err(|_| invalid_report())?;
    let mut fields = subject_fields(subject);
    fields.insert("candidate_commit".into(), text(raw_oid(candidate.commit)));
    fields.insert("merge_base".into(), text(raw_oid(candidate.merge_base)));
    fields.insert("bundle_hex_chunks".into(), encoded_chunks(bytes)?);
    // Check compatibility with the ACTUAL review/merge input adapter, rather
    // than relying on a second set of serialized coordinate conventions.
    let parsed = reviews::subject(&fields, subject.source_tip.algorithm()).map_err(|_| invalid_report())?;
    if parsed != (subject.clone(), candidate) {
        return Err(invalid_report());
    }
    let arguments = Value::Object(fields);
    // Leave room for the existing RPC envelope, caller-owned key and named
    // reviewer set. Optional review text still shares the global input bound.
    arguments.encode(json::MAX_INPUT - 4096)
        .map_err(|_| ToolError::failed("candidate_arguments_limit"))?;
    Ok(arguments)
}

fn check_selection(
    selected: &Selection,
    actual: &ReviewSubject,
    source_head: RepositoryAuthorityHeadId,
) -> Result<(), ToolError> {
    if &selected.subject != actual {
        return Err(invalid_report());
    }
    if selected.expected_head.is_some_and(|head| head != source_head) {
        return Err(ToolError::failed("candidate_snapshot_moved"));
    }
    Ok(())
}

const fn invalid_report() -> ToolError {
    ToolError::failed("invalid_pull_candidate_report")
}

fn check_oid(id: GitOid, format: GitHashAlgorithm) -> Result<(), ToolError> {
    if id.is_zero() || id.algorithm() != format {
        Err(invalid_report())
    } else {
        Ok(())
    }
}

fn commit_fields(body: &[u8]) -> Result<Object, ToolError> {
    if body.is_empty() || body.len() > MAX_COMMIT_BYTES {
        return Err(ToolError::failed("candidate_commit_limit"));
    }
    let Value::Object(fields) = object([
        ("candidate_commit_body_hex", text(hex(body))),
        ("candidate_commit_text_utf8", std::str::from_utf8(body).map_or(Value::Null, text)),
    ]) else { unreachable!() };
    Ok(fields)
}

pub(super) fn schema() -> Value { prepare::schema() }
pub(super) fn inspection_schema() -> Value { inspect::schema() }
pub(super) fn resolution_schema() -> Value { resolve::schema() }

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    permitted(backend)?;
    match required(args, "operation")? {
        PREPARE => prepare::call(backend, args),
        INSPECT => inspect::call(backend, args),
        RESOLVE => resolve::call(backend, args),
        _ => Err(ToolError::invalid("unsupported_candidate_operation")),
    }
}
