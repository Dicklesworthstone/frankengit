//! Inspect the actual uploaded two-parent result before any review or merge.
//! Native selection, closure checking and comparison own the evidence; this
//! adapter supplies no new object store, admission path or approval authority.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use std::collections::BTreeSet;

const LIMITS: &[(&str, usize, usize, usize)] = &[
    ("context_lines", 3, 0, 20),
    ("max_changes", 64, 1, 64),
    ("max_blob_bytes", 1024 * 1024, 1, 1024 * 1024),
    ("max_output_bytes", 64 * 1024, 1, 128 * 1024),
    ("max_diff_work", 1_000_000, 1, 1_000_000),
];
struct Input {
    selection: Selection,
    candidate: CandidateBinding,
    bundle: Vec<u8>,
    digest: [u8; 32],
    options: ReviewOptions,
}
fn bound(args: &Object, name: &str) -> Result<usize, ToolError> {
    let &(_, default, minimum, maximum) = LIMITS.iter().find(|limit| limit.0 == name)
        .ok_or(ToolError::invalid("invalid_inspection_limit"))?;
    let value = args.get(name).map(|value| value.unsigned()
        .ok_or(ToolError::invalid("invalid_inspection_limit")))
        .transpose()?.unwrap_or(default as u64);
    let value = usize::try_from(value)
        .map_err(|_| ToolError::invalid("invalid_inspection_limit"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ToolError::invalid("invalid_inspection_limit"));
    }
    Ok(value)
}
fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let mut allowed = SUBJECT_FIELDS.to_vec();
    allowed.extend(["candidate_commit", "merge_base", "bundle_hex_chunks", "expected_bundle_sha256"]);
    allowed.extend(LIMITS.iter().map(|limit| limit.0));
    require_fields(args, &allowed)?;
    if required(args, "operation")? != INSPECT {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    let selection = selection(args, format)?;
    let (subject, candidate) = reviews::subject(args, format)?;
    if subject != selection.subject {
        return Err(ToolError::invalid("invalid_pull_subject"));
    }
    let bundle = chunks(args, "bundle_hex_chunks")?;
    let digest = sha256_digest(&bundle);
    if let Some(expected) = string(args, "expected_bundle_sha256")?
        && (expected.len() != 64 || unhex(expected, 32)?.as_slice() != digest.as_slice())
    {
        return Err(ToolError::invalid("bundle_digest_mismatch"));
    }
    let mut options = ReviewOptions {
        mode: ComparisonMode::Direct,
        ..ReviewOptions::default()
    };
    options.context_lines = bound(args, "context_lines")?;
    options.limits.max_changes = bound(args, "max_changes")?;
    options.limits.max_blob_bytes = bound(args, "max_blob_bytes")?;
    options.limits.max_output_bytes = bound(args, "max_output_bytes")?;
    options.limits.max_diff_work = bound(args, "max_diff_work")?;
    options.limits.max_hunks = 256;
    options.limits.max_text_files = 32;
    options.validate().map_err(|_| ToolError::invalid("invalid_inspection_limit"))?;
    Ok(Input { selection, candidate, bundle, digest, options })
}

pub(super) fn schema() -> Value {
    let mut properties = subject_properties(INSPECT);
    for name in ["candidate_commit", "merge_base"] {
        properties.insert(name.into(), oid_schema());
    }
    properties.insert("bundle_hex_chunks".into(), chunk_schema());
    properties.insert("expected_bundle_sha256".into(), object([
        ("type", text("string")), ("pattern", text("^[0-9a-f]{64}$")),
    ]));
    for &(name, default, minimum, maximum) in LIMITS {
        properties.insert(name.into(), object([
            ("type", text("integer")), ("minimum", json::number(minimum as u64)),
            ("maximum", json::number(maximum as u64)), ("default", json::number(default as u64)),
        ]));
    }
    reviews::candidate_schema(properties, &[
        "operation", "number", "expected_version", "expected_source", "expected_target",
        "policy_epoch", "candidate_commit", "merge_base", "bundle_hex_chunks",
    ])
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    permitted(backend)?;
    let request = fgit_cli::command_request_context(&backend.node);
    call_in(backend, args, &request)
}

// Composed preparation/inspection retains the caller's SAME request context;
// entering another adapter must not reset cancellation or its server-work budget.
pub(super) fn call_in(
    backend: &NodeTools,
    args: &Object,
    request: &fgit_node::NodeRequestContext,
) -> Result<Value, ToolError> {
    permitted(backend)?;
    let input = parse(args, backend.options.format)?;
    // This native API ties PR metadata, both visible parents and the uploaded
    // result to one exact head. No separate latest-PR lookup precedes it.
    let inspected = backend.node.runtime().block_on(
        backend.node.inspect_pull_request_bundle_in(
            request, &input.selection.subject, input.candidate, &input.bundle,
            &Default::default(), &input.options,
        ),
    ).map_err(|_| ToolError::failed("pull_candidate_inspection_failed"))?;
    let subject = &input.selection.subject;
    check_selection(&input.selection, &inspected.subject, inspected.review.source_head)?;
    if inspected.candidate != input.candidate
        || inspected.parents != [subject.target_tip, subject.source_tip]
        || inspected.bundle.sha256 != input.digest
        || inspected.bundle.bytes != input.bundle.len()
        || inspected.bundle.pack_bytes == 0
        || inspected.bundle.pack_bytes > input.bundle.len()
        || inspected.bundle.pack_objects == 0
        || inspected.bundle.transport_only_objects > inspected.bundle.pack_objects
        || inspected.bundle.closure_objects == 0
        || inspected.prerequisites.is_empty()
        || inspected.prerequisites.len() > 64
        || !inspected.prerequisites.contains(&subject.target_tip)
        || inspected.prerequisites.iter().collect::<BTreeSet<_>>().len() != inspected.prerequisites.len()
    {
        return Err(invalid_report());
    }
    for id in &inspected.prerequisites { check_oid(*id, backend.options.format)?; }
    if inspected.candidate_commit_body.is_empty()
        || inspected.candidate_commit_body.len() > MAX_COMMIT_BYTES
    {
        return Err(ToolError::failed("candidate_commit_limit"));
    }
    if git_object_id(backend.options.format, GitObjectKind::Commit, &inspected.candidate_commit_body)
        != input.candidate.commit
    {
        return Err(invalid_report());
    }
    // Reuse the existing exact entry/span validator, retaining PR association.
    // A failed budget cannot become an empty or successfully truncated review.
    let review = super::super::super::review::render_pull_candidate(
        backend, subject, input.candidate, input.selection.expected_head,
        input.options, &inspected.review,
    )?;
    let arguments = candidate_arguments(subject, input.candidate, &input.bundle)?;
    let mut result = binding(backend);
    result.extend(subject_fields(subject));
    result.extend(commit_fields(&inspected.candidate_commit_body)?);
    result.extend([
        ("type".into(), text("pull_candidate_inspection")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(INSPECT)),
        ("snapshot_token".into(), text(head_token(inspected.review.source_head))),
        ("candidate_commit".into(), text(raw_oid(input.candidate.commit))),
        ("merge_base".into(), text(raw_oid(input.candidate.merge_base))),
        ("root_tree".into(), text(raw_oid(inspected.review.comparison.after_tree))),
        ("bundle_sha256".into(), text(hex(&input.digest))),
        ("bundle_bytes".into(), text(inspected.bundle.bytes.to_string())),
        ("pack_bytes".into(), text(inspected.bundle.pack_bytes.to_string())),
        ("pack_objects".into(), text(inspected.bundle.pack_objects.to_string())),
        ("expanded_bytes".into(), text(inspected.bundle.expanded_bytes.to_string())),
        ("closure_objects".into(), text(inspected.bundle.closure_objects.to_string())),
        ("transport_only_objects".into(), text(inspected.bundle.transport_only_objects.to_string())),
        ("parents".into(), Value::Array(inspected.parents.iter().map(|id| text(raw_oid(*id))).collect())),
        ("prerequisites".into(), Value::Array(inspected.prerequisites.iter().map(|id| text(raw_oid(*id))).collect())),
        ("review".into(), Value::Object(review)),
        ("complete".into(), Value::Bool(true)),
        ("completion_scope".into(), text("entire_candidate_tree")),
        // Inspection validates the uploaded result, not how it was constructed.
        ("merge_algorithm_verified".into(), Value::Bool(false)),
        ("candidate_arguments".into(), arguments),
        ("review_tool".into(), text(reviews::NAME)),
        ("publication_tool".into(), text(super::super::super::merge_writes::NAME)),
    ]);
    let result = Value::Object(result);
    result.encode(MAX_TOOL_RESULT).map_err(|_| ToolError::failed("candidate_response_limit"))?;
    Ok(result)
}

#[cfg(test)]
mod tests;
