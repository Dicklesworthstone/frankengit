//! Inspect uploaded candidate bytes through the same native validator used by
//! HTTP. Every path is compared; filters cannot disguise an incomplete review.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use fgit_types::RepositoryAuthorityHeadId;

const MAX_COMMIT_BYTES: usize = 64 * 1024;
const LIMITS: &[(&str, usize, usize, usize)] = &[
    ("context_lines", 3, 0, 20),
    ("max_changes", 64, 1, 64),
    ("max_blob_bytes", 1024 * 1024, 1, 1024 * 1024),
    ("max_output_bytes", 64 * 1024, 1, 128 * 1024),
    ("max_diff_work", 1_000_000, 1, 1_000_000),
];
struct Input {
    reference: RefName,
    base: GitOid,
    candidate: GitOid,
    bundle: Vec<u8>,
    digest: [u8; 32],
    head: Option<RepositoryAuthorityHeadId>,
    options: ReviewOptions,
}
fn bound(args: &Object, name: &str) -> Result<usize, ToolError> {
    let &(_, default, minimum, maximum) = LIMITS.iter().find(|limit| limit.0 == name)
        .ok_or(ToolError::invalid("invalid_inspection_limit"))?;
    let value = args.get(name).map(|value| value.unsigned()
        .ok_or(ToolError::invalid("invalid_inspection_limit")))
        .transpose()?.unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| ToolError::invalid("invalid_inspection_limit"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ToolError::invalid("invalid_inspection_limit"));
    }
    Ok(value)
}
fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    require_fields(args, &[
        "operation", "reference", "reference_hex", "expected_base", "expected_candidate",
        "bundle_hex_chunks", "expected_bundle_sha256", "expected_head", "context_lines",
        "max_changes", "max_blob_bytes", "max_output_bytes", "max_diff_work",
    ])?;
    if required(args, "operation")? != "inspect" {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    let reference = branch(args, "reference", "reference_hex")?;
    let base = oid(args, "expected_base", format)?;
    let candidate = oid(args, "expected_candidate", format)?;
    if base == candidate {
        return Err(ToolError::invalid("candidate_must_change_tip"));
    }
    let bundle = chunks(args, "bundle_hex_chunks")?;
    let digest = sha256_digest(&bundle);
    if let Some(expected) = string(args, "expected_bundle_sha256")? {
        if expected.len() != 64 || unhex(expected, 32)?.as_slice() != digest.as_slice() {
            return Err(ToolError::invalid("bundle_digest_mismatch"));
        }
    }
    let mut options = ReviewOptions { mode: ComparisonMode::Direct, ..ReviewOptions::default() };
    options.context_lines = bound(args, "context_lines")?;
    options.limits.max_changes = bound(args, "max_changes")?;
    options.limits.max_blob_bytes = bound(args, "max_blob_bytes")?;
    options.limits.max_output_bytes = bound(args, "max_output_bytes")?;
    options.limits.max_diff_work = bound(args, "max_diff_work")?;
    options.limits.max_hunks = 256;
    options.limits.max_text_files = 32;
    options.validate().map_err(|_| ToolError::invalid("invalid_inspection_limit"))?;
    Ok(Input {
        reference, base, candidate, bundle, digest,
        head: super::super::head(args, 0)?, options,
    })
}

pub(super) fn schema() -> Value {
    let mut properties = common_properties("inspect");
    properties.insert("expected_candidate".into(), oid_schema());
    properties.insert("bundle_hex_chunks".into(), chunk_schema());
    properties.insert("expected_bundle_sha256".into(), object([
        ("type", text("string")), ("pattern", text("^[0-9a-f]{64}$")),
    ]));
    properties.insert("expected_head".into(), text_schema(140));
    for &(name, default, minimum, maximum) in LIMITS {
        properties.insert(name.into(), object([
            ("type", text("integer")), ("minimum", json::number(minimum as u64)),
            ("maximum", json::number(maximum as u64)), ("default", json::number(default as u64)),
        ]));
    }
    input_schema(properties, &["operation", "expected_base", "expected_candidate", "bundle_hex_chunks"], Vec::new())
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    let input = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let inspected = backend.node.runtime().block_on(backend.node.inspect_workspace_bundle_in(
        &request, &input.reference, input.base, input.candidate, &input.bundle,
        &Default::default(), input.head, &input.options,
    )).map_err(|_| ToolError::failed("candidate_inspection_failed"))?;
    // A failed or over-budget native read never turns into an empty diff or a
    // prefix labelled complete. Verify transport and native coordinates again
    // before the common review renderer receives any source bytes.
    if inspected.parents != [input.base] || inspected.prerequisites != [input.base]
        || inspected.merge_base.is_some() || inspected.bundle_sha256 != input.digest
        || inspected.bundle_bytes != input.bundle.len() || inspected.pack_bytes == 0
        || inspected.pack_bytes > input.bundle.len() || inspected.pack_objects == 0
        || git_object_id(backend.options.format, GitObjectKind::Commit, &inspected.candidate_commit_body) != input.candidate
    {
        return Err(ToolError::failed("invalid_candidate_report"));
    }
    if inspected.candidate_commit_body.len() > MAX_COMMIT_BYTES {
        return Err(ToolError::failed("candidate_commit_limit"));
    }
    let review = super::super::review::render_candidate(
        backend, &input.reference, input.base, input.candidate,
        input.head, input.options, &inspected.review,
    )?;
    let mut result = backend.header(inspected.review.source_head);
    result.extend(binding(backend));
    result.extend([
        ("type".into(), text("source_candidate_inspection")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text("inspect")),
        ("reference_hex".into(), text(hex(input.reference.as_bytes()))),
        ("expected_base".into(), text(raw_oid(input.base))),
        ("expected_candidate".into(), text(raw_oid(input.candidate))),
        ("bundle_sha256".into(), text(hex(&input.digest))),
        ("bundle_bytes".into(), text(inspected.bundle_bytes.to_string())),
        ("pack_objects".into(), text(inspected.pack_objects.to_string())),
        ("expanded_bytes".into(), text(inspected.expanded_bytes.to_string())),
        ("closure_objects".into(), text(inspected.closure_objects.to_string())),
        ("transport_only_objects".into(), text(inspected.transport_only_objects.to_string())),
        ("parents".into(), Value::Array(inspected.parents.iter().map(|id| text(raw_oid(*id))).collect())),
        ("candidate_commit_body_hex".into(), text(hex(&inspected.candidate_commit_body))),
        ("candidate_commit_text_utf8".into(), std::str::from_utf8(&inspected.candidate_commit_body).ok().map_or(Value::Null, text)),
        ("review".into(), Value::Object(review)),
        ("complete".into(), Value::Bool(true)),
        ("completion_scope".into(), text("entire_candidate_tree")),
        ("publication_tool".into(), text("frankengit_source_publish")),
        ("publication_arguments".into(), publication_arguments(&input.reference, input.base, input.candidate, &input.bundle)?),
    ]);
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests;
