//! Inspect an actual uploaded root bundle; preparation metadata is not evidence
//! of its contents. This uses the native reader, never a producer-supplied plan.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::initial_commit::inspection::{InitialCommitInspection, InitialInspectionLimits};
use fgit_types::RepositoryAuthorityHeadId;

const MAX_PREVIEW: usize = 128 * 1024;
const MAX_COMMIT: usize = 64 * 1024;
const LIMITS: &[(&str, usize)] = &[
    ("max_files", 64), ("max_tree_entries", 256),
    ("max_file_bytes", MAX_PREVIEW), ("max_output_bytes", MAX_PREVIEW),
];
struct Input {
    reference: RefName,
    candidate: GitOid,
    bytes: Vec<u8>,
    digest: [u8; 32],
    head: Option<RepositoryAuthorityHeadId>,
    limits: InitialInspectionLimits,
}
fn bound(args: &Object, name: &str, maximum: usize) -> Result<usize, ToolError> {
    let number = args.get(name).map(|value| value.unsigned()
        .ok_or(ToolError::invalid("invalid_inspection_limit")))
        .transpose()?.unwrap_or(maximum as u64);
    let value = usize::try_from(number).map_err(|_| ToolError::invalid("invalid_inspection_limit"))?;
    if value == 0 || value > maximum { return Err(ToolError::invalid("invalid_inspection_limit")); }
    Ok(value)
}
fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    require_fields(args, &[
        "operation", "initial", "reference", "reference_hex", "expected_candidate",
        "bundle_hex_chunks", "expected_head", "expected_bundle_sha256",
        "max_files", "max_tree_entries", "max_file_bytes", "max_output_bytes",
    ])?;
    if required(args, "operation")? != "inspect_initial" {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    // The preparation's publication arguments may be reused, but a false flag
    // cannot silently choose another profile. Neither form grants publication.
    if args.get("initial").is_some_and(|value| value != &Value::Bool(true)) {
        return Err(ToolError::invalid("initial_must_be_true"));
    }
    let reference = branch(args, "reference", "reference_hex")?;
    let candidate = oid(args, "expected_candidate", format)?;
    let head = super::super::head(args, 0)?;
    let limits = InitialInspectionLimits {
        max_files: bound(args, "max_files", 64)?,
        max_tree_entries: bound(args, "max_tree_entries", 256)?,
        max_file_bytes: bound(args, "max_file_bytes", MAX_PREVIEW)?,
        max_output_bytes: bound(args, "max_output_bytes", MAX_PREVIEW)?,
        max_commit_bytes: MAX_COMMIT,
        ..Default::default()
    };
    limits.validate().map_err(|_| ToolError::invalid("invalid_inspection_limit"))?;
    let bytes = chunks(args, "bundle_hex_chunks")?;
    let digest = sha256_digest(&bytes);
    if let Some(pin) = string(args, "expected_bundle_sha256")?
        && (pin.len() != 64 || unhex(pin, 32)?.as_slice() != digest.as_slice())
    {
        return Err(ToolError::invalid("bundle_digest_mismatch"));
    }
    Ok(Input { reference, candidate, bytes, digest, head, limits })
}

pub(super) fn schema() -> Value {
    let mut properties = common_properties("inspect_initial");
    properties.remove("expected_base");
    properties.insert("initial".into(), object([("const", Value::Bool(true))]));
    properties.insert("expected_candidate".into(), oid_schema());
    properties.insert("bundle_hex_chunks".into(), chunk_schema());
    properties.insert("expected_head".into(), text_schema(140));
    properties.insert("expected_bundle_sha256".into(), object([
        ("type", text("string")), ("pattern", text("^[0-9a-f]{64}$")),
    ]));
    for &(name, maximum) in LIMITS {
        properties.insert(name.into(), object([
            ("type", text("integer")), ("minimum", json::number(1)),
            ("maximum", json::number(maximum as u64)), ("default", json::number(maximum as u64)),
        ]));
    }
    input_schema(properties, &["operation", "expected_candidate", "bundle_hex_chunks"], Vec::new())
}

fn validate(input: &Input, head: RepositoryAuthorityHeadId, report: &InitialCommitInspection)
    -> Result<(), ToolError>
{
    let invalid = || ToolError::failed("invalid_initial_inspection_report");
    if input.head.is_some_and(|pin| pin != head)
        || report.object_format != input.candidate.algorithm()
        || report.candidate_commit != input.candidate
        || report.root_tree.algorithm() != report.object_format || report.root_tree.is_zero()
        || report.bundle_sha256 != input.digest || report.bundle_bytes != input.bytes.len()
        || report.pack_bytes == 0 || report.pack_bytes > input.bytes.len() || report.object_count < 2
        || report.object_count > fgit_forge::initial_commit::MAX_INITIAL_OBJECTS
        || report.expanded_bytes < report.commit_body.len()
        || report.directories.iter().any(|d| d.tree.is_zero() || d.tree.algorithm() != report.object_format)
        || report.commit_body.len() > input.limits.max_commit_bytes
        || git_object_id(report.object_format, GitObjectKind::Commit, &report.commit_body) != input.candidate
        || report.files.len() > input.limits.max_files
        || report.files.windows(2).any(|pair| pair[0].path >= pair[1].path)
        || report.directories.windows(2).any(|pair| pair[0].path >= pair[1].path)
        || !report.directories.first().is_some_and(|d| d.path.is_empty() && d.tree == report.root_tree)
        || report.files.len().checked_add(report.directories.len())
            .is_none_or(|n| n.saturating_sub(1) > input.limits.max_tree_entries)
    { return Err(invalid()); }
    let mut size = report.commit_body.len();
    for path in report.files.iter().map(|f| f.path.as_slice())
        .chain(report.directories.iter().skip(1).map(|d| d.path.as_slice()))
    {
        if path.is_empty() || path.len() > input.limits.max_path_bytes || path.contains(&0)
            || path.split(|b| *b == b'/').any(|p| p.is_empty() || p == b"." || p == b"..")
        { return Err(invalid()); }
        size = size.checked_add(path.len()).ok_or_else(invalid)?;
    }
    for file in &report.files {
        if !matches!(file.mode, 0o100644 | 0o100755)
            || file.content.len() > input.limits.max_file_bytes
            || git_object_id(report.object_format, GitObjectKind::Blob, &file.content) != file.blob
        { return Err(invalid()); }
        size = size.checked_add(file.content.len()).ok_or_else(invalid)?;
    }
    if size > input.limits.max_output_bytes { return Err(invalid()); }
    Ok(())
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source { return Err(ToolError::invalid("tool_not_granted")); }
    let input = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (head, report) = backend.node.runtime().block_on(backend.node.inspect_initial_patch_bundle_in(
        &request, &input.reference, input.candidate, &input.bytes, &Default::default(), input.head, input.limits,
    )).map_err(|_| ToolError::failed("initial_candidate_inspection_failed"))?;
    validate(&input, head, &report)?;
    let files = report.files.iter().map(|file| object([
        ("path_hex", text(hex(&file.path))), ("blob", text(raw_oid(file.blob))),
        ("mode", text(format!("{:06o}", file.mode))),
        ("bytes", text(file.content.len().to_string())), ("bytes_hex", text(hex(&file.content))),
    ])).collect();
    let directories = report.directories.iter().map(|directory| object([
        ("path_hex", text(hex(&directory.path))), ("tree", text(raw_oid(directory.tree))),
    ])).collect();
    let mut result = backend.header(head);
    result.extend(binding(backend));
    result.extend([
        ("type".into(), text("source_initial_inspection")),
        ("schema_version".into(), json::number(1)), ("operation".into(), text("inspect_initial")),
        ("expected_absent".into(), Value::Bool(true)), ("source_commit".into(), Value::Null),
        ("parents".into(), Value::Array(Vec::new())),
        ("candidate_commit".into(), text(raw_oid(report.candidate_commit))),
        ("root_tree".into(), text(raw_oid(report.root_tree))),
        ("candidate_commit_body_hex".into(), text(hex(&report.commit_body))),
        ("candidate_commit_text_utf8".into(), std::str::from_utf8(&report.commit_body).ok().map_or(Value::Null, text)),
        ("files".into(), Value::Array(files)), ("directories".into(), Value::Array(directories)),
        ("file_count".into(), text(report.files.len().to_string())),
        ("directory_count".into(), text(report.directories.len().to_string())),
        ("bundle_sha256".into(), text(hex(&report.bundle_sha256))),
        ("bundle_bytes".into(), text(report.bundle_bytes.to_string())),
        ("pack_bytes".into(), text(report.pack_bytes.to_string())),
        ("object_count".into(), text(report.object_count.to_string())),
        ("expanded_bytes".into(), text(report.expanded_bytes.to_string())),
        ("complete".into(), Value::Bool(true)), ("completion_scope".into(), text("entire_initial_tree")),
        ("publication_tool".into(), text("frankengit_source_publish")),
        ("publication_arguments".into(), object([
            ("initial", Value::Bool(true)), ("reference_hex", text(hex(input.reference.as_bytes()))),
            ("expected_candidate", text(raw_oid(input.candidate))),
            ("bundle_hex_chunks", encoded_chunks(&input.bytes)?),
        ])),
    ]);
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests;
