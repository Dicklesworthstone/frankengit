//! Creation-only native candidates, including the first commit in an empty
//! repository. No synthetic base, selected actor, object staging or publication.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::initial_commit::{InitialCommitError, InitialCommitPlan};
use fgit_forge::{patch::PatchLimits, preparation::MergeMetadata};
use fgit_node::NodeWorkspaceRefusal;
use fgit_types::RepositoryAuthorityHeadId;
use std::collections::BTreeMap;

const MAX_PREVIEW_BYTES: usize = 128 * 1024;
const MAX_FILES: usize = 64;

struct Input {
    reference: RefName,
    expected_head: Option<RepositoryAuthorityHeadId>,
    patch: Vec<u8>,
    metadata: MergeMetadata,
}

fn parse(args: &Object) -> Result<Input, ToolError> {
    require_fields(args, &[
        "operation", "reference", "reference_hex", "expected_head", "patch",
        "patch_hex_chunks", "author", "committer", "timestamp", "message_hex",
    ])?;
    if required(args, "operation")? != "prepare_initial" {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    let reference = branch(args, "reference", "reference_hex")?;
    let expected_head = super::super::head(args, 0)?;
    let (patch, metadata) = prepare::payload(args)?;
    Ok(Input { reference, expected_head, patch, metadata })
}

pub(super) fn schema() -> Value {
    let mut properties = common_properties("prepare_initial");
    properties.remove("expected_base");
    properties.insert("expected_head".into(), text_schema(140));
    prepare::payload_properties(&mut properties);
    input_schema(properties, &[
        "operation", "author", "committer", "timestamp", "message_hex",
    ], vec![exactly_one("patch", "patch_hex_chunks")])
}

// Preview every file from the actual native object plan, not the input patch.
// Charge duplicate file contents per path before hex expansion. An oversized
// preview refuses the whole result; no partial candidate is labelled reviewed.
fn preview(plan: &InitialCommitPlan) -> Result<(Value, &[u8]), ToolError> {
    let invalid = || ToolError::failed("invalid_initial_candidate_report");
    if plan.files.is_empty() || plan.objects.is_empty()
        || plan.files.len() > MAX_FILES
        || plan.files.windows(2).any(|p| p[0].path >= p[1].path)
        || [plan.commit, plan.tree].iter()
            .any(|id| id.is_zero() || id.algorithm() != plan.object_format)
    {
        return Err(invalid());
    }
    let objects: BTreeMap<_, _> = plan.objects.iter().map(|object| (object.id, object)).collect();
    if objects.len() != plan.objects.len() {
        return Err(invalid());
    }
    let commit = *objects.get(&plan.commit).ok_or_else(invalid)?;
    if commit.kind != GitObjectKind::Commit
        || git_object_id(plan.object_format, commit.kind, &commit.body) != plan.commit
        || !objects.get(&plan.tree).is_some_and(|tree| tree.kind == GitObjectKind::Tree)
    {
        return Err(invalid());
    }
    let mut bytes = commit.body.len();
    // Validate and budget everything before retaining any expanded preview.
    for file in &plan.files {
        let blob = objects.get(&file.blob).ok_or_else(invalid)?;
        if file.path.is_empty() || file.path.len() > 4096 || file.path.contains(&0)
            || file.path.split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
            || !matches!(file.mode, 0o100644 | 0o100755)
            || blob.kind != GitObjectKind::Blob || file.bytes != blob.body.len()
            || git_object_id(plan.object_format, blob.kind, &blob.body) != file.blob
        {
            return Err(invalid());
        }
        bytes = bytes.checked_add(file.bytes)
            .and_then(|n| n.checked_add(file.path.len()))
            .filter(|n| *n <= MAX_PREVIEW_BYTES)
            .ok_or(ToolError::failed("initial_preview_limit"))?;
    }
    let files = plan.files.iter().map(|file| {
        let blob = objects.get(&file.blob).ok_or_else(invalid)?;
        Ok(object([
            ("path_hex", text(hex(&file.path))),
            ("blob", text(raw_oid(file.blob))),
            ("mode", text(format!("{:06o}", file.mode))),
            ("bytes", text(file.bytes.to_string())),
            ("bytes_hex", text(hex(&blob.body))),
        ]))
    }).collect::<Result<Vec<_>, ToolError>>()?;
    Ok((Value::Array(files), &commit.body))
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.source {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let input = parse(args)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (head, plan, bundle) = backend.node.runtime().block_on(
        backend.node.prepare_trusted_initial_patch_in(
            &request, &input.reference, &input.patch, &input.metadata,
            PatchLimits {
                max_patch_bytes: MAX_BUNDLE_BYTES, max_files: MAX_FILES,
                max_file_bytes: MAX_PREVIEW_BYTES, max_output_bytes: MAX_PREVIEW_BYTES,
                ..PatchLimits::default()
            },
            input.expected_head,
        ),
    ).map_err(preparation_error)?;
    if plan.object_format != backend.options.format
        || plan.patch_sha256 != sha256_digest(&input.patch)
        || input.expected_head.is_some_and(|expected| expected != head)
    {
        return Err(ToolError::failed("invalid_initial_candidate_report"));
    }
    let (files, commit) = preview(&plan)?;
    let publication = object([
        ("initial", Value::Bool(true)),
        ("reference_hex", text(hex(input.reference.as_bytes()))),
        ("expected_candidate", text(raw_oid(plan.commit))),
        ("bundle_hex_chunks", encoded_chunks(bundle.bytes())?),
    ]);
    let mut result = binding(backend);
    result.extend([
        ("type".into(), text("source_initial_candidate")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text("prepare_initial")),
        ("snapshot_token".into(), text(super::super::head_token(head))),
        ("source_commit".into(), Value::Null),
        ("expected_absent".into(), Value::Bool(true)),
        ("parents".into(), Value::Array(Vec::new())),
        ("candidate_commit".into(), text(raw_oid(plan.commit))),
        ("root_tree".into(), text(raw_oid(plan.tree))),
        ("candidate_commit_body_hex".into(), text(hex(commit))),
        ("patch_sha256".into(), text(hex(&plan.patch_sha256))),
        ("bundle_sha256".into(), text(hex(&sha256_digest(bundle.bytes())))),
        ("bundle_bytes".into(), text(bundle.bytes().len().to_string())),
        ("object_count".into(), text(plan.objects.len().to_string())),
        ("files".into(), files),
        ("file_count".into(), text(plan.files.len().to_string())),
        ("complete".into(), Value::Bool(true)),
        ("completion_scope".into(), text("entire_initial_tree")),
        ("publication_tool".into(), text("frankengit_source_publish")),
        ("publication_arguments".into(), publication),
    ]);
    let result = Value::Object(result);
    result.encode(MAX_TOOL_RESULT).map_err(|_| ToolError::failed("candidate_response_limit"))?;
    Ok(result)
}

fn preparation_error(error: NodeWorkspaceRefusal) -> ToolError {
    match error {
        NodeWorkspaceRefusal::InitialCommit(InitialCommitError::Budget(_)) => {
            ToolError::failed("resource_limit")
        }
        NodeWorkspaceRefusal::InitialCommit(InitialCommitError::Patch(error)) => {
            prepare::preparation_error(NodeWorkspaceRefusal::WorkspacePatch(error))
        }
        NodeWorkspaceRefusal::InitialCommit(InitialCommitError::CreationRequired) => {
            ToolError::invalid("initial_patch_requires_creations")
        }
        NodeWorkspaceRefusal::InitialCommit(_) => ToolError::invalid("invalid_initial_patch"),
        error => prepare::preparation_error(error),
    }
}

#[cfg(test)]
mod tests;
