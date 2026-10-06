//! Complete patch application stays in the native TreeFS planner. No local
//! object or workspace is stored, and no seal, retry key or CAS is created.
use super::*;
use fgit_crypto::sha256_digest;
use fgit_forge::patch::PatchError;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::NodeWorkspaceRefusal;

const MAX_TEXT_PATCH: usize = 16 * 1024;
const MAX_MESSAGE: usize = 4096;
const MAX_PATHS: usize = 64;

pub(super) struct Input {
    pub reference: RefName,
    pub base: GitOid,
    pub patch: Vec<u8>,
    pub metadata: MergeMetadata,
}

pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    require_fields(args, &[
        "operation", "reference", "reference_hex", "expected_base", "patch",
        "patch_hex_chunks", "author", "committer", "timestamp", "message_hex",
    ])?;
    if required(args, "operation")? != "prepare_patch" {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    let reference = branch(args, "reference", "reference_hex")?;
    let base = oid(args, "expected_base", format)?;
    let (patch, metadata) = payload(args)?;
    Ok(Input { reference, base, patch, metadata })
}

// Shared hostile-input contract; each operation separately checks its field set.
pub(super) fn payload(args: &Object) -> Result<(Vec<u8>, MergeMetadata), ToolError> {
    let patch = match (args.get("patch"), args.get("patch_hex_chunks")) {
        (Some(value), None) => {
            let value = value.text().ok_or(ToolError::invalid("patch_must_be_string"))?;
            if value.is_empty() || value.len() > MAX_TEXT_PATCH {
                return Err(ToolError::invalid("patch_byte_limit"));
            }
            value.as_bytes().to_vec()
        }
        (None, Some(_)) => chunks(args, "patch_hex_chunks")?,
        _ => return Err(ToolError::invalid("exactly_one_patch_encoding_required")),
    };
    let author = required(args, "author")?;
    let committer = required(args, "committer")?;
    if author.len() > 1024 || committer.len() > 1024 {
        return Err(ToolError::invalid("invalid_commit_metadata"));
    }
    let metadata = MergeMetadata {
        author: author.into(), committer: committer.into(),
        timestamp: json::decimal(required(args, "timestamp")?)
            .map_err(|_| ToolError::invalid("invalid_timestamp"))?,
        message: unhex(required(args, "message_hex")?, MAX_MESSAGE)?,
    };
    metadata.validate().map_err(|_| ToolError::invalid("invalid_commit_metadata"))?;
    Ok((patch, metadata))
}

pub(super) fn schema() -> Value {
    let mut properties = common_properties("prepare_patch");
    payload_properties(&mut properties);
    input_schema(properties, &[
        "operation", "expected_base", "author", "committer", "timestamp", "message_hex",
    ], vec![exactly_one("patch", "patch_hex_chunks")])
}

pub(super) fn payload_properties(properties: &mut Object) {
    properties.insert("patch".into(), text_schema(MAX_TEXT_PATCH));
    properties.insert("patch_hex_chunks".into(), chunk_schema());
    for name in ["author", "committer"] {
        properties.insert(name.into(), text_schema(1024));
    }
    properties.insert("timestamp".into(), super::super::decimal_schema());
    properties.insert("message_hex".into(), hex_schema(MAX_MESSAGE));
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    let input = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let digest = sha256_digest(&input.patch);
    // Only labels the ephemeral planner capability. This value is never an
    // admission identity, persistent workspace handle or caller-selected grant.
    let mut workspace = [0_u8; 16];
    workspace.copy_from_slice(&digest[..16]);
    let candidate = backend.node.runtime().block_on(backend.node.prepare_trusted_patch_in(
        &request, &input.reference, input.base, workspace, &input.patch,
        &input.metadata, Default::default(),
    )).map_err(preparation_error)?;
    if candidate.object_format != backend.options.format || candidate.source_commit != input.base
        || candidate.patch_sha256 != digest || candidate.candidate_commit == input.base
        || [candidate.candidate_commit, candidate.root_tree].iter()
            .any(|id| id.is_zero() || id.algorithm() != backend.options.format)
        || candidate.object_count == 0
        || candidate.paths.windows(2).any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(ToolError::failed("invalid_candidate_report"));
    }
    if candidate.paths.len() > MAX_PATHS {
        return Err(ToolError::failed("candidate_path_limit"));
    }
    let publication = publication_arguments(&input.reference, input.base, candidate.candidate_commit, candidate.bundle_bytes())?;
    let mut paths = Vec::new();
    for path in &candidate.paths {
        if path.path.is_empty() || path.path.len() > 4096 || path.path.contains(&0)
            || path.path.split(|b| *b == b'/').any(|p| p.is_empty() || p == b"." || p == b"..")
            || (path.old_blob.is_none() && path.new_blob.is_none())
            || path.new_blob.is_some() != path.new_mode.is_some()
            || path.new_mode.is_some_and(|m| !matches!(m, 0o100644 | 0o100755))
            || [path.old_blob, path.new_blob].into_iter().flatten()
                .any(|id| id.is_zero() || id.algorithm() != backend.options.format)
        {
            return Err(ToolError::failed("invalid_candidate_report"));
        }
        paths.push(object([
            ("path_hex", text(hex(&path.path))),
            ("old_blob", path.old_blob.map_or(Value::Null, |id| text(raw_oid(id)))),
            ("new_blob", path.new_blob.map_or(Value::Null, |id| text(raw_oid(id)))),
            ("new_mode", path.new_mode.map_or(Value::Null, |mode| text(format!("{mode:06o}")))),
            ("hunks", text(path.hunks.to_string())),
        ]));
    }
    let mut result = binding(backend);
    result.extend([
        ("type".into(), text("source_patch_candidate")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text("prepare_patch")),
        // The native planner returns an RCR, not a selecting authority head.
        // A separate read cannot safely manufacture a snapshot token for it.
        ("snapshot_token".into(), Value::Null),
        ("source_rcr".into(), text(candidate.source_rcr.to_string())),
        ("source_commit".into(), text(raw_oid(candidate.source_commit))),
        ("candidate_commit".into(), text(raw_oid(candidate.candidate_commit))),
        ("root_tree".into(), text(raw_oid(candidate.root_tree))),
        ("patch_sha256".into(), text(hex(&digest))),
        ("bundle_sha256".into(), text(hex(&sha256_digest(candidate.bundle_bytes())))),
        ("bundle_bytes".into(), text(candidate.bundle_bytes().len().to_string())),
        ("object_count".into(), text(candidate.object_count.to_string())),
        ("paths".into(), Value::Array(paths)),
        ("complete".into(), Value::Bool(true)),
        ("publication_tool".into(), text("frankengit_source_publish")),
        ("publication_arguments".into(), publication),
    ]);
    Ok(Value::Object(result))
}

pub(super) fn preparation_error(error: NodeWorkspaceRefusal) -> ToolError {
    match error {
        NodeWorkspaceRefusal::StaleWorkspaceBase => ToolError::failed("source_commit_moved"),
        NodeWorkspaceRefusal::RefUnavailable => ToolError::failed("reference_unavailable"),
        NodeWorkspaceRefusal::Cancelled { .. } => ToolError::failed("preparation_cancelled"),
        NodeWorkspaceRefusal::InvalidWorkspaceCandidate(_) => ToolError::invalid("invalid_source_patch"),
        NodeWorkspaceRefusal::WorkspacePatch(error) => match error {
            PatchError::Cancelled => ToolError::failed("preparation_cancelled"),
            PatchError::Budget(_) => ToolError::failed("resource_limit"),
            PatchError::ContextMismatch { .. } => ToolError::failed("patch_context_mismatch"),
            PatchError::SourcePresence | PatchError::SourceMode | PatchError::SourceRange { .. } => ToolError::failed("patch_source_mismatch"),
            _ => ToolError::invalid("invalid_source_patch"),
        },
        _ => ToolError::failed("source_preparation_failed"),
    }
}
