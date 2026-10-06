//! Native two-parent construction over one exact open-PR subject. Conflicts and
//! an already-integrated source never acquire a bundle or publishable candidate.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::preparation::{
    ConflictKind, MergeEntry, MergeMetadata, MergePreparation, MergeProfile,
    MergeSourceError, PreparationError, PreparationLimits,
};
use fgit_node::NodeWorkspaceRefusal;

#[derive(Debug)]
struct Input {
    selection: Selection,
    metadata: MergeMetadata,
    limits: PreparationLimits,
    profile: MergeProfile,
}

fn bound(args: &Object, field: &str, default: usize, maximum: usize) -> Result<usize, ToolError> {
    let value = args.get(field).map(|v| v.unsigned()
        .ok_or(ToolError::invalid("invalid_preparation_limit"))).transpose()?.unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| ToolError::invalid("invalid_preparation_limit"))?;
    if value == 0 || value > maximum {
        return Err(ToolError::invalid("invalid_preparation_limit"));
    }
    Ok(value)
}

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let mut allowed = SUBJECT_FIELDS.to_vec();
    allowed.extend([
        "author", "committer", "timestamp", "message_hex", "merge_profile",
        "max_commits", "max_tree_entries", "max_output_bytes", "max_conflicts",
    ]);
    require_fields(args, &allowed)?;
    if required(args, "operation")? != PREPARE {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    let profile = match string(args, "merge_profile")?.unwrap_or("path-merge-v1") {
        "path-merge-v1" => MergeProfile::PathMergeV1,
        "exact-renames-v1" => MergeProfile::ExactRenamesV1,
        _ => return Err(ToolError::invalid("invalid_merge_profile")),
    };
    let limits = PreparationLimits {
        max_commits: bound(args, "max_commits", 4096, 4096)?,
        max_tree_entries: bound(args, "max_tree_entries", 100_000, 100_000)?,
        max_output_bytes: bound(args, "max_output_bytes", 256 * 1024, 1024 * 1024)?,
        max_conflicts: bound(args, "max_conflicts", 64, 64)?,
        max_objects: 1024,
        ..PreparationLimits::default()
    };
    limits.validate().map_err(|_| ToolError::invalid("invalid_preparation_limit"))?;
    Ok(Input {
        selection: selection(args, format)?,
        metadata: super::super::prepare::metadata(args)?,
        limits,
        profile,
    })
}

pub(super) fn schema() -> Value {
    let mut properties = subject_properties(PREPARE);
    for name in ["author", "committer"] {
        properties.insert(name.into(), text_schema(1024));
    }
    properties.insert("timestamp".into(), super::super::super::decimal_schema());
    properties.insert("message_hex".into(), hex_schema(4096));
    properties.insert("merge_profile".into(), object([
        ("type", text("string")), ("default", text("path-merge-v1")),
        ("enum", Value::Array(vec![text("path-merge-v1"), text("exact-renames-v1")])),
    ]));
    for (name, default, maximum) in [
        ("max_commits", 4096, 4096), ("max_tree_entries", 100_000, 100_000),
        ("max_output_bytes", 262_144, 1_048_576), ("max_conflicts", 64, 64),
    ] {
        properties.insert(name.into(), object([
            ("type", text("integer")), ("minimum", json::number(1)),
            ("default", json::number(default)), ("maximum", json::number(maximum)),
        ]));
    }
    let mut schema = reviews::candidate_schema(properties, &[
        "operation", "number", "expected_version", "expected_source", "expected_target",
        "policy_epoch", "author", "committer", "timestamp", "message_hex",
    ]);
    if let Value::Object(fields) = &mut schema {
        fields.insert("description".into(), text("Requires source AND PR read grants. Explicit commit metadata; no reviewer, principal, retry key or publication. Only a clean complete native result carries candidate arguments."));
    }
    schema
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    permitted(backend)?;
    let input = parse(args, backend.options.format)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let prepared = backend.node.runtime().block_on(
        backend.node.prepare_pull_request_bundle_with_profile_in(
            &request, &input.selection.subject, &Default::default(),
            &input.metadata, input.limits, input.profile,
        ),
    ).map_err(preparation_error)?;
    check_selection(&input.selection, &prepared.subject, prepared.source_head)?;
    let mut result = binding(backend);
    result.extend(subject_fields(&prepared.subject));
    result.extend([
        ("type".into(), text("pull_merge_preparation")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(PREPARE)),
        ("snapshot_token".into(), text(head_token(prepared.source_head))),
        ("merge_profile".into(), text(match input.profile {
            MergeProfile::PathMergeV1 => "path-merge-v1",
            MergeProfile::ExactRenamesV1 => "exact-renames-v1",
        })),
        ("complete".into(), Value::Bool(true)),
    ]);
    result.extend(render(backend.options.format, &input, &prepared.outcome, prepared.bundle.as_deref())?);
    Ok(Value::Object(result))
}

fn render(
    format: GitHashAlgorithm,
    input: &Input,
    outcome: &MergePreparation,
    bundle: Option<&[u8]>,
) -> Result<Object, ToolError> {
    let subject = &input.selection.subject;
    let mut result = Object::new();
    for field in ["candidate_arguments", "candidate_commit", "root_tree", "bundle_sha256", "parents"] {
        result.insert(field.into(), Value::Null);
    }
    result.insert("candidate_available".into(), Value::Bool(false));
    match outcome {
        MergePreparation::Clean(plan) => {
            if plan.target != subject.target_tip || plan.source != subject.source_tip
                || plan.objects.is_empty() || plan.objects.len() > input.limits.max_objects
                || plan.objects.windows(2).any(|p| p[0].id >= p[1].id)
            { return Err(invalid_report()); }
            for id in [plan.base, plan.tree, plan.commit] { check_oid(id, format)?; }
            let candidate = CandidateBinding { merge_base: plan.base, commit: plan.commit };
            let bytes = bundle.ok_or_else(invalid_report)?;
            let arguments = candidate_arguments(subject, candidate, bytes)?;
            let mut total = 0usize;
            let mut commit = None;
            for object in &plan.objects {
                check_oid(object.id, format)?;
                total = total.checked_add(object.body.len()).filter(|n| *n <= input.limits.max_output_bytes)
                    .ok_or_else(invalid_report)?;
                if git_object_id(format, object.kind, &object.body) != object.id { return Err(invalid_report()); }
                if object.kind == GitObjectKind::Commit {
                    if object.id != plan.commit || commit.is_some() { return Err(invalid_report()); }
                    commit = Some(object.body.as_slice());
                }
            }
            result.extend(commit_fields(commit.ok_or_else(invalid_report)?)?);
            result.extend([
                ("state".into(), text("clean")),
                ("candidate_available".into(), Value::Bool(true)),
                ("candidate_commit".into(), text(raw_oid(plan.commit))),
                ("root_tree".into(), text(raw_oid(plan.tree))),
                ("merge_base".into(), text(raw_oid(plan.base))),
                ("parents".into(), Value::Array(vec![text(raw_oid(plan.target)), text(raw_oid(plan.source))])),
                ("bundle_sha256".into(), text(hex(&sha256_digest(bytes)))),
                ("bundle_bytes".into(), text(bytes.len().to_string())),
                ("generated_objects".into(), text(plan.objects.len().to_string())),
                ("candidate_arguments".into(), arguments),
                ("review_tool".into(), text(reviews::NAME)),
                ("publication_tool".into(), text(super::super::super::merge_writes::NAME)),
            ]);
        }
        MergePreparation::Conflicted { base, conflicts } => {
            check_oid(*base, format)?;
            if bundle.is_some() || conflicts.is_empty() || conflicts.len() > input.limits.max_conflicts
                || conflicts.windows(2).any(|p| p[0].path > p[1].path)
            { return Err(invalid_report()); }
            let mut rows = Vec::with_capacity(conflicts.len());
            for conflict in conflicts {
                if !valid_path(&conflict.path)
                    || (conflict.base.is_none() && conflict.ours.is_none() && conflict.theirs.is_none())
                { return Err(invalid_report()); }
                rows.push(object([
                    ("path_hex", text(hex(&conflict.path))),
                    ("root_path", Value::Bool(conflict.path.is_empty())),
                    ("kind", text(match conflict.kind {
                        ConflictKind::Content => "content", ConflictKind::Binary => "binary",
                        ConflictKind::ModifyDelete => "modify_delete", ConflictKind::TypeChange => "type_change",
                        ConflictKind::Mode => "mode", ConflictKind::Opaque => "opaque",
                        ConflictKind::AttributesRequireDriver => "attributes_require_driver",
                    })),
                    ("base", entry(conflict.base.as_ref(), format)?),
                    ("ours", entry(conflict.ours.as_ref(), format)?),
                    ("theirs", entry(conflict.theirs.as_ref(), format)?),
                ]));
            }
            result.insert("state".into(), text("conflicted"));
            result.insert("merge_base".into(), text(raw_oid(*base)));
            result.insert("conflicts".into(), Value::Array(rows));
        }
        MergePreparation::AlreadyUpToDate { target } => {
            if bundle.is_some() || *target != subject.target_tip { return Err(invalid_report()); }
            result.insert("state".into(), text("already_up_to_date"));
        }
    }
    Ok(result)
}

fn valid_path(path: &[u8]) -> bool {
    path.len() <= 4096 && !path.contains(&0) && (path.is_empty()
        || path.split(|b| *b == b'/').all(|p| !p.is_empty() && p != b"." && p != b".."))
}
fn entry(entry: Option<&MergeEntry>, format: GitHashAlgorithm) -> Result<Value, ToolError> {
    let Some(entry) = entry else { return Ok(Value::Null); };
    check_oid(entry.oid, format)?;
    if entry.name.is_empty() || !valid_path(&entry.name) || entry.name.contains(&b'/')
        || !matches!(entry.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000)
    { return Err(invalid_report()); }
    Ok(object([
        ("name_hex", text(hex(&entry.name))), ("oid", text(raw_oid(entry.oid))),
        ("mode", text(format!("{:06o}", entry.mode))),
    ]))
}
fn preparation_error(error: NodeWorkspaceRefusal) -> ToolError {
    match error {
        NodeWorkspaceRefusal::StaleWorkspaceBase => ToolError::failed("pull_subject_moved"),
        NodeWorkspaceRefusal::RefUnavailable => ToolError::failed("reference_unavailable"),
        NodeWorkspaceRefusal::Cancelled { .. }
        | NodeWorkspaceRefusal::MergePreparation(PreparationError::Source(MergeSourceError::Cancelled)) => ToolError::failed("preparation_cancelled"),
        NodeWorkspaceRefusal::MergePreparation(PreparationError::NoCommonAncestor) => ToolError::failed("no_common_ancestor"),
        NodeWorkspaceRefusal::MergePreparation(PreparationError::MultipleMergeBases(_)) => ToolError::failed("multiple_merge_bases"),
        NodeWorkspaceRefusal::MergePreparation(PreparationError::Budget(_))
        | NodeWorkspaceRefusal::MergePreparation(PreparationError::Source(MergeSourceError::BudgetExceeded)) => ToolError::failed("resource_limit"),
        _ => ToolError::failed("pull_preparation_failed"),
    }
}

#[cfg(test)]
mod tests;
