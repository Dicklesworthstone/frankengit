//! Validate the complete native result before handing exact, bounded bytes to
//! the existing inspector and publisher. No result manufactures a retry key.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::preparation::replay::PreparedReplay;
use fgit_forge::preparation::{ConflictKind, MergeConflict, MergeEntry};
use std::collections::BTreeMap;

pub(super) struct Report<'a> {
    pub head: RepositoryAuthorityHeadId,
    pub outcome: &'a ReplayPreparation,
    pub bundle: Option<&'a [u8]>,
    pub pack_objects: usize,
    pub borrowed_objects: usize,
    pub resolutions: &'a [ResolvedPath],
}

fn check_oid(id: GitOid, format: GitHashAlgorithm) -> Result<(), ToolError> {
    if id.is_zero() || id.algorithm() != format {
        Err(invalid_report())
    } else {
        Ok(())
    }
}
pub(super) fn coordinates(
    actual: ReplayCoordinates,
    requested: ReplayRequest,
) -> Result<(), ToolError> {
    if actual.request != requested
        || !matches!(
            (actual.selected_parent, actual.selected_mainline),
            (None, None) | (Some(_), Some(1..=u16::MAX))
        )
        || requested
            .mainline
            .is_some_and(|n| actual.selected_mainline != Some(n))
        || (requested.mainline.is_none() && actual.selected_mainline.is_some_and(|n| n != 1))
    {
        return Err(invalid_report());
    }
    if let Some(parent) = actual.selected_parent {
        check_oid(parent, requested.target.algorithm())?;
    }
    Ok(())
}

fn entry(
    value: Option<&MergeEntry>,
    path: &[u8],
    format: GitHashAlgorithm,
) -> Result<Value, ToolError> {
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    check_oid(value.oid, format)?;
    if path.rsplit(|byte| *byte == b'/').next() != Some(value.name.as_slice())
        || !matches!(
            value.mode,
            0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000
        )
    {
        return Err(invalid_report());
    }
    Ok(object([
        ("mode", text(format!("{:06o}", value.mode))),
        ("oid", text(raw_oid(value.oid))),
    ]))
}
const fn kind(value: ConflictKind) -> &'static str {
    match value {
        ConflictKind::Content => "content",
        ConflictKind::Binary => "binary",
        ConflictKind::ModifyDelete => "modify_delete",
        ConflictKind::TypeChange => "type_change",
        ConflictKind::Mode => "mode",
        ConflictKind::Opaque => "opaque",
        ConflictKind::AttributesRequireDriver => "attributes_require_driver",
    }
}
pub(in super::super) fn conflict(
    value: &MergeConflict,
    format: GitHashAlgorithm,
    max_path: usize,
) -> Result<Value, ToolError> {
    if value.path.is_empty()
        || value.path.len() > max_path
        || value.path.contains(&0)
        || value
            .path
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(invalid_report());
    }
    Ok(object([
        ("path_hex", text(hex(&value.path))),
        ("kind", text(kind(value.kind))),
        ("base", entry(value.base.as_ref(), &value.path, format)?),
        ("ours", entry(value.ours.as_ref(), &value.path, format)?),
        ("theirs", entry(value.theirs.as_ref(), &value.path, format)?),
    ]))
}
const fn choice_name(choice: ResolutionKind) -> &'static str {
    match choice {
        ResolutionKind::Base => "base",
        ResolutionKind::Ours => "ours",
        ResolutionKind::Theirs => "theirs",
        ResolutionKind::Delete => "delete",
        ResolutionKind::File => "file",
    }
}
pub(in super::super) fn receipts(
    requested: &[ConflictResolution],
    observed: &[ResolvedPath],
    format: GitHashAlgorithm,
    limits: PreparationLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<Value, ToolError> {
    if requested.is_empty()
        || requested.len() > MAX_RESOLUTIONS
        || requested.len() != observed.len()
    {
        return Err(invalid_report());
    }
    let by_path: BTreeMap<_, _> = observed
        .iter()
        .map(|row| (row.conflict.path.as_slice(), row))
        .collect();
    if by_path.len() != observed.len()
        || requested
            .windows(2)
            .any(|rows| rows[0].path >= rows[1].path)
    {
        return Err(invalid_report());
    }
    let mut result = Vec::with_capacity(requested.len());
    for request in requested {
        checkpoint(live)?;
        let row = by_path
            .get(request.path.as_slice())
            .ok_or_else(invalid_report)?;
        if row.choice != request.choice.kind() {
            return Err(invalid_report());
        }
        match &request.choice {
            ResolutionChoice::Base | ResolutionChoice::Ours | ResolutionChoice::Theirs => {
                let expected = match &request.choice {
                    ResolutionChoice::Base => &row.conflict.base,
                    ResolutionChoice::Ours => &row.conflict.ours,
                    _ => &row.conflict.theirs,
                };
                if expected.is_none() || &row.result != expected {
                    return Err(invalid_report());
                }
            }
            ResolutionChoice::Delete => {
                if row.result.is_some() {
                    return Err(invalid_report());
                }
            }
            ResolutionChoice::File { mode, bytes } => {
                let value = row.result.as_ref().ok_or_else(invalid_report)?;
                if value.mode != *mode
                    || value.oid != git_object_id(format, GitObjectKind::Blob, bytes)
                {
                    return Err(invalid_report());
                }
            }
        }
        result.push(object([
            ("path_hex", text(hex(&request.path))),
            (
                "conflict",
                conflict(&row.conflict, format, limits.max_path_bytes)?,
            ),
            ("choice", text(choice_name(row.choice))),
            ("result", entry(row.result.as_ref(), &request.path, format)?),
        ]));
    }
    Ok(Value::Array(result))
}

pub(super) fn commit_body(
    input: &input::Input,
    plan: &PreparedReplay,
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, ToolError> {
    let format = input.request.target.algorithm();
    check_oid(plan.tree, format)?;
    check_oid(plan.commit, format)?;
    if plan.commit == input.request.target
        || plan.objects.is_empty()
        || plan.objects.len() > input.limits.max_objects
        || plan.objects.windows(2).any(|rows| rows[0].id >= rows[1].id)
    {
        return Err(invalid_report());
    }
    let mut total = 0_usize;
    for object in &plan.objects {
        checkpoint(live)?;
        check_oid(object.id, format)?;
        total = total
            .checked_add(object.body.len())
            .filter(|n| *n <= input.limits.max_output_bytes)
            .ok_or_else(invalid_report)?;
        if git_object_id(format, object.kind, &object.body) != object.id {
            return Err(invalid_report());
        }
    }
    let mut expected = format!(
        "tree {}\nparent {}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
        plan.tree,
        input.request.target,
        input.metadata.author,
        input.metadata.timestamp,
        input.metadata.committer,
        input.metadata.timestamp
    )
    .into_bytes();
    expected.extend_from_slice(&input.metadata.message);
    let actual = plan
        .objects
        .iter()
        .find(|object| object.id == plan.commit)
        .ok_or_else(invalid_report)?;
    if actual.kind != GitObjectKind::Commit
        || actual.body != expected
        || git_object_id(format, GitObjectKind::Commit, &expected) != plan.commit
    {
        return Err(invalid_report());
    }
    Ok(expected)
}

pub(super) fn handoffs(
    reference: &RefName,
    base: GitOid,
    candidate: GitOid,
    head: RepositoryAuthorityHeadId,
    bytes: &[u8],
) -> Result<(Value, Value), ToolError> {
    let publication = publication_arguments(reference, base, candidate, bytes)?;
    let mut inspection = publication.object().ok_or_else(invalid_report)?.clone();
    inspection.insert("operation".into(), text("inspect"));
    inspection.insert("expected_head".into(), text(head_token(head)));
    inspection.insert(
        "expected_bundle_sha256".into(),
        text(hex(&sha256_digest(bytes))),
    );
    let inspection = Value::Object(inspection);
    for arguments in [&publication, &inspection] {
        // Leave room for RPC framing and the caller's original publication key.
        // Raw ref bytes can consume more space than ordinary UTF-8 names.
        arguments
            .encode(json::MAX_INPUT - 4096)
            .map_err(|_| ToolError::failed("candidate_arguments_limit"))?;
    }
    Ok((publication, inspection))
}

pub(super) fn bounded(value: Value, live: &mut impl FnMut() -> bool) -> Result<Value, ToolError> {
    checkpoint(live)?;
    value
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::failed("candidate_response_limit"))?;
    checkpoint(live)?;
    Ok(value)
}

pub(super) fn render(
    backend: &NodeTools,
    input: &input::Input,
    report: Report<'_>,
    live: &mut impl FnMut() -> bool,
) -> Result<Value, ToolError> {
    checkpoint(live)?;
    if input.expected_head.is_some_and(|head| head != report.head) {
        return Err(invalid_report());
    }
    let point = match report.outcome {
        ReplayPreparation::Clean(plan) => plan.coordinates,
        ReplayPreparation::Conflicted { coordinates, .. }
        | ReplayPreparation::NoChange { coordinates } => *coordinates,
    };
    coordinates(point, input.request)?;
    let resolved = if let Some(choices) = input.resolutions.as_deref() {
        if matches!(report.outcome, ReplayPreparation::Conflicted { .. }) {
            return Err(invalid_report());
        }
        receipts(
            choices,
            report.resolutions,
            backend.options.format,
            input.limits,
            live,
        )?
    } else {
        if !report.resolutions.is_empty() {
            return Err(invalid_report());
        }
        Value::Array(Vec::new())
    };
    let mut fields = backend.header(report.head);
    fields.extend(binding(backend));
    fields.extend([
        (
            "type".into(),
            text(if input.resolutions.is_some() {
                "source_replay_resolution"
            } else {
                "source_replay_candidate"
            }),
        ),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(input.operation())),
        ("profile".into(), text("path-v1")),
        (
            "direction".into(),
            text(match input.request.direction {
                ReplayDirection::CherryPick => "cherry-pick",
                ReplayDirection::Revert => "revert",
            }),
        ),
        ("source_head".into(), text(report.head.to_string())),
        (
            "reference_hex".into(),
            text(hex(input.reference.as_bytes())),
        ),
        (
            "source_reference_hex".into(),
            text(hex(input.source.as_bytes())),
        ),
        ("expected_base".into(), text(raw_oid(input.request.target))),
        (
            "expected_source".into(),
            text(raw_oid(input.request.source_tip)),
        ),
        (
            "selected_commit".into(),
            text(raw_oid(input.request.selected_commit)),
        ),
        (
            "requested_mainline".into(),
            input
                .request
                .mainline
                .map_or(Value::Null, |n| json::number(u64::from(n))),
        ),
        (
            "selected_parent".into(),
            point
                .selected_parent
                .map_or(Value::Null, |id| text(raw_oid(id))),
        ),
        (
            "selected_mainline".into(),
            point
                .selected_mainline
                .map_or(Value::Null, |n| json::number(u64::from(n))),
        ),
        ("author".into(), text(input.metadata.author.clone())),
        ("committer".into(), text(input.metadata.committer.clone())),
        (
            "timestamp".into(),
            text(input.metadata.timestamp.to_string()),
        ),
        ("message_hex".into(), text(hex(&input.metadata.message))),
        ("author_identity_verified".into(), Value::Bool(false)),
        ("objects_staged".into(), Value::Bool(false)),
        ("transaction_created".into(), Value::Bool(false)),
        ("inspection_performed".into(), Value::Bool(false)),
        ("complete".into(), Value::Bool(true)),
        (
            "resolution_profile".into(),
            if input.resolutions.is_some() {
                text("exact-path-resolutions-v1")
            } else {
                Value::Null
            },
        ),
        ("resolved_paths".into(), resolved),
        ("candidate_available".into(), Value::Bool(false)),
        ("candidate_commit".into(), Value::Null),
        ("candidate_commit_body_hex".into(), Value::Null),
        ("candidate_commit_text_utf8".into(), Value::Null),
        ("root_tree".into(), Value::Null),
        ("parents".into(), Value::Null),
        ("generated_objects".into(), text("0")),
        ("pack_objects".into(), text("0")),
        ("borrowed_objects".into(), text("0")),
        ("bundle_sha256".into(), Value::Null),
        ("bundle_bytes".into(), text("0")),
        ("conflicts".into(), Value::Array(Vec::new())),
        ("inspection_tool".into(), Value::Null),
        ("inspection_arguments".into(), Value::Null),
        ("publication_tool".into(), Value::Null),
        ("publication_arguments".into(), Value::Null),
    ]);
    match report.outcome {
        ReplayPreparation::Clean(plan) => {
            let bytes = report.bundle.ok_or_else(invalid_report)?;
            if report.pack_objects == 0
                || report.pack_objects > input.limits.max_objects
                || report.borrowed_objects > report.pack_objects
            {
                return Err(invalid_report());
            }
            let body = commit_body(input, plan, live)?;
            let (publication, inspection) = handoffs(
                &input.reference,
                input.request.target,
                plan.commit,
                report.head,
                bytes,
            )?;
            fields.extend([
                (
                    "state".into(),
                    text(if input.resolutions.is_some() {
                        "resolved"
                    } else {
                        "prepared"
                    }),
                ),
                ("candidate_available".into(), Value::Bool(true)),
                ("candidate_commit".into(), text(raw_oid(plan.commit))),
                ("candidate_commit_body_hex".into(), text(hex(&body))),
                (
                    "candidate_commit_text_utf8".into(),
                    std::str::from_utf8(&body).map_or(Value::Null, text),
                ),
                ("root_tree".into(), text(raw_oid(plan.tree))),
                (
                    "parents".into(),
                    Value::Array(vec![text(raw_oid(input.request.target))]),
                ),
                (
                    "generated_objects".into(),
                    text(plan.objects.len().to_string()),
                ),
                ("pack_objects".into(), text(report.pack_objects.to_string())),
                (
                    "borrowed_objects".into(),
                    text(report.borrowed_objects.to_string()),
                ),
                ("bundle_sha256".into(), text(hex(&sha256_digest(bytes)))),
                ("bundle_bytes".into(), text(bytes.len().to_string())),
                ("inspection_tool".into(), text(NAME)),
                ("inspection_arguments".into(), inspection),
                ("publication_tool".into(), text("frankengit_source_publish")),
                ("publication_arguments".into(), publication),
            ]);
        }
        ReplayPreparation::Conflicted { conflicts, .. } => {
            if report.bundle.is_some()
                || report.pack_objects != 0
                || report.borrowed_objects != 0
                || conflicts.is_empty()
                || conflicts.len() > input.limits.max_conflicts
                || conflicts
                    .windows(2)
                    .any(|rows| rows[0].path >= rows[1].path)
            {
                return Err(invalid_report());
            }
            let mut rows = Vec::with_capacity(conflicts.len());
            for value in conflicts {
                checkpoint(live)?;
                rows.push(conflict(
                    value,
                    backend.options.format,
                    input.limits.max_path_bytes,
                )?);
            }
            fields.insert("state".into(), text("conflicted"));
            fields.insert("conflicts".into(), Value::Array(rows));
        }
        ReplayPreparation::NoChange { .. } => {
            if report.bundle.is_some() || report.pack_objects != 0 || report.borrowed_objects != 0 {
                return Err(invalid_report());
            }
            fields.insert("state".into(), text("no_change"));
        }
    }
    bounded(Value::Object(fields), live)
}
