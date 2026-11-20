//! Exact-subject PR rebase planning. The bundle belongs to the target ref;
//! approval, publication, and rewriting the original source remain separate.
mod inspection;
#[cfg(test)]
mod tests;

use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, RebaseCommitter, RebasePreparation, RebaseRequest, RebaseStep,
    RebaseStepKind, RebaseStop,
};
use fgit_forge::preparation::{ConflictKind, PreparationLimits};
use fgit_node::NodeWorkspaceRefusal;
use std::collections::{BTreeMap, BTreeSet};

const MAX_COMMITS: usize = 256;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const PREPARATION_LIMITS: &[(&str, usize, usize)] = &[
    ("max_commits", MAX_COMMITS, MAX_COMMITS),
    ("max_edges", 16_384, 16_384),
    ("max_tree_entries", 100_000, 100_000),
    ("max_preparation_bytes", 256 * 1024, 1024 * 1024),
];

struct Input {
    selection: Selection,
    request: RebaseRequest,
    committer: RebaseCommitter,
    limits: PreparationLimits,
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ToolError> {
    if live() {
        Ok(())
    } else {
        Err(ToolError::failed("rebase_cancelled"))
    }
}

fn bounded(value: Value, live: &mut impl FnMut() -> bool) -> Result<Value, ToolError> {
    checkpoint(live)?;
    value
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::failed("rebase_result_limit"))?;
    checkpoint(live)?;
    Ok(value)
}

fn limit(
    args: &Object,
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ToolError> {
    let value = args
        .get(name)
        .map(|value| {
            value
                .unsigned()
                .ok_or(ToolError::invalid("invalid_rebase_limit"))
        })
        .transpose()?
        .unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| ToolError::invalid("invalid_rebase_limit"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ToolError::invalid("invalid_rebase_limit"));
    }
    Ok(value)
}

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let mut allowed = SUBJECT_FIELDS.to_vec();
    allowed.extend(["profile", "upstream", "committer", "timestamp", "empty"]);
    allowed.extend(PREPARATION_LIMITS.iter().map(|row| row.0));
    require_fields(args, &allowed)?;
    if required(args, "operation")? != REBASE_PREPARE || required(args, "profile")? != "path-v1" {
        return Err(ToolError::invalid("unsupported_rebase_profile"));
    }
    let selection = selection(args, format)?;
    let empty = match required(args, "empty")? {
        "stop" => EmptyCommitPolicy::Stop,
        "drop" => EmptyCommitPolicy::Drop,
        "keep" => EmptyCommitPolicy::Keep,
        _ => return Err(ToolError::invalid("invalid_empty_commit_policy")),
    };
    let committer = RebaseCommitter {
        identity: required(args, "committer")?.to_owned(),
        timestamp: json::decimal(required(args, "timestamp")?)
            .map_err(|_| ToolError::invalid("invalid_timestamp"))?,
    };
    if committer.identity.len() > 1024 || committer.validate().is_err() {
        return Err(ToolError::invalid("invalid_rebase_committer"));
    }
    let bound = |name| {
        let &(_, default, maximum) = PREPARATION_LIMITS
            .iter()
            .find(|row| row.0 == name)
            .ok_or(ToolError::invalid("invalid_rebase_limit"))?;
        limit(args, name, default, 1, maximum)
    };
    let limits = PreparationLimits {
        max_commits: bound("max_commits")?,
        max_edges: bound("max_edges")?,
        max_tree_entries: bound("max_tree_entries")?,
        max_output_bytes: bound("max_preparation_bytes")?,
        max_conflicts: 64,
        max_objects: 1024,
        ..PreparationLimits::default()
    };
    limits
        .validate()
        .map_err(|_| ToolError::invalid("invalid_rebase_limit"))?;
    let request = RebaseRequest {
        source_tip: selection.subject.source_tip,
        upstream: oid(args, "upstream", format)?,
        onto: selection.subject.target_tip,
        empty,
    };
    if request.upstream == request.source_tip
        || selection.subject.source_ref == selection.subject.target_ref
    {
        return Err(ToolError::invalid("nonempty_distinct_pr_rebase_required"));
    }
    Ok(Input {
        selection,
        request,
        committer,
        limits,
    })
}

pub(super) fn schema(inspecting: bool) -> Value {
    if inspecting {
        return inspection::schema();
    }
    let mut properties = subject_properties(REBASE_PREPARE);
    properties.insert("profile".into(), object([("const", text("path-v1"))]));
    properties.insert("upstream".into(), oid_schema());
    properties.insert("committer".into(), text_schema(1024));
    properties.insert("timestamp".into(), super::super::super::decimal_schema());
    properties.insert(
        "empty".into(),
        object([
            ("type", text("string")),
            (
                "enum",
                Value::Array(vec![text("stop"), text("drop"), text("keep")]),
            ),
        ]),
    );
    for &(name, default, maximum) in PREPARATION_LIMITS {
        properties.insert(
            name.into(),
            object([
                ("type", text("integer")),
                ("minimum", json::number(1)),
                ("maximum", json::number(maximum as u64)),
                ("default", json::number(default as u64)),
            ]),
        );
    }
    reviews::candidate_schema(
        properties,
        &[
            "operation",
            "profile",
            "number",
            "expected_version",
            "expected_source",
            "expected_target",
            "policy_epoch",
            "upstream",
            "committer",
            "timestamp",
            "empty",
        ],
    )
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    permitted(backend)?;
    if backend.options.agent_token_file.is_some() || backend.agent.is_some() {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    if required(args, "operation")? == REBASE_INSPECT {
        return inspection::call(backend, args);
    }
    let input = parse(args, backend.options.format)?;
    let context = backend.command_context();
    checkpoint(&mut || context.is_live())?;
    let prepared = backend
        .node
        .runtime()
        .block_on(backend.node.prepare_pull_request_rebase_bundle_in(
            &context,
            &input.selection.subject,
            &Default::default(),
            input.request.upstream,
            &input.committer,
            input.limits,
            input.request.empty,
        ))
        .map_err(|error| {
            if !context.is_live() {
                return ToolError::failed("rebase_cancelled");
            }
            if let NodeWorkspaceRefusal::RebasePreparation(error) = &error {
                if error.is_cancelled() {
                    return ToolError::failed("rebase_cancelled");
                }
                if error.is_resource_refusal() {
                    return ToolError::failed("resource_limit");
                }
                if error.is_tip_moved() || error.is_snapshot_moved() {
                    return ToolError::failed("pull_subject_moved");
                }
            }
            prepare::preparation_error(error)
        })?;
    check_selection(&input.selection, &prepared.subject, prepared.source_head)?;
    if prepared.preparation.source_head != prepared.source_head {
        return Err(invalid_report());
    }
    render(backend, &input, &prepared, &mut || context.is_live())
}

fn arguments(
    subject: &ReviewSubject,
    candidate: CandidateBinding,
    bytes: &[u8],
) -> Result<Value, ToolError> {
    let Value::Object(mut fields) = candidate_arguments(subject, candidate, bytes)? else {
        return Err(invalid_report());
    };
    fields.insert("method".into(), text("rebase"));
    let result = Value::Object(fields);
    result
        .encode(json::MAX_INPUT - 4096)
        .map_err(|_| ToolError::failed("candidate_arguments_limit"))?;
    Ok(result)
}

fn validate_steps(input: &Input, steps: &[RebaseStep]) -> Result<GitOid, ToolError> {
    if steps.len() > input.limits.max_commits {
        return Err(invalid_report());
    }
    let mut seen = BTreeSet::new();
    let mut rewritten = BTreeSet::new();
    let mut parent = input.request.onto;
    let mut tree = None;
    for step in steps {
        for id in [step.original, step.rewritten, step.tree] {
            check_oid(id, input.request.source_tip.algorithm())?;
        }
        if step.original == input.request.upstream || !seen.insert(step.original) {
            return Err(invalid_report());
        }
        if step.kind == RebaseStepKind::DroppedEmpty {
            if input.request.empty != EmptyCommitPolicy::Drop
                || step.rewritten != parent
                || tree.is_some_and(|value| value != step.tree)
            {
                return Err(invalid_report());
            }
        } else if step.rewritten == parent || !rewritten.insert(step.rewritten) {
            return Err(invalid_report());
        }
        parent = step.rewritten;
        tree = Some(step.tree);
    }
    Ok(parent)
}

fn render(
    backend: &NodeTools,
    input: &Input,
    prepared: &fgit_node::PreparedPullRequestRebaseBundle,
    live: &mut impl FnMut() -> bool,
) -> Result<Value, ToolError> {
    checkpoint(live)?;
    let artifact = &prepared.preparation;
    let (request, steps) = match &artifact.outcome {
        RebasePreparation::Clean(plan) => (&plan.request, plan.steps.as_slice()),
        RebasePreparation::Stopped {
            request, completed, ..
        } => (request, completed.as_slice()),
    };
    if *request != input.request
        || artifact.borrowed_objects > artifact.pack_objects
        || artifact.pack_objects > input.limits.max_objects
    {
        return Err(invalid_report());
    }
    let last = validate_steps(input, steps)?;
    let mut fields = backend.header(prepared.source_head);
    fields.extend(binding(backend));
    fields.extend(subject_fields(&prepared.subject));
    fields.extend([
        ("type".into(), text("pull_rebase_preparation")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(REBASE_PREPARE)),
        ("profile".into(), text("path-v1")),
        ("method".into(), text("rebase")),
        ("upstream".into(), text(raw_oid(request.upstream))),
        (
            "snapshot_token".into(),
            text(head_token(prepared.source_head)),
        ),
        (
            "empty".into(),
            text(match request.empty {
                EmptyCommitPolicy::Stop => "stop",
                EmptyCommitPolicy::Drop => "drop",
                EmptyCommitPolicy::Keep => "keep",
            }),
        ),
        ("committer".into(), text(&input.committer.identity)),
        (
            "timestamp".into(),
            text(input.committer.timestamp.to_string()),
        ),
        ("objects_staged".into(), Value::Bool(false)),
        ("transaction_created".into(), Value::Bool(false)),
        ("publication_authorized".into(), Value::Bool(false)),
        ("inspection_performed".into(), Value::Bool(false)),
        ("original_authors_preserved".into(), Value::Bool(true)),
        ("original_messages_preserved".into(), Value::Bool(true)),
        ("original_signatures_copied".into(), Value::Bool(false)),
        ("author_identity_verified".into(), Value::Bool(false)),
        ("candidate_available".into(), Value::Bool(false)),
        ("candidate_commit".into(), Value::Null),
        ("root_tree".into(), Value::Null),
        ("bundle_sha256".into(), Value::Null),
        ("candidate_arguments".into(), Value::Null),
        ("publication_arguments".into(), Value::Null),
        ("inspection_arguments".into(), Value::Null),
        ("publication_tool".into(), Value::Null),
        ("inspection_tool".into(), Value::Null),
        ("review_tool".into(), Value::Null),
        ("step_count".into(), text(steps.len().to_string())),
    ]);
    let mut mappings = Vec::with_capacity(steps.len());
    for step in steps {
        checkpoint(live)?;
        mappings.push(object([
            ("original", text(raw_oid(step.original))),
            ("rewritten", text(raw_oid(step.rewritten))),
            ("tree", text(raw_oid(step.tree))),
            (
                "kind",
                text(match step.kind {
                    RebaseStepKind::Replayed => "replayed",
                    RebaseStepKind::PreservedEmpty => "preserved_empty",
                    RebaseStepKind::DroppedEmpty => "dropped_empty",
                }),
            ),
        ]));
    }
    fields.insert("steps".into(), Value::Array(mappings));
    match &artifact.outcome {
        RebasePreparation::Clean(plan) => {
            if plan.steps.is_empty()
                || plan.commit == request.onto
                || last != plan.commit
                || plan.steps.last().is_none_or(|step| {
                    step.original != request.source_tip || step.tree != plan.tree
                })
                || plan.objects.len() > input.limits.max_objects
            {
                return Err(invalid_report());
            }
            let mut objects = BTreeMap::new();
            let mut retained = 0usize;
            for object in &plan.objects {
                checkpoint(live)?;
                retained = retained
                    .checked_add(object.body.len())
                    .filter(|value| *value <= input.limits.max_output_bytes)
                    .ok_or_else(invalid_report)?;
                if git_object_id(backend.options.format, object.kind, &object.body) != object.id
                    || objects.insert(object.id, object).is_some()
                {
                    return Err(invalid_report());
                }
            }
            let mut parent = request.onto;
            for step in &plan.steps {
                if step.kind != RebaseStepKind::DroppedEmpty {
                    let object = objects.get(&step.rewritten).ok_or_else(invalid_report)?;
                    let prefix = format!("tree {}\nparent {}\nauthor ", step.tree, parent);
                    if object.kind != GitObjectKind::Commit
                        || !object.body.starts_with(prefix.as_bytes())
                    {
                        return Err(invalid_report());
                    }
                }
                parent = step.rewritten;
            }
            let bytes = artifact.bundle.as_deref().ok_or_else(invalid_report)?;
            let digest = sha256_digest(bytes);
            let handoff = arguments(
                &prepared.subject,
                CandidateBinding {
                    merge_base: request.upstream,
                    commit: plan.commit,
                },
                bytes,
            )?;
            let mut inspect = handoff.object().ok_or_else(invalid_report)?.clone();
            inspect.insert("operation".into(), text(REBASE_INSPECT));
            inspect.insert(
                "expected_head".into(),
                text(head_token(prepared.source_head)),
            );
            inspect.insert("expected_bundle_sha256".into(), text(hex(&digest)));
            let inspect = Value::Object(inspect);
            inspect
                .encode(json::MAX_INPUT - 4096)
                .map_err(|_| ToolError::failed("candidate_arguments_limit"))?;
            fields.extend([
                ("state".into(), text("clean")),
                ("complete".into(), Value::Bool(true)),
                ("candidate_available".into(), Value::Bool(true)),
                ("candidate_commit".into(), text(raw_oid(plan.commit))),
                ("root_tree".into(), text(raw_oid(plan.tree))),
                ("merge_base".into(), text(raw_oid(request.upstream))),
                ("bundle_sha256".into(), text(hex(&digest))),
                ("bundle_bytes".into(), text(bytes.len().to_string())),
                ("candidate_arguments".into(), handoff.clone()),
                ("publication_arguments".into(), handoff),
                ("inspection_arguments".into(), inspect),
                ("inspection_tool".into(), text(NAME)),
                ("review_tool".into(), text(reviews::NAME)),
                (
                    "publication_tool".into(),
                    text(super::super::super::merge_writes::NAME),
                ),
            ]);
        }
        RebasePreparation::Stopped {
            original, reason, ..
        } => {
            if artifact.bundle.is_some()
                || artifact.pack_objects != 0
                || artifact.borrowed_objects != 0
                || *original == request.upstream
                || steps.iter().any(|step| step.original == *original)
            {
                return Err(invalid_report());
            }
            check_oid(*original, backend.options.format)?;
            let state = match reason {
                RebaseStop::BecameEmpty => "became_empty",
                RebaseStop::Conflicted(conflicts) => {
                    if conflicts.is_empty()
                        || conflicts.len() > input.limits.max_conflicts
                        || conflicts
                            .windows(2)
                            .any(|rows| rows[0].path >= rows[1].path)
                    {
                        return Err(invalid_report());
                    }
                    let mut rows = Vec::with_capacity(conflicts.len());
                    for conflict in conflicts {
                        checkpoint(live)?;
                        if !prepare::valid_path(&conflict.path) {
                            return Err(invalid_report());
                        }
                        rows.push(object([
                            ("path_hex", text(hex(&conflict.path))),
                            (
                                "kind",
                                text(match conflict.kind {
                                    ConflictKind::Content => "content",
                                    ConflictKind::Binary => "binary",
                                    ConflictKind::ModifyDelete => "modify_delete",
                                    ConflictKind::TypeChange => "type_change",
                                    ConflictKind::Mode => "mode",
                                    ConflictKind::Opaque => "opaque",
                                    ConflictKind::AttributesRequireDriver => {
                                        "attributes_require_driver"
                                    }
                                }),
                            ),
                            (
                                "base",
                                prepare::entry(conflict.base.as_ref(), backend.options.format)?,
                            ),
                            (
                                "ours",
                                prepare::entry(conflict.ours.as_ref(), backend.options.format)?,
                            ),
                            (
                                "theirs",
                                prepare::entry(conflict.theirs.as_ref(), backend.options.format)?,
                            ),
                        ]));
                    }
                    fields.insert("conflicts".into(), Value::Array(rows));
                    "conflicted"
                }
            };
            fields.extend([
                ("state".into(), text(state)),
                ("complete".into(), Value::Bool(false)),
                ("stopped_commit".into(), text(raw_oid(*original))),
            ]);
        }
    }
    bounded(Value::Object(fields), live)
}
