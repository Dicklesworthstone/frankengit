//! Complete rebase outcomes and exact handoffs. A stopped series exposes only
//! diagnostic mappings, never a partial bundle or publication candidate.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::preparation::rebase::PreparedRebase;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Report<'a> {
    pub head: RepositoryAuthorityHeadId,
    pub outcome: &'a RebasePreparation,
    pub bundle: Option<&'a [u8]>,
    pub pack_objects: usize,
    pub borrowed_objects: usize,
    pub resolutions: &'a [RebaseResolvedStep],
}
fn valid(id: GitOid, format: GitHashAlgorithm) -> bool {
    !id.is_zero() && id.algorithm() == format
}
pub(super) fn validate_steps(
    input: &input::Input,
    steps: &[RebaseStep],
) -> Result<GitOid, ToolError> {
    if steps.len() > input.limits.max_commits {
        return Err(invalid_report());
    }
    let mut seen = BTreeSet::new();
    let mut parent = input.request.onto;
    let mut tree = None;
    let format = input.request.source_tip.algorithm();
    for step in steps {
        if [step.original, step.rewritten, step.tree]
            .iter()
            .any(|id| !valid(*id, format))
            || step.original == input.request.upstream
            || !seen.insert(step.original)
        {
            return Err(invalid_report());
        }
        if step.kind == RebaseStepKind::DroppedEmpty {
            if input.request.empty != EmptyCommitPolicy::Drop
                || step.rewritten != parent
                || tree.is_some_and(|value| value != step.tree)
            {
                return Err(invalid_report());
            }
        } else if step.rewritten == parent {
            return Err(invalid_report());
        }
        parent = step.rewritten;
        tree = Some(step.tree);
    }
    Ok(parent)
}
pub(super) fn validate_clean(
    input: &input::Input,
    plan: &PreparedRebase,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ToolError> {
    checkpoint(live)?;
    let format = input.request.source_tip.algorithm();
    if !valid(plan.commit, format)
        || !valid(plan.tree, format)
        || validate_steps(input, &plan.steps)? != plan.commit
        || plan.objects.len() > input.limits.max_objects
        || plan
            .steps
            .last()
            .is_some_and(|step| step.original != input.request.source_tip || step.tree != plan.tree)
        || (plan.steps.is_empty() && input.request.source_tip != input.request.upstream)
    {
        return Err(invalid_report());
    }
    let mut objects = BTreeMap::new();
    let mut retained = 0_usize;
    for object in &plan.objects {
        checkpoint(live)?;
        retained = retained
            .checked_add(object.body.len())
            .filter(|total| *total <= input.limits.max_output_bytes)
            .ok_or_else(invalid_report)?;
        if !valid(object.id, format)
            || git_object_id(format, object.kind, &object.body) != object.id
            || objects.insert(object.id, object).is_some()
        {
            return Err(invalid_report());
        }
    }
    let mut parent = input.request.onto;
    for step in &plan.steps {
        checkpoint(live)?;
        if step.kind != RebaseStepKind::DroppedEmpty {
            let object = objects.get(&step.rewritten).ok_or_else(invalid_report)?;
            // Native construction already parses and verifies all commit bytes.
            // This narrow generated-prefix check binds each exposed mapping to
            // the actual named tree and sole predecessor before handing it on.
            let prefix = format!("tree {}\nparent {}\nauthor ", step.tree, parent);
            if object.kind != GitObjectKind::Commit || !object.body.starts_with(prefix.as_bytes()) {
                return Err(invalid_report());
            }
        }
        parent = step.rewritten;
    }
    checkpoint(live)
}
fn shared_error(error: ToolError) -> ToolError {
    if error.code == "replay_cancelled" {
        ToolError::failed("rebase_cancelled")
    } else {
        invalid_report()
    }
}
fn resolutions(
    input: &input::Input,
    outcome: &RebasePreparation,
    observed: &[RebaseResolvedStep],
    live: &mut impl FnMut() -> bool,
) -> Result<Value, ToolError> {
    let Some(recipes) = input.resolutions.as_deref() else {
        return if observed.is_empty() {
            Ok(Value::Array(Vec::new()))
        } else {
            Err(invalid_report())
        };
    };
    if recipes.is_empty() || observed.len() > recipes.len() {
        return Err(invalid_report());
    }
    let (steps, empty_stop, clean) = match outcome {
        RebasePreparation::Clean(plan) => (plan.steps.as_slice(), None, true),
        RebasePreparation::Stopped {
            original,
            completed,
            reason,
            ..
        } => (
            completed.as_slice(),
            matches!(reason, RebaseStop::BecameEmpty).then_some(*original),
            false,
        ),
    };
    let mut positions: BTreeMap<_, _> = steps
        .iter()
        .enumerate()
        .map(|(n, step)| (step.original, n))
        .collect();
    if positions.len() != steps.len() {
        return Err(invalid_report());
    }
    if let Some(original) = empty_stop
        && positions.insert(original, steps.len()).is_some()
    {
        return Err(invalid_report());
    }
    let supplied: BTreeMap<_, _> = recipes
        .iter()
        .map(|row| (row.original, row.paths.as_slice()))
        .collect();
    if supplied.len() != recipes.len() {
        return Err(invalid_report());
    }
    let expected: BTreeSet<_> = supplied
        .keys()
        .filter(|id| positions.contains_key(*id))
        .copied()
        .collect();
    let mut seen = BTreeSet::new();
    let mut previous = None;
    let mut rows = Vec::with_capacity(observed.len());
    for row in observed {
        checkpoint(live)?;
        let position = *positions.get(&row.original).ok_or_else(invalid_report)?;
        if previous.is_some_and(|value| value >= position) || !seen.insert(row.original) {
            return Err(invalid_report());
        }
        previous = Some(position);
        let paths = super::super::replay::output::receipts(
            supplied.get(&row.original).ok_or_else(invalid_report)?,
            &row.paths,
            input.request.source_tip.algorithm(),
            input.limits,
            live,
        )
        .map_err(shared_error)?;
        rows.push(object([
            ("original", text(raw_oid(row.original))),
            ("paths", paths),
        ]));
    }
    if seen != expected || (clean && seen.len() != supplied.len()) {
        return Err(invalid_report());
    }
    Ok(Value::Array(rows))
}
pub(super) fn render(
    backend: &NodeTools,
    input: &input::Input,
    report: Report<'_>,
    live: &mut impl FnMut() -> bool,
) -> Result<Value, ToolError> {
    checkpoint(live)?;
    let (request, steps) = match report.outcome {
        RebasePreparation::Clean(plan) => (&plan.request, plan.steps.as_slice()),
        RebasePreparation::Stopped {
            request, completed, ..
        } => (request, completed.as_slice()),
    };
    if *request != input.request
        || input
            .selection
            .head
            .is_some_and(|expected| expected != report.head)
        || report.borrowed_objects > report.pack_objects
        || report.pack_objects > input.limits.max_objects
    {
        return Err(invalid_report());
    }
    validate_steps(input, steps)?;
    let decisions = resolutions(input, report.outcome, report.resolutions, live)?;
    let mut fields = backend.header(report.head);
    fields.extend(binding(backend));
    fields.extend([
        ("type".into(), text("source_rebase_candidate")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(input.operation())),
        ("profile".into(), text("linear-v1")),
        ("source_head".into(), text(report.head.to_string())),
        (
            "reference_hex".into(),
            text(hex(input.selection.reference.as_bytes())),
        ),
        (
            "onto_reference_hex".into(),
            text(hex(input.selection.onto_reference.as_bytes())),
        ),
        ("expected_source".into(), text(raw_oid(request.source_tip))),
        ("upstream".into(), text(raw_oid(request.upstream))),
        ("onto".into(), text(raw_oid(request.onto))),
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
        ("counter_encoding".into(), text("decimal-strings-v1")),
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
        ("stopped_commit".into(), Value::Null),
        ("conflicts".into(), Value::Array(Vec::new())),
        ("generated_objects".into(), text("0")),
        ("pack_objects".into(), text(report.pack_objects.to_string())),
        (
            "borrowed_objects".into(),
            text(report.borrowed_objects.to_string()),
        ),
        ("bundle_sha256".into(), Value::Null),
        ("bundle_bytes".into(), text("0")),
        ("inspection_tool".into(), Value::Null),
        ("inspection_arguments".into(), Value::Null),
        ("publication_tool".into(), Value::Null),
        ("publication_arguments".into(), Value::Null),
        (
            "resolution_profile".into(),
            if input.resolutions.is_some() {
                text("original-commit-path-v1")
            } else {
                Value::Null
            },
        ),
        (
            "resolution_input_commits".into(),
            text(input.resolutions.as_ref().map_or(0, Vec::len).to_string()),
        ),
        (
            "resolution_consumed_commits".into(),
            text(report.resolutions.len().to_string()),
        ),
        ("resolutions".into(), decisions),
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
    match report.outcome {
        RebasePreparation::Clean(plan) => {
            validate_clean(input, plan, live)?;
            let bytes = report.bundle.ok_or_else(invalid_report)?;
            if bytes.len() > input.limits.max_output_bytes {
                return Err(ToolError::failed("candidate_bundle_limit"));
            }
            let digest = sha256_digest(bytes);
            let publish = publication(
                &input.selection.reference,
                request.source_tip,
                request.onto,
                plan.commit,
                bytes,
            )?;
            let inspect = handoff(object([
                ("operation", text(INSPECT)),
                ("profile", text("linear-v1")),
                (
                    "reference_hex",
                    text(hex(input.selection.reference.as_bytes())),
                ),
                (
                    "onto_reference_hex",
                    text(hex(input.selection.onto_reference.as_bytes())),
                ),
                ("expected_source", text(raw_oid(request.source_tip))),
                ("expected_onto", text(raw_oid(request.onto))),
                ("expected_candidate", text(raw_oid(plan.commit))),
                ("expected_head", text(head_token(report.head))),
                ("expected_bundle_sha256", text(hex(&digest))),
                ("bundle_hex_chunks", encoded_chunks(bytes)?),
            ]))?;
            fields.extend([
                ("state".into(), text("clean")),
                ("complete".into(), Value::Bool(true)),
                ("series_complete".into(), Value::Bool(true)),
                ("provisional_steps".into(), Value::Bool(false)),
                ("candidate_available".into(), Value::Bool(true)),
                ("candidate_commit".into(), text(raw_oid(plan.commit))),
                ("root_tree".into(), text(raw_oid(plan.tree))),
                (
                    "generated_objects".into(),
                    text(plan.objects.len().to_string()),
                ),
                ("bundle_bytes".into(), text(bytes.len().to_string())),
                ("bundle_sha256".into(), text(hex(&digest))),
                ("inspection_tool".into(), text(NAME)),
                ("inspection_arguments".into(), inspect),
                ("publication_tool".into(), text(PUBLICATION_TOOL)),
                ("publication_arguments".into(), publish),
            ]);
        }
        RebasePreparation::Stopped {
            original, reason, ..
        } => {
            if report.bundle.is_some()
                || report.pack_objects != 0
                || report.borrowed_objects != 0
                || !valid(*original, backend.options.format)
                || *original == request.upstream
                || steps.iter().any(|step| step.original == *original)
            {
                return Err(invalid_report());
            }
            let state = match reason {
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
                        rows.push(
                            super::super::replay::output::conflict(
                                conflict,
                                backend.options.format,
                                input.limits.max_path_bytes,
                            )
                            .map_err(shared_error)?,
                        );
                    }
                    fields.insert("conflicts".into(), Value::Array(rows));
                    "conflicted"
                }
                RebaseStop::BecameEmpty => "became_empty",
            };
            fields.extend([
                ("state".into(), text(state)),
                ("complete".into(), Value::Bool(false)),
                ("series_complete".into(), Value::Bool(false)),
                ("provisional_steps".into(), Value::Bool(true)),
                ("stopped_commit".into(), text(raw_oid(*original))),
            ]);
        }
    }
    bounded(Value::Object(fields), live)
}
