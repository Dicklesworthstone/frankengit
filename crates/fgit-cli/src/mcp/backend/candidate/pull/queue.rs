//! Read-only construction for the exact canonical queue head. The native
//! preparation API selects the queue and PR at one authenticated predecessor;
//! this adapter never combines separate latest-state observations.
use super::*;
use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_forge::QueueNumber;
use fgit_forge::event::NativeMerge;
use fgit_forge::preparation::{MergePreparation, MergeProfile};
use fgit_node::NodeWorkspaceRefusal;
use fgit_types::RepositoryIncarnationId;

use super::super::super::queues;

#[derive(Debug)]
struct Input {
    number: QueueNumber,
    expected_version: AggregateVersion,
    preparation: prepare::Input,
}

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let mut allowed = SUBJECT_FIELDS.to_vec();
    allowed.extend(prepare::PREPARATION_FIELDS);
    allowed.extend(["queue_number", "expected_queue_version"]);
    require_fields(args, &allowed)?;
    if required(args, "operation")? != QUEUE_PREPARE {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    let number = QueueNumber::try_new(common::number(args, "queue_number")?)
        .ok_or(ToolError::invalid("positive_queue_number_required"))?;
    let expected_version =
        AggregateVersion::try_new(common::number(args, "expected_queue_version")?)
            .ok_or(ToolError::invalid("positive_queue_version_required"))?;
    // A clean result must fit the real two-event queue transition and PR
    // successor. Refuse exhausted coordinates before expensive object work.
    expected_version
        .next()
        .and_then(AggregateVersion::next)
        .map_err(|_| ToolError::invalid("version_exhausted"))?;
    let preparation = prepare::configuration(args, format)?;
    if preparation.style != MergeCommitStyle::TwoParent {
        return Err(ToolError::invalid("queue_requires_merge_commit"));
    }
    preparation
        .selection
        .subject
        .pull_request_version
        .next()
        .map_err(|_| ToolError::invalid("pr_version_exhausted"))?;
    Ok(Input {
        number,
        expected_version,
        preparation,
    })
}

pub(super) fn schema() -> Value {
    let mut properties = prepare::properties(QUEUE_PREPARE);
    for name in ["queue_number", "expected_queue_version"] {
        properties.insert(name.into(), super::super::super::decimal_schema());
    }
    properties.insert(
        "method".into(),
        object([
            ("const", text("merge-commit")),
            ("default", text("merge-commit")),
        ]),
    );
    let mut required = prepare::REQUIRED_FIELDS.to_vec();
    required.extend(["queue_number", "expected_queue_version"]);
    let mut schema = reviews::candidate_schema(properties, &required);
    if let Value::Object(fields) = &mut schema {
        fields.insert("description".into(), text("Requires source, PR and queue read grants together. Selects the exact idle queue head and PR/version/tips/policy at one authenticated snapshot. Two-parent construction only; no publication, reviewer identity or retry key. A clean result supplies separate exact inspection, review and queue-landing arguments."));
    }
    schema
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // Check every disclosure grant before parsing even an incomplete payload.
    permitted(backend)?;
    if !backend.options.queues.read {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let input = parse(args, backend.options.format)?;
    let preparation = &input.preparation;
    let request = fgit_cli::command_request_context(&backend.node);
    let prepared = backend
        .node
        .runtime()
        .block_on(backend.node.prepare_queue_head_bundle_with_profile_in(
            &request,
            input.number,
            input.expected_version,
            &preparation.selection.subject,
            &Default::default(),
            &preparation.metadata,
            preparation.limits,
            preparation.profile,
        ))
        .map_err(|error| match error {
            NodeWorkspaceRefusal::StaleWorkspaceBase => ToolError::failed("queue_subject_moved"),
            other => prepare::preparation_error(other),
        })?;
    if prepared.number != input.number || prepared.expected_version != input.expected_version {
        return Err(invalid_report());
    }
    check_selection(
        &preparation.selection,
        &prepared.subject,
        prepared.source_head,
    )?;
    let mut result = binding(backend);
    result.extend(subject_fields(&prepared.subject));
    result.extend([
        ("type".into(), text("queue_merge_preparation")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(QUEUE_PREPARE)),
        (
            "queue_number".into(),
            text(prepared.number.get().to_string()),
        ),
        (
            "expected_queue_version".into(),
            text(prepared.expected_version.get().to_string()),
        ),
        (
            "snapshot_token".into(),
            text(head_token(prepared.source_head)),
        ),
        (
            "merge_profile".into(),
            text(match preparation.profile {
                MergeProfile::PathMergeV1 => "path-merge-v1",
                MergeProfile::ExactRenamesV1 => "exact-renames-v1",
            }),
        ),
        ("method".into(), text("merge-commit")),
        ("complete".into(), Value::Bool(true)),
    ]);
    result.extend(prepare::render_with_publication(
        backend.options.format,
        preparation,
        &prepared.outcome,
        prepared.bundle.as_deref(),
        |candidate, bytes| {
            publication_arguments(
                &input,
                backend.node.repository_incarnation_id(),
                candidate,
                bytes,
            )
        },
    )?);
    if matches!(prepared.outcome, MergePreparation::Clean(_)) {
        result.insert("publication_tool".into(), text(queues::LAND_CANDIDATE));
    }
    let inspection =
        prepare::inspection_arguments(&result, prepared.source_head, MergeCommitStyle::TwoParent)?;
    result.insert("inspection_arguments".into(), inspection);
    Ok(Value::Object(result))
}

fn publication_arguments(
    input: &Input,
    incarnation: RepositoryIncarnationId,
    candidate: CandidateBinding,
    bytes: &[u8],
) -> Result<Value, ToolError> {
    let subject = &input.preparation.selection.subject;
    candidate.validate(subject).map_err(|_| invalid_report())?;
    let Value::Object(mut fields) = object([
        ("number", text(input.number.get().to_string())),
        (
            "expected_version",
            text(input.expected_version.get().to_string()),
        ),
        ("expected_incarnation", text(incarnation.to_string())),
        (
            "object_format",
            text(subject.source_tip.algorithm().as_str()),
        ),
        ("pull_request", text(subject.pull_request.get().to_string())),
        (
            "expected_pull_request_version",
            text(subject.pull_request_version.get().to_string()),
        ),
        (
            "source_reference_hex",
            text(hex(subject.source_ref.as_bytes())),
        ),
        (
            "target_reference_hex",
            text(hex(subject.target_ref.as_bytes())),
        ),
        ("expected_source", text(raw_oid(subject.source_tip))),
        ("expected_target", text(raw_oid(subject.target_tip))),
        (
            "expected_policy_epoch",
            text(subject.policy_epoch.get().to_string()),
        ),
        ("merge_base", text(raw_oid(candidate.merge_base))),
        ("candidate_commit", text(raw_oid(candidate.commit))),
        ("bundle_hex_chunks", encoded_chunks(bytes)?),
    ]) else {
        unreachable!()
    };
    // Validate against the actual landing adapter, including its tighter branch
    // and version limits. This local parser key never reaches the node or result.
    fields.insert(
        "idempotency_key".into(),
        text("validate-queue-candidate-template"),
    );
    let actual =
        queues::parse_candidate_landing(&fields, subject.source_tip.algorithm(), incarnation)
            .map_err(|_| invalid_report())?;
    let expected = QueueCandidateLandingCommand {
        number: input.number,
        expected_version: input.expected_version,
        expected_policy_epoch: subject.policy_epoch,
        pull_request: subject.pull_request,
        expected_pull_request_version: subject.pull_request_version,
        merge: NativeMerge {
            source_ref: subject.source_ref.clone(),
            target_ref: subject.target_ref.clone(),
            source_tip: subject.source_tip,
            target_tip_before: subject.target_tip,
            base_tip: candidate.merge_base,
            merge_commit: candidate.commit,
        },
    };
    if actual != expected {
        return Err(invalid_report());
    }
    fields.remove("idempotency_key");
    let arguments = Value::Object(fields);
    arguments
        .encode(json::MAX_INPUT - 4096)
        .map_err(|_| ToolError::failed("candidate_arguments_limit"))?;
    Ok(arguments)
}

#[cfg(test)]
mod tests;
