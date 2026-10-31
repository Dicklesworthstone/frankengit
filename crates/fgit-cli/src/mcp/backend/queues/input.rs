//! Closed typed commands; no latest-state refresh, principal, force or bundle.
use std::collections::BTreeSet;

use fgit_admission::merge::native::queue::QueueLandingCommand;
use fgit_authority::IdempotencyKey;
use fgit_forge::merge_queue::{DequeueReason, QueueCommand, QueueCommandAction};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_types::{GitHashAlgorithm, PolicyEpoch, RefName, RepositoryIncarnationId};

use super::super::{pull_writes, string};
use super::*;

#[derive(Debug)]
pub(super) enum Command {
    Management(QueueCommand),
    Landing(QueueLandingCommand),
}

pub(super) const COMMON: &[&str] = &[
    "number",
    "expected_version",
    "idempotency_key",
    "expected_incarnation",
    "object_format",
    "target_reference",
    "target_reference_hex",
];
pub(super) const CANDIDATE: &[&str] = &[
    "pull_request",
    "expected_pull_request_version",
    "source_reference",
    "source_reference_hex",
    "expected_source",
    "expected_target",
];

pub(super) fn parse(
    name: &str,
    args: &Object,
    format: GitHashAlgorithm,
    incarnation: RepositoryIncarnationId,
) -> Result<(IdempotencyKey, Command), ToolError> {
    let mut allowed = COMMON.to_vec();
    match name {
        ENQUEUE | LAND => {
            allowed.extend(CANDIDATE);
            allowed.push(if name == ENQUEUE {
                "priority"
            } else {
                "expected_policy_epoch"
            });
        }
        DEQUEUE => allowed.extend(["pull_request", "reason"]),
        REORDER => allowed.push("order"),
        _ => return Err(ToolError::invalid("tool_not_granted")),
    }
    require_fields(args, &allowed)?;
    let key = common::key(args)?;
    let pinned = common::required(args, "expected_incarnation")?;
    let selected = RepositoryIncarnationId::from_hex(pinned)
        .map_err(|_| ToolError::invalid("invalid_repository_incarnation"))?;
    if selected.to_string() != pinned {
        return Err(ToolError::invalid("invalid_repository_incarnation"));
    }
    if selected != incarnation {
        return Err(ToolError::invalid("repository_incarnation_mismatch"));
    }
    if common::required(args, "object_format")? != format.as_str() {
        return Err(ToolError::invalid("object_format_mismatch"));
    }
    let number = QueueNumber::try_new(common::number(args, "number")?)
        .ok_or(ToolError::invalid("positive_queue_number_required"))?;
    let previous = common::number(args, "expected_version")?;
    let version = if previous == 0 && name == ENQUEUE {
        ExpectedVersion::NewStream
    } else {
        let version = AggregateVersion::try_new(previous)
            .ok_or(ToolError::invalid("positive_version_required"))?;
        version
            .next()
            .map_err(|_| ToolError::invalid("version_exhausted"))?;
        ExpectedVersion::Exactly(version)
    };
    let target_ref = branch(args, "target_reference", "target_reference_hex")?;
    let command = match name {
        ENQUEUE | LAND => {
            let pull_request = pull_number(common::required(args, "pull_request")?)?;
            let expected_pull_request_version =
                AggregateVersion::try_new(common::number(args, "expected_pull_request_version")?)
                    .ok_or(ToolError::invalid("positive_pull_version_required"))?;
            let source_ref = branch(args, "source_reference", "source_reference_hex")?;
            if source_ref == target_ref {
                return Err(ToolError::invalid("distinct_branches_required"));
            }
            let head_tip = pull_writes::oid(args, "expected_source", format)?;
            let expected_target_tip = pull_writes::oid(args, "expected_target", format)?;
            if name == LAND {
                if head_tip == expected_target_tip {
                    return Err(ToolError::invalid("invalid_queue_command"));
                }
                let ExpectedVersion::Exactly(expected_version) = version else {
                    unreachable!()
                };
                expected_version
                    .next()
                    .and_then(AggregateVersion::next)
                    .map_err(|_| ToolError::invalid("version_exhausted"))?;
                expected_pull_request_version
                    .next()
                    .map_err(|_| ToolError::invalid("pr_version_exhausted"))?;
                let expected_policy_epoch =
                    PolicyEpoch::try_new(common::number(args, "expected_policy_epoch")?)
                        .map_err(|_| ToolError::invalid("positive_policy_epoch_required"))?;
                Command::Landing(QueueLandingCommand {
                    number,
                    expected_version,
                    expected_policy_epoch,
                    pull_request,
                    expected_pull_request_version,
                    source_ref,
                    head_tip,
                    target_ref,
                    expected_target_tip,
                })
            } else {
                let priority = u32::try_from(super::super::decimal(args, "priority", 0)?)
                    .map_err(|_| ToolError::invalid("invalid_priority"))?;
                Command::Management(QueueCommand {
                    number,
                    target_ref,
                    expected_version: version,
                    action: QueueCommandAction::Enqueue {
                        pull_request,
                        expected_pull_request_version,
                        source_ref,
                        head_tip,
                        expected_target_tip,
                        priority,
                    },
                })
            }
        }
        DEQUEUE => Command::Management(QueueCommand {
            number,
            target_ref,
            expected_version: version,
            action: QueueCommandAction::Dequeue {
                pull_request: pull_number(common::required(args, "pull_request")?)?,
                reason: match common::required(args, "reason")? {
                    "withdrawn" => DequeueReason::Withdrawn,
                    "conflict" => DequeueReason::Conflict,
                    "check-failed" => DequeueReason::CheckFailed,
                    "base-moved" => DequeueReason::BaseMoved,
                    "evicted" => DequeueReason::Evicted,
                    "admin-override" => DequeueReason::AdminOverride,
                    _ => return Err(ToolError::invalid("invalid_dequeue_reason")),
                },
            },
        }),
        REORDER => {
            let Some(Value::Array(order)) = args.get("order") else {
                return Err(ToolError::invalid("queue_order_required"));
            };
            if order.is_empty() || order.len() > MAX_ORDER {
                return Err(ToolError::invalid("queue_order_limit"));
            }
            let mut seen = BTreeSet::new();
            let order = order
                .iter()
                .map(|entry| {
                    let number =
                        pull_number(entry.text().ok_or(ToolError::invalid("expected_string"))?)?;
                    if !seen.insert(number) {
                        return Err(ToolError::invalid("duplicate_queue_entry"));
                    }
                    Ok(number)
                })
                .collect::<Result<Vec<_>, ToolError>>()?;
            Command::Management(QueueCommand {
                number,
                target_ref,
                expected_version: version,
                action: QueueCommandAction::Reorder { order },
            })
        }
        _ => return Err(ToolError::invalid("tool_not_granted")),
    };
    Ok((key, command))
}

fn pull_number(value: &str) -> Result<PullRequestNumber, ToolError> {
    let number = super::super::super::json::decimal(value)
        .map_err(|_| ToolError::invalid("invalid_decimal_string"))?;
    PullRequestNumber::try_new(number).ok_or(ToolError::invalid("positive_pull_number_required"))
}
fn branch(args: &Object, plain: &str, encoded: &str) -> Result<RefName, ToolError> {
    if string(args, plain)?.is_some_and(|value| value.len() > MAX_BRANCH)
        || string(args, encoded)?.is_some_and(|value| value.len() > MAX_BRANCH * 2)
    {
        return Err(ToolError::invalid("branch_name_limit"));
    }
    pull_writes::branch(args, plain, encoded)
}
