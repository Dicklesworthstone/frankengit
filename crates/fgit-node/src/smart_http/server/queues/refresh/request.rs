//! Bounded exact original refresh semantics. No field is filled from live state.
use std::collections::BTreeMap;

use fgit_admission::merge::native::queue::QueueHeadRefreshCommand;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, QueueNumber};
use fgit_types::{GitHashAlgorithm, PolicyEpoch, RepositoryIncarnationId};

use super::super::super::issues::{ApiError, parse_decimal, parse_form};
use super::super::request::{binding, branch, oid, pull_number, take};
use super::MAX_COMMAND_BYTES;

pub(in super::super) fn parse(
    number: QueueNumber,
    bytes: &[u8],
    format: GitHashAlgorithm,
    incarnation: RepositoryIncarnationId,
) -> Result<QueueHeadRefreshCommand, ApiError> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(ApiError::too_large());
    }
    let mut fields = BTreeMap::new();
    for (key, value) in parse_form(bytes, 15)? {
        if !matches!(
            key.as_str(),
            "expected_incarnation"
                | "object_format"
                | "expected_version"
                | "expected_policy_epoch"
                | "pull_request"
                | "expected_pull_request_version"
                | "source_ref"
                | "source_ref_hex"
                | "target_ref"
                | "target_ref_hex"
                | "expected_source_tip"
                | "expected_recorded_target_tip"
                | "expected_target_tip"
                | "title"
                | "body"
        ) {
            return Err(ApiError::bad("unknown_or_inapplicable_field"));
        }
        if fields.insert(key, value).is_some() {
            return Err(ApiError::bad("duplicate_field"));
        }
    }
    binding(&mut fields, format, incarnation)?;
    let expected_queue_version =
        AggregateVersion::try_new(parse_decimal(&take(&mut fields, "expected_version")?)?)
            .ok_or_else(|| ApiError::bad("invalid_expected_version"))?;
    let expected_policy_epoch =
        PolicyEpoch::try_new(parse_decimal(&take(&mut fields, "expected_policy_epoch")?)?)
            .map_err(|_| ApiError::bad("invalid_policy_epoch"))?;
    let pull_number = pull_number(&take(&mut fields, "pull_request")?)?;
    let pull_version = AggregateVersion::try_new(parse_decimal(&take(
        &mut fields,
        "expected_pull_request_version",
    )?)?)
    .ok_or_else(|| ApiError::bad("positive_pull_version_required"))?;
    pull_version
        .next()
        .map_err(|_| ApiError::bad("version_exhausted"))?;
    let source_ref = branch(&mut fields, "source_ref", "source_ref_hex")?;
    let target_ref = branch(&mut fields, "target_ref", "target_ref_hex")?;
    let source_tip = oid(&take(&mut fields, "expected_source_tip")?, format)?;
    let expected_recorded_target_tip =
        oid(&take(&mut fields, "expected_recorded_target_tip")?, format)?;
    let target_tip = oid(&take(&mut fields, "expected_target_tip")?, format)?;
    if expected_recorded_target_tip == target_tip {
        return Err(ApiError::bad("queue_refresh_requires_target_movement"));
    }
    let data = PullRequestData {
        source_ref,
        target_ref,
        source_tip,
        target_tip,
        title: take(&mut fields, "title")?,
        body: take(&mut fields, "body")?,
    };
    data.validate()
        .map_err(|_| ApiError::bad("invalid_queue_refresh"))?;
    Ok(QueueHeadRefreshCommand {
        number,
        expected_queue_version,
        expected_policy_epoch,
        expected_recorded_target_tip,
        pull_request: PullRequestCommand {
            number: pull_number,
            expected_version: ExpectedVersion::Exactly(pull_version),
            action: PullRequestAction::Update,
            data,
        },
    })
}
