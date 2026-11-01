//! Every member names its original canonical PR coordinates. Projected merge
//! parents, actors, evidence and publication flags cannot be supplied here.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use fgit_forge::AggregateVersion;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::MergeProfile;
use fgit_forge::preparation::queue_prefix::MAX_PREFIX_ENTRIES;
use fgit_types::{GitHashAlgorithm, PolicyEpoch, RepositoryIncarnationId};

use super::super::super::issues::{ApiError, parse_decimal, parse_form_with_field_limit};
use super::super::preparation::{MAX_COMMAND_BYTES, request as common};
use super::super::request::{binding, branch, oid, pull_number, take};
use crate::QueuePrefixEntry;

const MAX_FIELDS: usize = 15 + 5 * MAX_PREFIX_ENTRIES;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Command {
    pub expected_version: AggregateVersion,
    pub entries: Vec<QueuePrefixEntry>,
    pub profile: MergeProfile,
}

pub(super) fn parse(
    bytes: &[u8],
    format: GitHashAlgorithm,
    incarnation: RepositoryIncarnationId,
) -> Result<Command, ApiError> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(ApiError::too_large());
    }
    let mut fields = BTreeMap::new();
    for (key, value) in parse_form_with_field_limit(
        bytes,
        MAX_FIELDS,
        "message_hex",
        2 * common::MAX_MESSAGE_BYTES,
    )? {
        if fields.insert(key, value).is_some() {
            return Err(ApiError::bad("duplicate_field"));
        }
    }
    binding(&mut fields, format, incarnation)?;
    let expected_version = positive_version(&take(&mut fields, "expected_version")?)?;
    let count = usize::try_from(parse_decimal(&take(&mut fields, "entry_count")?)?)
        .ok()
        .filter(|count| (1..=MAX_PREFIX_ENTRIES).contains(count))
        .ok_or_else(|| ApiError::bad("invalid_prefix_entry_count"))?;
    let policy_epoch =
        PolicyEpoch::try_new(parse_decimal(&take(&mut fields, "expected_policy_epoch")?)?)
            .map_err(|_| ApiError::bad("positive_policy_epoch_required"))?;
    let target_ref = branch(&mut fields, "target_ref", "target_ref_hex")?;
    let target_tip = oid(&take(&mut fields, "expected_target_tip")?, format)?;
    let metadata = common::metadata(&mut fields)?;
    let profile = common::profile(&mut fields)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| ApiError::unavailable())?;
    let mut numbers = BTreeSet::new();
    for index in 0..count {
        let pull_request = pull_number(&take(&mut fields, &format!("pull_request_{index}"))?)?;
        if !numbers.insert(pull_request) {
            return Err(ApiError::bad("duplicate_prefix_pull_request"));
        }
        let subject = ReviewSubject {
            pull_request,
            pull_request_version: positive_version(&take(
                &mut fields,
                &format!("expected_pull_request_version_{index}"),
            )?)?,
            policy_epoch,
            source_ref: branch(
                &mut fields,
                &format!("source_ref_{index}"),
                &format!("source_ref_hex_{index}"),
            )?,
            target_ref: target_ref.clone(),
            source_tip: oid(
                &take(&mut fields, &format!("expected_source_tip_{index}"))?,
                format,
            )?,
            target_tip,
        };
        subject
            .validate()
            .map_err(|_| ApiError::bad("invalid_preparation_subject"))?;
        entries.push(QueuePrefixEntry {
            subject,
            metadata: metadata.clone(),
        });
    }
    // Consuming the exact index spelling closes the grammar: missing members,
    // 00/+0 aliases, out-of-range indices and every unrecognized field refuse.
    if !fields.is_empty() {
        return Err(ApiError::bad("unknown_or_inapplicable_field"));
    }
    Ok(Command {
        expected_version,
        entries,
        profile,
    })
}

fn positive_version(value: &str) -> Result<AggregateVersion, ApiError> {
    AggregateVersion::try_new(parse_decimal(value)?)
        .ok_or_else(|| ApiError::bad("positive_expected_version_required"))
}
