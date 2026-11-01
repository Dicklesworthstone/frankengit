//! Closed preparation grammar. Every coordinate is original caller intent;
//! identity, policy decisions and successful checks cannot arrive in this form.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use fgit_forge::AggregateVersion;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{MergeMetadata, MergeProfile};
use fgit_types::{GitHashAlgorithm, PolicyEpoch, RepositoryIncarnationId};

use super::super::super::issues::{ApiError, parse_decimal, parse_form_with_field_limit};
use super::super::request::{binding, branch, oid, pull_number, take};
use super::MAX_COMMAND_BYTES;

const MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Command {
    pub expected_version: AggregateVersion,
    pub subject: ReviewSubject,
    pub metadata: MergeMetadata,
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
    for (key, value) in
        parse_form_with_field_limit(bytes, 19, "message_hex", 2 * MAX_MESSAGE_BYTES)?
    {
        if !matches!(
            key.as_str(),
            "expected_incarnation"
                | "object_format"
                | "expected_version"
                | "pull_request"
                | "expected_pull_request_version"
                | "expected_policy_epoch"
                | "source_ref"
                | "source_ref_hex"
                | "target_ref"
                | "target_ref_hex"
                | "expected_source_tip"
                | "expected_target_tip"
                | "author"
                | "committer"
                | "timestamp"
                | "message"
                | "message_hex"
                | "method"
                | "profile"
        ) {
            return Err(ApiError::bad("unknown_or_inapplicable_field"));
        }
        if fields.insert(key, value).is_some() {
            return Err(ApiError::bad("duplicate_field"));
        }
    }
    binding(&mut fields, format, incarnation)?;
    let expected_version =
        AggregateVersion::try_new(parse_decimal(&take(&mut fields, "expected_version")?)?)
            .ok_or_else(|| ApiError::bad("invalid_expected_version"))?;
    // A prepared queue candidate has an actionable original landing guard:
    // landing's prepare+complete events require two remaining queue versions.
    expected_version
        .next()
        .and_then(AggregateVersion::next)
        .map_err(|_| ApiError::bad("version_exhausted"))?;
    let pull_request_version = AggregateVersion::try_new(parse_decimal(&take(
        &mut fields,
        "expected_pull_request_version",
    )?)?)
    .ok_or_else(|| ApiError::bad("positive_pull_version_required"))?;
    pull_request_version
        .next()
        .map_err(|_| ApiError::bad("version_exhausted"))?;
    let subject = ReviewSubject {
        pull_request: pull_number(&take(&mut fields, "pull_request")?)?,
        pull_request_version,
        policy_epoch: PolicyEpoch::try_new(parse_decimal(&take(
            &mut fields,
            "expected_policy_epoch",
        )?)?)
        .map_err(|_| ApiError::bad("positive_policy_epoch_required"))?,
        source_ref: branch(&mut fields, "source_ref", "source_ref_hex")?,
        target_ref: branch(&mut fields, "target_ref", "target_ref_hex")?,
        source_tip: oid(&take(&mut fields, "expected_source_tip")?, format)?,
        target_tip: oid(&take(&mut fields, "expected_target_tip")?, format)?,
    };
    subject
        .validate()
        .map_err(|_| ApiError::bad("invalid_preparation_subject"))?;
    let metadata = MergeMetadata {
        author: take(&mut fields, "author")?,
        committer: take(&mut fields, "committer")?,
        timestamp: parse_decimal(&take(&mut fields, "timestamp")?)?,
        message: message(&mut fields)?,
    };
    metadata
        .validate()
        .map_err(|_| ApiError::bad("invalid_commit_metadata"))?;
    let profile = match fields.remove("profile").as_deref() {
        None | Some("path-merge-v1") => MergeProfile::PathMergeV1,
        Some("exact-renames-v1") => MergeProfile::ExactRenamesV1,
        Some(_) => return Err(ApiError::bad("unsupported_merge_profile")),
    };
    match fields.remove("method").as_deref() {
        None | Some("merge-commit") => {}
        Some(_) => return Err(ApiError::bad("unsupported_merge_method")),
    }
    if !fields.is_empty() {
        return Err(ApiError::bad("unknown_or_inapplicable_field"));
    }
    Ok(Command {
        expected_version,
        subject,
        metadata,
        profile,
    })
}

fn message(fields: &mut BTreeMap<String, String>) -> Result<Vec<u8>, ApiError> {
    match (fields.remove("message"), fields.remove("message_hex")) {
        (Some(value), None) => Ok(value.into_bytes()),
        (None, Some(value))
            if !value.is_empty()
                && value.len() <= 2 * MAX_MESSAGE_BYTES
                && value.len().is_multiple_of(2)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            let digit = |byte: u8| {
                if byte.is_ascii_digit() {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            let mut decoded = Vec::new();
            decoded
                .try_reserve_exact(value.len() / 2)
                .map_err(|_| ApiError::unavailable())?;
            for pair in value.as_bytes().as_chunks::<2>().0 {
                decoded.push((digit(pair[0]) << 4) | digit(pair[1]));
            }
            Ok(decoded)
        }
        _ => Err(ApiError::bad("exactly_one_message_encoding_required")),
    }
}
