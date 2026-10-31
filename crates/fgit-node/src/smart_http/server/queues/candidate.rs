//! Closed two-parent queue-candidate metadata. The multipart upload carries
//! objects only; it never supplies a method, actor or successful check evidence.

use std::collections::BTreeMap;

use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_forge::AggregateVersion;
use fgit_forge::event::NativeMerge;
use fgit_types::{GitHashAlgorithm, PolicyEpoch, RepositoryIncarnationId};

use super::super::issues::{ApiError, parse_decimal, parse_form};
use super::MAX_COMMAND_BYTES;
use super::request::{Operation, Request, binding, branch, oid, pull_number, take};

impl Request<'_> {
    pub(super) fn candidate_landing_command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
        incarnation: RepositoryIncarnationId,
    ) -> Result<QueueCandidateLandingCommand, ApiError> {
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(ApiError::too_large());
        }
        let Operation::LandCandidate { number, .. } = &self.operation else {
            return Err(ApiError::bad("not_a_candidate_landing"));
        };
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
                    | "expected_target_tip"
                    | "merge_base"
                    | "expected_commit"
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
        expected_version
            .next()
            .and_then(AggregateVersion::next)
            .map_err(|_| ApiError::bad("version_exhausted"))?;
        let expected_pull_request_version = AggregateVersion::try_new(parse_decimal(&take(
            &mut fields,
            "expected_pull_request_version",
        )?)?)
        .ok_or_else(|| ApiError::bad("positive_pull_version_required"))?;
        expected_pull_request_version
            .next()
            .map_err(|_| ApiError::bad("version_exhausted"))?;
        let expected_policy_epoch =
            PolicyEpoch::try_new(parse_decimal(&take(&mut fields, "expected_policy_epoch")?)?)
                .map_err(|_| ApiError::bad("positive_policy_epoch_required"))?;
        let pull_request = pull_number(&take(&mut fields, "pull_request")?)?;
        let merge = NativeMerge {
            source_ref: branch(&mut fields, "source_ref", "source_ref_hex")?,
            source_tip: oid(&take(&mut fields, "expected_source_tip")?, format)?,
            target_ref: branch(&mut fields, "target_ref", "target_ref_hex")?,
            target_tip_before: oid(&take(&mut fields, "expected_target_tip")?, format)?,
            base_tip: oid(&take(&mut fields, "merge_base")?, format)?,
            merge_commit: oid(&take(&mut fields, "expected_commit")?, format)?,
        };
        merge
            .validate()
            .map_err(|_| ApiError::bad("invalid_queue_command"))?;
        // Match the native candidate profile's structural checks before any
        // admission call. An FF or nonmoving input is not an uncertain merge.
        if merge.source_tip == merge.target_tip_before
            || merge.merge_commit == merge.source_tip
            || merge.merge_commit == merge.base_tip
        {
            return Err(ApiError::bad("invalid_queue_command"));
        }
        Ok(QueueCandidateLandingCommand {
            number: *number,
            expected_version,
            expected_policy_epoch,
            pull_request,
            expected_pull_request_version,
            merge,
        })
    }
}
