//! Exact-subject PR rebase construction through the existing native planner.
//! Original metadata is retained; no client-supplied author/message or alternate
//! merge method can silently change the selected series.

use super::super::super::issues::{ApiError, parse_decimal, parse_form, quote, ref_fields};
use super::super::subject::reference;
use super::{Request, Status, preparation_error};
use crate::smart_http::drive_request_while;
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode, PreparedPullRequestRebaseBundle};
use fgit_crypto::sha256_digest;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, RebaseCommitter, RebaseError, RebasePreparation, RebaseRequest, RebaseStep,
    RebaseStepKind, RebaseStop,
};
use fgit_forge::preparation::{MergeSourceError, PreparationLimits};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
struct Command {
    subject: ReviewSubject,
    upstream: GitOid,
    committer: RebaseCommitter,
    empty: EmptyCommitPolicy,
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_rebase_preparation_field"))
}
fn oid(value: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if value.len() != format.digest_len() * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_oid"));
    }
    let id = GitOid::from_hex(format, value).map_err(|_| ApiError::bad("invalid_oid"))?;
    if id.is_zero() {
        return Err(ApiError::bad("invalid_oid"));
    }
    Ok(id)
}
impl Command {
    fn parse(
        number: PullRequestNumber,
        bytes: &[u8],
        format: GitHashAlgorithm,
    ) -> Result<Self, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 14)? {
            if !matches!(
                name.as_str(),
                "object_format"
                    | "pull_request_version"
                    | "policy_epoch"
                    | "source_ref"
                    | "source_ref_hex"
                    | "target_ref"
                    | "target_ref_hex"
                    | "source_tip"
                    | "target_tip"
                    | "profile"
                    | "upstream"
                    | "committer"
                    | "timestamp"
                    | "empty"
            ) {
                return Err(ApiError::bad("unknown_rebase_preparation_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        if take(&mut fields, "profile")? != "path-v1" {
            return Err(ApiError::bad("unsupported_rebase_profile"));
        }
        let version =
            AggregateVersion::try_new(parse_decimal(&take(&mut fields, "pull_request_version")?)?)
                .ok_or_else(|| ApiError::bad("invalid_pull_request_version"))?;
        version
            .next()
            .map_err(|_| ApiError::bad("version_exhausted"))?;
        let subject = ReviewSubject {
            pull_request: number,
            pull_request_version: version,
            policy_epoch: PolicyEpoch::try_new(parse_decimal(&take(&mut fields, "policy_epoch")?)?)
                .map_err(|_| ApiError::bad("invalid_policy_epoch"))?,
            source_ref: reference(&mut fields, "source_ref", "source_ref_hex")?,
            target_ref: reference(&mut fields, "target_ref", "target_ref_hex")?,
            source_tip: oid(&take(&mut fields, "source_tip")?, format)?,
            target_tip: oid(&take(&mut fields, "target_tip")?, format)?,
        };
        subject
            .validate()
            .map_err(|_| ApiError::bad("invalid_preparation_subject"))?;
        let upstream = oid(&take(&mut fields, "upstream")?, format)?;
        if upstream == subject.source_tip
            || !subject.source_ref.as_bytes().starts_with(b"refs/heads/")
            || !subject.target_ref.as_bytes().starts_with(b"refs/heads/")
        {
            return Err(ApiError::bad("invalid_rebase_inputs"));
        }
        let committer = RebaseCommitter {
            identity: take(&mut fields, "committer")?,
            timestamp: parse_decimal(&take(&mut fields, "timestamp")?)?,
        };
        committer
            .validate()
            .map_err(|_| ApiError::bad("invalid_commit_metadata"))?;
        let empty = match take(&mut fields, "empty")?.as_str() {
            "stop" => EmptyCommitPolicy::Stop,
            "drop" => EmptyCommitPolicy::Drop,
            "keep" => EmptyCommitPolicy::Keep,
            _ => return Err(ApiError::bad("unsupported_empty_policy")),
        };
        if !fields.is_empty() {
            return Err(ApiError::bad("unknown_rebase_preparation_field"));
        }
        Ok(Self {
            subject,
            upstream,
            committer,
            empty,
        })
    }
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    bytes: &[u8],
    context: &NodeRequestContext,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<super::Reply, ApiError> {
    let command = Command::parse(request.number, bytes, node.object_format)?;
    let prepared = drive_request_while(
        node,
        context,
        node.prepare_pull_request_rebase_bundle_in(
            context,
            &command.subject,
            &Default::default(),
            command.upstream,
            &command.committer,
            PreparationLimits::default(),
            command.empty,
        ),
        live,
    )
    .map_err(|error| failure(&error))?;
    build(node, &command, prepared, maximum, live)
}

fn failure(error: &NodeWorkspaceRefusal) -> ApiError {
    let NodeWorkspaceRefusal::RebasePreparation(error) = error else {
        return preparation_error(error);
    };
    if error.is_snapshot_moved() || error.is_tip_moved() {
        return ApiError::new(Status::Conflict, "preparation_subject_moved");
    }
    if error.is_unavailable() {
        return ApiError::not_found();
    }
    if error.is_invalid_input() {
        return ApiError::bad("invalid_rebase_inputs");
    }
    if error.is_resource_refusal() {
        return ApiError::too_large();
    }
    if error.is_cancelled() {
        return ApiError::from_status(Status::Timeout, false);
    }
    if let Some(error) = error.preparation_refusal() {
        return match error {
            RebaseError::UpstreamOutsideLinearHistory => {
                ApiError::new(Status::Conflict, "upstream_outside_linear_history")
            }
            RebaseError::MergeCommit { .. } => {
                ApiError::new(Status::Conflict, "merge_commits_not_supported")
            }
            RebaseError::Preparation(error) => super::native_preparation_error(error),
            _ => ApiError::unavailable(),
        };
    }
    match error.source_refusal() {
        Some(MergeSourceError::Cancelled) => ApiError::from_status(Status::Timeout, false),
        Some(MergeSourceError::BudgetExceeded) => ApiError::too_large(),
        _ => ApiError::unavailable(),
    }
}

fn steps_valid(command: &Command, steps: &[RebaseStep]) -> Result<GitOid, ApiError> {
    if steps.len() > 256 {
        return Err(ApiError::unavailable());
    }
    let mut originals = BTreeSet::new();
    let mut rewrites = BTreeSet::new();
    let mut parent = command.subject.target_tip;
    let mut tree = None;
    for step in steps {
        if [step.original, step.rewritten, step.tree]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != parent.algorithm())
            || step.original == command.upstream
            || !originals.insert(step.original)
        {
            return Err(ApiError::unavailable());
        }
        if step.kind == RebaseStepKind::DroppedEmpty {
            if command.empty != EmptyCommitPolicy::Drop
                || step.rewritten != parent
                || tree.is_some_and(|tree| tree != step.tree)
            {
                return Err(ApiError::unavailable());
            }
        } else if step.rewritten == parent || !rewrites.insert(step.rewritten) {
            return Err(ApiError::unavailable());
        }
        parent = step.rewritten;
        tree = Some(step.tree);
    }
    Ok(parent)
}

fn build(
    node: &OneNode,
    command: &Command,
    prepared: PreparedPullRequestRebaseBundle,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<super::Reply, ApiError> {
    use super::output::{append, checkpoint, entry, hex, kind};
    checkpoint(live)?;
    let artifact = prepared.preparation;
    let expected = RebaseRequest {
        source_tip: command.subject.source_tip,
        upstream: command.upstream,
        onto: command.subject.target_tip,
        empty: command.empty,
    };
    let (request, steps) = match &artifact.outcome {
        RebasePreparation::Clean(plan) => (&plan.request, &plan.steps),
        RebasePreparation::Stopped {
            request, completed, ..
        } => (request, completed),
    };
    if prepared.subject != command.subject
        || prepared.source_head != artifact.source_head
        || *request != expected
        || artifact.borrowed_objects > artifact.pack_objects
        || artifact.pack_objects > PreparationLimits::default().max_objects
    {
        return Err(ApiError::unavailable());
    }
    let frontier = steps_valid(command, steps)?;
    let head = prepared.source_head.as_internal_object_id();
    let token = format!(
        "alg:{}:{}",
        head.algorithm().code_point(),
        hex(head.digest().as_bytes())
    );
    let subject = &command.subject;
    let empty = match command.empty {
        EmptyCommitPolicy::Stop => "stop",
        EmptyCommitPolicy::Drop => "drop",
        EmptyCommitPolicy::Keep => "keep",
    };
    let mut body = format!(
        concat!(
            "{{\"type\":\"pull_request_rebase_preparation\",\"schema_version\":1,\"profile\":\"path-v1\",\"method\":\"rebase\",",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
            "\"subject\":{{\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},{},{},\"source_tip\":{},\"target_tip\":{}}},",
            "\"merge_base\":{},\"committer\":{},\"timestamp\":{},\"empty_policy\":{},",
            "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,\"merge_authorized\":false,",
            "\"original_authors_preserved\":true,\"original_messages_preserved\":true,\"original_signatures_copied\":false,\"author_identity_verified\":false,"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
        quote(&prepared.source_head.to_string()),
        quote(&token),
        subject.pull_request.get(),
        subject.pull_request_version.get(),
        subject.policy_epoch.get(),
        ref_fields("source_ref", &subject.source_ref),
        ref_fields("target_ref", &subject.target_ref),
        quote(&subject.source_tip.to_string()),
        quote(&subject.target_tip.to_string()),
        quote(&command.upstream.to_string()),
        quote(&command.committer.identity),
        command.committer.timestamp,
        quote(empty)
    );
    let (status, digest) = match &artifact.outcome {
        RebasePreparation::Clean(plan) => {
            if plan.steps.is_empty()
                || plan.steps.last().is_none_or(|step| {
                    step.original != subject.source_tip || step.tree != plan.tree
                })
                || plan.commit != frontier
                || plan.commit == subject.target_tip
                || plan.objects.len() > PreparationLimits::default().max_objects
            {
                return Err(ApiError::unavailable());
            }
            let bundle = artifact
                .bundle
                .as_ref()
                .filter(|bytes| !bytes.is_empty())
                .ok_or_else(ApiError::unavailable)?;
            if bundle.len() > 64 * 1024 * 1024 {
                return Err(ApiError::too_large());
            }
            let digest = hex(&sha256_digest(bundle));
            checkpoint(live)?;
            append(
                &mut body,
                &format!(
                    concat!(
                        "\"state\":\"clean\",\"series_complete\":true,\"provisional_steps\":false,",
                        "\"candidate_commit\":{},\"root_tree\":{},\"generated_objects\":{},\"pack_objects\":{},\"borrowed_objects\":{},",
                        "\"bundle\":{{\"bytes\":{},\"sha256\":{}}},\"stopped_commit\":null,\"conflicts\":[],"
                    ),
                    quote(&plan.commit.to_string()),
                    quote(&plan.tree.to_string()),
                    plan.objects.len(),
                    artifact.pack_objects,
                    artifact.borrowed_objects,
                    bundle.len(),
                    quote(&digest)
                ),
            )?;
            (Status::Success, Some(digest))
        }
        RebasePreparation::Stopped {
            original, reason, ..
        } => {
            if artifact.bundle.is_some()
                || artifact.pack_objects != 0
                || artifact.borrowed_objects != 0
                || original.is_zero()
                || original.algorithm() != node.object_format
                || *original == command.upstream
                || steps.iter().any(|step| step.original == *original)
            {
                return Err(ApiError::unavailable());
            }
            let state = match reason {
                RebaseStop::Conflicted(_) => "conflicted",
                RebaseStop::BecameEmpty => "became_empty",
            };
            append(
                &mut body,
                &format!(
                    concat!(
                        "\"state\":{},\"series_complete\":false,\"provisional_steps\":true,",
                        "\"candidate_commit\":null,\"root_tree\":null,\"bundle\":null,\"stopped_commit\":{},\"conflicts\":["
                    ),
                    quote(state),
                    quote(&original.to_string())
                ),
            )?;
            if let RebaseStop::Conflicted(conflicts) = reason {
                if conflicts.is_empty()
                    || conflicts.len() > PreparationLimits::default().max_conflicts
                    || conflicts
                        .windows(2)
                        .any(|pair| pair[0].path >= pair[1].path)
                {
                    return Err(ApiError::unavailable());
                }
                for (index, conflict) in conflicts.iter().enumerate() {
                    checkpoint(live)?;
                    if conflict.path.is_empty()
                        || conflict.path.len() > PreparationLimits::default().max_path_bytes
                    {
                        return Err(ApiError::unavailable());
                    }
                    append(
                        &mut body,
                        &format!(
                            "{}{{\"path_hex\":{},\"kind\":{},\"base\":{},\"ours\":{},\"theirs\":{}}}",
                            if index == 0 { "" } else { "," },
                            quote(&hex(&conflict.path)),
                            quote(kind(conflict.kind)),
                            entry(conflict.base.as_ref()),
                            entry(conflict.ours.as_ref()),
                            entry(conflict.theirs.as_ref())
                        ),
                    )?;
                }
            }
            append(&mut body, "],")?;
            (Status::Conflict, None)
        }
    };
    append(
        &mut body,
        &format!("\"step_count\":{},\"steps\":[", steps.len()),
    )?;
    for (index, step) in steps.iter().enumerate() {
        checkpoint(live)?;
        let kind = match step.kind {
            RebaseStepKind::Replayed => "replayed",
            RebaseStepKind::PreservedEmpty => "preserved_empty",
            RebaseStepKind::DroppedEmpty => "dropped_empty",
        };
        append(
            &mut body,
            &format!(
                "{}{{\"original\":{},\"rewritten\":{},\"tree\":{},\"kind\":{}}}",
                if index == 0 { "" } else { "," },
                quote(&step.original.to_string()),
                quote(&step.rewritten.to_string()),
                quote(&step.tree.to_string()),
                quote(kind)
            ),
        )?;
    }
    append(&mut body, "]}")?;
    super::Reply::artifact(
        status,
        body,
        artifact.bundle,
        digest.as_deref(),
        maximum,
        live,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form(format: GitHashAlgorithm) -> String {
        format!(
            "object_format={}&profile=path-v1&pull_request_version=1&policy_epoch=1&source_ref=refs/heads/topic&target_ref=refs/heads/main&source_tip={}&target_tip={}&upstream={}&committer=User+%3Cu%40example.invalid%3E&timestamp=1&empty=stop",
            format.as_str(),
            "a".repeat(format.digest_len() * 2),
            "b".repeat(format.digest_len() * 2),
            "c".repeat(format.digest_len() * 2)
        )
    }
    #[test]
    fn rebase_preparation_route_is_a_body_bearing_read_without_resolution_fallback() {
        use fgit_wire::smart_http::{HttpLimits, head};
        let wire = "POST /r.git/api/v1/pulls/1/prepare-rebase HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n";
        let envelope = head::parse(wire.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let request = Request::parse(&envelope).unwrap().unwrap();
        assert!(request.rebase);
        assert!(!request.resolution);
        assert!(
            request
                .command(
                    form(GitHashAlgorithm::Sha1).as_bytes(),
                    GitHashAlgorithm::Sha1
                )
                .is_err()
        );
        for invalid in [
            wire.replace("prepare-rebase", "prepare-rebase/resolve"),
            wire.replace("POST", "GET"),
            wire.replace("prepare-rebase", "prepare-rebase?method=squash"),
            wire.replace(
                "application/x-www-form-urlencoded",
                "multipart/form-data; boundary=x",
            ),
        ] {
            let envelope = head::parse(invalid.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&envelope).is_err());
        }
    }

    #[test]
    fn rebase_preparation_requires_explicit_exact_subject_and_preserves_original_metadata() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let valid = form(format);
            let command =
                Command::parse(PullRequestNumber::FIRST, valid.as_bytes(), format).unwrap();
            assert_eq!(command.empty, EmptyCommitPolicy::Stop);
            for empty in ["stop", "drop", "keep"] {
                assert!(
                    Command::parse(
                        PullRequestNumber::FIRST,
                        valid
                            .replace("empty=stop", &format!("empty={empty}"))
                            .as_bytes(),
                        format
                    )
                    .is_ok()
                );
            }
            for invalid in [
                valid.clone() + "&author=Fake",
                valid.clone() + "&message=Replace",
                valid.clone() + "&method=squash",
                valid.clone() + "&upstream=0",
                valid.replace("profile=path-v1", "profile=linear-v1"),
                valid.replace("&empty=stop", ""),
                valid.replace("empty=stop", "empty=automatic"),
                valid.replace("pull_request_version=1", "pull_request_version=0"),
                valid.replace(
                    &format!("upstream={}", "c".repeat(format.digest_len() * 2)),
                    &format!("upstream={}", "a".repeat(format.digest_len() * 2)),
                ),
                valid.replace("source_ref=refs/heads/topic", "source_ref=refs/heads/main"),
                valid.replace("committer=User", "committer=User%0AInjected"),
            ] {
                assert!(
                    Command::parse(PullRequestNumber::FIRST, invalid.as_bytes(), format).is_err(),
                    "{invalid}"
                );
            }
            let raw = valid.replace(
                "source_ref=refs/heads/topic",
                "source_ref_hex=726566732f68656164732fff",
            );
            assert_eq!(
                Command::parse(PullRequestNumber::FIRST, raw.as_bytes(), format)
                    .unwrap()
                    .subject
                    .source_ref
                    .as_bytes(),
                b"refs/heads/\xff"
            );
        }
    }
}
