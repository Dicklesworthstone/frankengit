//! Complete read-only queue candidate artifacts, published locally only after
//! the node has drained. Reuse the merge command's create-only bundle writer.

use std::io::Write;

use fgit_forge::preparation::{MergePreparation, MergeProfile};
use fgit_node::PreparedQueueHeadBundle;
use fgit_types::RepositoryIncarnationId;

use super::options::{Operation, Options, head_token, hex};
use super::output::{bounded, scope};
use crate::merge_apply::preparation::{publish_new_bundle, render_conflict};
use crate::publication_support::quote;

pub(super) const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;

pub(super) fn finish(
    out: &mut impl Write,
    options: &Options,
    incarnation: RepositoryIncarnationId,
    artifact: &PreparedQueueHeadBundle,
) -> Result<u8, String> {
    let Operation::Prepare(preparation) = &options.operation else {
        return Err("candidate artifact does not match its request".into());
    };
    if artifact.number != preparation.number
        || artifact.expected_version != preparation.expected_version
        || artifact.subject != preparation.subject
    {
        return Err("candidate artifact changed its queue or PR subject".into());
    }
    let (outcome, exit, fields, bundle) = match &artifact.outcome {
        MergePreparation::Clean(plan) => {
            let bundle = artifact
                .bundle
                .as_deref()
                .ok_or("clean candidate omitted its bundle")?;
            if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
                return Err("candidate bundle exceeds the 128 MiB local artifact limit".into());
            }
            if plan.source != artifact.subject.source_tip
                || plan.target != artifact.subject.target_tip
            {
                return Err("candidate object plan changed its exact source or target".into());
            }
            (
                "prepared",
                0,
                format!(
                    concat!(
                        "\"merge_base\":{},\"candidate_commit\":{},\"root_tree\":{},",
                        "\"object_count\":{},\"bundle_bytes\":{},\"bundle_path\":{}"
                    ),
                    quote(&plan.base.to_string()),
                    quote(&plan.commit.to_string()),
                    quote(&plan.tree.to_string()),
                    plan.objects.len(),
                    bundle.len(),
                    quote(&preparation.output.to_string_lossy()),
                ),
                Some(bundle),
            )
        }
        MergePreparation::Conflicted { base, conflicts } => {
            if artifact.bundle.is_some() {
                return Err("conflicted preparation unexpectedly carried a bundle".into());
            }
            (
                "conflicted",
                5,
                format!(
                    "\"merge_base\":{},\"conflicts\":[{}]",
                    quote(&base.to_string()),
                    conflicts
                        .iter()
                        .map(render_conflict)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                None,
            )
        }
        MergePreparation::AlreadyUpToDate { target } => {
            if artifact.bundle.is_some() || *target != artifact.subject.target_tip {
                return Err("invalid already-up-to-date candidate artifact".into());
            }
            (
                "already_up_to_date",
                0,
                "\"candidate_commit\":null".into(),
                None,
            )
        }
    };
    let subject = &artifact.subject;
    let report = bounded(format!(
        concat!(
            "{{\"type\":\"merge_queue_preparation\",{},\"number\":{},\"expected_version\":{},",
            "\"pull_request\":{},\"expected_pull_request_version\":{},\"expected_policy_epoch\":{},",
            "\"source_ref_hex\":{},\"target_ref_hex\":{},\"expected_source_tip\":{},\"expected_target_tip\":{},",
            "\"source_head\":{},\"snapshot_token\":{},\"profile\":{},\"method\":\"merge-commit\",",
            "\"outcome\":{},\"bundle_created\":{},\"published_to_repository\":false,",
            "\"refs_changed\":false,\"complete\":true,\"node_closed\":true,{}}}"
        ),
        scope(options, incarnation),
        artifact.number.get(),
        artifact.expected_version.get(),
        subject.pull_request.get(),
        subject.pull_request_version.get(),
        subject.policy_epoch.get(),
        quote(&hex(subject.source_ref.as_bytes())),
        quote(&hex(subject.target_ref.as_bytes())),
        quote(&subject.source_tip.to_string()),
        quote(&subject.target_tip.to_string()),
        quote(&artifact.source_head.to_string()),
        quote(&head_token(artifact.source_head)),
        quote(match preparation.profile {
            MergeProfile::PathMergeV1 => "path-v1",
            MergeProfile::ExactRenamesV1 => "exact-renames-v1",
        }),
        quote(outcome),
        bundle.is_some(),
        fields,
    ))?;
    if let Some(bundle) = bundle {
        publish_new_bundle(&preparation.output, bundle)?;
    }
    writeln!(out, "{report}").and_then(|()| out.flush()).map_err(|error| {
        if bundle.is_some() {
            format!(
                "complete queue candidate bundle exists at {}; receipt output failed: {error}; repository state was not changed",
                preparation.output.display(),
            )
        } else {
            format!("queue preparation output failed: {error}; no bundle or repository mutation was published")
        }
    })?;
    Ok(exit)
}
