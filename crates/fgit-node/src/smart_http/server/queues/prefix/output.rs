//! Original PR subjects and projected construction receipts remain separate.
//! A stopped prefix exposes diagnostics only, never an abbreviated artifact.

#[cfg(test)]
mod tests;

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_forge::preparation::queue_prefix::{
    MAX_PREFIX_ENTRIES, PrefixPreparation, PrefixStep, PrefixStop,
};
use fgit_forge::preparation::{ConflictKind, MergeEntry, MergeProfile};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::super::super::issues::{ApiError, quote, ref_fields};
use super::super::super::pulls::PreparationReply;
use super::super::super::{Binding, Status};
use crate::{OneNode, PreparedQueuePrefixBundle, QueuePrefixEntry};

const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn build(
    node: &OneNode,
    prepared: PreparedQueuePrefixBundle,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<PreparationReply, ApiError> {
    build_bound(
        Binding {
            tenant: node.tenant_id,
            repository: node.repository_id(),
            incarnation: node.repository_incarnation_id(),
        },
        node.object_format,
        prepared,
        maximum,
        live,
    )
}

fn build_bound(
    binding: Binding,
    format: GitHashAlgorithm,
    prepared: PreparedQueuePrefixBundle,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<PreparationReply, ApiError> {
    checkpoint(live)?;
    let PreparedQueuePrefixBundle {
        number,
        expected_version,
        source_head,
        entries,
        profile,
        preparation_id,
        outcome,
        bundle,
    } = prepared;
    if entries.is_empty() || entries.len() > MAX_PREFIX_ENTRIES {
        return Err(ApiError::unavailable());
    }
    let first = &entries[0].subject;
    if entries.iter().any(|entry| {
        entry.subject.validate().is_err()
            || entry.subject.source_tip.algorithm() != format
            || entry.subject.target_ref != first.target_ref
            || entry.subject.target_tip != first.target_tip
            || entry.subject.policy_epoch != first.policy_epoch
    }) {
        return Err(ApiError::unavailable());
    }
    match &outcome {
        PrefixPreparation::Clean(_)
            if preparation_id.is_some()
                && bundle.as_ref().is_some_and(|bytes| !bytes.is_empty()) => {}
        PrefixPreparation::Stopped { .. } if preparation_id.is_none() && bundle.is_none() => {}
        _ => return Err(ApiError::unavailable()),
    }
    let digest = bundle
        .as_ref()
        .map(|bytes| {
            if bytes.len() > MAX_BUNDLE_BYTES {
                return Err(ApiError::too_large());
            }
            let mut hash = Sha256Hasher::new();
            for chunk in bytes.chunks(16 * 1024) {
                checkpoint(live)?;
                hash.update(chunk);
            }
            Ok(hex(&hash.finish()))
        })
        .transpose()?;
    let head_id = source_head.as_internal_object_id();
    let token = format!(
        "alg:{}:{}",
        head_id.algorithm().code_point(),
        hex(head_id.digest().as_bytes())
    );
    let mut metadata = format!(
        concat!(
            "{{\"type\":\"queue_prefix_preparation\",\"schema_version\":1,",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},",
            "\"source_head\":{},\"snapshot_token\":{},\"profile\":{},\"method\":\"merge-commit\",",
            "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,",
            "\"published\":false,\"merge_authorized\":false,\"publication_supported\":false,",
            "\"queue\":{{\"number\":{},\"expected_version\":{}}},\"entry_count\":{},",
            "\"preparation_id\":{},\"initial_target\":{},\"original_subjects\":["
        ),
        quote(&binding.tenant.to_string()),
        quote(&binding.repository.to_string()),
        quote(&binding.incarnation.to_string()),
        quote(format.as_str()),
        quote(&source_head.to_string()),
        quote(&token),
        quote(match profile {
            MergeProfile::PathMergeV1 => "path-merge-v1",
            MergeProfile::ExactRenamesV1 => "exact-renames-v1",
        }),
        number.get(),
        expected_version.get(),
        entries.len(),
        preparation_id.map_or_else(|| "null".to_owned(), |id| quote(&hex(&id))),
        quote(&first.target_tip.to_string()),
    );
    for (index, entry) in entries.iter().enumerate() {
        checkpoint(live)?;
        let subject = &entry.subject;
        append(
            &mut metadata,
            &format!(
                concat!(
                    "{}{{\"index\":{},\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
                    "{},{},\"source_tip\":{},\"target_tip\":{}}}"
                ),
                comma(index),
                index,
                subject.pull_request.get(),
                subject.pull_request_version.get(),
                subject.policy_epoch.get(),
                ref_fields("source_ref", &subject.source_ref),
                ref_fields("target_ref", &subject.target_ref),
                quote(&subject.source_tip.to_string()),
                quote(&subject.target_tip.to_string()),
            ),
        )?;
    }
    append(&mut metadata, "],\"projected_steps\":[")?;
    let status = match &outcome {
        PrefixPreparation::Clean(plan) => {
            if plan.initial_target != first.target_tip || plan.steps.len() != entries.len() {
                return Err(ApiError::unavailable());
            }
            let last = projected_steps(
                &mut metadata,
                &entries,
                &plan.steps,
                first.target_tip,
                format,
                live,
            )?;
            if last != plan.final_commit {
                return Err(ApiError::unavailable());
            }
            let tree = plan.steps.last().ok_or_else(ApiError::unavailable)?.tree;
            append(
                &mut metadata,
                &format!(
                    concat!(
                        "],\"state\":\"clean\",\"candidate\":{{\"commit\":{},\"tree\":{},\"new_object_count\":{}}},",
                        "\"bundle\":{{\"bytes\":{},\"sha256\":{}}},\"stop\":null}}"
                    ),
                    quote(&plan.final_commit.to_string()),
                    quote(&tree.to_string()),
                    plan.objects.len(),
                    bundle.as_ref().ok_or_else(ApiError::unavailable)?.len(),
                    quote(digest.as_deref().ok_or_else(ApiError::unavailable)?),
                ),
            )?;
            Status::Success
        }
        PrefixPreparation::Stopped {
            index,
            source,
            projected_target,
            completed,
            reason,
        } => {
            let stopped = entries.get(*index).ok_or_else(ApiError::unavailable)?;
            if completed.len() != *index || *source != stopped.subject.source_tip {
                return Err(ApiError::unavailable());
            }
            let last = projected_steps(
                &mut metadata,
                &entries,
                completed,
                first.target_tip,
                format,
                live,
            )?;
            if last != *projected_target {
                return Err(ApiError::unavailable());
            }
            append(
                &mut metadata,
                &format!(
                    concat!(
                        "],\"state\":\"stopped\",\"candidate\":null,\"bundle\":null,",
                        "\"stop\":{{\"index\":{},\"pull_request\":{},\"source_tip\":{},\"projected_target_tip\":{},"
                    ),
                    index,
                    stopped.subject.pull_request.get(),
                    quote(&source.to_string()),
                    quote(&projected_target.to_string()),
                ),
            )?;
            match reason {
                PrefixStop::AlreadyIntegrated => append(
                    &mut metadata,
                    "\"reason\":\"already_integrated\",\"merge_base\":null,\"conflicts\":[]}}",
                )?,
                PrefixStop::Conflicted { base, conflicts } => {
                    if conflicts.is_empty() || conflicts.len() > 128 {
                        return Err(ApiError::unavailable());
                    }
                    append(
                        &mut metadata,
                        &format!(
                            "\"reason\":\"conflicted\",\"merge_base\":{},\"conflicts\":[",
                            quote(&base.to_string())
                        ),
                    )?;
                    for (index, conflict) in conflicts.iter().enumerate() {
                        checkpoint(live)?;
                        if conflict.path.is_empty() || conflict.path.len() > 4096 {
                            return Err(ApiError::too_large());
                        }
                        append(
                            &mut metadata,
                            &format!(
                                "{}{{\"path_hex\":{},\"kind\":{},\"base\":{},\"ours\":{},\"theirs\":{}}}",
                                comma(index),
                                quote(&hex(&conflict.path)),
                                quote(conflict_kind(conflict.kind)),
                                merge_entry(conflict.base.as_ref()),
                                merge_entry(conflict.ours.as_ref()),
                                merge_entry(conflict.theirs.as_ref()),
                            ),
                        )?;
                    }
                    append(&mut metadata, "]}}")?;
                }
            }
            Status::Conflict
        }
    };
    PreparationReply::artifact(status, metadata, bundle, digest.as_deref(), maximum, live)
}

fn projected_steps(
    metadata: &mut String,
    entries: &[QueuePrefixEntry],
    steps: &[PrefixStep],
    initial: GitOid,
    format: GitHashAlgorithm,
    live: &mut impl FnMut() -> bool,
) -> Result<GitOid, ApiError> {
    let mut target = initial;
    for (index, step) in steps.iter().enumerate() {
        checkpoint(live)?;
        let entry = entries.get(index).ok_or_else(ApiError::unavailable)?;
        if step.projected_target != target
            || step.source != entry.subject.source_tip
            || step.commit == target
            || [
                step.source,
                step.base,
                step.projected_target,
                step.tree,
                step.commit,
            ]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != format)
        {
            return Err(ApiError::unavailable());
        }
        append(
            metadata,
            &format!(
                "{}{{\"index\":{},\"source_tip\":{},\"projected_target_tip\":{},\"merge_base\":{},\"commit\":{},\"tree\":{}}}",
                comma(index),
                index,
                quote(&step.source.to_string()),
                quote(&step.projected_target.to_string()),
                quote(&step.base.to_string()),
                quote(&step.commit.to_string()),
                quote(&step.tree.to_string()),
            ),
        )?;
        target = step.commit;
    }
    Ok(target)
}

fn append(out: &mut String, value: &str) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n > MAX_METADATA_BYTES)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(value.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(value);
    Ok(())
}
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
const fn comma(index: usize) -> &'static str {
    if index == 0 { "" } else { "," }
}
fn merge_entry(entry: Option<&MergeEntry>) -> String {
    entry.map_or_else(
        || "null".to_owned(),
        |entry| {
            format!(
                "{{\"mode\":{},\"oid\":{}}}",
                entry.mode,
                quote(&entry.oid.to_string())
            )
        },
    )
}
const fn conflict_kind(kind: ConflictKind) -> &'static str {
    match kind {
        ConflictKind::Content => "content",
        ConflictKind::Binary => "binary",
        ConflictKind::ModifyDelete => "modify_delete",
        ConflictKind::TypeChange => "type_change",
        ConflictKind::Mode => "mode",
        ConflictKind::Opaque => "opaque",
        ConflictKind::AttributesRequireDriver => "attributes_require_driver",
    }
}
