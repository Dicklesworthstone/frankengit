//! Complete PR series inspection using the existing exact-byte PR diff schema.
//! One output ceiling covers every commit body and every comparison together.

use super::{ApiError, ComparisonMode, Json, OneNode, ReviewContent, entry, quote, ref_fields};
use crate::treefs_workspace::candidate_inspection::RebaseBundleInspection;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::review::{ReviewOptions, SourceComparison};
use fgit_types::GitOid;
use std::collections::BTreeSet;

const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
fn add(total: &mut usize, amount: usize, maximum: usize) -> Result<(), ApiError> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or_else(ApiError::too_large)?;
    Ok(())
}
fn coordinates(value: &SourceComparison, before: GitOid, after: GitOid) -> bool {
    value.mode == ComparisonMode::Direct
        && value.requested_before == before
        && value.compared_before == before
        && value.requested_after == after
}
fn validate(
    node: &OneNode,
    subject: &ReviewSubject,
    candidate: CandidateBinding,
    value: &RebaseBundleInspection,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    if !live() {
        return Err(ApiError::from_status(super::Status::Timeout, false));
    }
    candidate
        .validate(subject)
        .map_err(|_| ApiError::unavailable())?;
    if value.repository_id != node.repository_id
        || value.source_reference != subject.source_ref
        || value.onto_reference != subject.target_ref
        || value.expected_source != subject.source_tip
        || value.onto != subject.target_tip
        || value.candidate != candidate.commit
        || candidate.merge_base == subject.source_tip
        || value.commits.is_empty()
        || value.commits.len() > 256
        || value.comparisons.len() != value.commits.len() + 1
        || value.bundle.transport_only_objects > value.bundle.pack_objects
        || value.bundle.pack_bytes > value.bundle.bytes
        || !coordinates(&value.comparisons[0], subject.source_tip, candidate.commit)
    {
        return Err(ApiError::unavailable());
    }
    let mut parent = subject.target_tip;
    let mut tree = None;
    let mut seen = BTreeSet::new();
    let mut bodies = 0;
    for (commit, comparison) in value.commits.iter().zip(&value.comparisons[1..]) {
        if !live() {
            return Err(ApiError::from_status(super::Status::Timeout, false));
        }
        add(&mut bodies, commit.body.len(), 16 * 1024 * 1024)?;
        if commit.parent != parent
            || !seen.insert(commit.id)
            || commit.id == subject.target_tip
            || commit.body.len() > 2 * 1024 * 1024
            || git_object_id(node.object_format, GitObjectKind::Commit, &commit.body) != commit.id
            || !coordinates(comparison, parent, commit.id)
            || comparison.after_tree != commit.tree
            || tree.is_some_and(|tree| tree != comparison.before_tree)
        {
            return Err(ApiError::unavailable());
        }
        parent = commit.id;
        tree = Some(commit.tree);
    }
    if parent != candidate.commit || tree != Some(value.comparisons[0].after_tree) {
        return Err(ApiError::unavailable());
    }
    let limits = ReviewOptions::default().limits;
    let (mut changes, mut files, mut hunks, mut bytes) = (0, 0, 0, 0);
    for comparison in &value.comparisons {
        if !live() {
            return Err(ApiError::from_status(super::Status::Timeout, false));
        }
        add(&mut changes, comparison.entries.len(), limits.max_changes)?;
        if comparison
            .entries
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(ApiError::unavailable());
        }
        for entry in &comparison.entries {
            add(&mut bytes, entry.path.len(), limits.max_output_bytes)?;
            if let ReviewContent::Text { hunks: spans, .. } = &entry.content {
                add(&mut files, 1, limits.max_text_files)?;
                add(&mut hunks, spans.len(), limits.max_hunks)?;
                for span in spans {
                    add(&mut bytes, span.before.len(), limits.max_output_bytes)?;
                    add(&mut bytes, span.after.len(), limits.max_output_bytes)?;
                }
            }
        }
    }
    Ok(())
}
fn comparison<C: FnMut() -> bool>(
    out: &mut Json<'_, C>,
    value: &SourceComparison,
) -> Result<(), ApiError> {
    out.put(&format!(concat!("{{\"mode\":\"direct\",\"before\":{},\"after\":{},\"before_tree\":{},\"after_tree\":{},",
        "\"entry_count\":{},\"entries\":["), quote(&value.requested_before.to_string()), quote(&value.requested_after.to_string()),
        quote(&value.before_tree.to_string()), quote(&value.after_tree.to_string()), value.entries.len()))?;
    for (index, row) in value.entries.iter().enumerate() {
        if index != 0 {
            out.put(",")?;
        }
        entry(out, row)?;
    }
    out.put("]}")
}

pub(in crate::smart_http::server::pulls::inspection) fn build(
    node: &OneNode,
    subject: &ReviewSubject,
    candidate: CandidateBinding,
    value: &RebaseBundleInspection,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    validate(node, subject, candidate, value, live)?;
    let mut out = Json {
        text: String::new(),
        maximum: maximum.min(MAX_REPLY_BYTES),
        live,
    };
    let head = value.source_head.as_internal_object_id();
    let digest: String = head
        .digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let token = format!("alg:{}:{digest}", head.algorithm().code_point());
    out.put(&format!(concat!("{{\"type\":\"pull_request_rebase_inspection\",\"schema_version\":1,\"profile\":\"verified-linear-series-v1\",",
        "\"scope\":\"all_paths_all_commits\",\"method\":\"rebase\",\"complete\":true,",
        "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,\"merge_authorized\":false,",
        "\"all_changed_paths\":true,\"all_rewritten_commits\":true,\"binary_bodies_included\":false,\"replay_equivalence_verified\":false,",
        "\"comparison_profile\":\"full-tree-direct-path-myers-v1\",\"context_lines\":3,",
        "\"subject\":{{\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},{},{},\"source_tip\":{},\"target_tip\":{}}},",
        "\"merge_base\":{},\"candidate_commit\":{},\"prerequisites\":[{}],\"bundle\":{{\"bytes\":{},\"pack_bytes\":{},\"pack_objects\":{},\"expanded_bytes\":{},",
        "\"closure_objects\":{},\"transport_only_objects\":{},\"sha256\":"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()), quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()),
        quote(&value.source_head.to_string()), quote(&token), subject.pull_request.get(), subject.pull_request_version.get(), subject.policy_epoch.get(),
        ref_fields("source_ref", &subject.source_ref), ref_fields("target_ref", &subject.target_ref), quote(&subject.source_tip.to_string()), quote(&subject.target_tip.to_string()),
        quote(&candidate.merge_base.to_string()), quote(&candidate.commit.to_string()), quote(&subject.target_tip.to_string()),
        value.bundle.bytes, value.bundle.pack_bytes, value.bundle.pack_objects, value.bundle.expanded_bytes, value.bundle.closure_objects, value.bundle.transport_only_objects))?;
    out.hex(&value.bundle.sha256)?;
    out.put(&format!(
        "}},\"commit_count\":{},\"source_comparison\":",
        value.commits.len()
    ))?;
    comparison(&mut out, &value.comparisons[0])?;
    out.put(",\"commits\":[")?;
    for (index, (commit, diff)) in value
        .commits
        .iter()
        .zip(&value.comparisons[1..])
        .enumerate()
    {
        if index != 0 {
            out.put(",")?;
        }
        out.put(&format!(
            "{{\"commit\":{},\"parent\":{},\"tree\":{},\"commit_hex\":",
            quote(&commit.id.to_string()),
            quote(&commit.parent.to_string()),
            quote(&commit.tree.to_string())
        ))?;
        out.hex(&commit.body)?;
        out.put(",\"comparison\":")?;
        comparison(&mut out, diff)?;
        out.put("}")?;
    }
    out.put("]}")?;
    out.checkpoint()?;
    Ok(out.text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn series_accounting_is_cumulative_and_comparisons_share_one_output_ceiling() {
        let mut used = 3;
        assert!(add(&mut used, 2, 4).is_err());
        let mut live = || true;
        let mut out = Json {
            text: String::new(),
            maximum: 8,
            live: &mut live,
        };
        out.hex(b"a").unwrap();
        assert!(out.hex(b"abc").is_err());
        assert_eq!(out.text, "\"61\"");
    }
}
