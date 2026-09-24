//! A complete bounded inspection response. Per-comparison content uses the
//! existing source-diff JSON renderer, not another hunk/span implementation.

use super::super::super::review::inspected;
use super::{ApiError, Command, Status};
use crate::OneNode;
use crate::smart_http::server::issues::quote;
use crate::treefs_workspace::candidate_inspection::RebaseBundleInspection;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::review::{ComparisonMode, ReviewContent, SourceComparison, SourceReview};
use fgit_types::{GitOid, RefName, RepositoryAuthorityHeadId};
use std::collections::BTreeSet;

const MAX_RESPONSE: usize = 8 * 1024 * 1024;
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
struct Output {
    body: String,
    maximum: usize,
}
impl Output {
    fn new(maximum: usize) -> Self {
        Self {
            body: String::new(),
            maximum: maximum.min(MAX_RESPONSE),
        }
    }
    const fn remaining(&self) -> usize {
        self.maximum.saturating_sub(self.body.len())
    }
    fn reserve(&mut self, count: usize) -> Result<(), ApiError> {
        if count > self.remaining() {
            return Err(ApiError::too_large());
        }
        self.body
            .try_reserve(count)
            .map_err(|_| ApiError::unavailable())
    }
    fn append(&mut self, value: &str) -> Result<(), ApiError> {
        self.reserve(value.len())?;
        self.body.push_str(value);
        Ok(())
    }
    fn hex(&mut self, bytes: &[u8], live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
        checkpoint(live)?;
        self.reserve(
            bytes
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(2))
                .ok_or_else(ApiError::too_large)?,
        )?;
        self.body.push('"');
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for chunk in bytes.chunks(4096) {
            checkpoint(live)?;
            for byte in chunk {
                self.body.push(char::from(HEX[usize::from(*byte >> 4)]));
                self.body.push(char::from(HEX[usize::from(*byte & 15)]));
            }
        }
        self.body.push('"');
        Ok(())
    }
}
fn add(value: &mut usize, amount: usize, maximum: usize) -> Result<(), ApiError> {
    *value = value
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or_else(ApiError::too_large)?;
    Ok(())
}
fn coordinates(comparison: &SourceComparison, before: GitOid, after: GitOid) -> bool {
    comparison.mode == ComparisonMode::Direct
        && comparison.requested_before == before
        && comparison.compared_before == before
        && comparison.requested_after == after
}
fn validate(
    node: &OneNode,
    command: &Command,
    report: &RebaseBundleInspection,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    checkpoint(live)?;
    if report.repository_id != node.repository_id
        || report.source_reference != command.source
        || report.onto_reference != command.onto_ref
        || report.expected_source != command.expected_source
        || report.onto != command.onto
        || report.candidate != command.candidate
        || command
            .expected_head
            .is_some_and(|head| head != report.source_head)
        || report.commits.len() > 256
        || report.comparisons.len() != report.commits.len() + 1
        || report.bundle.transport_only_objects > report.bundle.pack_objects
        || report.bundle.pack_bytes > report.bundle.bytes
        || !coordinates(
            &report.comparisons[0],
            report.expected_source,
            report.candidate,
        )
    {
        return Err(ApiError::unavailable());
    }
    let mut parent = report.onto;
    let mut previous_tree = None;
    let mut seen = BTreeSet::new();
    let mut bodies = 0;
    for (commit, comparison) in report.commits.iter().zip(&report.comparisons[1..]) {
        checkpoint(live)?;
        add(&mut bodies, commit.body.len(), 16 * 1024 * 1024)?;
        if commit.parent != parent
            || !seen.insert(commit.id)
            || commit.id == report.onto
            || commit.body.len() > 2 * 1024 * 1024
            || git_object_id(node.object_format, GitObjectKind::Commit, &commit.body) != commit.id
            || !coordinates(comparison, parent, commit.id)
            || comparison.after_tree != commit.tree
            || previous_tree.is_some_and(|tree| tree != comparison.before_tree)
        {
            return Err(ApiError::unavailable());
        }
        parent = commit.id;
        previous_tree = Some(commit.tree);
    }
    if parent != report.candidate
        || previous_tree.is_some_and(|tree| tree != report.comparisons[0].after_tree)
    {
        return Err(ApiError::unavailable());
    }
    // The native reader enforces these across every comparison. Recheck the
    // retained result before expansion so response construction cannot reset them.
    let (mut changes, mut files, mut hunks, mut bytes) = (0, 0, 0, 0);
    let limits = command.options.limits;
    for comparison in &report.comparisons {
        checkpoint(live)?;
        add(&mut changes, comparison.entries.len(), limits.max_changes)?;
        for entry in &comparison.entries {
            add(&mut bytes, entry.path.len(), limits.max_output_bytes)?;
            if let ReviewContent::Text { hunks: spans, .. } = &entry.content {
                add(&mut files, 1, limits.max_text_files)?;
                add(&mut hunks, spans.len(), limits.max_hunks)?;
                for span in spans {
                    checkpoint(live)?;
                    add(&mut bytes, span.before.len(), limits.max_output_bytes)?;
                    add(&mut bytes, span.after.len(), limits.max_output_bytes)?;
                }
            }
        }
    }
    checkpoint(live)
}
fn comparison(
    out: &mut Output,
    node: &OneNode,
    reference: &RefName,
    head: RepositoryAuthorityHeadId,
    value: SourceComparison,
    command: &Command,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    let report = SourceReview {
        repository_id: node.repository_id,
        source_head: head,
        before_reference: reference.clone(),
        after_reference: reference.clone(),
        pull_request: None,
        comparison: value,
    };
    // Temporary JSON is bounded by the REMAINING aggregate response allowance.
    // Native hunk buffers are moved here rather than cloning the entire series.
    let value = inspected::render(node, &report, &command.options, out.remaining(), live)?;
    out.append(&value)
}

pub(super) fn render(
    node: &OneNode,
    command: &Command,
    report: RebaseBundleInspection,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    validate(node, command, &report, live)?;
    let RebaseBundleInspection {
        source_head,
        source_reference,
        onto_reference,
        expected_source,
        onto,
        candidate,
        commits,
        comparisons,
        bundle,
        ..
    } = report;
    let id = source_head.as_internal_object_id();
    let digest: String = id
        .digest()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let token = format!("alg:{}:{digest}", id.algorithm().code_point());
    let mut out = Output::new(maximum);
    out.append(&format!(concat!("{{\"type\":\"rebase_inspection\",\"schema_version\":1,\"profile\":\"linear-v1\",",
        "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"expected_source\":{},\"onto\":{},\"candidate_commit\":{},",
        "\"read_only\":true,\"objects_staged\":false,\"transaction_created\":false,\"published\":false,",
        "\"approval_created\":false,\"publication_authorized\":false,\"replay_equivalence_verified\":false,",
        "\"complete\":true,\"all_changed_paths\":true,\"all_rewritten_commits\":true,",
        "\"binary_bodies_included\":false,\"source_ref_hex\":"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()),
        quote(&source_head.to_string()), quote(&token), quote(&expected_source.to_string()),
        quote(&onto.to_string()), quote(&candidate.to_string())))?;
    out.hex(source_reference.as_bytes(), live)?;
    out.append(",\"onto_ref_hex\":")?;
    out.hex(onto_reference.as_bytes(), live)?;
    out.append(&format!(
        concat!(
            ",\"bundle\":{{\"bytes\":{},\"pack_bytes\":{},\"pack_objects\":{},",
            "\"expanded_bytes\":{},\"closure_objects\":{},\"transport_only_objects\":{},\"sha256\":"
        ),
        bundle.bytes,
        bundle.pack_bytes,
        bundle.pack_objects,
        bundle.expanded_bytes,
        bundle.closure_objects,
        bundle.transport_only_objects
    ))?;
    out.hex(&bundle.sha256, live)?;
    out.append(&format!(
        "}},\"commit_count\":{},\"net_change\":",
        commits.len()
    ))?;
    let mut comparisons = comparisons.into_iter();
    comparison(
        &mut out,
        node,
        &source_reference,
        source_head,
        comparisons.next().ok_or_else(ApiError::unavailable)?,
        command,
        live,
    )?;
    out.append(",\"commits\":[")?;
    for (index, (commit, diff)) in commits.into_iter().zip(comparisons).enumerate() {
        checkpoint(live)?;
        if index != 0 {
            out.append(",")?;
        }
        out.append(&format!(
            "{{\"index\":{index},\"commit\":{},\"parent\":{},\"tree\":{},\"body_hex\":",
            quote(&commit.id.to_string()),
            quote(&commit.parent.to_string()),
            quote(&commit.tree.to_string())
        ))?;
        out.hex(&commit.body, live)?;
        out.append(",\"diff\":")?;
        comparison(
            &mut out,
            node,
            &source_reference,
            source_head,
            diff,
            command,
            live,
        )?;
        out.append("}")?;
    }
    out.append("]}")?;
    checkpoint(live)?;
    Ok(out.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_output_checks_expansion_before_allocation_and_keeps_exact_bytes() {
        let mut out = Output::new(12);
        out.hex(b"\0\xff\r\n\x1b", &mut || true).unwrap();
        assert_eq!(out.body, "\"00ff0d0a1b\"");
        assert_eq!(out.remaining(), 0);
        let previous = out.body.clone();
        assert!(out.hex(b"x", &mut || true).is_err());
        assert_eq!(out.body, previous);
        assert!(Output::new(10).hex(b"bytes", &mut || false).is_err());
        assert_eq!(Output::new(usize::MAX).maximum, MAX_RESPONSE);
        let mut charged = 2;
        assert!(add(&mut charged, 2, 3).is_err());
    }
}
