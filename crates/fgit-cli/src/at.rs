//! Position selection and native read adapters over one authenticated head.
//! Native Git identities stay native; the historical Digest compatibility view
//! is never used to manufacture a PR or a workflow observation.

use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::merge::native::pull_request::PullRequestView;
use fgit_authority::AuthenticatedHead;
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_forge::PullRequestNumber;
use fgit_forge::event::ForgeEventPayload;
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::snapshot::{
    ForgeSnapshot, ForgeSnapshotDiff, HistoricalBatch, PositionTarget, SnapshotDisclosurePolicy,
    SnapshotLimits, SnapshotRefusal, project_snapshot_from_history,
};
use fgit_node::{NodeRequestContext, OneNode, PullRequestChecksPage};
use fgit_types::{GitOid, RepositoryAuthorityHeadId};

use crate::{AtReport, CliOutcome, CliRefusal, encode_derived_id};

// Per-page node bounds also remain in force. These caps bound each complete
// native walk and its repeated page work. A diff owns two bounded walks; no
// partial page set is ever returned.
const MAX_ROWS: usize = 65_536;
const MAX_ROW_BYTES: usize = 32 * 1024 * 1024;
const PAGE_ROWS: u16 = 100;

type NativePrs = BTreeMap<PullRequestNumber, PullRequestView>;

fn inconsistent(detail: impl Into<String>) -> CliRefusal {
    CliRefusal::Snapshot(SnapshotRefusal::ConsistencyMismatch {
        detail: detail.into(),
    })
}
fn live(request: &NodeRequestContext) -> Result<(), CliRefusal> {
    if request.is_live() {
        Ok(())
    } else {
        Err(inconsistent(
            "snapshot request is no longer live: cancellation or resource/deadline exhaustion",
        ))
    }
}
fn charge(total: &mut usize, amount: usize, limit: usize) -> Result<(), CliRefusal> {
    let attempted = total
        .checked_add(amount)
        .ok_or_else(|| inconsistent("snapshot size overflow"))?;
    if attempted > limit {
        return Err(inconsistent(format!(
            "complete snapshot answer exceeds resource bound {limit}"
        )));
    }
    *total = attempted;
    Ok(())
}

pub(super) async fn ensure_current(
    node: &OneNode,
    request: &NodeRequestContext,
    initial: &AuthenticatedHead,
) -> Result<(), CliRefusal> {
    let current = node
        .authenticate_authority_head_in(request)
        .await
        .map_err(CliRefusal::Node)?;
    if current.receipt() != initial.receipt() {
        return Err(inconsistent(
            "authority head moved during snapshot inspection; retry the whole query",
        ));
    }
    live(request)
}

/// Canonical RCR inventories are not aggregate causal order. Within each
/// authenticated decision batch, independent streams commute; each stream's
/// versions must be applied in ascending order. Conflicting same-version data
/// is evidence failure, never last-writer-wins.
fn order_history(
    history: &mut [HistoricalBatch],
    request: &NodeRequestContext,
) -> Result<(), CliRefusal> {
    for batch in history {
        live(request)?;
        batch
            .forge_events
            .sort_by_key(|event| (event.aggregate, event.version));
        for pair in batch.forge_events.windows(2) {
            live(request)?;
            if pair[0].aggregate == pair[1].aggregate
                && pair[0].version == pair[1].version
                && pair[0] != pair[1]
            {
                return Err(inconsistent(
                    "conflicting canonical events at one aggregate version",
                ));
            }
        }
        batch.forge_events.dedup();
    }
    Ok(())
}

fn project(
    target: PositionTarget,
    head_id: RepositoryAuthorityHeadId,
    head: &RepositoryAuthorityHeadBody,
    history: &[HistoricalBatch],
    live_refs: &BTreeMap<Vec<u8>, GitOid>,
) -> Result<ForgeSnapshot, CliRefusal> {
    let mut result = project_snapshot_from_history(
        target,
        head_id,
        head,
        &[],
        history,
        &BTreeMap::new(),
        &SnapshotLimits::default(),
    )
    .map_err(CliRefusal::Snapshot)?;
    let current = match target {
        PositionTarget::Latest => true,
        PositionTarget::Decision(sequence) => Some(sequence) == head.latest_decision_sequence,
        PositionTarget::Head(id) => id == head_id,
        _ => false,
    };
    if current {
        if result.effective_decision_sequence != head.latest_decision_sequence
            || result.ref_root != head.ref_root
            || result.forge_position_root != head.forge_position_root
            || result.historical_policy_epoch != head.policy_epoch
            || result.effective_committed_rcr_id != head.latest_committed_rcr_id
        {
            return Err(inconsistent(
                "complete history does not reach the authenticated current state",
            ));
        }
        // A checkpoint activation advances head identity/generation without
        // inventing a decision batch. Current refs come from the independently
        // authenticated same-head materialization, including nonempty genesis.
        result.effective_head_id = head_id;
        result.effective_head_generation = head.generation;
        result.refs = live_refs.clone();
    }
    Ok(result)
}

async fn native_prs(
    node: &OneNode,
    request: &NodeRequestContext,
    head: RepositoryAuthorityHeadId,
    allowed_refs: Option<&BTreeMap<Vec<u8>, GitOid>>,
) -> Result<NativePrs, CliRefusal> {
    let mut rows = BTreeMap::new();
    let mut after = 0;
    let mut count = 0;
    let mut bytes = 0;
    loop {
        live(request)?;
        let page = node
            .read_pull_requests_in(request, &Default::default(), after, PAGE_ROWS, Some(head))
            .await
            .map_err(|error| inconsistent(error.to_string()))?;
        if page.source_head != head {
            return Err(inconsistent("native PR page changed its selected head"));
        }
        charge(&mut count, page.pull_requests.len(), MAX_ROWS)?;
        let mut previous = after;
        for row in page.pull_requests {
            live(request)?;
            if row.number.get() <= previous {
                return Err(inconsistent("native PR page is not strictly ordered"));
            }
            previous = row.number.get();
            let encoded =
                fgit_codec::encode_body(&row.event).map_err(|e| CliRefusal::Snapshot(e.into()))?;
            charge(&mut bytes, encoded.len(), MAX_ROW_BYTES)?;
            if let Some(data) = &row.data {
                charge(&mut bytes, data.title.len(), MAX_ROW_BYTES)?;
                charge(&mut bytes, data.body.len(), MAX_ROW_BYTES)?;
            }
            let (source, target) = match &row.event.payload {
                ForgeEventPayload::PullRequestChangedNative(change) => {
                    (&change.data.source_ref, &change.data.target_ref)
                }
                ForgeEventPayload::MergeCommittedNative(merge) => {
                    (&merge.source_ref, &merge.target_ref)
                }
                _ => return Err(inconsistent("native PR reader returned a legacy event")),
            };
            if allowed_refs.is_none_or(|refs| {
                refs.contains_key(source.as_bytes()) && refs.contains_key(target.as_bytes())
            }) {
                rows.insert(row.number, row);
            }
        }
        let Some(next) = page.next_after else {
            return Ok(rows);
        };
        if next != previous || next <= after || count == MAX_ROWS {
            return Err(inconsistent(
                "native PR continuation is invalid or exceeds the complete answer bound",
            ));
        }
        after = next;
    }
}

async fn checks(
    node: &OneNode,
    request: &NodeRequestContext,
    head: RepositoryAuthorityHeadId,
    number: PullRequestNumber,
    allowed_refs: Option<&BTreeMap<Vec<u8>, GitOid>>,
) -> Result<Option<PullRequestChecksPage>, CliRefusal> {
    let mut after = None;
    let mut answer: Option<PullRequestChecksPage> = None;
    let mut count = 0;
    let mut bytes = 0;
    loop {
        live(request)?;
        let page = node
            .read_pull_request_checks_in(
                request,
                &Default::default(),
                number,
                after,
                PAGE_ROWS,
                Some(head),
            )
            .await
            .map_err(|error| inconsistent(error.to_string()))?;
        let Some(mut page) = page else {
            return if answer.is_none() {
                Ok(None)
            } else {
                Err(inconsistent(
                    "native PR disappeared within a pinned check walk",
                ))
            };
        };
        page.validate_window(number, after, PAGE_ROWS, Some(head))
            .map_err(|error| inconsistent(format!("invalid native check page: {error:?}")))?;
        if allowed_refs.is_some_and(|refs| {
            !refs.contains_key(page.source_ref.as_bytes())
                || !refs.contains_key(page.target_ref.as_bytes())
        }) {
            return Ok(None);
        }
        charge(&mut count, page.checks.len(), MAX_ROWS)?;
        for row in &page.checks {
            live(request)?;
            charge(
                &mut bytes,
                row.job.len() + std::mem::size_of_val(row),
                MAX_ROW_BYTES,
            )?;
        }
        let next = page.next_after;
        if let Some(current) = &mut answer {
            if current.source_head != page.source_head
                || current.number != page.number
                || current.pull_request_version != page.pull_request_version
                || current.source_ref != page.source_ref
                || current.target_ref != page.target_ref
                || current.source_tip != page.source_tip
                || current.target_tip != page.target_tip
                || current.source_current != page.source_current
            {
                return Err(inconsistent(
                    "native check pages changed their selected PR/source coordinates",
                ));
            }
            current.checks.append(&mut page.checks);
            current.next_after = next;
        } else {
            answer = Some(page);
        }
        let Some(next) = next else {
            return Ok(answer);
        };
        if after.is_some_and(|old| next <= old) || count == MAX_ROWS {
            return Err(inconsistent(
                "native check continuation is invalid or exceeds the complete answer bound",
            ));
        }
        after = Some(next);
    }
}

fn all_prs(snapshot: &ForgeSnapshot, native: &NativePrs) -> BTreeSet<PullRequestNumber> {
    snapshot
        .pull_requests
        .keys()
        .chain(native.keys())
        .copied()
        .collect()
}
fn changed_prs(
    older: &ForgeSnapshot,
    old_native: &NativePrs,
    newer: &ForgeSnapshot,
    new_native: &NativePrs,
) -> usize {
    let mut numbers = all_prs(older, old_native);
    numbers.extend(all_prs(newer, new_native));
    numbers
        .into_iter()
        .filter(
            |number| match (old_native.get(number), new_native.get(number)) {
                (Some(left), Some(right)) => left != right,
                (None, None) => older.pull_requests.get(number) != newer.pull_requests.get(number),
                _ => true,
            },
        )
        .count()
}
fn pr_rows(
    snapshot: &ForgeSnapshot,
    native: &NativePrs,
) -> Result<Vec<(u64, String, String, String)>, CliRefusal> {
    all_prs(snapshot, native)
        .into_iter()
        .map(|number| {
            if let Some(row) = native.get(&number) {
                let (state, source, target) = match &row.event.payload {
                    ForgeEventPayload::PullRequestChangedNative(change) => (
                        if change.action == PullRequestAction::Close {
                            "closed".to_owned()
                        } else {
                            "open".to_owned()
                        },
                        &change.data.source_ref,
                        &change.data.target_ref,
                    ),
                    ForgeEventPayload::MergeCommittedNative(merge) => (
                        format!("merged (commit: {})", merge.merge_commit),
                        &merge.source_ref,
                        &merge.target_ref,
                    ),
                    _ => return Err(inconsistent("native PR row lost its typed coordinates")),
                };
                let title = row.data.as_ref().map_or_else(
                    || String::from_utf8_lossy(source.as_bytes()).into_owned(),
                    |data| data.title.clone(),
                );
                Ok((
                    number.get(),
                    title,
                    state,
                    String::from_utf8_lossy(target.as_bytes()).into_owned(),
                ))
            } else {
                let row = &snapshot.pull_requests[&number];
                Ok((
                    number.get(),
                    String::from_utf8_lossy(&row.source_ref).into_owned(),
                    row.state.to_string(),
                    String::from_utf8_lossy(&row.target_ref).into_owned(),
                ))
            }
        })
        .collect()
}

pub(super) async fn read_in(
    node: &OneNode,
    request: &NodeRequestContext,
    initial: &AuthenticatedHead,
    target: PositionTarget,
    diff_target: Option<PositionTarget>,
    subcommand: Option<&str>,
    check_pr: Option<PullRequestNumber>,
    restrict_to_current_refs: bool,
) -> Result<CliOutcome, CliRefusal> {
    let admission = node
        .materialize_admission_in(request)
        .await
        .map_err(|error| {
            CliRefusal::Node(fgit_node::NodeRefusal::AdmissionMaterialization(Box::new(
                error,
            )))
        })?;
    if admission.authenticated().receipt() != initial.receipt() {
        return Err(inconsistent(
            "authority head moved before snapshot materialization; retry the whole query",
        ));
    }
    let head = admission.basis().body();
    let head_id = admission.basis().id();
    let live_refs: BTreeMap<_, _> = admission
        .snapshot()
        .refs
        .iter()
        .map(|(name, id)| (name.as_bytes().to_vec(), *id))
        .collect();
    let mut history = node.snapshot_history_in(request).await.map_err(|error| {
        CliRefusal::Node(fgit_node::NodeRefusal::AdmissionMaterialization(Box::new(
            error,
        )))
    })?;
    order_history(&mut history, request)?;
    ensure_current(node, request, initial).await?;
    let policy = if restrict_to_current_refs {
        SnapshotDisclosurePolicy::Restricted {
            allowed_refs: Some(live_refs.keys().cloned().collect()),
            revoked_refs: BTreeSet::new(),
            allowed_prs: None,
            revoked_prs: BTreeSet::new(),
            repository_access_revoked: false,
        }
    } else {
        SnapshotDisclosurePolicy::PermitAll
    };
    let snapshot = policy
        .filter_snapshot(project(target, head_id, head, &history, &live_refs)?)
        .map_err(CliRefusal::Snapshot)?;
    let allowed = restrict_to_current_refs.then_some(&live_refs);
    let native = if matches!(subcommand, None | Some("prs") | Some("diff")) {
        native_prs(node, request, snapshot.effective_head_id, allowed).await?
    } else {
        BTreeMap::new()
    };
    let report = match subcommand {
        None => AtReport::Summary {
            snapshot_summary: format!(
                "{}\n  Native Pull Requests: {}",
                snapshot.summary(),
                native.len()
            ),
            target: target.to_string(),
            head_id: encode_derived_id(snapshot.effective_head_id.as_internal_object_id()),
            decision_sequence: snapshot
                .effective_decision_sequence
                .map(|sequence| sequence.get()),
            refs_count: snapshot.refs.len(),
            prs_count: all_prs(&snapshot, &native).len(),
        },
        Some("refs") => AtReport::Refs {
            position: target.to_string(),
            refs: snapshot
                .refs
                .iter()
                .map(|(name, id)| (String::from_utf8_lossy(name).into_owned(), id.to_string()))
                .collect(),
        },
        Some("prs") => AtReport::PullRequests {
            position: target.to_string(),
            pull_requests: pr_rows(&snapshot, &native)?,
        },
        Some("checks") => {
            let number = check_pr.ok_or(CliRefusal::Usage)?;
            AtReport::Checks {
                position: target.to_string(),
                pull_request: number.get(),
                page: checks(node, request, snapshot.effective_head_id, number, allowed).await?,
            }
        }
        Some("diff") => {
            let other = diff_target.ok_or(CliRefusal::Usage)?;
            let newer = policy
                .filter_snapshot(project(other, head_id, head, &history, &live_refs)?)
                .map_err(CliRefusal::Snapshot)?;
            let newer_native = native_prs(node, request, newer.effective_head_id, allowed).await?;
            let diff = ForgeSnapshotDiff::diff(&snapshot, &newer);
            AtReport::Diff {
                older: target.to_string(),
                newer: other.to_string(),
                ref_changes_count: diff.ref_changes.len(),
                pr_changes_count: changed_prs(&snapshot, &native, &newer, &newer_native),
            }
        }
        _ => return Err(CliRefusal::Usage),
    };
    // No observable answer exists until every page and this exact-head fence
    // have completed. run_at subsequently drains/closes the node on all paths.
    ensure_current(node, request, initial).await?;
    Ok(CliOutcome::At(report))
}

#[cfg(test)]
mod tests;
