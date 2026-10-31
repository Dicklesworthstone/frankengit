//! Native commit ancestry for file-backed mapped fetch. A selected object's
//! presence in a closure is not a proof that it is a commit ancestor.

use std::collections::BTreeSet;

use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, parse_commit};
use fgit_pack::full_bundle::fetch::BundleRefMapping;
use fgit_pack::full_bundle::{FullBundleHeader, FullBundleLimits};
use fgit_types::{GitOid, RefusalCode};
use fgit_wire::receive::ReceiveError;

use super::{
    AdmissionLimits, BundleImportObjectPlan, BundleVerifyError, BundleVerifyLimits,
    StreamBundleImportRefusal, checkpoint, receive_error,
};

/// One semantic mapping path for full and incremental intake. Header capacity
/// is independent of destination command capacity, including source fanout.
pub(super) fn commands(
    header: &FullBundleHeader,
    mappings: &[BundleRefMapping],
    query: &BundleVerifyLimits,
    limits: &AdmissionLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<RefCommand>, StreamBundleImportRefusal> {
    if mappings.is_empty() || mappings.len() > limits.command_limit(true) {
        return Err(StreamBundleImportRefusal::InvalidQuery(
            "reference command count",
        ));
    }
    let mapping_limits = FullBundleLimits {
        max_references: limits
            .command_limit(true)
            .min(fgit_wire::receive::ReceiveLimits::default().max_commands),
        ..query.envelope
    };
    Ok(header
        .select_updates(mappings, mapping_limits, live)
        .map_err(BundleVerifyError::Envelope)?
        .into_iter()
        .map(|update| RefCommand {
            name: update.destination,
            expected_old: update
                .expected_old
                .map_or(ExpectedOld::Absent, ExpectedOld::Exactly),
            proposed_new: ProposedNew::Update(update.target),
            force: false,
        })
        .collect())
}

fn refuse(code: RefusalCode) -> StreamBundleImportRefusal {
    receive_error(ReceiveError::AuthoritativeRefusal(code)).into()
}

fn charge(work: &mut usize) -> Result<(), StreamBundleImportRefusal> {
    *work = work
        .checked_sub(1)
        .ok_or_else(|| refuse(RefusalCode::ResourceBudgetExceeded))?;
    Ok(())
}

/// Only authenticated metadata spans are read. The work allowance is shared by
/// every destination and every commit/parent edge, matching buffered fetch's
/// finite additional ancestry walk. Blob bodies are never allocated here.
/// Captured original bytes enlarge only that work ceiling for incremental
/// history; no original source read or uploaded expansion budget is reset.
pub(super) fn require_fast_forwards<P: BundleImportObjectPlan>(
    commands: &[RefCommand],
    plan: &mut P,
    limits: &BundleVerifyLimits,
    original_bytes: u64,
    live: &mut impl FnMut() -> bool,
) -> Result<(), StreamBundleImportRefusal> {
    let work_bytes = limits
        .pack
        .max_total_expanded_bytes
        .saturating_add(usize::try_from(original_bytes).unwrap_or(usize::MAX));
    let mut work = limits.graph.max_edges.min(work_bytes).min(4_000_000);
    for command in commands {
        checkpoint(live)?;
        let name = command.name.as_bytes();
        let is_tag = name.starts_with(b"refs/tags/");
        let is_branch = name.starts_with(b"refs/heads/") || name.starts_with(b"refs/remotes/");
        if !is_tag && !is_branch {
            return Err(refuse(RefusalCode::RefNameInvalid));
        }
        let ProposedNew::Update(target) = command.proposed_new else {
            return Err(refuse(RefusalCode::EvidenceInvalid));
        };
        if is_branch {
            let object = plan
                .object(target)
                .ok_or_else(|| refuse(RefusalCode::ObjectClosureIncomplete))?;
            // Check the root kind even for an absent or already-equal lease.
            if object.kind != ObjectType::Commit {
                return Err(refuse(RefusalCode::EvidenceInvalid));
            }
        }
        let old = match command.expected_old {
            ExpectedOld::Absent => continue,
            ExpectedOld::Exactly(old) if old == target => continue,
            ExpectedOld::Exactly(old) => old,
            ExpectedOld::Unspecified => return Err(refuse(RefusalCode::EvidenceInvalid)),
        };
        if is_tag {
            return Err(refuse(RefusalCode::NonFastForwardRefused));
        }
        let parse_limits = ParseLimits {
            max_object_bytes: limits.graph.max_object_bytes,
            tree_reference_bytes: target.algorithm().digest_len(),
            ..ParseLimits::default()
        };
        let mut pending = BTreeSet::from([target]);
        let mut seen = BTreeSet::new();
        let mut found = false;
        while let Some(id) = pending.pop_first() {
            checkpoint(live)?;
            charge(&mut work)?;
            if !seen.insert(id) {
                continue;
            }
            let object = plan
                .object(id)
                .ok_or_else(|| refuse(RefusalCode::ObjectClosureIncomplete))?;
            if object.kind != ObjectType::Commit {
                return Err(refuse(RefusalCode::EvidenceInvalid));
            }
            if id == old {
                found = true;
                break;
            }
            let bytes = plan.read_metadata(id, live)?;
            let commit = parse_commit(
                &bytes,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits,
            )
            .map_err(|_| refuse(RefusalCode::ObjectHeaderInvalid))?;
            for parent in commit.parent_references() {
                checkpoint(live)?;
                charge(&mut work)?;
                let parent = std::str::from_utf8(parent)
                    .ok()
                    .and_then(|text| {
                        GitOid::from_hex(target.algorithm(), &text.to_ascii_lowercase()).ok()
                    })
                    .ok_or_else(|| refuse(RefusalCode::ObjectHeaderInvalid))?;
                if !seen.contains(&parent) {
                    pending.insert(parent);
                }
            }
        }
        if !found {
            return Err(refuse(RefusalCode::NonFastForwardRefused));
        }
    }
    checkpoint(live)
}
