//! Native commit ancestry for file-backed mapped fetch. A selected object's
//! presence in a closure is not a proof that it is a commit ancestor.

use std::collections::BTreeSet;

use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, parse_commit};
use fgit_types::{GitOid, RefusalCode};
use fgit_wire::receive::ReceiveError;

use super::{
    BundleVerifyLimits, FullBundleImportPlan, StreamBundleImportRefusal, checkpoint, receive_error,
};

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
pub(super) fn require_fast_forwards(
    commands: &[RefCommand],
    plan: &mut FullBundleImportPlan,
    limits: &BundleVerifyLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), StreamBundleImportRefusal> {
    let mut work = limits
        .graph
        .max_edges
        .min(limits.pack.max_total_expanded_bytes)
        .min(4_000_000);
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
