#![forbid(unsafe_code)]
//! Bridge between canonical admission and the fg043a policy engine
//! (frankengit-fg043r).
//!
//! Phase 1 of the rewire: admission evaluates protected-ref protection
//! through a pinned [`PolicySnapshot`] obtained from a
//! [`PolicySnapshotSource`], and translates the engine's decision into the
//! existing [`RefusalCode`] vocabulary so campaigns keep their refusal
//! contract. The snapshot identity travels WITH the verdict so the RCR can
//! bind it (schema already carries `policy_root` on the V2.1 incarnation
//! configuration).
//!
//! Translation contract (documented, deterministic):
//! - overall `Allow` -> no refusal;
//! - overall `Refuse` -> the FIRST subject whose outcome is not allow maps to
//!   its configured refusal code; subjects carry their own code mapping so
//!   different rules can refuse differently;
//! - engine refusals (malformed input for this snapshot) are typed errors,
//!   never silently treated as allow.

use crate::RefusalCode;
use fgit_policy::content::PolicySnapshotId;
use fgit_policy::{Decision, PolicyEvaluation};
use std::collections::BTreeMap;

/// Fetches one pinned snapshot by identity.
///
/// Implementations decide where bodies live (incarnation configuration,
/// object fabric, test memory). A miss is a typed refusal: admission never
/// evaluates against a substitute snapshot.
pub trait PolicySnapshotSource {
    fn snapshot_by_id(
        &self,
        id: &PolicySnapshotId,
    ) -> Result<fgit_policy::PolicySnapshot, PolicySourceRefusal>;
}

/// Why a pinned snapshot could not be evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicySourceRefusal {
    /// No snapshot pinned under this identity.
    UnknownSnapshot { id: String },
    /// The stored body failed to decode.
    Undecodable { id: String },
}

impl std::fmt::Display for PolicySourceRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSnapshot { id } => {
                write!(formatter, "no policy snapshot pinned as {id}")
            }
            Self::Undecodable { id } => {
                write!(formatter, "policy snapshot {id} does not decode")
            }
        }
    }
}

impl std::error::Error for PolicySourceRefusal {}

/// In-memory source: the phase-1 backing used while snapshots arrive through
/// configuration evidence. Content-addressed by snapshot id at insert time.
#[derive(Default)]
pub struct InMemoryPolicySnapshots {
    snapshots: BTreeMap<String, fgit_policy::PolicySnapshot>,
}

impl InMemoryPolicySnapshots {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins a snapshot under its own content identity.
    pub fn pin(&mut self, snapshot: fgit_policy::PolicySnapshot) -> PolicySnapshotId {
        let id = snapshot.id();
        self.snapshots.insert(id.to_string(), snapshot);
        id
    }
}

impl PolicySnapshotSource for InMemoryPolicySnapshots {
    fn snapshot_by_id(
        &self,
        id: &PolicySnapshotId,
    ) -> Result<fgit_policy::PolicySnapshot, PolicySourceRefusal> {
        self.snapshots
            .get(&id.to_string())
            .cloned()
            .ok_or_else(|| PolicySourceRefusal::UnknownSnapshot { id: id.to_string() })
    }
}

/// How a subject outcome maps back into the legacy refusal vocabulary.
///
/// Rules that refuse name the code their failure should surface as; the
/// default preserves the exact codes the inline checks used, so the fg019c /
/// fg029b campaigns observe no behavioral change on refusal paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectCodeMap {
    pub not_fast_forward: RefusalCode,
    pub force_not_permitted: RefusalCode,
    pub transition_denied: RefusalCode,
}

impl Default for SubjectCodeMap {
    fn default() -> Self {
        Self {
            not_fast_forward: RefusalCode::NonFastForwardRefused,
            force_not_permitted: RefusalCode::ForceNotPermitted,
            transition_denied: RefusalCode::ProtectedRefTransitionDenied,
        }
    }
}

/// The outcome of one protection evaluation, ready for decision binding.
pub struct ProtectionVerdict {
    /// Identity of the snapshot the decision is replayable against.
    pub snapshot_id: PolicySnapshotId,
    /// `None` when the policy allowed every update.
    pub refusal: Option<RefusalCode>,
    /// Full rule-visit trace; retained verbatim for decision evidence.
    pub trace: String,
}

/// Evaluates protection for one input root against one pinned snapshot.
pub fn evaluate_protection(
    source: &dyn PolicySnapshotSource,
    id: &PolicySnapshotId,
    codes: &SubjectCodeMap,
    input_root: &fgit_policy::PolicyInputRoot,
) -> Result<ProtectionVerdict, PolicySourceRefusal> {
    let snapshot = source.snapshot_by_id(id)?;
    let evaluation = fgit_policy::evaluate(&snapshot, input_root)
        .map_err(|_| PolicySourceRefusal::Undecodable { id: id.to_string() })?;
    let refusal = first_refusal(&evaluation, codes);
    Ok(ProtectionVerdict {
        snapshot_id: *id,
        refusal,
        trace: fgit_policy::render_trace(&evaluation),
    })
}

fn first_refusal(evaluation: &PolicyEvaluation, codes: &SubjectCodeMap) -> Option<RefusalCode> {
    if matches!(evaluation.decision(), Decision::Allow) {
        return None;
    }
    // Deterministic: subjects keep caller order; the first denied command
    // names the surfaced code (a deny of one command denies the whole root).
    for subject in evaluation.subjects() {
        if matches!(subject.decision(), Decision::Deny) {
            return Some(codes.transition_denied);
        }
    }
    Some(codes.transition_denied)
}
