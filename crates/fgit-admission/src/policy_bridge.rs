#![forbid(unsafe_code)]
//! Bridge between canonical admission and the fg043a policy engine
//! (frankengit-fg043r).
//!
//! Phase 1 of the rewire: admission evaluates protected-ref protection
//! through a pinned [`PolicySnapshot`] obtained from a
//! [`PolicySnapshotSource`], and translates the engine's decision into the
//! existing [`RefusalCode`] vocabulary so campaigns keep their refusal
//! contract. The snapshot identity travels WITH the verdict so the RCR can
//! bind it. The incarnation configuration's existing `policy_root` names
//! hidden-ref policy, not a compiled `PolicySnapshotId`. Policy selection must
//! retain these distinct domains rather than treating one root as the other.
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
    /// A valid snapshot was returned under the wrong requested identity.
    IdentityMismatch { requested: PolicySnapshotId, observed: PolicySnapshotId },
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
            Self::IdentityMismatch { requested, observed } => write!(
                formatter, "policy snapshot mismatch: requested {requested}, received {observed}",
            ),
        }
    }
}

impl std::error::Error for PolicySourceRefusal {}

/// In-process source, not durable storage or policy activation. Content-addressed
/// by snapshot id at insert time; the caller owns authenticated policy selection.
#[derive(Default)]
pub struct InMemoryPolicySnapshots {
    snapshots: BTreeMap<String, fgit_policy::PolicySnapshot>,
}

impl InMemoryPolicySnapshots {
    #[must_use]
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
    let snapshot = checked_snapshot(source, id)?;
    evaluate_snapshot(&snapshot, codes, input_root)
}

fn checked_snapshot(source: &dyn PolicySnapshotSource, id: &PolicySnapshotId)
    -> Result<fgit_policy::PolicySnapshot, PolicySourceRefusal>
{
    let snapshot = source.snapshot_by_id(id)?;
    if snapshot.id() != *id {
        return Err(PolicySourceRefusal::IdentityMismatch {
            requested: *id, observed: snapshot.id(),
        });
    }
    Ok(snapshot)
}

fn evaluate_snapshot(
    snapshot: &fgit_policy::PolicySnapshot,
    codes: &SubjectCodeMap,
    input_root: &fgit_policy::PolicyInputRoot,
) -> Result<ProtectionVerdict, PolicySourceRefusal> {
    let id = snapshot.id();
    let evaluation = fgit_policy::evaluate(snapshot, input_root)
        .map_err(|_| PolicySourceRefusal::Undecodable { id: id.to_string() })?;
    let refusal = first_refusal(&evaluation, codes);
    Ok(ProtectionVerdict {
        snapshot_id: id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct SubstitutingSource {
        replacement: fgit_policy::PolicySnapshot,
        reads: Cell<usize>,
    }
    impl PolicySnapshotSource for SubstitutingSource {
        fn snapshot_by_id(&self, _: &PolicySnapshotId)
            -> Result<fgit_policy::PolicySnapshot, PolicySourceRefusal>
        {
            self.reads.set(self.reads.get() + 1);
            Ok(self.replacement.clone())
        }
    }

    #[test]
    fn a_valid_allow_policy_cannot_be_substituted_for_the_requested_deny_policy() {
        let deny = fgit_policy::compile_and_seal("policy pinned { default deny \"review required\" }").unwrap();
        let allow = fgit_policy::compile_and_seal("policy pinned { default allow }").unwrap();
        assert_ne!(deny.id(), allow.id());
        let source = SubstitutingSource { replacement: allow.clone(), reads: Cell::new(0) };
        assert_eq!(checked_snapshot(&source, &deny.id()).unwrap_err(),
            PolicySourceRefusal::IdentityMismatch { requested: deny.id(), observed: allow.id() });
        assert_eq!(source.reads.get(), 1, "no fallback lookup after substitution");
        assert_eq!(checked_snapshot(&source, &allow.id()).unwrap(), allow);
        assert_eq!(source.reads.get(), 2);
    }

    #[test]
    fn absent_and_exact_policy_snapshots_remain_distinct() {
        let policy = fgit_policy::compile_and_seal("policy exact { default deny \"not allowed\" }").unwrap();
        let mut source = InMemoryPolicySnapshots::new();
        assert!(matches!(checked_snapshot(&source, &policy.id()), Err(PolicySourceRefusal::UnknownSnapshot { .. })));
        let id = source.pin(policy.clone());
        assert_eq!(checked_snapshot(&source, &id).unwrap(), policy);
        assert_eq!(source.pin(policy.clone()), id);
        assert_eq!(checked_snapshot(&source, &id).unwrap().id(), id);
    }
}
