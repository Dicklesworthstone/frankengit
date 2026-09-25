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

pub mod persisted;
/// Authority-bound reuse of validation evidence between receive commands.
pub mod receive_session;

mod compiled_protection;
mod input_facts;
pub use input_facts::MissingAdmissionFact;
pub(crate) use compiled_protection::receive_refusal;

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
    /// This adapter cannot establish a fact consulted by the pinned policy.
    MissingAdmissionFacts {
        id: String,
        fact: MissingAdmissionFact,
    },
    /// A valid snapshot was returned under the wrong requested identity.
    IdentityMismatch {
        requested: Box<PolicySnapshotId>,
        observed: Box<PolicySnapshotId>,
    },
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
            Self::MissingAdmissionFacts { id, fact } => {
                write!(formatter, "policy snapshot {id} requires {fact}")
            }
            Self::IdentityMismatch {
                requested,
                observed,
            } => write!(
                formatter,
                "policy snapshot mismatch: requested {requested}, received {observed}",
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionVerdict {
    /// Identity of the snapshot the decision is replayable against.
    pub snapshot_id: PolicySnapshotId,
    /// `None` when the policy allowed every update.
    pub refusal: Option<RefusalCode>,
    /// Full rule-visit trace; retained verbatim for decision evidence.
    pub trace: String,
}

/// Evaluates protection for one complete input root against one pinned snapshot.
///
/// The caller must bind principal attributes, validated ancestry, accepted
/// evidence, aggregates and evaluation time to this exact admission attempt.
/// Use this entry point for policies beyond the reference-only adapters below;
/// neither a claimed principal ID nor a requested force flag proves those facts.
pub fn evaluate_protection(
    source: &dyn PolicySnapshotSource,
    id: &PolicySnapshotId,
    codes: &SubjectCodeMap,
    input_root: &fgit_policy::PolicyInputRoot,
) -> Result<ProtectionVerdict, PolicySourceRefusal> {
    let snapshot = checked_snapshot(source, id)?;
    evaluate_snapshot(&snapshot, codes, input_root)
}

fn checked_snapshot(
    source: &dyn PolicySnapshotSource,
    id: &PolicySnapshotId,
) -> Result<fgit_policy::PolicySnapshot, PolicySourceRefusal> {
    let snapshot = source.snapshot_by_id(id)?;
    if snapshot.id() != *id {
        return Err(PolicySourceRefusal::IdentityMismatch {
            requested: Box::new(*id),
            observed: Box::new(snapshot.id()),
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
            if let Some(reason) = subject.reason() {
                let text = reason.as_str();
                if text.contains("fast_forward")
                    || text.contains("fast-forward")
                    || text.contains("non_fast_forward")
                {
                    return Some(codes.not_fast_forward);
                }
                if text.contains("force") {
                    return Some(codes.force_not_permitted);
                }
            }
            return Some(codes.transition_denied);
        }
    }
    Some(codes.transition_denied)
}

/// Adapts an [`fgit_authority::AuthorityStore`] as a [`PolicySnapshotSource`].
pub struct AuthorityPolicySource<'a, S: ?Sized> {
    pub store: &'a S,
    pub limits: persisted::PolicyStoreLimits,
}

impl<'a, S: fgit_authority::AuthorityStore + ?Sized> AuthorityPolicySource<'a, S> {
    #[must_use]
    pub fn new(store: &'a S) -> Self {
        Self {
            store,
            limits: persisted::PolicyStoreLimits::default(),
        }
    }

    #[must_use]
    pub const fn with_limits(store: &'a S, limits: persisted::PolicyStoreLimits) -> Self {
        Self { store, limits }
    }
}

impl<S: fgit_authority::AuthorityStore + ?Sized> PolicySnapshotSource
    for AuthorityPolicySource<'_, S>
{
    fn snapshot_by_id(
        &self,
        id: &PolicySnapshotId,
    ) -> Result<fgit_policy::PolicySnapshot, PolicySourceRefusal> {
        persisted::read_policy(self.store, *id, self.limits, &|| Ok(())).map_err(|err| match err {
            persisted::PolicyStoreError::Missing { .. } => {
                PolicySourceRefusal::UnknownSnapshot { id: id.to_string() }
            }
            persisted::PolicyStoreError::IdentityMismatch {
                requested,
                observed,
            } => PolicySourceRefusal::IdentityMismatch {
                requested,
                observed,
            },
            _ => PolicySourceRefusal::Undecodable { id: id.to_string() },
        })
    }
}

/// Provides the inert placeholder identity used by reference-only evaluation.
///
/// This is not an authenticated principal snapshot or a persisted object.
/// Policies consulting actor attributes must use a complete input root instead.
#[must_use]
pub fn default_principal_snapshot_id() -> fgit_types::PrincipalSnapshotId {
    let digest_bytes = fgit_types::DigestBytes::try_new(&[0u8; 32]).expect("valid digest bytes");
    let algorithm = fgit_types::DigestAlgorithmId::try_new(2).expect("valid algorithm id");
    fgit_types::PrincipalSnapshotId::from_internal_object_id(fgit_types::InternalObjectId::new(
        algorithm,
        fgit_types::PrincipalSnapshotId::DOMAIN_TAG,
        fgit_types::CANONICAL_CODEC_VERSION,
        digest_bytes,
    ))
    .expect("valid default principal snapshot id")
}

/// Builds the compatibility input for reference-only policy adapters.
///
/// The principal kind and snapshot are placeholders, NOT authenticated facts.
/// The adapters check the entire compiled predicate tree before allowing this
/// input to reach the evaluator. Never use this helper as an authentication
/// source: construct a complete [`fgit_policy::PolicyInputRoot`] with real
/// [`fgit_policy::PrincipalFacts`] for [`evaluate_protection`] instead.
pub fn build_input_root(
    principal_id: fgit_types::PrincipalId,
    snapshot_id: fgit_types::PrincipalSnapshotId,
    updates: Vec<fgit_policy::RefUpdateFact>,
    instant: fgit_policy::PolicyInstant,
) -> Result<fgit_policy::PolicyInputRoot, fgit_policy::error::PolicyInputRefusal> {
    let principal = fgit_policy::PrincipalFacts::try_new(
        principal_id,
        snapshot_id,
        fgit_policy::PrincipalKind::Human,
        fgit_policy::AuthenticationStrength::None,
        &[],
        &[],
    )?;
    fgit_policy::PolicyInputRoot::try_new(principal, updates, &[], &[], instant)
}

/// Translates materialized ref effects into policy engine ref update facts.
pub fn ref_updates_from_effects(
    refs_before: &BTreeMap<fgit_types::RefName, fgit_types::GitOid>,
    effects: &BTreeMap<fgit_types::RefName, fgit_reference::effect::RefEffect>,
) -> Result<Vec<fgit_policy::RefUpdateFact>, fgit_policy::error::PolicyInputRefusal> {
    let mut facts = Vec::with_capacity(effects.len());
    for (name, effect) in effects {
        let previous = refs_before.get(name).copied();
        let (next, kind) = match effect {
            fgit_reference::effect::RefEffect::Delete => (None, fgit_policy::RefUpdateKind::Delete),
            fgit_reference::effect::RefEffect::Set(oid) => {
                if previous.is_some() {
                    (Some(*oid), fgit_policy::RefUpdateKind::FastForward)
                } else {
                    (Some(*oid), fgit_policy::RefUpdateKind::Create)
                }
            }
        };
        facts.push(fgit_policy::RefUpdateFact::try_new(
            name.clone(),
            previous,
            next,
            kind,
            false,
        )?);
    }
    Ok(facts)
}

/// Translates wire receive commands into policy engine ref update facts.
pub fn ref_updates_from_commands(
    refs_before: &BTreeMap<fgit_types::RefName, fgit_types::GitOid>,
    commands: &[fgit_authority::RefCommand],
) -> Result<Vec<fgit_policy::RefUpdateFact>, fgit_policy::error::PolicyInputRefusal> {
    let mut facts = Vec::with_capacity(commands.len());
    for command in commands {
        let previous = refs_before
            .get(&command.name)
            .copied()
            .or(match command.expected_old {
                fgit_authority::ExpectedOld::Exactly(oid) => Some(oid),
                _ => None,
            });
        let (next, kind) = match command.proposed_new {
            fgit_authority::ProposedNew::Delete => (None, fgit_policy::RefUpdateKind::Delete),
            fgit_authority::ProposedNew::Update(oid) => {
                if previous.is_some() {
                    if command.force {
                        (Some(oid), fgit_policy::RefUpdateKind::NonFastForward)
                    } else {
                        (Some(oid), fgit_policy::RefUpdateKind::FastForward)
                    }
                } else {
                    (Some(oid), fgit_policy::RefUpdateKind::Create)
                }
            }
        };
        facts.push(fgit_policy::RefUpdateFact::try_new(
            command.name.clone(),
            previous,
            next,
            kind,
            command.force,
        )?);
    }
    Ok(facts)
}

/// Compiles a policy snapshot that prohibits deletion of branches matching `pattern`.
pub fn compile_branch_protection_policy(
    pattern: &str,
) -> Result<fgit_policy::PolicySnapshot, fgit_policy::error::PolicyCompileRefusal> {
    compiled_protection::branch_deletion(pattern)
}

/// Compiles a policy snapshot that prohibits direct updates to named protected branches.
pub fn compile_protected_branch_rules<'a, I>(
    branches: I,
) -> Result<fgit_policy::PolicySnapshot, fgit_policy::error::PolicyCompileRefusal>
where
    I: IntoIterator<Item = &'a str>,
{
    compiled_protection::named_branches(branches)
}

/// Evaluates reference-only receive-pack protection against a pinned snapshot.
///
/// Actor, evidence, aggregate and ancestry-dependent policies return
/// [`PolicySourceRefusal::MissingAdmissionFacts`]. A wire force request is an
/// intent, not proof of a non-fast-forward update. Use [`evaluate_protection`]
/// with an independently validated input root for these policy families.
pub fn evaluate_receive_pack_protection(
    source: &dyn PolicySnapshotSource,
    id: &PolicySnapshotId,
    codes: &SubjectCodeMap,
    principal_id: fgit_types::PrincipalId,
    principal_snapshot_id: fgit_types::PrincipalSnapshotId,
    refs_before: &BTreeMap<fgit_types::RefName, fgit_types::GitOid>,
    commands: &[fgit_authority::RefCommand],
    instant: fgit_policy::PolicyInstant,
) -> Result<ProtectionVerdict, PolicySourceRefusal> {
    let snapshot = checked_snapshot(source, id)?;
    input_facts::require_available(&snapshot, true)?;
    let updates = ref_updates_from_commands(refs_before, commands)
        .map_err(|_| PolicySourceRefusal::Undecodable { id: id.to_string() })?;
    let input = build_input_root(principal_id, principal_snapshot_id, updates, instant)
        .map_err(|_| PolicySourceRefusal::Undecodable { id: id.to_string() })?;
    evaluate_snapshot(&snapshot, codes, &input)
}

/// Evaluates reference-only ref-effects protection against a pinned snapshot.
///
/// Net effects carry neither authenticated actor attributes nor the original
/// force intent. Policies reading unavailable facts fail closed; complete-fact
/// callers use [`evaluate_protection`] instead.
pub fn evaluate_effects_protection(
    source: &dyn PolicySnapshotSource,
    id: &PolicySnapshotId,
    codes: &SubjectCodeMap,
    principal_id: fgit_types::PrincipalId,
    principal_snapshot_id: fgit_types::PrincipalSnapshotId,
    refs_before: &BTreeMap<fgit_types::RefName, fgit_types::GitOid>,
    effects: &BTreeMap<fgit_types::RefName, fgit_reference::effect::RefEffect>,
    instant: fgit_policy::PolicyInstant,
) -> Result<ProtectionVerdict, PolicySourceRefusal> {
    let snapshot = checked_snapshot(source, id)?;
    input_facts::require_available(&snapshot, false)?;
    let updates = ref_updates_from_effects(refs_before, effects)
        .map_err(|_| PolicySourceRefusal::Undecodable { id: id.to_string() })?;
    let input = build_input_root(principal_id, principal_snapshot_id, updates, instant)
        .map_err(|_| PolicySourceRefusal::Undecodable { id: id.to_string() })?;
    evaluate_snapshot(&snapshot, codes, &input)
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
        fn snapshot_by_id(
            &self,
            _: &PolicySnapshotId,
        ) -> Result<fgit_policy::PolicySnapshot, PolicySourceRefusal> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.replacement.clone())
        }
    }

    #[test]
    fn a_valid_allow_policy_cannot_be_substituted_for_the_requested_deny_policy() {
        let deny =
            fgit_policy::compile_and_seal("policy pinned { default deny \"review required\" }")
                .unwrap();
        let allow = fgit_policy::compile_and_seal("policy pinned { default allow }").unwrap();
        assert_ne!(deny.id(), allow.id());
        let source = SubstitutingSource {
            replacement: allow.clone(),
            reads: Cell::new(0),
        };
        assert_eq!(
            checked_snapshot(&source, &deny.id()).unwrap_err(),
            PolicySourceRefusal::IdentityMismatch {
                requested: Box::new(deny.id()),
                observed: Box::new(allow.id())
            }
        );
        assert_eq!(
            source.reads.get(),
            1,
            "no fallback lookup after substitution"
        );
        assert_eq!(checked_snapshot(&source, &allow.id()).unwrap(), allow);
        assert_eq!(source.reads.get(), 2);
    }

    #[test]
    fn absent_and_exact_policy_snapshots_remain_distinct() {
        let policy =
            fgit_policy::compile_and_seal("policy exact { default deny \"not allowed\" }").unwrap();
        let mut source = InMemoryPolicySnapshots::new();
        assert!(matches!(
            checked_snapshot(&source, &policy.id()),
            Err(PolicySourceRefusal::UnknownSnapshot { .. })
        ));
        let id = source.pin(policy.clone());
        assert_eq!(checked_snapshot(&source, &id).unwrap(), policy);
        assert_eq!(source.pin(policy), id);
        assert_eq!(checked_snapshot(&source, &id).unwrap().id(), id);
    }
}
