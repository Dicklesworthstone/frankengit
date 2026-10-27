//! The closed factual profile for canonically activated repository ref policy.
//!
//! Admission knows native ref names, scopes and create/delete/update shape. It
//! does not thereby know authentication strength, ancestry, accepted evidence,
//! aggregates or force intent. Inspect every predicate before activation, even
//! an unreachable arm: absence is not a false fact an author may negate.

use crate::program::{MAX_SET_ELEMENTS, MAX_TEXT_LITERAL_LEN, Predicate, Selector};
use crate::{PolicySnapshot, RefUpdateKind};

pub const MAX_REFERENCE_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_REFERENCE_POLICY_RULES: usize = 64;
pub const MAX_REFERENCE_POLICY_PREDICATES: usize = 4096;
/// Leave room for the canonical event/decision envelopes around the program.
pub const MAX_REFERENCE_POLICY_DEPTH: u32 = 16;
pub const MAX_REFERENCE_POLICY_EVALUATION_WORK: usize = 1_000_000;
pub const MAX_REFERENCE_POLICY_TRACE_BYTES: usize = 2 * 1024 * 1024;

/// Closed factual profiles. Historical ref-only decisions never learn new
/// facts; the actor profile additionally observes only the principal identifier
/// bound to the sealed transaction, not authentication or membership claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePolicyProfile {
    ReferenceFactsV1,
    ReferenceActorIdV1,
}
impl ReferencePolicyProfile {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReferenceFactsV1 => "reference_facts_v1",
            Self::ReferenceActorIdV1 => "reference_actor_id_v1",
        }
    }
}

/// Select the smallest supported profile. Forge event and evidence versions
/// retain this choice; an old ref-only record cannot acquire actor semantics
/// merely because its reader was upgraded.
pub fn classify(
    snapshot: &PolicySnapshot,
) -> Result<ReferencePolicyProfile, ReferencePolicyRefusal> {
    match validate(snapshot) {
        Ok(_) => Ok(ReferencePolicyProfile::ReferenceFactsV1),
        Err(ReferencePolicyRefusal::UnsupportedFacts) => {
            validate_for(ReferencePolicyProfile::ReferenceActorIdV1, snapshot)?;
            Ok(ReferencePolicyProfile::ReferenceActorIdV1)
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePolicyRefusal {
    UnsupportedFacts,
    ResourceLimit,
    Encoding,
    InvalidProgram,
}
impl core::fmt::Display for ReferencePolicyRefusal {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str(match self {
            Self::UnsupportedFacts => {
                "repository ref policy requires unavailable authenticated facts"
            }
            Self::ResourceLimit => "repository ref policy exceeds its bounded profile",
            Self::Encoding => "repository ref policy cannot be canonically encoded",
            Self::InvalidProgram => "repository ref policy has duplicate or noncanonical rules",
        })
    }
}
impl std::error::Error for ReferencePolicyRefusal {}

/// Inspect the complete program and bound its encoded size and evaluator work.
/// The returned count is used to reserve work before evaluating any subjects.
pub fn validate(snapshot: &PolicySnapshot) -> Result<usize, ReferencePolicyRefusal> {
    validate_for(ReferencePolicyProfile::ReferenceFactsV1, snapshot)
}

/// Validate one named factual profile without relaxing any resource bound.
pub fn validate_for(
    profile: ReferencePolicyProfile,
    snapshot: &PolicySnapshot,
) -> Result<usize, ReferencePolicyRefusal> {
    let policy = snapshot.policy();
    if !policy.aggregates().is_empty() || !policy.evidence().is_empty() {
        return Err(ReferencePolicyRefusal::UnsupportedFacts);
    }
    if policy.rules().len() > MAX_REFERENCE_POLICY_RULES {
        return Err(ReferencePolicyRefusal::ResourceLimit);
    }
    if policy
        .rules()
        .windows(2)
        .any(|rules| rules[0].id() >= rules[1].id())
    {
        return Err(ReferencePolicyRefusal::InvalidProgram);
    }
    let mut remaining = MAX_REFERENCE_POLICY_PREDICATES;
    // A conservative bound is accumulated before the canonical encoder can
    // allocate a frame, including literals created through public AST APIs.
    let mut bytes = 1024_usize;
    for rule in policy.rules() {
        reserve_bytes(
            &mut bytes,
            32 + rule.id().as_bytes().len()
                + rule
                    .outcome()
                    .reason()
                    .map_or(0, |reason| reason.as_str().len()),
        )?;
        inspect(profile, rule.predicate(), 0, &mut remaining, &mut bytes)?;
    }
    // The program was bounded before encoding can recursively allocate.
    if snapshot
        .encode()
        .map_err(|_| ReferencePolicyRefusal::Encoding)?
        .len()
        > MAX_REFERENCE_POLICY_BYTES
    {
        return Err(ReferencePolicyRefusal::ResourceLimit);
    }
    Ok(MAX_REFERENCE_POLICY_PREDICATES - remaining)
}

/// Reserve finite predicate visits and trace space before the engine allocates
/// its subjects/visits. Each host uses this same profile before evaluation.
pub fn validate_evaluation<'a>(
    snapshot: &PolicySnapshot,
    names: impl IntoIterator<Item = &'a fgit_types::RefName>,
) -> Result<(), ReferencePolicyRefusal> {
    validate_evaluation_for(ReferencePolicyProfile::ReferenceFactsV1, snapshot, names)
}

pub fn validate_evaluation_for<'a>(
    profile: ReferencePolicyProfile,
    snapshot: &PolicySnapshot,
    names: impl IntoIterator<Item = &'a fgit_types::RefName>,
) -> Result<(), ReferencePolicyRefusal> {
    let predicates = validate_for(profile, snapshot)?.max(1);
    let rules = snapshot.policy().rules().len().saturating_add(1);
    let mut count = 0_usize;
    let mut trace = 0_usize;
    for name in names {
        count = count.saturating_add(1);
        trace = trace.saturating_add(name.as_bytes().len().saturating_mul(4).saturating_add(1024));
        if count.saturating_mul(predicates) > MAX_REFERENCE_POLICY_EVALUATION_WORK
            || trace.saturating_mul(rules) > MAX_REFERENCE_POLICY_TRACE_BYTES
        {
            return Err(ReferencePolicyRefusal::ResourceLimit);
        }
    }
    Ok(())
}

fn inspect(
    profile: ReferencePolicyProfile,
    predicate: &Predicate,
    depth: u32,
    remaining: &mut usize,
    bytes: &mut usize,
) -> Result<(), ReferencePolicyRefusal> {
    if depth > MAX_REFERENCE_POLICY_DEPTH || *remaining == 0 {
        return Err(ReferencePolicyRefusal::ResourceLimit);
    }
    *remaining -= 1;
    reserve_bytes(bytes, 16)?;
    match predicate {
        Predicate::Always | Predicate::Never => Ok(()),
        Predicate::All(children) | Predicate::Any(children) => {
            for child in children {
                inspect(profile, child, depth + 1, remaining, bytes)?;
            }
            Ok(())
        }
        Predicate::Not(child) => inspect(profile, child, depth + 1, remaining, bytes),
        Predicate::TextEquals { selector, value } if text_selector(profile, *selector) => {
            if value.as_str().len() > MAX_TEXT_LITERAL_LEN {
                return Err(ReferencePolicyRefusal::ResourceLimit);
            }
            reserve_bytes(bytes, value.as_str().len())
        }
        Predicate::TextIn { selector, values } if text_selector(profile, *selector) => {
            if values.len() > MAX_SET_ELEMENTS || values.len() > *remaining {
                return Err(ReferencePolicyRefusal::ResourceLimit);
            }
            *remaining -= values.len();
            for value in values {
                if value.as_str().len() > MAX_TEXT_LITERAL_LEN {
                    return Err(ReferencePolicyRefusal::ResourceLimit);
                }
                reserve_bytes(bytes, 4 + value.as_str().len())?;
            }
            Ok(())
        }
        Predicate::TextMatches { selector, pattern } if text_selector(profile, *selector) => {
            reserve_bytes(bytes, pattern.as_str().len())
        }
        Predicate::UpdateKindEquals(kind) if structural(*kind) => Ok(()),
        Predicate::UpdateKindIn(kinds) if kinds.iter().all(|kind| structural(*kind)) => Ok(()),
        _ => Err(ReferencePolicyRefusal::UnsupportedFacts),
    }
}

const fn text_selector(profile: ReferencePolicyProfile, selector: Selector) -> bool {
    matches!(selector, Selector::RefName | Selector::RefScope)
        || (matches!(profile, ReferencePolicyProfile::ReferenceActorIdV1)
            && matches!(selector, Selector::ActorId))
}

fn reserve_bytes(used: &mut usize, extra: usize) -> Result<(), ReferencePolicyRefusal> {
    *used = used.saturating_add(extra);
    if *used > MAX_REFERENCE_POLICY_BYTES {
        Err(ReferencePolicyRefusal::ResourceLimit)
    } else {
        Ok(())
    }
}

const fn structural(kind: RefUpdateKind) -> bool {
    matches!(
        kind,
        RefUpdateKind::Create | RefUpdateKind::Delete | RefUpdateKind::UnclassifiedUpdate
    )
}
