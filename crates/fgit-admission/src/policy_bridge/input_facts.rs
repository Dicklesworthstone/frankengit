#![forbid(unsafe_code)]
//! Availability checks for the legacy reference-only admission adapters.
//!
//! Missing facts are not false facts. In particular, supplying an empty set of
//! memberships or receipts can make a negated predicate grant access. Inspect
//! the complete compiled predicate tree, not just the branches that happen to
//! run with placeholder input. The full-input evaluator remains unchanged.

use fgit_policy::program::{MAX_PREDICATE_DEPTH, MAX_RULES, Predicate, Selector};
use fgit_policy::{PolicySnapshot, RefUpdateKind};

use super::PolicySourceRefusal;

/// A fact that must be supplied by a complete, attempt-bound policy input root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingAdmissionFact {
    /// Authenticated identity, snapshot, kind, strength or membership facts.
    AuthenticatedPrincipal,
    /// Validated commit ancestry; a force flag cannot establish this.
    VerifiedAncestry,
    /// Evidence accepted for this subject and this evaluation instant.
    Evidence,
    /// Repository aggregates bound to the policy's authority basis.
    Aggregates,
    /// The original force intent, which is not recoverable from net effects.
    ForceIntent,
}

impl std::fmt::Display for MissingAdmissionFact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticatedPrincipal => "authenticated principal facts",
            Self::VerifiedAncestry => "verified commit ancestry",
            Self::Evidence => "attempt-bound evidence receipts",
            Self::Aggregates => "authority-bound repository aggregates",
            Self::ForceIntent => "the original force intent",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FactCheckRefusal {
    Missing(MissingAdmissionFact),
    TooComplex,
}

/// Check before constructing placeholder input, using the SAME checked snapshot
/// that will be evaluated. No second lookup, fallback policy or source parsing.
pub(super) fn require_available(
    snapshot: &PolicySnapshot,
    force_intent_known: bool,
) -> Result<(), PolicySourceRefusal> {
    let id = snapshot.id();
    let rules = snapshot.policy().rules();
    if rules.len() > MAX_RULES {
        return Err(PolicySourceRefusal::Undecodable { id: id.to_string() });
    }
    // A source byte can introduce at most one predicate node. Reuse the policy
    // compiler's finite source envelope rather than letting a custom snapshot
    // source manufacture an unbounded preflight walk. Recursion is separately
    // limited by the same depth bound used by the compiler and decoder.
    let mut remaining = fgit_policy::syntax::MAX_SOURCE_LEN;
    for rule in rules {
        match check_predicate(rule.predicate(), force_intent_known, 0, &mut remaining) {
            Ok(()) => {}
            Err(FactCheckRefusal::Missing(fact)) => {
                return Err(PolicySourceRefusal::MissingAdmissionFacts {
                    id: id.to_string(),
                    fact,
                });
            }
            Err(FactCheckRefusal::TooComplex) => {
                return Err(PolicySourceRefusal::Undecodable { id: id.to_string() });
            }
        }
    }
    Ok(())
}

fn check_predicate(
    predicate: &Predicate,
    force_intent_known: bool,
    depth: u32,
    remaining: &mut usize,
) -> Result<(), FactCheckRefusal> {
    if depth > MAX_PREDICATE_DEPTH || *remaining == 0 {
        return Err(FactCheckRefusal::TooComplex);
    }
    *remaining -= 1;
    let missing = match predicate {
        Predicate::Always | Predicate::Never => None,
        Predicate::All(children) | Predicate::Any(children) => {
            for child in children {
                check_predicate(child, force_intent_known, depth + 1, remaining)?;
            }
            None
        }
        Predicate::Not(child) => {
            check_predicate(child, force_intent_known, depth + 1, remaining)?;
            None
        }
        Predicate::TextEquals { selector, .. }
        | Predicate::TextIn { selector, .. }
        | Predicate::TextMatches { selector, .. } => match selector {
            Selector::RefName | Selector::RefScope => None,
            _ => Some(MissingAdmissionFact::AuthenticatedPrincipal),
        },
        Predicate::UpdateKindEquals(kind) => ancestry_fact(*kind),
        Predicate::UpdateKindIn(kinds) => kinds.iter().find_map(|kind| ancestry_fact(*kind)),
        Predicate::PrincipalKindEquals(_)
        | Predicate::PrincipalKindIn(_)
        | Predicate::AuthenticationCompare { .. }
        | Predicate::LabelContains { .. } => Some(MissingAdmissionFact::AuthenticatedPrincipal),
        Predicate::ForceRequested if force_intent_known => None,
        Predicate::ForceRequested => Some(MissingAdmissionFact::ForceIntent),
        Predicate::AggregateCompare { .. } => Some(MissingAdmissionFact::Aggregates),
        Predicate::EvidenceAccepted(_) => Some(MissingAdmissionFact::Evidence),
    };
    match missing {
        Some(fact) => Err(FactCheckRefusal::Missing(fact)),
        None => Ok(()),
    }
}

const fn ancestry_fact(kind: RefUpdateKind) -> Option<MissingAdmissionFact> {
    match kind {
        RefUpdateKind::Create | RefUpdateKind::Delete => None,
        RefUpdateKind::FastForward | RefUpdateKind::NonFastForward => {
            Some(MissingAdmissionFact::VerifiedAncestry)
        }
    }
}

#[cfg(test)]
mod tests;
