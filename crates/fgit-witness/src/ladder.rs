//! The semantic rebase ladder, and the certificates its rungs produce.
//!
//! Plan §16.4 lists what a prepared transaction may do after losing a head
//! compare-and-exchange, in increasing order of cost and decreasing order of
//! confidence:
//!
//! 1. exact witness revalidation with no change;
//! 2. deterministic intent replay on the new basis;
//! 3. structured ref, forge, or path patch reapplication with proof;
//! 4. a domain-specific append, range, or bitmap merge certificate;
//! 5. bounded witness refinement, followed by one of the above;
//! 6. typed retry, refusal, or manual merge.
//!
//! And the hard boundary: "There is no raw byte-level or XOR merge for source
//! state." A rung that cannot produce a certificate does not get to guess.
//!
//! ## Rung 1 reuses the capsule unchanged, by construction
//!
//! The acceptance line for this bead is that exact revalidation *provably*
//! reuses capsules unchanged when the witness holds. [`exact_revalidation`]
//! takes `&'c C` and returns [`Reused<'c, C>`], which holds that same shared
//! borrow. It is not that the function declines to modify the capsule — it is
//! handed a shared reference and gives back a borrow of the very same value,
//! so there is no capsule it *could* substitute and nothing it could mutate.
//! A test pins the observable consequence; the type pins the rest.

use std::collections::BTreeMap;

use crate::footprint::{Footprint, Scope};

/// One rung of the ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rung {
    /// Exact witness revalidation with no change.
    ExactRevalidation,
    /// Deterministic intent replay on the new basis.
    DeterministicReplay,
    /// Structured ref, forge, or path patch reapplication with proof.
    StructuredPatch,
    /// A domain-specific append, range, or bitmap merge certificate.
    DomainMergeCertificate,
    /// Bounded witness refinement, followed by another rung.
    BoundedRefinement,
    /// Typed retry, refusal, or manual merge.
    TypedRetryOrRefusal,
}

impl Rung {
    /// Every rung, in ladder order.
    pub const ALL: &'static [Self] = &[
        Self::ExactRevalidation,
        Self::DeterministicReplay,
        Self::StructuredPatch,
        Self::DomainMergeCertificate,
        Self::BoundedRefinement,
        Self::TypedRetryOrRefusal,
    ];

    /// Stable machine-readable name, for receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactRevalidation => "exact_revalidation",
            Self::DeterministicReplay => "deterministic_replay",
            Self::StructuredPatch => "structured_patch",
            Self::DomainMergeCertificate => "domain_merge_certificate",
            Self::BoundedRefinement => "bounded_refinement",
            Self::TypedRetryOrRefusal => "typed_retry_or_refusal",
        }
    }

    /// The next rung to try, or `None` at the bottom.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::ExactRevalidation => Some(Self::DeterministicReplay),
            Self::DeterministicReplay => Some(Self::StructuredPatch),
            Self::StructuredPatch => Some(Self::DomainMergeCertificate),
            Self::DomainMergeCertificate => Some(Self::BoundedRefinement),
            Self::BoundedRefinement => Some(Self::TypedRetryOrRefusal),
            Self::TypedRetryOrRefusal => None,
        }
    }
}

/// The exact values a transaction observed, keyed by scope.
///
/// A witness that recorded only *that* a read happened cannot support rung 1:
/// revalidation compares values, not access counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    values: BTreeMap<Scope, Vec<u8>>,
}

impl Observations {
    /// Builds observations from scope and value pairs.
    #[must_use]
    pub fn from_pairs(pairs: impl IntoIterator<Item = (Scope, Vec<u8>)>) -> Self {
        Self {
            values: pairs.into_iter().collect(),
        }
    }

    /// Records one observed value.
    pub fn observe(&mut self, scope: Scope, value: Vec<u8>) {
        self.values.insert(scope, value);
    }

    /// The value observed for a scope, if any.
    #[must_use]
    pub fn get(&self, scope: &Scope) -> Option<&[u8]> {
        self.values.get(scope).map(Vec::as_slice)
    }

    /// How many scopes were observed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True when nothing was observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The footprint these observations cover.
    #[must_use]
    pub fn footprint(&self) -> Footprint {
        Footprint::from_scopes(self.values.keys().cloned())
    }

    /// The scopes whose value differs from `current`.
    ///
    /// A scope that has vanished from `current` counts as changed: absence is
    /// a different value, not a missing comparison.
    #[must_use]
    pub fn changed_against(&self, current: &Self) -> Vec<Scope> {
        self.values
            .iter()
            .filter(|(scope, observed)| current.get(scope) != Some(observed.as_slice()))
            .map(|(scope, _)| scope.clone())
            .collect()
    }
}

/// Evidence explaining why a rung concluded what it did.
///
/// §12 requires every refinement decision and input root to be receipted, so a
/// rung that succeeds has to say what it compared, not merely that it passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictCertificate {
    rung: Rung,
    scopes_compared: usize,
    scopes_changed: Vec<Scope>,
}

impl ConflictCertificate {
    /// Which rung produced this certificate.
    #[must_use]
    pub const fn rung(&self) -> Rung {
        self.rung
    }

    /// How many scopes were compared.
    #[must_use]
    pub const fn scopes_compared(&self) -> usize {
        self.scopes_compared
    }

    /// The scopes that changed; empty when the witness held.
    #[must_use]
    pub fn scopes_changed(&self) -> &[Scope] {
        &self.scopes_changed
    }

    /// True when nothing the transaction read has moved.
    #[must_use]
    pub const fn witness_held(&self) -> bool {
        self.scopes_changed.is_empty()
    }
}

/// A capsule that rung 1 has revalidated and is handing back unchanged.
///
/// Holds a shared borrow of the original, which is what makes "unchanged"
/// structural rather than a promise in a doc comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reused<'c, C> {
    capsule: &'c C,
}

impl<'c, C> Reused<'c, C> {
    /// The original capsule, unchanged.
    #[must_use]
    pub const fn capsule(&self) -> &'c C {
        self.capsule
    }
}

/// What rung 1 concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revalidation<'c, C> {
    /// Every observed value still holds; reuse the capsule as it stands.
    Reuse {
        /// The unchanged capsule.
        reused: Reused<'c, C>,
        /// What was compared to reach that conclusion.
        certificate: ConflictCertificate,
    },
    /// Something the transaction read has moved; climb to the next rung.
    Advance {
        /// The rung to try next.
        next: Rung,
        /// What changed, so the next rung need not rediscover it.
        certificate: ConflictCertificate,
    },
}

/// Rung 1: exact witness revalidation.
///
/// Compares every value the transaction observed against the current basis. If
/// all hold, the capsule is reused **unchanged** — see [`Reused`]. Otherwise
/// the caller is pointed at the next rung with a certificate naming exactly
/// what moved.
///
/// This never consults a sketch. §12 requires an inconclusive refinement to
/// retain the coarse conflict, and rung 1 is the rung that is allowed to be
/// conclusive precisely because it compares exact values.
pub fn exact_revalidation<'c, C>(
    capsule: &'c C,
    witness: &Observations,
    current: &Observations,
) -> Revalidation<'c, C> {
    let changed = witness.changed_against(current);
    let certificate = ConflictCertificate {
        rung: Rung::ExactRevalidation,
        scopes_compared: witness.len(),
        scopes_changed: changed,
    };
    if certificate.witness_held() {
        Revalidation::Reuse {
            reused: Reused { capsule },
            certificate,
        }
    } else {
        Revalidation::Advance {
            next: Rung::ExactRevalidation
                .next()
                .unwrap_or(Rung::TypedRetryOrRefusal),
            certificate,
        }
    }
}

/// Why a climb ended without a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClimbFailure {
    /// Every rung was tried and none produced a certificate.
    Exhausted,
    /// The attempt ran out of its declared budget partway.
    ///
    /// §12: an over-budget refinement retains the coarse conflict rather than
    /// guessing.
    BudgetExhausted,
}

/// The outcome of climbing the ladder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Climb {
    /// A rung produced a certificate.
    Certified(ConflictCertificate),
    /// No rung could; the coarse conflict stands.
    RetainCoarseConflict(ClimbFailure),
}

/// Climbs from `start` until a rung certifies or the ladder is exhausted.
///
/// `attempt` is the caller's per-rung evaluator: it returns a certificate when
/// that rung succeeds. Rungs are tried in ladder order and never skipped, so a
/// cheap conclusive answer is always preferred to an expensive speculative
/// one.
///
/// `budget` bounds how many rungs may be attempted, because §12 makes
/// refinement bounded work rather than best-effort.
pub fn climb<F>(start: Rung, budget: u32, mut attempt: F) -> Climb
where
    F: FnMut(Rung) -> Option<ConflictCertificate>,
{
    let mut rung = Some(start);
    let mut spent = 0_u32;
    while let Some(current) = rung {
        if spent >= budget {
            return Climb::RetainCoarseConflict(ClimbFailure::BudgetExhausted);
        }
        spent += 1;
        if let Some(certificate) = attempt(current) {
            return Climb::Certified(certificate);
        }
        rung = current.next();
    }
    Climb::RetainCoarseConflict(ClimbFailure::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::{
        Climb, ClimbFailure, ConflictCertificate, Observations, Revalidation, Rung, climb,
        exact_revalidation,
    };
    use crate::footprint::Scope;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Capsule {
        payload: Vec<u8>,
    }

    fn scope(name: &str) -> Scope {
        Scope::ExactRef(name.as_bytes().to_vec())
    }

    fn observations(pairs: &[(&str, &[u8])]) -> Observations {
        Observations::from_pairs(
            pairs
                .iter()
                .map(|(name, value)| (scope(name), (*value).to_vec())),
        )
    }

    #[test]
    fn rung_one_reuses_the_capsule_unchanged_when_the_witness_holds() {
        let capsule = Capsule {
            payload: b"prepared".to_vec(),
        };
        let before = capsule.clone();
        let witness = observations(&[("refs/heads/main", b"aaa"), ("refs/tags/v1", b"bbb")]);
        let current = observations(&[("refs/heads/main", b"aaa"), ("refs/tags/v1", b"bbb")]);

        match exact_revalidation(&capsule, &witness, &current) {
            Revalidation::Reuse {
                reused,
                certificate,
            } => {
                assert_eq!(certificate.rung(), Rung::ExactRevalidation);
                assert!(certificate.witness_held());
                assert_eq!(certificate.scopes_compared(), 2);
                assert_eq!(certificate.scopes_changed(), &[]);
                // The reused capsule is the very same value, not a rebuild.
                assert_eq!(reused.capsule(), &before);
                assert!(std::ptr::eq(reused.capsule(), std::ptr::from_ref(&capsule)));
            }
            other @ Revalidation::Advance { .. } => panic!("expected reuse, got {other:?}"),
        }
        assert_eq!(capsule, before, "the capsule itself must be untouched");
    }

    #[test]
    fn rung_one_advances_and_names_exactly_what_moved() {
        let capsule = Capsule {
            payload: b"prepared".to_vec(),
        };
        let witness = observations(&[("refs/heads/main", b"aaa"), ("refs/tags/v1", b"bbb")]);
        let current = observations(&[("refs/heads/main", b"zzz"), ("refs/tags/v1", b"bbb")]);

        match exact_revalidation(&capsule, &witness, &current) {
            Revalidation::Advance { next, certificate } => {
                assert_eq!(next, Rung::DeterministicReplay);
                assert!(!certificate.witness_held());
                assert_eq!(certificate.scopes_changed(), &[scope("refs/heads/main")]);
            }
            other @ Revalidation::Reuse { .. } => panic!("expected advance, got {other:?}"),
        }
    }

    #[test]
    fn a_vanished_scope_counts_as_changed() {
        let capsule = Capsule { payload: vec![] };
        let witness = observations(&[("refs/heads/main", b"aaa")]);
        let current = Observations::default();
        match exact_revalidation(&capsule, &witness, &current) {
            Revalidation::Advance { certificate, .. } => {
                assert_eq!(certificate.scopes_changed(), &[scope("refs/heads/main")]);
            }
            other @ Revalidation::Reuse { .. } => {
                panic!("absence is a different value, not a skipped comparison: {other:?}")
            }
        }
    }

    #[test]
    fn an_empty_witness_holds_vacuously_and_still_reuses() {
        let capsule = Capsule { payload: vec![1] };
        let witness = Observations::default();
        let current = observations(&[("refs/heads/main", b"anything")]);
        match exact_revalidation(&capsule, &witness, &current) {
            Revalidation::Reuse { certificate, .. } => {
                assert_eq!(certificate.scopes_compared(), 0);
                assert!(certificate.witness_held());
            }
            other @ Revalidation::Advance { .. } => panic!("expected vacuous reuse, got {other:?}"),
        }
    }

    #[test]
    fn the_ladder_is_ordered_and_terminates() {
        assert_eq!(Rung::ALL.len(), 6);
        let mut rung = Rung::ExactRevalidation;
        let mut seen = vec![rung];
        while let Some(next) = rung.next() {
            seen.push(next);
            rung = next;
        }
        assert_eq!(
            seen,
            Rung::ALL.to_vec(),
            "next() must walk the declared order"
        );
        assert_eq!(Rung::TypedRetryOrRefusal.next(), None, "the ladder ends");
    }

    #[test]
    fn climbing_prefers_the_cheapest_rung_that_certifies() {
        let mut offered = Vec::new();
        let outcome = climb(Rung::ExactRevalidation, 6, |rung| {
            offered.push(rung);
            (rung == Rung::StructuredPatch).then(|| ConflictCertificate {
                rung,
                scopes_compared: 1,
                scopes_changed: Vec::new(),
            })
        });
        match outcome {
            Climb::Certified(certificate) => assert_eq!(certificate.rung(), Rung::StructuredPatch),
            other @ Climb::RetainCoarseConflict(_) => {
                panic!("expected certification, got {other:?}")
            }
        }
        assert_eq!(
            offered,
            vec![
                Rung::ExactRevalidation,
                Rung::DeterministicReplay,
                Rung::StructuredPatch
            ],
            "rungs must be tried in order and none skipped"
        );
    }

    #[test]
    fn an_over_budget_climb_retains_the_coarse_conflict() {
        // NPC section 12: inconclusive, failed, or over-budget refinement
        // retains the coarse conflict. It must never fall through to a guess.
        let outcome = climb(Rung::ExactRevalidation, 2, |_| None);
        assert_eq!(
            outcome,
            Climb::RetainCoarseConflict(ClimbFailure::BudgetExhausted)
        );
    }

    #[test]
    fn an_exhausted_climb_retains_the_coarse_conflict() {
        let outcome = climb(Rung::ExactRevalidation, 99, |_| None);
        assert_eq!(
            outcome,
            Climb::RetainCoarseConflict(ClimbFailure::Exhausted)
        );
    }

    #[test]
    fn rung_names_are_distinct() {
        use std::collections::BTreeSet;
        let names = Rung::ALL
            .iter()
            .map(|r| r.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), Rung::ALL.len());
    }
}
