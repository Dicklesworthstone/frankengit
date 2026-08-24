//! Preferred-combiner selection, and the tie-break that makes it closed.
//!
//! `frankengit-fg036a`. Rendezvous ("highest random weight") selection: every
//! candidate is scored for the key, and the highest score wins. The property
//! that makes it worth using over modular hashing is that removing one
//! candidate moves only the keys that candidate held, and leaves every other
//! key where it was.
//!
//! # This decides nothing
//!
//! §5.1 puts routing among the hints. A preferred combiner is a guess about
//! where work will go fastest, and the worst outcome of a wrong guess is a
//! slower correct answer. Nothing here may gate authorization, decide
//! visibility, or stand in for an authority read — see [`crate::hint::Hint`]
//! for the type that keeps that honest at the use site.
//!
//! That is also why this module takes the scoring function as a parameter
//! rather than choosing a hash. Selection *policy* — highest score, closed
//! tie-break, order independence — is what §8 requires to be deterministic and
//! observable, and it is testable without committing to how scores are
//! produced. Where the score comes from is a separate question about which
//! registry, if any, owns a hashed-but-non-identity value.

use core::cmp::Ordering;

/// A candidate's weight for one key. Higher wins.
///
/// Opaque bytes rather than an integer so a wider or narrower scorer can be
/// substituted without changing what "higher" means: comparison is
/// big-endian-style over the byte string, which is the ordering a digest
/// already has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlacementScore([u8; 32]);

impl PlacementScore {
    /// Wrap a scorer's output.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw weight.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Something that can be selected, with stable bytes to break ties on.
///
/// The tie-break key must identify the candidate and must not vary between
/// processes or runs. A cell's identifier qualifies; its index in whatever
/// list this process happened to build does not, and using one would make
/// selection depend on enumeration order — the exact thing
/// [`preferred_candidate`] promises it does not.
pub trait PlacementCandidate {
    /// Stable identifying bytes.
    fn placement_key(&self) -> &[u8];
}

/// Pick the preferred candidate for a key.
///
/// Returns `None` only for an empty candidate set: with no candidates there is
/// no preference to express, and inventing one would be a routing decision made
/// out of nothing.
///
/// # The tie-break, and why it is not "first wins"
///
/// Two candidates can score equally — astronomically unlikely with a real
/// digest, certain with a deliberately degenerate scorer, and a test will do
/// the latter. Resolving by position in the slice would make the answer depend
/// on the order the caller assembled its candidates, so two cells with the same
/// membership view could disagree purely because one enumerated a map. The tie
/// therefore breaks on the **lowest `placement_key`**, which every cell agrees
/// on without coordinating.
#[must_use]
pub fn preferred_candidate<C, S>(candidates: &[C], score: S) -> Option<&C>
where
    C: PlacementCandidate,
    S: Fn(&C) -> PlacementScore,
{
    candidates.iter().fold(None, |best, candidate| {
        let Some(incumbent) = best else {
            return Some(candidate);
        };
        let ordering = score(candidate)
            .cmp(&score(incumbent))
            // Reversed on purpose: the higher score wins, but the LOWER key
            // wins a tie, so the key comparison runs the other way.
            .then_with(|| incumbent.placement_key().cmp(candidate.placement_key()));
        match ordering {
            Ordering::Greater => Some(candidate),
            Ordering::Less | Ordering::Equal => Some(incumbent),
        }
    })
}

/// Rank every candidate, best first.
///
/// The ordered form of [`preferred_candidate`], for a caller that wants a
/// fallback list rather than one answer — trying the second-preferred cell when
/// the first does not answer is a latency decision, and it must use the same
/// order the preference did or the two would disagree about what "second" is.
#[must_use]
pub fn placement_order<C, S>(candidates: &[C], score: S) -> Vec<&C>
where
    C: PlacementCandidate,
    S: Fn(&C) -> PlacementScore,
{
    let mut ranked: Vec<&C> = candidates.iter().collect();
    ranked.sort_by(|left, right| {
        score(right)
            .cmp(&score(left))
            .then_with(|| left.placement_key().cmp(right.placement_key()))
    });
    ranked
}
