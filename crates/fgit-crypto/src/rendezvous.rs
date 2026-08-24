//! Scoring for preferred-combiner selection.
//!
//! `frankengit-fg036a`. Supplies the scorer that
//! [`fgit_types::routing::preferred_candidate`] takes as a parameter. The
//! selection policy — highest score, closed tie-break, order independence —
//! lives there and is tested there; this module only decides how a weight is
//! computed.
//!
//! # Why there is no registry row for this
//!
//! Deliberate, and raised on the bead before it was written rather than decided
//! quietly. A rendezvous score is hashed, so it is not a
//! [`crate::NonIdentityTag`] — those are defined as domain-separation prefixes
//! that are *never hashed*. But it is also not an identity: nothing commits to
//! it, nothing verifies it, and no other party ever recomputes it and compares.
//! Giving it an [`crate::IdentityDomain`] row would make it constructible into
//! [`crate::internal_object_id`], which is exactly the "claim in the table the
//! code does not honour" the registry documentation warns against.
//!
//! So it hashes with plain SHA-256 and takes no row. The cost of being wrong
//! about this is bounded and visible: a collision or a bias costs *balance* —
//! some cell gets more keys than its share — and cannot cost soundness, because
//! §5.1 makes routing a hint and every authority-sensitive use re-verifies. If
//! the registry gains a category for hashed non-identity values, this moves
//! into it without any published artifact changing, because nothing is
//! published from here.
//!
//! # Preimage ambiguity, handled rather than assumed away
//!
//! Both inputs are variable-length and one follows the other, so concatenating
//! them plainly would let `("ab", "c")` and `("a", "bc")` score identically —
//! two different cells could then tie on a key for a reason nobody chose. Each
//! field is length-prefixed. This is the same trap
//! [`crate::internal_digest_over_parts`] documents, arrived at independently
//! here because this path does not go through it.

use fgit_types::routing::{
    PlacementCandidate, PlacementScore, placement_order, preferred_candidate,
};

use crate::hashing::{DigestHasher, Sha256Hasher};

/// Domain separation for this computation, inside the preimage.
///
/// Not a registry tag — see the module documentation. It is here so that a
/// score can never coincide with some other SHA-256 over the same two byte
/// strings computed for a different purpose.
const PLACEMENT_PREFIX: &[u8] = b"fgit-rendezvous-placement-v1";

/// Weigh one candidate against one routing key.
///
/// Deterministic across processes and builds: the same two byte strings always
/// produce the same score, which is what lets independent cells agree on a
/// preferred combiner without coordinating.
#[must_use]
pub fn placement_score(candidate_key: &[u8], routing_key: &[u8]) -> PlacementScore {
    let mut hasher = Sha256Hasher::new();
    DigestHasher::update(&mut hasher, PLACEMENT_PREFIX);
    for field in [candidate_key, routing_key] {
        let length = u64::try_from(field.len())
            .expect("a slice length always fits in u64 on supported targets")
            .to_be_bytes();
        DigestHasher::update(&mut hasher, &length);
        DigestHasher::update(&mut hasher, field);
    }
    PlacementScore::from_bytes(DigestHasher::finish(hasher))
}

/// The preferred candidate for a routing key.
///
/// A hint. §5.1 puts routing among the things that guide work and never decide
/// it, so a caller must still verify anything it obtains by going where this
/// points — see [`fgit_types::hint::Hint`].
#[must_use]
pub fn preferred_combiner<'candidates, C>(
    candidates: &'candidates [C],
    routing_key: &[u8],
) -> Option<&'candidates C>
where
    C: PlacementCandidate,
{
    preferred_candidate(candidates, |candidate| {
        placement_score(candidate.placement_key(), routing_key)
    })
}

/// Every candidate for a routing key, most preferred first.
///
/// Uses the same comparator as [`preferred_combiner`], so a caller that falls
/// back to the second entry after a timeout reaches the cell the ranking names
/// rather than a different one.
#[must_use]
pub fn combiner_order<'candidates, C>(
    candidates: &'candidates [C],
    routing_key: &[u8],
) -> Vec<&'candidates C>
where
    C: PlacementCandidate,
{
    placement_order(candidates, |candidate| {
        placement_score(candidate.placement_key(), routing_key)
    })
}
