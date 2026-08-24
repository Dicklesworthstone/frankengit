//! Head-chain freshness: refusing a genuine proof about the wrong moment.
//!
//! `frankengit-fg037b`. Every other check in this crate asks *is this proof
//! valid against the pinned head*. This one asks the question none of them can:
//! **is the pinned head itself the one I should be looking at.**
//!
//! # The attack the rest of the crate cannot see
//!
//! A tampering mirror does not need to forge anything. It replays a head the
//! client legitimately trusted at some earlier point, together with envelopes
//! that verify perfectly against it. The proofs are real. The configuration
//! identifies. The Merkle paths reproduce the root. `PinnedHeadMismatch` does
//! not fire, because there is no mismatch — the envelope and the pin agree
//! exactly. The client reads a consistent, fully proved view of the repository
//! as it was before a ref was deleted, a permission was revoked, or a bad
//! commit was reverted.
//!
//! §5.5 states the rule this implements: *higher acknowledged unresolved roots
//! fail closed; never silently roll back to an older valid root.* "Valid" is
//! the load-bearing word. Validity is not freshness, and a verifier that only
//! checks validity is complete against forgery and blind to replay.
//!
//! # Why a client-side floor, and what it costs
//!
//! Freshness cannot be established from one head in isolation — a head does not
//! carry "and nothing newer exists". It is established by *memory*: a client
//! that has accepted generation N refuses to go back below it. So the floor
//! lives with the client, and the guarantee is relative to what that client has
//! already seen. A fresh client with no floor can still be handed an old head;
//! this policy makes a mirror unable to walk a client *backwards*, which is the
//! part that is actually achievable without a second trusted source.
//!
//! # Three cases that are usually collapsed, and must not be
//!
//! * **Older generation** — a replay. Refuse.
//! * **Same generation, same head identity** — the same head again, which is
//!   ordinary and must be permitted, or a client could not poll twice.
//! * **Same generation, *different* identity** — two distinct heads both
//!   claiming generation N. That is a fork or a forgery, never staleness, and
//!   it is strictly more serious than either. Collapsing it into "not newer, so
//!   refuse as stale" would report a split-brain as a caching artefact.
//!
//! # Advancing is also not one case
//!
//! A head one generation newer carries `predecessor_head_id`, so continuity is
//! checkable: it must name the floor's head. A head *several* generations newer
//! cannot be checked against the floor at all from these two bodies alone — the
//! intermediate heads are absent. That is not proof of a graft, and it is not
//! proof of continuity either, so it gets its own verdict rather than being
//! quietly accepted. A forged head at a *higher* generation is exactly what a
//! generation-only monotonicity check waves through.

use fgit_authority::authority_head_identity;
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_types::identity::RepositoryAuthorityHeadId;
use fgit_types::numeric::HeadGeneration;

use core::fmt;

/// The newest head a client has already accepted.
///
/// Held by value and advanced only through [`HeadChainFloor::accept`], so the
/// floor cannot be lowered by a caller that merely wants a read to succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadChainFloor {
    generation: HeadGeneration,
    identity: RepositoryAuthorityHeadId,
}

impl HeadChainFloor {
    /// Establish a floor from the first head a client decides to trust.
    ///
    /// # Errors
    ///
    /// [`FreshnessRefusal::HeadIdentityUnavailable`] when the head body has no
    /// canonical identity, which makes it unusable as a chain anchor.
    pub fn anchored_to(head: &RepositoryAuthorityHeadBody) -> Result<Self, FreshnessRefusal> {
        Ok(Self {
            generation: head.generation,
            identity: head_identity(head)?,
        })
    }

    /// The generation below which nothing is accepted.
    #[must_use]
    pub const fn generation(&self) -> HeadGeneration {
        self.generation
    }

    /// The identity of the head this floor stands on.
    #[must_use]
    pub const fn identity(&self) -> RepositoryAuthorityHeadId {
        self.identity
    }

    /// Judge an offered head against this floor without moving it.
    ///
    /// # Errors
    ///
    /// The refusals in [`FreshnessRefusal`]; each names what was observed
    /// rather than only that something was wrong, because "stale" and "forked"
    /// call for different operator responses.
    pub fn judge(
        &self,
        offered: &RepositoryAuthorityHeadBody,
    ) -> Result<FreshnessVerdict, FreshnessRefusal> {
        let offered_generation = offered.generation;
        let offered_identity = head_identity(offered)?;

        if offered_generation.get() < self.generation.get() {
            return Err(FreshnessRefusal::StaleHead {
                floor: self.generation,
                offered: offered_generation,
            });
        }

        if offered_generation.get() == self.generation.get() {
            // Same generation. Identity decides whether this is the same head
            // again or two heads claiming one slot.
            return if offered_identity == self.identity {
                Ok(FreshnessVerdict::Reaffirms)
            } else {
                Err(FreshnessRefusal::ForkedAtGeneration {
                    generation: offered_generation,
                })
            };
        }

        // Strictly newer. One step is checkable; a gap is not.
        let step = offered_generation
            .get()
            .saturating_sub(self.generation.get());
        if step > 1 {
            return Ok(FreshnessVerdict::AdvancesAcrossUnverifiedGap {
                from: self.generation,
                to: offered_generation,
            });
        }

        match offered.predecessor_head_id {
            Some(predecessor) if predecessor == self.identity => Ok(FreshnessVerdict::Advances {
                to: offered_generation,
            }),
            Some(predecessor) => Err(FreshnessRefusal::ChainBreak {
                offered: Box::new(predecessor),
            }),
            // A head one past the floor with no predecessor recorded claims to
            // be a genesis head that is not one. That is a break, not a gap.
            None => Err(FreshnessRefusal::PredecessorAbsent {
                generation: offered_generation,
            }),
        }
    }

    /// Judge `offered` and, if it is acceptable, move the floor onto it.
    ///
    /// Returns the verdict that permitted the move. A [`FreshnessVerdict`] is
    /// never a silent success: the caller sees whether continuity was checked
    /// or merely not contradicted.
    ///
    /// # Errors
    ///
    /// The same refusals as [`Self::judge`]. On refusal the floor is unchanged,
    /// so a rejected head cannot lower it.
    pub fn accept(
        &mut self,
        offered: &RepositoryAuthorityHeadBody,
    ) -> Result<FreshnessVerdict, FreshnessRefusal> {
        let verdict = self.judge(offered)?;
        if verdict.moves_the_floor() {
            self.generation = offered.generation;
            self.identity = head_identity(offered)?;
        }
        Ok(verdict)
    }
}

/// Why an offered head was acceptable, and how strongly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshnessVerdict {
    /// Exactly one generation newer, and its `predecessor_head_id` names the
    /// floor. Continuity is established, not assumed.
    Advances {
        /// The generation now accepted.
        to: HeadGeneration,
    },
    /// More than one generation newer. Nothing contradicts continuity and
    /// nothing establishes it either, because the intervening heads are not
    /// present to check.
    ///
    /// Deliberately not folded into [`Self::Advances`]. A caller that needs an
    /// unbroken chain must treat this as insufficient and fetch the gap; one
    /// that only needs monotonicity may proceed. Collapsing the two would make
    /// that choice for every caller, in the permissive direction.
    AdvancesAcrossUnverifiedGap {
        /// The floor before this judgement.
        from: HeadGeneration,
        /// The generation offered.
        to: HeadGeneration,
    },
    /// The same head as the floor, offered again. Ordinary; a client must be
    /// able to poll twice without being told it is being attacked.
    Reaffirms,
}

impl FreshnessVerdict {
    /// Whether accepting this verdict advances the floor.
    ///
    /// [`Self::Reaffirms`] does not: re-accepting the same head must be
    /// idempotent, and treating it as movement would let a repeated identical
    /// answer look like progress.
    #[must_use]
    pub const fn moves_the_floor(self) -> bool {
        matches!(
            self,
            Self::Advances { .. } | Self::AdvancesAcrossUnverifiedGap { .. }
        )
    }

    /// Whether continuity with the floor was positively established.
    #[must_use]
    pub const fn continuity_established(self) -> bool {
        matches!(self, Self::Advances { .. } | Self::Reaffirms)
    }
}

/// Why an offered head was refused on freshness grounds.
///
/// Separate from `VerifiedReadRefusal` on purpose. Every variant there answers
/// "this proof is not valid"; every variant here answers "this proof is valid
/// and about the wrong head". Folding them together would let a caller handle a
/// replayed-but-genuine answer with the same branch it uses for a corrupt path,
/// and those need different responses — one is a retry, the other is an
/// incident.
///
/// `Clone` but not `Copy`: one variant boxes a head identity, see below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreshnessRefusal {
    /// The offered head is older than one already accepted: a replay.
    StaleHead {
        /// The lowest generation this client still accepts.
        floor: HeadGeneration,
        /// What was offered.
        offered: HeadGeneration,
    },
    /// Two distinct heads claim the same generation.
    ForkedAtGeneration {
        /// The contested generation.
        generation: HeadGeneration,
    },
    /// The next head does not name the floor as its predecessor.
    ///
    /// Carries only what the caller does NOT already have. The expected value
    /// is the floor's own identity, reachable through
    /// [`HeadChainFloor::identity`]; duplicating it here would inflate every
    /// `Result` in this module for data the caller is holding when it asks.
    ChainBreak {
        /// The predecessor the offered head named instead.
        ///
        /// Boxed because a `RepositoryAuthorityHeadId` is 152 bytes -- it is a
        /// full internal object identity, not a bare digest -- and an unboxed
        /// one makes every `Result` in this module carry that much on the happy
        /// path. Same reason `OutcomeFailure` boxes its payloads.
        offered: Box<RepositoryAuthorityHeadId>,
    },
    /// A head immediately above the floor recorded no predecessor at all.
    PredecessorAbsent {
        /// The generation offered.
        generation: HeadGeneration,
    },
    /// A head body with no canonical identity cannot anchor or extend a chain.
    HeadIdentityUnavailable,
}

impl fmt::Display for FreshnessRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleHead { floor, offered } => write!(
                formatter,
                "offered head generation {} is older than the accepted floor {}",
                offered.get(),
                floor.get()
            ),
            Self::ForkedAtGeneration { generation } => write!(
                formatter,
                "two distinct heads claim generation {}",
                generation.get()
            ),
            Self::ChainBreak { .. } => formatter
                .write_str("the offered head does not name the accepted head as its predecessor"),
            Self::PredecessorAbsent { generation } => write!(
                formatter,
                "head generation {} records no predecessor but is not a genesis head",
                generation.get()
            ),
            Self::HeadIdentityUnavailable => {
                formatter.write_str("the head body has no canonical identity")
            }
        }
    }
}

impl core::error::Error for FreshnessRefusal {}

/// The canonical identity of a head body.
fn head_identity(
    head: &RepositoryAuthorityHeadBody,
) -> Result<RepositoryAuthorityHeadId, FreshnessRefusal> {
    authority_head_identity(head).map_err(|_| FreshnessRefusal::HeadIdentityUnavailable)
}
