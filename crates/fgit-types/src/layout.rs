//! How each authenticated root in a repository head is laid out.
//!
//! An authority head carries several roots — `ref_root`, `outcome_index_root`,
//! `forge_position_root` and the rest — and every one of them is a
//! [`Digest`](crate::hash::Digest) with no self-description. A digest cannot
//! say whether it commits to a whole canonical body or to the apex of a Merkle
//! tree, and the difference decides whether a client can be handed a
//! *membership proof* for one ref without being handed every ref.
//!
//! [`RootLayoutVersion`] is that missing statement, as one authoritative typed
//! value rather than a convention each verifier reimplements.
//!
//! # Why version 0 is the legacy layout and not an error
//!
//! Every root published before this vocabulary existed is a digest over the
//! whole canonical body. That layout is not wrong — it is a sound commitment,
//! and it is what the heads in existing histories carry. It simply admits no
//! membership proof, because there is no tree to walk.
//!
//! So [`RootLayoutVersion::LegacyWholeBody`] is code point **0**, deliberately,
//! and a head that names no layout means exactly that layout. Migration is then
//! an ordinary head transition that publishes a different version, never a
//! rewrite of published bytes.
//!
//! That choice has a cost worth naming: **a zeroed or defaulted field decodes
//! as a valid member** rather than being refused, which is the opposite of how
//! the other closed vocabularies in this crate behave. It is correct here only
//! because "absent" and "legacy" genuinely denote the same layout. Do not copy
//! the pattern into a vocabulary where they would not.
//!
//! # What this type does not decide
//!
//! It names a layout; it does not compute one. Root construction, proof
//! generation, and verification live in `fgit-crypto`, which is the lowest
//! crate that can hash. This crate's job is that the *name* has one definition.
//!
//! # Typed non-claim: `forge_position_root`
//!
//! This vocabulary says nothing about how `forge_position_root` is laid out,
//! and neither [`RootLayoutVersion::RefStateMerkleV1`] nor
//! [`RootLayoutVersion::RefStateAndObjectClosureMerkleV1`] changes it.
//!
//! A Merkle layout for forge positions needs a canonical forge materialisation
//! to commit to. `frankengit-fg029a` landed one while this was being written,
//! so the *prerequisite* now exists — but the layout itself is still undesigned,
//! and designing it was explicitly outside this work. Adding a version for it
//! here would be a commitment shape chosen without reading what fg029a actually
//! materialises, which is how a parallel root gets published that nothing
//! produces.
//!
//! Recorded as a non-claim rather than a TODO because the distinction matters:
//! a reader must be able to tell "not yet designed" from "designed and
//! unimplemented". Code point 2 went to the object closure, which had a
//! materialisation to commit to; code point 3 is allocated to the
//! forge-position layout and is not defined here. Do not take the next free
//! integer for something else.

use crate::error::TypeRefusal;

/// Which layout an authenticated root in a repository head uses.
///
/// A closed vocabulary: an unrecognised code point is a typed refusal, never a
/// silent fall back to a default member. A peer speaking a newer layout is
/// refused rather than misread — reading a Merkle apex as a whole-body digest
/// would produce a confident wrong answer about what the repository contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum RootLayoutVersion {
    /// Every root is a digest over the whole canonical body it commits to.
    ///
    /// Sound, and it admits **no** membership proof: there is no tree, so
    /// proving one ref means handing over every ref. This is the default
    /// because a head that names no layout is carrying exactly this one.
    #[default]
    LegacyWholeBody,
    /// The ref state is a domain-separated Merkle tree over its entries,
    /// sorted by ref name with a closed tie-break, admitting membership proofs.
    ///
    /// Other roots are unchanged from [`Self::LegacyWholeBody`] under this
    /// version. The layout advances one root at a time on purpose: a version
    /// that changed several at once could not be adopted until every consumer
    /// of every one of them was ready.
    RefStateMerkleV1,
    /// Everything [`Self::RefStateMerkleV1`] admits, **plus** membership and
    /// ordered-absence proofs over the object closure, whose entries are
    /// domain-separated Merkle leaves sorted with a closed tie-break.
    ///
    /// Cumulative, not parallel: a client that can read version one reads the
    /// ref state here identically. Only the object closure changes.
    ///
    /// # Why this needed a new code point rather than a wider version one
    ///
    /// Version one's own documentation says every other root is unchanged from
    /// the legacy layout, so under it the object closure root *is* a whole-body
    /// digest. Teaching version one to admit an object proof would assign new
    /// semantics to bytes already published under that code point — the
    /// key-reuse shape the normative contract requires to fail closed — and a
    /// peer that had already stored a version-one head would read the new
    /// meaning out of old bytes. Migration is a head transition that publishes
    /// a different version, never a redefinition of one.
    ///
    /// # Typed non-claim: what this code point does not yet establish
    ///
    /// This member says which proof families a layout *admits*. It does not by
    /// itself say that an admitted proof checks against a root the authority
    /// head authenticates, and today it does not: the object closure root is
    /// not a head field at all. It is a field of the `RepositoryCommitRecord`
    /// the head merely *names* through `latest_committed_rcr_id`, and that
    /// field is simultaneously the immutable content address the validated
    /// closure frame is staged under and read back by. Those two roles must
    /// agree, so moving that commitment to a Merkle apex is a change to where
    /// the closure is keyed and when the layout is resolved — not a change to
    /// this vocabulary.
    ///
    /// Until that migration lands, adopting this code point makes object proofs
    /// *servable*; it does not make them *authority-bound*. Recorded here
    /// rather than left to a reader's assumption, because the difference is the
    /// whole security property, and a version number that quietly implied the
    /// stronger reading would be the more expensive mistake.
    ///
    /// # Adoption must be coupled to a fresh commit record
    ///
    /// Every other root this vocabulary names is a field of the authority head
    /// body, recomputed by the transition that publishes it, so it can never be
    /// older than the layout describing it. The object closure root is not. A
    /// transition carrying only refused decisions publishes no commit record
    /// and carries the predecessor's id forward, so a head could otherwise
    /// adopt this version while still naming a record written under an earlier
    /// one. A non-genesis successor should therefore move to this version only
    /// in a transition that also publishes a commit record computed under it;
    /// later refusal-only successors then preserve the pairing inductively.
    /// That invariant belongs where head transitions are validated — this crate
    /// names a layout, it does not police publication.
    RefStateAndObjectClosureMerkleV1,
}

impl RootLayoutVersion {
    /// Every member, in stable code-point order.
    pub const ALL: &'static [Self] = &[
        Self::LegacyWholeBody,
        Self::RefStateMerkleV1,
        Self::RefStateAndObjectClosureMerkleV1,
    ];

    /// Compile-time completeness guard for [`RootLayoutVersion::ALL`].
    ///
    /// `ALL` is written by hand and the tests that assert a property of *every*
    /// layout version iterate it, so a variant missing from the array is not a
    /// failing test — it is a silently smaller corpus under a test whose name
    /// says "every". This match is exhaustive with no wildcard, so a new
    /// variant fails to compile **here**, beside the array that has to change.
    ///
    /// It cannot force the variant to be *added* to `ALL`, only to be
    /// considered. That is the honest limit and it is strictly more than the
    /// array had before.
    ///
    /// DELETION CONDITION: goes if `ALL` ever becomes derived rather than
    /// maintained, at which point the array cannot drift and this is dead
    /// weight.
    const fn _every_root_layout_version_is_listed(value: Self) {
        match value {
            Self::LegacyWholeBody
            | Self::RefStateMerkleV1
            | Self::RefStateAndObjectClosureMerkleV1 => (),
        }
    }

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::LegacyWholeBody => 0,
            Self::RefStateMerkleV1 => 1,
            Self::RefStateAndObjectClosureMerkleV1 => 2,
        }
    }

    /// Recovers a member from its wire code point.
    ///
    /// # Errors
    ///
    /// [`TypeRefusal::CodePointUnknown`] for a code point this build does not
    /// know. A newer layout is refused rather than approximated.
    pub fn from_code_point(code_point: u16) -> Result<Self, TypeRefusal> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code_point() == code_point)
            .ok_or_else(|| TypeRefusal::CodePointUnknown {
                field: "RootLayoutVersion",
                observed: u32::from(code_point),
            })
    }

    /// Whether this layout admits a membership proof for the ref state.
    ///
    /// [`Self::LegacyWholeBody`] does not, and that is a property of the
    /// layout rather than a gap in the implementation: a digest over the whole
    /// body has no interior to walk. A caller asking for a proof under it
    /// should be refused, not handed an empty proof that verifies vacuously.
    #[must_use]
    pub const fn admits_ref_state_membership_proof(self) -> bool {
        match self {
            Self::LegacyWholeBody => false,
            Self::RefStateMerkleV1 | Self::RefStateAndObjectClosureMerkleV1 => true,
        }
    }

    /// Whether this layout admits a membership proof for the object closure.
    ///
    /// Only [`Self::RefStateAndObjectClosureMerkleV1`] does.
    /// [`Self::LegacyWholeBody`] does not because a whole-body digest cannot be
    /// walked with a sibling path — and [`Self::RefStateMerkleV1`] does not for
    /// exactly the same reason: it advances the *ref state* only, and its own
    /// documentation says every other root is unchanged from the legacy layout,
    /// so under it the object closure root is still a whole-body digest.
    ///
    /// # This is a refusal, not a false answer
    ///
    /// Callers gate on this before verifying, and the distinction they draw is
    /// load-bearing. `false` here means "this layout has no object tree, so the
    /// question is unanswerable" and must surface as a typed refusal. Returning
    /// a verification result of `false` instead would say "that object is not
    /// in the closure", which is a different and unsupported claim — a caller
    /// told that could retry with another proof forever, since no proof can
    /// ever verify against a digest with no interior.
    #[must_use]
    pub const fn admits_object_closure_membership_proof(self) -> bool {
        match self {
            Self::LegacyWholeBody | Self::RefStateMerkleV1 => false,
            Self::RefStateAndObjectClosureMerkleV1 => true,
        }
    }
}
