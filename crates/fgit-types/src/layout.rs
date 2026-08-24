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
//! and [`RootLayoutVersion::RefStateMerkleV1`] does not change it.
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
//! unimplemented". This is the first, and the next version number is free.

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
}

impl RootLayoutVersion {
    /// Every member, in stable code-point order.
    pub const ALL: &'static [Self] = &[Self::LegacyWholeBody, Self::RefStateMerkleV1];

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
            Self::LegacyWholeBody | Self::RefStateMerkleV1 => (),
        }
    }

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::LegacyWholeBody => 0,
            Self::RefStateMerkleV1 => 1,
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
            Self::RefStateMerkleV1 => true,
        }
    }
}
