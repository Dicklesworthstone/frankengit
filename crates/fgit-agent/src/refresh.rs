//! Refresh relations: what happened when a workspace stopped floating.
//!
//! `docs/AGENT_PROTOCOL.md` §4.3 is short enough to quote whole, and every type
//! here exists to carry one clause of it:
//!
//! > A workspace never silently floats. Refresh creates a new receipt and one
//! > explicit relation: `FastForwarded`; `RebasedByIntentReplay`;
//! > `RebasedByStructuredPatch`; `MergedByDeclaredProof`; `ConflictRefused`.
//! > The evidence record distinguishes checks performed before and after
//! > refresh.
//!
//! # What this module delivers, and what it deliberately does not
//!
//! It delivers the typed **record** of a refresh and the constraints a machine
//! can check on it: the closed relation set, a receipt binding the base it
//! moved from to the base it moved to, and the before/after distinction that
//! stops a stale check from vouching for a state it never saw.
//!
//! It does **not** perform a refresh. Rebasing, replaying intents, applying a
//! structured patch and merging by declared proof are workspace operations and
//! belong to `fgit-treefs`, which owns the base views, overlay and export
//! boundary. A receipt binds identities; it does not compute them. That split
//! is the reason this is a real slice rather than a stub: §10's ECC bundle has
//! a `refreshed_authority_receipt` field, and the field needs a type with
//! enforced invariants long before anything in this workspace can rebase.
//!
//! # Exactly one relation, by construction rather than by validation
//!
//! §4.3 says a refresh creates "one explicit relation". [`RefreshReceipt`]
//! holds a single [`RefreshRelation`], so zero relations and two relations are
//! both unrepresentable — there is no validator to forget to call and no guard
//! that could rot into unreachability. The refusal that *is* reachable lives at
//! the decode boundary, where bytes arriving from elsewhere can name a relation
//! this build does not define; see [`RefreshRelation::from_code_point`].
//!
//! Stating that plainly matters more than it looks. An acceptance line reading
//! "more than one relation is refused" invites a runtime check that can never
//! fire, and a guard that cannot fire is worse than no guard: it reads as
//! coverage forever.

use core::fmt;

/// The five relations of §4.3. Closed set — a refresh is exactly one of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum RefreshRelation {
    /// The base moved forward and the workspace followed it directly.
    FastForwarded,
    /// The workspace's intents were replayed onto the new base.
    RebasedByIntentReplay,
    /// A structured patch was applied to the new base.
    RebasedByStructuredPatch,
    /// The two sides were merged, and the merge carries a declared proof.
    MergedByDeclaredProof,
    /// The refresh did not happen: the conflict was refused rather than
    /// resolved by guesswork.
    ConflictRefused,
}

impl RefreshRelation {
    /// Every relation, in the order §4.3 lists them.
    pub const ALL: &'static [Self] = &[
        Self::FastForwarded,
        Self::RebasedByIntentReplay,
        Self::RebasedByStructuredPatch,
        Self::MergedByDeclaredProof,
        Self::ConflictRefused,
    ];

    /// Stable wire/report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FastForwarded => "fast_forwarded",
            Self::RebasedByIntentReplay => "rebased_by_intent_replay",
            Self::RebasedByStructuredPatch => "rebased_by_structured_patch",
            Self::MergedByDeclaredProof => "merged_by_declared_proof",
            Self::ConflictRefused => "conflict_refused",
        }
    }

    /// Stable wire code point, assigned explicitly so inserting a relation in
    /// the middle of the enum cannot renumber the ones after it.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::FastForwarded => 1,
            Self::RebasedByIntentReplay => 2,
            Self::RebasedByStructuredPatch => 3,
            Self::MergedByDeclaredProof => 4,
            Self::ConflictRefused => 5,
        }
    }

    /// The relation a code point names, or `None` for one this build does not
    /// define. This is where "exactly one valid relation" is actually enforced.
    #[must_use]
    pub const fn from_code_point(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::FastForwarded),
            2 => Some(Self::RebasedByIntentReplay),
            3 => Some(Self::RebasedByStructuredPatch),
            4 => Some(Self::MergedByDeclaredProof),
            5 => Some(Self::ConflictRefused),
            _ => None,
        }
    }

    /// Whether the workspace actually moved onto the new base.
    ///
    /// [`Self::ConflictRefused`] is a *refusal outcome*: §4.3 lists it beside
    /// the four successes because a refused conflict is a legitimate, recorded
    /// result rather than an error to be papered over. But it means the
    /// workspace did **not** advance, so it must not satisfy a policy that
    /// requires a completed refresh. Keeping that distinction on the enum,
    /// rather than in each caller's `matches!`, is what stops one caller from
    /// quietly treating a refusal as a success.
    #[must_use]
    pub const fn advanced_the_workspace(self) -> bool {
        match self {
            Self::FastForwarded
            | Self::RebasedByIntentReplay
            | Self::RebasedByStructuredPatch
            | Self::MergedByDeclaredProof => true,
            Self::ConflictRefused => false,
        }
    }
}

impl fmt::Display for RefreshRelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which side of a refresh a check was performed on (§4.3, final clause).
///
/// The whole point of recording this is that a check performed against the old
/// base says nothing about the new one. See
/// [`crate::ecc::EvidenceRecordRef`], where an unstated side fails closed
/// rather than being assumed current.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum RefreshSide {
    /// Performed against the base the workspace refreshed *from*.
    BeforeRefresh,
    /// Performed against the base the workspace refreshed *to*.
    AfterRefresh,
}

impl RefreshSide {
    /// Both sides.
    pub const ALL: &'static [Self] = &[Self::BeforeRefresh, Self::AfterRefresh];

    /// Stable wire/report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeRefresh => "before_refresh",
            Self::AfterRefresh => "after_refresh",
        }
    }

    /// Stable wire code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::BeforeRefresh => 1,
            Self::AfterRefresh => 2,
        }
    }

    /// The side a code point names, or `None` for an unknown one.
    #[must_use]
    pub const fn from_code_point(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::BeforeRefresh),
            2 => Some(Self::AfterRefresh),
            _ => None,
        }
    }
}

impl fmt::Display for RefreshSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The receipt §4.3 requires a refresh to create.
///
/// `from_base` and `to_base` are opaque authority-basis identities, compared
/// only for equality. Holding both is what makes the receipt a *witness* rather
/// than an assertion: a reader can check that the state a bundle claims to
/// build on is the one the refresh actually arrived at, instead of taking
/// "refreshed" on trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RefreshReceipt {
    /// Exactly one relation. Zero and two are unrepresentable.
    pub relation: RefreshRelation,
    /// The authority basis the workspace refreshed from.
    pub from_base: u128,
    /// The authority basis the workspace refreshed to.
    ///
    /// For [`RefreshRelation::ConflictRefused`] the workspace did not move, so
    /// this is the base it *would* have moved to — the target that was refused,
    /// which is the useful thing to record.
    pub to_base: u128,
}

impl RefreshReceipt {
    /// Whether this receipt records a refresh that actually completed.
    #[must_use]
    pub const fn advanced(&self) -> bool {
        self.relation.advanced_the_workspace()
    }

    /// Whether the refresh was a no-op in the sense that matters: it did not
    /// change the basis.
    ///
    /// A `FastForwarded` receipt whose two bases are equal did not move
    /// anything, and evidence gathered before it is still current. Callers that
    /// need to know whether re-validation is owed should ask this rather than
    /// inferring it from the relation alone.
    #[must_use]
    pub const fn changed_basis(&self) -> bool {
        self.from_base != self.to_base
    }
}
