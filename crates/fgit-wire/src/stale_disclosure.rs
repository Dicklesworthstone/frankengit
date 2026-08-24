//! Advertising under a read mode, so a stale answer cannot widen disclosure.
//!
//! `frankengit-fg036a`, acceptance line 2. Plan §22.5 ends with the rule this
//! module exists to make unavoidable: *a stale projection never expands
//! disclosure.*
//!
//! # The mistake this prevents
//!
//! A cell serving a bounded-stale answer holds two things that both look like
//! authorization state: the ref set it verified at the older head, and the
//! visibility policy in force when that head was current. Filtering the older
//! refs with the older policy is the natural thing to write, and it is wrong.
//! A ref hidden since that head would be advertised again, and the client would
//! receive, from a live server, a disclosure the current policy withdrew. The
//! staleness the client agreed to is about *currentness of content*, never
//! about *who may see what*.
//!
//! So the policy argument here is the current one by construction, and the
//! served refs are only ever the input being narrowed. There is no parameter
//! that accepts a historical policy, because a function that took both would
//! eventually be called with them the wrong way round.
//!
//! # Why every mode goes through this, not just bounded-stale
//!
//! Snapshot and offline reads are staler than bounded-stale ones, not fresher.
//! Exempting them because they make no currentness claim would confuse two
//! different promises: how old the content is, and who is allowed to see it.
//! Current reads pass through unchanged in effect, which costs nothing and
//! means no caller has to decide whether the gate applies.

use fgit_types::cell::{ReadLabel, ServingCell};

use crate::AdvertisedRef;
use crate::visibility::{RefVisibility, filter_advertised_refs};

/// An advertisement together with the label that describes its currentness.
///
/// The two travel together because separating them is how a stale answer ends
/// up presented as a fresh one: a caller holding a bare `Vec<AdvertisedRef>`
/// has nothing to attach the mode to, and the label becomes something the
/// transport is trusted to remember.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelledAdvertisement {
    refs: Vec<AdvertisedRef>,
    label: ReadLabel,
    served_by: ServingCell,
}

impl LabelledAdvertisement {
    /// The refs the client may be told about.
    #[must_use]
    pub fn refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    /// How current this answer is, and under what bound.
    #[must_use]
    pub const fn label(&self) -> ReadLabel {
        self.label
    }

    /// Which cell produced this answer, or the explicit fact that none named
    /// itself.
    ///
    /// `frankengit-1egm`. Travels with the label for the same reason the label
    /// travels with the refs: a caller holding the parts separately has nothing
    /// to attach provenance to, and "which cell served this?" becomes something
    /// the transport is trusted to remember.
    ///
    /// This names who answered. It authorizes nothing — the identity inside is
    /// a [`fgit_types::hint::Hint`], so reaching the bare `CellId` requires
    /// saying what verified it.
    #[must_use]
    pub const fn served_by(&self) -> ServingCell {
        self.served_by
    }

    /// Take the refs, keeping the label's constraint visible at the call site.
    #[must_use]
    pub fn into_parts(self) -> (Vec<AdvertisedRef>, ReadLabel) {
        (self.refs, self.label)
    }
}

/// Narrow a served ref set to what the **current** policy permits, and label
/// it, without naming a serving cell.
///
/// Equivalent to [`advertise_under_read_label_served_by`] with
/// [`ServingCell::Unidentified`]. Kept at its original signature deliberately:
/// adding a required parameter would have been a behaviour change for every
/// caller, and `fgit-node`'s call site was under an active edit by another
/// agent when this landed. An advertisement built here genuinely has no cell
/// identity, so it records that as a fact rather than as a `None` a later
/// reader could mistake for one that went missing.
#[must_use]
pub fn advertise_under_read_label(
    served: &[AdvertisedRef],
    current_visibility: &RefVisibility,
    label: ReadLabel,
) -> LabelledAdvertisement {
    advertise_under_read_label_served_by(
        served,
        current_visibility,
        label,
        ServingCell::Unidentified,
    )
}

/// Narrow a served ref set to what the **current** policy permits, label it,
/// and record which cell answered.
///
/// `served` is whatever the cell verified — at the current head for
/// [`fgit_types::cell::ReadMode::Current`], at an older one otherwise.
/// `current_visibility` must be the policy in force **now**; passing the policy
/// that was in force at the served head is the defect this module exists to
/// prevent, and is why no parameter accepts one.
///
/// `served_by` is provenance, not authorization: it says who produced this
/// answer so an operator auditing a multi-cell deployment can find the cell
/// that drifted. Nothing in this function consults it, and the identity inside
/// [`ServingCell::Identified`] is a hint precisely so that a serving path
/// cannot start treating a cell's claim about itself as a permission.
#[must_use]
pub fn advertise_under_read_label_served_by(
    served: &[AdvertisedRef],
    current_visibility: &RefVisibility,
    label: ReadLabel,
    served_by: ServingCell,
) -> LabelledAdvertisement {
    LabelledAdvertisement {
        refs: filter_advertised_refs(served, current_visibility),
        label,
        served_by,
    }
}
