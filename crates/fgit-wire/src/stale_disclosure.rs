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

use fgit_types::cell::ReadLabel;

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

    /// Take the refs, keeping the label's constraint visible at the call site.
    #[must_use]
    pub fn into_parts(self) -> (Vec<AdvertisedRef>, ReadLabel) {
        (self.refs, self.label)
    }
}

/// Narrow a served ref set to what the **current** policy permits, and label it.
///
/// `served` is whatever the cell verified — at the current head for
/// [`fgit_types::cell::ReadMode::Current`], at an older one otherwise.
/// `current_visibility` must be the policy in force **now**; passing the policy
/// that was in force at the served head is the defect this module exists to
/// prevent, and is why no parameter accepts one.
#[must_use]
pub fn advertise_under_read_label(
    served: &[AdvertisedRef],
    current_visibility: &RefVisibility,
    label: ReadLabel,
) -> LabelledAdvertisement {
    LabelledAdvertisement {
        refs: filter_advertised_refs(served, current_visibility),
        label,
    }
}
