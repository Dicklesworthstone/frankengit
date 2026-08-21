//! Classifying a capsule that may be damaged, without inventing state.
//!
//! [`crate::recovery`] answers *what recovery may do* once someone has decided
//! whether the acknowledged capsule verified. It takes that verdict as an
//! argument and is deliberately unable to reach an older capsule. This module
//! is the step before it: given a capsule and what was actually found on disk,
//! it produces the verdict, and it separates two outcomes that a single
//! "invalid" would fatally conflate.
//!
//! # Repair reconstructs bytes; it cannot reconstruct a position
//!
//! A capsule can fail for two very different reasons.
//!
//! Some failures are *missing data*: an object body absent, a segment ending
//! early. If the capsule was written under
//! [`BackupProfile::FullClosureWithRepair`], repair symbols exist that were
//! generated precisely to survive that loss, and reconstruction is a real
//! option a human can authorize.
//!
//! Other failures are *the capsule lying about which position it holds*: the
//! recomputed identity does not match the identity it is stored under, or it
//! names a predecessor that is not the one it actually succeeds. No quantity of
//! repair symbols addresses those. Erasure-coded parity rebuilds bytes; it does
//! not make a capsule be a checkpoint of a different head than the one it
//! claims. Treating an authenticity or ordering failure as
//! "recoverable-with-repair" would invite an operator to reconstruct their way
//! into a repository whose canonical position is a forgery.
//!
//! So [`RestoreClassification::RecoverableWithRepair`] requires **both** that
//! every defect is of the reconstructible kind **and** that the capsule
//! actually declares repair material. A capsule with a missing body but no
//! repair profile is [`RestoreClassification::FailClosed`] — there is nothing
//! to repair *from*, and saying otherwise would be a claim with no material
//! behind it.
//!
//! # This never widens what automation may do
//!
//! Both damaged classifications map to
//! [`CapsuleVerification::PresentButUnverified`], so [`crate::plan_recovery`]
//! halts for audit either way. The repair distinction informs the human who
//! reads the receipt; it does not give a program a new path. That is
//! deliberate: the whole safety property of section 23 is that nothing
//! automatic retreats from an unverifiable acknowledged root, and a
//! classifier that let automation "just repair" would be that retreat wearing
//! a different name.

use core::fmt;

use fgit_types::{Digest, RepositoryCapsuleId};

use crate::capsule::{BackupProfile, RepositoryCapsuleBody};
use crate::recovery::CapsuleVerification;

/// One defect found while checking a capsule against what was found on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapsuleDefect {
    /// An object body the closure names is not present.
    ObjectBodyMissing {
        /// The closure root whose members could not all be resolved.
        closure_root: Digest,
        /// How many bodies were missing.
        missing: u32,
    },
    /// A segment's bytes end before its manifest says they should.
    SegmentTruncated {
        /// Bytes the manifest declares.
        declared_len: u64,
        /// Bytes actually present.
        observed_len: u64,
    },
    /// The segment manifests present do not hash to the declared root.
    SegmentManifestCorrupt {
        /// Root the capsule declares.
        declared: Digest,
        /// Root recomputed from the manifests found.
        observed: Digest,
    },
    /// The capsule's recomputed identity is not the one it is stored under.
    ///
    /// Never repairable. This is the capsule claiming to be a checkpoint it is
    /// not.
    IdentityMismatch {
        /// Identity the capsule is stored under.
        declared: RepositoryCapsuleId,
        /// Identity recomputed from the body.
        recomputed: RepositoryCapsuleId,
    },
    /// The capsule names a predecessor other than the one it actually follows.
    ///
    /// Never repairable. A chain with the wrong predecessor is a different
    /// history, not a damaged one.
    PredecessorStale {
        /// Predecessor the capsule names.
        named: Option<RepositoryCapsuleId>,
        /// Predecessor the pointer chain requires.
        expected: Option<RepositoryCapsuleId>,
    },
}

impl CapsuleDefect {
    /// Whether repair material could, in principle, address this defect.
    ///
    /// The three data-loss defects are reconstructible; the two
    /// authenticity/ordering defects are not, and no profile changes that.
    #[must_use]
    pub const fn is_reconstructible(self) -> bool {
        match self {
            Self::ObjectBodyMissing { .. }
            | Self::SegmentTruncated { .. }
            | Self::SegmentManifestCorrupt { .. } => true,
            Self::IdentityMismatch { .. } | Self::PredecessorStale { .. } => false,
        }
    }

    /// Stable lowercase name for receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectBodyMissing { .. } => "object_body_missing",
            Self::SegmentTruncated { .. } => "segment_truncated",
            Self::SegmentManifestCorrupt { .. } => "segment_manifest_corrupt",
            Self::IdentityMismatch { .. } => "identity_mismatch",
            Self::PredecessorStale { .. } => "predecessor_stale",
        }
    }
}

impl fmt::Display for CapsuleDefect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The most defects one classification will carry.
///
/// A bound rather than an unbounded vector because this value is produced
/// while inspecting untrusted, possibly hostile bytes, and a report that grows
/// with the damage is a resource the damage controls. Past the bound the
/// classification is still correct — the capsule fails closed either way — and
/// [`RestoreClassification::truncated`] says the list was cut.
pub const MAX_REPORTED_DEFECTS: usize = 16;

/// What a restore attempt may do with this capsule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreClassification {
    outcome: RestoreOutcome,
    defects: Vec<CapsuleDefect>,
    truncated: bool,
    profile: BackupProfile,
}

/// The three outcomes a damaged-capsule check can reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestoreOutcome {
    /// No defects. Restore may proceed.
    Restorable,
    /// Every defect is reconstructible and the capsule declares repair
    /// material. A human may authorize reconstruction.
    RecoverableWithRepair,
    /// Restore must not proceed: a defect no repair addresses, or no repair
    /// material to draw on.
    FailClosed,
}

impl RestoreOutcome {
    /// Stable lowercase name for receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restorable => "restorable",
            Self::RecoverableWithRepair => "recoverable_with_repair",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl RestoreClassification {
    /// Classifies a capsule from the defects found against it.
    ///
    /// The rule, stated once so it cannot drift between call sites: repair is
    /// available only when every defect is reconstructible **and** the capsule
    /// was written under [`BackupProfile::FullClosureWithRepair`].
    #[must_use]
    pub fn classify(capsule: &RepositoryCapsuleBody, found: &[CapsuleDefect]) -> Self {
        let profile = capsule.backup_profile;
        let truncated = found.len() > MAX_REPORTED_DEFECTS;
        let mut defects: Vec<CapsuleDefect> =
            found.iter().take(MAX_REPORTED_DEFECTS).copied().collect();
        defects.sort_unstable();
        defects.dedup();

        // Reconstructibility is judged over EVERY defect found, not over the
        // truncated list. A report cut at the bound must never look cleaner
        // than the damage actually is.
        let all_reconstructible = found.iter().all(|defect| defect.is_reconstructible());
        let has_repair_material = matches!(profile, BackupProfile::FullClosureWithRepair);

        let outcome = if found.is_empty() {
            RestoreOutcome::Restorable
        } else if all_reconstructible && has_repair_material {
            RestoreOutcome::RecoverableWithRepair
        } else {
            RestoreOutcome::FailClosed
        };

        Self {
            outcome,
            defects,
            truncated,
            profile,
        }
    }

    /// The outcome.
    #[must_use]
    pub const fn outcome(&self) -> RestoreOutcome {
        self.outcome
    }

    /// The defects found, sorted and deduplicated, bounded by
    /// [`MAX_REPORTED_DEFECTS`].
    #[must_use]
    pub fn defects(&self) -> &[CapsuleDefect] {
        &self.defects
    }

    /// Whether the defect list was cut at the bound.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// The capsule's declared backup profile.
    #[must_use]
    pub const fn profile(&self) -> BackupProfile {
        self.profile
    }

    /// The verdict [`crate::plan_recovery`] consumes.
    ///
    /// Both damaged outcomes report
    /// [`CapsuleVerification::PresentButUnverified`]. Repair is a decision a
    /// person makes on the record, never a path automation may take, so the
    /// distinction deliberately does not survive into the planner.
    #[must_use]
    pub const fn verification(&self) -> CapsuleVerification {
        match self.outcome {
            RestoreOutcome::Restorable => CapsuleVerification::Verified,
            RestoreOutcome::RecoverableWithRepair | RestoreOutcome::FailClosed => {
                CapsuleVerification::PresentButUnverified
            }
        }
    }

    /// One NDJSON receipt line.
    ///
    /// Fixed key order, no floats, no map iteration, and every defect rendered
    /// by its stable name, so two runs over one fixture produce identical
    /// bytes. Written by hand rather than through a serializer because this
    /// crate takes no serialization dependency and the shape is fixed.
    #[must_use]
    pub fn to_ndjson_line(&self) -> String {
        let mut line = String::with_capacity(128);
        line.push_str("{\"outcome\":\"");
        line.push_str(self.outcome.as_str());
        line.push_str("\",\"profile\":\"");
        line.push_str(self.profile.as_str());
        line.push_str("\",\"defect_count\":");
        line.push_str(&self.defects.len().to_string());
        line.push_str(",\"truncated\":");
        line.push_str(if self.truncated { "true" } else { "false" });
        line.push_str(",\"defects\":[");
        for (index, defect) in self.defects.iter().enumerate() {
            if index > 0 {
                line.push(',');
            }
            line.push('"');
            line.push_str(defect.as_str());
            line.push('"');
        }
        line.push_str("]}");
        line
    }
}
