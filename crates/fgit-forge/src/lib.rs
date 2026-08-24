#![forbid(unsafe_code)]

//! Canonical forge state: events, aggregates, and the atomic merge path.
//!
//! # What is canonical here and what is not
//!
//! Everything in this crate is canonical-side. A forge event is a body whose
//! identity is derived from its bytes, an aggregate version is admitted by
//! conditional replacement of an exact expected version, and a merge publishes
//! as one sealed transaction. None of it reads a projection, and nothing here
//! may become a second source of truth for repository state (`AGENTS.md` 5.1).
//! Web and API projections of forge state are rebuildable read models that live
//! elsewhere and carry the head position they were built from.
//!
//! # The one transaction
//!
//! A merge is not "write the objects, then move the ref, then record that it
//! happened". Those three are one effect package that is admitted together or
//! not at all, because any two of them without the third is a repository state
//! no reader should ever observe: a moved ref with no event is an unexplained
//! history, and an event with no ref movement is a claim about a merge that did
//! not occur. [`MergeEffectPackage`] carries all three, and
//! [`MergeEffectPackage::seal_into_record`] reduces them to a single
//! `RepositoryCommitRecord` carrying both the ref delta root and the forge
//! event batch root.
//!
//! # Layer
//!
//! This crate is L2. It computes and refuses; it does not admit. Admission is
//! L4 and takes the sealed package from here. That split is why nothing in this
//! crate can publish by itself.

pub mod aggregate;
pub mod event;
pub mod merge;

use core::fmt;

pub use aggregate::{AggregateHead, AggregateVersion, ExpectedVersion, PullRequestNumber};
pub use event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload, event_id};
pub use merge::{
    EffectRoots, MergeAttempt, MergeEffectPackage, MergedTree, ObservedTips, RefIntent,
    merge_pull_request_tree,
};

/// Every way this crate declines to produce a forge effect.
///
/// Each variant carries what was expected and what was observed, because a
/// refusal a caller cannot act on is only marginally better than a panic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForgeRefusal {
    /// The aggregate is not at the version the caller required.
    ///
    /// This is the variant that makes concurrent forge writes safe. It is
    /// never resolved by taking the later write: two callers who both believed
    /// they were extending version 7 have produced different histories, and
    /// only one of them can be right.
    VersionConflict {
        /// Version the caller required the aggregate to be at.
        expected: ExpectedVersion,
        /// Version the aggregate is actually at, absent for a new stream.
        observed: Option<AggregateVersion>,
    },
    /// The aggregate counter cannot advance any further.
    VersionExhausted {
        /// The version that has no successor.
        observed: AggregateVersion,
    },
    /// A ref moved out from under a merge that was already computed.
    ///
    /// The merge result describes a repository state that no longer exists, so
    /// admitting it would silently discard whatever moved the ref.
    MergeStale {
        /// Which ref moved.
        reference: MergeSide,
        /// The two tips, boxed.
        ///
        /// A `Digest` carries a maximum-length body inline, so a pair of them
        /// is far and away the largest thing this enum could hold. Left
        /// unboxed, every `Result` in the crate would pay for the rarest
        /// variant on its success path too.
        tips: Box<StaleTips>,
    },
    /// The workspace advanced after the merge was computed in it.
    ///
    /// Supervision means the result is a statement about one workspace at one
    /// epoch. If the workspace has moved on, the tree was computed over content
    /// that is no longer what the workspace holds, and admitting it would
    /// publish a merge nobody can reproduce from the state it names.
    WorkspaceMoved {
        /// Epoch the merge was computed in.
        computed_in: WorkspaceEpoch,
        /// Epoch observed at admission time.
        observed: WorkspaceEpoch,
    },
    /// The three-way merge produced conflicts, so there is no tree to commit.
    MergeConflicted {
        /// How many paths conflicted.
        paths: usize,
    },
    /// The merge engine refused before producing a result.
    MergeRefused {
        /// What the engine reported.
        cause: TreeMergeError,
    },
    /// A body could not be turned into canonical bytes.
    BodyUnrepresentable {
        /// What the codec reported.
        cause: Box<CodecRefusal>,
    },
    /// A body has no identity in this build's domain registry.
    IdentityUnavailable {
        /// Which body.
        body: &'static str,
    },
}

/// The tips a staleness refusal compares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleTips {
    /// Tip the merge was computed against.
    pub computed_against: Digest,
    /// Tip observed at admission time.
    pub observed: Digest,
}

/// Which side of a merge a staleness refusal is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeSide {
    /// The branch being merged from.
    Source,
    /// The branch being merged into.
    Target,
}

impl fmt::Display for MergeSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source => "source",
            Self::Target => "target",
        })
    }
}

impl fmt::Display for ForgeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionConflict { expected, observed } => match observed {
                Some(version) => write!(
                    formatter,
                    "aggregate is at version {version}, caller required {expected}"
                ),
                None => write!(
                    formatter,
                    "aggregate has no events yet, caller required {expected}"
                ),
            },
            Self::VersionExhausted { observed } => {
                write!(formatter, "aggregate version {observed} has no successor")
            }
            Self::MergeStale { reference, tips } => write!(
                formatter,
                "{reference} ref moved from {:?} to {:?} after the merge was computed",
                tips.computed_against, tips.observed
            ),
            Self::WorkspaceMoved {
                computed_in,
                observed,
            } => write!(
                formatter,
                "workspace advanced from epoch {} to {} after the merge was computed in it",
                computed_in.get(),
                observed.get()
            ),
            Self::MergeConflicted { paths } => {
                write!(formatter, "three-way merge left {paths} conflicted paths")
            }
            Self::MergeRefused { cause } => write!(formatter, "merge engine refused: {cause:?}"),
            Self::BodyUnrepresentable { cause } => {
                write!(formatter, "body has no canonical bytes: {cause:?}")
            }
            Self::IdentityUnavailable { body } => {
                write!(formatter, "{body} has no identity in this build")
            }
        }
    }
}

impl core::error::Error for ForgeRefusal {}

use fgit_codec::CodecRefusal;
use fgit_diff::TreeMergeError;
use fgit_treefs::WorkspaceEpoch;
use fgit_types::Digest;
