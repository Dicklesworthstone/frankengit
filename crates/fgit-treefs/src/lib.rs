#![forbid(unsafe_code)]
//! Git `TreeFS` core: immutable base views, capability-scoped copy-on-write
//! overlays, a typed edit-intent log, and workspace snapshots with explicit
//! staged/visible/durable epochs.
//!
//! Normative source: `docs/GIT_TREE_FS.md` (bound as normative for sparse
//! workspaces by `docs/NORMATIVE_PROTOCOL_CONTRACTS.md`, which wins on any
//! conflict).
//!
//! # What this crate is
//!
//! A pure, synchronous, direct-API model of a sparse workspace over immutable
//! Git tree state. It owns:
//!
//! * [`path`] — canonical repository path bytes and the refusals that keep
//!   every access inside a capability root;
//! * [`capability`] — scoping, budgets, and attenuation-only delegation;
//! * [`base`] — the immutable base view over Git tree state, reading through
//!   the caller-implemented [`ObjectSource`] boundary;
//! * [`overlay`] — the capability-scoped copy-on-write overlay;
//! * [`intent`] — the typed edit-intent log and its net-effect evaluation;
//! * [`snapshot`] — workspace snapshots with explicit staged/visible/durable
//!   epochs, plus the anti-rollback refusals;
//! * [`export`] — export planning over a base view and overlay;
//! * [`journal`] — export phases, cancellation state, and the step journal;
//! * [`materialize`] — the reference loose-object layout an export would take,
//!   described and never written;
//! * [`proposal`] — sealed ref intents and position receipts, inert by
//!   construction: a proposal cannot publish itself or infer commit from
//!   object existence;
//! * [`obligation`] — the workspace lease as a typed reserve/commit/abort
//!   obligation;
//! * [`archive`] and [`sparse`] — deterministic derived artifacts (ustar/zip
//!   bytes, sparse manifests) with their own completeness receipts.
//!
//! Every module in that list is real and exercised. It was previously the two
//! entries above plus a forward reference deferring the base view, overlay,
//! edit-intent log and snapshot epochs to bead
//! `frankengit-fg026a-treefs-core-0aw` — which closed on 2026-08-21 with all
//! four delivered. The rule that produced this list stands: a module is named
//! here when it is real, never before.
//!
//! # What this crate is not
//!
//! It does not fetch objects: the object-source boundary is a trait the caller
//! implements, so `TreeFS` decides *what* to read and *whether it is authorised*,
//! then verifies what comes back. It can produce deterministic sparse manifests
//! and archive bytes, but these are derived preparation artifacts, not host
//! adapters. FUSE and sparse-directory writers remain deliberately absent; see
//! `docs/ADR-0017-TREEFS-HOST-ADAPTER-MATRIX.md` for the support matrix.
//!
//! # Load-bearing invariants
//!
//! * A path is refused, never repaired. `..` is not resolved, and a name that
//!   would alias another on the target host is refused rather than silently
//!   mapped.
//! * Prefix containment is component-wise, so `a/bc` is not inside `a/b`.
//! * Discovery is not authorisation, and a capability can only ever be
//!   narrowed.

pub mod archive;
pub mod base;
pub mod capability;
pub mod export;
pub mod intent;
pub mod journal;
pub mod materialize;
pub mod obligation;
pub mod overlay;
pub mod path;
pub mod proposal;
pub mod snapshot;
pub mod sparse;

pub use archive::{
    ArchiveCompleteness, ArchiveProfile, ArchiveReceipt, ArchiveRefusal, ArchiveVerification,
    TarLimits, UstarArchive, ZipArchive, ZipLimits,
};
pub use base::{BaseEntry, BaseError, BaseView, DirectoryListing, ObjectSource, ObjectSourceError};
pub use capability::{
    CapabilityRefusal, GrantScope, ReadGrant, SymlinkPolicy, TreeCapability, WorkspaceId,
    WriteGrant,
};
pub use export::{ExportLimits, ExportPlan, ExportPlanner, ExportRefusal, ExportedObject};
pub use intent::{
    BasisEntry, IntentError, IntentEvaluation, IntentLog, NetEffect, NoOpReason, TreeEditIntent,
    TreeNetEffect,
};
pub use journal::{CancellationState, ExportJournal, ExportPhase, JournalRefusal, JournalStep};
pub use materialize::{Compression, LooseObject, MaterializeRefusal, ReferenceLayout, materialize};
pub use obligation::{
    WorkspaceAbortReason, WorkspaceLease, WorkspaceLeaseAbort, WorkspaceLeaseCommit,
    WorkspaceLeaseReservation,
};
pub use overlay::{
    ContentId, ContentRef, ContentStore, EntryClass, FileMode, Overlay, OverlayEntry,
    OverlayLookup, OverlayStats,
};
pub use path::{HostProfile, MAX_PATH_BYTES, PathPolicy, PathRefusal, TreePath};
pub use proposal::{
    ExpectedRef, PositionReceipt, ProposalRefusal, ProposedRefIntent, ProposedTransaction,
};
pub use snapshot::{
    AntiRollbackRefusal, EpochRefusal, EpochSet, OverlayRoot, SessionRecord, WorkspaceEpoch,
    WorkspaceSnapshotBody,
};
pub use sparse::{
    SparseCompleteness, SparseEntry, SparseEntryKind, SparseLimits, SparseManifest, SparseProfile,
    SparseReceipt, SparseRefusal, SparseVerification,
};
