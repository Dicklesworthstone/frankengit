#![forbid(unsafe_code)]
//! Git TreeFS core: immutable base views, capability-scoped copy-on-write
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
//! * [`capability`] — scoping, budgets, and attenuation-only delegation.
//!
//! The immutable base view, copy-on-write overlay, typed edit-intent log, and
//! snapshot epochs land in this same crate as their modules are completed under
//! bead `frankengit-fg026a-treefs-core-0aw`; each is added to this list when its
//! module is real, never before.
//!
//! # What this crate is not
//!
//! It does not fetch objects: the object-source boundary is a trait the caller
//! implements, so TreeFS decides *what* to read and *whether it is authorised*,
//! then verifies what comes back. FUSE and sparse-directory adapters and
//! export-to-Git belong to FG-026c and FG-052 and are deliberately absent.
//!
//! # Load-bearing invariants
//!
//! * A path is refused, never repaired. `..` is not resolved, and a name that
//!   would alias another on the target host is refused rather than silently
//!   mapped.
//! * Prefix containment is component-wise, so `a/bc` is not inside `a/b`.
//! * Discovery is not authorisation, and a capability can only ever be
//!   narrowed.

pub mod capability;
pub mod path;

pub use capability::{
    CapabilityRefusal, ReadGrant, SymlinkPolicy, TreeCapability, WorkspaceId, WriteGrant,
};
pub use path::{HostProfile, MAX_PATH_BYTES, PathPolicy, PathRefusal, TreePath};
