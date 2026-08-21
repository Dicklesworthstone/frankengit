//! Capability scoping for workspace access.
//!
//! `docs/GIT_TREE_FS.md` §4 and §15: a `TreeCapability` binds identity, path
//! prefixes, symlink policy, and budgets. Two properties are load-bearing and
//! are enforced here rather than left to callers:
//!
//! * **Discovery is not authorisation.** Learning that a path exists — from
//!   search, a graph query, a directory listing — grants nothing. Every byte
//!   read goes through [`TreeCapability::authorize_read`], and a lazy fetch
//!   rechecks the capability at the moment it would reveal bytes.
//! * **Repository content cannot widen a capability.** No method on this type
//!   takes repository bytes as input. A capability is narrowed by
//!   [`TreeCapability::attenuate`] and never widened at all, so a prompt, a
//!   config file, or a symlink target has no path to more authority.

use crate::path::TreePath;
use core::fmt::{self, Display, Formatter};
use fgit_types::{ByteCount, RepositoryId};
use std::sync::{Arc, Mutex};

/// Identity of one workspace.
///
/// Opaque and assigned, never derived from content, so two workspaces over the
/// same base are still distinct subjects.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceId([u8; 16]);

impl WorkspaceId {
    /// Wraps raw identity bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Display for WorkspaceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// How symlink entries may be used.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymlinkPolicy {
    /// Symlink entries are readable as link-text data and are never traversed.
    ///
    /// This is the default because `docs/GIT_TREE_FS.md` §15 states the rule
    /// plainly: repository symlinks are data, not host traversal authority.
    #[default]
    DataOnly,
    /// Symlink entries are refused outright.
    Refuse,
}

/// Why an access was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityRefusal {
    /// The path lies outside every readable prefix.
    ReadOutsideScope {
        /// The refused path.
        path: TreePath,
    },
    /// The path lies outside every writable prefix.
    WriteOutsideScope {
        /// The refused path.
        path: TreePath,
    },
    /// The capability has expired.
    Expired {
        /// The capability's expiry tick.
        expires_at: u64,
        /// The tick presented as "now".
        observed: u64,
    },
    /// The capability was revoked.
    Revoked,
    /// A symlink was encountered and the policy refuses them.
    SymlinkRefused {
        /// The refused path.
        path: TreePath,
    },
    /// Serving this read would exceed the fetch-byte budget.
    FetchBudgetExceeded {
        /// Bytes already served.
        consumed: u64,
        /// Bytes this request would add.
        requested: u64,
        /// Configured ceiling.
        budget: u64,
    },
    /// Serving this read would exceed the file-count budget.
    FileBudgetExceeded {
        /// Files already served.
        consumed: u64,
        /// Configured ceiling.
        budget: u64,
    },
    /// The capability belongs to a different repository.
    RepositoryMismatch,
    /// An attenuation attempted to widen scope.
    AttenuationWouldWiden {
        /// The prefix that is not contained by the parent capability.
        path: TreePath,
    },
}

impl Display for CapabilityRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOutsideScope { path } => write!(formatter, "read outside scope: {path}"),
            Self::WriteOutsideScope { path } => write!(formatter, "write outside scope: {path}"),
            Self::Expired {
                expires_at,
                observed,
            } => write!(
                formatter,
                "capability expired at {expires_at}, now {observed}"
            ),
            Self::Revoked => write!(formatter, "capability revoked"),
            Self::SymlinkRefused { path } => write!(formatter, "symlink refused: {path}"),
            Self::FetchBudgetExceeded {
                consumed,
                requested,
                budget,
            } => write!(
                formatter,
                "fetch budget exceeded: {consumed}+{requested} over {budget}"
            ),
            Self::FileBudgetExceeded { consumed, budget } => {
                write!(formatter, "file budget exceeded: {consumed} over {budget}")
            }
            Self::RepositoryMismatch => write!(formatter, "capability is for another repository"),
            Self::AttenuationWouldWiden { path } => {
                write!(formatter, "attenuation would widen scope at {path}")
            }
        }
    }
}

impl core::error::Error for CapabilityRefusal {}

/// Proof that one specific read was authorised.
///
/// Held by value and consumed by the object source, so an authorisation cannot
/// be reused for a second path by accident.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadGrant {
    workspace_id: WorkspaceId,
    scope: GrantScope,
}

/// What a read grant covers.
///
/// The repository root has no path of its own, so authorising a root listing
/// cannot go through a path check. An earlier revision faked one by inventing a
/// `.treefs-root` path and authorising *that*, which meant every root listing
/// was refused unless a capability happened to name the fabricated path. That
/// is why this is a typed scope rather than a `TreePath` with a magic value:
/// the root is a different kind of subject, not a strangely-named path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantScope {
    /// The repository root tree itself.
    Root,
    /// One exact path.
    Path(TreePath),
}

impl ReadGrant {
    /// The workspace this grant belongs to.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// What this grant covers.
    #[must_use]
    pub const fn scope(&self) -> &GrantScope {
        &self.scope
    }

    /// The exact path this grant authorises, or `None` for the root.
    #[must_use]
    pub const fn path(&self) -> Option<&TreePath> {
        match &self.scope {
            GrantScope::Root => None,
            GrantScope::Path(path) => Some(path),
        }
    }
}

/// Proof that one specific write was authorised.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteGrant {
    workspace_id: WorkspaceId,
    path: TreePath,
}

impl WriteGrant {
    /// The workspace this grant belongs to.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// The exact path this grant authorises.
    #[must_use]
    pub const fn path(&self) -> &TreePath {
        &self.path
    }
}

/// Consumption shared across one delegation tree.
///
/// The budget belongs to the tree, not to each capability in it. Copying the
/// counter into every child let two siblings each spend the same remaining
/// allowance, so a parent holding ten bytes with two already spent could issue
/// two children that between them spent sixteen. Narrowing scope must never
/// multiply spend, and a budget that resets per delegation is not a budget.
///
/// Held behind `Arc<Mutex<..>>` so the two counters move together: files and
/// bytes are checked as one decision, and a partial update would let a refused
/// charge still consume the file slot.
#[derive(Clone, Debug, Default)]
struct FetchLedger {
    counters: Arc<Mutex<FetchCounters>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FetchCounters {
    bytes: u64,
    files: u64,
}

impl FetchLedger {
    fn new() -> Self {
        Self::default()
    }

    /// Reads the tree-wide totals.
    ///
    /// A poisoned mutex is recovered rather than propagated: the counters are
    /// plain integers with no invariant a panic could have broken mid-update,
    /// and turning a budget check into a panic would be a worse failure than
    /// the one that poisoned it.
    fn get(&self) -> FetchCounters {
        *self
            .counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Charges the tree-wide totals if both ceilings admit the charge.
    fn charge(&self, bytes: u64, max_bytes: u64, max_files: u64) -> Result<(), FetchCounters> {
        let mut guard = self
            .counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_files = guard.files.saturating_add(1);
        if next_files > max_files {
            return Err(*guard);
        }
        let next_bytes = guard.bytes.saturating_add(bytes);
        if next_bytes > max_bytes {
            return Err(*guard);
        }
        guard.files = next_files;
        guard.bytes = next_bytes;
        // Released before returning rather than at end of scope. The lock guards
        // two counters that move together; holding it a moment longer than the
        // update serialises every other charger against nothing.
        drop(guard);
        Ok(())
    }
}

/// Two ledgers are equal when they hold the same totals. Identity of the shared
/// cell is not part of capability equality; what it has spent is.
impl PartialEq for FetchLedger {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for FetchLedger {}

/// A workspace access capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeCapability {
    workspace_id: WorkspaceId,
    repository_id: RepositoryId,
    read_prefixes: Vec<TreePath>,
    write_prefixes: Vec<TreePath>,
    symlink_policy: SymlinkPolicy,
    /// Fetch ceilings, shared across the delegation tree via `ledger`.
    ///
    /// UNBOUNDED BY DEFAULT, and that is a stated non-claim rather than an
    /// oversight. `new` sets both to `u64::MAX`, so a capability nobody gave a
    /// budget to charges forever and the tree-wide accounting below, while
    /// correct, decides nothing. Setting a ceiling is opt-in through
    /// `with_fetch_budget` / `with_file_budget`.
    ///
    /// Left unbounded deliberately: tightening the default is a behaviour change
    /// for every existing holder, and picking a number here would be inventing a
    /// resource policy that belongs to whoever mints capabilities, not to the
    /// type. Recorded because the audit that found `RepositoryMismatch` also
    /// flagged this, and an infinite default is indistinguishable from a
    /// forgotten one unless it says which it is.
    max_fetch_bytes: u64,
    max_file_count: u64,
    expires_at: Option<u64>,
    revoked: bool,
    /// What THIS capability has charged, including what it inherited when it was
    /// attenuated. Reported in refusals so a holder sees its own position.
    fetched_bytes: u64,
    fetched_files: u64,
    /// What the whole delegation tree has charged. This is what the ceilings are
    /// enforced against.
    ledger: FetchLedger,
}

impl TreeCapability {
    /// Builds a capability.
    ///
    /// An empty read-prefix list authorises nothing. That is deliberate: the
    /// vacuous case is "no access", never "all access", so a construction bug
    /// fails closed.
    // Not `const`: the shared fetch ledger is heap-allocated, and a budget that
    // is shared across a delegation tree cannot be built in a const context.
    #[must_use]
    pub fn new(
        workspace_id: WorkspaceId,
        repository_id: RepositoryId,
        read_prefixes: Vec<TreePath>,
        write_prefixes: Vec<TreePath>,
    ) -> Self {
        Self {
            workspace_id,
            repository_id,
            read_prefixes,
            write_prefixes,
            symlink_policy: SymlinkPolicy::DataOnly,
            // Unbounded until a caller opts in; see the field documentation.
            max_fetch_bytes: u64::MAX,
            max_file_count: u64::MAX,
            expires_at: None,
            revoked: false,
            fetched_bytes: 0,
            fetched_files: 0,
            ledger: FetchLedger::new(),
        }
    }

    /// Sets the symlink policy.
    #[must_use]
    pub const fn with_symlink_policy(mut self, policy: SymlinkPolicy) -> Self {
        self.symlink_policy = policy;
        self
    }

    /// Sets the total fetch-byte ceiling.
    #[must_use]
    pub const fn with_fetch_budget(mut self, budget: ByteCount) -> Self {
        self.max_fetch_bytes = budget.get();
        self
    }

    /// Sets the total file-count ceiling.
    #[must_use]
    pub const fn with_file_budget(mut self, budget: u64) -> Self {
        self.max_file_count = budget;
        self
    }

    /// Sets an expiry tick.
    #[must_use]
    pub const fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// The workspace identity.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// The repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// The symlink policy.
    #[must_use]
    pub const fn symlink_policy(&self) -> SymlinkPolicy {
        self.symlink_policy
    }

    /// Bytes served so far.
    #[must_use]
    pub const fn fetched_bytes(&self) -> u64 {
        self.fetched_bytes
    }

    /// Files served so far.
    #[must_use]
    pub const fn fetched_files(&self) -> u64 {
        self.fetched_files
    }

    /// Revokes the capability. Irreversible.
    pub const fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Authorises reading `path` at tick `now`.
    pub fn authorize_read(
        &self,
        path: &TreePath,
        now: u64,
    ) -> Result<ReadGrant, CapabilityRefusal> {
        self.check_live(now)?;
        if !self.read_prefixes.iter().any(|p| path.starts_with(p)) {
            return Err(CapabilityRefusal::ReadOutsideScope { path: path.clone() });
        }
        Ok(ReadGrant {
            workspace_id: self.workspace_id,
            scope: GrantScope::Path(path.clone()),
        })
    }

    /// Authorises reading the repository root tree at tick `now`.
    ///
    /// The root is the container every authorised path is reached through, so a
    /// capability that grants any read at all may read it. A capability with no
    /// read prefix still authorises nothing, which keeps the vacuous case
    /// failing closed.
    ///
    /// This does not authorise *disclosure* of every root entry. A caller that
    /// lists the root still has to check each child before revealing it;
    /// otherwise the listing becomes an existence oracle for top-level names
    /// outside the capability. That filtering is the caller's, and is noted
    /// here because the grant alone does not provide it.
    pub fn authorize_root(&self, now: u64) -> Result<ReadGrant, CapabilityRefusal> {
        self.check_live(now)?;
        if self.read_prefixes.is_empty() {
            return Err(CapabilityRefusal::ReadOutsideScope {
                path: TreePath::parse_default(b"<root>").unwrap_or_else(|_| {
                    unreachable!("the literal <root> is a valid single-component path")
                }),
            });
        }
        Ok(ReadGrant {
            workspace_id: self.workspace_id,
            scope: GrantScope::Root,
        })
    }

    /// Authorises writing `path` at tick `now`.
    ///
    /// A writable path must also be readable. Write-without-read would let a
    /// caller replace content it is not allowed to observe, which turns a blind
    /// write into an oracle for the previous bytes.
    pub fn authorize_write(
        &self,
        path: &TreePath,
        now: u64,
    ) -> Result<WriteGrant, CapabilityRefusal> {
        self.check_live(now)?;
        if !self.read_prefixes.iter().any(|p| path.starts_with(p)) {
            return Err(CapabilityRefusal::ReadOutsideScope { path: path.clone() });
        }
        if !self.write_prefixes.iter().any(|p| path.starts_with(p)) {
            return Err(CapabilityRefusal::WriteOutsideScope { path: path.clone() });
        }
        Ok(WriteGrant {
            workspace_id: self.workspace_id,
            path: path.clone(),
        })
    }

    /// Charges a served object against the budgets.
    pub fn charge_fetch(&mut self, bytes: u64) -> Result<(), CapabilityRefusal> {
        // Enforced against the SHARED tree totals, reported against this
        // capability's own. The ceiling belongs to the delegation tree, so a
        // sibling's spend has to be visible here; the refusal still names what
        // this holder itself has consumed, because that is the position it can
        // reason about.
        match self
            .ledger
            .charge(bytes, self.max_fetch_bytes, self.max_file_count)
        {
            Ok(()) => {
                self.fetched_files = self.fetched_files.saturating_add(1);
                self.fetched_bytes = self.fetched_bytes.saturating_add(bytes);
                Ok(())
            }
            Err(totals) => {
                if totals.files.saturating_add(1) > self.max_file_count {
                    Err(CapabilityRefusal::FileBudgetExceeded {
                        consumed: self.fetched_files,
                        budget: self.max_file_count,
                    })
                } else {
                    Err(CapabilityRefusal::FetchBudgetExceeded {
                        consumed: self.fetched_bytes,
                        requested: bytes,
                        budget: self.max_fetch_bytes,
                    })
                }
            }
        }
    }

    /// Whether this capability may reveal that `path` exists.
    ///
    /// Reaching the root tree is necessary to get to any authorised descendant,
    /// but that traversal must not turn a raw listing into an existence oracle
    /// for names outside the capability. A path is disclosable when it is in
    /// scope, or when it is an ancestor of something in scope -- a holder of
    /// `docs/readme.md` already knows `docs` exists, so naming it reveals
    /// nothing it did not have.
    #[must_use]
    pub fn admits_disclosure(&self, path: &TreePath) -> bool {
        self.read_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix) || prefix.starts_with(path))
    }

    /// Checks a symlink encounter against the policy.
    pub fn check_symlink(&self, path: &TreePath) -> Result<(), CapabilityRefusal> {
        match self.symlink_policy {
            SymlinkPolicy::DataOnly => Ok(()),
            SymlinkPolicy::Refuse => Err(CapabilityRefusal::SymlinkRefused { path: path.clone() }),
        }
    }

    /// Derives a strictly narrower capability.
    ///
    /// Every requested prefix must already be contained by this capability, so
    /// delegation can only ever lose authority. There is no widening operation
    /// anywhere on this type.
    pub fn attenuate(
        &self,
        read_prefixes: Vec<TreePath>,
        write_prefixes: Vec<TreePath>,
    ) -> Result<Self, CapabilityRefusal> {
        for prefix in &read_prefixes {
            if !self.read_prefixes.iter().any(|p| prefix.starts_with(p)) {
                return Err(CapabilityRefusal::AttenuationWouldWiden {
                    path: prefix.clone(),
                });
            }
        }
        for prefix in &write_prefixes {
            if !self.write_prefixes.iter().any(|p| prefix.starts_with(p)) {
                return Err(CapabilityRefusal::AttenuationWouldWiden {
                    path: prefix.clone(),
                });
            }
        }
        Ok(Self {
            workspace_id: self.workspace_id,
            repository_id: self.repository_id,
            read_prefixes,
            write_prefixes,
            symlink_policy: self.symlink_policy,
            max_fetch_bytes: self.max_fetch_bytes,
            max_file_count: self.max_file_count,
            expires_at: self.expires_at,
            revoked: self.revoked,
            // Consumption carries forward. Resetting these to zero would hand
            // the holder a fresh budget on every attenuation, so a capability
            // that had spent its allowance could mint an unlimited number of
            // full-allowance children -- an operation that WIDENS authority
            // while wearing the name `attenuate`. Narrowing scope must never
            // restore spend.
            fetched_bytes: self.fetched_bytes,
            fetched_files: self.fetched_files,
            // The child SHARES the parent's ledger rather than copying it.
            // Carrying the counter forward alone was not enough: it stopped one
            // child from starting fresh, but let two siblings each spend the
            // same remaining allowance, which is the same widening reached by
            // going sideways instead of down.
            ledger: self.ledger.clone(),
        })
    }

    const fn check_live(&self, now: u64) -> Result<(), CapabilityRefusal> {
        if self.revoked {
            return Err(CapabilityRefusal::Revoked);
        }
        if let Some(expires_at) = self.expires_at
            && now >= expires_at
        {
            return Err(CapabilityRefusal::Expired {
                expires_at,
                observed: now,
            });
        }
        Ok(())
    }
}
