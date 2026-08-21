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
            } => write!(formatter, "capability expired at {expires_at}, now {observed}"),
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
    path: TreePath,
}

impl ReadGrant {
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

/// A workspace access capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeCapability {
    workspace_id: WorkspaceId,
    repository_id: RepositoryId,
    read_prefixes: Vec<TreePath>,
    write_prefixes: Vec<TreePath>,
    symlink_policy: SymlinkPolicy,
    max_fetch_bytes: u64,
    max_file_count: u64,
    expires_at: Option<u64>,
    revoked: bool,
    fetched_bytes: u64,
    fetched_files: u64,
}

impl TreeCapability {
    /// Builds a capability.
    ///
    /// An empty read-prefix list authorises nothing. That is deliberate: the
    /// vacuous case is "no access", never "all access", so a construction bug
    /// fails closed.
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
            max_fetch_bytes: u64::MAX,
            max_file_count: u64::MAX,
            expires_at: None,
            revoked: false,
            fetched_bytes: 0,
            fetched_files: 0,
        }
    }

    /// Sets the symlink policy.
    #[must_use]
    pub fn with_symlink_policy(mut self, policy: SymlinkPolicy) -> Self {
        self.symlink_policy = policy;
        self
    }

    /// Sets the total fetch-byte ceiling.
    #[must_use]
    pub fn with_fetch_budget(mut self, budget: ByteCount) -> Self {
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
            path: path.clone(),
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
        let next_files = self.fetched_files.saturating_add(1);
        if next_files > self.max_file_count {
            return Err(CapabilityRefusal::FileBudgetExceeded {
                consumed: self.fetched_files,
                budget: self.max_file_count,
            });
        }
        let next_bytes = self.fetched_bytes.saturating_add(bytes);
        if next_bytes > self.max_fetch_bytes {
            return Err(CapabilityRefusal::FetchBudgetExceeded {
                consumed: self.fetched_bytes,
                requested: bytes,
                budget: self.max_fetch_bytes,
            });
        }
        self.fetched_files = next_files;
        self.fetched_bytes = next_bytes;
        Ok(())
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
            fetched_bytes: 0,
            fetched_files: 0,
        })
    }

    fn check_live(&self, now: u64) -> Result<(), CapabilityRefusal> {
        if self.revoked {
            return Err(CapabilityRefusal::Revoked);
        }
        if let Some(expires_at) = self.expires_at {
            if now >= expires_at {
                return Err(CapabilityRefusal::Expired {
                    expires_at,
                    observed: now,
                });
            }
        }
        Ok(())
    }
}
