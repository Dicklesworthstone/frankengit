//! A real Linux sparse-directory adapter over the direct TreeFS model.
//!
//! The caller supplies a private, broker-owned directory descriptor and a
//! region's typed reservation. No repository path is resolved against cwd.
//! Inputs are copied into a private staging directory, synced, and renamed
//! root-last. Import reads only declared paths and emits ordinary TreeFS
//! intents; it cannot publish repository authority. A failed close retains a
//! leak in the region ledger instead of claiming cleanup.
//!
//! This profile requires Linux openat2 and a byte-preserving local filesystem.
//! It supports trusted tools, not hostile-process isolation. The broker must
//! exclude concurrent tools during import/close and protect the parent from
//! rename or deletion by other principals. FUSE, reflinks, shared host inodes,
//! symlink materialization, and gitlinks are not supported by this profile.

use crate::Commitment;
use fgit_codec::Encoder;
use fgit_crypto::{GitHashAlgorithm, NativeObjectIdentity};
use fgit_resource::{
    Grade, InternalEffect, ObligationClass, ObligationKind, ObservationMode, ReservedObligation,
    ResourceVector, SettledObligation, TrivialAck,
};
use fgit_treefs::{
    CapabilityRefusal, EntryClass, FileMode, IntentLog, PathRefusal, SparseEntryKind, SparseLimits,
    SparseManifest, TreeCapability, TreeEditIntent, TreePath, WorkspaceId,
};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;

const MARKER: &[u8] = b".fgit-host-receipt";
const DOMAIN: &[u8] = b"frankengit/sparse-host/linux-openat2/v1\0";
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

/// Observable interruption boundaries. None publishes repository state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEpoch {
    Reserved,
    Staging,
    Writing(usize),
    Visible,
    Durable,
    Importing(usize),
    Imported,
}

/// Exact refusal at the host boundary; containment retains the owning name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostRefusal {
    Path(PathRefusal),
    Capability(CapabilityRefusal),
    IdentityMismatch,
    ReservationMismatch,
    ResourceLimit,
    UnsupportedEntry(TreePath),
    UndeclaredChange(TreePath),
    AliasedEntry(TreePath),
    ChangedDuringRead(TreePath),
    IncompleteWorkspace,
    Cancelled(HostEpoch),
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    Containment {
        name: String,
        cause: Box<Self>,
    },
}

impl std::fmt::Display for HostRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sparse host workspace refused: {self:?}")
    }
}
impl std::error::Error for HostRefusal {}

/// Reservation binds the immutable plan and its retained I/O ceilings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostReservation {
    pub plan: Commitment,
    pub workspace: WorkspaceId,
    pub max_bytes: u64,
    pub max_entries: u64,
}

/// Runtime-consumed receipt for a workspace whose directory has been reaped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostClosed {
    pub plan: Commitment,
    pub copied_bytes: u64,
    pub shared_host_bytes: u64,
    pub imported_bytes: u64,
    pub removed_entries: u64,
}

/// Internal workspace responsibility. Tools run under their own runner slot;
/// this lease remains reserved until the temporary directory is actually gone.
#[derive(Debug)]
pub struct SparseDirectoryLease;
impl ObligationKind for SparseDirectoryLease {
    const CLASS: ObligationClass = ObligationClass::WorkspaceLease;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] = &[Grade::Bytes, Grade::Objects];
    type Reservation = HostReservation;
    type CommitReceipt = HostClosed;
    type AbortReceipt = HostRefusal;
    type AckEvidence = TrivialAck;
}
impl InternalEffect for SparseDirectoryLease {}

/// Immutable shared base plus the exact writable-path manifest.
#[derive(Clone, Debug)]
pub struct SparseWorkspacePlan<A: GitHashAlgorithm> {
    manifest: Arc<SparseManifest<A>>,
    outputs: BTreeSet<TreePath>,
    directories: BTreeSet<TreePath>,
    limits: SparseLimits,
    reservation: HostReservation,
    marker: Vec<u8>,
}

impl<A: GitHashAlgorithm> SparseWorkspacePlan<A> {
    /// Authorize every disclosed input and every output before host I/O. An
    /// existing input becomes writable only when explicitly listed in outputs.
    pub fn new(
        manifest: Arc<SparseManifest<A>>,
        outputs: Vec<TreePath>,
        capability: &TreeCapability,
        now: u64,
        limits: SparseLimits,
    ) -> Result<Self, HostRefusal> {
        if capability.repository_id() != manifest.receipt().repository_id() {
            return Err(HostRefusal::IdentityMismatch);
        }
        capability
            .authorize_root(now)
            .map_err(HostRefusal::Capability)?;
        if limits.max_entries == 0
            || limits.max_entries > 100_000
            || limits.max_payload_bytes == 0
            || limits.max_payload_bytes > 512 * 1024 * 1024
            || limits.max_entry_bytes > limits.max_payload_bytes
            || manifest.entries().len() > limits.max_entries
            || manifest.receipt().payload_bytes() > limits.max_payload_bytes
            || outputs.len() > limits.max_entries
        {
            return Err(HostRefusal::ResourceLimit);
        }
        let mut directories = BTreeSet::new();
        let mut files = BTreeSet::new();
        for entry in manifest.entries() {
            validate_path(entry.path())?;
            authorize_entry(
                capability,
                entry.path(),
                matches!(entry.kind(), SparseEntryKind::Directory),
                now,
            )?;
            match entry.kind() {
                SparseEntryKind::Directory => {
                    directories.insert(entry.path().clone());
                }
                SparseEntryKind::File { body, .. } if body.len() <= limits.max_entry_bytes => {
                    files.insert(entry.path().clone());
                }
                SparseEntryKind::File { .. } => return Err(HostRefusal::ResourceLimit),
                SparseEntryKind::Symlink { .. } => {
                    return Err(HostRefusal::UnsupportedEntry(entry.path().clone()));
                }
            }
        }
        let count = outputs.len();
        let outputs: BTreeSet<_> = outputs.into_iter().collect();
        if outputs.len() != count {
            return Err(HostRefusal::IdentityMismatch);
        }
        for path in &outputs {
            validate_path(path)?;
            capability
                .authorize_read(path, now)
                .map_err(HostRefusal::Capability)?;
            capability
                .authorize_write(path, now)
                .map_err(HostRefusal::Capability)?;
            if directories.contains(path) {
                return Err(HostRefusal::UnsupportedEntry(path.clone()));
            }
            directories.extend(path.ancestors());
            files.insert(path.clone());
        }
        if files.iter().any(|path| directories.contains(path)) {
            return Err(HostRefusal::IdentityMismatch);
        }
        if files
            .len()
            .saturating_add(directories.len())
            .saturating_add(1)
            > limits.max_entries
        {
            return Err(HostRefusal::ResourceLimit);
        }
        let mut bytes = Encoder::new();
        bytes.write_raw(DOMAIN);
        bytes.write_opaque_id(capability.workspace_id().as_bytes());
        bytes.write_opaque_id(manifest.receipt().repository_id().as_bytes());
        bytes
            .write_internal_object_id(manifest.receipt().source_rcr_id().as_internal_object_id())
            .map_err(|_| HostRefusal::IdentityMismatch)?;
        frame(
            &mut bytes,
            manifest.receipt().source_commit_oid().digest_bytes(),
        )?;
        frame(
            &mut bytes,
            manifest.receipt().source_tree_oid().digest_bytes(),
        )?;
        bytes.write_scalar(manifest.entries().len() as u64);
        for entry in manifest.entries() {
            frame(&mut bytes, entry.path().as_bytes())?;
            frame(&mut bytes, entry.source_oid().digest_bytes())?;
            bytes.write_raw_byte(match entry.kind() {
                SparseEntryKind::Directory => 0,
                SparseEntryKind::File {
                    mode: FileMode::Regular,
                    ..
                } => 1,
                SparseEntryKind::File {
                    mode: FileMode::Executable,
                    ..
                } => 2,
                SparseEntryKind::Symlink { .. } => 3,
            });
        }
        // Framed counts separate input and output sequences unambiguously.
        bytes.write_scalar(outputs.len() as u64);
        for path in &outputs {
            frame(&mut bytes, path.as_bytes())?;
        }
        bytes.write_scalar(limits.max_entries as u64);
        bytes.write_scalar(limits.max_entry_bytes as u64);
        bytes.write_scalar(limits.max_payload_bytes as u64);
        let plan = Commitment::of_bytes(bytes.as_bytes());
        let reservation = HostReservation {
            plan,
            workspace: capability.workspace_id(),
            max_bytes: limits.max_payload_bytes as u64,
            max_entries: limits.max_entries as u64,
        };
        let mut marker = DOMAIN.to_vec();
        marker.extend_from_slice(plan.digest().bytes().as_bytes());
        Ok(Self {
            manifest,
            outputs,
            directories,
            limits,
            reservation,
            marker,
        })
    }

    #[must_use]
    pub fn reservation(&self) -> HostReservation {
        self.reservation.clone()
    }

    /// Reserve these grades in the caller's region before materialization.
    #[must_use]
    pub fn budget(&self) -> ResourceVector {
        ResourceVector::from_grades(&[
            (Grade::Bytes, self.reservation.max_bytes),
            (Grade::Objects, self.reservation.max_entries),
        ])
    }

    fn authorize(&self, capability: &TreeCapability, now: u64) -> Result<(), HostRefusal> {
        if capability.workspace_id() != self.reservation.workspace
            || capability.repository_id() != self.manifest.receipt().repository_id()
        {
            return Err(HostRefusal::IdentityMismatch);
        }
        capability
            .authorize_root(now)
            .map_err(HostRefusal::Capability)?;
        for entry in self.manifest.entries() {
            authorize_entry(
                capability,
                entry.path(),
                matches!(entry.kind(), SparseEntryKind::Directory),
                now,
            )?;
        }
        for path in &self.outputs {
            capability
                .authorize_read(path, now)
                .map_err(HostRefusal::Capability)?;
            capability
                .authorize_write(path, now)
                .map_err(HostRefusal::Capability)?;
        }
        Ok(())
    }
}

/// A descriptor-owned materialization. Dropping without close is a region
/// containment failure. The immutable manifest can be shared across runs;
/// host files and imported intent logs are always private to this workspace.
#[must_use = "close the workspace and settle its region-owned lease"]
#[derive(Debug)]
pub struct SparseWorkspace<A: GitHashAlgorithm> {
    plan: SparseWorkspacePlan<A>,
    parent: File,
    root: File,
    name: TreePath,
    obligation: ReservedObligation<SparseDirectoryLease>,
    copied_bytes: u64,
    imported_bytes: u64,
}

impl<A: GitHashAlgorithm> SparseWorkspace<A> {
    /// A fresh slot only: an occupied final or staging name never authorizes
    /// overwrite or retry. Parent must be a broker-owned directory with mode
    /// 0700; repository text cannot provide this descriptor.
    pub fn materialize(
        plan: SparseWorkspacePlan<A>,
        parent: File,
        name: TreePath,
        obligation: ReservedObligation<SparseDirectoryLease>,
        capability: &TreeCapability,
        now: u64,
        cancelled: &dyn Fn(HostEpoch) -> bool,
    ) -> Result<Self, HostRefusal> {
        let validation = validate_slot(&name)
            .and_then(|()| validate_parent(&parent))
            .and_then(|()| plan.authorize(capability, now))
            .and_then(|()| validate_reservation(&plan, &obligation))
            .and_then(|()| checkpoint(cancelled, HostEpoch::Reserved));
        if let Err(error) = validation {
            let _settled = obligation.abort_unused(error.clone());
            return Err(error);
        }
        let staging = format!(".fgit-staged-{}", name);
        if let Err(error) = fs::mkdirat(&parent, staging.as_str(), Mode::RWXU) {
            let error = io_error("reserve staging directory", error);
            let _settled = obligation.abort_unused(error.clone());
            return Err(error);
        }
        let root = match open(
            &parent,
            staging.as_bytes(),
            OFlags::RDONLY | OFlags::DIRECTORY,
        ) {
            Ok(root) => root,
            Err(error) => {
                // The directory exists but cannot be inspected. Its obligation
                // intentionally leaks; do not claim an unused reservation.
                return Err(HostRefusal::Containment {
                    name: staging,
                    cause: Box::new(error),
                });
            }
        };
        let mut visible = false;
        let result = (|| {
            lock(&root)?;
            write_new(
                &root,
                MARKER,
                &plan.marker,
                Mode::RUSR | Mode::WUSR,
                &|| Ok(()),
            )?;
            checkpoint(cancelled, HostEpoch::Staging)?;
            let mut aliases = BTreeSet::new();
            for path in &plan.directories {
                let parent = open_parent(&root, path)?;
                fs::mkdirat(&parent, os(path.file_name()), Mode::RWXU)
                    .map_err(|e| io_error("create generated parent", e))?;
                let directory = open(&root, path.as_bytes(), OFlags::RDONLY | OFlags::DIRECTORY)?;
                remember_inode(&directory, path, &mut aliases)?;
            }
            for (index, entry) in plan.manifest.entries().iter().enumerate() {
                checkpoint(cancelled, HostEpoch::Writing(index))?;
                if let SparseEntryKind::File { mode, body } = entry.kind() {
                    let file = write_new(
                        &root,
                        entry.path().as_bytes(),
                        body,
                        host_mode(*mode),
                        &|| checkpoint(cancelled, HostEpoch::Writing(index)),
                    )?;
                    remember_inode(&file, entry.path(), &mut aliases)?;
                }
            }
            // Children before parents, root last. No path is returned before
            // every body and directory has crossed its selected sync boundary.
            for path in plan.directories.iter().rev() {
                sync(&open(
                    &root,
                    path.as_bytes(),
                    OFlags::RDONLY | OFlags::DIRECTORY,
                )?)?;
            }
            sync(&root)?;
            fs::renameat_with(
                &parent,
                staging.as_str(),
                &parent,
                os(name.as_bytes()),
                RenameFlags::NOREPLACE,
            )
            .map_err(|e| io_error("publish workspace directory", e))?;
            visible = true;
            checkpoint(cancelled, HostEpoch::Visible)?;
            sync(&parent)?;
            checkpoint(cancelled, HostEpoch::Durable)
        })();
        if let Err(error) = result {
            let owned_name = if visible {
                name.as_bytes()
            } else {
                staging.as_bytes()
            };
            match reap(&parent, &root, owned_name, plan.limits.max_entries) {
                Ok(_) => {
                    // The work started: conservatively charge its reservation
                    // ceiling rather than asserting that no bytes were spent.
                    let spent = obligation.reserved();
                    let _settled = obligation
                        .abort(error.clone(), &spent)
                        .map_err(|_| HostRefusal::ReservationMismatch)?;
                    return Err(error);
                }
                Err(cleanup) => {
                    return Err(HostRefusal::Containment {
                        name: String::from_utf8_lossy(owned_name).into_owned(),
                        cause: Box::new(cleanup),
                    });
                }
            }
        }
        let copied_bytes = plan.manifest.receipt().payload_bytes() as u64;
        Ok(Self {
            plan,
            parent,
            root,
            name,
            obligation,
            copied_bytes,
            imported_bytes: 0,
        })
    }

    /// Reopen a completed root using the reconstructed, authorized plan.
    /// A surviving staging directory is incomplete, never a completed root.
    /// Marker equality is a plan check, not authorization or proof of commit.
    pub fn reopen(
        plan: SparseWorkspacePlan<A>,
        parent: File,
        name: TreePath,
        obligation: ReservedObligation<SparseDirectoryLease>,
        capability: &TreeCapability,
        now: u64,
    ) -> Result<Self, HostRefusal> {
        let opened: Result<File, HostRefusal> = (|| {
            validate_slot(&name)?;
            validate_parent(&parent)?;
            plan.authorize(capability, now)?;
            validate_reservation(&plan, &obligation)?;
            let root = open(&parent, name.as_bytes(), OFlags::RDONLY | OFlags::DIRECTORY)
                .map_err(|_| HostRefusal::IncompleteWorkspace)?;
            lock(&root)?;
            check_marker(&root, &plan.marker)?;
            Ok(root)
        })();
        match opened {
            Ok(root) => Ok(Self {
                plan,
                parent,
                root,
                name,
                obligation,
                copied_bytes: 0,
                imported_bytes: 0,
            }),
            Err(error) => {
                let _settled = obligation.abort_unused(error.clone());
                Err(error)
            }
        }
    }

    /// Reap an interrupted staging root only after its immutable plan marker
    /// matches. A crash before that marker was written remains explicit
    /// containment requiring the broker's original creation receipt.
    pub fn discard_incomplete(
        plan: SparseWorkspacePlan<A>,
        parent: File,
        name: TreePath,
        obligation: ReservedObligation<SparseDirectoryLease>,
    ) -> Result<SettledObligation<SparseDirectoryLease>, HostRefusal> {
        validate_slot(&name)?;
        validate_parent(&parent)?;
        validate_reservation(&plan, &obligation)?;
        let staging = format!(".fgit-staged-{name}");
        let cleanup = (|| {
            let root = open(
                &parent,
                staging.as_bytes(),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            lock(&root)?;
            check_marker(&root, &plan.marker)?;
            reap(&parent, &root, staging.as_bytes(), plan.limits.max_entries)
        })();
        cleanup.map_err(|cause| HostRefusal::Containment {
            name: staging,
            cause: Box::new(cause),
        })?;
        // Recovery cannot measure the dead process's partial writes. Charge
        // the reserved ceiling and retain the incomplete outcome.
        let spent = obligation.reserved();
        obligation
            .abort(HostRefusal::IncompleteWorkspace, &spent)
            .map_err(|_| HostRefusal::ReservationMismatch)
    }

    /// A path to the pinned root descriptor for a bounded trusted tool. Keep
    /// this workspace alive for the entire tool invocation; the path expires
    /// with the descriptor. The process substrate owns execution and reaping.
    #[must_use]
    pub fn tool_directory(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.root.as_raw_fd()
        ))
    }

    /// Read a declared output set at quiescence and return an all-or-nothing
    /// semantic edit log. No arbitrary directory walk contributes to import.
    pub fn import(
        &mut self,
        capability: &TreeCapability,
        now: u64,
        cancelled: &dyn Fn(HostEpoch) -> bool,
    ) -> Result<IntentLog, HostRefusal> {
        self.plan.authorize(capability, now)?;
        check_marker(&self.root, &self.plan.marker)?;
        let inputs: BTreeMap<_, _> = self
            .plan
            .manifest
            .entries()
            .iter()
            .filter(|entry| matches!(entry.kind(), SparseEntryKind::File { .. }))
            .map(|entry| (entry.path().clone(), entry))
            .collect();
        let paths: BTreeSet<_> = inputs
            .keys()
            .chain(self.plan.outputs.iter())
            .cloned()
            .collect();
        let mut aliases = BTreeSet::new();
        let mut total = 0_usize;
        let mut changed_bytes = 0_u64;
        let mut log = IntentLog::new();
        for (index, path) in paths.iter().enumerate() {
            checkpoint(cancelled, HostEpoch::Importing(index))?;
            let remaining = self.plan.limits.max_payload_bytes.saturating_sub(total);
            let current = read_regular(
                &self.root,
                path,
                remaining.min(self.plan.limits.max_entry_bytes),
                &mut aliases,
                &|| checkpoint(cancelled, HostEpoch::Importing(index)),
            )?;
            if let Some((body, _)) = &current {
                total += body.len();
            }
            let before = inputs.get(path).and_then(|entry| match entry.kind() {
                SparseEntryKind::File { mode, body } => Some((body.as_slice(), *mode)),
                _ => None,
            });
            if current
                .as_ref()
                .map(|(body, mode)| (body.as_slice(), *mode))
                == before
            {
                continue;
            }
            if !self.plan.outputs.contains(path) {
                return Err(HostRefusal::UndeclaredChange(path.clone()));
            }
            match current {
                Some((content, mode)) => {
                    changed_bytes += content.len() as u64;
                    log.push(TreeEditIntent::Write {
                        path: path.clone(),
                        content,
                        mode,
                        entry_class: EntryClass::Content,
                    });
                }
                None => log.push(TreeEditIntent::Delete { path: path.clone() }),
            }
        }
        checkpoint(cancelled, HostEpoch::Imported)?;
        self.plan.authorize(capability, now)?;
        self.imported_bytes = changed_bytes;
        Ok(log)
    }

    /// Drain host files and settle the lease. Unknown tool outputs are cleaned
    /// descriptor-relatively under the same entry budget. A substituted mount,
    /// raced root name, or cleanup excess is explicit containment failure.
    pub fn close(self) -> Result<SettledObligation<SparseDirectoryLease>, HostRefusal> {
        let removed = reap(
            &self.parent,
            &self.root,
            self.name.as_bytes(),
            self.plan.limits.max_entries,
        )
        .map_err(|cause| HostRefusal::Containment {
            name: self.name.to_string(),
            cause: Box::new(cause),
        })?;
        let receipt = HostClosed {
            plan: self.plan.reservation.plan,
            copied_bytes: self.copied_bytes,
            shared_host_bytes: 0,
            imported_bytes: self.imported_bytes,
            removed_entries: removed as u64,
        };
        let actual = ResourceVector::from_grades(&[
            (
                Grade::Bytes,
                receipt.copied_bytes.max(receipt.imported_bytes),
            ),
            (Grade::Objects, removed as u64),
        ]);
        self.obligation
            .commit_internal(receipt, &actual)
            .map_err(|_| HostRefusal::ReservationMismatch)
    }
}

fn validate_path(path: &TreePath) -> Result<(), HostRefusal> {
    TreePath::parse_default(path.as_bytes()).map_err(HostRefusal::Path)?;
    if path.components().next() == Some(MARKER) {
        return Err(HostRefusal::UnsupportedEntry(path.clone()));
    }
    Ok(())
}
fn authorize_entry(
    capability: &TreeCapability,
    path: &TreePath,
    directory: bool,
    now: u64,
) -> Result<(), HostRefusal> {
    if directory && capability.admits_disclosure(path) {
        return Ok(());
    }
    capability
        .authorize_read(path, now)
        .map(|_| ())
        .map_err(HostRefusal::Capability)
}
fn validate_slot(path: &TreePath) -> Result<(), HostRefusal> {
    validate_path(path)?;
    if path.component_count() != 1 || path.as_bytes().len() > 220 || !path.as_bytes().is_ascii() {
        return Err(HostRefusal::UnsupportedEntry(path.clone()));
    }
    Ok(())
}
fn validate_parent(parent: &File) -> Result<(), HostRefusal> {
    let stat = fs::fstat(parent).map_err(|e| io_error("inspect broker parent", e))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(HostRefusal::Io {
            operation: "private broker parent required",
            kind: std::io::ErrorKind::PermissionDenied,
        });
    }
    Ok(())
}
fn validate_reservation<A: GitHashAlgorithm>(
    plan: &SparseWorkspacePlan<A>,
    obligation: &ReservedObligation<SparseDirectoryLease>,
) -> Result<(), HostRefusal> {
    if obligation.reservation() != &plan.reservation
        || obligation.reserved().get(Grade::Bytes) < plan.reservation.max_bytes
        || obligation.reserved().get(Grade::Objects) < plan.reservation.max_entries
    {
        return Err(HostRefusal::ReservationMismatch);
    }
    Ok(())
}
fn frame(bytes: &mut Encoder, value: &[u8]) -> Result<(), HostRefusal> {
    bytes
        .write_bytes("sparse-host", value)
        .map_err(|_| HostRefusal::ResourceLimit)
}
fn os(bytes: &[u8]) -> &OsStr {
    OsStr::from_bytes(bytes)
}
fn io_error(operation: &'static str, error: impl Into<std::io::Error>) -> HostRefusal {
    HostRefusal::Io {
        operation,
        kind: error.into().kind(),
    }
}
fn checkpoint(cancelled: &dyn Fn(HostEpoch) -> bool, epoch: HostEpoch) -> Result<(), HostRefusal> {
    if cancelled(epoch) {
        Err(HostRefusal::Cancelled(epoch))
    } else {
        Ok(())
    }
}
fn host_mode(mode: FileMode) -> Mode {
    match mode {
        FileMode::Regular => Mode::RUSR | Mode::WUSR,
        FileMode::Executable => Mode::RWXU,
    }
}
fn sync(file: &File) -> Result<(), HostRefusal> {
    file.sync_all().map_err(|e| io_error("sync workspace", e))
}
fn lock(file: &File) -> Result<(), HostRefusal> {
    fs::flock(file, fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|e| io_error("exclusive workspace lease", e))
}
fn open(root: &File, path: &[u8], flags: OFlags) -> Result<File, HostRefusal> {
    fs::openat2(
        root,
        os(path),
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        RESOLVE,
    )
    .map(File::from)
    .map_err(|e| io_error("open beneath workspace", e))
}
fn open_parent(root: &File, path: &TreePath) -> Result<File, HostRefusal> {
    match path.parent() {
        Some(parent) => open(root, parent.as_bytes(), OFlags::RDONLY | OFlags::DIRECTORY),
        None => root
            .try_clone()
            .map_err(|e| io_error("duplicate workspace root", e)),
    }
}
fn write_new(
    root: &File,
    path: &[u8],
    body: &[u8],
    mode: Mode,
    checkpoint: &dyn Fn() -> Result<(), HostRefusal>,
) -> Result<File, HostRefusal> {
    let mut file = fs::openat2(
        root,
        os(path),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        mode,
        RESOLVE,
    )
    .map(File::from)
    .map_err(|e| io_error("create workspace file", e))?;
    fs::fchmod(&file, mode).map_err(|e| io_error("set workspace file mode", e))?;
    for chunk in body.chunks(8192) {
        checkpoint()?;
        file.write_all(chunk)
            .map_err(|e| io_error("write workspace file", e))?;
    }
    sync(&file)?;
    Ok(file)
}
fn remember_inode(
    file: &File,
    path: &TreePath,
    aliases: &mut BTreeSet<(u64, u64)>,
) -> Result<(), HostRefusal> {
    let stat = fs::fstat(file).map_err(|e| io_error("inspect workspace inode", e))?;
    if !aliases.insert((stat.st_dev, stat.st_ino)) {
        return Err(HostRefusal::AliasedEntry(path.clone()));
    }
    Ok(())
}
fn check_marker(root: &File, expected: &[u8]) -> Result<(), HostRefusal> {
    let mut marker = Vec::new();
    open(root, MARKER, OFlags::RDONLY)?
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut marker)
        .map_err(|e| io_error("read workspace identity", e))?;
    if marker != expected {
        return Err(HostRefusal::IdentityMismatch);
    }
    Ok(())
}
fn read_regular(
    root: &File,
    path: &TreePath,
    limit: usize,
    aliases: &mut BTreeSet<(u64, u64)>,
    checkpoint: &dyn Fn() -> Result<(), HostRefusal>,
) -> Result<Option<(Vec<u8>, FileMode)>, HostRefusal> {
    let mut file = match open(root, path.as_bytes(), OFlags::RDONLY) {
        Err(HostRefusal::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }) => return Ok(None),
        result => result?,
    };
    let before = fs::fstat(&file).map_err(|e| io_error("inspect output", e))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile || before.st_nlink != 1 {
        return Err(HostRefusal::UnsupportedEntry(path.clone()));
    }
    let mode = match before.st_mode & 0o7777 {
        0o600 | 0o644 => FileMode::Regular,
        0o700 | 0o755 => FileMode::Executable,
        _ => return Err(HostRefusal::UnsupportedEntry(path.clone())),
    };
    let size = usize::try_from(before.st_size).map_err(|_| HostRefusal::ResourceLimit)?;
    if size > limit {
        return Err(HostRefusal::ResourceLimit);
    }
    remember_inode(&file, path, aliases)?;
    let mut body = Vec::new();
    body.try_reserve_exact(size)
        .map_err(|_| HostRefusal::ResourceLimit)?;
    let mut chunk = [0; 8192];
    loop {
        checkpoint()?;
        let count = file
            .read(&mut chunk)
            .map_err(|e| io_error("read declared output", e))?;
        if count == 0 {
            break;
        }
        if count > limit.saturating_sub(body.len()) {
            return Err(HostRefusal::ResourceLimit);
        }
        body.extend_from_slice(&chunk[..count]);
    }
    let after = fs::fstat(&file).map_err(|e| io_error("recheck output", e))?;
    let named = open(root, path.as_bytes(), OFlags::RDONLY)?;
    let named = fs::fstat(&named).map_err(|e| io_error("recheck output path", e))?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_nlink,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ctime,
        before.st_ctime_nsec,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_nlink,
        after.st_mtime,
        after.st_mtime_nsec,
        after.st_ctime,
        after.st_ctime_nsec,
    ) || (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
    {
        return Err(HostRefusal::ChangedDuringRead(path.clone()));
    }
    Ok(Some((body, mode)))
}

fn reap(parent: &File, root: &File, name: &[u8], limit: usize) -> Result<usize, HostRefusal> {
    let named = open(parent, name, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let a = fs::fstat(root).map_err(|e| io_error("inspect owned root", e))?;
    let b = fs::fstat(&named).map_err(|e| io_error("inspect named root", e))?;
    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) {
        return Err(HostRefusal::IdentityMismatch);
    }
    let mut remaining = limit;
    reap_children(root, &mut remaining, 0)?;
    fs::unlinkat(parent, os(name), AtFlags::REMOVEDIR)
        .map_err(|e| io_error("remove workspace root", e))?;
    sync(parent)?;
    Ok(limit - remaining)
}
fn reap_children(root: &File, remaining: &mut usize, depth: usize) -> Result<(), HostRefusal> {
    if depth > 64 {
        return Err(HostRefusal::ResourceLimit);
    }
    let entries = fs::Dir::read_from(root).map_err(|e| io_error("enumerate cleanup entries", e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_error("read cleanup entry", e))?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        *remaining = remaining.checked_sub(1).ok_or(HostRefusal::ResourceLimit)?;
        // fstatat never follows a symlink. A substituted symlink is unlinked,
        // never traversed, while a substituted directory is opened beneath.
        let stat = fs::statat(root, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| io_error("inspect cleanup entry", e))?;
        let flags = if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let child = open(root, name, OFlags::RDONLY | OFlags::DIRECTORY)?;
            reap_children(&child, remaining, depth + 1)?;
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        fs::unlinkat(root, entry.file_name(), flags)
            .map_err(|e| io_error("reap workspace entry", e))?;
    }
    Ok(())
}
