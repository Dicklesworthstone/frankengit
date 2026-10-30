//! Bounded, invocation-owned immutable source descriptors for sparse workspaces.
//! No cache path survives creation and no descriptor is exported. Cache bytes
//! are derived from an authorized manifest, never authority or retention roots.
use super::{
    BTreeMap, File, FileType, GitHashAlgorithm, Grade, HostEpoch, HostRefusal, InternalEffect,
    Mode, OFlags, ObligationClass, ObligationKind, ObservationMode, RESOLVE, ReservedObligation,
    ResourceVector, SettledObligation, SparseEntryKind, SparseWorkspacePlan, TreePath, TrivialAck,
    WorkspaceManifest, Write, fs, io_error, os, sync, validate_parent, write_new,
};
use fgit_crypto::{DigestHasher, NativeObjectIdentity, Sha256Hasher};
use fgit_types::InternalObjectId;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;

const SCOPE_DOMAIN: &[u8] = b"frankengit/shared-workspace-source/v1\0";
const CONTENT_DOMAIN: &[u8] = b"frankengit/shared-workspace-content/v1\0";
const CHUNK: usize = 8192;
const MAX_CACHED_INPUTS: u64 = 128;

/// Sharing is an explicit host-materialization policy, never a Git codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedInputPolicy {
    /// A recognized unsupported operation or full cache copies private bytes.
    PreferReflink,
    /// A source file that cannot be shared refuses instead of claiming sharing.
    RequireReflink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedInputFallback {
    UnsupportedFilesystem,
    Capacity,
}

/// Independent source-cache custody and lifetime seeding budget. Two anonymous
/// probe descriptors are funded in addition to the bounded source-file slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedInputCacheReservation {
    pub scope: [u8; 32],
    pub max_bytes: u64,
    pub max_entries: u64,
    pub policy: SharedInputPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedInputCachePlan {
    reservation: SharedInputCacheReservation,
}

impl SharedInputCachePlan {
    /// Bind the exact source inventory, repository and canonical/candidate
    /// provenance. Workspace IDs, writable outputs and supplemental job inputs
    /// are deliberately absent; each materialization authorizes those itself.
    #[must_use]
    pub fn for_workspace<A: GitHashAlgorithm>(
        plan: &SparseWorkspacePlan<A>,
        policy: SharedInputPolicy,
    ) -> Self {
        let mut hash = Sha256Hasher::new();
        hash.update(SCOPE_DOMAIN);
        let identity = plan.manifest.receipt();
        frame(&mut hash, identity.repository_id().as_bytes());
        frame_internal_id(&mut hash, identity.source_rcr_id().as_internal_object_id());
        frame(&mut hash, identity.source_commit_oid().digest_bytes());
        frame(&mut hash, identity.source_tree_oid().digest_bytes());
        match &plan.manifest {
            WorkspaceManifest::Canonical(_) => hash.update(&[0]),
            WorkspaceManifest::Candidate(manifest) => {
                hash.update(&[1]);
                frame(&mut hash, manifest.candidate_commit_oid().digest_bytes());
                frame(&mut hash, manifest.candidate_tree_oid().digest_bytes());
            }
        }
        hash.update(&(plan.manifest.entries().len() as u64).to_be_bytes());
        let mut max_bytes = 0;
        let mut max_entries = 2;
        for entry in plan.manifest.entries() {
            frame(&mut hash, entry.path().as_bytes());
            frame(&mut hash, entry.source_oid().digest_bytes());
            match entry.kind() {
                SparseEntryKind::Directory => hash.update(&[0]),
                SparseEntryKind::File { mode, body } => {
                    hash.update(&[match mode {
                        fgit_treefs::FileMode::Regular => 1,
                        fgit_treefs::FileMode::Executable => 2,
                    }]);
                    hash.update(&(body.len() as u64).to_be_bytes());
                    max_bytes += body.len() as u64;
                    max_entries += 1;
                }
                // Valid host plans already reject symlink materialization.
                SparseEntryKind::Symlink { .. } => hash.update(&[3]),
            }
        }
        Self {
            reservation: SharedInputCacheReservation {
                scope: hash.finish(),
                max_bytes,
                max_entries: max_entries.min(MAX_CACHED_INPUTS + 2),
                policy,
            },
        }
    }

    #[must_use]
    pub fn reservation(&self) -> SharedInputCacheReservation {
        self.reservation.clone()
    }

    #[must_use]
    pub fn budget(&self) -> ResourceVector {
        ResourceVector::from_grades(&[
            // A typed lease requires a nonzero grant even for an empty source.
            // The administrative unit is returned: no source bytes are spent.
            (Grade::Bytes, self.reservation.max_bytes.max(1)),
            (Grade::Objects, self.reservation.max_entries),
            (Grade::FileDescriptors, self.reservation.max_entries + 1),
        ])
    }
}

fn frame(hash: &mut Sha256Hasher, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn frame_internal_id(hash: &mut Sha256Hasher, id: &InternalObjectId) {
    hash.update(&id.algorithm().code_point().to_be_bytes());
    frame(hash, id.domain().as_bytes());
    hash.update(&id.codec_version().major().to_be_bytes());
    hash.update(&id.codec_version().minor().to_be_bytes());
    frame(hash, id.digest().as_bytes());
}

/// Observable logical sharing and independent cache-seeding work. Cloned bytes
/// are NOT filesystem-exclusive physical allocation measurements. Failed seed
/// writes conservatively charge the complete admitted source body once.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedInputCacheStats {
    pub reflink_supported: bool,
    pub resident_bytes: u64,
    pub resident_entries: u64,
    pub seeded_bytes: u64,
    pub seeded_entries: u64,
    pub probe_entries: u64,
    pub cloned_bytes: u64,
    pub clone_operations: u64,
    pub fallback_bytes: u64,
    pub fallback_files: u64,
    pub unsupported_files: u64,
    pub capacity_files: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedInputCacheClosed {
    pub scope: [u8; 32],
    pub stats: SharedInputCacheStats,
}

/// A cache owns its own typed obligation; closing a workspace does not settle
/// the source descriptors retained for another job. Dropping without close
/// closes the descriptors but records an unresolved cache obligation.
#[derive(Debug)]
pub struct SharedInputCacheLease;
impl ObligationKind for SharedInputCacheLease {
    const CLASS: ObligationClass = ObligationClass::WorkspaceLease;
    const OBSERVATION: ObservationMode = ObservationMode::Internal;
    const REQUIRED_GRADES: &'static [Grade] =
        &[Grade::Bytes, Grade::Objects, Grade::FileDescriptors];
    type Reservation = SharedInputCacheReservation;
    type CommitReceipt = SharedInputCacheClosed;
    type AbortReceipt = HostRefusal;
    type AckEvidence = TrivialAck;
}
impl InternalEffect for SharedInputCacheLease {}

#[derive(Debug)]
struct CachedInput {
    file: File,
    length: u64,
}

/// Finite source descriptors with no persistent directory or global namespace.
/// Entries are never evicted/reseeded, so cumulative seed work is bounded by
/// the same reservation as retained bytes. At most 128 source descriptors are
/// retained; a full preferred cache copies. Anonymous descriptors are created
/// writable for seeding, then mode-sealed and never exported or written again.
/// This is private broker custody, not a kernel-enforced read-only descriptor.
#[must_use = "close the shared input cache and settle its independent lease"]
#[derive(Debug)]
pub struct SharedInputCache {
    plan: SharedInputCachePlan,
    parent: File,
    entries: BTreeMap<[u8; 32], CachedInput>,
    stats: SharedInputCacheStats,
    unusable: bool,
    obligation: ReservedObligation<SharedInputCacheLease>,
}

impl SharedInputCache {
    pub fn create(
        plan: SharedInputCachePlan,
        parent: File,
        obligation: ReservedObligation<SharedInputCacheLease>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, HostRefusal> {
        let mut stats = SharedInputCacheStats::default();
        let check = || {
            if cancelled() {
                Err(HostRefusal::Cancelled(HostEpoch::Staging))
            } else {
                Ok(())
            }
        };
        let prepared = (|| {
            validate_parent(&parent)?;
            if obligation.reservation() != &plan.reservation
                || obligation.reserved().get(Grade::Bytes) < plan.reservation.max_bytes
                || obligation.reserved().get(Grade::Objects) < plan.reservation.max_entries
                || obligation.reserved().get(Grade::FileDescriptors)
                    < plan.reservation.max_entries + 1
            {
                return Err(HostRefusal::ReservationMismatch);
            }
            check()?;
            stats.reflink_supported = probe(&parent, &mut stats.probe_entries, &check)?;
            if !stats.reflink_supported
                && plan.reservation.policy == SharedInputPolicy::RequireReflink
            {
                return Err(HostRefusal::SharedInputUnavailable(
                    SharedInputFallback::UnsupportedFilesystem,
                ));
            }
            check()
        })();
        if let Err(error) = prepared {
            // Probe locals have already closed. Return descriptor capacity
            // only after the cache's retained parent descriptor closes too.
            drop(parent);
            let actual = ResourceVector::from_grades(&[(Grade::Objects, stats.probe_entries)]);
            let _settled = obligation
                .abort(error.clone(), &actual)
                .map_err(|_| HostRefusal::ReservationMismatch)?;
            return Err(error);
        }
        Ok(Self {
            plan,
            parent,
            entries: BTreeMap::new(),
            stats,
            unusable: false,
            obligation,
        })
    }

    #[must_use]
    pub const fn stats(&self) -> SharedInputCacheStats {
        self.stats
    }

    pub(super) fn validate_scope<A: GitHashAlgorithm>(
        &self,
        plan: &SparseWorkspacePlan<A>,
    ) -> Result<(), HostRefusal> {
        if self.unusable {
            return Err(HostRefusal::SharedInputCacheUnusable);
        }
        let expected = SharedInputCachePlan::for_workspace(plan, self.plan.reservation.policy);
        if expected.reservation.scope != self.plan.reservation.scope {
            return Err(HostRefusal::SharedInputScopeMismatch);
        }
        Ok(())
    }

    pub(super) fn write_input(
        &mut self,
        root: &File,
        path: &TreePath,
        body: &[u8],
        mode: Mode,
        check: &dyn Fn() -> Result<(), HostRefusal>,
    ) -> Result<(File, bool), HostRefusal> {
        check()?;
        if self.unusable {
            return Err(HostRefusal::SharedInputCacheUnusable);
        }
        if !self.stats.reflink_supported {
            return self.copy(
                root,
                path,
                body,
                mode,
                SharedInputFallback::UnsupportedFilesystem,
                check,
            );
        }
        let mut hash = Sha256Hasher::new();
        hash.update(CONTENT_DOMAIN);
        hash.update(&(body.len() as u64).to_be_bytes());
        for chunk in body.chunks(CHUNK) {
            check()?;
            hash.update(chunk);
        }
        let key = hash.finish();
        if !self.entries.contains_key(&key) {
            let next_bytes = self
                .stats
                .seeded_bytes
                .checked_add(body.len() as u64)
                .ok_or(HostRefusal::ResourceLimit)?;
            let next_entries = self
                .stats
                .seeded_entries
                .checked_add(1)
                .ok_or(HostRefusal::ResourceLimit)?;
            if next_bytes > self.plan.reservation.max_bytes
                || next_entries > self.plan.reservation.max_entries - 2
            {
                return self.copy(root, path, body, mode, SharedInputFallback::Capacity, check);
            }
            check()?;
            let seeded = (|| {
                let mut file = anonymous(&self.parent)
                    .map_err(|error| io_error("create anonymous shared input", error))?;
                self.stats.seeded_entries = next_entries;
                self.stats.seeded_bytes = next_bytes;
                for chunk in body.chunks(CHUNK) {
                    check()?;
                    file.write_all(chunk)
                        .map_err(|error| io_error("seed shared input", error))?;
                }
                fs::fchmod(&file, Mode::RUSR)
                    .map_err(|error| io_error("seal shared input mode", error))?;
                check()?;
                validate_source(&file, body.len() as u64)?;
                Ok::<File, HostRefusal>(file)
            })();
            let file = match seeded {
                Ok(file) => file,
                Err(error) => {
                    self.unusable = true;
                    return Err(error);
                }
            };
            self.entries.insert(
                key,
                CachedInput {
                    file,
                    length: body.len() as u64,
                },
            );
            self.stats.resident_bytes = next_bytes;
            self.stats.resident_entries = next_entries;
        }
        let source = &self.entries[&key];
        validate_source(&source.file, source.length)?;
        let mut target = create_target(root, path, mode)?;
        check()?;
        match clone_file(&target, &source.file) {
            Ok(()) => {
                let verified = verify_clone(&target, &source.file, body, check);
                if let Err(error) = verified {
                    self.unusable = true;
                    return Err(error);
                }
                check()?;
                sync(&target)?;
                add(&mut self.stats.cloned_bytes, body.len() as u64)?;
                add(&mut self.stats.clone_operations, 1)?;
                Ok((target, true))
            }
            Err(error) if unsupported(error) => {
                if self.plan.reservation.policy == SharedInputPolicy::RequireReflink {
                    return Err(HostRefusal::SharedInputUnavailable(
                        SharedInputFallback::UnsupportedFilesystem,
                    ));
                }
                // The fresh unpublished target may contain partial clone state.
                // Truncate before copying; no existing file is ever replaced.
                target
                    .set_len(0)
                    .map_err(|error| io_error("reset unsupported reflink target", error))?;
                target
                    .seek(SeekFrom::Start(0))
                    .map_err(|error| io_error("rewind unsupported reflink target", error))?;
                for chunk in body.chunks(CHUNK) {
                    check()?;
                    target
                        .write_all(chunk)
                        .map_err(|error| io_error("copy unsupported reflink target", error))?;
                }
                sync(&target)?;
                self.note_fallback(
                    body.len() as u64,
                    SharedInputFallback::UnsupportedFilesystem,
                )?;
                Ok((target, false))
            }
            Err(error) => Err(io_error("clone shared input", error)),
        }
    }

    fn copy(
        &mut self,
        root: &File,
        path: &TreePath,
        body: &[u8],
        mode: Mode,
        reason: SharedInputFallback,
        check: &dyn Fn() -> Result<(), HostRefusal>,
    ) -> Result<(File, bool), HostRefusal> {
        if self.plan.reservation.policy == SharedInputPolicy::RequireReflink {
            return Err(HostRefusal::SharedInputUnavailable(reason));
        }
        let file = write_new(root, path.as_bytes(), body, mode, check)?;
        self.note_fallback(body.len() as u64, reason)?;
        Ok((file, false))
    }

    fn note_fallback(
        &mut self,
        bytes: u64,
        reason: SharedInputFallback,
    ) -> Result<(), HostRefusal> {
        add(&mut self.stats.fallback_bytes, bytes)?;
        add(&mut self.stats.fallback_files, 1)?;
        add(
            match reason {
                SharedInputFallback::UnsupportedFilesystem => &mut self.stats.unsupported_files,
                SharedInputFallback::Capacity => &mut self.stats.capacity_files,
            },
            1,
        )
    }

    /// Close every anonymous descriptor before settling its independent lease.
    /// Existing reflink workspaces retain their own references to the extents.
    pub fn close(self) -> Result<SettledObligation<SharedInputCacheLease>, HostRefusal> {
        let Self {
            plan,
            parent,
            entries,
            mut stats,
            obligation,
            ..
        } = self;
        drop(entries);
        drop(parent);
        stats.resident_bytes = 0;
        stats.resident_entries = 0;
        let actual = ResourceVector::from_grades(&[
            (Grade::Bytes, stats.seeded_bytes),
            (Grade::Objects, stats.seeded_entries + stats.probe_entries),
        ]);
        obligation
            .commit_internal(
                SharedInputCacheClosed {
                    scope: plan.reservation.scope,
                    stats,
                },
                &actual,
            )
            .map_err(|_| HostRefusal::ReservationMismatch)
    }
}

fn add(value: &mut u64, amount: u64) -> Result<(), HostRefusal> {
    *value = value
        .checked_add(amount)
        .ok_or(HostRefusal::ResourceLimit)?;
    Ok(())
}

fn anonymous(parent: &File) -> rustix::io::Result<File> {
    fs::openat2(
        parent,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        RESOLVE,
    )
    .map(File::from)
}

fn unsupported(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::OPNOTSUPP
            | rustix::io::Errno::NOTTY
            | rustix::io::Errno::NOSYS
            | rustix::io::Errno::XDEV
            | rustix::io::Errno::INVAL
    )
}

fn clone_file(target: &File, source: &File) -> rustix::io::Result<()> {
    #[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
    {
        fs::ioctl_ficlone(target, source)
    }
    #[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
    {
        let _ = (target, source);
        Err(rustix::io::Errno::OPNOTSUPP)
    }
}

fn probe(
    parent: &File,
    opened: &mut u64,
    check: &dyn Fn() -> Result<(), HostRefusal>,
) -> Result<bool, HostRefusal> {
    check()?;
    let source = match anonymous(parent) {
        Ok(file) => file,
        Err(error) if unsupported(error) => return Ok(false),
        Err(error) => return Err(io_error("probe anonymous shared input", error)),
    };
    *opened += 1;
    check()?;
    let target = match anonymous(parent) {
        Ok(file) => file,
        Err(error) if unsupported(error) => return Ok(false),
        Err(error) => return Err(io_error("probe anonymous reflink target", error)),
    };
    *opened += 1;
    check()?;
    let supported = match clone_file(&target, &source) {
        Ok(()) => true,
        Err(error) if unsupported(error) => false,
        Err(error) => return Err(io_error("probe shared-input reflink", error)),
    };
    check()?;
    Ok(supported)
}

fn create_target(root: &File, path: &TreePath, mode: Mode) -> Result<File, HostRefusal> {
    let file = fs::openat2(
        root,
        os(path.as_bytes()),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        mode,
        RESOLVE,
    )
    .map(File::from)
    .map_err(|error| io_error("create reflink workspace file", error))?;
    fs::fchmod(&file, mode).map_err(|error| io_error("set reflink workspace mode", error))?;
    Ok(file)
}

fn validate_source(file: &File, length: u64) -> Result<(), HostRefusal> {
    let stat = fs::fstat(file).map_err(|error| io_error("inspect shared input", error))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 0
        || stat.st_mode & 0o7777 != 0o400
        || stat.st_size < 0
        || stat.st_size as u64 != length
    {
        return Err(HostRefusal::SharedInputCorrupt);
    }
    Ok(())
}

fn verify_clone(
    target: &File,
    source: &File,
    body: &[u8],
    check: &dyn Fn() -> Result<(), HostRefusal>,
) -> Result<(), HostRefusal> {
    check()?;
    let expected = body.len() as u64;
    let origin = fs::fstat(source).map_err(|error| io_error("inspect reflink source", error))?;
    let before = fs::fstat(target).map_err(|error| io_error("inspect reflink target", error))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || before.st_size < 0
        || before.st_size as u64 != expected
        || (before.st_dev, before.st_ino) == (origin.st_dev, origin.st_ino)
    {
        return Err(HostRefusal::SharedInputCorrupt);
    }
    let mut buffer = [0; CHUNK];
    let mut offset = 0;
    for bytes in body.chunks(CHUNK) {
        check()?;
        target
            .read_exact_at(&mut buffer[..bytes.len()], offset)
            .map_err(|error| io_error("verify reflink content", error))?;
        if buffer[..bytes.len()] != *bytes {
            return Err(HostRefusal::SharedInputCorrupt);
        }
        offset += bytes.len() as u64;
    }
    check()?;
    let mut tail = [0];
    if target
        .read_at(&mut tail, expected)
        .map_err(|error| io_error("verify reflink EOF", error))?
        != 0
    {
        return Err(HostRefusal::SharedInputCorrupt);
    }
    let after = fs::fstat(target).map_err(|error| io_error("recheck reflink target", error))?;
    if after.st_size != before.st_size
        || after.st_nlink != 1
        || (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
    {
        return Err(HostRefusal::SharedInputCorrupt);
    }
    check()
}

#[cfg(test)]
mod tests;
