//! Bounded streaming composition over the existing LFS custody codec and store.
//! An opened companion remains pinned by its complete independently supplied
//! checksum across every pass; no pathname is reopened during installation.

use super::super::archive::stream::{StreamHeader, TransferLimits};
use super::super::input::PinnedArchive;
use super::super::profile::Deadline;
use super::Receipt;
use fgit_crypto::GitObjectKind;
use fgit_object_fabric::artifact::storage::ArtifactOperation;
use fgit_object_fabric::artifact::storage::lfs::transfer::{
    self, Encoder, SourceIdentity, VerifiedArchive,
};
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, LfsStore, MAX_OBJECT_BYTES};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const POINTER_BYTES: usize = 1024;
const CHUNK_BYTES: usize = 64 * 1024;

/// Pointer candidates come only from complete, individually verified Git blobs
/// in the pinned native archive. The caller additionally verifies the native
/// graph against its authority-selected closure before publishing or restoring.
pub struct Inventory {
    source: SourceIdentity,
    objects: Vec<LfsObject>,
    payload_bytes: u64,
}
impl Inventory {
    pub fn collect<R: Read + Seek>(
        archive: &mut PinnedArchive<R>,
        deadline: Deadline,
        selected: TransferLimits,
    ) -> Result<Self, String> {
        let limits = limits(selected)?;
        let source = source_identity(archive.header())?;
        if archive.header().objects > selected.max_objects {
            return Err("LFS native inventory object-count limit exceeded".into());
        }
        let mut objects = BTreeMap::new();
        let mut payload_bytes = 0_u64;
        // A prefix remains tentative until scan_stream checks every record's
        // native identity and strong commitment, then the original whole pin.
        archive.scan_stream(deadline, |record, body| {
            let mut prefix = [0_u8; POINTER_BYTES];
            let mut prefix_bytes = 0_usize;
            let mut buffer = [0_u8; CHUNK_BYTES];
            loop {
                deadline.check()?;
                let count = match body.read(&mut buffer) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(format!("LFS native pointer scan failed: {error}")),
                };
                deadline.check()?;
                if count == 0 {
                    break;
                }
                if record.kind == GitObjectKind::Blob {
                    let copy = count.min(POINTER_BYTES - prefix_bytes);
                    prefix[prefix_bytes..prefix_bytes + copy].copy_from_slice(&buffer[..copy]);
                    prefix_bytes += copy;
                }
            }
            if record.kind == GitObjectKind::Blob {
                observe_pointer(
                    &prefix[..prefix_bytes],
                    record.length,
                    &mut objects,
                    &mut payload_bytes,
                    limits,
                )?;
            }
            Ok(())
        })?;
        let mut selected_objects = Vec::new();
        selected_objects
            .try_reserve_exact(objects.len())
            .map_err(|_| "LFS pointer inventory allocation refused")?;
        selected_objects.extend(
            objects
                .into_iter()
                .map(|(oid, size)| LfsObject { oid, size }),
        );
        deadline.check()?;
        Ok(Self {
            source,
            objects: selected_objects,
            payload_bytes,
        })
    }

    fn matches(&self, header: &StreamHeader) -> Result<(), String> {
        if self.source != source_identity(header)? {
            return Err("LFS pointer inventory belongs to a different source snapshot".into());
        }
        Ok(())
    }
}

fn observe_pointer(
    prefix: &[u8],
    length: u64,
    objects: &mut BTreeMap<LfsOid, u64>,
    payload_bytes: &mut u64,
    limits: transfer::TransferLimits,
) -> Result<(), String> {
    if !prefix.starts_with(b"version https://git-lfs.github.com/spec/") {
        return Ok(());
    }
    if length > POINTER_BYTES as u64 || prefix.len() as u64 != length {
        return Err("unsupported oversized LFS pointer in source backup".into());
    }
    let object = LfsObject::parse_pointer(prefix)
        .map_err(|error| format!("unsupported LFS pointer in source backup: {error}"))?;
    if object.size > limits.max_object_bytes {
        return Err("LFS pointer exceeds per-object payload limit".into());
    }
    if let Some(size) = objects.get(&object.oid) {
        if *size != object.size {
            return Err("conflicting lengths for one source backup LFS OID".into());
        }
        return Ok(());
    }
    if objects.len() >= limits.max_objects {
        return Err("LFS pointer object-count limit exceeded".into());
    }
    *payload_bytes = payload_bytes
        .checked_add(object.size)
        .filter(|bytes| *bytes <= limits.max_payload_bytes)
        .ok_or("LFS pointer payload-byte limit exceeded")?;
    objects.insert(object.oid, object.size);
    Ok(())
}

fn limits(selected: TransferLimits) -> Result<transfer::TransferLimits, String> {
    selected.validate()?;
    Ok(transfer::TransferLimits {
        max_objects: selected.max_objects,
        max_object_bytes: MAX_OBJECT_BYTES,
        max_payload_bytes: selected.max_archive_bytes,
        max_archive_bytes: selected.max_archive_bytes,
    })
}

fn source_identity(header: &StreamHeader) -> Result<SourceIdentity, String> {
    let head = header
        .authority
        .head
        .as_ref()
        .ok_or("LFS source snapshot has no published authority head")?;
    if head.generation == 0 {
        return Err("LFS source snapshot has a zero authority generation".into());
    }
    Ok(SourceIdentity {
        tenant: header.identity.tenant,
        repository: header.identity.repository,
        incarnation: header.identity.incarnation,
        format: header.identity.format,
        head_generation: head.generation,
        head_token: head
            .token
            .as_slice()
            .try_into()
            .map_err(|_| "LFS source snapshot has an invalid authority token")?,
        head_sha256: fgit_crypto::sha256_digest(&head.body),
    })
}

/// Encode to the caller's new private staging handle and read back the actual
/// bytes. The caller owns no-replace archive publication and final source-head
/// revalidation under the original operation's deadline.
pub fn export(
    root: &Path,
    header: &StreamHeader,
    inventory: &Inventory,
    file: &mut File,
    selected: TransferLimits,
    deadline: Deadline,
) -> Result<Receipt, String> {
    deadline.check()?;
    inventory.matches(header)?;
    let limits = limits(selected)?;
    if file.metadata().map_err(|error| error.to_string())?.len() != 0 {
        return Err("LFS companion export requires a new empty staging file".into());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let store = open_store(root, inventory.source)?;
    let live = || deadline.check().is_ok();
    let operation = artifact_operation(deadline, &live)?;
    let mut archive_live = || deadline.check().is_ok();
    let mut encoder = Encoder::new(
        &mut *file,
        inventory.source,
        inventory.objects.len(),
        inventory.payload_bytes,
        limits,
        &mut archive_live,
    )
    .map_err(|error| error.to_string())?;
    for &object in &inventory.objects {
        deadline.check()?;
        let mut payload = store.open_verified(object, &operation).map_err(|error| {
            format!(
                "LFS source custody missing or invalid for {}: {error}",
                object.oid
            )
        })?;
        encoder
            .object(object, &mut payload, &mut archive_live)
            .map_err(|error| error.to_string())?;
    }
    let seal = encoder
        .finish(&mut archive_live)
        .map_err(|error| error.to_string())?;
    let verified = transfer::verify(file, seal.digest, limits, &mut archive_live)
        .map_err(|error| error.to_string())?;
    match_inventory(&verified, inventory)?;
    if verified.seal() != seal {
        return Err("LFS companion changed during export readback".into());
    }
    deadline.check()?;
    Ok(receipt(&verified))
}

/// A verified companion and its original opened input. Snapshot labels and
/// record offsets only survive after complete pin, payload, and inventory
/// checks. Every installation repeats those checks, then hashes each payload
/// again through the immutable custody store before any repository publication.
pub struct Companion {
    input: File,
    verified: VerifiedArchive,
    limits: transfer::TransferLimits,
}
impl Companion {
    pub fn open(
        path: &Path,
        expected: [u8; 32],
        header: &StreamHeader,
        inventory: &Inventory,
        selected: TransferLimits,
        deadline: Deadline,
    ) -> Result<Self, String> {
        deadline.check()?;
        inventory.matches(header)?;
        let limits = limits(selected)?;
        let mut input = open_archive(path, limits.max_archive_bytes)?;
        let verified = transfer::verify(&mut input, expected, limits, &mut || {
            deadline.check().is_ok()
        })
        .map_err(|error| error.to_string())?;
        match_inventory(&verified, inventory)?;
        deadline.check()?;
        Ok(Self {
            input,
            verified,
            limits,
        })
    }

    fn recheck(&mut self, deadline: Deadline) -> Result<(), String> {
        deadline.check()?;
        let verified = transfer::verify(
            &mut self.input,
            self.verified.seal().digest,
            self.limits,
            &mut || deadline.check().is_ok(),
        )
        .map_err(|error| format!("pinned LFS companion changed or became unreadable: {error}"))?;
        if verified.source() != self.verified.source()
            || verified.seal() != self.verified.seal()
            || verified.records() != self.verified.records()
        {
            return Err("pinned LFS companion changed its source or inventory".into());
        }
        deadline.check()
    }

    /// Recheck the original open companion after native graph preflight, before
    /// reporting successful verification. This reads and hashes every payload
    /// again without creating custody or reopening the input pathname.
    pub fn verify_archive(&mut self, deadline: Deadline) -> Result<(), String> {
        self.recheck(deadline)
    }

    /// `root` is the custody directory inside unpublished restore quarantine.
    /// A failure can retain verified immutable custody there; retry uses the
    /// same source/companion pins and normal idempotent LfsStore::put behavior.
    pub fn install(&mut self, root: &Path, deadline: Deadline) -> Result<(), String> {
        self.recheck(deadline)?;
        let root = custody_path(root)?;
        let parent = root
            .parent()
            .ok_or("LFS restore custody must name a directory")?;
        inspect_directory(parent)?;
        match fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| format!("cannot sync LFS restore custody parent: {error}"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create LFS restore custody: {error}")),
        }
        let store = open_store(&root, *self.verified.source())?;
        let live = || deadline.check().is_ok();
        let operation = artifact_operation(deadline, &live)?;
        for record in self.verified.records() {
            deadline.check()?;
            let object = record.object();
            self.input
                .seek(SeekFrom::Start(record.payload_offset()))
                .map_err(|error| format!("cannot seek pinned LFS payload: {error}"))?;
            let mut payload = (&mut self.input).take(object.size);
            store.put(object, &mut payload, &operation).map_err(|error| {
                format!(
                    "LFS restore custody stopped at {}; verified quarantine payloads may remain: {error}",
                    object.oid
                )
            })?;
        }
        // An external writer cannot turn a valid initial header into approval
        // for a later changed archive. Per-payload put verification alone does
        // not reauthenticate the original complete companion framing.
        self.recheck(deadline)
    }

    /// Read-only verification also serves published restore retries. Missing
    /// custody is a refusal; this path never creates directories or repairs it.
    pub fn verify_stored(&mut self, root: &Path, deadline: Deadline) -> Result<(), String> {
        self.recheck(deadline)?;
        let store = open_store(root, *self.verified.source())?;
        let live = || deadline.check().is_ok();
        let operation = artifact_operation(deadline, &live)?;
        for record in self.verified.records() {
            deadline.check()?;
            let object = record.object();
            if !store.contains(object, &operation).map_err(|error| {
                format!(
                    "restored LFS custody is invalid for {}: {error}",
                    object.oid
                )
            })? {
                return Err(format!("restored LFS custody is missing {}", object.oid));
            }
        }
        self.recheck(deadline)
    }

    pub fn receipt(&self) -> Receipt {
        receipt(&self.verified)
    }
}

fn match_inventory(verified: &VerifiedArchive, inventory: &Inventory) -> Result<(), String> {
    if verified.source() != &inventory.source {
        return Err("LFS companion belongs to a different exact source snapshot".into());
    }
    if verified.seal().payload_bytes != inventory.payload_bytes
        || !verified
            .records()
            .iter()
            .map(|record| record.object())
            .eq(inventory.objects.iter().copied())
    {
        return Err("LFS companion does not exactly match all native source pointers".into());
    }
    Ok(())
}

fn receipt(verified: &VerifiedArchive) -> Receipt {
    let seal = verified.seal();
    Receipt {
        digest: seal.digest,
        bytes: seal.bytes,
        objects: verified.records().len(),
        payload_bytes: seal.payload_bytes,
    }
}

fn artifact_operation<'a>(
    deadline: Deadline,
    live: &'a dyn Fn() -> bool,
) -> Result<ArtifactOperation<'a>, String> {
    // The custody primitive permits at most one hour. Narrow that envelope;
    // never renew the enclosing backup operation's absolute deadline.
    ArtifactOperation::new(
        MAX_OBJECT_BYTES,
        deadline.remaining()?.min(Duration::from_secs(3600)),
        live,
    )
    .map_err(|error| error.to_string())
}

fn custody_path(root: &Path) -> Result<PathBuf, String> {
    let path = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(root)
    };
    if !path
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("LFS custody paths must not contain parent traversal".into());
    }
    Ok(path)
}

fn inspect_directory(path: &Path) -> Result<(), String> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        let metadata = fs::symlink_metadata(&prefix)
            .map_err(|error| format!("cannot inspect LFS custody directory: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("LFS custody path contains a symlink or non-directory".into());
        }
    }
    Ok(())
}

fn open_store(root: &Path, source: SourceIdentity) -> Result<LfsStore, String> {
    let root = custody_path(root)?;
    // LfsStore::open selects an existing private directory without creating
    // any namespace, and validates every ancestor against symlink traversal.
    LfsStore::open(&root, source.tenant, source.repository, source.incarnation)
        .map_err(|error| format!("cannot select LFS custody: {error}"))
}

fn open_archive(path: &Path, maximum: u64) -> Result<File, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect LFS companion: {error}"))?;
    let valid = |metadata: &fs::Metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() != 0
            && metadata.len() <= maximum
    };
    if !valid(&before) {
        return Err("LFS companion must be a nonempty bounded regular file".into());
    }
    // Do not follow a substituted final symlink or block on a substituted FIFO.
    // The trusted-local operator owns the stability of all parent components.
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| format!("cannot open LFS companion: {error}"))?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if !valid(&after)
        || (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
    {
        return Err("LFS companion identity changed while opening".into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests;
