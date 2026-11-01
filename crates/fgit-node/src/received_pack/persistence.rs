//! Discardable received-pack custody across node restarts, never object authority.
//!
//! Every restored record is UNTRUSTED. Framing and SHA-256 detect corruption;
//! only native parsing, exact hint comparison and canonical collision-checked
//! object validation may promote it into the process-local received-pack cache.
//!
//! One namespace binds tenant, repository, incarnation and native hash format.
//! It owns 64 fixed record slots, one fixed staging slot and one stable empty
//! lock file. The configured logical byte budget charges each retained/staging
//! record for its raw bytes plus the existing cache metadata allowance. Eviction
//! precedes staging, so interruption cannot create unbounded orphan files or
//! exceed that allowance. Filesystem allocation overhead is not a physical-disk
//! quota. Missing, corrupt, busy and unavailable optional custody are misses;
//! cancellation remains the caller's explicit stop condition.

use super::{
    Deadline, ENTRY_OVERHEAD, HASH_CHUNK_BYTES, MAX_CAPTURE_BYTES, MAX_ENTRIES, OBJECT_OVERHEAD,
    ObjectType, PackError, PendingReceivedPack, VerifiedReceivedObject, check,
};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::{
    GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, RepositoryId, RepositoryIncarnationId,
    TenantId,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

const MAGIC: &[u8; 8] = b"FGRP0001";
const HEADER_BYTES: usize = 102;
const FOOTER_BYTES: usize = 32;
const STAGE: &str = "stage.rpack";
const LOCK: &str = "writer.lock";

/// A fingerprint and object hints are not proof of canonical object membership.
#[derive(Debug)]
pub(crate) struct Candidate {
    pub(crate) bytes: Vec<u8>,
    pub(crate) objects: Vec<VerifiedReceivedObject>,
    pub(crate) sha256: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct DurableStore {
    directory: PathBuf,
    binding: [u8; 50],
    format: GitHashAlgorithm,
    max_bytes: usize,
}

impl DurableStore {
    /// No filesystem access, including when the configured budget is zero.
    pub(crate) fn new(
        root: PathBuf,
        tenant: TenantId,
        repository: RepositoryId,
        incarnation: RepositoryIncarnationId,
        format: GitHashAlgorithm,
        max_bytes: usize,
    ) -> Self {
        let mut binding = [0; 50];
        binding[..16].copy_from_slice(tenant.as_bytes());
        binding[16..32].copy_from_slice(repository.as_bytes());
        binding[32..48].copy_from_slice(incarnation.as_bytes());
        binding[48..].copy_from_slice(&format.code_point().to_be_bytes());
        let mut hash = Sha256Hasher::new();
        hash.update(b"frankengit/received-pack-custody/v1\0");
        hash.update(&binding);
        let namespace = hash.finish();
        let mut name = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in namespace {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Self {
            directory: root.join(name),
            binding,
            format,
            max_bytes,
        }
    }

    /// Called only after native validation and canonical collision-checked
    /// placement. Optional custody failure never changes the receive outcome.
    pub(crate) fn persist(
        &self,
        pending: &PendingReceivedPack,
        deadline: &mut impl Deadline,
    ) -> Result<(), PackError> {
        check(deadline)?;
        if self.max_bytes == 0 {
            return Ok(());
        }
        #[cfg(unix)]
        let result = self.persist_parts(
            pending.entry.bytes.bytes(),
            &pending.entry.objects,
            pending.entry.receipt.sha256,
            deadline,
        );
        #[cfg(not(unix))]
        let result: Result<(), Miss> = {
            let _ = pending;
            Err(Miss::Unavailable)
        };
        // An I/O failure or optional corruption miss must never mask a stop
        // that became visible during that operation.
        check(deadline)?;
        match result {
            Err(Miss::Stopped) => Err(PackError::DeadlineExceeded),
            Ok(()) | Err(Miss::Unavailable) => Ok(()),
        }
    }

    /// Read only eligible hints before allocating their raw bytes. This is a
    /// candidate filter, not authorization: the caller must independently
    /// validate the exact pack and every canonical object before any reuse.
    pub(crate) fn candidates(
        &self,
        selected: &BTreeSet<GitOid>,
        held: &BTreeSet<GitOid>,
        already_verified: &BTreeSet<[u8; 32]>,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<Candidate>, PackError> {
        check(deadline)?;
        if self.max_bytes == 0 || selected.is_empty() {
            return Ok(Vec::new());
        }
        #[cfg(unix)]
        let result = self.read_candidates(selected, held, already_verified, deadline);
        #[cfg(not(unix))]
        let result: Result<Vec<Candidate>, Miss> = {
            let _ = (held, already_verified);
            Err(Miss::Unavailable)
        };
        check(deadline)?;
        match result {
            Ok(candidates) => Ok(candidates),
            Err(Miss::Unavailable) => Ok(Vec::new()),
            Err(Miss::Stopped) => Err(PackError::DeadlineExceeded),
        }
    }

    fn header(&self, count: usize, raw_bytes: usize, sha256: [u8; 32]) -> Option<Header> {
        if count == 0
            || count > u32::MAX as usize
            || raw_bytes < 12 + self.format.digest_len()
            || raw_bytes > MAX_CAPTURE_BYTES
        {
            return None;
        }
        let charge = count
            .checked_mul(OBJECT_OVERHEAD)?
            .checked_add(ENTRY_OVERHEAD)?
            .checked_add(raw_bytes)?;
        let encoded_bytes = count
            .checked_mul(self.format.digest_len() + 9)?
            .checked_add(HEADER_BYTES + FOOTER_BYTES)?
            .checked_add(raw_bytes)?;
        if charge > self.max_bytes || encoded_bytes > charge {
            return None;
        }
        Some(Header {
            count,
            raw_bytes,
            sha256,
            charge,
            encoded_bytes,
        })
    }

    fn decode_header(&self, bytes: &[u8; HEADER_BYTES], length: u64) -> Option<Header> {
        if &bytes[..8] != MAGIC || bytes[8..58] != self.binding {
            return None;
        }
        let count = u32::from_be_bytes(bytes[58..62].try_into().ok()?) as usize;
        let raw_bytes = usize::try_from(u64::from_be_bytes(bytes[62..70].try_into().ok()?)).ok()?;
        let header = self.header(count, raw_bytes, bytes[70..102].try_into().ok()?)?;
        (u64::try_from(header.encoded_bytes).ok()? == length).then_some(header)
    }

    fn encode_header(&self, header: &Header) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..58].copy_from_slice(&self.binding);
        bytes[58..62].copy_from_slice(&(header.count as u32).to_be_bytes());
        bytes[62..70].copy_from_slice(&(header.raw_bytes as u64).to_be_bytes());
        bytes[70..].copy_from_slice(&header.sha256);
        bytes
    }
}

struct Header {
    count: usize,
    raw_bytes: usize,
    sha256: [u8; 32],
    charge: usize,
    encoded_bytes: usize,
}

// Failed checksums consume inspection work too: repeated corrupt slots must
// not multiply the configured raw/metadata read allowance by the slot count.
struct ReadBudget {
    retained: usize,
    inspected: usize,
}

impl ReadBudget {
    const fn new(max_bytes: usize) -> Self {
        Self {
            retained: max_bytes,
            inspected: max_bytes,
        }
    }
}

#[derive(Debug)]
enum Miss {
    Unavailable,
    Stopped,
}

impl From<std::io::Error> for Miss {
    fn from(_: std::io::Error) -> Self {
        Self::Unavailable
    }
}

fn checkpoint(deadline: &mut impl Deadline) -> Result<(), Miss> {
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(Miss::Stopped)
    }
}

#[cfg(unix)]
use {
    rustix::fs::{AtFlags, Mode, OFlags},
    std::fs::{File, Metadata},
    std::io::{Read, Write},
    std::os::unix::fs::MetadataExt,
    std::path::{Component, Path},
};

#[cfg(unix)]
impl From<rustix::io::Errno> for Miss {
    fn from(_: rustix::io::Errno) -> Self {
        Self::Unavailable
    }
}

#[cfg(unix)]
impl DurableStore {
    fn persist_parts(
        &self,
        raw: &[u8],
        objects: &[VerifiedReceivedObject],
        sha256: [u8; 32],
        deadline: &mut impl Deadline,
    ) -> Result<(), Miss> {
        checkpoint(deadline)?;
        let header = self
            .header(objects.len(), raw.len(), sha256)
            .ok_or(Miss::Unavailable)?;
        let mut previous = None;
        for object in objects {
            checkpoint(deadline)?;
            if object.id.algorithm() != self.format
                || object.id.is_zero()
                || previous.is_some_and(|id| id >= object.id)
            {
                return Err(Miss::Unavailable);
            }
            previous = Some(object.id);
        }
        let directory = open_directory(&self.directory, true, deadline)?;
        let _lock = writer_lock(&directory)?;
        checkpoint(deadline)?;
        // Only the one known staging name can survive a crash. Under the same
        // lock, removing it releases all prior staging responsibility.
        if let Some(file) = open_slot(&directory, STAGE)? {
            let metadata = private_file(&file)?;
            unlink_checked(&directory, STAGE, &metadata)?;
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(MAX_ENTRIES)
            .map_err(|_| Miss::Unavailable)?;
        let mut resident = 0usize;
        for index in 0..MAX_ENTRIES {
            checkpoint(deadline)?;
            let name = slot_name(index);
            let Some(mut file) = open_slot(&directory, &name)? else {
                slots.push(None);
                continue;
            };
            let metadata = private_file(&file)?;
            let mut bytes = [0; HEADER_BYTES];
            let decoded = if metadata.len() >= (HEADER_BYTES + FOOTER_BYTES) as u64 {
                read_exact(&mut file, &mut bytes, deadline)?;
                self.decode_header(&bytes, metadata.len())
            } else {
                None
            };
            let Some(stored) = decoded else {
                // The bounded namespace is disposable; never retain a corrupt
                // slot as an uncharged allocation beside later writes.
                unlink_checked(&directory, &name, &metadata)?;
                slots.push(None);
                continue;
            };
            resident = resident
                .checked_add(stored.charge)
                .ok_or(Miss::Unavailable)?;
            slots.push(Some((stored, metadata)));
        }
        let target = slots
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|(entry, _)| entry.sha256 == sha256)
            })
            .or_else(|| slots.iter().position(Option::is_none))
            .unwrap_or(usize::from(sha256[0]) % MAX_ENTRIES);
        // Free the destination and enough additional records BEFORE staging.
        // A retry with the same fingerprint replaces a possibly damaged copy.
        for step in 0..MAX_ENTRIES {
            checkpoint(deadline)?;
            let index = (target + step) % MAX_ENTRIES;
            if index == target || resident > self.max_bytes - header.charge {
                if let Some((entry, metadata)) = slots[index].take() {
                    unlink_checked(&directory, &slot_name(index), &metadata)?;
                    resident = resident
                        .checked_sub(entry.charge)
                        .ok_or(Miss::Unavailable)?;
                }
            }
        }
        if resident > self.max_bytes - header.charge {
            return Err(Miss::Unavailable);
        }
        directory.sync_all()?;
        checkpoint(deadline)?;
        let mut stage = create_private(&directory, STAGE)?;
        self.write_record(&mut stage, &header, raw, objects, deadline)?;
        stage.sync_all()?;
        checkpoint(deadline)?;
        let metadata = private_file(&stage)?;
        if metadata.len() != header.encoded_bytes as u64 {
            return Err(Miss::Unavailable);
        }
        verify_named(&directory, STAGE, &metadata)?;
        rustix::fs::renameat(&directory, STAGE, &directory, slot_name(target))?;
        directory.sync_all()?;
        checkpoint(deadline)
    }

    fn write_record(
        &self,
        file: &mut File,
        header: &Header,
        raw: &[u8],
        objects: &[VerifiedReceivedObject],
        deadline: &mut impl Deadline,
    ) -> Result<(), Miss> {
        let bytes = self.encode_header(header);
        let mut record_hash = Sha256Hasher::new();
        write_hashed(file, &bytes, &mut record_hash, deadline)?;
        for object in objects {
            checkpoint(deadline)?;
            let mut row = [0; 41];
            let width = self.format.digest_len();
            row[..width].copy_from_slice(object.id.as_bytes());
            row[width] = object.kind.type_code();
            row[width + 1..width + 9].copy_from_slice(&(object.bytes as u64).to_be_bytes());
            write_hashed(file, &row[..width + 9], &mut record_hash, deadline)?;
        }
        let mut raw_hash = Sha256Hasher::new();
        for chunk in raw.chunks(HASH_CHUNK_BYTES) {
            write_hashed(file, chunk, &mut record_hash, deadline)?;
            raw_hash.update(chunk);
        }
        if raw_hash.finish() != header.sha256 {
            return Err(Miss::Unavailable);
        }
        checkpoint(deadline)?;
        file.write_all(&record_hash.finish())?;
        checkpoint(deadline)
    }

    fn read_candidates(
        &self,
        selected: &BTreeSet<GitOid>,
        held: &BTreeSet<GitOid>,
        already_verified: &BTreeSet<[u8; 32]>,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<Candidate>, Miss> {
        let directory = open_directory(&self.directory, false, deadline)?;
        let _lock = writer_lock(&directory)?;
        let mut budget = ReadBudget::new(self.max_bytes);
        let mut candidates = Vec::new();
        for index in 0..MAX_ENTRIES {
            checkpoint(deadline)?;
            match self.read_candidate(
                &directory,
                index,
                selected,
                held,
                already_verified,
                &mut budget,
                deadline,
            ) {
                Ok((candidate, charge)) => {
                    candidates
                        .try_reserve_exact(1)
                        .map_err(|_| Miss::Unavailable)?;
                    budget.retained = budget
                        .retained
                        .checked_sub(charge)
                        .ok_or(Miss::Unavailable)?;
                    candidates.push(candidate);
                }
                Err(Miss::Unavailable) => {}
                Err(error @ Miss::Stopped) => return Err(error),
            }
        }
        checkpoint(deadline)?;
        Ok(candidates)
    }

    fn read_candidate(
        &self,
        directory: &File,
        index: usize,
        selected: &BTreeSet<GitOid>,
        held: &BTreeSet<GitOid>,
        already_verified: &BTreeSet<[u8; 32]>,
        budget: &mut ReadBudget,
        deadline: &mut impl Deadline,
    ) -> Result<(Candidate, usize), Miss> {
        let name = slot_name(index);
        let mut file = open_slot(directory, &name)?.ok_or(Miss::Unavailable)?;
        let metadata = private_file(&file)?;
        let mut bytes = [0; HEADER_BYTES];
        read_exact(&mut file, &mut bytes, deadline)?;
        let header = self
            .decode_header(&bytes, metadata.len())
            .ok_or(Miss::Unavailable)?;
        // This fingerprint is untrusted. It may suppress optional work only;
        // a match never promotes a record or creates any evidence of its own.
        if header.charge > budget.retained || already_verified.contains(&header.sha256) {
            return Err(Miss::Unavailable);
        }
        budget.inspected = budget
            .inspected
            .checked_sub(header.charge)
            .ok_or(Miss::Unavailable)?;
        let mut record_hash = Sha256Hasher::new();
        record_hash.update(&bytes);
        checkpoint(deadline)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(header.count)
            .map_err(|_| Miss::Unavailable)?;
        let mut intersects = false;
        let mut previous = None;
        for _ in 0..header.count {
            let mut row = [0; 41];
            let width = self.format.digest_len();
            read_exact(&mut file, &mut row[..width + 9], deadline)?;
            record_hash.update(&row[..width + 9]);
            let id = match self.format {
                GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes(
                    row[..20].try_into().map_err(|_| Miss::Unavailable)?,
                )),
                GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes(
                    row[..32].try_into().map_err(|_| Miss::Unavailable)?,
                )),
            };
            let kind = match row[width] {
                1 => ObjectType::Commit,
                2 => ObjectType::Tree,
                3 => ObjectType::Blob,
                4 => ObjectType::Tag,
                _ => return Err(Miss::Unavailable),
            };
            if id.is_zero()
                || previous.is_some_and(|previous| previous >= id)
                || (!selected.contains(&id) && !held.contains(&id))
            {
                return Err(Miss::Unavailable);
            }
            intersects |= selected.contains(&id);
            previous = Some(id);
            let bytes = usize::try_from(u64::from_be_bytes(
                row[width + 1..width + 9]
                    .try_into()
                    .map_err(|_| Miss::Unavailable)?,
            ))
            .map_err(|_| Miss::Unavailable)?;
            objects.push(VerifiedReceivedObject { id, kind, bytes });
        }
        if !intersects {
            return Err(Miss::Unavailable);
        }
        checkpoint(deadline)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(header.raw_bytes)
            .map_err(|_| Miss::Unavailable)?;
        raw.resize(header.raw_bytes, 0);
        let mut raw_hash = Sha256Hasher::new();
        for chunk in raw.chunks_mut(HASH_CHUNK_BYTES) {
            read_exact(&mut file, chunk, deadline)?;
            record_hash.update(chunk);
            raw_hash.update(chunk);
        }
        let mut footer = [0; FOOTER_BYTES];
        read_exact(&mut file, &mut footer, deadline)?;
        if raw_hash.finish() != header.sha256 || record_hash.finish() != footer {
            return Err(Miss::Unavailable);
        }
        let after = private_file(&file)?;
        if !same_file(&metadata, &after) {
            return Err(Miss::Unavailable);
        }
        verify_named(directory, &name, &after)?;
        checkpoint(deadline)?;
        Ok((
            Candidate {
                bytes: raw,
                objects,
                sha256: header.sha256,
            },
            header.charge,
        ))
    }
}

#[cfg(unix)]
fn slot_name(index: usize) -> String {
    format!("slot-{index:02x}.rpack")
}

#[cfg(unix)]
fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

/// Walk bounded absolute components by directory descriptor. Symlinks at any
/// component refuse; directory replacement cannot redirect later slot access.
#[cfg(unix)]
fn open_directory(path: &Path, create: bool, deadline: &mut impl Deadline) -> Result<File, Miss> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(Miss::Unavailable);
    }
    checkpoint(deadline)?;
    let mut directory = File::from(rustix::fs::open(
        "/",
        read_flags() | OFlags::DIRECTORY,
        Mode::empty(),
    )?);
    for (index, component) in path.components().enumerate() {
        checkpoint(deadline)?;
        if index >= 128 {
            return Err(Miss::Unavailable);
        }
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => return Err(Miss::Unavailable),
        };
        let opened = rustix::fs::openat(
            &directory,
            name,
            read_flags() | OFlags::DIRECTORY,
            Mode::empty(),
        );
        let child = match opened {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) if create => {
                match rustix::fs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) => directory.sync_all()?,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                checkpoint(deadline)?;
                File::from(rustix::fs::openat(
                    &directory,
                    name,
                    read_flags() | OFlags::DIRECTORY,
                    Mode::empty(),
                )?)
            }
            Err(error) => return Err(error.into()),
        };
        directory = child;
    }
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(Miss::Unavailable);
    }
    checkpoint(deadline)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_slot(directory: &File, name: &str) -> Result<Option<File>, Miss> {
    match rustix::fs::openat(directory, name, read_flags(), Mode::empty()) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn create_private(directory: &File, name: &str) -> Result<File, Miss> {
    Ok(File::from(rustix::fs::openat(
        directory,
        name,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )?))
}

#[cfg(unix)]
fn writer_lock(directory: &File) -> Result<File, Miss> {
    let file = match create_private(directory, LOCK) {
        Ok(file) => file,
        Err(_) => File::from(rustix::fs::openat(
            directory,
            LOCK,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?),
    };
    let metadata = private_file(&file)?;
    if metadata.len() != 0 {
        return Err(Miss::Unavailable);
    }
    file.try_lock().map_err(|_| Miss::Unavailable)?;
    verify_named(directory, LOCK, &metadata)?;
    Ok(file)
}

#[cfg(unix)]
fn private_file(file: &File) -> Result<Metadata, Miss> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        return Err(Miss::Unavailable);
    }
    Ok(metadata)
}

#[cfg(unix)]
fn same_file(first: &Metadata, next: &Metadata) -> bool {
    (
        first.dev(),
        first.ino(),
        first.len(),
        first.mtime(),
        first.mtime_nsec(),
        first.ctime(),
        first.ctime_nsec(),
    ) == (
        next.dev(),
        next.ino(),
        next.len(),
        next.mtime(),
        next.mtime_nsec(),
        next.ctime(),
        next.ctime_nsec(),
    )
}

#[cfg(unix)]
fn verify_named(directory: &File, name: &str, metadata: &Metadata) -> Result<(), Miss> {
    let named = open_slot(directory, name)?.ok_or(Miss::Unavailable)?;
    let current = private_file(&named)?;
    if !same_file(metadata, &current) {
        return Err(Miss::Unavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn unlink_checked(directory: &File, name: &str, metadata: &Metadata) -> Result<(), Miss> {
    verify_named(directory, name, metadata)?;
    rustix::fs::unlinkat(directory, name, AtFlags::empty())?;
    Ok(())
}

#[cfg(unix)]
fn read_exact(file: &mut File, bytes: &mut [u8], deadline: &mut impl Deadline) -> Result<(), Miss> {
    for chunk in bytes.chunks_mut(HASH_CHUNK_BYTES) {
        checkpoint(deadline)?;
        file.read_exact(chunk)?;
        checkpoint(deadline)?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_hashed(
    file: &mut File,
    bytes: &[u8],
    hash: &mut Sha256Hasher,
    deadline: &mut impl Deadline,
) -> Result<(), Miss> {
    for chunk in bytes.chunks(HASH_CHUNK_BYTES) {
        checkpoint(deadline)?;
        file.write_all(chunk)?;
        hash.update(chunk);
        checkpoint(deadline)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
