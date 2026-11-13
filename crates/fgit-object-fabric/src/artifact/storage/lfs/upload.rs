//! Persistent, principal-bound resumable upload custody. This is private staging,
//! not a Git ref, artifact publication, or authorization grant. One scope catalog
//! lock bounds reservations; one session lock owns each checked prefix. The
//! caller supplies an authenticated principal and a finite, framed request body.
use super::{LfsObject, LfsOid, LfsStore, MAX_OBJECT_BYTES};
use crate::artifact::storage::{
    ArtifactOperation, ArtifactStorageError, CHUNK_BYTES, hex, io as storage_io,
    local::private_directory,
};
use fgit_crypto::{DigestHasher, Sha256Hasher, sha256_digest};
use fgit_types::PrincipalId;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Shared by all authenticated principals within one artifact scope.
pub const MAX_ACTIVE_UPLOADS: usize = 64;
/// Reserve declared object sizes, including bytes not yet received.
pub const MAX_RESERVED_UPLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const CHECKPOINT_BYTES: u64 = 1024 * 1024;
const IDENTITY_MAGIC: &[u8; 8] = b"FGLFID01";
const CHECKPOINT_MAGIC: &[u8; 8] = b"FGLFCP01";
const IDENTITY_BYTES: usize = 64;
const CHECKPOINT_SIZE: usize = 81;
const SESSION_FILES: [&str; 6] = [
    "identity.next",
    "checkpoint.next",
    "payload",
    "checkpoint",
    "identity",
    "lock",
];

/// `complete` is true only after verified immutable custody and durable cleanup.
/// An incomplete state always has `offset < object.size`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadState {
    pub offset: u64,
    pub complete: bool,
}

#[derive(Debug)]
pub enum UploadError {
    Busy,
    Offset {
        expected: u64,
    },
    NotFound,
    Quota,
    /// A retained checkpoint, prefix, or final digest is inconsistent. No reset
    /// or overwrite is attempted; operator investigation is required.
    Corrupt,
    Storage(ArtifactStorageError),
}
impl fmt::Display for UploadError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "LFS upload refused: {self:?}")
    }
}
impl std::error::Error for UploadError {}
impl From<ArtifactStorageError> for UploadError {
    fn from(error: ArtifactStorageError) -> Self {
        Self::Storage(error)
    }
}
fn io_error(operation: &'static str, error: io::Error) -> UploadError {
    storage_io(operation, error).into()
}

impl LfsStore {
    /// Create or reopen one principal-bound session. Repeated negotiation does
    /// not reserve twice or reset an acknowledged prefix. Empty objects complete
    /// immediately through the same immutable custody verification.
    pub fn begin_upload(
        &self,
        object: LfsObject,
        principal: PrincipalId,
        op: &ArtifactOperation<'_>,
    ) -> Result<UploadState, UploadError> {
        op.admit(object.size)?;
        if self.contains(object, op)? {
            return self.completed(object, principal, op);
        }
        if object.size == 0 {
            if object.oid != LfsOid::of_payload(b"") {
                return Err(UploadError::Corrupt);
            }
            self.put(object, &mut io::empty(), op)?;
            if !self.contains(object, op)? {
                return Err(UploadError::Corrupt);
            }
            return self.completed(object, principal, op);
        }
        let catalog = Catalog::open(self, true)?;
        let mut session = catalog.session(self, object, principal, true, op)?;
        drop(catalog);
        session.verify(op)?;
        self.session_state(object, principal, session, op)
    }

    /// Verify the durable prefix after a reopen. A final-ready staging record is
    /// replayed into immutable custody before reporting completion; merely
    /// receiving the declared length is never a complete upload.
    pub fn upload_status(
        &self,
        object: LfsObject,
        principal: PrincipalId,
        op: &ArtifactOperation<'_>,
    ) -> Result<UploadState, UploadError> {
        op.admit(object.size)?;
        if self.contains(object, op)? {
            return self.completed(object, principal, op);
        }
        let catalog = Catalog::open(self, false)?;
        let mut session = catalog.session(self, object, principal, false, op)?;
        drop(catalog);
        session.verify(op)?;
        self.session_state(object, principal, session, op)
    }

    /// Read-only PATCH admission before consuming a body or acknowledging
    /// `100 Continue`. This verifies retained custody and takes nonblocking
    /// ownership, but never initializes, replays, cleans up, or truncates a
    /// session. `append_upload` repeats the check under its own exclusive owner.
    pub fn check_upload_offset(
        &self,
        object: LfsObject,
        principal: PrincipalId,
        expected_offset: u64,
        op: &ArtifactOperation<'_>,
    ) -> Result<(), UploadError> {
        op.admit(object.size)?;
        if self.contains(object, op)? {
            return if expected_offset == object.size {
                Ok(())
            } else {
                Err(UploadError::Offset {
                    expected: object.size,
                })
            };
        }
        let catalog = Catalog::open(self, false)?;
        let mut session = catalog.session(self, object, principal, false, op)?;
        drop(catalog);
        session.verify(op)?;
        session.check_offset(expected_offset)
    }

    /// Append a framed body at its exact durable offset under one exclusive
    /// session owner. An offset conflict never consumes the body or changes
    /// staging. Interrupted requests checkpoint successfully written prefixes;
    /// the caller must HEAD before retrying after any ambiguous result.
    pub fn append_upload(
        &self,
        object: LfsObject,
        principal: PrincipalId,
        expected_offset: u64,
        input: &mut impl Read,
        op: &ArtifactOperation<'_>,
    ) -> Result<UploadState, UploadError> {
        op.admit(object.size)?;
        if self.contains(object, op)? {
            if expected_offset != object.size {
                return Err(UploadError::Offset {
                    expected: object.size,
                });
            }
            require_eof(input, op)?;
            return self.completed(object, principal, op);
        }
        let catalog = Catalog::open(self, false)?;
        let mut session = catalog.session(self, object, principal, false, op)?;
        drop(catalog);
        let mut hash = session.verify(op)?;
        session.check_offset(expected_offset)?;
        if session.checkpoint.state == State::Ready {
            require_eof(input, op)?;
            return self.finish_upload(object, principal, session, op);
        }
        op.checkpoint()?;
        // Only unacknowledged crash residue is discarded. A checked prefix is
        // never reset, repaired, or inferred from the file length.
        session
            .payload
            .set_len(expected_offset)
            .map_err(|e| io_error("truncate unacknowledged LFS suffix", e))?;
        session
            .payload
            .seek(SeekFrom::Start(expected_offset))
            .map_err(|e| io_error("seek LFS upload offset", e))?;
        let mut offset = expected_offset;
        let mut buffer = [0_u8; CHUNK_BYTES];
        while offset < object.size {
            if let Err(error) = op.checkpoint() {
                session.save_progress(offset, &hash)?;
                return Err(error.into());
            }
            let capacity = (object.size - offset).min(buffer.len() as u64) as usize;
            let count = match input.read(&mut buffer[..capacity]) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    session.save_progress(offset, &hash)?;
                    return Err(io_error("read LFS upload body", error));
                }
            };
            if let Err(error) = op.checkpoint() {
                session.save_progress(offset, &hash)?;
                return Err(error.into());
            }
            if count == 0 {
                session.save_progress(offset, &hash)?;
                session.confirm_receipt(self, op)?;
                return Ok(UploadState {
                    offset,
                    complete: false,
                });
            }
            if let Err(error) = session.payload.write_all(&buffer[..count]) {
                session.save_progress(offset, &hash)?;
                return Err(io_error("write LFS upload prefix", error));
            }
            DigestHasher::update(&mut hash, &buffer[..count]);
            offset += count as u64;
            if offset < object.size && offset - session.checkpoint.offset >= CHECKPOINT_BYTES {
                session.save_progress(offset, &hash)?;
            }
        }
        // Framing/length failures must never leave a complete checkpoint: a Tus
        // client treats HEAD offset == length as success without another PATCH.
        require_eof(input, op)?;
        let digest = DigestHasher::finish(hash);
        if digest != object.oid.0 {
            session.save(Checkpoint {
                offset,
                digest,
                state: State::Corrupt,
            })?;
            return Err(UploadError::Corrupt);
        }
        session.save(Checkpoint {
            offset,
            digest,
            state: State::Ready,
        })?;
        self.finish_upload(object, principal, session, op)
    }

    fn session_state(
        &self,
        object: LfsObject,
        principal: PrincipalId,
        session: Session,
        op: &ArtifactOperation<'_>,
    ) -> Result<UploadState, UploadError> {
        if session.checkpoint.state == State::Ready {
            self.finish_upload(object, principal, session, op)
        } else {
            session.confirm_receipt(self, op)?;
            Ok(UploadState {
                offset: session.checkpoint.offset,
                complete: false,
            })
        }
    }

    fn finish_upload(
        &self,
        object: LfsObject,
        _principal: PrincipalId,
        mut session: Session,
        op: &ArtifactOperation<'_>,
    ) -> Result<UploadState, UploadError> {
        session
            .payload
            .seek(SeekFrom::Start(0))
            .map_err(|e| io_error("rewind complete LFS upload", e))?;
        self.put(object, &mut session.payload, op)?;
        if !self.contains(object, op)? {
            return Err(UploadError::Corrupt);
        }
        self.0.sync_namespace(op)?;
        let catalog = Catalog::open(self, false)?;
        remove_completed_session(&session.directory)?;
        sync(&catalog.directory)?;
        op.checkpoint()?;
        Ok(UploadState {
            offset: object.size,
            complete: true,
        })
    }

    fn completed(
        &self,
        object: LfsObject,
        principal: PrincipalId,
        op: &ArtifactOperation<'_>,
    ) -> Result<UploadState, UploadError> {
        self.0.sync_namespace(op)?;
        let catalog = match Catalog::open(self, false) {
            Ok(catalog) => catalog,
            Err(UploadError::NotFound) => {
                return Ok(UploadState {
                    offset: object.size,
                    complete: true,
                });
            }
            Err(error) => return Err(error),
        };
        let descriptor = Descriptor::new(object, principal);
        let directory = catalog.directory.join(descriptor.key(self));
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("inspect completed LFS session", error)),
            Ok(_) => {
                private_directory(&directory)?;
                let _owner = lock_file(&directory.join("lock"), true)?;
                // Canonical custody has already verified. This also finishes a
                // cleanup interrupted after some staging files were removed.
                remove_completed_session(&directory)?;
            }
        }
        // Also settle an earlier cleanup whose remove succeeded but whose
        // catalog-directory fsync failed before the response was returned.
        sync(&catalog.directory)?;
        op.checkpoint()?;
        Ok(UploadState {
            offset: object.size,
            complete: true,
        })
    }
}

fn require_eof(input: &mut impl Read, op: &ArtifactOperation<'_>) -> Result<(), UploadError> {
    let mut byte = [0_u8; 1];
    loop {
        op.checkpoint()?;
        match input.read(&mut byte) {
            Ok(0) => return op.checkpoint().map_err(Into::into),
            Ok(_) => return Err(ArtifactStorageError::PayloadMismatch.into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error("finish LFS request framing", error)),
        }
    }
}

struct Descriptor([u8; IDENTITY_BYTES]);
impl Descriptor {
    fn new(object: LfsObject, principal: PrincipalId) -> Self {
        let mut bytes = [0; IDENTITY_BYTES];
        bytes[..8].copy_from_slice(IDENTITY_MAGIC);
        bytes[8..24].copy_from_slice(principal.as_bytes());
        bytes[24..56].copy_from_slice(&object.oid.0);
        bytes[56..].copy_from_slice(&object.size.to_be_bytes());
        Self(bytes)
    }
    fn size(&self) -> Result<u64, UploadError> {
        if &self.0[..8] != IDENTITY_MAGIC {
            return Err(UploadError::Corrupt);
        }
        let size = u64::from_be_bytes(self.0[56..].try_into().expect("fixed descriptor"));
        if size == 0 || size > MAX_OBJECT_BYTES {
            return Err(UploadError::Corrupt);
        }
        Ok(size)
    }
    fn commitment(&self, store: &LfsStore) -> [u8; 32] {
        let mut hash = Sha256Hasher::new();
        DigestHasher::update(&mut hash, b"frankengit/lfs-upload-session/v1\0");
        DigestHasher::update(&mut hash, store.0.scope().commitment().bytes().as_bytes());
        DigestHasher::update(&mut hash, &self.0);
        DigestHasher::finish(hash)
    }
    fn key(&self, store: &LfsStore) -> String {
        self.commitment(store)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

struct Catalog {
    directory: PathBuf,
    _owner: File,
}
impl Catalog {
    fn open(store: &LfsStore, create: bool) -> Result<Self, UploadError> {
        private_directory(store.0.root()).map_err(|error| match error {
            ArtifactStorageError::NotFound => ArtifactStorageError::Io {
                operation: "selected LFS root unavailable",
                kind: io::ErrorKind::NotFound,
            },
            other => other,
        })?;
        let directory = store.0.root().join(format!(
            ".lfs-uploads-{}",
            hex(&store.0.scope().commitment())
        ));
        if create {
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => sync(store.0.root())?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_error("create LFS upload namespace", error)),
            }
        }
        private_directory(&directory).map_err(|error| match error {
            ArtifactStorageError::NotFound => UploadError::NotFound,
            other => other.into(),
        })?;
        let owner = lock_file(&directory.join("lock"), create)?;
        Ok(Self {
            directory,
            _owner: owner,
        })
    }
    fn reserve(
        &self,
        store: &LfsStore,
        size: u64,
        op: &ArtifactOperation<'_>,
    ) -> Result<(), UploadError> {
        let entries =
            fs::read_dir(&self.directory).map_err(|e| io_error("list LFS reservations", e))?;
        let mut count = 0_usize;
        let mut bytes = size;
        for entry in entries {
            op.checkpoint()?;
            let entry = entry.map_err(|e| io_error("read LFS reservation", e))?;
            let name = entry.file_name();
            if name == "lock" {
                continue;
            }
            count += 1;
            if count >= MAX_ACTIVE_UPLOADS {
                return Err(UploadError::Quota);
            }
            let name = name.to_str().ok_or(UploadError::Corrupt)?;
            if name.len() != 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(UploadError::Corrupt);
            }
            private_directory(&entry.path())?;
            let reserved = match read_fixed::<IDENTITY_BYTES>(&entry.path().join("identity")) {
                Ok(raw) => {
                    let descriptor = Descriptor(raw);
                    if descriptor.key(store) != name {
                        return Err(UploadError::Corrupt);
                    }
                    descriptor.size()?
                }
                // Initialization/cleanup may be interrupted. Charge the full
                // object ceiling until exact retry finishes that session.
                Err(UploadError::NotFound) => MAX_OBJECT_BYTES,
                Err(error) => return Err(error),
            };
            bytes = bytes.checked_add(reserved).ok_or(UploadError::Quota)?;
            if bytes > MAX_RESERVED_UPLOAD_BYTES {
                return Err(UploadError::Quota);
            }
        }
        Ok(())
    }
    fn session(
        &self,
        store: &LfsStore,
        object: LfsObject,
        principal: PrincipalId,
        create: bool,
        op: &ArtifactOperation<'_>,
    ) -> Result<Session, UploadError> {
        let descriptor = Descriptor::new(object, principal);
        let directory = self.directory.join(descriptor.key(store));
        let exists = match fs::symlink_metadata(&directory) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(io_error("inspect LFS session", error)),
        };
        if !exists {
            if !create {
                return Err(UploadError::NotFound);
            }
            self.reserve(store, object.size, op)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|e| io_error("create LFS session", e))?;
            sync(&self.directory)?;
        }
        private_directory(&directory)?;
        let owner = lock_file(&directory.join("lock"), create)?;
        checked_entries(&directory)?;
        match read_fixed::<IDENTITY_BYTES>(&directory.join("identity")) {
            Ok(raw) if raw == descriptor.0 => {}
            Ok(_) => return Err(UploadError::Corrupt),
            Err(UploadError::NotFound) if create => {
                if exists_file(&directory.join("payload"))?
                    || exists_file(&directory.join("checkpoint"))?
                {
                    return Err(UploadError::Corrupt);
                }
                atomic_record(&directory, "identity", &descriptor.0)?;
            }
            Err(UploadError::NotFound) => return Err(UploadError::Corrupt),
            Err(error) => return Err(error),
        }
        let binding = descriptor.commitment(store);
        let retained = match read_fixed::<CHECKPOINT_SIZE>(&directory.join("checkpoint")) {
            Ok(raw) => Some(Checkpoint::decode(&raw, &binding, object)?),
            Err(UploadError::NotFound) if create => None,
            Err(UploadError::NotFound) => return Err(UploadError::Corrupt),
            Err(error) => return Err(error),
        };
        let payload =
            checked_file(&directory.join("payload"), retained.is_none()).map_err(|error| {
                match error {
                    UploadError::NotFound => UploadError::Corrupt,
                    other => other,
                }
            })?;
        let checkpoint = match retained {
            Some(checkpoint) => checkpoint,
            None => {
                if payload
                    .metadata()
                    .map_err(|e| io_error("inspect new LFS payload", e))?
                    .len()
                    != 0
                {
                    return Err(UploadError::Corrupt);
                }
                let checkpoint = Checkpoint {
                    offset: 0,
                    digest: sha256_digest(b""),
                    state: State::Active,
                };
                payload
                    .sync_all()
                    .map_err(|e| io_error("sync empty LFS payload", e))?;
                atomic_record(&directory, "checkpoint", &checkpoint.encode(&binding))?;
                checkpoint
            }
        };
        Ok(Session {
            directory,
            _owner: owner,
            payload,
            binding,
            checkpoint,
            object,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Active,
    Ready,
    Corrupt,
}
#[derive(Clone, Copy)]
struct Checkpoint {
    offset: u64,
    digest: [u8; 32],
    state: State,
}
impl Checkpoint {
    fn encode(self, binding: &[u8; 32]) -> [u8; CHECKPOINT_SIZE] {
        let mut bytes = [0; CHECKPOINT_SIZE];
        bytes[..8].copy_from_slice(CHECKPOINT_MAGIC);
        bytes[8..40].copy_from_slice(binding);
        bytes[40..48].copy_from_slice(&self.offset.to_be_bytes());
        bytes[48..80].copy_from_slice(&self.digest);
        bytes[80] = match self.state {
            State::Active => 0,
            State::Ready => 1,
            State::Corrupt => 2,
        };
        bytes
    }
    fn decode(
        raw: &[u8; CHECKPOINT_SIZE],
        binding: &[u8; 32],
        object: LfsObject,
    ) -> Result<Self, UploadError> {
        if &raw[..8] != CHECKPOINT_MAGIC || &raw[8..40] != binding {
            return Err(UploadError::Corrupt);
        }
        let offset = u64::from_be_bytes(raw[40..48].try_into().expect("fixed checkpoint"));
        let digest: [u8; 32] = raw[48..80].try_into().expect("fixed digest");
        let state = match raw[80] {
            0 if offset < object.size => State::Active,
            1 if offset == object.size && digest == object.oid.0 => State::Ready,
            _ => return Err(UploadError::Corrupt),
        };
        Ok(Self {
            offset,
            digest,
            state,
        })
    }
}

struct Session {
    directory: PathBuf,
    _owner: File,
    payload: File,
    binding: [u8; 32],
    checkpoint: Checkpoint,
    object: LfsObject,
}
impl Session {
    fn confirm_receipt(
        &self,
        store: &LfsStore,
        op: &ArtifactOperation<'_>,
    ) -> Result<(), UploadError> {
        let catalog = self.directory.parent().ok_or(UploadError::Corrupt)?;
        // A prior mkdir/rename may be visible after its fsync reported failure.
        // Settle the entire namespace chain before acknowledging this prefix.
        for directory in [self.directory.as_path(), catalog, store.0.root()] {
            op.checkpoint()?;
            sync(directory)?;
        }
        op.checkpoint()?;
        Ok(())
    }
    fn check_offset(&self, expected: u64) -> Result<(), UploadError> {
        if self.checkpoint.offset == expected {
            return Ok(());
        }
        // This is a conflict hint, never an UploadState or a completion claim.
        // A Tus adapter returns 409 without an Upload-Offset response header;
        // HEAD must still publish Ready custody before reporting full length.
        Err(UploadError::Offset {
            expected: self.checkpoint.offset,
        })
    }
    fn verify(&mut self, op: &ArtifactOperation<'_>) -> Result<Sha256Hasher, UploadError> {
        let length = self
            .payload
            .metadata()
            .map_err(|e| io_error("inspect LFS prefix", e))?
            .len();
        if length < self.checkpoint.offset || length > self.object.size {
            return Err(UploadError::Corrupt);
        }
        self.payload
            .seek(SeekFrom::Start(0))
            .map_err(|e| io_error("rewind LFS prefix", e))?;
        let mut remaining = self.checkpoint.offset;
        let mut hash = Sha256Hasher::new();
        let mut buffer = [0_u8; CHUNK_BYTES];
        while remaining != 0 {
            op.checkpoint()?;
            let count = remaining.min(buffer.len() as u64) as usize;
            self.payload
                .read_exact(&mut buffer[..count])
                .map_err(|e| io_error("verify LFS prefix", e))?;
            DigestHasher::update(&mut hash, &buffer[..count]);
            remaining -= count as u64;
        }
        op.checkpoint()?;
        if DigestHasher::finish(hash.clone()) != self.checkpoint.digest {
            return Err(UploadError::Corrupt);
        }
        Ok(hash)
    }
    fn save_progress(&mut self, offset: u64, hash: &Sha256Hasher) -> Result<(), UploadError> {
        if offset > self.checkpoint.offset && offset < self.object.size {
            self.save(Checkpoint {
                offset,
                digest: DigestHasher::finish(hash.clone()),
                state: State::Active,
            })?;
        }
        Ok(())
    }
    fn save(&mut self, checkpoint: Checkpoint) -> Result<(), UploadError> {
        self.payload
            .sync_all()
            .map_err(|e| io_error("sync LFS upload prefix", e))?;
        atomic_record(
            &self.directory,
            "checkpoint",
            &checkpoint.encode(&self.binding),
        )?;
        self.checkpoint = checkpoint;
        Ok(())
    }
}

fn exists_file(path: &Path) -> Result<bool, UploadError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            checked_file(path, false)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect LFS staging file", error)),
    }
}
fn checked_file(path: &Path, create: bool) -> Result<File, UploadError> {
    if create {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => {
                file.sync_all()
                    .map_err(|e| io_error("sync new LFS staging file", e))?;
                sync(path.parent().ok_or(UploadError::Corrupt)?)?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error("create LFS staging file", error)),
        }
    }
    let before = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            UploadError::NotFound
        } else {
            io_error("inspect LFS staging file", error)
        }
    })?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
    {
        return Err(ArtifactStorageError::UnsafePath.into());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| io_error("open LFS staging file", e))?;
    let after = file
        .metadata()
        .map_err(|e| io_error("inspect opened LFS staging file", e))?;
    if !after.is_file()
        || (after.dev(), after.ino()) != (before.dev(), before.ino())
        || after.nlink() != 1
    {
        return Err(ArtifactStorageError::UnsafePath.into());
    }
    Ok(file)
}
fn lock_file(path: &Path, create: bool) -> Result<File, UploadError> {
    let file = checked_file(path, create)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Err(UploadError::Busy),
        Err(fs::TryLockError::Error(error)) => {
            return Err(io_error("lock LFS upload ownership", error));
        }
    }
    if file
        .metadata()
        .map_err(|e| io_error("inspect LFS lock", e))?
        .len()
        != 0
    {
        return Err(UploadError::Corrupt);
    }
    Ok(file)
}
fn read_fixed<const N: usize>(path: &Path) -> Result<[u8; N], UploadError> {
    let mut file = checked_file(path, false)?;
    if file
        .metadata()
        .map_err(|e| io_error("inspect LFS record", e))?
        .len()
        != N as u64
    {
        return Err(UploadError::Corrupt);
    }
    let mut bytes = [0; N];
    file.read_exact(&mut bytes)
        .map_err(|e| io_error("read LFS record", e))?;
    Ok(bytes)
}
fn atomic_record(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), UploadError> {
    let temporary = directory.join(format!("{name}.next"));
    if exists_file(&temporary)? {
        let maximum = if name == "identity" {
            IDENTITY_BYTES
        } else {
            CHECKPOINT_SIZE
        };
        if checked_file(&temporary, false)?
            .metadata()
            .map_err(|e| io_error("inspect uncommitted LFS record", e))?
            .len()
            > maximum as u64
        {
            return Err(UploadError::Corrupt);
        }
        fs::remove_file(&temporary).map_err(|e| io_error("discard uncommitted LFS record", e))?;
    }
    let mut file = checked_file(&temporary, true)?;
    file.write_all(bytes)
        .map_err(|e| io_error("write LFS checkpoint", e))?;
    file.sync_all()
        .map_err(|e| io_error("sync LFS checkpoint", e))?;
    fs::rename(&temporary, directory.join(name))
        .map_err(|e| io_error("install LFS checkpoint", e))?;
    sync(directory)
}
fn checked_entries(directory: &Path) -> Result<(), UploadError> {
    for (index, entry) in fs::read_dir(directory)
        .map_err(|e| io_error("list LFS session files", e))?
        .enumerate()
    {
        let entry = entry.map_err(|e| io_error("read LFS session entry", e))?;
        if index >= SESSION_FILES.len()
            || !SESSION_FILES.iter().any(|name| entry.file_name() == *name)
        {
            return Err(UploadError::Corrupt);
        }
        let file = checked_file(&entry.path(), false)?;
        let name = entry.file_name();
        let maximum = match name.to_str() {
            Some("lock") => 0,
            Some("identity" | "identity.next") => IDENTITY_BYTES as u64,
            Some("checkpoint" | "checkpoint.next") => CHECKPOINT_SIZE as u64,
            Some("payload") => MAX_OBJECT_BYTES,
            _ => return Err(UploadError::Corrupt),
        };
        if file
            .metadata()
            .map_err(|e| io_error("inspect bounded LFS session file", e))?
            .len()
            > maximum
        {
            return Err(UploadError::Corrupt);
        }
    }
    Ok(())
}
fn remove_completed_session(directory: &Path) -> Result<(), UploadError> {
    private_directory(directory)?;
    checked_entries(directory)?;
    for name in SESSION_FILES {
        let path = directory.join(name);
        if exists_file(&path)? {
            fs::remove_file(&path).map_err(|e| io_error("remove completed LFS staging file", e))?;
        }
    }
    sync(directory)?;
    fs::remove_dir(directory).map_err(|e| io_error("remove completed LFS session", e))?;
    Ok(())
}
fn sync(path: &Path) -> Result<(), UploadError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| io_error("sync LFS upload directory", e))
}
