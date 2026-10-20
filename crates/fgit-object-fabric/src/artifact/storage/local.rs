//! Root-last immutable containers. Never use directory listings as artifact truth.
use super::*;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);

/// Local payload lane in the object fabric, deliberately separate from Git OIDs.
/// Neither a payload's existence nor its provenance fields authorize a check.
#[derive(Clone, Debug)]
pub struct LocalArtifactStore {
    root: PathBuf,
    scope: ArtifactScope,
}
impl LocalArtifactStore {
    /// Select an existing private root; this read does not create any namespace.
    pub fn open(root: &Path, scope: ArtifactScope) -> Result<Self, ArtifactStorageError> {
        private_directory(root)?;
        Ok(Self {
            root: root.to_owned(),
            scope,
        })
    }
    /// Return a complete verified payload in memory. No partial bytes escape on
    /// failure. This grants custody only, not permission to execute or reuse.
    pub fn read_payload(
        &self,
        id: &Digest,
        op: &ArtifactOperation<'_>,
    ) -> Result<(ArtifactIdentity, Vec<u8>), ArtifactStorageError> {
        if op.maximum_bytes > 64 * 1024 * 1024 {
            return Err(ArtifactStorageError::PayloadLimit);
        }
        struct Buffer {
            bytes: Vec<u8>,
            maximum: usize,
        }
        impl Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
                    return Err(std::io::ErrorKind::OutOfMemory.into());
                }
                self.bytes
                    .try_reserve(bytes.len())
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        op.checkpoint()?;
        let mut file = self.source(id)?;
        let mut buffer = Buffer {
            bytes: Vec::new(),
            maximum: op.maximum_bytes as usize,
        };
        let identity = verify(&mut file, &self.scope, id, &mut buffer, op)?;
        op.checkpoint()?;
        Ok((identity, buffer.bytes))
    }
    pub fn scope(&self) -> &ArtifactScope {
        &self.scope
    }
    fn directory(&self) -> PathBuf {
        self.root
            .join(format!("scope-{}", hex(&self.scope.commitment())))
    }
    fn source(&self, id: &Digest) -> Result<File, ArtifactStorageError> {
        valid_digest(id)?;
        private_directory(&self.root).map_err(|error| match error {
            ArtifactStorageError::NotFound => ArtifactStorageError::Io {
                operation: "selected artifact root unavailable",
                kind: std::io::ErrorKind::NotFound,
            },
            other => other,
        })?;
        let directory = self.directory();
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ArtifactStorageError::NotFound);
            }
            Err(error) => return Err(io("inspect artifact namespace", error)),
            Ok(_) => {}
        }
        private_directory(&directory)?;
        regular(&directory.join(hex(id)))
    }
    pub(super) fn put_inner(
        &self,
        identity: &ArtifactIdentity,
        source: &mut File,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactPut, ArtifactStorageError> {
        op.admit(identity.payload_len())?;
        let metadata = source
            .metadata()
            .map_err(|e| io("inspect upload source", e))?;
        if !metadata.is_file() {
            return Err(ArtifactStorageError::UnsafePath);
        }
        if metadata.len() != identity.payload_len() {
            return Err(ArtifactStorageError::PayloadMismatch);
        }
        source
            .seek(SeekFrom::Start(0))
            .map_err(|e| io("rewind source", e))?;
        self.put_reader_inner(identity, source, op)
    }

    pub(super) fn put_reader_inner(
        &self,
        identity: &ArtifactIdentity,
        source: &mut impl Read,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactPut, ArtifactStorageError> {
        op.admit(identity.payload_len())?;
        let header = codec::encode(&self.scope, identity)?;
        private_directory(&self.root)?;
        let directory = self.directory();
        op.checkpoint()?;
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => sync(&self.root).map_err(|e| io("sync scope directory", e))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io("create scope directory", e)),
        }
        private_directory(&directory)?;
        sync(&self.root).map_err(|e| io("sync selected scope", e))?;
        let mut stage = Stage::new(&directory)?;
        stage
            .file
            .write_all(MAGIC)
            .and_then(|()| stage.file.write_all(&(header.len() as u32).to_be_bytes()))
            .and_then(|()| stage.file.write_all(&header))
            .map_err(|e| io("write artifact header", e))?;
        transfer(source, &mut stage.file, identity, op)?;
        stage
            .file
            .sync_all()
            .map_err(|e| io("sync artifact stage", e))?;
        // Verify actual retained bytes before making their immutable name visible.
        stage
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|e| io("rewind artifact stage", e))?;
        verify(
            &mut stage.file,
            &self.scope,
            identity.artifact_id(),
            &mut std::io::sink(),
            op,
        )?;
        op.checkpoint()?;
        let target = directory.join(hex(identity.artifact_id()));
        let result = match fs::hard_link(&stage.path, &target) {
            Ok(()) => ArtifactPut::Created,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing = regular(&target)?;
                let observed = verify(
                    &mut existing,
                    &self.scope,
                    identity.artifact_id(),
                    &mut std::io::sink(),
                    op,
                )?;
                if &observed != identity {
                    return Err(ArtifactStorageError::IdentityMismatch);
                }
                ArtifactPut::AlreadyPresent
            }
            Err(e) => return Err(io("install artifact", e)),
        };
        // From the final link onwards do not reinterpret cancellation as absence.
        sync(&directory).map_err(|_| ArtifactStorageError::PublicationUncertain {
            operation: "sync artifact namespace",
        })?;
        stage
            .remove()
            .map_err(|_| ArtifactStorageError::PublicationUncertain {
                operation: "remove artifact staging name",
            })?;
        sync(&directory).map_err(|_| ArtifactStorageError::PublicationUncertain {
            operation: "sync artifact staging removal",
        })?;
        Ok(result)
    }
    pub(super) fn inspect_inner(
        &self,
        id: &Digest,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactIdentity, ArtifactStorageError> {
        op.checkpoint()?;
        let mut file = self.source(id)?;
        verify(&mut file, &self.scope, id, &mut std::io::sink(), op)
    }
    pub(super) fn export_inner(
        &self,
        id: &Digest,
        destination: &Path,
        op: &ArtifactOperation<'_>,
    ) -> Result<ArtifactIdentity, ArtifactStorageError> {
        op.checkpoint()?;
        valid_digest(id)?;
        if destination.file_name().is_none() {
            return Err(ArtifactStorageError::UnsafePath);
        }
        let parent = destination
            .parent()
            .ok_or(ArtifactStorageError::UnsafePath)?;
        private_directory(parent)?;
        match fs::symlink_metadata(destination) {
            Ok(_) => return Err(ArtifactStorageError::DestinationExists),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io("inspect export destination", e)),
        }
        let mut source = self.source(id)?;
        let mut stage = Stage::new(parent)?;
        let identity = verify(&mut source, &self.scope, id, &mut stage.file, op)?;
        stage
            .file
            .sync_all()
            .map_err(|e| io("sync artifact export", e))?;
        stage
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|e| io("rewind artifact export", e))?;
        transfer(&mut stage.file, &mut std::io::sink(), &identity, op)?;
        op.checkpoint()?;
        match fs::hard_link(&stage.path, destination) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ArtifactStorageError::DestinationExists);
            }
            Err(e) => return Err(io("install artifact export", e)),
        }
        sync(parent).map_err(|_| ArtifactStorageError::PublicationUncertain {
            operation: "sync export namespace",
        })?;
        stage
            .remove()
            .map_err(|_| ArtifactStorageError::PublicationUncertain {
                operation: "remove export staging name",
            })?;
        sync(parent).map_err(|_| ArtifactStorageError::PublicationUncertain {
            operation: "sync export staging removal",
        })?;
        Ok(identity)
    }
}
fn sync(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}
fn private_directory(path: &Path) -> Result<(), ArtifactStorageError> {
    if !path.is_absolute() {
        return Err(ArtifactStorageError::UnsafePath);
    }
    let mut prefix = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => prefix.push(component),
            _ => return Err(ArtifactStorageError::UnsafePath),
        }
        let meta = fs::symlink_metadata(&prefix).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ArtifactStorageError::NotFound
            } else {
                io("inspect artifact directory", e)
            }
        })?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(ArtifactStorageError::UnsafePath);
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|e| io("inspect private directory", e))?;
    if meta.mode() & 0o777 != 0o700 {
        return Err(ArtifactStorageError::UnsafePath);
    }
    Ok(())
}
fn regular(path: &Path) -> Result<File, ArtifactStorageError> {
    let before = fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ArtifactStorageError::NotFound
        } else {
            io("inspect artifact file", e)
        }
    })?;
    if !before.is_file() || before.file_type().is_symlink() || before.mode() & 0o777 != 0o600 {
        return Err(ArtifactStorageError::UnsafePath);
    }
    let file = File::open(path).map_err(|e| io("open artifact file", e))?;
    let after = file
        .metadata()
        .map_err(|e| io("inspect opened artifact", e))?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) || !after.is_file() {
        return Err(ArtifactStorageError::UnsafePath);
    }
    Ok(file)
}
struct Stage {
    path: PathBuf,
    file: File,
    removed: bool,
}
impl Stage {
    fn new(parent: &Path) -> Result<Self, ArtifactStorageError> {
        for _ in 0..1024 {
            let path = parent.join(format!(
                ".fg-artifact-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file,
                        removed: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(io("create artifact stage", e)),
            }
        }
        Err(ArtifactStorageError::InvalidInput(
            "artifact staging slots exhausted",
        ))
    }
    fn remove(&mut self) -> std::io::Result<()> {
        fs::remove_file(&self.path)?;
        self.removed = true;
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        if !self.removed {
            let _cleanup = fs::remove_file(&self.path);
        }
    }
}
fn verify(
    file: &mut File,
    scope: &ArtifactScope,
    id: &Digest,
    sink: &mut impl Write,
    op: &ArtifactOperation<'_>,
) -> Result<ArtifactIdentity, ArtifactStorageError> {
    op.checkpoint()?;
    let mut magic = [0u8; 8];
    let mut length = [0u8; 4];
    file.read_exact(&mut magic)
        .and_then(|()| file.read_exact(&mut length))
        .map_err(|e| io("read artifact framing", e))?;
    if &magic != MAGIC {
        return Err(ArtifactStorageError::InvalidEncoding);
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > HEADER_BYTES {
        return Err(ArtifactStorageError::InvalidEncoding);
    }
    let mut header = vec![0u8; length];
    file.read_exact(&mut header)
        .map_err(|e| io("read artifact metadata", e))?;
    let identity = codec::decode(&header, scope, id)?;
    op.admit(identity.payload_len())?;
    let expected = 12u64
        .checked_add(length as u64)
        .and_then(|n| n.checked_add(identity.payload_len()))
        .ok_or(ArtifactStorageError::PayloadLimit)?;
    if file
        .metadata()
        .map_err(|e| io("inspect artifact length", e))?
        .len()
        != expected
    {
        return Err(ArtifactStorageError::PayloadMismatch);
    }
    transfer(file, sink, &identity, op)?;
    Ok(identity)
}
fn transfer(
    source: &mut impl Read,
    sink: &mut impl Write,
    identity: &ArtifactIdentity,
    op: &ArtifactOperation<'_>,
) -> Result<(), ArtifactStorageError> {
    op.admit(identity.payload_len())?;
    let mut remaining = identity.payload_len();
    let mut chunk = [0u8; CHUNK_BYTES];
    let mut hash = Sha256Hasher::new();
    while remaining > 0 {
        op.checkpoint()?;
        let length = remaining.min(CHUNK_BYTES as u64) as usize;
        source
            .read_exact(&mut chunk[..length])
            .map_err(|e| io("read artifact payload", e))?;
        DigestHasher::update(&mut hash, &chunk[..length]);
        op.checkpoint()?;
        sink.write_all(&chunk[..length])
            .map_err(|e| io("write artifact payload", e))?;
        remaining -= length as u64;
    }
    op.checkpoint()?;
    let mut extra = [0u8; 1];
    if source
        .read(&mut extra)
        .map_err(|e| io("check artifact end", e))?
        != 0
        || &finish(hash) != identity.payload_digest()
    {
        return Err(ArtifactStorageError::PayloadMismatch);
    }
    op.checkpoint()?;
    Ok(())
}
