//! Creation-only proof that an original merge publication preceded dispatch.
//! The fixed frame commits existing event/bundle bytes; it grants no authority.

use fgit_crypto::{DigestHasher, Sha256Hasher, sha256_digest};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAGIC: &[u8; 8] = b"FGWPI001";
const BODY_BYTES: usize = 249;
const FRAME_BYTES: usize = BODY_BYTES + 32;
const MAX_EVENT_BYTES: u64 = 192 * 1024;
// Same ceiling as the native full-bundle reader, checked before allocation.
const MAX_BUNDLE_BYTES: u64 = 128 * 1024 * 1024;
const FILE: &str = "prestart-intent";

/// Typed local custody failure. It never reports a canonical publication outcome.
#[derive(Debug)]
pub enum WatchPrestartRefusal {
    Invalid(&'static str),
    Io(std::io::Error),
    Stopped,
}
impl fmt::Display for WatchPrestartRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(formatter, "prestart custody refused: {detail}"),
            Self::Io(error) => write!(formatter, "prestart custody I/O: {error}"),
            Self::Stopped => formatter.write_str("prestart custody verification stopped"),
        }
    }
}
impl std::error::Error for WatchPrestartRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
fn invalid(detail: &'static str) -> WatchPrestartRefusal {
    WatchPrestartRefusal::Invalid(detail)
}
fn io(error: std::io::Error) -> WatchPrestartRefusal {
    WatchPrestartRefusal::Io(error)
}

/// Opaque commitments supplied by the owning native watcher. The owner must
/// hold its exclusive scope lock, derive paths independently, and separately
/// prove that no dispatch-start fence exists. This frame alone permits no run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchPrestartIntent {
    pub scope: [u8; 32],
    pub event: [u8; 32],
    pub merge_config: [u8; 32],
    pub execution_config: [u8; 32],
    pub event_sha256: [u8; 32],
    pub bundle_sha256: [u8; 32],
    pub bundle_len: u64,
    pub landing: Option<([u8; 32], u64)>,
}

impl WatchPrestartIntent {
    /// Last preparation write: every committed artifact must already exist.
    /// A partial frame is retained and never promoted to a valid intent.
    pub fn create(
        directory: &Path,
        intent: &Self,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WatchPrestartRefusal> {
        checkpoint(live)?;
        let original = private_directory(directory)?;
        intent.validate()?;
        intent.verify_artifacts(directory, live)?;
        same_directory(directory, &original)?;
        checkpoint(live)?;
        write_new(&directory.join(FILE), &intent.encode())
            .and_then(|()| File::open(directory)?.sync_all())
            .map_err(io)?;
        // Once the write starts its sync completes even if cancellation arrives.
        same_directory(directory, &original)
    }

    /// Missing means legacy or incomplete preparation, never permission to run.
    /// All other malformed, foreign, oversized or partial records refuse.
    pub fn read(
        directory: &Path,
        scope: &[u8; 32],
        event: &[u8; 32],
        merge_config: &[u8; 32],
        live: &dyn Fn() -> bool,
    ) -> Result<Option<Self>, WatchPrestartRefusal> {
        checkpoint(live)?;
        let original = private_directory(directory)?;
        let path = directory.join(FILE);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(error)),
            Ok(_) => {}
        }
        let bytes = read_frame(&path)?;
        checkpoint(live)?;
        same_directory(directory, &original)?;
        let intent = Self::decode(&bytes)?;
        if intent.scope != *scope || intent.event != *event || intent.merge_config != *merge_config
        {
            return Err(invalid(
                "prestart intent belongs to another watch or merge configuration",
            ));
        }
        Ok(Some(intent))
    }

    /// Verify retained bytes with bounded streaming reads, without allocating a
    /// second candidate/landing bundle during reporter or startup inspection.
    pub fn verify_artifacts(
        &self,
        directory: &Path,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WatchPrestartRefusal> {
        self.validate()?;
        checkpoint(live)?;
        let original = private_directory(directory)?;
        read_verified(
            &directory.join("event.json"),
            None,
            MAX_EVENT_BYTES,
            self.event_sha256,
            false,
            live,
        )?;
        read_verified(
            &directory.join("candidate.bundle"),
            Some(self.bundle_len),
            MAX_BUNDLE_BYTES,
            self.bundle_sha256,
            false,
            live,
        )?;
        if let Some((digest, length)) = self.landing {
            read_verified(
                &directory.join("landing.bundle"),
                Some(length),
                MAX_BUNDLE_BYTES,
                digest,
                false,
                live,
            )?;
        }
        checkpoint(live)?;
        same_directory(directory, &original)
    }

    /// Load only the original bounded candidate, rechecking its commitment and
    /// file identity on the same descriptor from which admission receives bytes.
    pub fn load_bundle(
        &self,
        directory: &Path,
        live: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, WatchPrestartRefusal> {
        self.validate()?;
        let original = private_directory(directory)?;
        let bytes = read_verified(
            &directory.join("candidate.bundle"),
            Some(self.bundle_len),
            MAX_BUNDLE_BYTES,
            self.bundle_sha256,
            true,
            live,
        )?;
        same_directory(directory, &original)?;
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), WatchPrestartRefusal> {
        if self.bundle_len == 0
            || self.bundle_len > MAX_BUNDLE_BYTES
            || self
                .landing
                .is_some_and(|(_, n)| n == 0 || n > MAX_BUNDLE_BYTES)
        {
            return Err(invalid(
                "prestart candidate exceeds the retained bundle envelope",
            ));
        }
        Ok(())
    }

    fn encode(&self) -> [u8; FRAME_BYTES] {
        let mut bytes = [0; FRAME_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        for (index, digest) in [
            &self.scope,
            &self.event,
            &self.merge_config,
            &self.execution_config,
            &self.event_sha256,
            &self.bundle_sha256,
        ]
        .into_iter()
        .enumerate()
        {
            let start = 8 + index * 32;
            bytes[start..start + 32].copy_from_slice(digest);
        }
        bytes[200..208].copy_from_slice(&self.bundle_len.to_be_bytes());
        if let Some((digest, length)) = self.landing {
            bytes[208] = 1;
            bytes[209..241].copy_from_slice(&digest);
            bytes[241..249].copy_from_slice(&length.to_be_bytes());
        }
        let digest = sha256_digest(&bytes[..BODY_BYTES]);
        bytes[BODY_BYTES..].copy_from_slice(&digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, WatchPrestartRefusal> {
        if bytes.len() != FRAME_BYTES
            || &bytes[..8] != MAGIC
            || sha256_digest(&bytes[..BODY_BYTES]) != bytes[BODY_BYTES..]
        {
            return Err(invalid("invalid prestart intent frame or checksum"));
        }
        let digest = |start: usize| -> [u8; 32] {
            // Frame length is checked before these fixed offsets are used.
            bytes[start..start + 32]
                .try_into()
                .expect("fixed digest width")
        };
        let number = |start: usize| -> u64 {
            u64::from_be_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .expect("fixed number width"),
            )
        };
        let landing = match bytes[208] {
            0 if bytes[209..249].iter().all(|byte| *byte == 0) => None,
            1 => Some((digest(209), number(241))),
            _ => return Err(invalid("noncanonical prestart landing commitment")),
        };
        let intent = Self {
            scope: digest(8),
            event: digest(40),
            merge_config: digest(72),
            execution_config: digest(104),
            event_sha256: digest(136),
            bundle_sha256: digest(168),
            bundle_len: number(200),
            landing,
        };
        intent.validate()?;
        Ok(intent)
    }
}

fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), WatchPrestartRefusal> {
    if live() {
        Ok(())
    } else {
        Err(WatchPrestartRefusal::Stopped)
    }
}

fn private_directory(path: &Path) -> Result<Metadata, WatchPrestartRefusal> {
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(invalid(
            "prestart custody requires a nonsymlink 0700 directory",
        ));
    }
    Ok(metadata)
}

fn same_directory(path: &Path, original: &Metadata) -> Result<(), WatchPrestartRefusal> {
    let current = private_directory(path)?;
    if current.dev() != original.dev() || current.ino() != original.ino() {
        return Err(invalid("prestart custody directory changed"));
    }
    Ok(())
}

fn private_file(metadata: &Metadata, expected: Option<u64>, maximum: u64) -> bool {
    metadata.is_file()
        && metadata.mode() & 0o777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() <= maximum
        && expected.is_none_or(|length| metadata.len() == length)
}

fn same_file(original: &Metadata, current: &Metadata) -> bool {
    private_file(current, Some(original.len()), original.len())
        && (
            original.dev(),
            original.ino(),
            original.mtime(),
            original.mtime_nsec(),
            original.ctime(),
            original.ctime_nsec(),
        ) == (
            current.dev(),
            current.ino(),
            current.mtime(),
            current.mtime_nsec(),
            current.ctime(),
            current.ctime_nsec(),
        )
}

fn read_verified(
    path: &Path,
    expected_length: Option<u64>,
    maximum: u64,
    expected_digest: [u8; 32],
    retain: bool,
    live: &dyn Fn() -> bool,
) -> Result<Vec<u8>, WatchPrestartRefusal> {
    checkpoint(live)?;
    let original = fs::symlink_metadata(path).map_err(io)?;
    if !private_file(&original, expected_length, maximum) {
        return Err(invalid("invalid bounded private prestart artifact"));
    }
    let mut file = File::open(path).map_err(io)?;
    if !same_file(&original, &file.metadata().map_err(io)?) {
        return Err(invalid("prestart artifact changed during open"));
    }
    let mut bytes = Vec::new();
    if retain {
        let length = usize::try_from(original.len())
            .map_err(|_| invalid("prestart bundle length cannot be represented"))?;
        bytes
            .try_reserve_exact(length)
            .map_err(|_| invalid("prestart bundle allocation refused"))?;
    }
    let mut hash = Sha256Hasher::new();
    let mut remaining = original.len();
    let mut chunk = [0; 16 * 1024];
    while remaining != 0 {
        checkpoint(live)?;
        let wanted = remaining.min(chunk.len() as u64) as usize;
        let count = file.read(&mut chunk[..wanted]).map_err(io)?;
        if count == 0 {
            return Err(invalid("prestart artifact truncated during read"));
        }
        hash.update(&chunk[..count]);
        if retain {
            bytes.extend_from_slice(&chunk[..count]);
        }
        remaining -= count as u64;
    }
    checkpoint(live)?;
    if file.read(&mut chunk[..1]).map_err(io)? != 0
        || hash.finish() != expected_digest
        || !same_file(&original, &file.metadata().map_err(io)?)
        || !same_file(&original, &fs::symlink_metadata(path).map_err(io)?)
    {
        return Err(invalid(
            "prestart artifact differs from its original commitment",
        ));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn read_frame(path: &Path) -> Result<[u8; FRAME_BYTES], WatchPrestartRefusal> {
    let original = fs::symlink_metadata(path).map_err(io)?;
    if !private_file(&original, Some(FRAME_BYTES as u64), FRAME_BYTES as u64) {
        return Err(invalid("invalid private prestart intent frame"));
    }
    let mut file = File::open(path).map_err(io)?;
    if !same_file(&original, &file.metadata().map_err(io)?) {
        return Err(invalid("prestart intent changed during open"));
    }
    let mut bytes = [0; FRAME_BYTES];
    file.read_exact(&mut bytes).map_err(io)?;
    if file.read(&mut [0; 1]).map_err(io)? != 0
        || !same_file(&original, &file.metadata().map_err(io)?)
        || !same_file(&original, &fs::symlink_metadata(path).map_err(io)?)
    {
        return Err(invalid("prestart intent changed during read"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
