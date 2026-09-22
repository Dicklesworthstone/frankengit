//! Local restore ownership, not canonical authority or a proof of completion.
//! The immutable intent binds the exact archive pin and destination instance.
//! Progress is re-derived from authenticated data, never trusted from a counter.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fgit_authority::StoreInstanceId;
use super::{create_private, parent, require_absent, sync_directory};

const INTENT: &str = ".restore-intent";
const LOCK: &str = ".restore-lock";
const MAGIC: &[u8; 8] = b"FGRES001";
const INTENT_BYTES: usize = 48;

/// Retain the OS lock through restore execution. It is advisory: repository
/// serving and hostile same-UID filesystem mutation remain outside this profile.
/// A dead process leaves a lock file, not a stale lock that needs to be broken.
#[derive(Debug)]
pub(super) struct Intent {
    root: PathBuf,
    _lock: File,
}
impl Intent {
    pub(super) fn reserve(root: &Path, pin: [u8; 32], instance: StoreInstanceId) -> Result<Self, String> {
        create_private(root)?;
        let lock = private_options().create_new(true).open(root.join(LOCK)).map_err(|e| e.to_string())?;
        lock.try_lock().map_err(|e| format!("restore lock unavailable: {e}"))?;
        lock.sync_all().map_err(|e| e.to_string())?;
        let mut marker = private_options().create_new(true).open(root.join(INTENT)).map_err(|e| e.to_string())?;
        marker.write_all(&binding(pin, instance)).and_then(|()| marker.sync_all()).map_err(|e| e.to_string())?;
        drop(marker);
        sync_directory(root).map_err(|e| e.to_string())?;
        sync_directory(parent(root)).map_err(|e| e.to_string())?;
        Ok(Self { root: root.to_path_buf(), _lock: lock })
    }

    pub(super) fn open(root: &Path, pin: [u8; 32], instance: StoreInstanceId) -> Result<Self, String> {
        if !has_kind(root, true)? { return Err("resume requires an existing restore root".into()); }
        let marker = root.join(INTENT);
        if !has_kind(&marker, false)? { return Err("resume refused: missing restore intent (legacy roots cannot be resumed)".into()); }
        let mut bytes = Vec::new();
        File::open(&marker).map_err(|e| e.to_string())?.take((INTENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if bytes.as_slice() != binding(pin, instance).as_slice() {
            return Err("resume intent does not match archive checksum and destination instance".into());
        }
        let lock_path = root.join(LOCK);
        if !has_kind(&lock_path, false)? { return Err("resume refused: missing restore lock file".into()); }
        let lock = OpenOptions::new().read(true).write(true).open(lock_path).map_err(|e| e.to_string())?;
        lock.try_lock().map_err(|e| format!("restore already running or lock unavailable: {e}"))?;
        Ok(Self { root: root.to_path_buf(), _lock: lock })
    }

    pub(super) fn published(&self) -> Result<bool, String> {
        has_kind(&self.root.join("authority.fsqlite"), false)
    }

    /// Return a partially moved, still-unpublished image to quarantine before
    /// ANY database reopen. In particular, never open a database without its
    /// moved WAL. All path/type/collision checks precede the first rename.
    /// Only two fixed data paths may move; no archive-controlled path is used.
    pub(super) fn quarantine(&self) -> Result<PathBuf, String> {
        require_absent(&self.root.join("authority.fsqlite"))?;
        let quarantine = self.root.join(".restore-quarantine");
        let exists = has_kind(&quarantine, true)?;
        let objects_at_root = has_kind(&self.root.join("objects"), true)?;
        let wal_at_root = has_kind(&self.root.join("authority.fsqlite-wal"), false)?;
        require_absent(&self.root.join("authority.fsqlite-journal"))?;
        require_absent(&self.root.join("authority.fsqlite-shm"))?;
        if !exists && (objects_at_root || wal_at_root) {
            return Err("resume found moved data without its quarantine; no paths changed".into());
        }
        let objects_in_quarantine = has_kind(&quarantine.join("objects"), true)?;
        let wal_in_quarantine = has_kind(&quarantine.join("authority.fsqlite-wal"), false)?;
        let database = has_kind(&quarantine.join("authority.fsqlite"), false)?;
        has_kind(&quarantine.join("authority.fsqlite-journal"), false)?;
        has_kind(&quarantine.join("authority.fsqlite-shm"), false)?;
        if (objects_at_root && objects_in_quarantine) || (wal_at_root && wal_in_quarantine) {
            return Err("resume found conflicting data locations; no paths changed".into());
        }
        if (wal_at_root || wal_in_quarantine) && !database {
            return Err("resume found a WAL without its database; no paths changed".into());
        }
        if !exists { create_private(&quarantine)?; }
        // A new preparation moves rather than hard-links the WAL. Thus a crash
        // has exactly one location per path, and normalization is repeatable.
        for (name, moved) in [("objects", objects_at_root), ("authority.fsqlite-wal", wal_at_root)] {
            if moved {
                fs::rename(self.root.join(name), quarantine.join(name)).map_err(|e| e.to_string())?;
            }
        }
        sync_directory(&quarantine).map_err(|e| e.to_string())?;
        sync_directory(&self.root).map_err(|e| e.to_string())?;
        Ok(quarantine)
    }

    /// Called only after the final authority image AND all source objects have
    /// reverified and the node closed. The intent and lock files stay for a
    /// lost-response retry; they never claim that validation has completed.
    pub(super) fn cleanup(&self) -> Result<(), String> {
        if !self.published()? { return Err("cannot clean unpublished restore quarantine".into()); }
        let quarantine = self.root.join(".restore-quarantine");
        if has_kind(&quarantine, true)? {
            fs::remove_dir_all(&quarantine).map_err(|e| format!("restore is published; quarantine cleanup failed: {e}"))?;
        }
        sync_directory(&self.root).map_err(|e| format!("restore is published; cleanup sync failed: {e}"))
    }
}
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new(); options.read(true).write(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    options
}
fn binding(pin: [u8; 32], instance: StoreInstanceId) -> [u8; INTENT_BYTES] {
    let mut bytes = [0; INTENT_BYTES]; bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&pin); bytes[40..].copy_from_slice(&instance.raw().to_be_bytes()); bytes
}
/// Existing symlinks/devices and unexpected path kinds are never treated as
/// absence. Caller owns stable parent paths; this is not a hostile-host adapter.
fn has_kind(path: &Path, directory: bool) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if (directory && metadata.is_dir()) || (!directory && metadata.is_file()) => Ok(true),
        Ok(_) => Err(format!("unexpected restore path kind: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
#[path = "resume_tests.rs"]
mod tests;
