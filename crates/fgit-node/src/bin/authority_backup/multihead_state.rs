//! Local custody of an all-heads restore, never canonical authority.
//! The immutable binding permits a retry; only whole-image verification proves
//! what was imported. No mutable progress file decides that verification ran.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fgit_authority::StoreInstanceId;
use super::super::super::{parent, publish_new, regular, require_absent, sync_directory};

const INTENT: &str = ".authority-restore-intent";
const LOCK: &str = ".restore-lock";
const QUARANTINE: &str = ".authority-restore-quarantine";
const DATABASE: &str = "authority.fsqlite";
const WAL: &str = "authority.fsqlite-wal";
const JOURNAL: &str = "authority.fsqlite-journal";
const SHM: &str = "authority.fsqlite-shm";
const MAGIC: &[u8; 8] = b"FGARM002";

/// One OS lock is retained until verification, close and cleanup finish. This
/// excludes cooperating restorers, not node services or hostile same-UID code.
#[derive(Debug)]
pub(super) struct Custody {
    root: PathBuf,
    _lock: File,
}
impl Custody {
    pub(super) fn acquire(root: &Path, pin: [u8; 32], instance: StoreInstanceId,
        resume: bool,
    ) -> Result<Self, String> {
        if !resume {
            create_private(root)?;
        } else if !exists(root, true)? {
            return Err("resume requires an existing all-heads restore directory".into());
        }
        let lock_path = root.join(LOCK);
        if resume && !exists(&lock_path, false)? {
            return Err("all-heads resume refused: missing original restore lock".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if !resume { options.create_new(true); }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&lock_path).map_err(|e| format!("restore lock open failed: {e}"))?;
        lock.try_lock().map_err(|e| format!("restore already running or lock unavailable: {e}"))?;
        let custody = Self { root: root.to_path_buf(), _lock: lock };
        let binding = binding(pin, instance);
        let marker = root.join(INTENT);
        if resume {
            // Bound and compare the exact format after acquiring custody. A
            // source-archive intent or a legacy directory is never adopted.
            if !exists(&marker, false)? {
                return Err("all-heads resume refused: missing original intent (legacy directories cannot resume)".into());
            }
            let mut bytes = Vec::new();
            File::open(&marker).map_err(|e| e.to_string())?.take(49)
                .read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            if bytes.as_slice() != binding.as_slice() {
                return Err("all-heads resume intent disagrees with format, checksum or destination instance".into());
            }
        } else {
            // Quarantine predates the durable intent. Thus an intent with
            // neither quarantine nor public database is damage, not permission
            // to recreate a previously published/later advanced store.
            create_private(&root.join(QUARANTINE))?;
            sync_directory(&root.join(QUARANTINE)).map_err(|e| e.to_string())?;
            custody._lock.sync_all().map_err(|e| e.to_string())?;
            // Whole-file, same-directory, no-replace publication: a torn marker
            // can never authorize an import. A pre-marker crash is not adopted.
            publish_new(&marker, &binding)?;
            sync_directory(parent(root)).map_err(|e| e.to_string())?;
        }
        Ok(custody)
    }

    pub(super) fn published(&self) -> Result<bool, String> {
        exists(&self.root.join(DATABASE), false)
    }

    /// Recover only fixed paths. Move a prepared WAL back before any engine
    /// opens its database; never guess between two versions of the same path.
    pub(super) fn quarantine(&self) -> Result<PathBuf, String> {
        require_absent(&self.root.join(DATABASE))?;
        require_absent(&self.root.join(JOURNAL))?;
        require_absent(&self.root.join(SHM))?;
        let quarantine = self.root.join(QUARANTINE);
        let present = exists(&quarantine, true)?;
        let public_wal = exists(&self.root.join(WAL), false)?;
        let private_wal = exists(&quarantine.join(WAL), false)?;
        let database = exists(&quarantine.join(DATABASE), false)?;
        exists(&quarantine.join(JOURNAL), false)?;
        exists(&quarantine.join(SHM), false)?;
        if public_wal && private_wal {
            return Err("conflicting restore WAL locations; no paths changed".into());
        }
        if (public_wal || private_wal) && (!present || !database) {
            return Err("restore WAL lacks its quarantined database; no paths changed".into());
        }
        if !database && (exists(&quarantine.join(JOURNAL), false)?
            || exists(&quarantine.join(SHM), false)?)
        {
            return Err("restore sidecar lacks its database; no paths changed".into());
        }
        if !present {
            return Err("restore intent has neither a public database nor its original quarantine; refusing to recreate lost authority".into());
        }
        if public_wal {
            fs::rename(self.root.join(WAL), quarantine.join(WAL)).map_err(|e| e.to_string())?;
        }
        sync_directory(&quarantine).map_err(|e| e.to_string())?;
        sync_directory(&self.root).map_err(|e| e.to_string())?;
        Ok(quarantine)
    }

    /// Only a closed, completely verified image reaches this boundary. WAL
    /// moves first; the database's no-replace link is the visibility boundary.
    pub(super) fn publish(&self, mut after_wal: impl FnMut() -> Result<(), String>)
        -> Result<(), String>
    {
        let quarantine = self.root.join(QUARANTINE);
        if !exists(&quarantine, true)? { return Err("missing verified quarantine".into()); }
        let database = quarantine.join(DATABASE);
        regular(&database)?;
        require_absent(&self.root.join(DATABASE))?;
        require_absent(&self.root.join(WAL))?;
        require_absent(&self.root.join(JOURNAL))?;
        require_absent(&self.root.join(SHM))?;
        let journal = quarantine.join(JOURNAL);
        if exists(&journal, false)? && fs::metadata(&journal).map_err(|e| e.to_string())?.len() != 0 {
            return Err("closed restore retains a rollback journal; publication refused".into());
        }
        exists(&quarantine.join(SHM), false)?;
        let wal = quarantine.join(WAL);
        let has_wal = exists(&wal, false)?;
        File::open(&database).and_then(|file| file.sync_all()).map_err(|e| e.to_string())?;
        if has_wal {
            File::open(&wal).and_then(|file| file.sync_all()).map_err(|e| e.to_string())?;
            fs::rename(&wal, self.root.join(WAL)).map_err(|e| e.to_string())?;
        }
        sync_directory(&quarantine).map_err(|e| e.to_string())?;
        sync_directory(&self.root).map_err(|e| e.to_string())?;
        after_wal()?;
        fs::hard_link(&database, self.root.join(DATABASE))
            .map_err(|e| format!("final authority link did not complete: {e}"))?;
        sync_directory(&self.root)
            .map_err(|e| format!("final authority is visible; directory sync failed: {e}"))?;
        sync_directory(parent(&self.root))
            .map_err(|e| format!("final authority is visible; parent sync failed: {e}"))
    }

    /// Remove only owned, fixed staging names after final-location verification
    /// and shutdown. Unknown files prevent directory removal, never get erased.
    /// The intent and lock remain for resolving a lost success response.
    pub(super) fn cleanup(&self) -> Result<(), String> {
        if !self.published()? { return Err("cannot clean an unpublished all-heads restore".into()); }
        let quarantine = self.root.join(QUARANTINE);
        if exists(&quarantine, true)? {
            for name in [DATABASE, WAL, JOURNAL, SHM] {
                exists(&quarantine.join(name), false)?;
            }
            for name in [DATABASE, WAL, JOURNAL, SHM] {
                let path = quarantine.join(name);
                if exists(&path, false)? { fs::remove_file(path).map_err(|e| e.to_string())?; }
            }
            fs::remove_dir(&quarantine).map_err(|e| format!("owned quarantine cleanup refused: {e}"))?;
        }
        sync_directory(&self.root).map_err(|e| e.to_string())
    }
}
fn create_private(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
    builder.create(path).map_err(|e| format!("cannot reserve restore directory: {e}"))
}
fn binding(pin: [u8; 32], instance: StoreInstanceId) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&pin);
    bytes[40..].copy_from_slice(&instance.raw().to_be_bytes());
    bytes
}
fn exists(path: &Path, directory: bool) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if (directory && meta.is_dir()) || (!directory && meta.is_file()) => Ok(true),
        Ok(_) => Err(format!("unexpected restore path kind: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
#[path = "multihead_state_tests.rs"]
mod tests;
