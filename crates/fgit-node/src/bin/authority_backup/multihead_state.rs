//! Local custody of an all-heads restore, never canonical authority.
//! The immutable binding permits a retry; only whole-image verification proves
//! what was imported. No mutable progress file decides that verification ran.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::super::super::{parent, publish_new, regular, require_absent, sync_directory};
use fgit_authority::StoreInstanceId;

const INTENT: &str = ".authority-restore-intent";
const LOCK: &str = ".restore-lock";
const QUARANTINE: &str = ".authority-restore-quarantine";
const DATABASE: &str = "authority.fsqlite";
const WAL: &str = "authority.fsqlite-wal";
const JOURNAL: &str = "authority.fsqlite-journal";
const SHM: &str = "authority.fsqlite-shm";
/// The WAL and its RaptorQ repair sidecar (fsqlite >= 0.4), which also
/// persists the repair-symbol pragma. They move as one unit under the WAL's
/// crash rules and are never discarded like `-shm`.
const WAL_SET: [&str; 2] = [WAL, "authority.fsqlite-wal-fec"];
/// Engine records bound to the quarantine path and its WAL generation
/// (fsqlite >= 0.4): namespace gate/use records, the migration marker, lock
/// files and parallel-WAL commit certificates. The final location opens with
/// its own. Moving the certificates made the final open fail permanently on
/// resume, so they stay behind and are removed only by `cleanup`, which runs
/// after the final location's whole-image verification has passed.
const LOCAL_STATE: [&str; 8] = [
    "authority.fsqlite-fsqlite-ns-gate",
    "authority.fsqlite-fsqlite-ns-use",
    "authority.fsqlite.fsqlite-migration-state",
    "authority.fsqlite-lock-shared",
    "authority.fsqlite-lock-reserved",
    "authority.fsqlite-lock-pending",
    "authority.fsqlite-wal-cert",
    "authority.fsqlite-wal-cert-head",
];
const MAGIC: &[u8; 8] = b"FGARM002";

/// One OS lock is retained until verification, close and cleanup finish. This
/// excludes cooperating restorers, not node services or hostile same-UID code.
#[derive(Debug)]
pub(super) struct Custody {
    root: PathBuf,
    _lock: File,
}
impl Custody {
    pub(super) fn acquire(
        root: &Path,
        pin: [u8; 32],
        instance: StoreInstanceId,
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
        if !resume {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(&lock_path)
            .map_err(|e| format!("restore lock open failed: {e}"))?;
        lock.try_lock()
            .map_err(|e| format!("restore already running or lock unavailable: {e}"))?;
        let custody = Self {
            root: root.to_path_buf(),
            _lock: lock,
        };
        let binding = binding(pin, instance);
        let marker = root.join(INTENT);
        if resume {
            // Bound and compare the exact format after acquiring custody. A
            // source-archive intent or a legacy directory is never adopted.
            if !exists(&marker, false)? {
                return Err("all-heads resume refused: missing original intent (legacy directories cannot resume)".into());
            }
            let mut bytes = Vec::new();
            File::open(&marker)
                .map_err(|e| e.to_string())?
                .take(49)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
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

    /// Recover only fixed paths. Move a prepared WAL set back before any engine
    /// opens its database; never guess between two versions of the same path.
    pub(super) fn quarantine(&self) -> Result<PathBuf, String> {
        require_absent(&self.root.join(DATABASE))?;
        require_absent(&self.root.join(JOURNAL))?;
        require_absent(&self.root.join(SHM))?;
        let quarantine = self.root.join(QUARANTINE);
        let present = exists(&quarantine, true)?;
        let database = exists(&quarantine.join(DATABASE), false)?;
        exists(&quarantine.join(JOURNAL), false)?;
        exists(&quarantine.join(SHM), false)?;
        for name in LOCAL_STATE {
            exists(&quarantine.join(name), false)?;
        }
        // Every check precedes the first rename: a refusal changes no path.
        let mut public_names = Vec::new();
        for name in WAL_SET {
            let public = exists(&self.root.join(name), false)?;
            let private = exists(&quarantine.join(name), false)?;
            if public && private {
                return Err(format!(
                    "conflicting restore {name} locations; no paths changed"
                ));
            }
            if (public || private) && (!present || !database) {
                return Err(format!(
                    "restore {name} lacks its quarantined database; no paths changed"
                ));
            }
            if public {
                public_names.push(name);
            }
        }
        if !database
            && (exists(&quarantine.join(JOURNAL), false)? || exists(&quarantine.join(SHM), false)?)
        {
            return Err("restore sidecar lacks its database; no paths changed".into());
        }
        if !present {
            return Err("restore intent has neither a public database nor its original quarantine; refusing to recreate lost authority".into());
        }
        for name in public_names {
            fs::rename(self.root.join(name), quarantine.join(name)).map_err(|e| e.to_string())?;
        }
        sync_directory(&quarantine).map_err(|e| e.to_string())?;
        sync_directory(&self.root).map_err(|e| e.to_string())?;
        Ok(quarantine)
    }

    /// Only a closed, completely verified image reaches this boundary. The WAL
    /// set moves first; the database's no-replace link is the visibility
    /// boundary. Publication then drops the quarantine alias: fsqlite >= 0.4
    /// refuses to open a database path with multiple hard links ("not an
    /// isolated authority namespace"), and the verified image lives on at the
    /// final path as the same file.
    pub(super) fn publish(
        &self,
        mut after_wal: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let quarantine = self.root.join(QUARANTINE);
        if !exists(&quarantine, true)? {
            return Err("missing verified quarantine".into());
        }
        let database = quarantine.join(DATABASE);
        regular(&database)?;
        require_absent(&self.root.join(DATABASE))?;
        for name in WAL_SET {
            require_absent(&self.root.join(name))?;
        }
        require_absent(&self.root.join(JOURNAL))?;
        require_absent(&self.root.join(SHM))?;
        let journal = quarantine.join(JOURNAL);
        if exists(&journal, false)? && fs::metadata(&journal).map_err(|e| e.to_string())?.len() != 0
        {
            return Err("closed restore retains a rollback journal; publication refused".into());
        }
        exists(&quarantine.join(SHM), false)?;
        File::open(&database)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        for name in WAL_SET {
            let path = quarantine.join(name);
            if exists(&path, false)? {
                File::open(&path)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| e.to_string())?;
                fs::rename(&path, self.root.join(name)).map_err(|e| e.to_string())?;
            }
        }
        sync_directory(&quarantine).map_err(|e| e.to_string())?;
        sync_directory(&self.root).map_err(|e| e.to_string())?;
        after_wal()?;
        fs::hard_link(&database, self.root.join(DATABASE))
            .map_err(|e| format!("final authority link did not complete: {e}"))?;
        sync_directory(&self.root)
            .map_err(|e| format!("final authority is visible; directory sync failed: {e}"))?;
        sync_directory(parent(&self.root))
            .map_err(|e| format!("final authority is visible; parent sync failed: {e}"))?;
        self.settle_publication()
    }

    /// Complete a publication whose quarantine alias may survive a crash
    /// between the no-replace link and its removal. Only an alias proven to be
    /// the published file is removed; a different file is retained and refused.
    pub(super) fn settle_publication(&self) -> Result<(), String> {
        let alias = self.root.join(QUARANTINE).join(DATABASE);
        if !exists(&alias, false)? {
            return Ok(());
        }
        let published = self.root.join(DATABASE);
        if !same_file(&alias, &published)? {
            return Err(
                "quarantined database differs from the published authority; both retained".into(),
            );
        }
        fs::remove_file(&alias).map_err(|e| {
            format!("final authority is visible; quarantine alias removal failed: {e}")
        })?;
        sync_directory(&self.root.join(QUARANTINE))
            .map_err(|e| format!("final authority is visible; quarantine sync failed: {e}"))
    }

    /// Remove only owned, fixed staging names after final-location verification
    /// and shutdown. Unknown files prevent directory removal, never get erased.
    /// The intent and lock remain for resolving a lost success response.
    pub(super) fn cleanup(&self) -> Result<(), String> {
        if !self.published()? {
            return Err("cannot clean an unpublished all-heads restore".into());
        }
        let quarantine = self.root.join(QUARANTINE);
        if exists(&quarantine, true)? {
            let owned = [DATABASE, JOURNAL, SHM]
                .into_iter()
                .chain(WAL_SET)
                .chain(LOCAL_STATE);
            for name in owned.clone() {
                exists(&quarantine.join(name), false)?;
            }
            for name in owned {
                let path = quarantine.join(name);
                if exists(&path, false)? {
                    fs::remove_file(path).map_err(|e| e.to_string())?;
                }
            }
            fs::remove_dir(&quarantine).map_err(|e| {
                format!(
                    "owned quarantine cleanup refused: {e}; retained entries: {}",
                    retained_entries(&quarantine)
                )
            })?;
        }
        sync_directory(&self.root).map_err(|e| e.to_string())
    }
}
/// Whether two paths name the same file (device and inode), without following
/// a final symlink.
#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let left = fs::symlink_metadata(left).map_err(|e| e.to_string())?;
    let right = fs::symlink_metadata(right).map_err(|e| e.to_string())?;
    Ok(left.is_file() && right.is_file() && left.dev() == right.dev() && left.ino() == right.ino())
}
#[cfg(not(unix))]
fn same_file(_: &Path, _: &Path) -> Result<bool, String> {
    Err("cannot prove the quarantine alias is the published file on this platform".into())
}
/// Name (at most eight of) the entries that kept a directory from being
/// removed, so an operator can resolve them; nothing here deletes them.
fn retained_entries(directory: &Path) -> String {
    let Ok(entries) = fs::read_dir(directory) else {
        return "unreadable".into();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let total = names.len();
    names.truncate(8);
    if total > names.len() {
        names.push(format!("... {} more", total - names.len()));
    }
    names.join(", ")
}
fn create_private(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| format!("cannot reserve restore directory: {e}"))
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
