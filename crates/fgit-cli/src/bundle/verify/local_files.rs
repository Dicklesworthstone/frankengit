//! Private local ownership for the seekable native bundle reader.
//!
//! The verifier owns Git semantics. These guards bind one input descriptor and
//! remove only a scratch file created by this invocation. Paths must remain
//! quiescent under the operator's control; these checks are not a sandbox
//! against a hostile process running with the same filesystem authority.

use std::fs::{File, Metadata, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), String> {
    if live() {
        Ok(())
    } else {
        Err("bundle_verification_stopped".into())
    }
}

fn same_identity(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn same_input(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same_identity(left, right)
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
            && left.nlink() == right.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn private_directory(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_dir() && metadata.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn private_file(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_file() && metadata.mode() & 0o077 == 0 && metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

// Reject named symlink components as well as a symlink at the final name.
// Filesystem namespace checks cannot make a same-user mutation race safe.
fn ordinary_parents(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.as_os_str().as_encoded_bytes().len() > 4096 {
        return Err("file-backed paths must contain 1..4096 bytes".into());
    }
    let mut walked = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (at, component) in components.iter().enumerate() {
        if *component == Component::ParentDir {
            return Err("file-backed paths must not contain parent traversal".into());
        }
        walked.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&walked)
            .map_err(|error| format!("cannot inspect bundle path component: {error}"))?;
        if metadata.is_symlink() || (at + 1 < components.len() && !metadata.is_dir()) {
            return Err("file-backed path components must be ordinary non-symlink entries".into());
        }
    }
    Ok(())
}

/// A nonempty regular input opened once and rechecked after every complete use.
pub(crate) struct StableInput {
    path: PathBuf,
    file: File,
    before: Metadata,
}

impl StableInput {
    pub(crate) fn open(
        path: &Path,
        maximum: u64,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, String> {
        checkpoint(live)?;
        if !cfg!(unix) {
            return Err(
                "file-backed bundle verification requires the Unix local-file profile".into(),
            );
        }
        ordinary_parents(path)?;
        let named = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !named.is_file() || named.len() == 0 || named.len() > maximum {
            return Err(
                "bundle input must be a nonempty regular non-symlink file within the byte limit"
                    .into(),
            );
        }
        checkpoint(live)?;
        let file = File::open(path).map_err(|error| error.to_string())?;
        let before = file.metadata().map_err(|error| error.to_string())?;
        if !before.is_file() || !same_input(&named, &before) {
            return Err("bundle input changed while opening".into());
        }
        let input = Self {
            path: path.to_path_buf(),
            file,
            before,
        };
        input.recheck(live)?;
        Ok(input)
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn len(&self) -> u64 {
        self.before.len()
    }

    pub(crate) fn recheck(&self, live: &mut impl FnMut() -> bool) -> Result<(), String> {
        checkpoint(live)?;
        ordinary_parents(&self.path)?;
        let after = self.file.metadata().map_err(|error| error.to_string())?;
        let named = std::fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        if !named.is_file()
            || !after.is_file()
            || !same_input(&self.before, &after)
            || !same_input(&after, &named)
        {
            return Err("bundle input changed during file-backed verification".into());
        }
        checkpoint(live)
    }
}

/// Exactly one newly created private scratch file, with no reuse of old residue.
pub(crate) struct OwnedScratch {
    directory: PathBuf,
    directory_identity: Metadata,
    path: PathBuf,
    file: Option<File>,
    identity: Metadata,
    removed: bool,
}

impl OwnedScratch {
    pub(crate) fn create(
        directory: &Path,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, String> {
        checkpoint(live)?;
        ordinary_parents(directory)?;
        let directory_identity = std::fs::symlink_metadata(directory)
            .map_err(|error| format!("cannot inspect scratch directory: {error}"))?;
        if !private_directory(&directory_identity) {
            return Err("scratch directory must be an existing private ordinary Unix directory (mode 0700 or tighter)".into());
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            checkpoint(live)?;
            let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(".fg-bundle-{}-{nonce}.scratch", std::process::id()));
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("cannot create private bundle scratch: {error}")),
            };
            let identity = file.metadata().map_err(|error| {
                format!(
                    "cannot inspect newly created scratch; retained at {}: {error}",
                    path.display()
                )
            })?;
            let scratch = Self {
                directory: directory.to_path_buf(),
                directory_identity,
                path,
                file: Some(file),
                identity,
                removed: false,
            };
            scratch.recheck()?;
            checkpoint(live)?;
            return Ok(scratch);
        }
        Err("cannot reserve a fresh bundle scratch name after 64 collisions".into())
    }

    pub(crate) fn file_mut(&mut self) -> Result<&mut File, String> {
        self.file
            .as_mut()
            .ok_or_else(|| "bundle scratch already closed".into())
    }

    pub(crate) fn recheck(&self) -> Result<(), String> {
        ordinary_parents(&self.directory)?;
        let directory = std::fs::symlink_metadata(&self.directory)
            .map_err(|error| format!("scratch directory changed: {error}"))?;
        let named = std::fs::symlink_metadata(&self.path)
            .map_err(|error| format!("scratch name changed: {error}"))?;
        let current = self
            .file
            .as_ref()
            .ok_or("bundle scratch already closed")?
            .metadata()
            .map_err(|error| format!("cannot inspect scratch descriptor: {error}"))?;
        if !private_directory(&directory)
            || !same_identity(&self.directory_identity, &directory)
            || !private_file(&named)
            || !private_file(&current)
            || !same_identity(&self.identity, &current)
            || !same_identity(&current, &named)
        {
            return Err("bundle scratch ownership or identity changed".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.uid() != directory.uid() {
                return Err("scratch directory must belong to the invoking file owner".into());
            }
        }
        Ok(())
    }

    /// Cleanup remains live after cancellation and never removes a replacement.
    pub(crate) fn cleanup(&mut self) -> Result<(), String> {
        if self.removed {
            return Ok(());
        }
        self.recheck().map_err(|error| {
            format!(
                "scratch_cleanup_incomplete: {error}; inspect {}",
                self.path.display()
            )
        })?;
        std::fs::remove_file(&self.path).map_err(|error| {
            format!(
                "scratch_cleanup_incomplete: cannot remove {}: {error}",
                self.path.display()
            )
        })?;
        self.removed = true;
        self.file.take();
        Ok(())
    }
}

impl Drop for OwnedScratch {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
#[path = "local_files/tests.rs"]
mod tests;
