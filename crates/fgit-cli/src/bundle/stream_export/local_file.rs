//! Create-only publication of one native export stream. Git validation stays
//! with the node. These Unix paths must be quiescent and operator controlled;
//! std path checks are not a sandbox against a hostile process with the same
//! filesystem authority. Cleanup never removes an entry with another identity.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const CHUNK_BYTES: usize = 64 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum State {
    Staged,
    Visible,
    Durable,
}

impl State {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Visible => "visible",
            Self::Durable => "durable",
        }
    }

    pub(super) const fn published(self) -> bool {
        !matches!(self, Self::Staged)
    }
}

#[derive(Debug)]
pub(super) struct Error {
    pub(super) state: State,
    detail: String,
}

impl Error {
    fn new(state: State, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "streaming_bundle_export: state={} bundle_created={} detail={}",
            self.state.as_str(),
            self.state.published(),
            self.detail
        )
    }
}

impl std::error::Error for Error {}

fn same_identity(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.mode() == b.mode()
            && a.uid() == b.uid()
            && a.gid() == b.gid()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

fn private_file(metadata: &Metadata, links: u64) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_file() && metadata.mode() & 0o077 == 0 && metadata.nlink() == links
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, links);
        false
    }
}

fn ordinary_directory(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.as_os_str().as_encoded_bytes().len() > 4096 {
        return Err("export directory path must contain 1..4096 bytes".into());
    }
    let mut walked = PathBuf::new();
    for component in path.components() {
        if component == Component::ParentDir {
            return Err("streaming export paths must not contain parent traversal".into());
        }
        walked.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&walked)
            .map_err(|error| format!("cannot inspect export directory component: {error}"))?;
        if !metadata.is_dir() || metadata.is_symlink() {
            return Err("export parent components must be existing ordinary directories".into());
        }
    }
    Ok(())
}

fn absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect export destination: {error}")),
        Ok(_) => Err("export destination already exists; no file is replaced".into()),
    }
}

/// A fresh mode-0600 file. The final name is not created until `publish`.
pub(super) struct OwnedExport {
    directory: PathBuf,
    directory_file: File,
    directory_identity: Metadata,
    destination: PathBuf,
    path: PathBuf,
    file: Option<File>,
    identity: Metadata,
    maximum: u64,
    written: u64,
    poisoned: bool,
    removed: bool,
    state: State,
}

impl OwnedExport {
    pub(super) fn create(destination: &Path, maximum: u64) -> Result<Self, Error> {
        let error = |detail| Error::new(State::Staged, detail);
        if !cfg!(unix) {
            return Err(error(
                "streaming export requires the Unix file-publication profile".into(),
            ));
        }
        if maximum == 0
            || maximum > 16 * 1024 * 1024 * 1024
            || destination.as_os_str().as_encoded_bytes().len() > 4096
            || !matches!(
                destination.components().next_back(),
                Some(Component::Normal(_))
            )
        {
            return Err(error(
                "invalid streaming export destination or byte limit".into(),
            ));
        }
        let directory = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ordinary_directory(directory).map_err(error)?;
        absent(destination).map_err(error)?;
        let directory_identity = fs::symlink_metadata(directory)
            .map_err(|cause| error(format!("cannot inspect export directory: {cause}")))?;
        let directory_file = File::open(directory)
            .map_err(|cause| error(format!("cannot open export directory: {cause}")))?;
        let opened = directory_file.metadata().map_err(|cause| {
            error(format!(
                "cannot inspect export directory descriptor: {cause}"
            ))
        })?;
        if !opened.is_dir() || !same_identity(&directory_identity, &opened) {
            return Err(error("export directory changed while opening".into()));
        }
        // Refuse unsupported directory durability before spending work on Git.
        directory_file
            .sync_all()
            .map_err(|cause| error(format!("export directory sync unsupported: {cause}")))?;
        for _ in 0..64 {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                ".fg-stream-export-{}-{sequence}.tmp",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = match options.open(&path) {
                Ok(file) => file,
                Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(cause) => return Err(error(format!("cannot stage export: {cause}"))),
            };
            let identity = file.metadata().map_err(|cause| {
                error(format!(
                    "cannot establish export file ownership; stage retained at {}: {cause}",
                    path.display()
                ))
            })?;
            let stage = Self {
                directory: directory.to_path_buf(),
                directory_file,
                directory_identity,
                destination: destination.to_path_buf(),
                path,
                file: Some(file),
                identity,
                maximum,
                written: 0,
                poisoned: false,
                removed: false,
                state: State::Staged,
            };
            stage.recheck().map_err(|cause| {
                stage.fail(format!(
                    "cannot establish staging ownership: {cause}; inspect {} if cleanup could not complete",
                    stage.path.display()
                ))
            })?;
            return Ok(stage);
        }
        Err(error("export temporary-name budget exhausted".into()))
    }

    pub(super) const fn state(&self) -> State {
        self.state
    }

    fn fail(&self, detail: impl Into<String>) -> Error {
        Error::new(self.state, detail)
    }

    fn recheck_directory(&self) -> Result<(), Error> {
        ordinary_directory(&self.directory).map_err(|cause| self.fail(cause))?;
        let named = fs::symlink_metadata(&self.directory)
            .map_err(|cause| self.fail(format!("export directory changed: {cause}")))?;
        let descriptor = self
            .directory_file
            .metadata()
            .map_err(|cause| self.fail(format!("export directory descriptor failed: {cause}")))?;
        if !named.is_dir()
            || !descriptor.is_dir()
            || !same_identity(&self.directory_identity, &named)
            || !same_identity(&named, &descriptor)
        {
            return Err(self.fail("export directory identity changed"));
        }
        Ok(())
    }

    fn recheck(&self) -> Result<(), Error> {
        self.recheck_directory()?;
        let named = fs::symlink_metadata(&self.path)
            .map_err(|cause| self.fail(format!("export stage name changed: {cause}")))?;
        let descriptor = self
            .file
            .as_ref()
            .ok_or_else(|| self.fail("export stage already closed"))?
            .metadata()
            .map_err(|cause| self.fail(format!("export stage descriptor failed: {cause}")))?;
        let links = if self.state.published() { 2 } else { 1 };
        if !private_file(&named, links)
            || !private_file(&descriptor, links)
            || !same_identity(&self.identity, &descriptor)
            || !same_identity(&descriptor, &named)
        {
            return Err(self.fail("export stage ownership or identity changed"));
        }
        Ok(())
    }

    fn checkpoint(&self, live: &mut impl FnMut() -> bool) -> Result<(), Error> {
        if live() {
            Ok(())
        } else {
            Err(self.fail("export stopped before local publication"))
        }
    }

    /// Call only after native completion and successful node shutdown. It is
    /// safe to abort before the link; after it, every error retains visible truth.
    pub(super) fn publish(
        &mut self,
        expected_bytes: u64,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), Error> {
        self.publish_with_sync(expected_bytes, live, File::sync_all)
    }

    fn publish_with_sync(
        &mut self,
        expected_bytes: u64,
        live: &mut impl FnMut() -> bool,
        sync_directory: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), Error> {
        self.checkpoint(live)?;
        if self.state != State::Staged
            || self.poisoned
            || expected_bytes == 0
            || self.written != expected_bytes
        {
            return Err(self.fail("export stream is incomplete, failed, or already published"));
        }
        self.recheck()?;
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| self.fail("export stage closed"))?;
        if file
            .metadata()
            .map_err(|cause| self.fail(format!("cannot inspect completed export: {cause}")))?
            .len()
            != expected_bytes
        {
            return Err(self.fail("export stage length differs from native receipt"));
        }
        file.sync_all()
            .map_err(|cause| self.fail(format!("export file sync failed: {cause}")))?;
        self.recheck()?;
        self.checkpoint(live)?;
        // hard_link atomically creates the requested name or refuses a collision.
        fs::hard_link(&self.path, &self.destination).map_err(|cause| {
            self.fail(format!("create-only export publication failed: {cause}"))
        })?;
        self.state = State::Visible;
        let published = fs::symlink_metadata(&self.destination).map_err(|cause| {
            self.fail(format!("export became visible; cannot inspect it: {cause}"))
        })?;
        if !private_file(&published, 2) || !same_identity(&self.identity, &published) {
            return Err(self.fail("export became visible; destination identity changed"));
        }
        // Cleanup owns only the temporary name. The destination is never removed.
        self.cleanup()?;
        self.recheck_directory()?;
        sync_directory(&self.directory_file).map_err(|cause| {
            self.fail(format!("export is visible; directory sync failed: {cause}"))
        })?;
        self.state = State::Durable;
        Ok(())
    }

    /// This is independent of request liveness. A replaced/aliased stage is
    /// retained for inspection, never deleted under an assumed ownership claim.
    pub(super) fn cleanup(&mut self) -> Result<(), Error> {
        if self.removed {
            return Ok(());
        }
        self.recheck().map_err(|cause| {
            self.fail(format!(
                "export_cleanup_incomplete: {cause}; inspect {}",
                self.path.display()
            ))
        })?;
        fs::remove_file(&self.path).map_err(|cause| {
            self.fail(format!(
                "export_cleanup_incomplete: cannot remove {}: {cause}",
                self.path.display()
            ))
        })?;
        self.removed = true;
        self.file.take();
        Ok(())
    }
}

impl Write for OwnedExport {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.poisoned || self.state != State::Staged {
            return Err(io::Error::other(
                "export writer failed or is no longer staging",
            ));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let offered = bytes.len().min(CHUNK_BYTES);
        if self
            .written
            .checked_add(offered as u64)
            .is_none_or(|total| total > self.maximum)
        {
            self.poisoned = true;
            return Err(io::Error::other(
                "streaming export output-byte budget exceeded",
            ));
        }
        let result = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("export stage closed"))?
            .write(&bytes[..offered]);
        match result {
            Ok(0) => {
                self.poisoned = true;
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "export write made no progress",
                ))
            }
            Ok(count) if count <= offered => {
                self.written += count as u64;
                Ok(count)
            }
            Ok(_) => {
                self.poisoned = true;
                Err(io::Error::other("invalid export writer byte count"))
            }
            Err(cause) => {
                self.poisoned = cause.kind() != io::ErrorKind::Interrupted;
                Err(cause)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.poisoned || self.state != State::Staged {
            return Err(io::Error::other(
                "export writer failed or is no longer staging",
            ));
        }
        let result = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("export stage closed"))?
            .flush();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl Drop for OwnedExport {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
#[path = "local_file/tests.rs"]
mod tests;
