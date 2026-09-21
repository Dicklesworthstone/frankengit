//! Local-process ownership, not an authority lease. The persistent anchor is
//! never unlinked: replacing a locked inode could admit a second live owner.
//! An inode-bound run marker distinguishes this protocol from legacy sentinels.
use super::{File, OpenOptions, Path, PathBuf, Read, Write, fs, invalid, io, private_new};

const ANCHOR: &str = "owner.lock";
const RUN: &str = "run.lock";
const MAX_MARKER: u64 = 128;

fn identity(metadata: &fs::Metadata) -> io::Result<(u64, u64)> {
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err(invalid("ownership files must be private regular files with one link"));
        }
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))] {
        let _ = metadata;
        Err(io::Error::new(io::ErrorKind::Unsupported, "process ownership requires Unix"))
    }
}
fn same_file(path: &Path, file: &File) -> io::Result<()> {
    let named = fs::symlink_metadata(path)?;
    if identity(&named)? != identity(&file.metadata()?)? {
        return Err(invalid("ownership file was replaced"));
    }
    Ok(())
}
fn existing(path: &Path) -> io::Result<File> {
    identity(&fs::symlink_metadata(path)?)?; // Never intentionally follow links/devices.
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    same_file(path, &file)?;
    Ok(file)
}

pub(super) struct Owner {
    directory: PathBuf,
    anchor: Option<File>,
    marker: File,
    created: bool,
}
impl Owner {
    pub(super) fn acquire(directory: &Path, initialize: bool) -> io::Result<Self> {
        let path = directory.join(ANCHOR);
        let anchor = match private_new(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => existing(&path)?,
            Err(error) => return Err(error),
        };
        // Nonblocking and kernel-owned. No PID, elapsed-time or heartbeat guess
        // grants ownership; an unsupported lock implementation fails closed.
        anchor.try_lock()?;
        same_file(&path, &anchor)?;
        if anchor.metadata()?.len() != 0 { return Err(invalid("invalid ownership anchor")); }
        let (device, inode) = identity(&anchor.metadata()?)?;
        let expected = format!("frankengit-index-owner-v1 {device} {inode}\n");
        let path = directory.join(RUN);
        let (marker, created) = match private_new(&path) {
            Ok(mut file) => {
                file.write_all(expected.as_bytes())?;
                file.sync_all()?;
                (file, true)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && !initialize => {
                let mut file = existing(&path)?;
                if file.metadata()?.len() > MAX_MARKER { return Err(invalid("invalid run marker size")); }
                let mut bytes = Vec::new();
                (&mut file).take(MAX_MARKER + 1).read_to_end(&mut bytes)?;
                if bytes != expected.as_bytes() {
                    return Err(invalid("legacy, corrupt or foreign run marker requires inspection"));
                }
                // Only a matching marker AND this exclusive anchor permit
                // resumption. Never rewrite the checkpoint or pending identity.
                (file, false)
            }
            Err(error) => return Err(error),
        };
        anchor.sync_all()?;
        File::open(directory)?.sync_all()?;
        let owner = Self { directory: directory.to_path_buf(), anchor: Some(anchor), marker, created };
        owner.check()?;
        Ok(owner)
    }
    pub(super) fn check(&self) -> io::Result<()> {
        let anchor = self.anchor.as_ref().ok_or_else(|| invalid("ownership already released"))?;
        same_file(&self.directory.join(ANCHOR), anchor)?;
        same_file(&self.directory.join(RUN), &self.marker)
    }
    /// The caller has not started native work. Clean only a marker acquired by
    /// this open, preserving an inherited crash marker on corrupt/wrong-scope
    /// checkpoint failure. No responsibility can be lost by closing here.
    pub(super) fn abort_open(mut self) {
        if self.created && self.check().is_ok() {
            let _ = fs::remove_file(self.directory.join(RUN));
            let _ = File::open(&self.directory).and_then(|file| file.sync_all());
        }
        drop(self.anchor.take());
    }
    /// Call only after explicit native shutdown. The run marker is removed
    /// while still locked; the permanent anchor stays available for all peers.
    pub(super) fn release(mut self) -> io::Result<()> {
        self.check()?;
        fs::remove_file(self.directory.join(RUN))?;
        File::open(&self.directory)?.sync_all()?;
        drop(self.anchor.take());
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        // Unwinding or dropping progress does not prove that native work has
        // drained. Keep this one descriptor locked until PROCESS termination.
        // The OS then closes it, providing the missing exclusive-restart proof.
        // Normal release and pre-work failure explicitly close it above.
        if let Some(anchor) = self.anchor.take() { std::mem::forget(anchor); }
    }
}
