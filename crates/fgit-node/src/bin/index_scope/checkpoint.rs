//! Operator-owned pre-publication candidate recording. Not a commit receipt.
//! The parent must be a private trusted directory; not a hostile-user sandbox.
use super::options::invalid;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
pub const MAX_RECORD_BYTES: usize = 96 * 1024;

#[cfg(unix)]
pub fn preflight(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.file_name().is_none() {
        return Err(invalid("Candidate record requires a file name."));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(invalid(
            "Candidate parent must be an existing private 0700 directory, not a symlink.",
        ));
    }
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Candidate record already exists; inspect it, never overwrite it.",
        )),
    }
}
#[cfg(not(unix))]
pub fn preflight(_path: &Path) -> io::Result<()> {
    Err(invalid(
        "Durable candidate recording is supported only by the Unix private-directory profile.",
    ))
}
pub fn record(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("Candidate record exceeds its byte bound."));
    }
    preflight(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    // Keep a partial/suspect file on any failure. The guarded native caller may
    // not stage anything until both data and directory synchronization succeed.
    file.write_all(bytes)?;
    file.sync_all()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::File::open(parent)?.sync_all()
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
