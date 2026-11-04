//! Private host paths and an unlinked operation spool. No live input is reread
//! after archive verification; only this owned file handle survives the copy.
use super::*;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Component;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

pub(super) fn directory(path: &Path, private: bool) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("LFS paths must be absolute".into());
    }
    let mut prefix = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => prefix.push(component),
            _ => return Err("LFS paths must not contain parent traversal".into()),
        }
        let meta = fs::symlink_metadata(&prefix)
            .map_err(|e| format!("LFS directory inspection failed: {e}"))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("LFS directory path contains a symlink or non-directory".into());
        }
    }
    if private
        && fs::symlink_metadata(path)
            .map_err(|e| e.to_string())?
            .mode()
            & 0o777
            != 0o700
    {
        return Err("LFS archive/custody directory must have mode 0700".into());
    }
    Ok(())
}

pub(super) fn output(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|_| path.file_name().is_some())
        .ok_or("LFS archive must name a file")?;
    directory(parent, true)?;
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
        Ok(_) => Err("LFS archive output already exists".into()),
    }
}

fn source(path: &Path, maximum: u64) -> Result<File, String> {
    let parent = path
        .parent()
        .filter(|_| path.file_name().is_some())
        .ok_or("LFS archive must name a file")?;
    directory(parent, true)?;
    let owner = fs::symlink_metadata(parent)
        .map_err(|e| e.to_string())?
        .uid();
    let before =
        fs::symlink_metadata(path).map_err(|e| format!("LFS archive inspection failed: {e}"))?;
    let valid = |metadata: &fs::Metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.mode() & 0o077 == 0
            && metadata.uid() == owner
            && metadata.len() <= maximum
    };
    if !valid(&before) {
        return Err("LFS archive must be a private, bounded regular file".into());
    }
    // NOFOLLOW prevents following a swapped final symlink. NONBLOCK prevents
    // a swapped FIFO from hanging before fstat can reject its actual type.
    // Parent components remain part of the stable operator-owned path profile.
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| format!("LFS archive open failed: {e}"))?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if !valid(&after)
        || (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
    {
        return Err("LFS archive identity changed while opening".into());
    }
    Ok(file)
}

pub(super) fn spool(
    path: &Path,
    parent: &Path,
    maximum: u64,
    deadline: Deadline,
) -> Result<File, String> {
    deadline.check()?;
    directory(parent, true)?;
    let mut input = source(path, maximum)?;
    let mut selected = None;
    for _ in 0..32 {
        deadline.check()?;
        let name = parent.join(format!(
            ".fg-lfs-spool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&name)
        {
            Ok(file) => {
                // The operation retains the sole path-free handle. A caller
                // replacing/mutating the original cannot alter the second pass.
                if let Err(error) = fs::remove_file(&name) {
                    return Err(format!(
                        "cannot unlink private LFS spool {}: {error}",
                        name.display()
                    ));
                }
                selected = Some(file);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("cannot create private LFS spool: {e}")),
        }
    }
    let mut spool = selected.ok_or("no unused LFS spool slot")?;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        deadline.check()?;
        let count = match input.read(&mut buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("LFS archive copy failed: {e}")),
        };
        deadline.check()?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .filter(|n| *n <= maximum)
            .ok_or("LFS archive byte limit")?;
        spool
            .write_all(&buffer[..count])
            .map_err(|e| format!("LFS spool write failed: {e}"))?;
    }
    spool.flush().map_err(|e| e.to_string())?;
    deadline.check()?;
    spool.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(spool)
}
