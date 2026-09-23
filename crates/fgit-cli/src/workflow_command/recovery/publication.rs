//! Private staging and no-overwrite publication of recovered bytes, not jobs.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const MAX_BYTES: usize = 64 * 1024 * 1024;

/// Stable operator-controlled parent paths are a precondition. This is not a
/// hostile same-UID filesystem boundary. Refuse every existing destination;
/// do not infer absence from a dangling symlink. A failed stage is retained and
/// named in the error. Once linked, sync/cleanup completes without cancellation.
pub(super) fn publish(path: &Path, bytes: &[u8], live: &dyn Fn() -> bool) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES { return Err("recovered artifact exceeds the export envelope".into()); }
    if !live() { return Err("recovery export cancelled before staging".into()); }
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("recovery output requires an absolute file path".into());
    }
    let parent = path.parent().ok_or("recovery output has no parent")?;
    let metadata = fs::symlink_metadata(parent).map_err(|e| format!("inspect recovery output parent: {e}"))?;
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err("recovery output parent must be a nonsymlink 0700 directory".into());
    }
    match fs::symlink_metadata(path) {
        Ok(_) => return Err("recovery output already exists; nothing overwritten".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("inspect recovery output: {e}")),
    }
    let (stage, mut file) = (0..8).find_map(|_| {
        let stage = parent.join(format!(".fg-recover-{}-{}.partial", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        if stage == path { return None; }
        match OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&stage) {
            Ok(file) => Some(Ok((stage, file))),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
            Err(e) => Some(Err(format!("create recovery stage: {e}"))),
        }
    }).ok_or("recovery staging names are occupied; no output published")??;
    let prepared = (|| -> Result<(), String> {
        if !live() { return Err("recovery export cancelled".into()); }
        file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| format!("write/sync recovery stage: {e}"))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        // Compare in fixed chunks; do not allocate a second evidence-sized copy.
        let mut buffer = [0; 16 * 1024];
        for expected in bytes.chunks(buffer.len()) {
            if !live() { return Err("recovery export cancelled during readback".into()); }
            file.read_exact(&mut buffer[..expected.len()]).map_err(|e| format!("read recovery stage: {e}"))?;
            if &buffer[..expected.len()] != expected { return Err("recovery stage readback mismatch".into()); }
        }
        let mut trailing = [0];
        if file.read(&mut trailing).map_err(|e| e.to_string())? != 0 { return Err("recovery stage contains trailing bytes".into()); }
        let opened = file.metadata().map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(&stage).map_err(|e| e.to_string())?;
        if !opened.is_file() || !named.is_file() || opened.nlink() != 1 || opened.mode() & 0o777 != 0o600
            || opened.len() != bytes.len() as u64 || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
        { return Err("recovery stage identity changed".into()); }
        if !live() { return Err("recovery export cancelled before publication".into()); }
        // hard_link is no-replace even if a competing destination appeared.
        fs::hard_link(&stage, path).map_err(|e| format!("publish recovery output without replacement: {e}"))?;
        Ok(())
    })();
    if let Err(error) = prepared {
        return Err(format!("{error}; private staging file retained at {}", stage.display()));
    }
    let published_error = |e| format!("recovery output is published at {}, but finalization failed: {e}; inspect output and staging at {}", path.display(), stage.display());
    File::open(parent).and_then(|dir| dir.sync_all()).map_err(published_error)?;
    fs::remove_file(&stage).map_err(published_error)?;
    File::open(parent).and_then(|dir| dir.sync_all()).map_err(published_error)?;
    Ok(())
}
