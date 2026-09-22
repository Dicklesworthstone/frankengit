#![forbid(unsafe_code)]
//! Trusted-local source recovery; authority operations remain in their backend.
#[path = "repository_backup/mod.rs"]
mod repository;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_authority::{AuthorityLimits, StoreInstanceId};
use fgit_authority_fsqlite::{ExportBundle, FsqliteAuthorityStore};
#[cfg(test)]
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match repository::run(&args, &mut std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{{\"type\":\"repository_backup_error\",\"schema_version\":1,\"complete\":false,\"error\":{}}}", quote(&error));
            ExitCode::from(2)
        }
    }
}
#[cfg(test)]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"),
            c if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}'
                | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
                out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}").and_then(|()| output.flush()).map_err(|e| e.to_string())
}
fn regular(path: &Path) -> Result<u64, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect input: {e}"))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err("input must be an existing nonempty regular file, not a symlink or device".into());
    }
    Ok(metadata.len())
}
fn require_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
        Ok(_) => Err("destination already exists".into()),
    }
}
fn parent(path: &Path) -> &Path {
    path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."))
}
#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> { File::open(path)?.sync_all() }
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> { Ok(()) }
fn context(runtime: &NodeRuntime) -> Cx {
    let cx = Cx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
    cx
}
/// Top-level host adapter. The backend owns all SQL, transactions and tokens;
/// cleanup uses its own finite context even after request budget exhaustion.
fn with_store<T>(path: &Path, instance: StoreInstanceId, existing: bool,
    operation: impl FnOnce(&NodeRuntime, &FsqliteAuthorityStore, &Cx) -> Result<T, String>,
) -> Result<T, String> {
    let path = path.to_str().ok_or("database path is not UTF-8")?;
    let runtime = RuntimeProfile::production(2).build().map_err(|e| e.to_string())?;
    let cx = context(&runtime);
    let opened = if existing {
        runtime.block_on(FsqliteAuthorityStore::open_portable_source(&cx, path, AuthorityLimits::default()))
            .map_err(|error| error.to_string())
    } else {
        runtime.block_on(FsqliteAuthorityStore::open(&cx, path, instance, AuthorityLimits::default()))
            .map_err(|error| error.to_string())
    };
    let result = match opened {
        Ok(mut store) => {
            let result = operation(&runtime, &store, &cx);
            let cleanup = context(&runtime);
            let closed = runtime.block_on(store.close(&cleanup)).map_err(|e| e.to_string());
            match (result, closed) {
                (Ok(result), Ok(())) => Ok(result),
                (Err(error), Ok(())) => Err(error),
                (Ok(_), Err(error)) => Err(format!("operation finished but store shutdown failed: {error}")),
                (Err(error), Err(cleanup)) => Err(format!("{error}; store shutdown also failed: {cleanup}")),
            }
        }
        Err(error) => Err(format!("cannot open authority store: {error}")),
    };
    drop(cx);
    if !runtime.join_root(Duration::from_secs(5)) {
        return Err(format!("{}; runtime did not drain", result.err().unwrap_or_else(|| "operation finished".into())));
    }
    result
}
fn generation(bundle: &ExportBundle) -> String {
    bundle.head.as_ref().map_or_else(|| "null".into(), |head| head.generation.to_string())
}
/// Build and verify through one private read/write handle. The callback must
/// finish its source verification and node close before any final path exists.
/// The result is retained until file sync and no-replace publication succeed.
fn publish_streamed<T>(destination: &Path, build: impl FnOnce(&mut File) -> Result<T, String>) -> Result<T, String> {
    require_absent(destination)?;
    let mut staged = None;
    for _ in 0..16 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = parent(destination).join(format!(".fg-source-backup-{}-{sequence}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => { staged = Some((path, file)); break; }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot stage repository backup: {error}")),
        }
    }
    let (temporary, mut file) = staged.ok_or("no unused repository backup staging path")?;
    let built = build(&mut file).and_then(|result| {
        file.sync_all().map_err(|error| format!("repository backup staging sync failed: {error}"))?;
        Ok(result)
    });
    drop(file);
    let result = match built {
        Ok(result) => result,
        Err(error) => return Err(remove_stage(&temporary, error)),
    };
    if let Err(error) = fs::hard_link(&temporary, destination) {
        return Err(remove_stage(&temporary, format!("repository backup publication failed: {error}")));
    }
    fs::remove_file(&temporary).map_err(|e| format!("repository backup is visible; staging cleanup failed: {e}"))?;
    sync_directory(parent(destination)).map_err(|e| format!("repository backup is visible; parent sync failed: {e}"))?;
    Ok(result)
}
fn remove_stage(path: &Path, original: String) -> String {
    fs::remove_file(path).err().map_or_else(|| original.clone(), |cleanup|
        format!("{original}; staging cleanup also failed at {}: {cleanup}", path.display()))
}
