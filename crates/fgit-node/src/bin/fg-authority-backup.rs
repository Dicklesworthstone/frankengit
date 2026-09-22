#![forbid(unsafe_code)]
//! Trusted-local portable authority recovery. No external Git or SQL shell.
//! This command backs up authority metadata, NOT the separate Git object fabric.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_authority::{AuthorityLimits, StoreInstanceId};
use fgit_authority_fsqlite::{ExportBundle, FsqliteAuthorityStore, PortableStoreLimits,
    export_bundle, import_bundle};
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);
const USAGE: &str = "usage: fg-authority-backup export <existing-authority.fsqlite> <new-backup-file> --trusted-local
       fg-authority-backup restore <backup-file> <new-directory> --trusted-local
         --expected-sha256 <64-lowercase-hex> --destination-instance <positive-integer>

Single-head embedded authority metadata only: immutable bodies, published head,
and full issuance ledger. Git objects, private keys, configuration outside the
store, runner workspaces and routing are NOT backed up or restored. This is not
a complete repository backup or a signed capsule recovery profile.

Export is one bounded SQL snapshot; its current head may advance afterward.
Restore requires an independently trusted checksum, a new directory and a new
store-instance identity distinct from the source. Original canonical bytes and
generations survive; source CAS tokens do not. Output: authority.fsqlite in the
new directory. Do not route or serve it until the remaining repository backup
components and canonical evidence have been restored and verified.

This operator profile requires stable regular files and trusted parent paths;
it is not an adversarial-host-filesystem boundary. Input/output is limited to
64 MiB, at most 100000 immutable bodies and 100000 ledger rows. Authority, codec and runtime budgets
may refuse earlier. Export never overwrites a file. Restore never overwrites a
directory. An interrupted restore directory is retained for investigation; its
existence is not evidence of success or non-commit. Only a success receipt after
store close and runtime drain confirms this scoped operation. Exit 0: complete;
2: invalid input, incomplete operation, cleanup failure or receipt I/O failure.";

#[derive(Debug)]
enum Mode { Export, Restore { expected: [u8; 32], instance: StoreInstanceId } }
#[derive(Debug)]
struct Options { input: PathBuf, output: PathBuf, mode: Mode }

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match run(&args, &mut std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{{\"type\":\"authority_backup_error\",\"schema_version\":1,\"complete\":false,\"error\":{}}}", quote(&error));
            ExitCode::from(2)
        }
    }
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 || args.len() > 8 || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[1].is_empty() || args[2].is_empty()
    { return Err(USAGE.into()); }
    let mut trusted = false;
    let mut expected = None;
    let mut instance = None;
    let mut cursor = 3;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted { return Err("duplicate --trusted-local".into()); }
            trusted = true;
            continue;
        }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--expected-sha256" if expected.is_none() => expected = Some(digest(value)?),
            "--destination-instance" if instance.is_none() => {
                if value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("destination instance must be canonical positive decimal".into());
                }
                let number = value.parse::<u64>().ok().filter(|n| *n > 0 && *n <= i64::MAX as u64)
                    .ok_or("destination instance must fit a positive SQL integer")?;
                instance = Some(StoreInstanceId::from_raw(number));
            }
            _ => return Err(format!("unknown or duplicate backup option: {flag}")),
        }
    }
    if !trusted { return Err("--trusted-local and whole-store operator authorization are required".into()); }
    let mode = match args[0].as_str() {
        "export" if expected.is_none() && instance.is_none() => Mode::Export,
        "restore" => Mode::Restore {
            expected: expected.ok_or("restore requires an independently trusted --expected-sha256")?,
            instance: instance.ok_or("restore requires a fresh --destination-instance")?,
        },
        _ => return Err(USAGE.into()),
    };
    let output = PathBuf::from(&args[2]);
    if output.file_name().is_none() { return Err("destination must have a final path component".into()); }
    Ok(Options { input: args[1].clone().into(), output, mode })
}
fn digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("expected SHA-256 must be exactly 64 lowercase hexadecimal characters".into());
    }
    let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *out = 16 * nibble(pair[0]) + nibble(pair[1]);
    }
    Ok(result)
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
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
    out.push('"'); out
}
fn regular(path: &Path) -> Result<u64, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect input: {e}"))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err("input must be an existing nonempty regular file, not a symlink or device".into());
    }
    Ok(metadata.len())
}
fn read_backup(path: &Path) -> Result<Vec<u8>, String> {
    if regular(path)? > MAX_BYTES as u64 { return Err("backup exceeds the 64 MiB input limit".into()); }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() > MAX_BYTES as u64 {
        return Err("backup changed into a non-regular or oversized input".into());
    }
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES { return Err("empty or oversized backup".into()); }
    Ok(bytes)
}
fn context(runtime: &NodeRuntime) -> Cx {
    let cx = Cx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
    cx
}

/// Own the entire lifecycle, including the independent bounded cleanup context.
/// CLI block_on is a top-level host adapter, not a replacement request runtime.
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
    if !runtime.join_root(CLOSE_TIMEOUT) {
        return Err(format!("{}; runtime did not drain", result.err().unwrap_or_else(|| "operation finished".into())));
    }
    result
}
fn generation(bundle: &ExportBundle) -> String {
    bundle.head.as_ref().map_or_else(|| "null".into(), |head| head.generation.to_string())
}
fn run(args: &[String], output: &mut impl Write) -> Result<(), String> {
    if args == ["--help"] { return emit(output, USAGE); }
    let options = parse(args)?;
    let receipt = match options.mode {
        Mode::Export => export(&options.input, &options.output)?,
        Mode::Restore { expected, instance } => restore(&options.input, &options.output, expected, instance)?,
    };
    emit(output, &receipt).map_err(|error| format!("operation completed; receipt failed: {error}"))
}
fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}").and_then(|()| output.flush()).map_err(|e| e.to_string())
}
fn export(input: &Path, destination: &Path) -> Result<String, String> {
    regular(input)?;
    require_absent(destination)?;
    let (bytes, bodies, issuance, generation, instance) = with_store(input, StoreInstanceId::from_raw(0), true, |runtime, store, cx| {
        let bundle = runtime.block_on(store.export_portable(cx, PortableStoreLimits::default())).map_err(|e| e.to_string())?;
        let bytes = export_bundle(&bundle).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_BYTES { return Err("serialized backup exceeds 64 MiB".into()); }
        // Prove that the exact default import codec can read the emitted file.
        // Do not publish an export that exceeds the decoder's own envelope.
        let decoded = import_bundle(&bytes).map_err(|e| format!("export is outside the restore codec envelope: {e}"))?;
        if decoded != bundle { return Err("portable encoding changed its source snapshot".into()); }
        Ok((bytes, bundle.bodies.len(), bundle.issuance.len(), generation(&bundle), bundle.instance))
    })?;
    let hash = hex(&sha256(&bytes));
    publish_new(destination, &bytes)?;
    Ok(format!(concat!("{{\"type\":\"authority_backup_export\",\"schema_version\":1,\"sha256\":{},",
        "\"bytes\":{},\"bodies\":{},\"issuance_rows\":{},\"head_generation\":{},\"source_instance\":{},",
        "\"complete\":true,\"store_closed\":true,\"runtime_drained\":true,",
        "\"git_objects_included\":false,\"signature_verified\":false,\"authority_changed\":false}}"),
        quote(&hash), bytes.len(), bodies, issuance, generation, instance))
}
fn restore(input: &Path, destination: &Path, expected: [u8; 32], instance: StoreInstanceId) -> Result<String, String> {
    let bytes = read_backup(input)?;
    if sha256(&bytes) != expected { return Err("backup checksum mismatch; no destination created".into()); }
    let bundle = import_bundle(&bytes).map_err(|e| format!("invalid backup; no destination created: {e}"))?;
    if bundle.instance == instance.raw() { return Err("destination instance must differ from source; no destination created".into()); }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(destination).map_err(|e| format!("cannot create new restore directory: {e}"))?;
    let path = destination.join("authority.fsqlite");
    with_store(&path, instance, false, |runtime, store, cx| {
        let result = runtime.block_on(store.import_portable(cx, &bundle, PortableStoreLimits::default()))
            .map_err(|e| format!("restore did not confirm a complete result: {e}"))?;
        if result.as_ref().map(|r| (r.generation().get(), r.body()))
            != bundle.head.as_ref().map(|h| (h.generation, h.body.as_slice()))
        { return Err("restore returned an inconsistent publication receipt".into()); }
        Ok(())
    }).map_err(|e| format!("{e}; restore directory retained at {}; do not infer success or non-commit from its presence", destination.display()))?;
    sync_directory(destination).map_err(|e| format!("restore committed and store closed; directory sync failed: {e}"))?;
    sync_directory(parent(destination)).map_err(|e| format!("restore committed and store closed; parent sync failed: {e}"))?;
    Ok(format!(concat!("{{\"type\":\"authority_backup_restore\",\"schema_version\":1,\"sha256\":{},",
        "\"bodies\":{},\"issuance_rows\":{},\"head_generation\":{},\"source_instance\":{},",
        "\"destination_instance\":{},\"database\":{},\"complete\":true,\"store_closed\":true,",
        "\"runtime_drained\":true,\"source_tokens_preserved\":false,\"git_objects_restored\":false,",
        "\"routing_published\":false,\"signature_verified\":false}}"), quote(&hex(&expected)),
        bundle.bodies.len(), bundle.issuance.len(), generation(&bundle), bundle.instance,
        instance.raw(), quote(&path.to_string_lossy())))
}
fn parent(path: &Path) -> &Path {
    path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."))
}
fn require_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
        Ok(_) => Err("destination already exists".into()),
    }
}
#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> { File::open(path)?.sync_all() }
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> { Ok(()) }

/// Same-directory complete-file/no-replace publication. No delete-before-write.
fn publish_new(destination: &Path, bytes: &[u8]) -> Result<(), String> {
    require_absent(destination)?;
    let mut staged = None;
    for _ in 0..16 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = parent(destination).join(format!(".fg-authority-backup-{}-{sequence}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => { staged = Some((path, file)); break; }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot stage backup: {error}")),
        }
    }
    let (temporary, mut file) = staged.ok_or("no unused backup staging path")?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        return Err(remove_failed_stage(&temporary, format!("backup staging failed: {error}")));
    }
    if let Err(error) = fs::hard_link(&temporary, destination) {
        return Err(remove_failed_stage(&temporary, format!("backup publication failed: {error}")));
    }
    fs::remove_file(&temporary).map_err(|e| format!("backup is visible at {}; staging cleanup failed at {}: {e}",
        destination.display(), temporary.display()))?;
    sync_directory(parent(destination)).map_err(|e| format!("backup is visible; parent sync failed: {e}"))?;
    Ok(())
}
fn remove_failed_stage(path: &Path, original: String) -> String {
    fs::remove_file(path).err().map_or_else(|| original.clone(), |cleanup|
        format!("{original}; staging cleanup also failed at {}: {cleanup}", path.display()))
}

#[cfg(test)]
#[path = "authority_backup/tests.rs"]
mod tests;
