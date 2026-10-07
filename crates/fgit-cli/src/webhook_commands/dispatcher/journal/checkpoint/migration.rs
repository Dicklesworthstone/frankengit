//! Explicit offline v1 -> v2 upgrade. The original checksum-pinned journal is
//! backed up before replacement. Both old data-inode and new sidecar locks are
//! held: no cooperating old or new worker can send during the conversion.
//! This command has no node, registration, signing or network dependency.

use super::*;
use crate::publication_support::quote;

const LEGACY_MAGIC: &str = "fgit-webhook-dispatch-v1";
const USAGE: &str = "usage: fg webhook dispatch-migrate <journal-path> --trusted-local
       fg webhook dispatch-migrate <journal-path> --trusted-local --apply --expected-sha256 <digest>

Stop the dispatcher first. Without --apply, validate and preview without writing.
Apply requires the preview's exact original_sha256. Retain the .v1-backup and
.lock files. Every attempt, payload, outcome, uncertainty bit, delay, evidence
hash and clock floor is preserved. A changed/corrupt source refuses; no tail is
trimmed. Repeating an interrupted upgrade confirms the exact installed v2 state
using its retained v1 backup. No delivery or canonical settlement is performed.
Exit 0: complete preview/upgrade; 2: refusal, incomplete upgrade or lost output.";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    path: PathBuf,
    expected: Option<[u8; 32]>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    if !matches!(args.len(), 2 | 5) || args[0].is_empty() || args[0].len() > 4096
        || args[1] != "--trusted-local"
    {
        return Err(USAGE.into());
    }
    let expected = if args.len() == 5 {
        if args[2] != "--apply" || args[3] != "--expected-sha256" {
            return Err(USAGE.into());
        }
        Some(unhex(&args[4])?)
    } else {
        None
    };
    Ok(Options { path: PathBuf::from(&args[0]), expected })
}

pub(crate) fn run(args: &[String]) -> Result<u8, String> {
    let mut output = std::io::stdout().lock();
    if args == ["--help"] {
        writeln!(output, "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    execute(args, &mut output)
}

fn execute(args: &[String], output: &mut impl Write) -> Result<u8, String> {
    let options = parse(args)?;
    let report = migrate(&options.path, options.expected, &mut |_| Ok(()))?;
    let body = format!(
        "{{\"type\":\"webhook_dispatch_migration\",\"schema_version\":1,\"applied\":{},\"already_migrated\":{},\"original_sha256\":{},\"checkpoint_sha256\":{},\"journal_scope_sha256\":{},\"retained_deliveries\":{},\"attempt_limit\":{},\"clock_floor_millis\":\"{}\",\"original_bytes\":{},\"checkpoint_bytes\":{},\"backup_path\":{},\"transport_attempted\":false,\"canonical_settled\":false}}",
        options.expected.is_some(), report.already_migrated, quote(&hex(&report.original)),
        quote(&hex(&report.checkpoint)), quote(&hex(&report.scope)), report.keys,
        report.max_attempts, report.clock_floor, report.original_bytes, report.checkpoint_bytes,
        quote(&backup_path(&options.path).to_string_lossy()),
    );
    writeln!(output, "{body}").and_then(|()| output.flush()).map_err(|e| {
        format!("migration output incomplete; upgrade may already be complete, retain both files and retry with the original checksum; no delivery attempted: {e}")
    })?;
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
struct Report {
    original: [u8; 32],
    checkpoint: [u8; 32],
    scope: [u8; 32],
    keys: usize,
    max_attempts: u32,
    clock_floor: u64,
    original_bytes: usize,
    checkpoint_bytes: usize,
    already_migrated: bool,
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".v1-backup");
    PathBuf::from(name)
}

/// Replay the complete shipped v1 grammar, not a guessed final-state snapshot.
/// Checksums bind every original record; the shared transition validator proves
/// ordinals, payload identity, delay monotonicity and cumulative uncertainty.
fn legacy(bytes: &[u8]) -> Result<([u8; 32], u32, Decoded), String> {
    if bytes.len() as u64 > MAX_BYTES { return Err("legacy journal exceeds its byte bound".into()); }
    let text = std::str::from_utf8(bytes).map_err(|_| "legacy journal is not UTF-8")?;
    let end = text.find('\n').ok_or("legacy journal header is incomplete")?;
    if end >= MAX_RECORD || !text.ends_with('\n') || text.contains('\r') {
        return Err("legacy journal is incomplete; no tail was trimmed".into());
    }
    let fields: Vec<_> = text[..end].split('\t').collect();
    if fields.len() != 3 || fields[0] != LEGACY_MAGIC {
        return Err("not a supported v1 dispatch journal".into());
    }
    let scope = unhex(fields[1])?;
    let attempts = u32::try_from(decimal(fields[2])?).map_err(|_| "legacy retry limit overflow")?;
    if !(2..=16).contains(&attempts) { return Err("legacy retry limit is outside 2..16".into()); }
    let mut decoded = Decoded { entries: BTreeMap::new(), tail: sha256_digest(&bytes[..=end]), clock_floor: 0 };
    for line in text[end + 1..].split_terminator('\n') {
        let (body, tail) = checked_line(line, decoded.tail)?;
        let (key, entry) = parse_record(body)?;
        validate_transition(&decoded.entries, decoded.clock_floor, attempts, key, &entry)?;
        decoded.clock_floor = entry.observed_at;
        decoded.entries.insert(key, entry);
        decoded.tail = tail;
    }
    Ok((scope, attempts, decoded))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MigrationStage {
    Fenced,
    BackedUp,
    Checkpoint(Stage),
}

#[cfg(unix)]
fn read_existing(path: &Path) -> Result<Vec<u8>, String> {
    let meta = private_slot(path)?.ok_or("required retained migration file is missing")?;
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    same_file(&file, path, meta.len())?;
    let bytes = read_bounded(&mut file, MAX_BYTES)?;
    same_file(&file, path, bytes.len() as u64)?;
    Ok(bytes)
}

#[cfg(unix)]
fn migration_fence(path: &Path, header: &str, allow_initialization: bool, directory: &File) -> Result<File, String> {
    let lock_path = fence_path(path);
    let present = private_slot(&lock_path)?.is_some();
    if !present && !allow_initialization { return Err("migrated journal lost its stable fence; retain all evidence".into()); }
    let mut fence = OpenOptions::new().read(true).write(true).create_new(!present).truncate(false)
        .mode(0o600).open(&lock_path).map_err(|e| format!("cannot open migration fence: {e}"))?;
    fence.try_lock().map_err(|e| format!("another owner holds the migration fence: {e}"))?;
    let actual = read_bounded(&mut fence, MAX_RECORD as u64)?;
    same_file(&fence, &lock_path, actual.len() as u64)?;
    let expected = fence_header(header);
    if actual != expected.as_bytes() {
        // Recover only an exact interrupted initialization prefix while the
        // complete checksum-pinned v1 source is still exclusively locked.
        // Never manufacture a missing fence for an already-installed v2 file.
        if !allow_initialization || !expected.as_bytes().starts_with(&actual) {
            return Err("migration fence is corrupt or belongs to another scope".into());
        }
        fence.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        fence.write_all(&expected.as_bytes()[actual.len()..]).map_err(|e| e.to_string())?;
    }
    fence.sync_all().and_then(|()| directory.sync_all()).map_err(|e| format!("migration fence durability unknown: {e}"))?;
    same_file(&fence, &lock_path, expected.len() as u64)?;
    Ok(fence)
}

#[cfg(unix)]
fn save_backup(path: &Path, bytes: &[u8], directory: &File) -> Result<(), String> {
    let backup = backup_path(path);
    if private_slot(&backup)?.is_some() {
        if read_existing(&backup)? != bytes { return Err("retained v1 backup differs; it was not overwritten".into()); }
        File::open(&backup).and_then(|file| file.sync_all()).and_then(|()| directory.sync_all())
            .map_err(|e| format!("cannot confirm retained backup durability: {e}"))?;
        return Ok(());
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    for _ in 0..128 {
        let temporary = parent.join(format!(".fg-dispatch-migration-{}-{}.tmp", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut file = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot stage v1 backup: {e}")),
        };
        let temporary = Temporary(temporary);
        file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| format!("cannot sync v1 backup: {e}"))?;
        // The stable fence excludes cooperating migrations. The parent must be
        // operator-owned, as for the journal's existing replacement protocol.
        if private_slot(&backup)?.is_some() { return Err("v1 backup appeared during migration; no overwrite".into()); }
        std::fs::rename(&temporary.0, &backup).and_then(|()| directory.sync_all())
            .map_err(|e| format!("backup publication outcome unknown; retain files and retry the original checksum: {e}"))?;
        if read_existing(&backup)? != bytes { return Err("published v1 backup verification failed".into()); }
        return Ok(());
    }
    Err("migration temporary-name budget exhausted".into())
}

fn migrate(path: &Path, expected: Option<[u8; 32]>, barrier: &mut impl FnMut(MigrationStage) -> Result<(), String>) -> Result<Report, String> {
    #[cfg(not(unix))]
    { let _ = (path, expected, barrier); Err("offline dispatch migration requires Unix file locks and directory sync".into()) }
    #[cfg(unix)]
    {
        let metadata = private_slot(path)?.ok_or("original journal is missing; migration never recreates it")?;
        let mut file = OpenOptions::new().read(true).write(true).open(path).map_err(|e| e.to_string())?;
        // Also excludes old v1 workers, which know nothing about a sidecar.
        // All locks are try-locks; opposing acquisition orders cannot deadlock.
        file.try_lock().map_err(|e| format!("stop the dispatcher before migration: {e}"))?;
        same_file(&file, path, metadata.len())?;
        let selected = read_bounded(&mut file, MAX_BYTES)?;
        same_file(&file, path, selected.len() as u64)?;
        let is_legacy = selected.starts_with(format!("{LEGACY_MAGIC}\t").as_bytes());
        let original = if is_legacy { selected.clone() } else { read_existing(&backup_path(path))? };
        let original_hash = sha256_digest(&original);
        if expected.is_some_and(|pin| pin != original_hash) {
            return Err("original journal checksum changed; no migration was applied".into());
        }
        let (scope, max_attempts, decoded) = legacy(&original)?;
        let header = header(scope, max_attempts);
        let (checkpoint, _) = encode(&header, &decoded.entries, decoded.clock_floor, max_attempts)?;
        let verified = decode(&checkpoint, &header, max_attempts)?;
        if verified.entries != decoded.entries || verified.clock_floor != decoded.clock_floor {
            return Err("migration failed exact retained-state equivalence".into());
        }
        if !is_legacy && selected != checkpoint {
            return Err("selected v2 journal differs from the exact migration checkpoint; no backup fallback or rollback".into());
        }
        if private_slot(&backup_path(path))?.is_some() && read_existing(&backup_path(path))? != original {
            return Err("retained v1 backup differs; no file was overwritten".into());
        }
        let lock_path = fence_path(path);
        if private_slot(&lock_path)?.is_some() {
            let fence_bytes = read_existing(&lock_path)?;
            let fence_header = fence_header(&header);
            if fence_bytes != fence_header.as_bytes()
                && (!is_legacy || !fence_header.as_bytes().starts_with(&fence_bytes))
            { return Err("migration fence is incompatible; retain both files".into()); }
        } else if !is_legacy {
            return Err("migrated journal lost its stable fence".into());
        }
        let report = Report { original: original_hash, checkpoint: sha256_digest(&checkpoint), scope,
            keys: decoded.entries.len(), max_attempts, clock_floor: decoded.clock_floor,
            original_bytes: original.len(), checkpoint_bytes: checkpoint.len(), already_migrated: !is_legacy };
        if expected.is_none() { return Ok(report); }
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let directory = File::open(parent).map_err(|e| e.to_string())?;
        directory.sync_all().map_err(|e| format!("migration directory durability unavailable: {e}"))?;
        let fence = migration_fence(path, &header, is_legacy, &directory)?;
        barrier(MigrationStage::Fenced)?;
        save_backup(path, &original, &directory)?;
        barrier(MigrationStage::BackedUp)?;
        let mut journal = Journal { file, fence, directory, path: path.to_owned(), header,
            entries: decoded.entries, tail: if is_legacy { decoded.tail } else { verified.tail }, bytes: selected.len() as u64,
            clock_floor: decoded.clock_floor, max_attempts, poisoned: false };
        verify_owned(&journal)?;
        if is_legacy {
            // Use the very same body-first, root-last checkpoint replacement.
            // Any error after rename poisons this owner and leaves both files
            // available for exact-checksum recovery, never for automatic sends.
            journal.compact_with(&mut |stage| barrier(MigrationStage::Checkpoint(stage)))?;
        } else {
            journal.file.sync_all().and_then(|()| journal.fence.sync_all())
                .and_then(|()| journal.directory.sync_all()).map_err(|e| format!("migration durability remains unknown: {e}"))?;
        }
        verify_owned(&journal)?;
        if read_bounded(&mut journal.file, MAX_BYTES)? != checkpoint {
            return Err("installed migration checkpoint changed before confirmation".into());
        }
        Ok(report)
    }
}

#[cfg(all(test, unix))]
mod tests;
