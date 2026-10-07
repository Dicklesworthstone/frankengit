//! Bounded local checkpoints. Atomic replacement changes storage, not delivery
//! identity or lifecycle. A separate never-replaced fence survives every swap.

pub(super) mod migration;

use super::{AsciiSlug, BTreeMap, Entry, File, Journal, MAGIC, MAX_BYTES, MAX_KEYS,
    MAX_RECORD, Path, PathBuf, chained, decimal, hex, parse_record, record_body,
    sha256_digest, unhex, validate_saved, validate_transition};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Decoded {
    pub(super) entries: BTreeMap<AsciiSlug, Entry>,
    pub(super) tail: [u8; 32],
    pub(super) clock_floor: u64,
}

fn checked_line(line: &str, previous: [u8; 32]) -> Result<(&str, [u8; 32]), String> {
    if line.is_empty() || line.len() + 1 > MAX_RECORD {
        return Err("invalid dispatch journal frame size".into());
    }
    let (body, checksum) = line.rsplit_once('\t').ok_or("dispatch journal checksum missing")?;
    let tail = chained(previous, body.as_bytes());
    if unhex(checksum)? != tail { return Err("dispatch journal checksum chain mismatch".into()); }
    Ok((body, tail))
}

/// The same decoder is used after restart and by read-only inspection. Never
/// skip a partial tail or select a prefix when the observed bytes are invalid.
pub(super) fn decode(bytes: &[u8], header: &str, max_attempts: u32) -> Result<Decoded, String> {
    if bytes.len() as u64 > MAX_BYTES || !(2..=16).contains(&max_attempts) {
        return Err("dispatch journal exceeds its profile".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "dispatch journal is not UTF-8")?;
    if !text.starts_with(header) || !text.ends_with('\n') || text.contains('\r') {
        return Err("dispatch journal is incomplete, incompatible, or its scope changed; retain the original files".into());
    }
    let mut decoded = Decoded { entries: BTreeMap::new(), tail: sha256_digest(header.as_bytes()), clock_floor: 0 };
    let mut checkpoint_seen = false;
    for line in text[header.len()..].split_terminator('\n') {
        let (body, tail) = checked_line(line, decoded.tail)?;
        if let Some(row) = body.strip_prefix("snapshot\t") {
            if checkpoint_seen || decoded.entries.len() >= MAX_KEYS {
                return Err("misplaced or oversized dispatch checkpoint".into());
            }
            let (key, entry) = parse_record(row)?;
            validate_saved(key, &entry, max_attempts)?;
            if decoded.entries.last_key_value().is_some_and(|(last, _)| *last >= key) {
                return Err("dispatch checkpoint keys are not strictly ordered".into());
            }
            decoded.clock_floor = decoded.clock_floor.max(entry.observed_at);
            decoded.entries.insert(key, entry);
        } else if let Some(row) = body.strip_prefix("checkpoint\t") {
            let (count, floor) = row.split_once('\t').ok_or("incomplete dispatch checkpoint footer")?;
            if checkpoint_seen || decimal(count)? != decoded.entries.len() as u64
                || decimal(floor)? != decoded.clock_floor
            { return Err("dispatch checkpoint count or clock floor mismatch".into()); }
            checkpoint_seen = true;
        } else if let Some(row) = body.strip_prefix("event\t") {
            if !checkpoint_seen { return Err("dispatch checkpoint footer is missing".into()); }
            let (key, entry) = parse_record(row)?;
            validate_transition(&decoded.entries, decoded.clock_floor, max_attempts, key, &entry)?;
            decoded.clock_floor = entry.observed_at;
            decoded.entries.insert(key, entry);
        } else {
            return Err("unknown required dispatch journal record".into());
        }
        decoded.tail = tail;
    }
    if !checkpoint_seen { return Err("dispatch checkpoint footer is missing".into()); }
    Ok(decoded)
}

fn add(bytes: &mut Vec<u8>, tail: &mut [u8; 32], body: &str) -> Result<(), String> {
    let next = chained(*tail, body.as_bytes());
    let line = format!("{body}\t{}\n", hex(&next));
    if line.len() > MAX_RECORD || !super::fits(bytes.len() as u64, line.len(), MAX_BYTES) {
        return Err("dispatch checkpoint exceeds its byte budget".into());
    }
    bytes.try_reserve(line.len()).map_err(|_| "dispatch checkpoint allocation refused")?;
    bytes.extend_from_slice(line.as_bytes());
    *tail = next;
    Ok(())
}

pub(super) fn encode(header: &str, entries: &BTreeMap<AsciiSlug, Entry>, clock_floor: u64,
    max_attempts: u32) -> Result<(Vec<u8>, [u8; 32]), String>
{
    if entries.len() > MAX_KEYS || !(2..=16).contains(&max_attempts)
        || entries.values().map(|entry| entry.observed_at).max().unwrap_or(0) != clock_floor
    { return Err("dispatch checkpoint has inconsistent retained state".into()); }
    let mut bytes = header.as_bytes().to_vec();
    let mut tail = sha256_digest(&bytes);
    for (key, entry) in entries {
        validate_saved(*key, entry, max_attempts)?;
        add(&mut bytes, &mut tail, &format!("snapshot\t{}", record_body(*key, entry)))?;
    }
    add(&mut bytes, &mut tail, &format!("checkpoint\t{}\t{clock_floor}", entries.len()))?;
    Ok((bytes, tail))
}

pub(super) fn header(scope: [u8; 32], max_attempts: u32) -> String {
    format!("{MAGIC}\t{}\t{max_attempts}\n", hex(&scope))
}
fn fence_header(header: &str) -> String {
    format!("{MAGIC}-fence\t{}\n", hex(&sha256_digest(header.as_bytes())))
}
pub(super) fn fence_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

#[cfg(unix)]
fn private_slot(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && meta.nlink() == 1 && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= MAX_BYTES => Ok(Some(meta)),
        Ok(_) => Err("dispatch files must be private, singly-linked regular files within the byte limit".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect dispatch file: {error}")),
    }
}

#[cfg(unix)]
fn same_file(file: &File, path: &Path, length: u64) -> Result<(), String> {
    let slot = private_slot(path)?.ok_or("owned dispatch file disappeared")?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if slot.dev() != opened.dev() || slot.ino() != opened.ino() || slot.len() != length
        || opened.len() != length || opened.nlink() != 1
    { return Err("dispatch journal or fence changed while owned; no further send is permitted".into()); }
    Ok(())
}

pub(super) fn verify_owned(journal: &Journal) -> Result<(), String> {
    #[cfg(unix)]
    {
        same_file(&journal.file, &journal.path, journal.bytes)?;
        same_file(&journal.fence, &fence_path(&journal.path), fence_header(&journal.header).len() as u64)
    }
    #[cfg(not(unix))]
    { let _ = journal; Err("durable webhook dispatch requires the Unix profile".into()) }
}

fn read_bounded(file: &mut File, maximum: u64) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    Read::by_ref(file).take(maximum + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > maximum { return Err("dispatch file exceeds its byte limit".into()); }
    Ok(bytes)
}

pub(super) fn open(path: &Path, scope: [u8; 32], max_attempts: u32) -> Result<Journal, String> {
    if !(2..=16).contains(&max_attempts) { return Err("dispatch retry limit must be 2..16".into()); }
    #[cfg(not(unix))]
    { let _ = (path, scope); Err("durable webhook dispatch requires the Unix directory-sync profile".into()) }
    #[cfg(unix)]
    {
        let lock_path = fence_path(path);
        let present = private_slot(path)?.is_some();
        let fenced = private_slot(&lock_path)?.is_some();
        if present != fenced {
            return Err("dispatch journal/fence is missing or legacy v1 requires offline migration; retain both original files, never reset attempts".into());
        }
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let directory = File::open(parent).map_err(|e| format!("dispatch directory unavailable: {e}"))?;
        directory.sync_all().map_err(|e| format!("dispatch directory durability unavailable: {e}"))?;
        let header = header(scope, max_attempts);
        let expected_fence = fence_header(&header);
        let mut fence = OpenOptions::new().read(true).write(true).create_new(!fenced).truncate(false)
            .mode(0o600).open(&lock_path).map_err(|e| format!("cannot open dispatch fence: {e}"))?;
        fence.try_lock().map_err(|e| format!("another dispatcher owns this local journal: {e}"))?;
        if !fenced {
            fence.write_all(expected_fence.as_bytes()).and_then(|()| fence.sync_all())
                .and_then(|()| directory.sync_all())
                .map_err(|e| format!("dispatch fence initialization incomplete; retain file: {e}"))?;
        }
        if read_bounded(&mut fence, MAX_RECORD as u64)? != expected_fence.as_bytes() {
            return Err("dispatch fence is incomplete or its scope changed".into());
        }
        same_file(&fence, &lock_path, expected_fence.len() as u64)?;
        let mut file = OpenOptions::new().read(true).write(true).create_new(!present).truncate(false)
            .mode(0o600).open(path).map_err(|e| format!("cannot open dispatch journal: {e}"))?;
        file.try_lock().map_err(|e| format!("dispatch data file is already owned: {e}"))?;
        if !present {
            let (empty, _) = encode(&header, &BTreeMap::new(), 0, max_attempts)?;
            file.write_all(&empty).and_then(|()| file.sync_all()).and_then(|()| directory.sync_all())
                .map_err(|e| format!("dispatch journal initialization incomplete; retain files: {e}"))?;
        }
        let bytes = read_bounded(&mut file, MAX_BYTES)?;
        let decoded = decode(&bytes, &header, max_attempts)?;
        // A complete frame may survive a previous sync error. Confirm the
        // selected file before using any observation to suppress or retry I/O.
        file.sync_all().and_then(|()| fence.sync_all()).and_then(|()| directory.sync_all())
            .map_err(|e| format!("cannot confirm reopened dispatch durability: {e}"))?;
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        let journal = Journal { file, fence, directory, path: path.to_owned(), header,
            entries: decoded.entries, tail: decoded.tail, bytes: bytes.len() as u64,
            clock_floor: decoded.clock_floor, max_attempts, poisoned: false };
        verify_owned(&journal)?;
        Ok(journal)
    }
}

/// Private fault boundaries, shared by the production path and crash tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage { Staged, Renamed, Synced }

#[cfg(unix)]
struct Temporary(PathBuf);
#[cfg(unix)]
impl Drop for Temporary {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}

pub(super) fn replace(journal: &mut Journal,
    barrier: &mut impl FnMut(Stage) -> Result<(), String>) -> Result<(), String>
{
    #[cfg(not(unix))]
    { let _ = (journal, barrier); Err("durable webhook checkpoint replacement requires Unix".into()) }
    #[cfg(unix)]
    {
        if let Err(error) = verify_owned(journal) {
            journal.poisoned = true;
            return Err(error);
        }
        let (bytes, tail) = encode(&journal.header, &journal.entries, journal.clock_floor, journal.max_attempts)?;
        let parent = journal.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let mut selected = None;
        for _ in 0..128 {
            let path = parent.join(format!(".fg-dispatch-checkpoint-{}-{}.tmp", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path) {
                Ok(file) => { selected = Some((file, Temporary(path))); break; }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("cannot stage dispatch checkpoint: {e}")),
            }
        }
        let (mut file, temporary) = selected.ok_or("dispatch checkpoint temporary-name budget exhausted")?;
        file.try_lock().map_err(|e| e.to_string())?;
        file.write_all(&bytes).and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot sync staged dispatch checkpoint: {e}"))?;
        barrier(Stage::Staged)?;
        // No send may follow an unknown replacement outcome on this handle.
        journal.poisoned = true;
        verify_owned(journal)?;
        std::fs::rename(&temporary.0, &journal.path)
            .map_err(|e| format!("dispatch checkpoint replacement failed; reopen before retry: {e}"))?;
        barrier(Stage::Renamed)?;
        journal.directory.sync_all()
            .map_err(|e| format!("dispatch checkpoint visibility/durability unknown; reopen before retry: {e}"))?;
        barrier(Stage::Synced)?;
        journal.file = file;
        journal.bytes = bytes.len() as u64;
        journal.tail = tail;
        verify_owned(journal)?;
        journal.poisoned = false;
        Ok(())
    }
}
