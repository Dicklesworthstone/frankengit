//! Local webhook configuration and diagnostic storage, not repository authority.
//!
//! Mutations lock a stable sidecar, reload the latest complete file, stage a
//! private replacement, sync it, rename it, and sync the directory before
//! acknowledging success. Independent handles cannot overwrite unseen updates.
//! Lock contention refuses without waiting. A post-rename sync failure is an
//! explicitly unknown durability outcome; reopening observes the visible file.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fgit_forge::webhook::{DeadLetterEntry, WebhookId, WebhookRegistration, WebhookSecret};
use fgit_types::AsciiSlug;

use super::persistence::{
    MAX_RECORD_BYTES, parse_dead_letter_line, parse_registration_line, serialize_dead_letter,
    serialize_registration,
};

const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
#[cfg(unix)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn read_records<T, K: Ord>(
    path: &Path,
    parse: fn(&str) -> Option<T>,
    key: fn(&T) -> K,
) -> Result<Vec<T>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read webhook store: {error}")),
    };
    if !file.metadata().map_err(|error| error.to_string())?.is_file() {
        return Err("webhook store is not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take((MAX_STORE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read webhook store: {error}"))?;
    if bytes.len() > MAX_STORE_BYTES {
        return Err("webhook store exceeds the 16 MiB limit".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "webhook store is not UTF-8")?;
    let mut records = Vec::new();
    let mut keys = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_matches([' ', '\t', '\r']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if records.len() >= MAX_RECORDS || line.len() > MAX_RECORD_BYTES {
            return Err(format!("webhook store limit at line {}", index + 1));
        }
        let record = parse(line)
            .ok_or_else(|| format!("invalid webhook record at line {}", index + 1))?;
        if !keys.insert(key(&record)) {
            return Err(format!("duplicate webhook record at line {}", index + 1));
        }
        records.push(record);
    }
    Ok(records)
}

fn encode_records<T: PartialEq>(
    records: &[T],
    encode: fn(&T) -> String,
    parse: fn(&str) -> Option<T>,
) -> Result<Vec<u8>, String> {
    if records.len() > MAX_RECORDS {
        return Err("webhook store exceeds its record limit".into());
    }
    let mut bytes = Vec::new();
    for record in records {
        let line = encode(record);
        if line.len() > MAX_RECORD_BYTES || parse(&line).as_ref() != Some(record) {
            return Err("webhook record cannot be restored losslessly within its limits".into());
        }
        if bytes.len().saturating_add(line.len()).saturating_add(1) > MAX_STORE_BYTES {
            return Err("webhook store exceeds the 16 MiB limit".into());
        }
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn lock_writer(path: &Path) -> Result<File, String> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(PathBuf::from(name))
        .map_err(|error| format!("cannot open webhook writer lock: {error}"))?;
    file.try_lock().map_err(|error| format!("webhook writer lock unavailable: {error}"))?;
    // Never unlink this inode: another process may already be waiting on it.
    Ok(file)
}

#[cfg(unix)]
struct StagedFile(PathBuf);

#[cfg(unix)]
impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let directory = File::open(parent)
        .map_err(|error| format!("cannot open webhook store directory: {error}"))?;
    // Refuse unsupported directory durability before replacing any visible data.
    directory.sync_all().map_err(|error| format!("webhook directory sync unavailable: {error}"))?;
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".fg-webhook-{}-{sequence}.tmp", std::process::id()));
        let mut file = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("cannot stage webhook store: {error}")),
        };
        let staged = StagedFile(temporary);
        file.write_all(bytes).and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot sync staged webhook store: {error}"))?;
        drop(file);
        std::fs::rename(&staged.0, path)
            .map_err(|error| format!("cannot publish webhook store: {error}"))?;
        directory.sync_all().map_err(|error| {
            format!("OutcomeUnknown: webhook store is visible but directory sync failed: {error}; reopen before retry")
        })?;
        return Ok(());
    }
    Err("webhook temporary-file collision budget exhausted".into())
}

#[cfg(not(unix))]
fn replace_file(_path: &Path, _bytes: &[u8]) -> Result<(), String> {
    Err("durable webhook replacement is unsupported on this platform".into())
}

fn ensure_directory(root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    let missing = {
        let mut missing = Vec::new();
        let mut current = root;
        loop {
            match std::fs::metadata(current) {
                Ok(metadata) if metadata.is_dir() => break,
                Ok(_) => return Err("webhook store parent is not a directory".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if missing.len() >= 128 {
                        return Err("webhook directory depth budget exhausted".into());
                    }
                    missing.push(current.to_path_buf());
                    current = current.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
                }
                Err(error) => return Err(format!("cannot inspect webhook directory: {error}")),
            }
        }
        missing
    };
    std::fs::create_dir_all(root).map_err(|error| format!("cannot create webhook directory: {error}"))?;
    #[cfg(unix)]
    for directory in missing.iter().rev() {
        let parent = directory.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
        File::open(parent).and_then(|file| file.sync_all())
            .map_err(|error| format!("cannot sync new webhook directory entry: {error}"))?;
    }
    Ok(())
}

fn load_dead_letters(path: &Path) -> Result<Vec<DeadLetterEntry>, String> {
    read_records(path, parse_dead_letter_line, |entry| entry.delivery_id)
}

fn load_registrations(path: &Path) -> Result<Vec<WebhookRegistration>, String> {
    read_records(path, parse_registration_line, |entry| entry.id)
}

#[derive(Debug, Default)]
struct DeadLetterState {
    entries: Vec<DeadLetterEntry>,
    last_error: Option<String>,
    // A legacy infallible open must not turn corruption into an empty writable store.
    failed_open: bool,
}

/// In-memory or checked file-backed diagnostic dead letters. Canonical outbox
/// state, not this queue, remains responsible for unresolved delivery effects.
#[derive(Clone, Debug, Default)]
pub struct DeadLetterQueue {
    state: Arc<Mutex<DeadLetterState>>,
    persist_path: Option<PathBuf>,
}

impl DeadLetterQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_with_persist_path(path: PathBuf) -> Result<Self, String> {
        let entries = load_dead_letters(&path)?;
        Ok(Self {
            state: Arc::new(Mutex::new(DeadLetterState { entries, ..DeadLetterState::default() })),
            persist_path: Some(path),
        })
    }

    /// Compatibility surface. Check `persistence_error`, or use the checked
    /// constructor: an unreadable file produces a permanently non-writable handle.
    pub fn with_persist_path(path: PathBuf) -> Self {
        match Self::try_with_persist_path(path.clone()) {
            Ok(queue) => queue,
            Err(error) => Self {
                state: Arc::new(Mutex::new(DeadLetterState {
                    entries: Vec::new(), last_error: Some(error), failed_open: true,
                })),
                persist_path: Some(path),
            },
        }
    }

    pub fn persistence_error(&self) -> Option<String> {
        match self.state.lock() {
            Ok(state) => state.last_error.clone(),
            Err(_) => Some("webhook dead-letter state is poisoned".into()),
        }
    }

    fn mutate<R>(
        &self,
        change: impl FnOnce(&mut Vec<DeadLetterEntry>) -> Result<R, String>,
    ) -> Result<R, String> {
        let mut state = self.state.lock().map_err(|_| "webhook dead-letter state is poisoned")?;
        if state.failed_open {
            return Err(state.last_error.clone().unwrap_or_else(|| "webhook store open failed".into()));
        }
        let result: Result<R, String> = (|| {
            let _writer = self.persist_path.as_ref().map(|path| lock_writer(path)).transpose()?;
            let mut next = match &self.persist_path {
                Some(path) => load_dead_letters(path)?,
                None => state.entries.clone(),
            };
            let value = change(&mut next)?;
            let bytes = encode_records(&next, serialize_dead_letter, parse_dead_letter_line)?;
            if let Some(path) = &self.persist_path {
                replace_file(path, &bytes)?;
            }
            state.entries = next;
            Ok(value)
        })();
        state.last_error = result.as_ref().err().cloned();
        result
    }

    pub fn try_push(&self, entry: DeadLetterEntry) -> Result<(), String> {
        self.mutate(|entries| {
            // A delivery key cannot silently acquire different replay parameters.
            if let Some(previous) = entries.iter().find(|previous| previous.delivery_id == entry.delivery_id) {
                if previous.webhook_id != entry.webhook_id || previous.payload_root != entry.payload_root
                    || previous.target_url != entry.target_url || previous.event_name != entry.event_name {
                    return Err("dead-letter delivery key reused with different payload or destination".into());
                }
            }
            entries.retain(|previous| previous.delivery_id != entry.delivery_id);
            entries.push(entry);
            Ok(())
        })
    }

    /// Legacy callers can inspect `persistence_error`; delivery uses `try_push`.
    pub fn push(&self, entry: DeadLetterEntry) {
        let _ = self.try_push(entry);
    }

    #[must_use]
    pub fn list(&self) -> Vec<DeadLetterEntry> {
        self.state.lock().unwrap().entries.clone()
    }

    #[must_use]
    pub fn get(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        self.state.lock().unwrap().entries.iter().find(|entry| entry.delivery_id == delivery_id).cloned()
    }

    pub fn try_remove(&self, delivery_id: AsciiSlug) -> Result<Option<DeadLetterEntry>, String> {
        self.mutate(|entries| {
            Ok(entries.iter().position(|entry| entry.delivery_id == delivery_id).map(|position| entries.remove(position)))
        })
    }

    pub fn remove(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        self.try_remove(delivery_id).ok().flatten()
    }
}

/// Local registration snapshots with serialized, reload-before-write mutations.
/// Reopen to refresh a read snapshot held by an independently opened handle.
#[derive(Clone, Debug)]
pub struct WebhookStore {
    root_dir: PathBuf,
    dead_letters: DeadLetterQueue,
    registrations: Arc<Mutex<Vec<WebhookRegistration>>>,
}

impl WebhookStore {
    pub fn open(root_dir: PathBuf) -> Result<Self, String> {
        ensure_directory(&root_dir)?;
        let dead_letters = DeadLetterQueue::try_with_persist_path(root_dir.join("dead_letters.jsonl"))?;
        let registrations = load_registrations(&root_dir.join("registrations.json"))?;
        Ok(Self { root_dir, dead_letters, registrations: Arc::new(Mutex::new(registrations)) })
    }

    fn mutate<R>(
        &self,
        change: impl FnOnce(&mut Vec<WebhookRegistration>) -> Result<R, String>,
    ) -> Result<R, String> {
        let mut current = self.registrations.lock().map_err(|_| "webhook registration state is poisoned")?;
        let path = self.root_dir.join("registrations.json");
        let _writer = lock_writer(&path)?;
        let mut next = load_registrations(&path)?;
        let value = change(&mut next)?;
        let bytes = encode_records(&next, serialize_registration, parse_registration_line)?;
        replace_file(&path, &bytes)?;
        *current = next;
        Ok(value)
    }

    pub fn register(&self, registration: WebhookRegistration) -> Result<(), String> {
        self.mutate(|entries| {
            entries.retain(|entry| entry.id != registration.id);
            entries.push(registration);
            Ok(())
        })
    }

    #[must_use]
    pub fn list(&self) -> Vec<WebhookRegistration> {
        self.registrations.lock().unwrap().clone()
    }

    #[must_use]
    pub fn get(&self, id: WebhookId) -> Option<WebhookRegistration> {
        self.registrations.lock().unwrap().iter().find(|entry| entry.id == id).cloned()
    }

    pub fn rotate_secret(
        &self,
        id: WebhookId,
        new_secret: WebhookSecret,
        window_duration_secs: u64,
        now_unix_secs: u64,
    ) -> Result<WebhookRegistration, String> {
        self.mutate(|entries| {
            let entry = entries.iter_mut().find(|entry| entry.id == id)
                .ok_or_else(|| format!("webhook id {} not found", id.0))?;
            entry.secrets.rotate(new_secret, window_duration_secs, now_unix_secs);
            Ok(entry.clone())
        })
    }

    #[must_use]
    pub fn dead_letters(&self) -> DeadLetterQueue {
        self.dead_letters.clone()
    }

    #[must_use]
    pub fn list_dead_letters(&self) -> Vec<DeadLetterEntry> {
        self.dead_letters.list()
    }

    #[must_use]
    pub fn get_dead_letter(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        self.dead_letters.get(delivery_id)
    }

    pub fn try_replay_dead_letter(&self, delivery_id: AsciiSlug) -> Result<Option<DeadLetterEntry>, String> {
        self.dead_letters.try_remove(delivery_id)
    }

    pub fn replay_dead_letter(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        self.dead_letters.remove(delivery_id)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;
    use fgit_forge::webhook::{SsrfPolicy, WebhookEventFilter, WebhookRetrySchedule, WebhookSecretRotation};
    use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("fg-webhook-durable-{}-{}", std::process::id(), TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    fn registration(id: u64) -> WebhookRegistration {
        WebhookRegistration {
            id: WebhookId(id), url: SsrfPolicy::STRICT.validate_url("http://example.com/hook").unwrap(),
            secrets: WebhookSecretRotation::new(WebhookSecret::new(vec![1; 32]).unwrap()),
            filter: WebhookEventFilter::Selected(vec!["issue".into()]), active: true,
            retry_schedule: WebhookRetrySchedule::default(),
        }
    }
    fn letter() -> DeadLetterEntry {
        DeadLetterEntry {
            delivery_id: AsciiSlug::from_static("durable-delivery"), webhook_id: WebhookId(1),
            target_url: "http://example.com/hook".into(),
            payload_root: Digest::new(DigestAlgorithmId::try_new(2).unwrap(), DigestBytes::try_new(&[0x17; 32]).unwrap()),
            event_name: "issue".into(), attempts: 5, terminal_reason: "unavailable".into(), failed_at_unix_secs: 7,
        }
    }

    #[test]
    fn reopen_preserves_registration_rotation_and_dead_letter_replay() {
        let dir = Directory::new(); let store = WebhookStore::open(dir.0.clone()).unwrap();
        store.register(registration(1)).unwrap();
        let updated = store.rotate_secret(WebhookId(1), WebhookSecret::new(vec![2; 32]).unwrap(), 30, 100).unwrap();
        store.dead_letters().try_push(letter()).unwrap();
        let reopened = WebhookStore::open(dir.0.clone()).unwrap();
        assert_eq!(reopened.get(WebhookId(1)), Some(updated));
        assert_eq!(reopened.try_replay_dead_letter(letter().delivery_id).unwrap(), Some(letter()));
        assert!(WebhookStore::open(dir.0.clone()).unwrap().list_dead_letters().is_empty());
    }

    #[test]
    fn independent_stale_handles_preserve_each_others_registrations() {
        let dir = Directory::new();
        let first = WebhookStore::open(dir.0.clone()).unwrap();
        let second = WebhookStore::open(dir.0.clone()).unwrap();
        first.register(registration(1)).unwrap(); second.register(registration(2)).unwrap();
        assert_eq!(WebhookStore::open(dir.0.clone()).unwrap().list().len(), 2);
    }

    #[test]
    fn independent_dead_letter_handles_do_not_lose_unseen_entries() {
        let dir = Directory::new(); let path = dir.0.join("dead_letters.jsonl");
        let first = DeadLetterQueue::try_with_persist_path(path.clone()).unwrap();
        let second = DeadLetterQueue::try_with_persist_path(path.clone()).unwrap();
        first.try_push(letter()).unwrap();
        let mut other = letter(); other.delivery_id = AsciiSlug::from_static("another-delivery");
        second.try_push(other).unwrap();
        assert_eq!(DeadLetterQueue::try_with_persist_path(path).unwrap().list().len(), 2);
    }

    #[test]
    fn corrupt_and_duplicate_records_refuse_without_rewriting_file() {
        for filename in ["registrations.json", "dead_letters.jsonl"] {
            let dir = Directory::new(); let path = dir.0.join(filename);
            let record = if filename == "registrations.json" { serialize_registration(&registration(1)) } else { serialize_dead_letter(&letter()) };
            for bytes in [format!("{record}\ntruncated{{\n"), format!("{record}\n{record}\n")] {
                std::fs::write(&path, &bytes).unwrap();
                assert!(WebhookStore::open(dir.0.clone()).is_err());
                assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn failed_legacy_open_cannot_replace_corruption_with_empty_state() {
        let dir = Directory::new(); let path = dir.0.join("bad.jsonl");
        std::fs::write(&path, "broken").unwrap();
        let queue = DeadLetterQueue::with_persist_path(path.clone());
        assert!(queue.persistence_error().is_some());
        assert!(queue.try_push(letter()).is_err());
        queue.push(letter());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "broken");
    }

    #[test]
    fn write_refusal_does_not_publish_registration_to_memory() {
        let dir = Directory::new(); let store = WebhookStore::open(dir.0.clone()).unwrap();
        let path = dir.0.join("registrations.json"); std::fs::create_dir(&path).unwrap();
        assert!(store.register(registration(1)).is_err());
        assert!(store.list().is_empty()); assert!(path.is_dir());
    }

    #[test]
    fn failed_replay_retains_dead_letter_and_reports_error() {
        let dir = Directory::new(); let path = dir.0.join("letters.jsonl");
        let queue = DeadLetterQueue::try_with_persist_path(path.clone()).unwrap();
        queue.try_push(letter()).unwrap();
        let lock = lock_writer(&path).unwrap();
        assert!(queue.try_remove(letter().delivery_id).is_err());
        assert_eq!(queue.get(letter().delivery_id), Some(letter()));
        assert!(queue.persistence_error().is_some());
        drop(lock);
        assert_eq!(queue.try_remove(letter().delivery_id).unwrap(), Some(letter()));
        assert!(queue.persistence_error().is_none());
    }

    #[test]
    fn reused_delivery_key_cannot_change_payload_identity() {
        let queue = DeadLetterQueue::new(); queue.try_push(letter()).unwrap();
        let mut replacement = letter(); replacement.target_url.push_str("/different");
        assert!(queue.try_push(replacement).is_err());
        assert_eq!(queue.get(letter().delivery_id), Some(letter()));
    }

    #[test]
    fn writer_contention_refuses_then_recovers_without_stale_lock_file() {
        let dir = Directory::new(); let store = WebhookStore::open(dir.0.clone()).unwrap();
        let lock = lock_writer(&dir.0.join("registrations.json")).unwrap();
        assert!(store.register(registration(1)).is_err());
        assert!(store.list().is_empty()); drop(lock);
        store.register(registration(1)).unwrap();
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn unrepresentable_duration_refuses_without_losing_previous_configuration() {
        let dir = Directory::new(); let store = WebhookStore::open(dir.0.clone()).unwrap();
        store.register(registration(1)).unwrap();
        let before = std::fs::read(dir.0.join("registrations.json")).unwrap();
        let mut invalid = registration(1); invalid.retry_schedule.initial_delay = Duration::from_nanos(1);
        assert!(store.register(invalid).is_err());
        assert_eq!(std::fs::read(dir.0.join("registrations.json")).unwrap(), before);
        assert_eq!(store.get(WebhookId(1)), Some(registration(1)));
    }

    #[test]
    fn abandoned_stage_is_not_selected_and_secrets_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Directory::new(); let store = WebhookStore::open(dir.0.clone()).unwrap();
        store.register(registration(1)).unwrap();
        std::fs::write(dir.0.join(".fg-webhook-abandoned.tmp"), serialize_registration(&registration(2))).unwrap();
        let reopened = WebhookStore::open(dir.0.clone()).unwrap();
        assert_eq!(reopened.list(), vec![registration(1)]);
        let mode = std::fs::metadata(dir.0.join("registrations.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn oversized_store_and_invalid_utf8_are_not_empty_configuration() {
        let dir = Directory::new(); let path = dir.0.join("registrations.json");
        let file = File::create(&path).unwrap(); file.set_len((MAX_STORE_BYTES + 1) as u64).unwrap(); drop(file);
        assert!(WebhookStore::open(dir.0.clone()).is_err());
        std::fs::write(&path, [0xff]).unwrap();
        assert!(WebhookStore::open(dir.0.clone()).is_err());
    }
}
