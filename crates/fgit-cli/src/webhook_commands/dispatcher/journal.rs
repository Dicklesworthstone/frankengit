//! A local transport-attempt journal, NOT a canonical outbox or delivery proof.
//! One stable, exclusively locked inode fences cooperating local dispatchers.
//! Every reservation is synced before HTTP; a torn tail refuses, never rewinds.
//! Operator-owned directories and retained journal files are trust assumptions.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use fgit_crypto::sha256_digest;
use fgit_types::AsciiSlug;

const MAGIC: &str = "fgit-webhook-dispatch-v1";
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORD: usize = 1024;
const MAX_KEYS: usize = 16_384;

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

fn unhex(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid dispatch journal digest".into());
    }
    let mut bytes = [0; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}

fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("invalid dispatch journal integer".into());
    }
    text.parse().map_err(|_| "dispatch journal integer overflow".into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    InFlight,
    Accepted,
    Rejected,
    Retryable,
    Unknown,
}
impl State {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::InFlight => "in-flight",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Retryable => "retryable",
            Self::Unknown => "unknown",
        }
    }
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "in-flight" => Ok(Self::InFlight),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "retryable" => Ok(Self::Retryable),
            "unknown" => Ok(Self::Unknown),
            _ => Err("invalid dispatch journal state".into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    payload: [u8; 32],
    attempt: u32,
    observed_at: u64,
    next_at: u64,
    state: State,
    uncertain: bool,
    evidence: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    Due { attempt: u32, outcome_unknown: bool },
    Sleeping { until: u64, outcome_unknown: bool },
    Settled { state: State, outcome_unknown: bool },
    Exhausted { outcome_unknown: bool },
}

impl Plan {
    pub(super) const fn outcome_unknown(self) -> bool {
        match self {
            Self::Due { outcome_unknown, .. } | Self::Sleeping { outcome_unknown, .. }
            | Self::Settled { outcome_unknown, .. } | Self::Exhausted { outcome_unknown } => outcome_unknown,
        }
    }
}

/// The file and its advisory lock live exactly as long as the dispatcher.
/// Never unlink/replace it while any dispatcher may hold it. Lost journals may
/// cause duplicates; the checksum chain is not protection against operator rollback.
pub(super) struct Journal {
    file: File,
    entries: BTreeMap<AsciiSlug, Entry>,
    tail: [u8; 32],
    bytes: u64,
    clock_floor: u64,
    max_attempts: u32,
    poisoned: bool,
}

impl Journal {
    pub(super) fn open(path: &Path, scope: [u8; 32], max_attempts: u32) -> Result<Self, String> {
        if !(2..=16).contains(&max_attempts) {
            return Err("dispatch retry limit must be 2..16".into());
        }
        #[cfg(not(unix))]
        {
            let _ = (path, scope);
            Err("durable webhook dispatch requires the Unix directory-sync profile".into())
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let present = match std::fs::symlink_metadata(path) {
                Ok(meta) if meta.is_file() => true,
                Ok(_) => return Err("dispatch journal must be a regular file, not a link or special file".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(e) => return Err(format!("cannot inspect dispatch journal: {e}")),
            };
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let directory = File::open(parent).map_err(|e| format!("dispatch directory unavailable: {e}"))?;
            directory.sync_all().map_err(|e| format!("dispatch directory durability unavailable: {e}"))?;
            let mut file = OpenOptions::new().read(true).write(true).create_new(!present)
                .truncate(false).mode(0o600).open(path)
                .map_err(|e| format!("cannot open dispatch journal: {e}"))?;
            file.try_lock().map_err(|e| format!("another dispatcher owns this local journal: {e}"))?;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if !metadata.is_file() || metadata.len() > MAX_BYTES || metadata.permissions().mode() & 0o077 != 0 {
                return Err("dispatch journal must be private, regular and at most 16 MiB".into());
            }
            let header = format!("{MAGIC}\t{}\t{max_attempts}\n", hex(&scope));
            if !present {
                file.write_all(header.as_bytes()).and_then(|()| file.sync_all())
                    .and_then(|()| directory.sync_all())
                    .map_err(|e| format!("dispatch journal initialization incomplete; retain file and inspect before retry: {e}"))?;
            }
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err("dispatch journal exceeds 16 MiB".into());
            }
            let text = std::str::from_utf8(&bytes).map_err(|_| "dispatch journal is not UTF-8")?;
            if !text.starts_with(&header) || !text.ends_with('\n') || text.contains('\r') {
                return Err("dispatch journal is incomplete or its repository, endpoint or retry policy changed".into());
            }
            let mut journal = Self {
                file, entries: BTreeMap::new(), tail: sha256_digest(header.as_bytes()),
                bytes: bytes.len() as u64, clock_floor: 0, max_attempts, poisoned: false,
            };
            for line in text[header.len()..].split_terminator('\n') {
                journal.replay(line)?;
            }
            // A complete frame may have survived a writer's reported sync error.
            // Re-sync observed bytes before using them to suppress or retry I/O.
            journal.file.sync_all().and_then(|()| directory.sync_all())
                .map_err(|e| format!("cannot confirm reopened dispatch journal durability: {e}"))?;
            journal.file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
            Ok(journal)
        }
    }

    pub(super) fn plan(&self, key: AsciiSlug, payload: [u8; 32], now: u64) -> Result<Plan, String> {
        self.live(now)?;
        let Some(entry) = self.entries.get(&key) else {
            return Ok(Plan::Due { attempt: 1, outcome_unknown: false });
        };
        if payload != entry.payload {
            return Err("dispatch delivery key was reused with a different payload commitment".into());
        }
        let unknown = entry.uncertain || entry.state == State::InFlight;
        if matches!(entry.state, State::Accepted | State::Rejected) {
            return Ok(Plan::Settled { state: entry.state, outcome_unknown: unknown && entry.state != State::Accepted });
        }
        if entry.attempt >= self.max_attempts {
            return Ok(Plan::Exhausted { outcome_unknown: unknown });
        }
        if now < entry.next_at {
            return Ok(Plan::Sleeping { until: entry.next_at, outcome_unknown: unknown });
        }
        Ok(Plan::Due { attempt: entry.attempt + 1, outcome_unknown: unknown })
    }

    pub(super) fn due_at(&self, key: AsciiSlug) -> u64 {
        self.entries.get(&key).map_or(0, |entry| entry.next_at)
    }

    /// Returns only after the reservation is synced. Failed sync poisons this
    /// owner; it may not dispatch or reinterpret an uncertain append as absent.
    pub(super) fn reserve(&mut self, key: AsciiSlug, payload: [u8; 32], now: u64, retry_at: u64) -> Result<u32, String> {
        let Plan::Due { attempt, outcome_unknown } = self.plan(key, payload, now)? else {
            return Err("dispatch attempt is settled, exhausted or not yet due".into());
        };
        // Guarantee room for a bounded observation before consuming the attempt.
        self.capacity(2 * MAX_RECORD)?;
        let entry = Entry { payload, attempt, observed_at: now, next_at: retry_at,
            state: State::InFlight, uncertain: outcome_unknown, evidence: [0; 32] };
        self.append(key, entry)?;
        Ok(attempt)
    }

    pub(super) fn observe(&mut self, key: AsciiSlug, state: State, now: u64, retry_at: u64, evidence: &[u8]) -> Result<(), String> {
        self.live(now)?;
        if state == State::InFlight { return Err("observation cannot reserve another dispatch".into()); }
        let previous = *self.entries.get(&key).ok_or("dispatch has no durable reservation")?;
        let entry = Entry {
            state, observed_at: now, next_at: retry_at,
            uncertain: previous.uncertain || state == State::Unknown,
            evidence: sha256_digest(evidence), ..previous
        };
        self.append(key, entry)
    }

    fn live(&self, now: u64) -> Result<(), String> {
        if self.poisoned { return Err("dispatch journal durability unknown; this owner cannot send again".into()); }
        if now < self.clock_floor { return Err("dispatch clock moved backwards; retries remain fenced".into()); }
        Ok(())
    }
    fn capacity(&self, additional: usize) -> Result<(), String> {
        if self.bytes.checked_add(additional as u64).is_none_or(|size| size > MAX_BYTES) {
            Err("dispatch journal byte budget exhausted; no further reservation".into())
        } else { Ok(()) }
    }
    fn validate(&self, key: AsciiSlug, next: &Entry) -> Result<(), String> {
        self.live(next.observed_at)?;
        if key.as_str().contains(['\t', '\n', '\r']) || key.len() > 256
            || next.attempt == 0 || next.attempt > self.max_attempts || next.next_at < next.observed_at
        { return Err("invalid dispatch journal record".into()); }
        let valid = match self.entries.get(&key) {
            None => self.entries.len() < MAX_KEYS && next.attempt == 1
                && next.state == State::InFlight && !next.uncertain,
            Some(old) if old.payload != next.payload => false,
            Some(old) if matches!(old.state, State::Accepted | State::Rejected) => false,
            Some(old) if next.state == State::InFlight => {
                next.attempt == old.attempt + 1 && next.observed_at >= old.next_at
                    && next.uncertain == (old.uncertain || matches!(old.state, State::InFlight | State::Unknown))
            }
            Some(old) => old.state == State::InFlight && next.attempt == old.attempt
                && next.next_at >= old.next_at
                && next.uncertain == (old.uncertain || next.state == State::Unknown),
        };
        if !valid || (next.state == State::InFlight && next.evidence != [0; 32]) {
            return Err("dispatch journal lifecycle or payload discontinuity".into());
        }
        Ok(())
    }
    fn append(&mut self, key: AsciiSlug, entry: Entry) -> Result<(), String> {
        self.validate(key, &entry)?;
        let record = format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            key.as_str(), hex(&entry.payload), entry.attempt, entry.observed_at, entry.next_at,
            entry.state.name(), u8::from(entry.uncertain), hex(&entry.evidence));
        let tail = chained(self.tail, record.as_bytes());
        let line = format!("{record}\t{}\n", hex(&tail));
        if line.len() > MAX_RECORD { return Err("dispatch record exceeds its byte ceiling".into()); }
        self.capacity(line.len())?;
        self.poisoned = true;
        // Detect replacement/truncation by cooperative callers. Parent-directory
        // mutation by hostile actors remains outside this trusted-local profile.
        if self.file.metadata().map_err(|e| e.to_string())?.len() != self.bytes {
            return Err("dispatch journal changed while owned; outcome unknown".into());
        }
        self.file.write_all(line.as_bytes()).and_then(|()| self.file.sync_all())
            .map_err(|e| format!("dispatch journal append outcome unknown; retain journal, do not reset attempts: {e}"))?;
        self.bytes += line.len() as u64;
        self.tail = tail;
        self.clock_floor = entry.observed_at;
        self.entries.insert(key, entry);
        self.poisoned = false;
        Ok(())
    }
    fn replay(&mut self, line: &str) -> Result<(), String> {
        if line.is_empty() || line.len() + 1 > MAX_RECORD { return Err("invalid dispatch journal frame size".into()); }
        let (body, checksum) = line.rsplit_once('\t').ok_or("dispatch journal checksum missing")?;
        let tail = chained(self.tail, body.as_bytes());
        if unhex(checksum)? != tail { return Err("dispatch journal checksum chain mismatch".into()); }
        let fields: Vec<_> = body.split('\t').collect();
        if fields.len() != 8 { return Err("dispatch journal field count mismatch".into()); }
        let key = AsciiSlug::try_new("dispatch key", fields[0].as_bytes()).map_err(|e| e.to_string())?;
        let uncertain = match fields[6] { "0" => false, "1" => true, _ => return Err("invalid dispatch uncertainty flag".into()) };
        let entry = Entry {
            payload: unhex(fields[1])?, attempt: u32::try_from(decimal(fields[2])?).map_err(|_| "dispatch attempt overflow")?,
            observed_at: decimal(fields[3])?, next_at: decimal(fields[4])?, state: State::parse(fields[5])?,
            uncertain, evidence: unhex(fields[7])?,
        };
        self.validate(key, &entry)?;
        self.tail = tail;
        self.clock_floor = entry.observed_at;
        self.entries.insert(key, entry);
        Ok(())
    }
}

fn chained(previous: [u8; 32], record: &[u8]) -> [u8; 32] {
    let mut input = b"frankengit/local-webhook-attempt/v1\0".to_vec();
    input.extend_from_slice(&previous);
    input.extend_from_slice(record);
    sha256_digest(&input)
}

#[cfg(all(test, unix))]
mod tests;
