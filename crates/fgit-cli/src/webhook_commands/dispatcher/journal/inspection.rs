//! Non-owning observations of one bounded file prefix. No lock acquisition,
//! sync, mutation, tail repair, retry grant or acknowledgement is performed.
//! A complete concurrently written record may not yet be synced by its owner.

use super::{AsciiSlug, Entry, File, MAGIC, MAX_BYTES, MAX_RECORD, Path, State,
    checkpoint, decimal, unhex};
#[cfg(unix)]
use std::io::Read;

#[derive(Debug, PartialEq, Eq)]
pub(in super::super) struct Row {
    pub(in super::super) key: AsciiSlug,
    pub(in super::super) payload: [u8; 32],
    pub(in super::super) attempt: u32,
    pub(in super::super) observed_at: u64,
    pub(in super::super) next_at: u64,
    pub(in super::super) state: State,
    pub(in super::super) uncertain: bool,
    pub(in super::super) outcome_unknown: bool,
    pub(in super::super) exhausted: bool,
    pub(in super::super) evidence: [u8; 32],
}
#[derive(Default, Debug, PartialEq, Eq)]
pub(in super::super) struct Counts {
    pub(in super::super) total: usize,
    pub(in super::super) in_flight: usize,
    pub(in super::super) accepted: usize,
    pub(in super::super) rejected: usize,
    pub(in super::super) retryable: usize,
    pub(in super::super) unknown: usize,
    pub(in super::super) unresolved: usize,
    pub(in super::super) exhausted: usize,
}
#[derive(Default, Debug, PartialEq, Eq)]
pub(in super::super) struct Inspection {
    pub(in super::super) present: bool,
    pub(in super::super) bytes: u64,
    pub(in super::super) scope: Option<[u8; 32]>,
    pub(in super::super) tail: Option<[u8; 32]>,
    pub(in super::super) max_attempts: Option<u32>,
    pub(in super::super) clock_floor: Option<u64>,
    pub(in super::super) counts: Counts,
    pub(in super::super) rows: Vec<Row>,
    pub(in super::super) next_after: Option<AsciiSlug>,
}

fn unknown(entry: &Entry) -> bool {
    entry.state != State::Accepted && (entry.uncertain || entry.state == State::InFlight)
}
fn exhausted(entry: &Entry, max_attempts: u32) -> bool {
    !matches!(entry.state, State::Accepted | State::Rejected) && entry.attempt >= max_attempts
}

#[cfg(unix)]
fn prefix(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    // Inspect the directory entry before opening so a FIFO or dangling link
    // cannot become a blocking read or an invented empty journal.
    checkpoint::private_slot(path)?.ok_or("dispatch inspection file disappeared")?;
    let mut file = File::open(path).map_err(|e| format!("dispatch inspection cannot open file: {e}"))?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > maximum {
        return Err("dispatch inspection file exceeds its profile".into());
    }
    let size = usize::try_from(meta.len()).map_err(|_| "dispatch inspection size overflow")?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| "dispatch inspection allocation refused")?;
    // Capture the length once. Later appends are not silently mixed into this
    // observation, and truncation of the captured prefix is a refusal.
    Read::by_ref(&mut file).take(meta.len()).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() != size { return Err("dispatch inspection prefix was truncated".into()); }
    Ok(bytes)
}

pub(in super::super) fn inspect(path: &Path, after: Option<AsciiSlug>, limit: usize,
    expected_tail: Option<[u8; 32]>) -> Result<Inspection, String>
{
    if !(1..=100).contains(&limit) || (after.is_some() && expected_tail.is_none()) {
        return Err("dispatch inspection requires a bounded page and an exact continuation token".into());
    }
    #[cfg(not(unix))]
    { let _ = path; Err("dispatch inspection requires the Unix journal profile".into()) }
    #[cfg(unix)]
    {
        let lock_path = checkpoint::fence_path(path);
        let present = checkpoint::private_slot(path)?.is_some();
        let fenced = checkpoint::private_slot(&lock_path)?.is_some();
        if present != fenced {
            return Err("dispatch journal/fence is missing or legacy v1 requires offline migration; no empty status was inferred".into());
        }
        if !present {
            if expected_tail.is_some() { return Err("dispatch inspection snapshot moved or disappeared".into()); }
            return Ok(Inspection::default());
        }
        let fence = prefix(&lock_path, MAX_RECORD as u64)?;
        let bytes = prefix(path, MAX_BYTES)?;
        let end = bytes.iter().position(|b| *b == b'\n').ok_or("dispatch inspection header is incomplete")?;
        if end >= MAX_RECORD { return Err("dispatch inspection header exceeds its bound".into()); }
        let line = std::str::from_utf8(&bytes[..end]).map_err(|_| "dispatch inspection header is not UTF-8")?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 || fields[0] != MAGIC { return Err("unsupported dispatch journal version".into()); }
        let scope = unhex(fields[1])?;
        let max_attempts = u32::try_from(decimal(fields[2])?).map_err(|_| "dispatch inspection retry limit overflow")?;
        let header = checkpoint::header(scope, max_attempts);
        if fence != checkpoint::fence_header(&header).as_bytes() {
            return Err("dispatch inspection journal and fence disagree".into());
        }
        let decoded = checkpoint::decode(&bytes, &header, max_attempts)?;
        if expected_tail.is_some_and(|expected| expected != decoded.tail) {
            return Err("dispatch inspection snapshot moved; restart pagination explicitly".into());
        }
        let mut counts = Counts { total: decoded.entries.len(), ..Counts::default() };
        for entry in decoded.entries.values() {
            match entry.state {
                State::InFlight => counts.in_flight += 1,
                State::Accepted => counts.accepted += 1,
                State::Rejected => counts.rejected += 1,
                State::Retryable => counts.retryable += 1,
                State::Unknown => counts.unknown += 1,
            }
            counts.unresolved += usize::from(unknown(entry));
            counts.exhausted += usize::from(exhausted(entry, max_attempts));
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(limit).map_err(|_| "dispatch inspection page allocation refused")?;
        let mut more = false;
        for (key, entry) in &decoded.entries {
            if after.is_some_and(|cursor| *key <= cursor) { continue; }
            if rows.len() == limit { more = true; break; }
            rows.push(Row { key: *key, payload: entry.payload, attempt: entry.attempt,
                observed_at: entry.observed_at, next_at: entry.next_at, state: entry.state,
                uncertain: entry.uncertain, outcome_unknown: unknown(entry),
                exhausted: exhausted(entry, max_attempts), evidence: entry.evidence });
        }
        let next_after = if more { rows.last().map(|row| row.key) } else { None };
        Ok(Inspection { present: true, bytes: bytes.len() as u64, scope: Some(scope), tail: Some(decoded.tail),
            max_attempts: Some(max_attempts), clock_floor: Some(decoded.clock_floor), counts, rows, next_after })
    }
}
