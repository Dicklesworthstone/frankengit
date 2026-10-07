use super::*;
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::os::unix::fs::{PermissionsExt, symlink};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-dispatch-journal-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf { self.0.join("attempts") }
    fn open(&self) -> Journal { Journal::open(&self.path(), [4; 32], 3).unwrap() }
    fn bytes(&self, bytes: &[u8]) {
        fs::write(self.path(), bytes).unwrap();
        fs::set_permissions(self.path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn key() -> AsciiSlug { AsciiSlug::from_static("delivery-one") }
fn payload() -> [u8; 32] { [5; 32] }

#[test]
fn live_owner_excludes_an_independent_handle_and_drop_releases_lock() {
    let scratch = Scratch::new();
    let owner = scratch.open();
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
    drop(owner);
    let reopened = scratch.open();
    assert_eq!(reopened.plan(key(), payload(), 100).unwrap(), Plan::Due { attempt: 1, outcome_unknown: false });
    assert_eq!(fs::metadata(scratch.path()).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn accepted_observation_survives_reopen_and_cannot_be_resent() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    assert_eq!(journal.reserve(key(), payload(), 100, 200).unwrap(), 1);
    journal.observe(key(), State::Accepted, 120, 220, b"HTTP/1.1 204").unwrap();
    drop(journal);
    let mut journal = scratch.open();
    assert_eq!(journal.plan(key(), payload(), 1000).unwrap(), Plan::Settled { state: State::Accepted, outcome_unknown: false });
    assert!(journal.reserve(key(), payload(), 1000, 1100).is_err());
    assert!(journal.observe(key(), State::Unknown, 1000, 1100, b"cannot rewrite ACK").is_err());
}

#[test]
fn every_crash_reservation_consumes_an_ordinal_and_exhausts_as_unknown() {
    let scratch = Scratch::new();
    for attempt in 1..=3 {
        let mut journal = scratch.open();
        let now = u64::from(attempt) * 100;
        assert_eq!(journal.plan(key(), payload(), now).unwrap(), Plan::Due { attempt, outcome_unknown: attempt > 1 });
        assert_eq!(journal.reserve(key(), payload(), now, now + 100).unwrap(), attempt);
        assert_eq!(journal.plan(key(), payload(), now + 1).unwrap(), if attempt == 3 {
            Plan::Exhausted { outcome_unknown: true }
        } else { Plan::Sleeping { until: now + 100, outcome_unknown: true } });
        // Drop without observation represents a process crash after reservation,
        // whether it happened before or after sending bytes to the receiver.
    }
    let mut journal = scratch.open();
    assert_eq!(journal.plan(key(), payload(), 500).unwrap(), Plan::Exhausted { outcome_unknown: true });
    assert!(journal.reserve(key(), payload(), 500, 600).is_err());
}

#[test]
fn successful_retry_resolves_delivery_but_later_rejection_cannot_erase_unknown() {
    for terminal in [State::Accepted, State::Rejected] {
        let scratch = Scratch::new();
        let mut journal = scratch.open();
        journal.reserve(key(), payload(), 100, 200).unwrap();
        journal.observe(key(), State::Unknown, 110, 210, b"lost ack").unwrap();
        drop(journal);
        let mut journal = scratch.open();
        assert_eq!(journal.reserve(key(), payload(), 210, 310).unwrap(), 2);
        journal.observe(key(), terminal, 220, 320, b"final response").unwrap();
        assert_eq!(journal.plan(key(), payload(), 500).unwrap(), Plan::Settled {
            state: terminal, outcome_unknown: terminal != State::Accepted,
        });
        assert!(journal.entries[&key()].uncertain);
    }
}

#[test]
fn retry_backoff_is_measured_from_completion_and_clock_rollback_refuses() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    journal.reserve(key(), payload(), 100, 200).unwrap();
    journal.observe(key(), State::Retryable, 150, 250, b"503").unwrap();
    assert!(journal.plan(key(), payload(), 149).is_err());
    assert!(journal.plan(AsciiSlug::from_static("other"), payload(), 149).is_err());
    assert_eq!(journal.plan(key(), payload(), 249).unwrap(), Plan::Sleeping { until: 250, outcome_unknown: false });
    assert!(journal.reserve(key(), payload(), 249, 400).is_err());
    assert_eq!(journal.reserve(key(), payload(), 250, 350).unwrap(), 2);
    journal.observe(key(), State::Retryable, 260, 360, b"503").unwrap();
    assert_eq!(journal.reserve(key(), payload(), 360, 460).unwrap(), 3);
    journal.observe(key(), State::Retryable, 370, 470, b"503").unwrap();
    assert_eq!(journal.plan(key(), payload(), 1000).unwrap(), Plan::Exhausted { outcome_unknown: false });
}

#[test]
fn scope_policy_and_payload_changes_never_reset_attempts() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    journal.reserve(key(), payload(), 100, 200).unwrap();
    assert!(journal.plan(key(), [9; 32], 300).is_err());
    drop(journal);
    for (scope, attempts) in [([9; 32], 3), ([4; 32], 4), ([4; 32], 0), ([4; 32], 17)] {
        assert!(Journal::open(&scratch.path(), scope, attempts).is_err());
    }
    assert_eq!(scratch.open().plan(key(), payload(), 300).unwrap(), Plan::Due { attempt: 2, outcome_unknown: true });
}

#[test]
fn truncated_header_or_frame_is_not_an_empty_or_rewound_journal() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    let header_len = journal.bytes as usize;
    journal.reserve(key(), payload(), 100, 200).unwrap();
    let reserved_len = journal.bytes as usize;
    journal.observe(key(), State::Accepted, 120, 220, b"204").unwrap();
    drop(journal);
    let valid = fs::read(scratch.path()).unwrap();
    // A complete older prefix can be an actual crash point; malicious removal
    // of whole valid frames is NOT detectable by a local checksum journal.
    for length in 0..valid.len() {
        if length == header_len || length == reserved_len { continue; }
        scratch.bytes(&valid[..length]);
        assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err(), "length {length}");
    }
    scratch.bytes(&valid[..reserved_len]);
    assert_eq!(scratch.open().plan(key(), payload(), 300).unwrap(), Plan::Due { attempt: 2, outcome_unknown: true });
    scratch.bytes(&valid);
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_ok());
}

#[test]
fn every_single_byte_corruption_refuses_without_recovery_writes() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    journal.reserve(key(), payload(), 100, 200).unwrap();
    journal.observe(key(), State::Retryable, 150, 250, b"503").unwrap();
    drop(journal);
    let valid = fs::read(scratch.path()).unwrap();
    for index in 0..valid.len() {
        let mut corrupt = valid.clone();
        corrupt[index] ^= 1;
        scratch.bytes(&corrupt);
        assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err(), "byte {index}");
        assert_eq!(fs::read(scratch.path()).unwrap(), corrupt);
    }
}

#[test]
fn checksum_valid_illegal_lifecycles_still_refuse() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    let original = fs::read(scratch.path()).unwrap();
    let initial_tail = journal.tail;
    let invalid = Entry { payload: payload(), attempt: 1, observed_at: 100, next_at: 200,
        state: State::Accepted, uncertain: false, evidence: [6; 32] };
    assert!(journal.append(key(), invalid).is_err());
    assert_eq!(fs::read(scratch.path()).unwrap(), original);
    journal.reserve(key(), payload(), 100, 200).unwrap();
    assert!(journal.observe(key(), State::Retryable, 101, 150, b"shortened delay").is_err());
    assert!(journal.observe(key(), State::InFlight, 101, 201, b"not a result").is_err());
    assert_eq!(journal.entries[&key()].state, State::InFlight);
    drop(journal);
    // Integrity alone must not admit an acceptance without a reservation.
    // Build a correctly chained but semantically invalid first record.
    let body = format!("event\t{}\t{}\t1\t100\t200\taccepted\t0\t{}",
        key().as_str(), hex(&payload()), hex(&[6; 32]));
    let checksum = chained(initial_tail, body.as_bytes());
    let mut forged = original;
    forged.extend_from_slice(format!("{body}\t{}\n", hex(&checksum)).as_bytes());
    scratch.bytes(&forged);
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
    assert_eq!(fs::read(scratch.path()).unwrap(), forged);
}

#[test]
fn budget_is_reserved_for_both_write_ahead_and_result_records() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    journal.bytes = MAX_BYTES - MAX_RECORD as u64;
    assert!(journal.reserve(key(), payload(), 100, 200).is_err());
    assert!(journal.entries.is_empty());
}

#[test]
fn owner_detects_truncation_and_never_dispatches_after_durability_error() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    journal.reserve(key(), payload(), 100, 200).unwrap();
    journal.file.set_len(1).unwrap();
    assert!(journal.observe(key(), State::Accepted, 120, 220, b"204").is_err());
    assert!(journal.poisoned);
    assert!(journal.plan(AsciiSlug::from_static("other"), payload(), 300).is_err());
}

#[test]
fn links_directories_public_files_and_oversized_files_refuse() {
    let scratch = Scratch::new();
    symlink(scratch.0.join("absent"), scratch.path()).unwrap();
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
    fs::remove_file(scratch.path()).unwrap();
    fs::create_dir(scratch.path()).unwrap();
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
    fs::remove_dir(scratch.path()).unwrap();
    drop(scratch.open());
    fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
    fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o600)).unwrap();
    OpenOptions::new().write(true).open(scratch.path()).unwrap().set_len(MAX_BYTES + 1).unwrap();
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
}

fn numbered_key(index: usize) -> AsciiSlug {
    AsciiSlug::try_new("test key", format!("delivery-{index:05}").as_bytes()).unwrap()
}

fn varied_entries(journal: &mut Journal) {
    for (index, state) in [State::Accepted, State::Rejected, State::Retryable, State::Unknown, State::InFlight].into_iter().enumerate() {
        let now = 100 + index as u64 * 100;
        journal.reserve(numbered_key(index), payload(), now, now + 10).unwrap();
        if state != State::InFlight {
            journal.observe(numbered_key(index), state, now + 1, now + 11, b"retained observation").unwrap();
        }
    }
    // A later rejection must preserve the earlier unknown even in a checkpoint.
    journal.reserve(numbered_key(3), payload(), 600, 610).unwrap();
    journal.observe(numbered_key(3), State::Rejected, 601, 611, b"later rejection").unwrap();
}

#[test]
fn checkpoint_preserves_every_state_counter_commitment_clock_and_uncertainty() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    varied_entries(&mut journal);
    let original = journal.entries.clone();
    let floor = journal.clock_floor;
    let old_bytes = journal.bytes;
    let plans: Vec<_> = original.keys().map(|k| (*k, journal.plan(*k, payload(), 1000).unwrap())).collect();
    journal.compact().unwrap();
    assert!(journal.bytes < old_bytes);
    assert_eq!(journal.entries, original);
    assert_eq!(journal.clock_floor, floor);
    let encoded = fs::read(scratch.path()).unwrap();
    journal.compact().unwrap();
    assert_eq!(fs::read(scratch.path()).unwrap(), encoded, "identical state has identical checkpoint bytes");
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err(), "replacement must not release the stable fence");
    drop(journal);
    let mut journal = scratch.open();
    assert_eq!(journal.entries, original);
    for (k, plan) in plans { assert_eq!(journal.plan(k, payload(), 1000).unwrap(), plan); }
    assert!(journal.plan(key(), payload(), floor - 1).is_err());
    assert_eq!(journal.reserve(numbered_key(2), payload(), 1000, 1010).unwrap(), 2);
    journal.observe(numbered_key(2), State::Accepted, 1001, 1011, b"retry accepted").unwrap();
    drop(journal);
    assert_eq!(scratch.open().plan(numbered_key(2), payload(), 2000).unwrap(),
        Plan::Settled { state: State::Accepted, outcome_unknown: false });
}

#[test]
fn checkpoint_faults_never_select_incomplete_state_or_lose_the_fence() {
    for stage in [checkpoint::Stage::Staged, checkpoint::Stage::Renamed, checkpoint::Stage::Synced] {
        let scratch = Scratch::new();
        let mut journal = scratch.open();
        varied_entries(&mut journal);
        let before = journal.entries.clone();
        let original = fs::read(scratch.path()).unwrap();
        assert!(journal.compact_with(&mut |observed| {
            if observed == stage { Err("injected checkpoint interruption".into()) } else { Ok(()) }
        }).is_err());
        assert_eq!(journal.poisoned, stage != checkpoint::Stage::Staged);
        assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
        if stage == checkpoint::Stage::Staged {
            assert_eq!(fs::read(scratch.path()).unwrap(), original);
            assert!(journal.plan(numbered_key(0), payload(), 2000).is_ok());
        } else {
            assert!(journal.plan(numbered_key(0), payload(), 2000).is_err());
        }
        assert!(!fs::read_dir(&scratch.0).unwrap().any(|row| row.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        drop(journal);
        let reopened = scratch.open();
        assert_eq!(reopened.entries, before, "stage {stage:?}");
        assert_eq!(reopened.plan(numbered_key(0), payload(), 2000).unwrap(),
            Plan::Settled { state: State::Accepted, outcome_unknown: false });
        assert_eq!(reopened.plan(numbered_key(3), payload(), 2000).unwrap(),
            Plan::Settled { state: State::Rejected, outcome_unknown: true });
    }
}

#[test]
fn reservation_compacts_automatically_without_resetting_any_attempt_limit() {
    let scratch = Scratch::new();
    let mut journal = scratch.open();
    let mut now = 100;
    let mut compactions = 0;
    for index in 0..12 {
        for attempt in 1..=3 {
            let old_bytes = journal.bytes;
            assert_eq!(journal.reserve_with_limit(numbered_key(index), payload(), now, now + 10, 8192).unwrap(), attempt);
            if journal.bytes < old_bytes { compactions += 1; }
            journal.observe(numbered_key(index), State::Retryable, now + 1, now + 11, b"503").unwrap();
            assert!(journal.bytes <= 8192);
            now += 20;
        }
    }
    assert!(compactions >= 2, "the test must exercise repeated automatic replacement");
    assert_eq!(journal.entries.len(), 12);
    drop(journal);
    let mut journal = scratch.open();
    for index in 0..12 {
        assert_eq!(journal.plan(numbered_key(index), payload(), now).unwrap(), Plan::Exhausted { outcome_unknown: false });
        assert!(journal.reserve(numbered_key(index), payload(), now, now + 10).is_err());
    }
}

#[test]
fn maximum_key_checkpoint_fits_without_dropping_acceptances_or_unknowns() {
    let mut entries = BTreeMap::new();
    for index in 0..MAX_KEYS {
        let state = if index % 2 == 0 { State::Accepted } else { State::Unknown };
        entries.insert(numbered_key(index), Entry { payload: payload(), attempt: 3,
            observed_at: index as u64, next_at: index as u64 + 100, state,
            uncertain: state == State::Unknown, evidence: [8; 32] });
    }
    let header = checkpoint::header([4; 32], 3);
    let floor = MAX_KEYS as u64 - 1;
    let (bytes, _) = checkpoint::encode(&header, &entries, floor, 3).unwrap();
    assert!(fits(bytes.len() as u64, 2 * MAX_RECORD, MAX_BYTES));
    assert_eq!(checkpoint::decode(&bytes, &header, 3).unwrap().entries, entries);
    entries.insert(numbered_key(MAX_KEYS), entries[&numbered_key(0)]);
    assert!(checkpoint::encode(&header, &entries, floor, 3).is_err());
}

#[test]
fn losing_only_the_journal_or_its_fence_cannot_initialize_a_fresh_retry_budget() {
    for remove_data in [true, false] {
        let scratch = Scratch::new();
        let mut journal = scratch.open();
        journal.reserve(key(), payload(), 100, 200).unwrap();
        journal.observe(key(), State::Accepted, 101, 201, b"204").unwrap();
        drop(journal);
        let missing = if remove_data { scratch.path() } else { checkpoint::fence_path(&scratch.path()) };
        fs::remove_file(&missing).unwrap();
        assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
        assert!(!missing.exists(), "opening must not replace the missing responsibility record");
    }
}

#[test]
fn replacing_same_length_data_or_fence_is_detected_before_another_reservation() {
    for replace_fence in [true, false] {
        let scratch = Scratch::new();
        let mut journal = scratch.open();
        let target = if replace_fence { checkpoint::fence_path(&scratch.path()) } else { scratch.path() };
        let bytes = fs::read(&target).unwrap();
        let replacement = scratch.0.join("replacement");
        fs::write(&replacement, bytes).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(replacement, &target).unwrap();
        assert!(journal.reserve(key(), payload(), 100, 200).is_err());
        assert!(journal.poisoned);
        assert!(journal.entries.is_empty());
    }
}

#[test]
fn hard_links_cannot_split_data_ownership_across_independent_sidecars() {
    for link_fence in [true, false] {
        let scratch = Scratch::new();
        let mut journal = scratch.open();
        let target = if link_fence { checkpoint::fence_path(&scratch.path()) } else { scratch.path() };
        fs::hard_link(&target, scratch.0.join("alias")).unwrap();
        assert!(journal.reserve(key(), payload(), 100, 200).is_err());
        assert!(journal.poisoned);
        drop(journal);
        assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
    }
}

#[test]
fn legacy_unfenced_journals_are_preserved_and_refused_not_silently_migrated() {
    let scratch = Scratch::new();
    let old = format!("fgit-webhook-dispatch-v1\t{}\t3\n", hex(&[4; 32]));
    scratch.bytes(old.as_bytes());
    assert!(Journal::open(&scratch.path(), [4; 32], 3).is_err());
    assert_eq!(fs::read(scratch.path()).unwrap(), old.as_bytes());
    assert!(!checkpoint::fence_path(&scratch.path()).exists());
}

fn framed(mut bytes: Vec<u8>, mut tail: [u8; 32], bodies: &[String]) -> Vec<u8> {
    for body in bodies {
        tail = chained(tail, body.as_bytes());
        bytes.extend_from_slice(format!("{body}\t{}\n", hex(&tail)).as_bytes());
    }
    bytes
}

#[test]
fn checkpoint_checks_count_floor_order_completeness_and_state_not_only_checksums() {
    let header = checkpoint::header([4; 32], 3);
    let entry = Entry { payload: payload(), attempt: 1, observed_at: 100, next_at: 200,
        state: State::Accepted, uncertain: false, evidence: [7; 32] };
    let a = format!("snapshot\t{}", record_body(numbered_key(0), &entry));
    let b = format!("snapshot\t{}", record_body(numbered_key(1), &entry));
    for bodies in [
        vec![a.clone()],
        vec![a.clone(), "checkpoint\t2\t100".into()],
        vec![a.clone(), "checkpoint\t1\t99".into()],
        vec![a.clone(), a.clone(), "checkpoint\t2\t100".into()],
        vec![b.clone(), a.clone(), "checkpoint\t2\t100".into()],
        vec!["checkpoint\t0\t0".into(), a.clone()],
        vec!["checkpoint\t0\t0".into(), "checkpoint\t0\t0".into()],
    ] {
        let bytes = framed(header.as_bytes().to_vec(), sha256_digest(header.as_bytes()), &bodies);
        assert!(checkpoint::decode(&bytes, &header, 3).is_err(), "{bodies:?}");
    }
    let mut entries = BTreeMap::from([(numbered_key(0), entry)]);
    for invalid in [Entry { attempt: 0, ..entry }, Entry { attempt: 4, ..entry },
        Entry { state: State::Unknown, ..entry }, Entry { uncertain: true, ..entry },
        Entry { state: State::InFlight, ..entry }, Entry { next_at: 99, ..entry }]
    {
        entries.insert(numbered_key(0), invalid);
        assert!(checkpoint::encode(&header, &entries, 100, 3).is_err());
    }
}
