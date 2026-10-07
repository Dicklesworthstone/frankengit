use super::*;
use super::super::super::{Plan, State};
use std::fs;
use std::io;
use std::os::unix::fs::symlink;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-dispatch-migration-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf { self.0.join("attempts") }
    fn write(&self, bytes: &[u8]) {
        fs::write(self.path(), bytes).unwrap();
        fs::set_permissions(self.path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn key(name: &'static str) -> AsciiSlug { AsciiSlug::from_static(name) }

// Original v1 wire framing: no event prefix, no checkpoint/footer, one chained
// checksum per legal event. These rows do not use the new journal writer.
fn v1(rows: &[(&str, u32, u64, u64, &str, bool)], limit: u32) -> Vec<u8> {
    let mut bytes = format!("{LEGACY_MAGIC}\t{}\t{limit}\n", "04".repeat(32)).into_bytes();
    let mut tail = sha256_digest(&bytes);
    for (name, attempt, now, next, state, uncertain) in rows {
        let evidence = if *state == "in-flight" { [0; 32] } else { [6; 32] };
        let body = format!("{name}\t{}\t{attempt}\t{now}\t{next}\t{state}\t{}\t{}",
            "05".repeat(32), u8::from(*uncertain), hex(&evidence));
        tail = chained(tail, body.as_bytes());
        bytes.extend_from_slice(format!("{body}\t{}\n", hex(&tail)).as_bytes());
    }
    bytes
}
fn fixture() -> Vec<u8> {
    v1(&[
        ("accepted", 1, 10, 20, "in-flight", false),
        ("accepted", 1, 11, 21, "accepted", false),
        ("lost", 1, 30, 40, "in-flight", false),
        ("lost", 1, 31, 41, "unknown", true),
        ("lost", 2, 41, 51, "in-flight", true),
        ("lost", 2, 42, 52, "rejected", true),
        ("pending", 1, 60, 70, "in-flight", false),
        ("pending", 1, 61, 71, "retryable", false),
        ("crashed", 1, 80, 90, "in-flight", false),
        ("exhausted", 1, 100, 110, "in-flight", false),
        ("exhausted", 2, 110, 120, "in-flight", true),
        ("exhausted", 3, 120, 130, "in-flight", true),
    ], 3)
}
fn apply(scratch: &Scratch, bytes: &[u8]) -> Result<Report, String> {
    migrate(&scratch.path(), Some(sha256_digest(bytes)), &mut |_| Ok(()))
}
fn arguments(scratch: &Scratch, bytes: Option<&[u8]>) -> Vec<String> {
    let mut args = vec![scratch.path().to_string_lossy().into_owned(), "--trusted-local".into()];
    if let Some(bytes) = bytes {
        args.extend(["--apply".into(), "--expected-sha256".into(), hex(&sha256_digest(bytes))]);
    }
    args
}

#[test]
fn preview_reads_original_state_without_creating_a_fence_or_backup() {
    let scratch = Scratch::new();
    let bytes = fixture();
    scratch.write(&bytes);
    let report = migrate(&scratch.path(), None, &mut |_| panic!("preview reached a write barrier")).unwrap();
    assert_eq!(report.original, sha256_digest(&bytes));
    assert_eq!(report.keys, 5);
    assert_eq!(report.clock_floor, 120);
    assert!(!report.already_migrated);
    assert_eq!(fs::read(scratch.path()).unwrap(), bytes);
    assert!(!fence_path(&scratch.path()).exists());
    assert!(!backup_path(&scratch.path()).exists());
    let mut out = Vec::new();
    assert_eq!(execute(&arguments(&scratch, None), &mut out).unwrap(), 0);
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("\"applied\":false"));
    assert!(out.contains("\"transport_attempted\":false"));
}

#[test]
fn conversion_preserves_exact_responsibility_and_reopens_in_the_real_worker() {
    let scratch = Scratch::new();
    let bytes = fixture();
    scratch.write(&bytes);
    let before = legacy(&bytes).unwrap().2;
    let report = apply(&scratch, &bytes).unwrap();
    assert_eq!(fs::read(backup_path(&scratch.path())).unwrap(), bytes);
    assert_eq!(sha256_digest(&fs::read(scratch.path()).unwrap()), report.checkpoint);
    assert!(legacy(&fs::read(scratch.path()).unwrap()).is_err(), "an old worker must not accept v2");
    let mut journal = Journal::open(&scratch.path(), [4; 32], 3).unwrap();
    assert_eq!(journal.entries, before.entries);
    assert_eq!(journal.clock_floor, before.clock_floor);
    assert_eq!(journal.plan(key("accepted"), [5; 32], 500).unwrap(), Plan::Settled { state: State::Accepted, outcome_unknown: false });
    assert_eq!(journal.plan(key("lost"), [5; 32], 500).unwrap(), Plan::Settled { state: State::Rejected, outcome_unknown: true });
    assert_eq!(journal.plan(key("pending"), [5; 32], 500).unwrap(), Plan::Due { attempt: 2, outcome_unknown: false });
    assert_eq!(journal.plan(key("crashed"), [5; 32], 500).unwrap(), Plan::Due { attempt: 2, outcome_unknown: true });
    assert_eq!(journal.plan(key("exhausted"), [5; 32], 500).unwrap(), Plan::Exhausted { outcome_unknown: true });
    assert_eq!(journal.reserve(key("pending"), [5; 32], 500, 600).unwrap(), 2);
    journal.observe(key("pending"), State::Accepted, 510, 610, b"real subsequent observation").unwrap();
    drop(journal);
    let journal = Journal::open(&scratch.path(), [4; 32], 3).unwrap();
    assert_eq!(journal.plan(key("pending"), [5; 32], 700).unwrap(), Plan::Settled { state: State::Accepted, outcome_unknown: false });
}

#[test]
fn every_checkpoint_crash_boundary_is_recoverable_by_original_checksum() {
    for stop in [MigrationStage::Fenced, MigrationStage::BackedUp,
        MigrationStage::Checkpoint(Stage::Staged), MigrationStage::Checkpoint(Stage::Renamed), MigrationStage::Checkpoint(Stage::Synced)]
    {
        let scratch = Scratch::new();
        let bytes = fixture();
        scratch.write(&bytes);
        let err = migrate(&scratch.path(), Some(sha256_digest(&bytes)), &mut |stage|
            if stage == stop { Err("simulated process interruption".into()) } else { Ok(()) });
        assert!(err.is_err(), "{stop:?}");
        let changed = matches!(stop, MigrationStage::Checkpoint(Stage::Renamed | Stage::Synced));
        assert_eq!(fs::read(scratch.path()).unwrap() == bytes, !changed);
        let report = apply(&scratch, &bytes).unwrap();
        assert_eq!(report.already_migrated, changed);
        assert_eq!(fs::read(backup_path(&scratch.path())).unwrap(), bytes);
        let installed = fs::read(scratch.path()).unwrap();
        let again = apply(&scratch, &bytes).unwrap();
        assert!(again.already_migrated);
        assert_eq!(installed, fs::read(scratch.path()).unwrap());
        let journal = Journal::open(&scratch.path(), [4; 32], 3).unwrap();
        assert_eq!(journal.entries, legacy(&bytes).unwrap().2.entries);
    }
}

#[test]
fn a_running_v1_or_v2_owner_prevents_migration_without_blocking() {
    let scratch = Scratch::new();
    let bytes = fixture();
    scratch.write(&bytes);
    let old_worker = OpenOptions::new().read(true).write(true).open(scratch.path()).unwrap();
    old_worker.try_lock().unwrap();
    assert!(apply(&scratch, &bytes).is_err());
    assert!(!fence_path(&scratch.path()).exists());
    assert!(!backup_path(&scratch.path()).exists());
    drop(old_worker);
    apply(&scratch, &bytes).unwrap();
    let owner = Journal::open(&scratch.path(), [4; 32], 3).unwrap();
    assert!(apply(&scratch, &bytes).is_err());
    drop(owner);
    assert!(apply(&scratch, &bytes).unwrap().already_migrated);
}

#[test]
fn wrong_expected_bytes_and_changed_old_worker_state_are_not_overwritten() {
    let scratch = Scratch::new();
    let original = fixture();
    scratch.write(&original);
    assert!(migrate(&scratch.path(), Some([0; 32]), &mut |_| Ok(())).is_err());
    assert!(!fence_path(&scratch.path()).exists());
    assert!(!backup_path(&scratch.path()).exists());
    let changed = v1(&[("new", 1, 700, 800, "in-flight", false)], 3);
    scratch.write(&changed);
    assert!(apply(&scratch, &original).is_err());
    assert_eq!(fs::read(scratch.path()).unwrap(), changed);
}

#[test]
fn interrupted_fence_initialization_is_extended_only_from_an_exact_prefix() {
    let expected = fence_header(&header([4; 32], 3)).into_bytes();
    for length in [0, 1, expected.len() / 2, expected.len()] {
        let scratch = Scratch::new();
        let bytes = fixture();
        scratch.write(&bytes);
        let fence = fence_path(&scratch.path());
        fs::write(&fence, &expected[..length]).unwrap();
        fs::set_permissions(&fence, fs::Permissions::from_mode(0o600)).unwrap();
        apply(&scratch, &bytes).unwrap();
        assert_eq!(fs::read(&fence).unwrap(), expected);
    }
    let scratch = Scratch::new();
    let bytes = fixture();
    scratch.write(&bytes);
    let fence = fence_path(&scratch.path());
    fs::write(&fence, b"wrong scope").unwrap();
    fs::set_permissions(&fence, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(apply(&scratch, &bytes).is_err());
    assert_eq!(fs::read(&fence).unwrap(), b"wrong scope");
    assert_eq!(fs::read(scratch.path()).unwrap(), bytes);
}

#[test]
fn torn_corrupt_and_checksum_valid_illegal_legacy_records_refuse() {
    let bytes = fixture();
    for end in 0..bytes.len() {
        if end > 0 && bytes[end - 1] == b'\n' { continue; }
        assert!(legacy(&bytes[..end]).is_err(), "torn prefix {end}");
    }
    let mut corrupt = bytes.clone();
    corrupt[120] ^= 1;
    assert!(legacy(&corrupt).is_err());
    for rows in [vec![("a", 2, 10, 20, "in-flight", false)],
        vec![("a", 1, 10, 20, "accepted", false)],
        vec![("a", 1, 10, 20, "in-flight", false), ("a", 1, 11, 21, "unknown", false)],
        vec![("a", 1, 10, 20, "in-flight", false), ("a", 2, 20, 30, "in-flight", false)],
        vec![("a", 1, 10, 20, "in-flight", false), ("b", 1, 9, 30, "in-flight", false)]]
    { assert!(legacy(&v1(&rows, 3)).is_err()); }
    let scratch = Scratch::new();
    scratch.write(&corrupt);
    assert!(apply(&scratch, &corrupt).is_err());
    assert!(!fence_path(&scratch.path()).exists());
}

#[test]
fn old_scope_and_all_retry_limits_are_preserved_without_rebinding() {
    for maximum in 2..=16 {
        let scratch = Scratch::new();
        let rows: Vec<_> = (1..=maximum).map(|n| ("lost", n, u64::from(n) * 10, u64::from(n + 1) * 10, "in-flight", n > 1)).collect();
        let bytes = v1(&rows, maximum);
        scratch.write(&bytes);
        let report = apply(&scratch, &bytes).unwrap();
        assert_eq!(report.max_attempts, maximum);
        assert_eq!(report.scope, [4; 32]);
        assert!(Journal::open(&scratch.path(), [9; 32], maximum).is_err());
        let journal = Journal::open(&scratch.path(), [4; 32], maximum).unwrap();
        assert_eq!(journal.plan(key("lost"), [5; 32], 1000).unwrap(), Plan::Exhausted { outcome_unknown: true });
    }
}

#[test]
fn a_conflicting_or_unsafe_backup_is_preserved_and_cannot_authorize_upgrade() {
    for mode in ["conflict", "symlink", "hardlink", "public"] {
        let scratch = Scratch::new();
        let bytes = fixture();
        scratch.write(&bytes);
        let backup = backup_path(&scratch.path());
        match mode {
            "symlink" => symlink(scratch.path(), &backup).unwrap(),
            "hardlink" => fs::hard_link(scratch.path(), &backup).unwrap(),
            _ => {
                let content: &[u8] = if mode == "conflict" { b"not the original" } else { &bytes };
                fs::write(&backup, content).unwrap();
                fs::set_permissions(&backup, fs::Permissions::from_mode(if mode == "public" { 0o644 } else { 0o600 })).unwrap();
            }
        }
        assert!(apply(&scratch, &bytes).is_err(), "{mode}");
        assert_eq!(fs::read(scratch.path()).unwrap(), bytes);
    }
}

#[test]
fn progressed_v2_is_never_rolled_back_to_a_retained_v1_backup() {
    let scratch = Scratch::new();
    let bytes = fixture();
    scratch.write(&bytes);
    apply(&scratch, &bytes).unwrap();
    let mut owner = Journal::open(&scratch.path(), [4; 32], 3).unwrap();
    owner.reserve(key("pending"), [5; 32], 500, 600).unwrap();
    drop(owner);
    let progressed = fs::read(scratch.path()).unwrap();
    assert!(apply(&scratch, &bytes).is_err());
    assert_eq!(fs::read(scratch.path()).unwrap(), progressed);
    assert_eq!(fs::read(backup_path(&scratch.path())).unwrap(), bytes);
}

#[test]
fn missing_data_or_fence_and_corrupt_selected_v2_never_fall_back() {
    for mode in ["data", "fence", "corrupt"] {
        let scratch = Scratch::new();
        let bytes = fixture();
        scratch.write(&bytes);
        apply(&scratch, &bytes).unwrap();
        match mode {
            "data" => fs::remove_file(scratch.path()).unwrap(),
            "fence" => fs::remove_file(fence_path(&scratch.path())).unwrap(),
            _ => {
                let mut selected = fs::read(scratch.path()).unwrap();
                selected[120] ^= 1;
                scratch.write(&selected);
            }
        }
        assert!(apply(&scratch, &bytes).is_err(), "{mode}");
        assert_eq!(fs::read(backup_path(&scratch.path())).unwrap(), bytes);
        if mode == "data" { assert!(!scratch.path().exists()); }
    }
}

#[test]
fn output_failure_does_not_undo_an_installed_upgrade_or_permit_a_resend() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::other("closed output")) }
        fn flush(&mut self) -> io::Result<()> { Err(io::Error::other("closed output")) }
    }
    let scratch = Scratch::new();
    let bytes = fixture();
    scratch.write(&bytes);
    let args = arguments(&scratch, Some(&bytes));
    assert!(execute(&args, &mut Broken).unwrap_err().contains("upgrade may already be complete"));
    let mut out = Vec::new();
    assert_eq!(execute(&args, &mut out).unwrap(), 0);
    assert!(String::from_utf8(out).unwrap().contains("\"already_migrated\":true"));
    let owner = Journal::open(&scratch.path(), [4; 32], 3).unwrap();
    assert_eq!(owner.plan(key("accepted"), [5; 32], 500).unwrap(), Plan::Settled { state: State::Accepted, outcome_unknown: false });
}

#[test]
fn migration_cli_requires_explicit_trust_apply_and_original_digest() {
    let scratch = Scratch::new();
    assert!(parse(&arguments(&scratch, None)).unwrap().expected.is_none());
    assert_eq!(parse(&arguments(&scratch, Some(&fixture()))).unwrap().expected, Some(sha256_digest(&fixture())));
    for args in [vec![], vec!["p"], vec!["p", "--apply"], vec!["p", "--trusted-local", "--apply"],
        vec!["p", "--trusted-local", "--apply", "--expected-sha256", "wrong"],
        vec!["p", "--trusted-local", "--at-least-once", "--expected-sha256", "00"],
        vec!["", "--trusted-local"]]
    { assert!(parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()); }
}
