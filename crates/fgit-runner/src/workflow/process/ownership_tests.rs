//! Private procfs fixtures are scanner tests, not evidence of live containment.
//! The separate real-child tests exercise the waitable ownership boundary.
use super::*;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct ProcRoot(std::path::PathBuf);
impl ProcRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-proc-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn record(&self, pid: u32, group: u32, state: u8) {
        let directory = self.0.join(pid.to_string());
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("stat"),
            format!("{pid} (opaque ) command) {} 1 {group} 0", char::from(state)),
        )
        .unwrap();
    }
    fn inspect(&self) -> io::Result<Snapshot> {
        inspect(&self.0, 123, Instant::now() + Duration::from_secs(10))
    }
}
impl Drop for ProcRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn scan_requires_leader_and_distinguishes_live_members_from_zombies() {
    let root = ProcRoot::new();
    assert!(root.inspect().is_err());
    root.record(123, 123, b'Z');
    let alone = root.inspect().unwrap();
    assert!(!alone.other && !alone.live_other);
    root.record(42, 123, b'S');
    let running = root.inspect().unwrap();
    assert!(running.other && running.live_other);
    root.record(42, 123, b'Z');
    let zombie = root.inspect().unwrap();
    assert!(zombie.other && !zombie.live_other);
    root.record(42, 321, b'S');
    let unrelated = root.inspect().unwrap();
    assert!(!unrelated.other && !unrelated.live_other);
    root.record(123, 321, b'Z');
    assert!(root.inspect().is_err());
}

#[test]
fn scan_rejects_incomplete_identity_oversized_records_and_expired_deadlines() {
    let root = ProcRoot::new();
    root.record(123, 123, b'Z');
    assert!(root.inspect().is_ok());
    assert!(inspect(&root.0, 123, Instant::now()).is_err());
    let path = root.0.join("123/stat");
    let mut exact = fs::read(&path).unwrap();
    exact.resize(MAX_STAT_BYTES, b' ');
    fs::write(&path, &exact).unwrap();
    assert!(root.inspect().is_ok());
    exact.push(b' ');
    fs::write(&path, &exact).unwrap();
    assert!(root.inspect().is_err());
    fs::write(&path, b"124 (mismatched) Z 1 123").unwrap();
    assert!(root.inspect().is_err());
    root.record(123, 123, b'Z');
    assert!(root.inspect().is_ok());
}

#[test]
fn scan_entry_bound_accepts_exact_capacity_and_refuses_one_more() {
    let root = ProcRoot::new();
    root.record(123, 123, b'Z');
    for index in 1..MAX_PROC_ENTRIES {
        File::create(root.0.join(format!("entry-{index}"))).unwrap();
    }
    assert!(root.inspect().is_ok());
    File::create(root.0.join("one-over-limit")).unwrap();
    assert!(root.inspect().is_err());
}

fn terminal_child() -> ProcessGroup {
    let child = Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut owned = ProcessGroup::new(child);
    let end = Instant::now() + Duration::from_secs(3);
    while !owned.exited().unwrap() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    owned
}

#[test]
fn repeated_terminal_observation_keeps_pid_pinned_until_the_final_reap() {
    let mut owned = terminal_child();
    let path = format!("/proc/{}/stat", owned.pid.as_raw_pid());
    for _ in 0..16 {
        assert!(owned.exited().unwrap());
        assert!(
            fs::read(&path).is_ok(),
            "WNOWAIT must retain the leader identity"
        );
    }
    let (status, orphaned) = owned.complete().unwrap();
    assert_eq!(status.code(), Some(7));
    assert!(!orphaned);
    assert!(owned.finalized);
    assert!(owned.exited().is_err());
    assert!(
        owned.terminate().is_err(),
        "a reaped identity must never be signalled"
    );
}

#[test]
fn competing_reap_invalidates_group_ownership_instead_of_signalling_reused_ids() {
    let mut owned = terminal_child();
    assert_eq!(owned.child.wait().unwrap().code(), Some(7));
    let error = owned.exited().unwrap_err();
    assert_eq!(
        error.raw_os_error(),
        Some(rustix::io::Errno::CHILD.raw_os_error())
    );
    assert!(owned.ownership_lost);
    assert!(owned.terminate().is_err());
    assert!(owned.finalized);
}
