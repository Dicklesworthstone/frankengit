//! Private procfs fixtures are scanner tests, not evidence of live containment.
//! The separate real-child tests exercise the waitable ownership boundary.
use super::*;
use std::cell::Cell;
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
        inspect_until(&self.0, 123, Instant::now() + Duration::from_secs(10))
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
    assert!(inspect_until(&root.0, 123, Instant::now()).is_err());
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

#[derive(Clone, Copy, Debug)]
enum FaultyStat {
    Malformed,
    Oversized,
    Missing,
    OpenFailure,
    ReadFailure,
}
impl FaultyStat {
    const ALL: [Self; 5] = [
        Self::Malformed,
        Self::Oversized,
        Self::Missing,
        Self::OpenFailure,
        Self::ReadFailure,
    ];

    fn install(self, root: &ProcRoot, pid: u32) {
        let directory = root.0.join(pid.to_string());
        fs::create_dir(&directory).unwrap();
        let path = directory.join("stat");
        match self {
            Self::Malformed => fs::write(path, b"malformed stat record").unwrap(),
            Self::Oversized => fs::write(path, vec![b' '; MAX_STAT_BYTES + 1]).unwrap(),
            Self::Missing => {}
            // These fail even for a privileged test user; chmod(000) would not.
            Self::OpenFailure => std::os::unix::fs::symlink("stat", path).unwrap(),
            Self::ReadFailure => fs::create_dir(path).unwrap(),
        }
    }

    fn assert_preserved(self, error: &io::Error) {
        match self {
            Self::Malformed => assert_eq!(error.to_string(), "invalid process stat identity"),
            Self::Oversized => assert_eq!(error.to_string(), "process stat limit exceeded"),
            Self::Missing => assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::NOENT.raw_os_error())
            ),
            Self::OpenFailure => assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::LOOP.raw_os_error())
            ),
            Self::ReadFailure => assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::ISDIR.raw_os_error())
            ),
        }
    }
}

#[test]
fn failed_stat_records_require_positive_nonmembership_or_a_vanished_pid() {
    for fault in FaultyStat::ALL {
        for (membership, may_skip) in [
            (Ok(Pid::from_raw(321).unwrap()), true),
            (Err(rustix::io::Errno::SRCH), true),
            (Ok(Pid::from_raw(123).unwrap()), false),
            (Err(rustix::io::Errno::ACCESS), false),
            (Err(rustix::io::Errno::IO), false),
        ] {
            for has_live_member in [false, true] {
                let root = ProcRoot::new();
                root.record(123, 123, b'Z');
                root.record(77, 321, b'S');
                if has_live_member {
                    root.record(44, 123, b'S');
                }
                fault.install(&root, 42);
                let lookups = Cell::new(0);
                let result = inspect_with_group_lookup(&root.0, 123, &|| Ok(()), &|pid| {
                    assert_eq!(pid, 42, "intact records need no kernel lookup");
                    lookups.set(lookups.get() + 1);
                    membership
                });
                if may_skip {
                    let snapshot = result.unwrap();
                    assert_eq!(snapshot.other, has_live_member, "{fault:?}");
                    assert_eq!(snapshot.live_other, has_live_member, "{fault:?}");
                } else {
                    let Err(ScanError::Failed(error)) = result else {
                        panic!("member or unknown membership must retain {fault:?}");
                    };
                    fault.assert_preserved(&error);
                }
                assert_eq!(lookups.get(), 1, "one lookup, no deadline-reset retries");
            }
        }
    }
}

#[test]
fn failed_leader_records_never_use_an_unrelated_or_vanished_fallback() {
    for fault in FaultyStat::ALL {
        let root = ProcRoot::new();
        fault.install(&root, 123);
        let Err(ScanError::Failed(error)) =
            inspect_with_group_lookup(&root.0, 123, &|| Ok(()), &|_| {
                panic!("a pinned leader cannot be waived by another observation")
            })
        else {
            panic!("a leader's {fault:?} must remain a failure");
        };
        fault.assert_preserved(&error);
    }
}

#[test]
fn membership_fallback_preserves_cancellation_and_the_existing_deadline() {
    for reason in [CompletionStop::Cancelled, CompletionStop::TimedOut] {
        for stop_after_lookup in [false, true] {
            let root = ProcRoot::new();
            // A single failed record makes both checkpoint locations exact.
            // No partial observation is allowed to substitute for the leader.
            FaultyStat::Malformed.install(&root, 42);
            let started = Instant::now();
            let checkpoints = Cell::new(0);
            let lookups = Cell::new(0);
            let checkpoint = || {
                let count = checkpoints.get() + 1;
                checkpoints.set(count);
                let stop = if stop_after_lookup {
                    lookups.get() != 0
                } else {
                    count == 3
                };
                completion_checkpoint(
                    started + Duration::from_secs(10),
                    &|| !stop || reason != CompletionStop::Cancelled,
                    &|| {
                        started
                            + if stop && reason == CompletionStop::TimedOut {
                                Duration::from_secs(10)
                            } else {
                                Duration::ZERO
                            }
                    },
                )
            };
            assert!(matches!(
                inspect_with_group_lookup(&root.0, 123, &checkpoint, &|pid| {
                    assert_eq!(pid, 42);
                    lookups.set(lookups.get() + 1);
                    Ok(Pid::from_raw(321).unwrap())
                }),
                Err(ScanError::Stopped(stopped)) if stopped == reason
            ));
            assert_eq!(lookups.get(), usize::from(stop_after_lookup));
            assert_eq!(checkpoints.get(), if stop_after_lookup { 4 } else { 3 });
        }
    }
}

#[test]
fn kernel_group_lookup_rejects_self_and_wrapping_pid_names() {
    for pid in [0, (i32::MAX as u32) + 1, u32::MAX] {
        assert_eq!(kernel_group(pid), Err(rustix::io::Errno::INVAL));
    }
}

// frankengit-twuw: injected time advances through the real scanner, without
// pretending a fixture directory proves live process containment. Observation
// is one bounded traversal under the caller's budget, not a restart loop.
#[test]
fn completion_scan_preserves_progress_through_descheduling_within_the_caller_budget() {
    let root = ProcRoot::new();
    root.record(123, 123, b'Z');
    root.record(42, 123, b'S');
    let started = Instant::now();
    let now = Cell::new(started);
    let checkpoints = Cell::new(0);
    let checkpoint = || {
        let count = checkpoints.get() + 1;
        checkpoints.set(count);
        if count == 3 {
            // Descheduled beyond BOTH former 250ms and 3s completion windows,
            // but still within the execution time the caller already granted.
            now.set(started + Duration::from_secs(4));
        }
        completion_checkpoint(started + Duration::from_secs(10), &|| true, &|| now.get())
    };
    let live = inspect(&root.0, 123, &checkpoint).unwrap();
    assert!(live.other && live.live_other);
    assert_eq!(checkpoints.get(), 6, "one start, two per entry, one end");
    // The permitted twin: a zombie member is stopped, not live.
    root.record(42, 123, b'Z');
    let settled = inspect(&root.0, 123, &checkpoint).unwrap();
    assert!(settled.other && !settled.live_other);
    // A clean joined process has no other group member at all.
    root.record(42, 321, b'S');
    let joined = inspect(&root.0, 123, &checkpoint).unwrap();
    assert!(!joined.other && !joined.live_other);
}

#[test]
fn interrupted_scans_never_establish_quiescence_or_restart_with_a_fresh_budget() {
    let root = ProcRoot::new();
    root.record(123, 123, b'Z');
    root.record(42, 123, b'S');
    let started = Instant::now();
    for stop in [CompletionStop::Cancelled, CompletionStop::TimedOut] {
        let checkpoints = Cell::new(0);
        let checkpoint = || {
            let count = checkpoints.get() + 1;
            checkpoints.set(count);
            completion_checkpoint(
                started + Duration::from_secs(10),
                &|| count != 3 || stop != CompletionStop::Cancelled,
                &|| {
                    started
                        + if count == 3 && stop == CompletionStop::TimedOut {
                            Duration::from_secs(10)
                        } else {
                            Duration::ZERO
                        }
                },
            )
        };
        assert!(matches!(
            inspect(&root.0, 123, &checkpoint),
            Err(ScanError::Stopped(reason)) if reason == stop
        ));
        assert_eq!(checkpoints.get(), 3, "interruption must remain latched");
    }
    // The non-cancellable forced drain retains its original absolute bound.
    let error = inspect_until(&root.0, 123, Instant::now()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "process-group observation limit exceeded"
    );
    // A leader that left its group remains a definitive refusal.
    root.record(123, 321, b'Z');
    let started = Instant::now();
    let error = root.inspect().unwrap_err();
    assert_eq!(
        error.to_string(),
        "direct child left its owned process group"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
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
fn real_kernel_nonmembership_isolates_a_bad_record_without_reaping_either_child() {
    let mut owned = terminal_child();
    let mut sibling = terminal_child();
    let leader = owned.pid.as_raw_pid() as u32;
    let sibling_pid = sibling.pid.as_raw_pid() as u32;
    assert_ne!(leader, sibling_pid);
    let root = ProcRoot::new();
    root.record(leader, leader, b'Z');
    FaultyStat::Malformed.install(&root, sibling_pid);
    let snapshot = inspect(&root.0, leader, &|| Ok(())).unwrap();
    assert!(!snapshot.other && !snapshot.live_other);
    assert!(owned.exited().unwrap());
    assert!(sibling.exited().unwrap());
    assert_eq!(kernel_group(leader).unwrap(), owned.pid);
    assert_eq!(kernel_group(sibling_pid).unwrap(), sibling.pid);
    // No signal was needed. These finite no-descendant shells remain waitable
    // until their owners explicitly perform the final reap.
    assert_eq!(owned.reap().unwrap().code(), Some(7));
    assert_eq!(sibling.reap().unwrap().code(), Some(7));
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
    let completion = owned
        .complete(Instant::now() + Duration::from_secs(10), &|| true)
        .unwrap();
    assert_eq!(completion.status.code(), Some(7));
    assert!(!completion.leftover);
    assert!(completion.stopped.is_none());
    assert!(owned.finalized);
    assert!(owned.exited().is_err());
    assert!(
        owned.terminate().is_err(),
        "a reaped identity must never be signalled"
    );
}

#[test]
fn terminal_child_interruption_drains_and_preserves_the_stop_reason() {
    for reason in [CompletionStop::Cancelled, CompletionStop::TimedOut] {
        let mut owned = terminal_child();
        let pid = owned.pid.as_raw_pid();
        let deadline = Instant::now()
            + if reason == CompletionStop::TimedOut {
                Duration::ZERO
            } else {
                Duration::from_secs(10)
            };
        let completion = owned
            .complete(deadline, &|| reason != CompletionStop::Cancelled)
            .unwrap();
        assert_eq!(completion.stopped, Some(reason));
        assert_eq!(completion.status.code(), Some(7));
        assert!(!completion.leftover);
        assert!(owned.finalized);
        assert!(!Path::new(&format!("/proc/{pid}/stat")).exists());
        assert!(owned.exited().is_err());
    }
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
