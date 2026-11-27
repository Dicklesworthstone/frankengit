//! Own one freshly spawned process group until all signalling is finished.
//! The unreaped direct child pins its numeric PID/PGID. Never signal a group
//! after reaping that child: its numeric identity may then name somebody else.
//! This is trusted-host cleanup, not a sandbox for processes that escape groups.
use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, kill_process, kill_process_group, test_kill_process, waitid,
};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

const DRAIN: Duration = Duration::from_secs(3);
const MAX_PROC_ENTRIES: usize = 16_384;
const MAX_STAT_BYTES: usize = 4096;
const MAX_STATUS_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompletionStop {
    Cancelled,
    TimedOut,
}

pub(super) struct Completion {
    pub status: ExitStatus,
    pub leftover: bool,
    pub stopped: Option<CompletionStop>,
}

pub(super) struct ProcessGroup {
    child: Child,
    pid: Pid,
    finalized: bool,
    ownership_lost: bool,
}
impl ProcessGroup {
    // Caller must spawn with process_group(0), and must never independently
    // reap this child or install a competing SIGCHLD reaper.
    pub(super) fn new(child: Child) -> Self {
        let pid = Pid::from_child(&child);
        Self {
            child,
            pid,
            finalized: false,
            ownership_lost: false,
        }
    }

    pub(super) fn exited(&mut self) -> io::Result<bool> {
        if self.finalized || self.ownership_lost || self.pid.as_raw_pid() <= 1 {
            return Err(io::Error::other("process-group ownership unavailable"));
        }
        // WNOWAIT observes termination without releasing the PID anchor.
        for _ in 0..8 {
            match waitid(
                WaitId::Pid(self.pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Ok(status) => return Ok(status.is_some()),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => {
                    if error == rustix::io::Errno::CHILD {
                        self.ownership_lost = true;
                    }
                    return Err(error.into());
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "child observation repeatedly interrupted",
        ))
    }

    /// Observe normal completion within the caller's existing execution budget.
    /// A slow host does not acquire a second, shorter completion deadline, and
    /// partial scans are never discarded and restarted. Cancellation or expiry
    /// transfers to the independent bounded drain and remains a non-pass.
    /// Even successful cleanup cannot turn an orphan-producing script into a pass.
    pub(super) fn complete(
        &mut self,
        end: Instant,
        live: &dyn Fn() -> bool,
    ) -> io::Result<Completion> {
        if !self.exited()? {
            return Err(io::Error::other("process group is not ready to complete"));
        }
        match inspect(Path::new("/proc"), self.pid.as_raw_pid() as u32, &|| {
            completion_checkpoint(end, live, &Instant::now)
        }) {
            Ok(snapshot) if !snapshot.other => Ok(Completion {
                status: self.reap()?,
                leftover: false,
                stopped: None,
            }),
            Ok(_) => Ok(Completion {
                status: self.terminate()?,
                leftover: true,
                stopped: None,
            }),
            Err(ScanError::Stopped(reason)) => Ok(Completion {
                status: self.terminate()?,
                leftover: false,
                stopped: Some(reason),
            }),
            Err(ScanError::Failed(error)) => {
                let _cleanup = self.terminate();
                Err(error)
            }
        }
    }

    /// Non-cancellable bounded cleanup. Signal before reaping, and keep the
    /// leader waitable while checking that remaining group members stopped.
    /// Zombies count as stopped, NOT as descendants reaped by this owner.
    pub(super) fn terminate(&mut self) -> io::Result<ExitStatus> {
        let end = Instant::now() + DRAIN;
        let result = self.drain(end);
        self.finalized = true;
        result
    }
    fn drain(&mut self, end: Instant) -> io::Result<ExitStatus> {
        loop {
            self.exited()?;
            match kill_process_group(self.pid, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => {
                    // We still own the direct child even if group signalling
                    // failed. Reap it if possible, but preserve the group error.
                    let _direct = kill_process(self.pid, Signal::KILL);
                    let _reap = self.reap_until(end);
                    return Err(error.into());
                }
            }
            // A trusted executable may have moved the leader out of its group.
            // Kill the still-owned direct child too; never broaden to other PIDs.
            let _direct = kill_process(self.pid, Signal::KILL);
            let exited = self.exited()?;
            let snapshot = inspect_until(Path::new("/proc"), self.pid.as_raw_pid() as u32, end);
            match snapshot {
                Ok(snapshot) if exited && !snapshot.live_other => return self.reap(),
                Ok(_) => {}
                Err(error) => {
                    let _reap = self.reap_until(end);
                    return Err(error);
                }
            }
            if Instant::now() >= end {
                let _reap = self.reap_until(end);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "process-group cleanup did not settle",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn reap_until(&mut self, end: Instant) -> io::Result<ExitStatus> {
        loop {
            if self.exited()? {
                return self.reap();
            }
            if Instant::now() >= end {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "direct child did not reap",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn reap(&mut self) -> io::Result<ExitStatus> {
        // Only called after WNOWAIT reported a terminal direct child. This is
        // the FINAL process operation, whether it succeeds or ownership is lost.
        self.finalized = true;
        self.child
            .try_wait()?
            .ok_or_else(|| io::Error::other("waitable child lost its terminal status"))
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if !self.finalized && !self.ownership_lost {
            // Covers unwinding of the caller's liveness callback. The outer
            // coordinator still records unresolved containment after unwind.
            let _cleanup = self.terminate();
        }
    }
}

#[derive(Debug, Default)]
struct Snapshot {
    other: bool,
    live_other: bool,
}

/// Interruption never establishes quiescence. The process owner must drain
/// before returning a cancelled or timed-out observation.
#[derive(Debug)]
enum ScanError {
    Stopped(CompletionStop),
    Failed(io::Error),
}
impl From<io::Error> for ScanError {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}

fn completion_checkpoint(
    end: Instant,
    live: &dyn Fn() -> bool,
    now: &dyn Fn() -> Instant,
) -> Result<(), ScanError> {
    if !live() {
        Err(ScanError::Stopped(CompletionStop::Cancelled))
    } else if now() >= end {
        Err(ScanError::Stopped(CompletionStop::TimedOut))
    } else {
        Ok(())
    }
}

/// Forced cleanup has one non-cancellable drain deadline. One complete scan
/// must fit in its remaining budget; it never retries with a fresh budget.
fn inspect_until(root: &Path, leader: u32, end: Instant) -> io::Result<Snapshot> {
    match inspect(root, leader, &|| {
        completion_checkpoint(end, &|| true, &Instant::now)
    }) {
        Ok(snapshot) => Ok(snapshot),
        Err(ScanError::Stopped(_)) => {
            Err(io::Error::other("process-group observation limit exceeded"))
        }
        Err(ScanError::Failed(error)) => Err(error),
    }
}

fn inspect(
    root: &Path,
    leader: u32,
    checkpoint: &dyn Fn() -> Result<(), ScanError>,
) -> Result<Snapshot, ScanError> {
    inspect_with_group_lookup(root, leader, checkpoint, &|pid| proc_group(root, pid))
}

fn inspect_with_group_lookup(
    root: &Path,
    leader: u32,
    checkpoint: &dyn Fn() -> Result<(), ScanError>,
    group_of: &dyn Fn(u32) -> io::Result<u32>,
) -> Result<Snapshot, ScanError> {
    checkpoint()?;
    let mut snapshot = Snapshot::default();
    let mut saw_leader = false;
    for (count, entry) in fs::read_dir(root)?.enumerate() {
        if count >= MAX_PROC_ENTRIES {
            return Err(io::Error::other("process-group observation limit exceeded").into());
        }
        checkpoint()?;
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let observed = read_stat(&entry.path().join("stat"), pid);
        checkpoint()?;
        let (group, state) = match observed {
            Ok(record) => record,
            Err(error) => {
                // Procfs includes unrelated host processes. A failed record
                // does not invalidate this group's observation when the kernel
                // independently proves that PID absent or in another group.
                // Never waive a pinned leader's failure, a member's failure or
                // an unknown membership. Keep the original diagnostic in those
                // cases; this lookup cannot prove a member stopped or reap it.
                if pid == leader {
                    return Err(error.into());
                }
                let group = group_of(pid);
                checkpoint()?;
                if outside_group(group, leader) {
                    continue;
                }
                return Err(error.into());
            }
        };
        if pid == leader {
            saw_leader = true;
            if group != leader {
                return Err(io::Error::other("direct child left its owned process group").into());
            }
        } else if group == leader {
            snapshot.other = true;
            snapshot.live_other |= !matches!(state, b'Z' | b'X');
        }
    }
    if !saw_leader {
        return Err(io::Error::other("incomplete process-group observation").into());
    }
    checkpoint()?;
    Ok(snapshot)
}

fn outside_group(membership: io::Result<u32>, leader: u32) -> bool {
    match membership {
        Ok(group) => group != leader,
        Err(error) => error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()),
    }
}

fn proc_group(root: &Path, pid: u32) -> io::Result<u32> {
    let process = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or(rustix::io::Errno::INVAL)?;
    // Kernel entries can have group zero. Procfs can represent that value;
    // rustix's getpgid API returns a strictly positive Pid.
    let mut bytes = [0; MAX_STATUS_BYTES + 1];
    let path = root.join(pid.to_string()).join("status");
    let group = read_proc_file(&path, &mut bytes, "process status limit exceeded")
        .and_then(|len| status_group(&bytes[..len], pid));
    match group {
        Err(_) if test_kill_process(process) == Err(rustix::io::Errno::SRCH) => {
            Err(rustix::io::Errno::SRCH.into())
        }
        _ => group,
    }
}

fn status_group(bytes: &[u8], expected: u32) -> io::Result<u32> {
    let bad = || io::Error::other("invalid process status group identity");
    let number = |field: &[u8]| {
        let first = field
            .split(|b| b.is_ascii_whitespace())
            .find(|s| !s.is_empty())?;
        std::str::from_utf8(first).ok()?.parse::<u32>().ok()
    };
    let mut pid = None;
    let mut group = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        let (field, slot) = if let Some(field) = line.strip_prefix(b"Pid:") {
            (field, &mut pid)
        } else if let Some(field) = line.strip_prefix(b"NSpgid:") {
            // The first value is relative to the procfs mount, just like stat.
            (field, &mut group)
        } else {
            continue;
        };
        if slot.replace(number(field).ok_or_else(bad)?).is_some() {
            return Err(bad());
        }
    }
    if pid != Some(expected) {
        return Err(bad());
    }
    group.ok_or_else(bad)
}

fn read_stat(path: &Path, pid: u32) -> io::Result<(u32, u8)> {
    let mut bytes = [0; MAX_STAT_BYTES + 1];
    let len = read_proc_file(path, &mut bytes, "process stat limit exceeded")?;
    stat(&bytes[..len], pid)
}

fn read_proc_file(path: &Path, bytes: &mut [u8], limit: &'static str) -> io::Result<usize> {
    let mut file = File::open(path)?;
    let mut len = 0;
    while len < bytes.len() {
        match file.read(&mut bytes[len..]) {
            Ok(0) => return Ok(len),
            Ok(count) => len += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other(limit))
}

fn stat(bytes: &[u8], expected: u32) -> io::Result<(u32, u8)> {
    let bad = || io::Error::other("invalid process stat identity");
    let start = bytes.windows(2).position(|p| p == b" (").ok_or_else(bad)?;
    let pid = std::str::from_utf8(&bytes[..start])
        .map_err(|_| bad())?
        .parse::<u32>()
        .map_err(|_| bad())?;
    let close = bytes
        .iter()
        .rposition(|b| *b == b')')
        .filter(|close| *close > start)
        .ok_or_else(bad)?;
    if pid != expected {
        return Err(bad());
    }
    let mut fields = bytes[close + 1..]
        .split(|b| b.is_ascii_whitespace())
        .filter(|s| !s.is_empty());
    let state = fields.next().filter(|s| s.len() == 1).ok_or_else(bad)?[0];
    fields.next().ok_or_else(bad)?;
    let group = std::str::from_utf8(fields.next().ok_or_else(bad)?)
        .map_err(|_| bad())?
        .parse::<u32>()
        .map_err(|_| bad())?;
    Ok((group, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stat_names_are_opaque_and_group_identity_is_exact() {
        assert_eq!(
            stat(b"123 (spaces ) and\nnewlines) S 9 123 123 0", 123).unwrap(),
            (123, b'S')
        );
        assert_eq!(stat(b"44 (finished) Z 1 123 0", 44).unwrap(), (123, b'Z'));
        for bytes in [
            b"124 (wrong) S 1 123".as_slice(),
            b"123 no-name S 1 123",
            b"123 (bad) SS 1 123",
            b"123 (bad) S 1 nope",
        ] {
            assert!(stat(bytes, 123).is_err());
        }
    }
}

#[cfg(test)]
#[path = "ownership_tests.rs"]
mod ownership_tests;
