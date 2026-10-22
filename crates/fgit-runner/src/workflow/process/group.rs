//! Own one freshly spawned process group until all signalling is finished.
//! The unreaped direct child pins its numeric PID/PGID. Never signal a group
//! after reaping that child: its numeric identity may then name somebody else.
//! This is trusted-host cleanup, not a sandbox for processes that escape groups.
use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, kill_process, kill_process_group, waitid,
};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

const DRAIN: Duration = Duration::from_secs(3);
const SCAN: Duration = Duration::from_millis(250);
const MAX_PROC_ENTRIES: usize = 16_384;
const MAX_STAT_BYTES: usize = 4096;

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
                Err(rustix::io::Errno::INTR) => continue,
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

    /// Returns whether completion found leftover group members. Even successful
    /// cleanup cannot retroactively turn an orphan-producing script into a pass.
    pub(super) fn complete(&mut self) -> io::Result<(ExitStatus, bool)> {
        if !self.exited()? {
            return Err(io::Error::other("process group is not ready to complete"));
        }
        match inspect_until(
            Path::new("/proc"),
            self.pid.as_raw_pid() as u32,
            Instant::now() + DRAIN,
            SCAN,
        ) {
            Ok(snapshot) if !snapshot.other => Ok((self.reap()?, false)),
            Ok(_) => Ok((self.terminate()?, true)),
            Err(error) => {
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
            let snapshot =
                inspect_until(Path::new("/proc"), self.pid.as_raw_pid() as u32, end, SCAN);
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

/// A scan that outlived its window says nothing about the group: a busy host
/// can simply deschedule it. Every other failure is a definitive refusal.
#[derive(Debug)]
enum ScanError {
    Expired,
    Failed(io::Error),
}
impl From<io::Error> for ScanError {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}

/// Retry expired scans, doubling the window, until `end`; refuse at once on a
/// definitive failure. Quiescence still has to be proved by one complete scan
/// (frankengit-twuw).
fn inspect_until(
    root: &Path,
    leader: u32,
    end: Instant,
    first_window: Duration,
) -> io::Result<Snapshot> {
    let mut window = first_window;
    loop {
        match inspect(root, leader, end.min(Instant::now() + window)) {
            Ok(snapshot) => return Ok(snapshot),
            Err(ScanError::Expired) if Instant::now() < end => {
                window = window.saturating_mul(2).max(Duration::from_millis(1));
            }
            Err(ScanError::Expired) => {
                return Err(io::Error::other("process-group observation limit exceeded"));
            }
            Err(ScanError::Failed(error)) => return Err(error),
        }
    }
}

fn inspect(root: &Path, leader: u32, end: Instant) -> Result<Snapshot, ScanError> {
    let mut snapshot = Snapshot::default();
    let mut saw_leader = false;
    for (count, entry) in fs::read_dir(root)?.enumerate() {
        if count >= MAX_PROC_ENTRIES {
            return Err(io::Error::other("process-group observation limit exceeded").into());
        }
        if Instant::now() >= end {
            return Err(ScanError::Expired);
        }
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
        let file = match File::open(entry.path().join("stat")) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        if let Err(error) = file
            .take((MAX_STAT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
        {
            // procfs can return ESRCH after a process vanishes during the read.
            if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) {
                continue;
            }
            return Err(error.into());
        }
        if bytes.len() > MAX_STAT_BYTES {
            return Err(io::Error::other("process stat limit exceeded").into());
        }
        let (group, state) = stat(&bytes, pid)?;
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
    if Instant::now() >= end {
        return Err(ScanError::Expired);
    }
    Ok(snapshot)
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
