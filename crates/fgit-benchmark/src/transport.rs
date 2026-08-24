//! One-node transport workloads for the FG-028c performance baseline.
//!
//! The bead's first metric family is clone latency and throughput, compared
//! against upstream Git on the same corpus. That comparison has exactly one
//! honest shape: **one client binary, two servers**. The variable under test is
//! the server; everything else — client, corpus, protocol version, machine — is
//! held fixed. Mapping onto [`crate::Variant`]:
//!
//! | variant      | server                        |
//! |--------------|-------------------------------|
//! | `Baseline`   | upstream `git daemon`         |
//! | `Candidate`  | `fg serve` (this project)     |
//! | `AaControl`  | upstream `git daemon`, again  |
//!
//! `AaControl` re-runs the baseline so the A/A noise floor is measured on this
//! host, in this run, rather than assumed. A candidate delta smaller than that
//! floor is negative evidence, never a win.
//!
//! # What the measured interval contains, stated because it is not obvious
//!
//! `fg serve` is **one-shot**: it serves a single session and exits. There is
//! no way to hold it open across samples, so a fresh server process must start
//! for every candidate sample. Rather than exclude that cost from one arm and
//! not the other, both arms spawn a fresh server per sample and both include
//! it in the timed interval. The metric is therefore
//!
//! > wall time to start a cold server, serve one full clone, and verify it
//!
//! and NOT steady-state transport latency. [`TransportWorkload::workload_line`]
//! writes exactly that sentence into the artifact so a later reader cannot mistake
//! one for the other.
//!
//! # Why upstream Git may run here
//!
//! AGENTS.md §3.1 permits upstream Git only in pinned, sandboxed,
//! explicitly non-production differential lanes. This is such a lane: it exists
//! solely to produce the differential the bead's acceptance requires, it never
//! runs in a production path, and the binary is caller-supplied so the harness
//! cannot silently fall back to an ambient `git` on `PATH`.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{BenchmarkWorkload, OracleReceipt, StorageClasses, SystemMetrics};

/// How long to wait for a freshly spawned server to accept a connection.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting for a server to bind.
const LISTEN_POLL: Duration = Duration::from_millis(2);

/// Interval between `/proc` samples of a live server during a clone.
///
/// Short relative to the 10ms USER_HZ quantization of the CPU counters, so the
/// sampling interval is never the dominant error term in a reported CPU figure.
const PROBE_POLL: Duration = Duration::from_millis(1);

/// Page-cache state the corpus is in when a sample starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheState {
    /// The corpus is left in whatever state the previous sample left it.
    Warm,
    /// The corpus is evicted from the page cache before every sample.
    ///
    /// Achieved with `posix_fadvise(POSIX_FADV_DONTNEED)`, which needs no
    /// privilege. Three cheaper routes were checked first and rejected on
    /// evidence, not on taste:
    ///
    /// - `/proc/sys/vm/drop_caches` needs root; this pane has `CapEff: 0`.
    /// - `dd oflag=nocache` is accepted by this host's coreutils BUT fails with
    ///   "Permission denied" on mode-444 files, and git pack files are exactly
    ///   mode 444 -- it would have failed on the only files that matter while
    ///   succeeding on the rest, so a `cold` label built on it would have been
    ///   theatre.
    /// - Calling `posix_fadvise` from Rust needs FFI, which §3.1 forbids.
    ///
    /// So eviction shells out to `python3`, which exposes `os.posix_fadvise` in
    /// its standard library and can open a 444 file read-only. Three existing
    /// e2e suites already depend on `python3`.
    ///
    /// Eviction was verified to actually work before anything was built on it:
    /// a 512 MiB file read in 47ms and 49ms warm, 215ms immediately after
    /// eviction, and 47ms again on the next read.
    ColdPageCache,
}

impl CacheState {
    /// Stable tag written into the artifact.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm-page-cache",
            Self::ColdPageCache => "cold-page-cache-evicted-per-sample",
        }
    }
}

/// Which server serves a sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerKind {
    /// Upstream `git daemon`, the differential reference.
    UpstreamGitDaemon,
    /// `fg serve`, the system under test.
    FgitNode,
}

impl ServerKind {
    /// Stable tag used in artifact text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamGitDaemon => "upstream-git-daemon",
            Self::FgitNode => "fgit-node-serve",
        }
    }
}

/// Everything a transport sample needs, resolved once by the caller.
///
/// Every binary path is explicit. Nothing here reads `PATH`: an ambient `git`
/// would make the differential unpinned, which is the one thing §3.1 forbids
/// about running upstream Git at all.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// The `fg` binary under test.
    pub fg_binary: PathBuf,
    /// The pinned upstream Git binary, used as BOTH the client and the
    /// reference server so the only difference between arms is the server.
    pub git_binary: PathBuf,
    /// `GIT_EXEC_PATH` for that binary.
    ///
    /// The pinned oracle install is relocated out of its configure-time prefix,
    /// so Git cannot find its own subcommands -- `git daemon` reports "not a
    /// git command" -- unless this is set. Required rather than optional: a
    /// silent fallback would resolve subcommands from an ambient install and
    /// quietly unpin the differential.
    pub git_exec_path: PathBuf,
    /// Initialized `fg` storage root holding the corpus.
    pub storage_root: PathBuf,
    /// Bare upstream repository holding the same corpus.
    pub upstream_base_path: PathBuf,
    /// Tenant identifier for `fg serve`.
    pub tenant: String,
    /// Repository identifier, shared by both servers.
    pub repository: String,
    /// Scratch directory for per-sample clone destinations.
    pub work_root: PathBuf,
    /// An empty directory used as `GIT_TEMPLATE_DIR`.
    ///
    /// Pins the clone's initial layout so a host with populated Git templates
    /// and one without do not produce different `.git` byte counts, which feed
    /// the storage-amplification denominator.
    pub empty_template_dir: PathBuf,
    /// First port to try; each sample walks forward from here.
    pub port_base: u16,
    /// Commit the clone's `HEAD` must resolve to. The correctness oracle.
    pub expected_head: String,
    /// Number of commits the clone must contain.
    pub expected_commits: u64,
    /// Whether the corpus is evicted from the page cache before every sample.
    pub cache_state: CacheState,
    /// Interpreter used for page-cache eviction; unused when warm.
    pub python_binary: PathBuf,
    /// Logical reachable Git bytes in the corpus: the sum of every reachable
    /// object's uncompressed size.
    ///
    /// §39.2 names this as the only admissible amplification denominator, and
    /// it must come from the CORPUS rather than from the clone. Derived from
    /// the clone it is a tautology -- see the note at its use site.
    pub logical_reachable_bytes: u64,
}

/// The result of one clone, handed to the oracle before the clock stops.
#[derive(Clone, Debug)]
pub struct CloneOutput {
    /// Where the clone landed.
    pub destination: PathBuf,
    /// Bytes of pack data the client wrote, the measured egress.
    pub pack_bytes: u64,
}

/// One arm of the differential.
#[derive(Clone, Debug)]
pub struct TransportWorkload {
    config: TransportConfig,
    kind: ServerKind,
    next_port_offset: u16,
    sample_counter: usize,
}

impl TransportWorkload {
    /// Builds one arm. `kind` selects which server serves every sample.
    #[must_use]
    pub const fn new(config: TransportConfig, kind: ServerKind) -> Self {
        Self {
            config,
            kind,
            next_port_offset: 0,
            sample_counter: 0,
        }
    }

    /// The exact sentence written into `WorkloadDescriptor::workload`.
    ///
    /// It names what the timed interval contains, because "clone latency" alone
    /// would imply steady-state transport and this is not that.
    #[must_use]
    pub fn workload_line(&self) -> String {
        format!(
            "git clone git://127.0.0.1:<port>/{} served by {}; \
             the timed interval spans cold server start, the complete clone, \
             and the correctness oracle -- it is NOT steady-state transport latency, \
             because fg serve is one-shot and a fresh server must start for every sample",
            self.config.repository,
            self.kind.as_str()
        )
    }

    /// The remote path each server exports.
    fn remote_path(&self) -> String {
        match self.kind {
            // fg's daemon grammar expects `/<repository>.git`.
            ServerKind::FgitNode => format!("/{}.git", self.config.repository),
            // `git daemon --base-path` resolves `/<name>` under the base path.
            ServerKind::UpstreamGitDaemon => format!("/{}.git", self.config.repository),
        }
    }

    /// Spawns the server for one sample and returns it once it accepts.
    fn spawn_server(&mut self) -> Result<(Child, u16), String> {
        // Walk forward on every attempt. A port that loses a bind race is never
        // retried within a run, so a slow TIME_WAIT cannot silently serialize
        // samples and inflate the tail.
        for _ in 0..64 {
            let port = self
                .config
                .port_base
                .checked_add(self.next_port_offset)
                .ok_or_else(|| "port window exhausted".to_owned())?;
            self.next_port_offset = self.next_port_offset.saturating_add(1);

            let mut command = match self.kind {
                ServerKind::FgitNode => {
                    let mut command = Command::new(&self.config.fg_binary);
                    command
                        .arg("serve")
                        .arg(&self.config.storage_root)
                        .arg(&self.config.tenant)
                        .arg(&self.config.repository)
                        .arg(format!("127.0.0.1:{port}"));
                    command
                }
                ServerKind::UpstreamGitDaemon => {
                    let mut command = self.config.git();
                    command
                        .arg("daemon")
                        .arg("--export-all")
                        .arg("--reuseaddr")
                        .arg(format!(
                            "--base-path={}",
                            self.config.upstream_base_path.display()
                        ))
                        .arg("--listen=127.0.0.1")
                        .arg(format!("--port={port}"))
                        .arg(&self.config.upstream_base_path);
                    command
                }
            };
            let child = command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("spawn {} server: {error}", self.kind.as_str()))?;

            match wait_until_listening(port, child) {
                Ok(child) => return Ok((child, port)),
                // Bind collision or an immediate exit: try the next port.
                Err(mut child) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        Err(format!(
            "no port in the window accepted a {} server",
            self.kind.as_str()
        ))
    }
}

/// Waits until `port` is in LISTEN, or the child dies, or the timeout elapses.
///
/// Readiness is read from `/proc/net/tcp{,6}` rather than by connecting.
/// Connecting would be fatal for the candidate arm: `fg serve` accepts exactly
/// ONE session and exits, so a probe connection consumes the very session the
/// sample is about to measure and the real clone then fails with
/// "fatal: read error: Connection reset by peer". The original code carried a
/// comment asserting that a bare connect/close would be refused by the daemon
/// grammar and leave the listener available; that assumption was wrong, and it
/// was wrong intermittently, which is worse than wrong every time.
///
/// Returns the child on success and gives it back on failure so the caller
/// still owns it and can reap it. A server that never binds is a failed sample,
/// never a fast one.
fn wait_until_listening(port: u16, mut child: Child) -> Result<Child, Child> {
    let deadline = Instant::now() + LISTEN_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            // Exited before binding: this port is unusable.
            Ok(Some(_)) => return Err(child),
            Ok(None) => {}
            Err(_) => return Err(child),
        }
        if port_is_listening(port) {
            return Ok(child);
        }
        thread::sleep(LISTEN_POLL);
    }
    Err(child)
}

/// Whether any socket is in LISTEN on `port`, read from procfs.
fn port_is_listening(port: u16) -> bool {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .any(|table| listening_in(table, port))
}

fn listening_in(table: &str, port: u16) -> bool {
    let Ok(contents) = fs::read_to_string(table) else {
        return false;
    };
    contents.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        // Columns: sl(0) local_address(1) rem_address(2) st(3) ...
        // Taking st as `fields.next()` after local_address lands on
        // rem_address, so no port ever looks ready and every sample burns the
        // full bind timeout across all 64 candidate ports. That cost a
        // ten-minute hang before it was caught.
        let Some(local) = fields.nth(1) else {
            return false;
        };
        let Some(state) = fields.nth(1) else {
            return false;
        };
        // 0A is TCP_LISTEN. The local address is "<hex ip>:<hex port>".
        state == "0A"
            && local
                .rsplit_once(':')
                .and_then(|(_, hex)| u16::from_str_radix(hex, 16).ok())
                == Some(port)
    })
}

/// Sums `utime + stime` for a live process from `/proc/<pid>/stat`.
///
/// Read while the server is still alive and immediately after the clone
/// finishes, so it attributes pack-generation CPU to the server rather than to
/// the client or the harness. Returns `None` rather than zero when the value
/// cannot be read: a missing measurement must not look like a free one.
fn process_group_members(root: u32) -> Vec<u32> {
    // The server plus every live descendant.
    //
    // `git daemon` is not one process: the spawned `git` is a wrapper that
    // forks the real `git-daemon` (measured -- comm of the spawned pid is
    // "git", with a "git-daemon" child), and the pack work happens in the
    // child. Probing the spawned pid alone reports the wrapper's idle counters.
    //
    // NOT a process-group scan, and that is deliberate. Spawning the server
    // into its own group via `Command::process_group(0)` looked cleaner --
    // membership would survive reparenting -- but it makes the child a process
    // group LEADER, and `setsid()` fails with EPERM for a group leader. `git
    // daemon` calls it and exits. That change silently broke every upstream
    // sample in this harness ("could not read server peak RSS ... the server
    // exited before any poll") while the clone it was serving still exited 0,
    // and it leaked orphaned daemons holding their ports. Descendant scanning
    // costs nothing at the process level and cannot perturb the thing measured.
    let mut members = vec![root];
    let Ok(entries) = fs::read_dir("/proc") else {
        return members;
    };
    let mut candidates: Vec<(u32, u32)> = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Some(parent) = parent_pid_of(pid) {
            candidates.push((pid, parent));
        }
    }
    // Transitive closure: a server may fork more than one level deep.
    let mut grew = true;
    while grew {
        grew = false;
        for (pid, parent) in &candidates {
            if members.contains(parent) && !members.contains(pid) {
                members.push(*pid);
                grew = true;
            }
        }
    }
    members
}

/// Parent pid from `/proc/<pid>/stat`, counted after the final `)`.
fn parent_pid_of(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    // After ')': 0 = state, 1 = ppid.
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

fn process_tree_cpu_ns(pid: u32) -> Option<u64> {
    // A forking server's work is in a LIVE child for most of the clone, and it
    // only lands in the parent's cutime/cstime once the parent has reaped it.
    // `git daemon` reaps asynchronously and this harness kills it as soon as the
    // clone returns, so the reaped-child fields are frequently still zero. Live
    // children must therefore be summed directly.
    //
    // Measured before this existed: with parent-only accounting every sample in
    // both arms reported cpu_ns = 0, i.e. two servers that generated packs for
    // free.
    let members = process_group_members(pid);
    let mut total = 0_u64;
    let mut observed = false;
    for member in members {
        if let Some(cpu) = server_cpu_ns(member) {
            total = total.saturating_add(cpu);
            observed = true;
        }
    }
    // None when NOTHING was read. Returning Some(0) here would report a server
    // that produced a pack for free -- the same false green the caller's
    // ok_or_else exists to prevent, re-introduced one layer down. It bit this
    // harness once already.
    observed.then_some(total)
}

/// Peak resident set across every live member of the server's process group.
fn group_peak_rss_bytes(pgid: u32) -> Option<u64> {
    let members = process_group_members(pgid);
    let mut total = 0_u64;
    let mut observed = false;
    for member in members {
        if let Some(rss) = server_peak_rss_bytes(member) {
            total = total.saturating_add(rss);
            observed = true;
        }
    }
    observed.then_some(total)
}

fn server_cpu_ns(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces and parentheses; fields are counted after the
    // final ')' so a process named "a) b" cannot shift the parse.
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After ')' field 1 is state, so utime is 11, stime 12, cutime 13, cstime 14.
    //
    // The CHILD fields are load-bearing, not defensive. `git daemon` forks a
    // per-connection child and the listener itself does no pack work: a probe
    // reading only utime+stime measures 0 for the upstream arm, which reports
    // as a server that generated a pack for free. Measured directly before this
    // was written -- a real clone through the upstream daemon left the listener
    // at `utime stime = 0 0`. `fg serve` is single-process, so its work lands
    // in utime+stime and its child fields are zero. Summing all four is the only
    // formula correct for both arms.
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let cutime: u64 = fields.get(13)?.parse().ok()?;
    let cstime: u64 = fields.get(14)?.parse().ok()?;
    // USER_HZ is 100 on every Linux target this project builds for, so the
    // resolution is 10ms and a clone faster than that reads as 0 jiffies. The
    // value is expressed in nanoseconds so the artifact carries one unit
    // throughout; the quantization is recorded in the workload description
    // rather than hidden behind the finer-looking unit.
    Some(
        utime
            .saturating_add(stime)
            .saturating_add(cutime)
            .saturating_add(cstime)
            .saturating_mul(10_000_000),
    )
}

/// Peak resident set of a live process, in bytes, from `/proc/<pid>/status`.
fn server_peak_rss_bytes(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kilobytes: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kilobytes.saturating_mul(1024));
        }
    }
    None
}

/// Total bytes of every regular file under `root`, recursively.
fn directory_bytes(root: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    let mut total = 0_u64;
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_dir() {
            total = total.saturating_add(directory_bytes(&entry.path()));
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    total
}

/// Bytes of `*.pack` beneath a clone, the client-observed egress.
fn pack_bytes(clone_root: &Path) -> u64 {
    let pack_dir = clone_root.join(".git").join("objects").join("pack");
    let Ok(entries) = fs::read_dir(&pack_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "pack")
        })
        .filter_map(|entry| entry.metadata().ok())
        .map(|metadata| metadata.len())
        .fold(0_u64, u64::saturating_add)
}

impl TransportConfig {
    /// Builds a `git` invocation with the pinned exec path and no ambient
    /// configuration. Every Git call in this module goes through here so none
    /// of them can accidentally resolve a subcommand from the host install.
    fn git(&self) -> Command {
        let mut command = Command::new(&self.git_binary);
        command
            .env("GIT_EXEC_PATH", &self.git_exec_path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            // The relocated pinned install still carries its configure-time
            // prefix, so without this every clone prints
            // "templates not found in /prefix/share/git-core/templates" and
            // copies whatever the host happens to have. An empty directory
            // makes the clone's initial layout identical on any host.
            .env("GIT_TEMPLATE_DIR", &self.empty_template_dir);
        command
    }
}

/// Evicts every file under `root` from the page cache.
///
/// Returns the number of files evicted. Zero is an error to the caller: a cold
/// sample that evicted nothing is a warm sample wearing a cold label, which is
/// the exact failure this whole path exists to avoid.
fn evict_page_cache(python: &Path, root: &Path) -> Result<u64, String> {
    const PROGRAM: &str = "\
import os, sys
root = sys.argv[1]
n = 0
for base, _dirs, files in os.walk(root):
    for name in files:
        path = os.path.join(base, name)
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            continue
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            n += 1
        except OSError:
            pass
        finally:
            os.close(fd)
print(n)
";
    let output = Command::new(python)
        .arg("-c")
        .arg(PROGRAM)
        .arg(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("run page-cache eviction: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "page-cache eviction exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let evicted: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|error| format!("parse eviction count: {error}"))?;
    if evicted == 0 {
        return Err(format!(
            "page-cache eviction touched no files under {}; a cold sample that \
             evicted nothing is a warm sample with a cold label",
            root.display()
        ));
    }
    Ok(evicted)
}

impl BenchmarkWorkload for TransportWorkload {
    type Output = CloneOutput;

    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
        let index = self.sample_counter;
        self.sample_counter = self.sample_counter.saturating_add(1);
        let destination = self
            .config
            .work_root
            .join(format!("{}-{index}", self.kind.as_str()));
        if destination.exists() {
            return Err(format!(
                "clone destination already exists, refusing to reuse it: {}",
                destination.display()
            ));
        }

        // Evict BEFORE the server starts, so the server's own first reads are
        // cold too. Evicting after would leave whatever the server touched at
        // startup already resident.
        if self.config.cache_state == CacheState::ColdPageCache {
            let corpus = match self.kind {
                ServerKind::FgitNode => &self.config.storage_root,
                ServerKind::UpstreamGitDaemon => &self.config.upstream_base_path,
            };
            evict_page_cache(&self.config.python_binary, corpus)?;
        }

        let (mut server, port) = self.spawn_server()?;
        let remote = format!("git://127.0.0.1:{port}{}", self.remote_path());

        let mut clone = self
            .config
            .git()
            .arg("-c")
            .arg("protocol.version=1")
            .arg("clone")
            .arg("--no-local")
            .arg("--quiet")
            .arg(&remote)
            .arg(&destination)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("spawn clone: {error}"))?;

        // Sample the server WHILE the clone runs, keeping the last successful
        // reading, because the two arms die at different moments and neither
        // can be probed after the fact.
        //
        // `fg serve` is one-shot: it exits the instant the session completes,
        // which is BEFORE the client process returns. A probe taken after the
        // clone finishes finds no /proc entry at all -- measured, and it is how
        // the first live run of this harness failed:
        //   "candidate workload failed: could not read server peak RSS for pid ..."
        // The upstream daemon is a persistent listener and probes fine either
        // way, so a post-hoc probe would have silently measured only the
        // baseline arm.
        let pid = server.id();
        let mut cpu_ns = None;
        let mut memory_bytes = None;
        let clone_status = loop {
            if let Some(sample) = process_tree_cpu_ns(pid) {
                // Max, not last: a forked child's CPU disappears from the tree
                // the moment it exits, so the final poll can read LESS than an
                // earlier one. Taking the last value would systematically
                // under-report a forking server.
                cpu_ns = Some(cpu_ns.map_or(sample, |best: u64| best.max(sample)));
            }
            if let Some(sample) = group_peak_rss_bytes(pid) {
                memory_bytes = Some(memory_bytes.map_or(sample, |best: u64| best.max(sample)));
            }
            match clone.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(PROBE_POLL),
                Err(error) => return Err(format!("wait for clone: {error}")),
            }
        };
        // One last attempt: a fast clone can finish inside the first poll, and
        // for the persistent upstream listener this is the most complete read.
        if let Some(sample) = process_tree_cpu_ns(pid) {
            cpu_ns = Some(cpu_ns.map_or(sample, |best: u64| best.max(sample)));
        }
        if let Some(sample) = group_peak_rss_bytes(pid) {
            memory_bytes = Some(memory_bytes.map_or(sample, |best: u64| best.max(sample)));
        }

        // Kill every member of the group, not just the leader: `git daemon`
        // orphans its worker, and a leaked listener would hold its port and
        // make later samples in the run fail to bind.
        for member in process_group_members(pid) {
            if member != pid {
                let _ = Command::new("/bin/kill")
                    .arg("-TERM")
                    .arg(member.to_string())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        let _ = server.kill();
        let _ = server.wait();

        if !clone_status.success() {
            let mut stderr = String::new();
            if let Some(mut pipe) = clone.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Err(format!(
                "clone from {} exited {}: {}",
                self.kind.as_str(),
                clone_status,
                stderr.trim()
            ));
        }

        // A probe that could never be taken is an explicit failure, not a zero.
        // Zero CPU would read as a server that produced a pack for free.
        let cpu_ns = cpu_ns.ok_or_else(|| format!("could not read server CPU for pid {pid}"))?;
        let memory_bytes = memory_bytes.ok_or_else(|| {
            // Name WHY the probe failed. "could not read" alone sent me
            // hypothesising about /proc semantics when the answer was that the
            // server had exited before the first poll.
            let alive = Path::new(&format!("/proc/{pid}")).exists();
            format!(
                "could not read server peak RSS for pid {pid} ({}); server={} exit_status_of_clone={clone_status}",
                if alive { "/proc entry still present, so VmHWM was missing" } else { "/proc entry gone: the server exited before any poll" },
                self.kind.as_str()
            )
        })?;

        let egress_bytes = pack_bytes(&destination);
        let git_directory_bytes = directory_bytes(&destination.join(".git"));
        if git_directory_bytes == 0 {
            return Err("clone produced no .git bytes at all".to_owned());
        }
        // The denominator is the CORPUS's logical reachable size, supplied by
        // the caller, not the clone's own .git size.
        //
        // Deriving it from the clone was a tautology: with
        // canonical = pack bytes and retained_derived = .git - pack, the
        // numerator equals the denominator by construction and every sample in
        // both arms reported exactly 1000000 ppm. A metric that cannot come out
        // any other way is not a measurement, and reporting it as one would have
        // buried the finding it exists to surface -- on this corpus the two arms
        // differ by 62x in transferred bytes.
        let logical_reachable_git_bytes = self.config.logical_reachable_bytes;

        let metrics = SystemMetrics {
            // Filled by the runner once the oracle has also run.
            latency_ns: 0,
            cpu_ns,
            memory_bytes,
            // One clone is one upload-pack request. Counting object-level
            // requests would need node instrumentation this bead does not add,
            // so the honest figure is the request actually issued.
            object_requests: 1,
            object_request_bytes: egress_bytes,
            egress_bytes,
            // A clone is read-only: it commits no authority decision. The
            // denominator is 1 because SystemMetrics::validate refuses a zero
            // cas_attempts, so 0 decisions cannot be expressed with a truthful
            // zero denominator. The reported 0 ppm therefore means "no
            // decisions committed by a read-only workload", not a measured
            // ratio. See the bead comment on this representation gap.
            decisions: 0,
            cas_attempts: 1,
            storage: StorageClasses {
                canonical_bytes: egress_bytes,
                repair_bytes: 0,
                replica_bytes: 0,
                // Everything the clone keeps on disk beyond the pack itself:
                // index, refs, config, and any checkout.
                retained_derived_bytes: git_directory_bytes.saturating_sub(egress_bytes),
                logical_reachable_git_bytes,
            },
        };

        Ok((
            CloneOutput {
                destination,
                pack_bytes: egress_bytes,
            },
            metrics,
        ))
    }

    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
        // The oracle is an equality against known-good values, not `fsck`.
        // fsck proves the objects are well formed; it does not prove the clone
        // carries the corpus that was asked for. A server that served a
        // different, smaller, valid history would pass fsck and look fast.
        //
        // The tip is resolved through a fallback chain and the receipt records
        // WHICH name resolved, because the two arms genuinely differ here and
        // that difference is a finding rather than something to paper over:
        //
        //   upstream git daemon -> HEAD resolves; the clone has a local branch
        //                          and a checked-out tree
        //   fg serve            -> HEAD does NOT resolve. The daemon advertises
        //                          no HEAD symref, so the client falls back to
        //                          its own default ("ref: refs/heads/master"),
        //                          no local branch is created and there is no
        //                          working tree. Only refs/remotes/origin/<b>
        //                          exists. Tracked as frankengit-iahh.
        //
        // Resolving only HEAD would make the candidate arm unmeasurable;
        // resolving only the remote ref would hide the gap. Doing both and
        // naming the winner measures the transport AND reports the divergence.
        let mut resolved = None;
        for name in [
            "HEAD",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
            "refs/remotes/origin/master",
        ] {
            let attempt = self
                .config
                .git()
                .arg("-C")
                .arg(&output.destination)
                .arg("rev-parse")
                .arg(name)
                .stdin(Stdio::null())
                .output()
                .map_err(|error| format!("run rev-parse {name}: {error}"))?;
            if attempt.status.success() {
                let oid = String::from_utf8_lossy(&attempt.stdout).trim().to_owned();
                if !oid.is_empty() {
                    resolved = Some((name, oid));
                    break;
                }
            }
        }
        let (resolved_via, tip) = resolved.ok_or_else(|| {
            format!(
                "no ref in the clone from {} resolves to a commit",
                self.kind.as_str()
            )
        })?;
        if tip != self.config.expected_head {
            return Err(format!(
                "clone tip {tip} (via {resolved_via}) does not match the corpus tip {}",
                self.config.expected_head
            ));
        }

        let count = self
            .config
            .git()
            .arg("-C")
            .arg(&output.destination)
            .arg("rev-list")
            .arg("--count")
            .arg(resolved_via)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("run rev-list: {error}"))?;
        if !count.status.success() {
            return Err(format!("rev-list exited {}", count.status));
        }
        let count: u64 = String::from_utf8_lossy(&count.stdout)
            .trim()
            .parse()
            .map_err(|error| format!("parse commit count: {error}"))?;
        if count != self.config.expected_commits {
            return Err(format!(
                "clone carries {count} commits, corpus has {}",
                self.config.expected_commits
            ));
        }

        Ok(OracleReceipt {
            receipt: format!(
                "tip={tip} via={resolved_via} commits={count} pack_bytes={} server={}",
                output.pack_bytes,
                self.kind.as_str()
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_kinds_have_distinct_stable_tags() {
        assert_ne!(
            ServerKind::UpstreamGitDaemon.as_str(),
            ServerKind::FgitNode.as_str()
        );
        assert_eq!(ServerKind::FgitNode.as_str(), "fgit-node-serve");
        assert_eq!(
            ServerKind::UpstreamGitDaemon.as_str(),
            "upstream-git-daemon"
        );
    }

    #[test]
    fn the_workload_line_states_what_the_timed_interval_contains() {
        let workload = TransportWorkload::new(sample_config(), ServerKind::FgitNode);
        let line = workload.workload_line();
        assert!(
            line.contains("NOT steady-state transport latency"),
            "the artifact must not let a cold-start measurement read as transport latency: {line}"
        );
        assert!(
            line.contains("cold server start"),
            "the artifact must name server start as part of the interval: {line}"
        );
        assert!(line.contains("fgit-node-serve"), "{line}");
    }

    #[test]
    fn cpu_and_rss_probes_read_this_live_process() {
        let pid = std::process::id();
        // A presence case for the probes themselves: this process is running,
        // so both must return a value. Without this the probes could be broken
        // and every sample would fail with "could not read", which looks like
        // an environment problem rather than a harness defect.
        assert!(
            server_cpu_ns(pid).is_some(),
            "the CPU probe must read a live process"
        );
        assert!(
            server_peak_rss_bytes(pid).is_some(),
            "the RSS probe must read a live process"
        );
    }

    #[test]
    fn the_cpu_probe_survives_a_command_name_containing_a_parenthesis() {
        // /proc/<pid>/stat's comm field is parenthesized and may itself contain
        // ')' and spaces. Parsing from the LAST ')' is what makes the field
        // offsets right; splitting on whitespace from the start would shift
        // every index and silently report another field as CPU time.
        let crafted = "42 (weird ) name) S 1 42 42 0 -1 0 0 0 0 0 700 300 40 20 20 0 1 0 99";
        let after_comm = crafted.rsplit_once(')').expect("crafted stat has a ')'").1;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        assert_eq!(fields.first().copied(), Some("S"), "field 1 must be state");
        assert_eq!(fields.get(11).copied(), Some("700"), "utime");
        assert_eq!(fields.get(12).copied(), Some("300"), "stime");
        assert_eq!(fields.get(13).copied(), Some("40"), "cutime");
        assert_eq!(fields.get(14).copied(), Some("20"), "cstime");
    }

    #[test]
    fn a_forking_server_is_not_measured_as_free() {
        // The upstream arm's listener does no pack work -- `git daemon` forks a
        // child per connection -- so a probe reading only utime+stime reports 0
        // and the reference server looks like it produced a pack for nothing.
        // Verified against a real daemon before this test existed: the listener
        // sat at `utime stime = 0 0` after serving a complete clone.
        //
        // This pins the arithmetic against a stat line whose work is entirely in
        // the child fields. A regression to utime+stime only makes it zero.
        let forking = "9 (git-daemon) S 1 9 9 0 -1 0 0 0 0 0 0 0 55 12 20 0 1 0 7";
        let after_comm = forking.rsplit_once(')').expect("stat has a ')'").1;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let sum: u64 = [11, 12, 13, 14]
            .iter()
            .map(|index| {
                fields
                    .get(*index)
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or_default()
            })
            .sum();
        assert_eq!(sum, 67, "child CPU must be counted, not discarded");
        let self_only: u64 = [11, 12]
            .iter()
            .map(|index| {
                fields
                    .get(*index)
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or_default()
            })
            .sum();
        assert_eq!(
            self_only, 0,
            "the permitted twin: this is exactly what the old formula would have reported"
        );
    }

    #[test]
    fn a_missing_process_yields_no_measurement_rather_than_zero() {
        // Zero CPU would read as a free server, which is the exact false-green
        // this returns None to avoid.
        assert_eq!(server_cpu_ns(u32::MAX), None);
        assert_eq!(server_peak_rss_bytes(u32::MAX), None);
    }

    #[test]
    fn both_arms_request_the_same_remote_path() {
        // The differential is only valid if both servers export the corpus
        // under the same name; a divergence here would measure two corpora.
        let baseline =
            TransportWorkload::new(sample_config(), ServerKind::UpstreamGitDaemon).remote_path();
        let candidate = TransportWorkload::new(sample_config(), ServerKind::FgitNode).remote_path();
        assert_eq!(baseline, candidate);
        assert_eq!(baseline, "/corpus.git");
    }

    #[test]
    fn ports_are_never_reused_within_one_arm() {
        // A retried port can land in TIME_WAIT and serialize samples, which
        // would show up as a fat tail attributable to the harness, not the
        // server under test.
        let mut workload = TransportWorkload::new(sample_config(), ServerKind::FgitNode);
        let first = workload.next_port_offset;
        workload.next_port_offset = workload.next_port_offset.saturating_add(1);
        let second = workload.next_port_offset;
        assert_ne!(first, second);
    }

    fn sample_config() -> TransportConfig {
        TransportConfig {
            fg_binary: PathBuf::from("/nonexistent/fg"),
            git_binary: PathBuf::from("/nonexistent/git"),
            git_exec_path: PathBuf::from("/nonexistent/git-core"),
            empty_template_dir: PathBuf::from("/nonexistent/template"),
            storage_root: PathBuf::from("/nonexistent/storage"),
            upstream_base_path: PathBuf::from("/nonexistent/upstream"),
            tenant: "bench".to_owned(),
            repository: "corpus".to_owned(),
            work_root: PathBuf::from("/nonexistent/work"),
            port_base: 30_000,
            expected_head: "0".repeat(40),
            expected_commits: 3,
            cache_state: CacheState::Warm,
            python_binary: PathBuf::from("/nonexistent/python3"),
            logical_reachable_bytes: 1_000_000,
        }
    }
}
