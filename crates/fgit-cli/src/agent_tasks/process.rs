//! Explicit local Beads process boundary. No shell, ambient tracker discovery,
//! automatic import/export, or background child is used by this profile.

use fgit_agent::LogicalTime;
use fgit_agent::beads::{
    BeadsClaimRequest, BeadsReadSource, BeadsTransport, BeadsTransportRefusal, BeadsWriteOutcome,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = fgit_agent::beads::MAX_BEADS_JSON_BYTES;
const ERROR_LIMIT: usize = 64 * 1024;

/// Foreground, explicitly trusted `br 0.7.6` adapter. A single deadline covers
/// version selection, reads, the one mutation, export, and confirming rereads.
/// The operator owns the executable and Beads directory; this is not a sandbox
/// for hostile executables. This Beads profile does not launch descendants.
pub struct BeadsProcess<'a> {
    program: PathBuf,
    root: PathBuf,
    deadline: Instant,
    live: &'a dyn Fn() -> bool,
    now: &'a dyn Fn() -> LogicalTime,
}

struct Failure {
    reason: BeadsTransportRefusal,
    started: bool,
    quiescent: bool,
}

impl<'a> BeadsProcess<'a> {
    /// Validate an explicit existing tracker and the supported executable
    /// profile before accepting any task mutation. The constructor never
    /// creates a tracker or imports its collaborative projection.
    pub fn open(
        program: &Path,
        root: &Path,
        deadline: Instant,
        live: &'a dyn Fn() -> bool,
        now: &'a dyn Fn() -> LogicalTime,
    ) -> Result<Self, BeadsTransportRefusal> {
        if !program.is_absolute() || !root.is_absolute() {
            return Err(BeadsTransportRefusal::Policy);
        }
        let program = program
            .canonicalize()
            .map_err(|_| BeadsTransportRefusal::Unavailable)?;
        let root = root
            .canonicalize()
            .map_err(|_| BeadsTransportRefusal::Unavailable)?;
        if !matches!(
            root.file_name().and_then(|name| name.to_str()),
            Some(".beads" | "_beads")
        ) {
            return Err(BeadsTransportRefusal::Policy);
        }
        if !program.is_file() || !root.is_dir() || !root.join("beads.db").is_file() {
            return Err(BeadsTransportRefusal::Unavailable);
        }
        let adapter = Self {
            program,
            root,
            deadline,
            live,
            now,
        };
        adapter.check_tracker()?;
        let version = adapter
            .invoke(&["--version".into()], false)
            .map_err(|failure| failure.reason)?;
        if std::str::from_utf8(&version).map(str::trim) != Ok("br 0.7.6") {
            return Err(BeadsTransportRefusal::Unsupported);
        }
        Ok(adapter)
    }

    /// Canonical directory actually selected by the host, for disclosure and
    /// provenance. It is never derived from a task's text or routing prefix.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn interruption(&self) -> Option<BeadsTransportRefusal> {
        if !(self.live)() {
            Some(BeadsTransportRefusal::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(BeadsTransportRefusal::TimeLimit)
        } else {
            None
        }
    }

    // Beads supports explicit directory redirects and cross-project task
    // routing even with --db. This profile selects exactly one local tracker.
    // Recheck on every call; concurrently editing operator-owned routing/config
    // files is outside this trusted local profile.
    fn check_tracker(&self) -> Result<(), BeadsTransportRefusal> {
        fn absent(path: &Path) -> Result<(), BeadsTransportRefusal> {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(BeadsTransportRefusal::Policy),
            }
        }
        for name in ["redirect", "routes.jsonl"] {
            absent(&self.root.join(name))?;
        }
        for ancestor in self.root.ancestors() {
            absent(&ancestor.join(".beads/redirect"))?;
            absent(&ancestor.join(".beads/routes.jsonl"))?;
        }
        for name in ["beads.db", "beads.db-wal", "beads.db-shm", "issues.jsonl"] {
            match std::fs::symlink_metadata(self.root.join(name)) {
                Ok(info) if info.is_file() => {}
                Err(error)
                    if name != "beads.db" && error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(BeadsTransportRefusal::Policy),
            }
        }
        let metadata = self.root.join("metadata.json");
        match std::fs::symlink_metadata(&metadata) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(BeadsTransportRefusal::Unavailable),
            Ok(info) => {
                if !info.is_file() || info.len() > 64 * 1024 {
                    return Err(BeadsTransportRefusal::Policy);
                }
                use std::io::Read;
                let mut bytes = Vec::new();
                std::fs::File::open(metadata)
                    .and_then(|file| file.take(64 * 1024 + 1).read_to_end(&mut bytes))
                    .map_err(|_| BeadsTransportRefusal::Unavailable)?;
                let document =
                    fgit_schema::json::parse(&bytes).map_err(|_| BeadsTransportRefusal::Policy)?;
                let object = document.object().ok_or(BeadsTransportRefusal::Policy)?;
                for (key, expected) in [("database", "beads.db"), ("jsonl_export", "issues.jsonl")]
                {
                    if object
                        .get(key)
                        .is_some_and(|value| value.text() != Some(expected))
                    {
                        return Err(BeadsTransportRefusal::Policy);
                    }
                }
            }
        }
        Ok(())
    }

    fn write(&self, arguments: &[String]) -> BeadsWriteOutcome {
        match self.invoke(arguments, true) {
            Ok(_) => BeadsWriteOutcome::Completed,
            Err(failure) if !failure.started => BeadsWriteOutcome::NotStarted(failure.reason),
            Err(failure) => BeadsWriteOutcome::Uncertain {
                quiescent: failure.quiescent,
                reason: failure.reason,
            },
        }
    }

    #[cfg(unix)]
    fn invoke(&self, arguments: &[String], tracker: bool) -> Result<Vec<u8>, Failure> {
        use std::io::{self, Read};
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};

        let before = |reason| Failure {
            reason,
            started: false,
            quiescent: true,
        };
        if let Some(reason) = self.interruption() {
            return Err(before(reason));
        }
        if tracker {
            self.check_tracker().map_err(before)?;
        }
        let (mut stdout, child_stdout) =
            UnixStream::pair().map_err(|_| before(BeadsTransportRefusal::Unavailable))?;
        let (mut stderr, child_stderr) =
            UnixStream::pair().map_err(|_| before(BeadsTransportRefusal::Unavailable))?;
        stdout
            .set_nonblocking(true)
            .and_then(|()| stderr.set_nonblocking(true))
            .map_err(|_| before(BeadsTransportRefusal::Unavailable))?;
        let mut command = Command::new(&self.program);
        command
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .env("BEADS_JSONL", self.root.join("issues.jsonl"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from(child_stdout)))
            .stderr(Stdio::from(OwnedFd::from(child_stderr)));
        if tracker {
            command
                .arg("--db")
                .arg(self.root.join("beads.db"))
                .arg("--no-auto-import")
                .arg("--no-auto-flush");
        }
        command.args(arguments);
        let mut child = command
            .spawn()
            .map_err(|_| before(BeadsTransportRefusal::Unavailable))?;
        // Close the parent's copies of the child ends. EOF is now an actual
        // observation of the spawned program closing its output descriptors.
        drop(command);
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut status = None;
        let failure = loop {
            if let Some(reason) = self.interruption() {
                break reason;
            }
            let drain = |stream: &mut UnixStream, bytes: &mut Vec<u8>, limit, eof: &mut bool| {
                if *eof {
                    return Ok(());
                }
                let mut buffer = [0u8; 8192];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            *eof = true;
                            return Ok(());
                        }
                        Ok(count) => {
                            if count > limit - bytes.len() {
                                return Err(BeadsTransportRefusal::OutputLimit);
                            }
                            bytes.extend_from_slice(&buffer[..count]);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => return Err(BeadsTransportRefusal::ProcessFailed),
                    }
                }
            };
            if let Err(reason) = drain(&mut stdout, &mut output, OUTPUT_LIMIT, &mut stdout_eof)
                .and_then(|()| drain(&mut stderr, &mut errors, ERROR_LIMIT, &mut stderr_eof))
            {
                break reason;
            }
            if status.is_none() {
                status = match child.try_wait() {
                    Ok(status) => status,
                    Err(_) => break BeadsTransportRefusal::ProcessFailed,
                };
            }
            if let Some(status) = status
                && stdout_eof
                && stderr_eof
            {
                return if status.success() {
                    Ok(output)
                } else {
                    // A nonzero exit never proves a write did not occur.
                    Err(Failure {
                        reason: BeadsTransportRefusal::ProcessFailed,
                        started: true,
                        quiescent: true,
                    })
                };
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        // No output reader thread/future can outlive this call. On interruption
        // stop output acquisition, kill the foreground child if still running,
        // and reap it before reporting any recoverable ambiguity.
        drop(stdout);
        drop(stderr);
        if status.is_none() {
            let _ = child.kill();
        }
        let quiescent = child.wait().is_ok();
        Err(Failure {
            reason: failure,
            started: true,
            quiescent,
        })
    }

    #[cfg(not(unix))]
    fn invoke(&self, _arguments: &[String], _tracker: bool) -> Result<Vec<u8>, Failure> {
        Err(Failure {
            reason: BeadsTransportRefusal::Unsupported,
            started: false,
            quiescent: true,
        })
    }
}

impl BeadsTransport for BeadsProcess<'_> {
    fn observed_at(&mut self) -> LogicalTime {
        (self.now)()
    }

    fn show(
        &mut self,
        id: &str,
        source: BeadsReadSource,
    ) -> Result<Vec<u8>, BeadsTransportRefusal> {
        if id.is_empty()
            || id.len() > 256
            || id.starts_with('-')
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(BeadsTransportRefusal::Policy);
        }
        let mut args = Vec::new();
        if matches!(source, BeadsReadSource::Export) {
            args.push("--no-db".into());
        }
        args.extend(["show".into(), id.into(), "--json".into()]);
        self.invoke(&args, true).map_err(|failure| failure.reason)
    }

    fn ready_unassigned(&mut self) -> Result<Vec<u8>, BeadsTransportRefusal> {
        self.invoke(
            &[
                "ready".into(),
                "--unassigned".into(),
                "--limit".into(),
                "4096".into(),
                "--json".into(),
            ],
            true,
        )
        .map_err(|failure| failure.reason)
    }

    fn claim(&mut self, request: &BeadsClaimRequest) -> BeadsWriteOutcome {
        self.write(&request.update_arguments())
    }

    fn flush(&mut self) -> BeadsWriteOutcome {
        self.write(&["sync".into(), "--flush-only".into(), "--json".into()])
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use fgit_agent::beads::BeadsTaskRecord;
    use std::cell::Cell;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Tracker {
        program: PathBuf,
        directory: PathBuf,
        root: PathBuf,
        id: String,
    }

    impl Tracker {
        fn new() -> Self {
            let program = PathBuf::from(
                std::env::var_os("FGIT_BEADS_NATIVE_BR")
                    .expect("set FGIT_BEADS_NATIVE_BR to the verified br 0.7.6 executable"),
            );
            let directory = std::env::temp_dir().join(format!(
                "fg-beads-process-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&directory).expect("private tracker directory");
            let root = directory.join(".beads");
            let mut tracker = Self {
                program,
                directory,
                root,
                id: String::new(),
            };
            tracker.command(&["init", "--prefix", "fg", "--json"], false);
            let created =
                tracker.command(&["create", "Native task", "--type", "task", "--json"], true);
            let json = fgit_schema::json::parse(&created).expect("real create JSON");
            json.object().expect("real create object")["id"]
                .text()
                .expect("real task id")
                .clone_into(&mut tracker.id);
            tracker
        }

        fn command(&self, arguments: &[&str], explicit: bool) -> Vec<u8> {
            let mut command = Command::new(&self.program);
            command
                .current_dir(&self.directory)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("NO_COLOR", "1")
                .env("BEADS_JSONL", self.root.join("issues.jsonl"));
            if explicit {
                command
                    .arg("--db")
                    .arg(self.root.join("beads.db"))
                    .arg("--no-auto-import")
                    .arg("--no-auto-flush");
            }
            let output = command.args(arguments).output().expect("run real br");
            assert!(
                output.status.success(),
                "real br failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        }
    }

    impl Drop for Tracker {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    #[ignore = "requires a verified br 0.7.6 executable in FGIT_BEADS_NATIVE_BR"]
    fn native_process_reads_database_and_flushed_export_and_observes_cancellation() {
        let tracker = Tracker::new();
        let live = Cell::new(true);
        let is_live = || live.get();
        let now = || LogicalTime::new(1);
        let mut transport = BeadsProcess::open(
            &tracker.program,
            &tracker.root,
            Instant::now() + Duration::from_secs(10),
            &is_live,
            &now,
        )
        .expect("pinned foreground Beads profile");
        let database = transport
            .show(&tracker.id, BeadsReadSource::Database)
            .expect("database read");
        let database =
            BeadsTaskRecord::parse_show_json(&tracker.id, &database).expect("real task record");
        assert_eq!(database.title(), "Native task");
        assert_eq!(transport.flush(), BeadsWriteOutcome::Completed);
        let export = transport
            .show(&tracker.id, BeadsReadSource::Export)
            .expect("export read");
        let export =
            BeadsTaskRecord::parse_show_json(&tracker.id, &export).expect("real exported task");
        assert_eq!(database.updated_at(), export.updated_at());
        assert_eq!(database.id(), export.id());
        live.set(false);
        assert_eq!(
            transport.show(&tracker.id, BeadsReadSource::Database),
            Err(BeadsTransportRefusal::Cancelled)
        );
        assert_eq!(
            transport.flush(),
            BeadsWriteOutcome::NotStarted(BeadsTransportRefusal::Cancelled)
        );
    }

    #[test]
    #[ignore = "requires a verified br 0.7.6 executable in FGIT_BEADS_NATIVE_BR"]
    fn native_process_refuses_routing_and_external_export_before_execution() {
        let tracker = Tracker::new();
        let live = || true;
        let now = || LogicalTime::new(1);
        std::fs::write(tracker.root.join("routes.jsonl"), "{}\n").expect("private routing fixture");
        assert!(matches!(
            BeadsProcess::open(
                &tracker.program,
                &tracker.root,
                Instant::now() + Duration::from_secs(10),
                &live,
                &now,
            ),
            Err(BeadsTransportRefusal::Policy)
        ));
        std::fs::remove_file(tracker.root.join("routes.jsonl"))
            .expect("remove own routing fixture");
        std::fs::write(
            tracker.root.join("metadata.json"),
            "{\"database\":\"beads.db\",\"jsonl_export\":\"../external.jsonl\"}",
        )
        .expect("private metadata fixture");
        assert!(matches!(
            BeadsProcess::open(
                &tracker.program,
                &tracker.root,
                Instant::now() + Duration::from_secs(10),
                &live,
                &now,
            ),
            Err(BeadsTransportRefusal::Policy)
        ));
        assert!(!tracker.directory.join("external.jsonl").exists());
    }

    #[test]
    #[ignore = "requires a verified br 0.7.6 executable in FGIT_BEADS_NATIVE_BR"]
    fn native_process_bounds_real_task_output_and_reaps_the_child() {
        let tracker = Tracker::new();
        let description = tracker.directory.join("large-description.txt");
        std::fs::write(&description, vec![b'x'; OUTPUT_LIMIT + 4096]).expect("private description");
        tracker.command(
            &[
                "update",
                &tracker.id,
                "--description-file",
                description.to_str().unwrap(),
                "--json",
            ],
            true,
        );
        let live = || true;
        let now = || LogicalTime::new(1);
        let mut transport = BeadsProcess::open(
            &tracker.program,
            &tracker.root,
            Instant::now() + Duration::from_secs(10),
            &live,
            &now,
        )
        .expect("pinned foreground Beads profile");
        assert_eq!(
            transport.show(&tracker.id, BeadsReadSource::Database),
            Err(BeadsTransportRefusal::OutputLimit)
        );
        // A second bounded invocation still runs after the oversized reader was
        // closed and its child reaped; no detached output worker exists.
        assert_eq!(transport.flush(), BeadsWriteOutcome::Completed);
    }
}
