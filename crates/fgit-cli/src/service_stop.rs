//! Explicit operator-owned stop-file control for a continuously running listener.
//!
//! No file contents are interpreted, and this module never creates, removes or
//! rewrites the selected file. The parent must already exist and remain under
//! operator control. This is lifecycle control, not repository authorization.

use std::cell::Cell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fgit_node::TerminationSignals;

const POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) struct StopFile {
    path: PathBuf,
    parent: PathBuf,
    parent_metadata: fs::Metadata,
    last_poll: Cell<Option<Instant>>,
    stopped: Cell<bool>,
}

impl StopFile {
    /// Refuse a pre-existing stop entry BEFORE repository open or listener bind.
    /// Reusing a previous stop request must never accidentally report readiness.
    pub(crate) fn arm(path: &Path) -> io::Result<Self> {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "service stop path needs a file name",
            )
        })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent)?;
        let parent_metadata = fs::symlink_metadata(&parent)?;
        if !parent_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service stop parent is not a directory",
            ));
        }
        let control = Self {
            path: parent.join(name),
            parent,
            parent_metadata,
            last_poll: Cell::new(None),
            stopped: Cell::new(false),
        };
        if control.inspect()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "service stop file already exists",
            ));
        }
        Ok(control)
    }

    fn inspect(&self) -> io::Result<bool> {
        // A missing/replaced parent is not a negative stop observation.
        let parent = fs::symlink_metadata(&self.parent)?;
        if !parent.is_dir() || !same_directory(&parent, &self.parent_metadata) {
            return Err(io::Error::other("service stop directory changed"));
        }
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service stop entry must be a regular file, not a link or special file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn should_stop(&self) -> io::Result<bool> {
        self.poll_at(Instant::now())
    }

    fn poll_at(&self, now: Instant) -> io::Result<bool> {
        if self.stopped.get() {
            return Ok(true);
        }
        if self
            .last_poll
            .get()
            .is_some_and(|last| now.saturating_duration_since(last) < POLL_INTERVAL)
        {
            return Ok(false);
        }
        self.last_poll.set(Some(now));
        let stopped = self.inspect()?;
        self.stopped.set(stopped);
        Ok(stopped)
    }
}

/// The executable owns process signals; library listeners only poll an explicit
/// callback. Install this before readiness so a supervisor cannot signal a
/// newly announced service before its handlers exist.
pub(crate) struct StopControl<'a> {
    file: &'a StopFile,
    signals: Option<TerminationSignals>,
    announced: Cell<bool>,
}

impl<'a> StopControl<'a> {
    pub(crate) fn new(file: &'a StopFile) -> Self {
        let signals = TerminationSignals::install()
            .inspect_err(|error| {
                eprintln!("fg: termination signals not installed ({error}); use the stop file");
            })
            .ok();
        Self {
            file,
            signals,
            announced: Cell::new(false),
        }
    }

    pub(crate) fn should_stop(&self) -> io::Result<bool> {
        if self
            .signals
            .as_ref()
            .is_some_and(TerminationSignals::requested)
        {
            if !self.announced.replace(true) {
                eprintln!("fg: termination signal received; draining accepted connections");
            }
            return Ok(true);
        }
        self.file.should_stop()
    }
}

#[cfg(unix)]
fn same_directory(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_directory(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    // Portable std does not expose a comparable directory identity everywhere.
    // Both entries must remain directories; their parent is operator-owned.
    left.is_dir() && right.is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            for _ in 0..128 {
                let path = std::env::temp_dir().join(format!(
                    "fg-http-stop-{}-{}",
                    std::process::id(),
                    SEQUENCE.fetch_add(1, Ordering::Relaxed),
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("test directory collision budget exhausted")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ordinary_stop_is_latched_without_reading_or_removing_the_file() {
        let dir = Directory::new();
        let path = dir.0.join("stop");
        let control = StopFile::arm(&path).unwrap();
        let now = Instant::now();
        assert!(!control.poll_at(now).unwrap());
        fs::write(&path, b"operator request, not repository data\xff").unwrap();
        assert!(control.poll_at(now + POLL_INTERVAL).unwrap());
        assert_eq!(
            fs::read(&path).unwrap(),
            b"operator request, not repository data\xff"
        );
        fs::remove_file(&path).unwrap();
        assert!(control.poll_at(now + POLL_INTERVAL).unwrap());
    }

    #[test]
    fn existing_stop_refuses_startup_and_is_never_removed_automatically() {
        let dir = Directory::new();
        let path = dir.0.join("stop");
        fs::write(&path, b"previous stop").unwrap();
        assert_eq!(
            StopFile::arm(&path).err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"previous stop");
        fs::remove_file(&path).unwrap();
        assert!(StopFile::arm(&path).is_ok());
    }

    #[test]
    fn first_poll_observes_a_stop_created_immediately_after_arming() {
        let dir = Directory::new();
        let path = dir.0.join("stop");
        let control = StopFile::arm(&path).unwrap();
        fs::write(&path, b"").unwrap();
        assert!(control.should_stop().unwrap());
    }

    #[test]
    fn polling_has_an_exact_finite_interval_and_does_not_renew_on_cache_hits() {
        let dir = Directory::new();
        let path = dir.0.join("stop");
        let control = StopFile::arm(&path).unwrap();
        let now = Instant::now();
        assert!(!control.poll_at(now).unwrap());
        fs::write(&path, b"").unwrap();
        for millis in 1..50 {
            assert!(
                !control
                    .poll_at(now + Duration::from_millis(millis))
                    .unwrap()
            );
        }
        assert!(control.poll_at(now + POLL_INTERVAL).unwrap());
    }

    #[test]
    fn unavailable_parent_is_an_error_not_permission_to_keep_serving() {
        let dir = Directory::new();
        let parent = dir.0.join("control");
        fs::create_dir(&parent).unwrap();
        let control = StopFile::arm(&parent.join("stop")).unwrap();
        assert!(!control.inspect().unwrap());
        fs::remove_dir(&parent).unwrap();
        assert_eq!(
            control.inspect().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(StopFile::arm(&parent.join("stop")).is_err());
    }

    #[test]
    fn a_directory_stop_entry_is_refused_without_opening_it() {
        let dir = Directory::new();
        let path = dir.0.join("stop");
        let control = StopFile::arm(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            control.inspect().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(StopFile::arm(&path).is_err());
        fs::remove_dir(&path).unwrap();
        fs::write(&path, b"").unwrap();
        assert!(control.inspect().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_socket_stop_entries_fail_closed_without_touching_targets() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;
        let dir = Directory::new();
        let path = dir.0.join("stop");
        let target = dir.0.join("target");
        let control = StopFile::arm(&path).unwrap();
        for dangling in [true, false] {
            if !dangling {
                fs::write(&target, b"untouched").unwrap();
            }
            symlink(&target, &path).unwrap();
            assert!(control.inspect().is_err());
            assert!(StopFile::arm(&path).is_err());
            assert_eq!(fs::read_link(&path).unwrap(), target);
            fs::remove_file(&path).unwrap();
        }
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        let listener = UnixListener::bind(&path).unwrap();
        assert!(control.inspect().is_err());
        drop(listener);
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"").unwrap();
        assert!(control.inspect().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn replaced_control_directory_cannot_hide_a_stop_request() {
        let dir = Directory::new();
        let parent = dir.0.join("control");
        let moved = dir.0.join("old-control");
        fs::create_dir(&parent).unwrap();
        let control = StopFile::arm(&parent.join("stop")).unwrap();
        assert!(!control.inspect().unwrap());
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        // A different empty directory must not be observed as continued service.
        assert_eq!(
            control.inspect().unwrap_err().to_string(),
            "service stop directory changed"
        );
        fs::remove_dir(&parent).unwrap();
        fs::rename(&moved, &parent).unwrap();
        assert!(!control.inspect().unwrap());
        fs::write(parent.join("stop"), b"").unwrap();
        assert!(control.inspect().unwrap());
    }
}
