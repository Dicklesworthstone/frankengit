//! Actual OS process death and file locking, not a PID/heartbeat simulation.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const REF: &[u8] = b"refs/heads/main";
const CHILD_DIRECTORY: &str = "FGIT_PROGRESS_OWNER_TEST_DIRECTORY";
static NEXT: AtomicU64 = AtomicU64::new(0);
fn state() -> State { State::new("owner test sha256".into(), &[REF.to_vec()]).unwrap() }
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-owner-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
struct Process(Child);
impl Process {
    fn start(directory: &Path, phase: &str) -> Self {
        let module = module_path!().split_once("::").unwrap().1;
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("{module}::child_owner"), "--nocapture", "--test-threads=1"])
            .env(CHILD_DIRECTORY, directory).env("FGIT_PROGRESS_OWNER_TEST_PHASE", phase)
            .spawn().unwrap();
        let mut process = Self(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !directory.join("ready").exists() {
            assert!(process.0.try_wait().unwrap().is_none(), "child exited before acquiring ownership");
            assert!(Instant::now() < deadline, "child failed to report durable progress");
            std::thread::sleep(Duration::from_millis(10));
        }
        process
    }
    fn kill(&mut self) {
        self.0.kill().unwrap();
        assert!(!self.0.wait().unwrap().success());
    }
}
impl Drop for Process {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

#[test]
fn child_owner() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else { return; };
    let directory = PathBuf::from(directory);
    let mut file = ProgressFile::open(&directory, true, state()).unwrap();
    file.state.begin_preparation(REF).unwrap();
    file.state.completed(REF, Pin { number: 7, digest: [4; 32] }).unwrap();
    file.state.begin_preparation(REF).unwrap();
    if std::env::var("FGIT_PROGRESS_OWNER_TEST_PHASE").unwrap() == "pending" {
        file.arm(REF, [8; 32]).unwrap();
    } else { file.save().unwrap(); }
    fs::write(directory.join("ready"), b"durable").unwrap();
    // Deliberately remain alive with progress owned until the parent kills us.
    loop { std::thread::sleep(Duration::from_secs(1)); }
}

#[test]
fn process_death_allows_exclusive_resume_without_losing_floor_or_pending_candidate() {
    for phase in ["preparing", "pending"] {
        let scratch = Scratch::new();
        let mut child = Process::start(&scratch.0, phase);
        let original = fs::read(scratch.0.join("checkpoint")).unwrap();
        let marker = fs::read(scratch.0.join("run.lock")).unwrap();
        assert_eq!(ProgressFile::open(&scratch.0, false, state()).err().unwrap().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(fs::read(scratch.0.join("checkpoint")).unwrap(), original);
        child.kill();
        // No release, sentinel deletion, PID probing or progress rewrite.
        assert_eq!(fs::read(scratch.0.join("run.lock")).unwrap(), marker);
        assert!(ProgressFile::open(&scratch.0, true, state()).is_err());
        let mut file = ProgressFile::open(&scratch.0, false, state()).unwrap();
        assert_eq!(file.state.encode().unwrap(), original);
        assert_eq!(file.state.rows[REF].floor, Some(Pin { number: 7, digest: [4; 32] }));
        if phase == "pending" {
            assert_eq!(file.state.rows[REF].pending, Some([8; 32]));
            assert!(file.state.begin_preparation(REF).is_err());
            assert!(file.state.abandon_preparation(REF).is_err());
        } else {
            assert!(file.state.rows[REF].preparing);
            file.state.abandon_preparation(REF).unwrap();
            assert_eq!(file.state.rows[REF].floor.as_ref().unwrap().number, 7);
        }
        file.release().unwrap();
    }
}

#[test]
fn crashed_owner_does_not_authorize_wrong_scope_or_discard_an_interrupted_replacement() {
    let scratch = Scratch::new();
    let mut child = Process::start(&scratch.0, "pending");
    child.kill();
    let original = fs::read(scratch.0.join("checkpoint")).unwrap();
    let marker = fs::read(scratch.0.join("run.lock")).unwrap();
    let foreign = State::new("different owner".into(), &[REF.to_vec()]).unwrap();
    assert!(ProgressFile::open(&scratch.0, false, foreign).is_err());
    fs::write(scratch.0.join("checkpoint.next"), b"interrupted").unwrap();
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
    assert_eq!(fs::read(scratch.0.join("checkpoint.next")).unwrap(), b"interrupted");
    assert_eq!(fs::read(scratch.0.join("checkpoint")).unwrap(), original);
    assert_eq!(fs::read(scratch.0.join("run.lock")).unwrap(), marker);
    // Remove only our known injected test artifact, never an operator recovery rule.
    fs::remove_file(scratch.0.join("checkpoint.next")).unwrap();
    ProgressFile::open(&scratch.0, false, state()).unwrap().release().unwrap();
}

#[test]
fn clean_releases_keep_one_anchor_inode_and_legacy_or_corrupt_sentinels_stay_blocked() {
    let scratch = Scratch::new();
    ProgressFile::open(&scratch.0, true, state()).unwrap().release().unwrap();
    let anchor = fs::metadata(scratch.0.join("owner.lock")).unwrap();
    let original = fs::read(scratch.0.join("checkpoint")).unwrap();
    for _ in 0..3 {
        ProgressFile::open(&scratch.0, false, state()).unwrap().release().unwrap();
        let next = fs::metadata(scratch.0.join("owner.lock")).unwrap();
        assert_eq!((next.dev(), next.ino()), (anchor.dev(), anchor.ino()));
        assert!(!scratch.0.join("run.lock").exists());
    }
    for bytes in [b"".as_slice(), b"legacy owner", b"frankengit-index-owner-v1 0 0\n", &[b'x'; 129]] {
        fs::write(scratch.0.join("run.lock"), bytes).unwrap();
        fs::set_permissions(scratch.0.join("run.lock"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
        assert_eq!(fs::read(scratch.0.join("run.lock")).unwrap(), bytes);
        assert_eq!(fs::read(scratch.0.join("checkpoint")).unwrap(), original);
        fs::remove_file(scratch.0.join("run.lock")).unwrap();
    }
    ProgressFile::open(&scratch.0, false, state()).unwrap().release().unwrap();
}

#[test]
fn replaced_anchor_cannot_authorize_a_peer_or_publish_progress() {
    let scratch = Scratch::new();
    let file = ProgressFile::open(&scratch.0, true, state()).unwrap();
    let original = fs::read(scratch.0.join("checkpoint")).unwrap();
    fs::rename(scratch.0.join("owner.lock"), scratch.0.join("held-anchor")).unwrap();
    private_new(&scratch.0.join("owner.lock")).unwrap();
    assert!(file.save().is_err());
    assert!(ProgressFile::open(&scratch.0, false, state()).is_err());
    assert!(!scratch.0.join("checkpoint.next").exists());
    assert_eq!(fs::read(scratch.0.join("checkpoint")).unwrap(), original);
    assert!(file.release().is_err());
    assert!(scratch.0.join("run.lock").exists());
}

#[test]
fn ownership_anchor_rejects_symlinks_hardlinks_and_nonprivate_files() {
    let scratch = Scratch::new();
    let target = scratch.0.join("target");
    private_new(&target).unwrap();
    let anchor = scratch.0.join("owner.lock");
    symlink(&target, &anchor).unwrap();
    assert!(ProgressFile::open(&scratch.0, true, state()).is_err());
    fs::remove_file(&anchor).unwrap();
    fs::hard_link(&target, &anchor).unwrap();
    assert!(ProgressFile::open(&scratch.0, true, state()).is_err());
    fs::remove_file(&anchor).unwrap();
    fs::rename(&target, &anchor).unwrap();
    fs::set_permissions(&anchor, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ProgressFile::open(&scratch.0, true, state()).is_err());
    assert!(!scratch.0.join("run.lock").exists());
    fs::set_permissions(&anchor, fs::Permissions::from_mode(0o600)).unwrap();
    ProgressFile::open(&scratch.0, true, state()).unwrap().release().unwrap();
}
