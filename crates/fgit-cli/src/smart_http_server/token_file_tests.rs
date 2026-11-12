//! Exercise token-file substitutions after a real metadata inspection so the
//! initial nonregular-file rejection cannot hide a blocking descriptor open.

use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fg-http-token-open-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create token test directory: {error}"),
            }
        }
        panic!("token test directory collision budget exhausted")
    }

    fn path(&self) -> PathBuf {
        self.0.join("token")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn private_regular_tokens_accept_the_exact_supported_sizes() {
    let scratch = Scratch::new();
    let path = scratch.path();
    let token = "a".repeat(64);
    for ending in ["", "\n", "\r\n"] {
        private_write(&path, format!("{token}{ending}").as_bytes());
        assert_eq!(read_token(&path).unwrap(), sha256_digest(token.as_bytes()));
        fs::remove_file(&path).unwrap();
    }
    private_write(&path, format!("{token}\r\n\n").as_bytes());
    assert!(read_token(&path).is_err());
}

#[test]
fn substituted_symlink_directory_and_socket_refuse_before_token_reads() {
    let scratch = Scratch::new();
    let path = scratch.path();
    let token = "a".repeat(64);
    private_write(&path, token.as_bytes());
    let before = fs::symlink_metadata(&path).unwrap();
    let retained = scratch.0.join("retained");
    fs::rename(&path, &retained).unwrap();

    symlink(&retained, &path).unwrap();
    // The symlink targets the original inode: dev/ino checks alone would allow
    // it. The descriptor open must refuse to follow the substituted link.
    assert!(open_token_file(&path, &before).is_err());
    fs::remove_file(&path).unwrap();

    fs::create_dir(&path).unwrap();
    assert!(
        open_token_file(&path, &before)
            .unwrap_err()
            .contains("bounded regular file"),
    );
    fs::remove_dir(&path).unwrap();

    let listener = UnixListener::bind(&path).unwrap();
    assert!(open_token_file(&path, &before).is_err());
    drop(listener);
    fs::remove_file(&path).unwrap();

    fs::rename(&retained, &path).unwrap();
    open_token_file(&path, &before).unwrap();
    assert_eq!(read_token(&path).unwrap(), sha256_digest(token.as_bytes()));
}

#[test]
fn substituted_fifo_never_waits_for_a_writer() {
    use rustix::fs::{Mode, OFlags};

    let scratch = Scratch::new();
    let path = scratch.path();
    let token = "a".repeat(64);
    private_write(&path, token.as_bytes());
    let before = fs::symlink_metadata(&path).unwrap();
    let retained = scratch.0.join("retained");
    fs::rename(&path, &retained).unwrap();
    rustix::fs::mkfifoat(rustix::fs::CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();

    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let child_path = path.clone();
    let child = std::thread::spawn(move || {
        let result = open_token_file(&child_path, &before).map(|_| ());
        let _ = send.send(result);
    });
    // No writer exists during the observation. Rescue a regressed blocking
    // opener before failing so the test never abandons its worker thread.
    let observed = receive.recv_timeout(Duration::from_secs(2));
    let rescue = if matches!(observed, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
        Some(
            rustix::fs::open(
                &path,
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .unwrap(),
        )
    } else {
        None
    };
    child.join().unwrap();
    drop(rescue);
    assert!(
        observed
            .expect("token open waited for a FIFO writer")
            .unwrap_err()
            .contains("bounded regular file"),
    );

    fs::remove_file(&path).unwrap();
    fs::rename(&retained, &path).unwrap();
    assert_eq!(read_token(&path).unwrap(), sha256_digest(token.as_bytes()));
}

#[test]
fn changed_identity_permissions_and_size_refuse_with_valid_token_twins() {
    let scratch = Scratch::new();
    let path = scratch.path();
    private_write(&path, &[b'a'; 64]);
    let before = fs::symlink_metadata(&path).unwrap();
    let replacement = scratch.0.join("replacement");
    private_write(&replacement, &[b'b'; 64]);
    assert_eq!(before.len(), fs::metadata(&replacement).unwrap().len());
    fs::rename(&replacement, &path).unwrap();
    assert!(open_token_file(&path, &before).is_err());
    assert_eq!(read_token(&path).unwrap(), sha256_digest(&[b'b'; 64]));

    let before = fs::symlink_metadata(&path).unwrap();
    for mode in [0o640, 0o604] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(open_token_file(&path, &before).is_err());
        assert!(read_token(&path).is_err());
        let exposed = fs::symlink_metadata(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_token_file(&path, &exposed).is_err());
        open_token_file(&path, &before).unwrap();
        assert_eq!(read_token(&path).unwrap(), sha256_digest(&[b'b'; 64]));
    }

    let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    writer.set_len(67).unwrap();
    assert!(
        open_token_file(&path, &before)
            .unwrap_err()
            .contains("bounded regular file"),
    );
    writer.set_len(before.len()).unwrap();
    assert_eq!(read_token(&path).unwrap(), sha256_digest(&[b'b'; 64]));
}

#[test]
fn an_opened_token_snapshot_survives_atomic_rotation() {
    let scratch = Scratch::new();
    let path = scratch.path();
    private_write(&path, &[b'a'; 64]);
    let before = fs::symlink_metadata(&path).unwrap();
    let mut file = open_token_file(&path, &before).unwrap();
    let replacement = scratch.0.join("replacement");
    private_write(&replacement, &[b'b'; 64]);
    fs::rename(&replacement, &path).unwrap();

    let mut bytes = Vec::new();
    (&mut file).take(67).read_to_end(&mut bytes).unwrap();
    assert_eq!(token_digest(&bytes).unwrap(), sha256_digest(&[b'a'; 64]));
    assert_eq!(read_token(&path).unwrap(), sha256_digest(&[b'b'; 64]));
}
