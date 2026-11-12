//! Exercise the descriptor-open boundary after a real, successful metadata
//! inspection. Loading an already-nonregular path would miss the substitution
//! race because the earlier metadata check already rejects it.

use super::*;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-http-credential-open-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("credentials")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding() -> Binding {
    Binding {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
    }
}

fn table(token: &str, principal: u8) -> String {
    let binding = binding();
    let digest: String = sha256_digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{HEADER} {} {} {}\n{digest} {} read\n",
        binding.tenant,
        binding.repository,
        binding.incarnation,
        PrincipalId::from_bytes([principal; 16]),
    )
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

fn source(path: &Path) -> CredentialSource {
    CredentialSource::File {
        path: path.to_path_buf(),
        binding: binding(),
    }
}

fn inspected(path: &Path) -> Metadata {
    let before = fs::symlink_metadata(path).unwrap();
    safe_metadata(&before).unwrap();
    before
}

#[test]
fn substituted_symlink_directory_and_socket_refuse_before_credential_reads() {
    let scratch = Scratch::new();
    let path = scratch.path();
    let token = "a".repeat(64);
    private_write(&path, table(&token, 4).as_bytes());
    let before = inspected(&path);
    let retained = scratch.0.join("retained");
    fs::rename(&path, &retained).unwrap();

    symlink(&retained, &path).unwrap();
    // Following this symlink would select the original inode and pass the
    // existing dev/ino comparison. NOFOLLOW must reject the open itself.
    assert!(matches!(
        open_credential_file(&path, &before),
        Err(CredentialFailure::Unavailable),
    ));
    fs::remove_file(&path).unwrap();

    fs::create_dir(&path).unwrap();
    assert!(matches!(
        open_credential_file(&path, &before),
        Err(CredentialFailure::UnsafeFile),
    ));
    fs::remove_dir(&path).unwrap();

    let listener = UnixListener::bind(&path).unwrap();
    assert!(matches!(
        open_credential_file(&path, &before),
        Err(CredentialFailure::Unavailable),
    ));
    drop(listener);
    fs::remove_file(&path).unwrap();

    fs::rename(&retained, &path).unwrap();
    open_credential_file(&path, &before).unwrap();
    let grant = source(&path)
        .authenticate(Some(&format!("Bearer {token}")))
        .unwrap();
    assert_eq!(grant.principal, PrincipalId::from_bytes([4; 16]));
    assert!(grant.permits(Service::UploadPack));
    assert!(!grant.permits(Service::ReceivePack));
}

#[test]
fn substituted_fifo_never_waits_for_a_writer() {
    use rustix::fs::{Mode, OFlags};

    let scratch = Scratch::new();
    let path = scratch.path();
    let token = "a".repeat(64);
    private_write(&path, table(&token, 4).as_bytes());
    let before = inspected(&path);
    let retained = scratch.0.join("retained");
    fs::rename(&path, &retained).unwrap();
    rustix::fs::mkfifoat(rustix::fs::CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();

    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let child_path = path.clone();
    let child = std::thread::spawn(move || {
        let result = open_credential_file(&child_path, &before).map(|_| ());
        let _ = send.send(result);
    });
    // No FIFO writer exists during the observation. If NONBLOCK regresses,
    // release the blocked opener before failing rather than leaking a thread.
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
    assert_eq!(
        observed.expect("credential open waited for a FIFO writer"),
        Err(CredentialFailure::UnsafeFile),
    );

    fs::remove_file(&path).unwrap();
    fs::rename(&retained, &path).unwrap();
    assert!(
        source(&path)
            .authenticate(Some(&format!("Bearer {token}")))
            .is_ok(),
    );
}

#[test]
fn replacement_identity_and_changed_descriptor_limits_refuse_with_valid_reload_twins() {
    let scratch = Scratch::new();
    let path = scratch.path();
    let token = "a".repeat(64);
    private_write(&path, table(&token, 4).as_bytes());
    let before = inspected(&path);
    let replacement = scratch.0.join("replacement");
    private_write(&replacement, table(&token, 5).as_bytes());
    assert_eq!(before.len(), fs::metadata(&replacement).unwrap().len());
    fs::rename(&replacement, &path).unwrap();
    assert!(matches!(
        open_credential_file(&path, &before),
        Err(CredentialFailure::UnsafeFile),
    ));
    assert_eq!(
        source(&path)
            .authenticate(Some(&format!("Bearer {token}")))
            .unwrap()
            .principal,
        PrincipalId::from_bytes([5; 16]),
    );

    let before = inspected(&path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        open_credential_file(&path, &before),
        Err(CredentialFailure::UnsafeFile),
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    open_credential_file(&path, &before).unwrap();

    let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    writer.set_len((MAX_FILE_BYTES + 1) as u64).unwrap();
    assert!(matches!(
        open_credential_file(&path, &before),
        Err(CredentialFailure::UnsafeFile),
    ));
    writer.set_len(before.len()).unwrap();
    assert!(
        source(&path)
            .authenticate(Some(&format!("Bearer {token}")))
            .is_ok(),
    );
}

#[test]
fn an_opened_snapshot_survives_atomic_rotation_while_new_requests_use_the_new_grant() {
    let scratch = Scratch::new();
    let path = scratch.path();
    let token = "a".repeat(64);
    let original = table(&token, 4);
    private_write(&path, original.as_bytes());
    let before = inspected(&path);
    let (mut file, _) = open_credential_file(&path, &before).unwrap();
    let existing = source(&path)
        .authenticate(Some(&format!("Bearer {token}")))
        .unwrap();
    let replacement = scratch.0.join("replacement");
    private_write(&replacement, table(&token, 5).as_bytes());
    fs::rename(&replacement, &path).unwrap();

    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, original.as_bytes());
    assert_eq!(
        parse(&bytes, binding()).unwrap()[0].grant.principal,
        PrincipalId::from_bytes([4; 16]),
    );
    assert_eq!(existing.principal, PrincipalId::from_bytes([4; 16]));
    assert_eq!(
        source(&path)
            .authenticate(Some(&format!("Bearer {token}")))
            .unwrap()
            .principal,
        PrincipalId::from_bytes([5; 16]),
    );
}
