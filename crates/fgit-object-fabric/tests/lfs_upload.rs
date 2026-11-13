#![forbid(unsafe_code)]
#![cfg(unix)]
use fgit_object_fabric::artifact::storage::lfs::{
    LfsObject, LfsOid, LfsStore, MAX_ACTIVE_UPLOADS, MAX_OBJECT_BYTES, MAX_RESERVED_UPLOAD_BYTES,
    TRUST_DOMAIN, UploadError, UploadState,
};
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactScope, ArtifactStorageError,
};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = base.join(format!(
            "fg-lfs-upload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> LfsStore {
        self.scoped(1, 2, 3)
    }
    fn scoped(&self, tenant: u8, repo: u8, incarnation: u8) -> LfsStore {
        LfsStore::open(
            &self.0,
            TenantId::from_bytes([tenant; 16]),
            RepositoryId::from_bytes([repo; 16]),
            RepositoryIncarnationId::from_bytes([incarnation; 16]),
        )
        .unwrap()
    }
    fn catalog(&self) -> PathBuf {
        fs::read_dir(&self.0)
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with(".lfs-uploads-")
            })
            .unwrap()
            .path()
    }
    fn sessions(&self) -> Vec<PathBuf> {
        fs::read_dir(self.catalog())
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.file_name() != "lock")
            .map(|entry| entry.path())
            .collect()
    }
    fn session(&self) -> PathBuf {
        let sessions = self.sessions();
        assert_eq!(sessions.len(), 1);
        sessions[0].clone()
    }
    fn artifact_namespace(&self) -> PathBuf {
        let scope = ArtifactScope::new(
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            RepositoryIncarnationId::from_bytes([3; 16]),
            TRUST_DOMAIN,
        )
        .unwrap();
        let key: String = scope
            .commitment()
            .bytes()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        self.0.join(format!("scope-{key}"))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn object(bytes: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(bytes),
        size: bytes.len() as u64,
    }
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([7; 16])
}
fn operation() -> ArtifactOperation<'static> {
    ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(30), &|| true).unwrap()
}
fn partial(offset: u64) -> UploadState {
    UploadState {
        offset,
        complete: false,
    }
}
fn complete(offset: u64) -> UploadState {
    UploadState {
        offset,
        complete: true,
    }
}

#[test]
fn resumable_upload_survives_reopen_and_repeated_negotiation() {
    let temp = Temp::new();
    let data = b"abc\0def\xffghi";
    let expected = object(data);
    assert_eq!(
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .unwrap(),
        partial(0)
    );
    assert_eq!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                0,
                &mut Cursor::new(&data[..4]),
                &operation()
            )
            .unwrap(),
        partial(4)
    );
    assert!(!temp.store().contains(expected, &operation()).unwrap());
    assert_eq!(
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .unwrap(),
        partial(4)
    );
    assert_eq!(temp.sessions().len(), 1);
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        partial(4)
    );
    assert_eq!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                4,
                &mut Cursor::new(&data[4..]),
                &operation()
            )
            .unwrap(),
        complete(data.len() as u64)
    );
    assert_eq!(temp.store().read(expected, &operation()).unwrap(), data);
    assert!(temp.sessions().is_empty());
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        complete(data.len() as u64)
    );
    assert_eq!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                data.len() as u64,
                &mut io::empty(),
                &operation()
            )
            .unwrap(),
        complete(data.len() as u64)
    );
    assert_eq!(
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .unwrap(),
        complete(data.len() as u64)
    );
}

#[test]
fn empty_object_requires_exact_digest_and_verified_custody() {
    let temp = Temp::new();
    let expected = object(b"");
    assert!(matches!(
        temp.store()
            .upload_status(expected, principal(), &operation()),
        Err(UploadError::NotFound)
    ));
    assert_eq!(
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .unwrap(),
        complete(0)
    );
    assert_eq!(temp.store().read(expected, &operation()).unwrap(), b"");
    let wrong = LfsObject {
        oid: object(b"x").oid,
        size: 0,
    };
    assert!(matches!(
        temp.store().begin_upload(wrong, principal(), &operation()),
        Err(UploadError::Corrupt)
    ));
    assert!(!temp.store().contains(wrong, &operation()).unwrap());
}

#[test]
fn offset_conflict_never_reads_request_or_changes_retained_files() {
    struct Unread;
    impl Read for Unread {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("conflicting body must not be read")
        }
    }
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    temp.store()
        .append_upload(
            expected,
            principal(),
            0,
            &mut Cursor::new(b"abc"),
            &operation(),
        )
        .unwrap();
    let directory = temp.session();
    let checkpoint = fs::read(directory.join("checkpoint")).unwrap();
    let payload = fs::read(directory.join("payload")).unwrap();
    for offset in [0, 2, 4, u64::MAX] {
        assert!(matches!(
            temp.store()
                .check_upload_offset(expected, principal(), offset, &operation()),
            Err(UploadError::Offset { expected: 3 })
        ));
        assert!(matches!(
            temp.store()
                .append_upload(expected, principal(), offset, &mut Unread, &operation()),
            Err(UploadError::Offset { expected: 3 })
        ));
        assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
        assert_eq!(fs::read(directory.join("payload")).unwrap(), payload);
    }
    temp.store()
        .check_upload_offset(expected, principal(), 3, &operation())
        .unwrap();
}

#[test]
fn interrupted_read_retains_durable_prefix_and_short_reads_finish() {
    struct Broken {
        bytes: Cursor<&'static [u8]>,
    }
    impl Read for Broken {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.bytes.read(buffer)?;
            if count == 0 {
                Err(io::ErrorKind::ConnectionReset.into())
            } else {
                Ok(count)
            }
        }
    }
    struct Slow(Cursor<&'static [u8]>);
    impl Read for Slow {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(1);
            self.0.read(&mut buffer[..count])
        }
    }
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    assert!(matches!(
        temp.store().append_upload(
            expected,
            principal(),
            0,
            &mut Broken {
                bytes: Cursor::new(b"abc")
            },
            &operation()
        ),
        Err(UploadError::Storage(ArtifactStorageError::Io { .. }))
    ));
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        partial(3)
    );
    assert_eq!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                3,
                &mut Slow(Cursor::new(b"def")),
                &operation()
            )
            .unwrap(),
        complete(6)
    );
}

#[test]
fn cancellation_finishes_owned_checkpoint_and_retry_uses_original_prefix() {
    struct Cancel<'a> {
        live: &'a Cell<bool>,
        first: bool,
    }
    impl Read for Cancel<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.first {
                self.first = false;
                buffer[..3].copy_from_slice(b"abc");
                Ok(3)
            } else {
                self.live.set(false);
                Ok(0)
            }
        }
    }
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    let live = Cell::new(true);
    let check = || live.get();
    let op = ArtifactOperation::new(6, Duration::from_secs(5), &check).unwrap();
    assert!(matches!(
        temp.store().append_upload(
            expected,
            principal(),
            0,
            &mut Cancel {
                live: &live,
                first: true
            },
            &op
        ),
        Err(UploadError::Storage(ArtifactStorageError::Cancelled))
    ));
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        partial(3)
    );
    assert_eq!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                3,
                &mut Cursor::new(b"def"),
                &operation()
            )
            .unwrap(),
        complete(6)
    );
}

#[test]
fn overlong_body_and_failed_final_framing_never_advertise_full_offset() {
    struct MissingEnd(Cursor<&'static [u8]>);
    impl Read for MissingEnd {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.0.read(buffer)?;
            if count == 0 {
                Err(io::ErrorKind::UnexpectedEof.into())
            } else {
                Ok(count)
            }
        }
    }
    for incomplete_framing in [false, true] {
        let temp = Temp::new();
        let expected = object(b"abcdef");
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .unwrap();
        let result = if incomplete_framing {
            temp.store().append_upload(
                expected,
                principal(),
                0,
                &mut MissingEnd(Cursor::new(b"abcdef")),
                &operation(),
            )
        } else {
            temp.store().append_upload(
                expected,
                principal(),
                0,
                &mut Cursor::new(b"abcdefEXTRA"),
                &operation(),
            )
        };
        assert!(result.is_err());
        assert!(!temp.store().contains(expected, &operation()).unwrap());
        assert_eq!(
            temp.store()
                .upload_status(expected, principal(), &operation())
                .unwrap(),
            partial(0)
        );
        assert_eq!(
            temp.store()
                .append_upload(
                    expected,
                    principal(),
                    0,
                    &mut Cursor::new(b"abcdef"),
                    &operation()
                )
                .unwrap(),
            complete(6)
        );
    }
}

#[test]
fn wrong_final_hash_is_a_persistent_refusal_without_reset_or_publication() {
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    assert!(matches!(
        temp.store().append_upload(
            expected,
            principal(),
            0,
            &mut Cursor::new(b"ABCDEF"),
            &operation()
        ),
        Err(UploadError::Corrupt)
    ));
    let directory = temp.session();
    let checkpoint = fs::read(directory.join("checkpoint")).unwrap();
    for result in [
        temp.store()
            .begin_upload(expected, principal(), &operation()),
        temp.store()
            .upload_status(expected, principal(), &operation()),
        temp.store().append_upload(
            expected,
            principal(),
            0,
            &mut Cursor::new(b"abcdef"),
            &operation(),
        ),
    ] {
        assert!(matches!(result, Err(UploadError::Corrupt)));
    }
    assert!(!temp.store().contains(expected, &operation()).unwrap());
    assert_eq!(fs::read(directory.join("payload")).unwrap(), b"ABCDEF");
    assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
}

#[test]
fn retained_corruption_fails_closed_and_unacknowledged_suffix_can_be_retried() {
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    temp.store()
        .append_upload(
            expected,
            principal(),
            0,
            &mut Cursor::new(b"abc"),
            &operation(),
        )
        .unwrap();
    let directory = temp.session();
    let mut payload = OpenOptions::new()
        .append(true)
        .open(directory.join("payload"))
        .unwrap();
    payload.write_all(b"BAD").unwrap();
    payload.sync_all().unwrap();
    let mut next = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("checkpoint.next"))
        .unwrap();
    next.write_all(b"uncommitted partial record").unwrap();
    next.sync_all().unwrap();
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        partial(3)
    );
    assert_eq!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                3,
                &mut Cursor::new(b"def"),
                &operation()
            )
            .unwrap(),
        complete(6)
    );
    assert_eq!(
        temp.store().read(expected, &operation()).unwrap(),
        b"abcdef"
    );

    let other = object(b"ghijkl");
    temp.store()
        .begin_upload(other, principal(), &operation())
        .unwrap();
    temp.store()
        .append_upload(
            other,
            principal(),
            0,
            &mut Cursor::new(b"ghi"),
            &operation(),
        )
        .unwrap();
    let corrupt_payload = temp.session().join("payload");
    fs::write(&corrupt_payload, b"BAD").unwrap();
    assert!(matches!(
        temp.store().upload_status(other, principal(), &operation()),
        Err(UploadError::Corrupt)
    ));
    assert!(matches!(
        temp.store().begin_upload(other, principal(), &operation()),
        Err(UploadError::Corrupt)
    ));
    assert!(matches!(
        temp.store().append_upload(
            other,
            principal(),
            3,
            &mut Cursor::new(b"jkl"),
            &operation()
        ),
        Err(UploadError::Corrupt)
    ));
    assert_eq!(fs::read(corrupt_payload).unwrap(), b"BAD");
}

#[test]
fn final_ready_record_recovers_publication_failure_before_reporting_completion() {
    struct BlockPublication {
        input: Cursor<&'static [u8]>,
        blocker: PathBuf,
    }
    impl Read for BlockPublication {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.input.read(buffer)?;
            if count == 0 {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&self.blocker)?;
            }
            Ok(count)
        }
    }
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    let blocker = temp.artifact_namespace();
    assert!(matches!(
        temp.store().append_upload(
            expected,
            principal(),
            0,
            &mut BlockPublication {
                input: Cursor::new(b"abcdef"),
                blocker: blocker.clone()
            },
            &operation()
        ),
        Err(UploadError::Storage(ArtifactStorageError::UnsafePath))
    ));
    fs::remove_file(blocker).unwrap();
    assert!(!temp.store().contains(expected, &operation()).unwrap());
    let checkpoint = fs::read(temp.session().join("checkpoint")).unwrap();
    assert!(matches!(
        temp.store()
            .check_upload_offset(expected, principal(), 0, &operation()),
        Err(UploadError::Offset { expected: 6 })
    ));
    temp.store()
        .check_upload_offset(expected, principal(), 6, &operation())
        .unwrap();
    assert!(!temp.store().contains(expected, &operation()).unwrap());
    assert!(matches!(
        temp.store()
            .append_upload(expected, principal(), 0, &mut io::empty(), &operation()),
        Err(UploadError::Offset { expected: 6 })
    ));
    assert_eq!(
        fs::read(temp.session().join("checkpoint")).unwrap(),
        checkpoint
    );
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        complete(6)
    );
    assert_eq!(
        temp.store().read(expected, &operation()).unwrap(),
        b"abcdef"
    );
    assert!(temp.sessions().is_empty());
}

#[test]
fn response_loss_and_interrupted_cleanup_recover_from_verified_immutable_custody() {
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    temp.store()
        .append_upload(
            expected,
            principal(),
            0,
            &mut Cursor::new(b"abc"),
            &operation(),
        )
        .unwrap();
    temp.store()
        .put(expected, &mut Cursor::new(b"abcdef"), &operation())
        .unwrap();
    let directory = temp.session();
    fs::remove_file(directory.join("payload")).unwrap();
    fs::remove_file(directory.join("checkpoint")).unwrap();
    assert!(matches!(
        temp.store()
            .check_upload_offset(expected, principal(), 3, &operation()),
        Err(UploadError::Offset { expected: 6 })
    ));
    temp.store()
        .check_upload_offset(expected, principal(), 6, &operation())
        .unwrap();
    assert!(
        directory.exists(),
        "PATCH preflight must not clean up staging"
    );
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        complete(6)
    );
    assert!(temp.sessions().is_empty());
}

#[test]
fn principal_tenant_repository_incarnation_and_size_are_session_boundaries() {
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    temp.store()
        .append_upload(
            expected,
            principal(),
            0,
            &mut Cursor::new(b"abc"),
            &operation(),
        )
        .unwrap();
    let other = PrincipalId::from_bytes([8; 16]);
    assert!(matches!(
        temp.store().upload_status(expected, other, &operation()),
        Err(UploadError::NotFound)
    ));
    assert_eq!(
        temp.store()
            .begin_upload(expected, other, &operation())
            .unwrap(),
        partial(0)
    );
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        partial(3)
    );
    for store in [
        temp.scoped(9, 2, 3),
        temp.scoped(1, 9, 3),
        temp.scoped(1, 2, 9),
    ] {
        assert!(matches!(
            store.upload_status(expected, principal(), &operation()),
            Err(UploadError::NotFound)
        ));
        assert_eq!(
            store
                .begin_upload(expected, principal(), &operation())
                .unwrap(),
            partial(0)
        );
    }
    let size = LfsObject {
        size: 7,
        ..expected
    };
    assert!(matches!(
        temp.store().upload_status(size, principal(), &operation()),
        Err(UploadError::NotFound)
    ));
    assert_eq!(
        temp.store()
            .begin_upload(size, principal(), &operation())
            .unwrap(),
        partial(0)
    );
}

#[test]
fn active_session_count_and_reserved_declared_bytes_are_bounded_and_released() {
    let temp = Temp::new();
    for n in 0..MAX_ACTIVE_UPLOADS {
        temp.store()
            .begin_upload(object(&[n as u8]), principal(), &operation())
            .unwrap();
    }
    assert!(matches!(
        temp.store()
            .begin_upload(object(b"extra"), principal(), &operation()),
        Err(UploadError::Quota)
    ));
    assert_eq!(temp.sessions().len(), MAX_ACTIVE_UPLOADS);
    temp.store()
        .append_upload(
            object(&[0]),
            principal(),
            0,
            &mut Cursor::new([0]),
            &operation(),
        )
        .unwrap();
    temp.store()
        .begin_upload(object(b"extra"), principal(), &operation())
        .unwrap();
    assert_eq!(temp.sessions().len(), MAX_ACTIVE_UPLOADS);

    let reserved = Temp::new();
    let count = MAX_RESERVED_UPLOAD_BYTES / MAX_OBJECT_BYTES;
    for n in 0..count {
        let expected = LfsObject {
            oid: object(&[n as u8]).oid,
            size: MAX_OBJECT_BYTES,
        };
        reserved
            .store()
            .begin_upload(expected, principal(), &operation())
            .unwrap();
    }
    assert!(matches!(
        reserved.store().begin_upload(
            object(b"extra"),
            PrincipalId::from_bytes([9; 16]),
            &operation()
        ),
        Err(UploadError::Quota)
    ));
    assert_eq!(reserved.sessions().len(), count as usize);
    for session in reserved.sessions() {
        assert_eq!(fs::metadata(session.join("payload")).unwrap().len(), 0);
    }
}

#[test]
fn held_catalog_and_session_ownership_refuse_concurrent_requests() {
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    for lock in [temp.catalog().join("lock"), temp.session().join("lock")] {
        let owner = File::open(lock).unwrap();
        owner.try_lock().unwrap();
        assert!(matches!(
            temp.store()
                .upload_status(expected, principal(), &operation()),
            Err(UploadError::Busy)
        ));
        assert!(matches!(
            temp.store().append_upload(
                expected,
                principal(),
                0,
                &mut Cursor::new(b"abc"),
                &operation()
            ),
            Err(UploadError::Busy)
        ));
        assert!(matches!(
            temp.store()
                .begin_upload(expected, principal(), &operation()),
            Err(UploadError::Busy)
        ));
        drop(owner);
        assert_eq!(
            temp.store()
                .upload_status(expected, principal(), &operation())
                .unwrap(),
            partial(0)
        );
    }
}

#[test]
fn initialization_crash_retry_is_bounded_and_does_not_overwrite_retained_data() {
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    let directory = temp.session();
    fs::remove_file(directory.join("checkpoint")).unwrap();
    fs::remove_file(directory.join("payload")).unwrap();
    fs::rename(directory.join("identity"), directory.join("identity.next")).unwrap();
    assert_eq!(
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .unwrap(),
        partial(0)
    );
    temp.store()
        .append_upload(
            expected,
            principal(),
            0,
            &mut Cursor::new(b"abc"),
            &operation(),
        )
        .unwrap();
    fs::remove_file(directory.join("checkpoint")).unwrap();
    assert!(matches!(
        temp.store()
            .begin_upload(expected, principal(), &operation()),
        Err(UploadError::Corrupt)
    ));
    assert_eq!(fs::read(directory.join("payload")).unwrap(), b"abc");
}

#[test]
fn symlinks_hardlinks_and_missing_retained_payload_are_not_accepted() {
    for hardlink in [false, true] {
        let temp = Temp::new();
        let expected = object(b"abcdef");
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .unwrap();
        let payload = temp.session().join("payload");
        let target = temp.0.join("outside");
        if hardlink {
            fs::hard_link(&payload, &target).unwrap();
        } else {
            fs::remove_file(&payload).unwrap();
            symlink(&target, &payload).unwrap();
        }
        assert!(matches!(
            temp.store()
                .upload_status(expected, principal(), &operation()),
            Err(UploadError::Storage(ArtifactStorageError::UnsafePath))
        ));
        assert!(matches!(
            temp.store()
                .begin_upload(expected, principal(), &operation()),
            Err(UploadError::Storage(ArtifactStorageError::UnsafePath))
        ));
    }
    let temp = Temp::new();
    let expected = object(b"abcdef");
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    let payload = temp.session().join("payload");
    fs::remove_file(&payload).unwrap();
    assert!(
        temp.store()
            .begin_upload(expected, principal(), &operation())
            .is_err()
    );
    assert!(!payload.exists());
}

#[test]
fn byte_and_cancellation_envelopes_apply_before_any_reservation() {
    let temp = Temp::new();
    let expected = object(b"abcdef");
    let small = ArtifactOperation::new(5, Duration::from_secs(5), &|| true).unwrap();
    assert!(matches!(
        temp.store().begin_upload(expected, principal(), &small),
        Err(UploadError::Storage(ArtifactStorageError::PayloadLimit))
    ));
    let cancelled = ArtifactOperation::new(6, Duration::from_secs(5), &|| false).unwrap();
    assert!(matches!(
        temp.store().begin_upload(expected, principal(), &cancelled),
        Err(UploadError::Storage(ArtifactStorageError::Cancelled))
    ));
    let huge = LfsObject {
        size: MAX_OBJECT_BYTES + 1,
        ..expected
    };
    assert!(matches!(
        temp.store().begin_upload(huge, principal(), &operation()),
        Err(UploadError::Storage(ArtifactStorageError::PayloadLimit))
    ));
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
}

#[test]
fn long_patch_checkpoints_incrementally_before_read_failure() {
    struct Interrupted<'a> {
        input: Cursor<&'a [u8]>,
        checkpoint: PathBuf,
    }
    impl Read for Interrupted<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.input.read(buffer)?;
            if count == 0 {
                let record = fs::read(&self.checkpoint)?;
                assert_eq!(
                    u64::from_be_bytes(record[40..48].try_into().unwrap()),
                    1024 * 1024
                );
                Err(io::ErrorKind::ConnectionReset.into())
            } else {
                Ok(count)
            }
        }
    }
    let temp = Temp::new();
    let data: Vec<_> = (0..(1024 * 1024 + 65537))
        .map(|n| (n % 251) as u8)
        .collect();
    let expected = object(&data);
    let prefix = 1024 * 1024 + 17;
    temp.store()
        .begin_upload(expected, principal(), &operation())
        .unwrap();
    assert!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                0,
                &mut Interrupted {
                    input: Cursor::new(&data[..prefix]),
                    checkpoint: temp.session().join("checkpoint"),
                },
                &operation()
            )
            .is_err()
    );
    assert_eq!(
        temp.store()
            .upload_status(expected, principal(), &operation())
            .unwrap(),
        partial(prefix as u64)
    );
    assert_eq!(
        temp.store()
            .append_upload(
                expected,
                principal(),
                prefix as u64,
                &mut Cursor::new(&data[prefix..]),
                &operation()
            )
            .unwrap(),
        complete(data.len() as u64)
    );
    assert_eq!(temp.store().read(expected, &operation()).unwrap(), data);
}
