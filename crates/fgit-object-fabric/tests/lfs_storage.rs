#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, LfsStore};
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactPut, ArtifactStorageError as Error,
};
use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    fs,
    io::{self, Cursor, Read},
    path::PathBuf,
    time::Duration,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "fg-lfs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
    fn store(&self, tenant: u8) -> LfsStore {
        LfsStore::open(
            &self.0,
            TenantId::from_bytes([tenant; 16]),
            RepositoryId::from_bytes([2; 16]),
            RepositoryIncarnationId::from_bytes([3; 16]),
        )
        .unwrap()
    }
    fn files(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.0)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().unwrap().is_dir())
            .flat_map(|e| {
                fs::read_dir(e.path())
                    .unwrap()
                    .flatten()
                    .map(|f| f.path())
                    .collect::<Vec<_>>()
            })
            .collect()
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
fn op() -> ArtifactOperation<'static> {
    ArtifactOperation::new(8 * 1024 * 1024, Duration::from_secs(15), &|| true).unwrap()
}
#[test]
fn pointer_roundtrips_and_rejects_ambiguous_identity() {
    for bytes in [&b""[..], &b"asset\0binary\xff"[..]] {
        let x = object(bytes);
        assert_eq!(LfsObject::parse_pointer(x.pointer().as_bytes()).unwrap(), x);
    }
    let x = object(b"hello");
    let pointer = x.pointer();
    for bad in [
        pointer.replace("size 5", "size 05"),
        pointer.replace("size 5", "size -5"),
        pointer.replace("sha256:", "sha1:"),
        pointer.replace("/v1", "/v2"),
        pointer.trim_end().into(),
        format!("{pointer}other value\n"),
        pointer.replace('\n', "\r\n"),
    ] {
        assert!(LfsObject::parse_pointer(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(LfsOid::parse(&x.oid.to_string().to_uppercase()).is_err());
    assert!(LfsObject::parse(&x.oid.to_string(), "18446744073709551616").is_err());
}
#[test]
fn streamed_payloads_survive_reopen_and_retry_without_duplicate_storage() {
    for size in [0, 1, 65537, 2 * 1024 * 1024] {
        let t = Temp::new();
        let data = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let x = object(&data);
        assert!(!t.store(1).contains(x, &op()).unwrap());
        assert_eq!(
            t.store(1).put(x, &mut Cursor::new(&data), &op()).unwrap(),
            ArtifactPut::Created
        );
        assert_eq!(
            t.store(1).put(x, &mut Cursor::new(&data), &op()).unwrap(),
            ArtifactPut::AlreadyPresent
        );
        assert_eq!(t.store(1).read(x, &op()).unwrap(), data);
        assert_eq!(t.files().len(), 1);
        assert!(!t.store(9).contains(x, &op()).unwrap());
    }
}
#[test]
fn incomplete_overlong_and_wrong_digest_never_publish_and_exact_retry_recovers() {
    for bad in [&b"abc"[..], &b"abcdefg"[..], &b"ABCDEF"[..]] {
        let t = Temp::new();
        let x = object(b"abcdef");
        assert!(t.store(1).put(x, &mut Cursor::new(bad), &op()).is_err());
        assert!(!t.store(1).contains(x, &op()).unwrap());
        assert!(t.files().is_empty());
        assert_eq!(
            t.store(1)
                .put(x, &mut Cursor::new(b"abcdef"), &op())
                .unwrap(),
            ArtifactPut::Created
        );
    }
}
#[test]
fn streamed_intake_handles_short_reads_without_buffering_whole_payload() {
    struct Slow(Cursor<Vec<u8>>);
    impl Read for Slow {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = b.len().min(7);
            self.0.read(&mut b[..n])
        }
    }
    let t = Temp::new();
    let bytes = vec![8; 70001];
    let x = object(&bytes);
    t.store(1)
        .put(x, &mut Slow(Cursor::new(bytes.clone())), &op())
        .unwrap();
    assert_eq!(t.store(1).read(x, &op()).unwrap(), bytes);
}
#[test]
fn cancellation_limits_and_io_failure_leave_no_payload_name() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::ConnectionReset.into())
        }
    }
    let t = Temp::new();
    let x = object(b"data");
    assert!(t.store(1).put(x, &mut Broken, &op()).is_err());
    let cancelled = ArtifactOperation::new(4, Duration::from_secs(1), &|| false).unwrap();
    assert!(matches!(
        t.store(1).put(x, &mut Cursor::new(b"data"), &cancelled),
        Err(Error::Cancelled)
    ));
    let limited = ArtifactOperation::new(3, Duration::from_secs(1), &|| true).unwrap();
    assert!(matches!(
        t.store(1).put(x, &mut Cursor::new(b"data"), &limited),
        Err(Error::PayloadLimit)
    ));
    assert!(t.files().is_empty());
    t.store(1).put(x, &mut Cursor::new(b"data"), &op()).unwrap();
    assert!(t.store(1).contains(x, &op()).unwrap());
}
#[test]
fn corrupt_custody_is_not_absence_and_is_never_healed_by_overwrite() {
    let t = Temp::new();
    let x = object(b"payload");
    t.store(1)
        .put(x, &mut Cursor::new(b"payload"), &op())
        .unwrap();
    let p = t.files().pop().unwrap();
    let mut raw = fs::read(&p).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    fs::write(&p, &raw).unwrap();
    assert!(t.store(1).contains(x, &op()).is_err());
    assert!(t.store(1).read(x, &op()).is_err());
    assert!(
        t.store(1)
            .put(x, &mut Cursor::new(b"payload"), &op())
            .is_err()
    );
    assert_eq!(fs::read(p).unwrap(), raw);
    assert_eq!(t.files().len(), 1);
}
#[test]
fn symlink_namespace_is_not_treated_as_missing() {
    let t = Temp::new();
    let x = object(b"payload");
    t.store(1)
        .put(x, &mut Cursor::new(b"payload"), &op())
        .unwrap();
    let directory = t.files()[0].parent().unwrap().to_path_buf();
    fs::remove_dir_all(&directory).unwrap();
    symlink(t.0.join("absent"), directory).unwrap();
    assert!(matches!(
        t.store(1).contains(x, &op()),
        Err(Error::UnsafePath)
    ));
}

#[test]
fn a_missing_selected_root_is_unavailable_not_an_absent_object() {
    let t = Temp::new();
    let store = t.store(1);
    fs::remove_dir(&t.0).unwrap();
    assert!(matches!(
        store.contains(object(b"x"), &op()),
        Err(Error::Io { .. })
    ));
    fs::DirBuilder::new().mode(0o700).create(&t.0).unwrap();
    assert!(!store.contains(object(b"x"), &op()).unwrap());
}
