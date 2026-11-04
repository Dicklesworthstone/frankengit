#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

//! Generated large payloads exercise the actual custody and reader APIs without
//! allocating a payload-sized input or output in the fixture.

use std::cell::Cell;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, LfsStore, MAX_OBJECT_BYTES};
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactPut, ArtifactStorageError as Error, MAX_BUFFERED_PAYLOAD_BYTES,
};
use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};

const CHUNK: usize = 64 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-lfs-stream-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn store(&self, tenant: u8, repository: u8, incarnation: u8) -> LfsStore {
        LfsStore::open(
            &self.0,
            TenantId::from_bytes([tenant; 16]),
            RepositoryId::from_bytes([repository; 16]),
            RepositoryIncarnationId::from_bytes([incarnation; 16]),
        )
        .unwrap()
    }
    fn object_file(&self) -> PathBuf {
        let mut namespaces = fs::read_dir(&self.0).unwrap();
        let namespace = namespaces.next().unwrap().unwrap();
        assert!(namespace.file_type().unwrap().is_dir());
        assert!(
            namespaces.next().is_none(),
            "no named read spool may remain"
        );
        let mut files = fs::read_dir(namespace.path()).unwrap();
        let object = files.next().unwrap().unwrap().path();
        assert!(
            files.next().is_none(),
            "only immutable custody may be named"
        );
        object
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Generated {
    remaining: u64,
}
impl Read for Generated {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.remaining as usize);
        output[..count].fill(0x9d);
        self.remaining -= count as u64;
        Ok(count)
    }
}
fn generated_object(size: u64) -> LfsObject {
    let mut hash = Sha256Hasher::new();
    let chunk = [0x9d; CHUNK];
    let mut remaining = size;
    while remaining != 0 {
        let count = (remaining as usize).min(chunk.len());
        hash.update(&chunk[..count]);
        remaining -= count as u64;
    }
    LfsObject {
        oid: LfsOid::parse(&hex(&hash.finish())).unwrap(),
        size,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn operation() -> ArtifactOperation<'static> {
    ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(120), &|| true).unwrap()
}
fn put(store: &LfsStore, object: LfsObject) -> ArtifactPut {
    store
        .put(
            object,
            &mut Generated {
                remaining: object.size,
            },
            &operation(),
        )
        .unwrap()
}
fn verify_reader(reader: &mut impl Read, expected: LfsObject) {
    // Deliberately larger than the reader's advertised per-read envelope.
    let mut chunk = [0_u8; CHUNK * 2];
    let mut count = 0_u64;
    let mut hash = Sha256Hasher::new();
    loop {
        let read = reader.read(&mut chunk).unwrap();
        assert!(read <= CHUNK);
        if read == 0 {
            break;
        }
        count += read as u64;
        hash.update(&chunk[..read]);
    }
    assert_eq!(count, expected.size);
    assert_eq!(hex(&hash.finish()), expected.oid.to_string());
}

#[test]
fn payload_above_buffered_limit_survives_cold_reopen_and_streams_exactly() {
    let temp = Temp::new();
    let object = generated_object(MAX_BUFFERED_PAYLOAD_BYTES + 17);
    let store = temp.store(1, 2, 3);
    assert_eq!(put(&store, object), ArtifactPut::Created);
    drop(store);
    let reopened = temp.store(1, 2, 3);
    let op = operation();
    assert!(matches!(
        reopened.read(object, &op),
        Err(Error::PayloadLimit)
    ));
    let mut reader = reopened.open_verified(object, &op).unwrap();
    assert_eq!(reader.identity(), &object.artifact_identity());
    assert_eq!(reader.remaining(), object.size);
    verify_reader(&mut reader, object);
    assert_eq!(reader.remaining(), 0);
    assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
    drop(reader);
    assert_eq!(put(&reopened, object), ArtifactPut::AlreadyPresent);
    assert!(temp.object_file().is_file());
}

#[test]
fn empty_small_and_multichunk_payloads_preserve_the_buffered_api() {
    for size in [0, 1, CHUNK as u64 + 7] {
        let temp = Temp::new();
        let object = generated_object(size);
        let store = temp.store(1, 2, 3);
        put(&store, object);
        let op = operation();
        verify_reader(&mut store.open_verified(object, &op).unwrap(), object);
        let bytes = store.read(object, &op).unwrap();
        assert_eq!(bytes.len() as u64, size);
        assert!(bytes.iter().all(|byte| *byte == 0x9d));
        assert!(temp.object_file().is_file());
    }
}

#[test]
fn later_source_mutation_cannot_change_an_already_verified_stream() {
    let temp = Temp::new();
    let object = generated_object(CHUNK as u64 * 2 + 9);
    let store = temp.store(1, 2, 3);
    put(&store, object);
    let op = operation();
    let mut reader = store.open_verified(object, &op).unwrap();
    let path = temp.object_file();
    // Replace the original container after complete verification, before any
    // caller read. A second pass over that path would now disclose bad bytes.
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, bytes).unwrap();
    verify_reader(&mut reader, object);
    assert!(store.open_verified(object, &op).is_err());
    assert_eq!(temp.object_file(), path);
}

#[test]
fn corrupt_short_and_overlong_sources_never_construct_a_reader() {
    for variant in 0..3 {
        let temp = Temp::new();
        let object = generated_object(CHUNK as u64 + 7);
        let store = temp.store(1, 2, 3);
        put(&store, object);
        let path = temp.object_file();
        let mut bytes = fs::read(&path).unwrap();
        match variant {
            0 => *bytes.last_mut().unwrap() ^= 1,
            1 => {
                bytes.pop();
            }
            _ => bytes.push(0),
        }
        fs::write(&path, &bytes).unwrap();
        assert!(store.open_verified(object, &operation()).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(temp.object_file(), path);
    }
}

#[test]
fn cancellation_during_construction_cleans_spool_and_keeps_immutable_custody() {
    let temp = Temp::new();
    let object = generated_object(CHUNK as u64 * 8);
    let store = temp.store(1, 2, 3);
    put(&store, object);
    let path = temp.object_file();
    let calls = Cell::new(0);
    let live = || {
        calls.set(calls.get() + 1);
        calls.get() < 8
    };
    let op = ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(60), &live).unwrap();
    assert!(matches!(
        store.open_verified(object, &op),
        Err(Error::Cancelled)
    ));
    assert_eq!(calls.get(), 8);
    assert_eq!(temp.object_file(), path);
    let fresh = operation();
    verify_reader(&mut store.open_verified(object, &fresh).unwrap(), object);
}

#[test]
fn cancellation_after_verification_cannot_be_reset_on_the_same_reader() {
    let temp = Temp::new();
    let object = generated_object(CHUNK as u64 * 2);
    let store = temp.store(1, 2, 3);
    put(&store, object);
    let running = Cell::new(true);
    let live = || running.get();
    let op = ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(60), &live).unwrap();
    let mut reader = store.open_verified(object, &op).unwrap();
    let mut chunk = [0; CHUNK];
    assert_eq!(reader.read(&mut chunk).unwrap(), CHUNK);
    running.set(false);
    assert_eq!(
        reader.read(&mut chunk).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    running.set(true);
    assert_eq!(
        reader.read(&mut chunk).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    drop(reader);
    let fresh = operation();
    verify_reader(&mut store.open_verified(object, &fresh).unwrap(), object);
    assert!(temp.object_file().is_file());
}

#[test]
fn exact_scope_and_declared_envelopes_are_enforced_before_exposure() {
    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("an oversized declaration must be refused before input")
        }
    }
    let temp = Temp::new();
    let object = generated_object(7);
    let store = temp.store(1, 2, 3);
    put(&store, object);
    for (tenant, repository, incarnation) in [(9, 2, 3), (1, 9, 3), (1, 2, 9)] {
        assert!(matches!(
            temp.store(tenant, repository, incarnation)
                .open_verified(object, &operation()),
            Err(Error::NotFound)
        ));
    }
    let smaller = ArtifactOperation::new(6, Duration::from_secs(60), &|| true).unwrap();
    assert!(matches!(
        store.open_verified(object, &smaller),
        Err(Error::PayloadLimit)
    ));
    assert!(matches!(
        store.open_verified(LfsObject { size: 8, ..object }, &operation()),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.put(
            LfsObject {
                size: MAX_OBJECT_BYTES + 1,
                ..object
            },
            &mut NoRead,
            &operation()
        ),
        Err(Error::PayloadLimit)
    ));
    assert!(
        ArtifactOperation::new(MAX_OBJECT_BYTES + 1, Duration::from_secs(60), &|| true).is_err()
    );
    let expired =
        ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_nanos(1), &|| true).unwrap();
    assert!(matches!(
        store.open_verified(object, &expired),
        Err(Error::Deadline)
    ));
    assert!(temp.object_file().is_file());
}
