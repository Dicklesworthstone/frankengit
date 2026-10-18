use super::super::graph;
use super::*;
use fgit_git_object::ParseLimits;
use fgit_types::GitHashAlgorithm;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-spool-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn empty(&self) -> bool {
        fs::read_dir(&self.0).unwrap().next().is_none()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn blob(format: GitHashAlgorithm, body: Vec<u8>) -> (GitOid, LooseObject) {
    let id = fgit_crypto::git_object_id(format, ObjectType::Blob, &body);
    (
        id,
        LooseObject {
            object_type: ObjectType::Blob,
            declared_size: body.len(),
            body,
        },
    )
}

#[test]
fn disk_custody_matches_memory_oracle_in_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let objects: BTreeMap<_, _> = (0..25)
            .map(|i| blob(format, vec![i as u8; i * 4097]))
            .collect();
        let roots: Vec<_> = objects
            .keys()
            .copied()
            .map(|id| (id, Some(ObjectType::Blob)))
            .collect();
        let limits = graph::Limits::default();
        let oracle = graph::validate_typed_controlled(
            roots.clone(),
            format,
            &ParseLimits::default(),
            limits,
            |id| Ok(objects[&id].clone()),
            &control,
        )
        .unwrap();
        let mut spool = Spool::create(&scratch.0, limits.bytes, &control).unwrap();
        let disk = graph::validate_typed_with_custody(
            roots,
            format,
            &ParseLimits::default(),
            limits,
            |id| Ok(objects[&id].clone()),
            |id, object| spool.retain(id, object, &control),
            &control,
        )
        .unwrap();
        assert_eq!(disk.total_bytes, oracle.total_bytes);
        assert_eq!(disk.objects.len(), oracle.objects.len());
        assert!(
            std::mem::size_of::<Entry>() <= 32,
            "handles cannot retain whole bodies"
        );
        for (id, entry) in disk.objects.into_iter().rev() {
            assert_eq!(
                spool.read(id, entry, &control).unwrap(),
                oracle.objects[&id]
            );
        }
        spool.finish().unwrap();
        assert!(scratch.empty());
    }
}

#[test]
fn inclusive_disk_limit_and_failed_write_never_grow_past_the_allowance() {
    let scratch = Scratch::new();
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    let (id, object) = blob(GitHashAlgorithm::Sha256, vec![42; IO_CHUNK_BYTES + 1]);
    let mut short = Spool::create(&scratch.0, IO_CHUNK_BYTES as u64, &control).unwrap();
    assert!(matches!(
        short.retain(id, object.clone(), &control),
        Err(LooseGitImportRefusal::TotalObjectBytesExceeded { .. })
    ));
    assert_eq!(short.file.as_ref().unwrap().metadata().unwrap().len(), 0);
    short.finish().unwrap();
    let mut exact = Spool::create(&scratch.0, object.body.len() as u64, &control).unwrap();
    let entry = exact.retain(id, object.clone(), &control).unwrap();
    assert_eq!(exact.read(id, entry, &control).unwrap(), object);
    exact.finish().unwrap();
    assert!(scratch.empty());
}

#[test]
fn spool_corruption_and_truncation_refuse_before_returning_a_body() {
    for truncate in [false, true] {
        let scratch = Scratch::new();
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let (id, object) = blob(
            GitHashAlgorithm::Sha256,
            b"original verified source".to_vec(),
        );
        let mut spool = Spool::create(&scratch.0, 1024, &control).unwrap();
        let entry = spool.retain(id, object, &control).unwrap();
        if truncate {
            spool.file.as_mut().unwrap().set_len(1).unwrap();
        } else {
            let file = spool.file.as_mut().unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(b"X").unwrap();
        }
        let result = spool.read(id, entry, &control);
        if truncate {
            assert!(matches!(result, Err(LooseGitImportRefusal::Io { .. })));
        } else {
            assert!(
                matches!(result, Err(LooseGitImportRefusal::ObjectIdentityMismatch { expected, .. }) if expected == id)
            );
        }
        spool.finish().unwrap();
        assert!(scratch.empty());
    }
}

#[test]
fn cancelled_creation_and_mid_body_write_leave_no_named_scratch() {
    let scratch = Scratch::new();
    let mut stopped = || false;
    let control = ImportControl::new(&mut stopped);
    assert!(Spool::create(&scratch.0, 1024, &control).is_err());
    assert!(scratch.empty());
    let calls = Cell::new(0);
    let mut live = || {
        calls.set(calls.get() + 1);
        calls.get() < 5
    };
    let control = ImportControl::new(&mut live);
    let mut spool = Spool::create(&scratch.0, 4 * IO_CHUNK_BYTES as u64, &control).unwrap();
    let (id, object) = blob(GitHashAlgorithm::Sha1, vec![3; 3 * IO_CHUNK_BYTES]);
    assert!(matches!(
        spool.retain(id, object, &control),
        Err(LooseGitImportRefusal::Interrupted { .. })
    ));
    assert!(spool.file.as_ref().unwrap().metadata().unwrap().len() <= IO_CHUNK_BYTES as u64);
    assert!(control.checkpoint().is_err());
    drop(spool);
    assert!(scratch.empty());
}

#[cfg(unix)]
#[test]
fn unix_custody_is_an_unlinked_private_file_before_any_payload_write() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let scratch = Scratch::new();
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    let spool = Spool::create(&scratch.0, 1024, &control).unwrap();
    assert!(scratch.empty());
    let metadata = spool.file.as_ref().unwrap().metadata().unwrap();
    assert_eq!(metadata.nlink(), 0);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    spool.finish().unwrap();
}

#[test]
fn interleaved_reads_cannot_overwrite_earlier_custody() {
    let scratch = Scratch::new();
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    let mut spool = Spool::create(&scratch.0, 1024, &control).unwrap();
    let (a, first) = blob(GitHashAlgorithm::Sha1, b"first".to_vec());
    let (b, second) = blob(GitHashAlgorithm::Sha1, b"second".to_vec());
    let (c, third) = blob(GitHashAlgorithm::Sha1, b"third".to_vec());
    let a = (a, spool.retain(a, first.clone(), &control).unwrap());
    let b = (b, spool.retain(b, second.clone(), &control).unwrap());
    assert_eq!(spool.read(a.0, a.1, &control).unwrap(), first);
    let c = (c, spool.retain(c, third.clone(), &control).unwrap());
    assert_eq!(spool.read(b.0, b.1, &control).unwrap(), second);
    assert_eq!(spool.read(c.0, c.1, &control).unwrap(), third);
    spool.finish().unwrap();
}
