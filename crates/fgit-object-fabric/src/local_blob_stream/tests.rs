use super::super::{CANONICAL_CODEC_VERSION, NEXT_STAGE, OBJECT_MAGIC};
use super::*;
use crate::SegmentLimits;
use crate::local::LocalFilesystemConfig;
use fgit_resource::OpaqueHandle;
use fgit_types::GitHashAlgorithm;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

struct Fixture {
    root: PathBuf,
    fabric: LocalFilesystemFabric,
    id: GitOid,
    path: PathBuf,
    envelope: ObjectEnvelope,
    body: Vec<u8>,
}

impl Fixture {
    fn new(format: GitHashAlgorithm, body: Vec<u8>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "frankengit-blob-stream-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed),
        ));
        let fabric = LocalFilesystemFabric::open(LocalFilesystemConfig::new(
            root.clone(),
            b"stream-test".to_vec(),
            OpaqueHandle::new(b"disk").unwrap(),
            OpaqueHandle::new(b"key").unwrap(),
            1024 * 1024,
            SegmentLimits::default(),
        ))
        .unwrap();
        let id = fgit_crypto::git_object_id(format, GitObjectKind::Blob, &body);
        let commitment = fgit_crypto::git_payload_commitment(
            GitObjectKind::Blob,
            &body,
            CANONICAL_CODEC_VERSION,
        );
        let envelope = ObjectEnvelope::new(
            b"stream-test".to_vec(),
            id,
            ObjectKind::Blob,
            body.len() as u64,
            commitment.digest().as_bytes().try_into().unwrap(),
            b"raw".to_vec(),
            [7; 32],
            None,
            &SegmentLimits::default(),
        )
        .unwrap();
        let path = fabric.object_path(id);
        let fixture = Self {
            root,
            fabric,
            id,
            path,
            envelope,
            body,
        };
        fixture.store(&fixture.envelope, &fixture.body);
        fixture
    }

    fn store(&self, envelope: &ObjectEnvelope, body: &[u8]) {
        fs::create_dir_all(self.path.parent().unwrap()).unwrap();
        let bytes = envelope.encode().unwrap();
        let mut file = File::create(&self.path).unwrap();
        file.write_all(OBJECT_MAGIC).unwrap();
        file.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
        file.write_all(&bytes).unwrap();
        file.write_all(body).unwrap();
    }

    fn open(&self) -> LocalBlobStream {
        self.fabric
            .open_blob_stream_bounded(self.id, self.body.len() as u64)
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.root);
    }
}

fn collect(stream: &mut LocalBlobStream, chunk: usize) -> Result<Vec<u8>, StoreRefusal> {
    let mut bytes = Vec::new();
    let mut buffer = vec![0; chunk];
    loop {
        let count = stream.read_tentative(&mut buffer)?;
        assert!(count <= CHUNK_BYTES);
        if count == 0 {
            assert!(stream.is_verified());
            break;
        }
        assert!(
            !stream.is_verified(),
            "chunks remain tentative until the EOF probe"
        );
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

#[test]
fn one_descriptor_stream_checks_both_hashes_at_exact_eof_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for body in [Vec::new(), vec![91; CHUNK_BYTES + 17]] {
            let fixture = Fixture::new(format, body);
            for chunk in [1, 7, CHUNK_BYTES, CHUNK_BYTES * 2] {
                let mut stream = fixture.open();
                assert_eq!(stream.identity(), fixture.id);
                assert_eq!(stream.declared_length(), fixture.body.len() as u64);
                assert!(!stream.is_verified());
                assert_eq!(collect(&mut stream, chunk).unwrap(), fixture.body);
                assert_eq!(stream.read_tentative(&mut [0]), Ok(0));
            }
            assert_eq!(
                fixture
                    .fabric
                    .read_whole_bounded(fixture.id, fixture.body.len() as u64)
                    .unwrap()
                    .object
                    .payload(),
                fixture.body
            );
        }
    }
}

#[test]
fn limits_namespace_kind_identity_and_length_are_checked_before_body_reads() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, vec![42; 100]);
    assert!(matches!(
        fixture.fabric.open_blob_stream_bounded(fixture.id, 99),
        Err(StoreRefusal::StreamingBudgetExceeded {
            offered: 100,
            maximum: 99
        })
    ));
    assert_eq!(collect(&mut fixture.open(), 17).unwrap(), fixture.body);
    for case in 0..4 {
        let mut envelope = fixture.envelope.clone();
        match case {
            0 => envelope.namespace = b"other".to_vec(),
            1 => envelope.object_kind = ObjectKind::Tree,
            2 => {
                envelope.object_identity = fgit_crypto::git_object_id(
                    GitHashAlgorithm::Sha1,
                    GitObjectKind::Blob,
                    b"wrong",
                );
            }
            3 => envelope.declared_length += 1,
            _ => unreachable!(),
        }
        fixture.store(&envelope, &fixture.body);
        let error = fixture
            .fabric
            .open_blob_stream_bounded(fixture.id, 100)
            .unwrap_err();
        match case {
            0 => assert_eq!(error, StoreRefusal::NamespaceMismatch),
            1 => assert_eq!(error, StoreRefusal::NativeObjectIdentityMismatch),
            2 => assert!(matches!(
                error,
                StoreRefusal::StoredObjectReconstructionMismatch { .. }
            )),
            3 => assert_eq!(error, StoreRefusal::MalformedStoredObject),
            _ => unreachable!(),
        }
    }
    fixture.store(&fixture.envelope, &fixture.body);
    assert_eq!(collect(&mut fixture.open(), 17).unwrap(), fixture.body);
    File::options()
        .write(true)
        .open(&fixture.path)
        .unwrap()
        .set_len(2 * 1024 * 1024)
        .unwrap();
    assert!(matches!(
        fixture
            .fabric
            .open_blob_stream_bounded(fixture.id, u64::MAX),
        Err(StoreRefusal::StoredObjectTooLarge { .. })
    ));
}

#[test]
fn changed_bytes_short_files_and_growing_files_never_complete_and_refusals_latch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, vec![42; 100]);
        for case in 0..4 {
            fixture.store(&fixture.envelope, &fixture.body);
            let mut stream = fixture.open();
            match case {
                0 => {
                    let mut body = fixture.body.clone();
                    body[99] ^= 1;
                    fixture.store(&fixture.envelope, &body);
                }
                1 => {
                    let mut envelope = fixture.envelope.clone();
                    envelope.payload_commitment[0] ^= 1;
                    fixture.store(&envelope, &fixture.body);
                    stream = fixture.open();
                }
                2 => {
                    let file = File::options().write(true).open(&fixture.path).unwrap();
                    file.set_len(file.metadata().unwrap().len() - 1).unwrap();
                }
                3 => {
                    File::options()
                        .append(true)
                        .open(&fixture.path)
                        .unwrap()
                        .write_all(&[1])
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let error = collect(&mut stream, 17).unwrap_err();
            assert_eq!(
                error,
                if case < 2 {
                    StoreRefusal::PayloadCommitmentMismatch
                } else {
                    StoreRefusal::MalformedStoredObject
                }
            );
            assert!(!stream.is_verified());
            assert_eq!(stream.read_tentative(&mut [0]), Err(error));
        }
        fixture.store(&fixture.envelope, &fixture.body);
        assert_eq!(collect(&mut fixture.open(), 17).unwrap(), fixture.body);
    }
}

#[test]
fn a_valid_strong_commitment_cannot_replace_native_identity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, vec![42; 100]);
        let wrong = fgit_crypto::git_object_id(format, GitObjectKind::Blob, b"other");
        let mut envelope = fixture.envelope.clone();
        envelope.object_identity = wrong;
        fixture.store(&envelope, &fixture.body);
        fs::rename(&fixture.path, fixture.fabric.object_path(wrong)).unwrap();
        let mut stream = fixture.fabric.open_blob_stream_bounded(wrong, 100).unwrap();
        assert_eq!(
            collect(&mut stream, 11),
            Err(StoreRefusal::NativeObjectIdentityMismatch)
        );
        assert!(!stream.is_verified());
    }
}

#[test]
fn replacing_the_path_does_not_replace_the_checked_descriptor_and_drop_is_retryable() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, vec![42; 100]);
    let mut stream = fixture.open();
    fs::rename(&fixture.path, fixture.path.with_extension("old")).unwrap();
    fixture.store(&fixture.envelope, &[1; 100]);
    assert_eq!(collect(&mut stream, 7).unwrap(), fixture.body);
    assert!(collect(&mut fixture.open(), 7).is_err());
    fixture.store(&fixture.envelope, &fixture.body);
    let mut interrupted = fixture.open();
    assert_eq!(interrupted.read_tentative(&mut [0; 7]), Ok(7));
    assert!(!interrupted.is_verified());
    drop(interrupted);
    assert_eq!(collect(&mut fixture.open(), 7).unwrap(), fixture.body);
}
