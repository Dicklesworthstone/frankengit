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
        Self::for_kind(format, ObjectKind::Blob, body)
    }

    fn for_kind(format: GitHashAlgorithm, kind: ObjectKind, body: Vec<u8>) -> Self {
        let native = native_kind(kind).unwrap();
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
        let id = fgit_crypto::git_object_id(format, native, &body);
        let commitment =
            fgit_crypto::git_payload_commitment(native, &body, CANONICAL_CODEC_VERSION);
        let envelope = ObjectEnvelope::new(
            b"stream-test".to_vec(),
            id,
            kind,
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

const NATIVE_KINDS: [ObjectKind; 4] = [
    ObjectKind::Commit,
    ObjectKind::Tree,
    ObjectKind::Blob,
    ObjectKind::Tag,
];

#[test]
fn integrity_scan_matches_whole_object_verification_for_every_native_kind_and_format() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for kind in NATIVE_KINDS {
            for body in [Vec::new(), vec![91; CHUNK_BYTES * 2 + 17]] {
                let fixture = Fixture::for_kind(format, kind, body);
                let maximum = fixture.body.len() as u64;
                let original = fixture
                    .fabric
                    .read_whole_bounded(fixture.id, maximum)
                    .unwrap()
                    .object;
                let mut probes = 0;
                let receipt = fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || {
                        probes += 1;
                        true
                    })
                    .unwrap();
                assert_eq!(receipt.identity(), original.identity());
                assert_eq!(receipt.object_kind(), original.envelope().object_kind());
                assert_eq!(receipt.payload_length(), original.payload().len() as u64);
                assert!(probes >= 4);
                if !fixture.body.is_empty() {
                    assert!(
                        probes > 4,
                        "multi-chunk scans retain cooperative checkpoints"
                    );
                }
                assert_eq!(
                    fs::read_dir(fixture.root.join("staging")).unwrap().count(),
                    0
                );
                if kind != ObjectKind::Blob {
                    assert!(matches!(
                        fixture.fabric.open_blob_stream_bounded(fixture.id, maximum),
                        Err(StoreRefusal::NativeObjectIdentityMismatch)
                    ));
                }
            }
        }
    }
}

#[test]
fn integrity_preflight_refuses_limits_and_invalid_envelopes_before_payload_work() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for kind in NATIVE_KINDS {
            let fixture = Fixture::for_kind(format, kind, vec![42; CHUNK_BYTES + 17]);
            let maximum = fixture.body.len() as u64;
            let mut corrupt = fixture.body.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            fixture.store(&fixture.envelope, &corrupt);
            // A corrupt body must not be scanned to discover a known budget
            // failure. Opening and its post-I/O probe are the only checkpoints.
            let mut probes = 0;
            assert_eq!(
                fixture.fabric.verify_object_integrity_bounded(
                    fixture.id,
                    maximum - 1,
                    &mut || {
                        probes += 1;
                        true
                    },
                ),
                Err(StoreRefusal::StreamingBudgetExceeded {
                    offered: maximum,
                    maximum: maximum - 1,
                })
            );
            assert_eq!(probes, 2);
            assert_eq!(
                fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || true,),
                Err(StoreRefusal::PayloadCommitmentMismatch)
            );
            for fault in ["namespace", "identity", "internal", "length"] {
                let mut envelope = fixture.envelope.clone();
                match fault {
                    "namespace" => envelope.namespace = b"foreign".to_vec(),
                    "identity" => {
                        envelope.object_identity = fgit_crypto::git_object_id(
                            format,
                            native_kind(kind).unwrap(),
                            b"another identity",
                        );
                    }
                    "internal" => envelope.object_kind = ObjectKind::Internal,
                    "length" => envelope.declared_length += 1,
                    _ => unreachable!(),
                }
                fixture.store(&envelope, &fixture.body);
                let error = fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || true)
                    .unwrap_err();
                match fault {
                    "namespace" => assert_eq!(error, StoreRefusal::NamespaceMismatch),
                    "identity" => assert!(matches!(
                        error,
                        StoreRefusal::StoredObjectReconstructionMismatch { .. }
                    )),
                    "internal" => assert_eq!(error, StoreRefusal::NativeObjectIdentityMismatch),
                    "length" => assert_eq!(error, StoreRefusal::MalformedStoredObject),
                    _ => unreachable!(),
                }
            }
            fixture.store(&fixture.envelope, &fixture.body);
            assert_eq!(
                fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || true)
                    .unwrap()
                    .payload_length(),
                maximum
            );
        }
    }
}

#[test]
fn integrity_scan_checks_both_original_commitments_for_every_kind() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for kind in NATIVE_KINDS {
            let fixture = Fixture::for_kind(format, kind, vec![42; CHUNK_BYTES + 17]);
            let maximum = fixture.body.len() as u64;
            let mut changed = fixture.envelope.clone();
            changed.payload_commitment[0] ^= 1;
            fixture.store(&changed, &fixture.body);
            assert_eq!(
                fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || true,),
                Err(StoreRefusal::PayloadCommitmentMismatch)
            );
            // The strong commitment still matches these bytes, but the claimed
            // native identity does not. The keyed path alone cannot bless it.
            changed = fixture.envelope.clone();
            let wrong = fgit_crypto::git_object_id(
                format,
                native_kind(kind).unwrap(),
                b"wrong native bytes",
            );
            changed.object_identity = wrong;
            fixture.store(&changed, &fixture.body);
            let wrong_path = fixture.fabric.object_path(wrong);
            fs::rename(&fixture.path, &wrong_path).unwrap();
            assert_eq!(
                fixture
                    .fabric
                    .verify_object_integrity_bounded(wrong, maximum, &mut || true,),
                Err(StoreRefusal::NativeObjectIdentityMismatch)
            );
            fs::rename(wrong_path, &fixture.path).unwrap();
            fixture.store(&fixture.envelope, &fixture.body);
            assert!(
                fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || true,)
                    .is_ok()
            );
        }
    }
}

#[test]
fn integrity_scan_detects_mutation_after_open_and_keeps_the_checked_descriptor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for kind in NATIVE_KINDS {
            for fault in ["payload", "short", "extra", "replace"] {
                let fixture = Fixture::for_kind(format, kind, vec![73; CHUNK_BYTES * 3 + 17]);
                let maximum = fixture.body.len() as u64;
                let mut probes = 0;
                let result = fixture.fabric.verify_object_integrity_bounded(
                    fixture.id,
                    maximum,
                    &mut || {
                        probes += 1;
                        // The post-open probe owns a checked descriptor but
                        // has not started body reads. Mutate the path now.
                        if probes == 2 {
                            match fault {
                                "payload" => {
                                    let mut corrupt = fixture.body.clone();
                                    *corrupt.last_mut().unwrap() ^= 1;
                                    fixture.store(&fixture.envelope, &corrupt);
                                }
                                "short" => {
                                    let file =
                                        File::options().write(true).open(&fixture.path).unwrap();
                                    file.set_len(file.metadata().unwrap().len() - 1).unwrap();
                                }
                                "extra" => {
                                    File::options()
                                        .append(true)
                                        .open(&fixture.path)
                                        .unwrap()
                                        .write_all(&[1])
                                        .unwrap();
                                }
                                "replace" => {
                                    fs::rename(
                                        &fixture.path,
                                        fixture.path.with_extension("original"),
                                    )
                                    .unwrap();
                                    fixture.store(&fixture.envelope, &vec![1; fixture.body.len()]);
                                }
                                _ => unreachable!(),
                            }
                        }
                        true
                    },
                );
                match fault {
                    "payload" => assert_eq!(result, Err(StoreRefusal::PayloadCommitmentMismatch)),
                    "short" | "extra" => {
                        assert_eq!(result, Err(StoreRefusal::MalformedStoredObject))
                    }
                    "replace" => {
                        assert_eq!(result.unwrap().identity(), fixture.id);
                        assert_eq!(
                            fixture.fabric.verify_object_integrity_bounded(
                                fixture.id,
                                maximum,
                                &mut || true,
                            ),
                            Err(StoreRefusal::PayloadCommitmentMismatch)
                        );
                    }
                    _ => unreachable!(),
                }
                fixture.store(&fixture.envelope, &fixture.body);
                assert!(
                    fixture
                        .fabric
                        .verify_object_integrity_bounded(fixture.id, maximum, &mut || true,)
                        .is_ok()
                );
            }
        }
    }
}

#[test]
fn integrity_cancellation_is_chunk_bounded_closes_custody_and_preserves_error_precedence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for kind in NATIVE_KINDS {
            let fixture = Fixture::for_kind(format, kind, vec![59; CHUNK_BYTES * 3 + 17]);
            let maximum = fixture.body.len() as u64;
            let mut probes = 0;
            assert_eq!(
                fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || {
                        probes += 1;
                        probes < 5
                    },),
                Err(StoreRefusal::RuntimeCheckpointRejected)
            );
            assert_eq!(probes, 5, "cancel before the second bounded chunk");
            #[cfg(target_os = "linux")]
            {
                let held = fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter_map(|entry| fs::read_link(entry.path()).ok())
                    .filter(|path| path == &fixture.path)
                    .count();
                assert_eq!(
                    held, 0,
                    "cancelled integrity reads must close their descriptor"
                );
            }
            assert!(
                fixture
                    .fabric
                    .verify_object_integrity_bounded(fixture.id, maximum, &mut || true,)
                    .is_ok()
            );

            let empty = Fixture::for_kind(format, kind, Vec::new());
            let mut changed = empty.envelope.clone();
            changed.payload_commitment[0] ^= 1;
            empty.store(&changed, &[]);
            let mut probes = 0;
            assert_eq!(
                empty
                    .fabric
                    .verify_object_integrity_bounded(empty.id, 0, &mut || {
                        probes += 1;
                        probes < 4
                    }),
                Err(StoreRefusal::RuntimeCheckpointRejected),
                "post-read expiry outranks the failed exact-EOF commitment check"
            );
            assert_eq!(probes, 4);
            assert_eq!(
                empty
                    .fabric
                    .verify_object_integrity_bounded(empty.id, 0, &mut || true),
                Err(StoreRefusal::PayloadCommitmentMismatch)
            );
            empty.store(&empty.envelope, &[]);
            assert_eq!(
                empty
                    .fabric
                    .verify_object_integrity_bounded(empty.id, 0, &mut || true)
                    .unwrap()
                    .payload_length(),
                0
            );
        }
    }
}

#[test]
fn integrity_scan_never_promotes_or_reads_private_unplaced_residue() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, vec![97; 100]);
        let private = fixture.root.join("staging").join("unplaced.stage");
        fs::rename(&fixture.path, &private).unwrap();
        assert_eq!(
            fixture
                .fabric
                .verify_object_integrity_bounded(fixture.id, 100, &mut || false),
            Err(StoreRefusal::RuntimeCheckpointRejected)
        );
        assert_eq!(
            fixture
                .fabric
                .verify_object_integrity_bounded(fixture.id, 100, &mut || true),
            Err(StoreRefusal::ObjectAbsent)
        );
        assert!(
            private.exists(),
            "integrity inspection must not mutate private custody"
        );
        assert!(!fixture.path.exists());
        fs::rename(private, &fixture.path).unwrap();
        assert!(
            fixture
                .fabric
                .verify_object_integrity_bounded(fixture.id, 100, &mut || true)
                .is_ok()
        );
    }
}
