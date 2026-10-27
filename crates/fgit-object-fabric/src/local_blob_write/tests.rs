use super::super::NEXT_STAGE;
use super::*;
use crate::SegmentLimits;
use crate::fabric::VerifiedObject;
use crate::local::LocalFilesystemConfig;
use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_resource::{LeakDisposition, ObligationLedger, OpaqueHandle, RegionId};
use fgit_types::GitHashAlgorithm;
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

struct Fixture {
    root: PathBuf,
    fabric: LocalFilesystemFabric,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "frankengit-blob-write-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed),
        ));
        let fabric = LocalFilesystemFabric::open(Self::config(root.clone())).unwrap();
        Self { root, fabric }
    }

    fn config(root: PathBuf) -> LocalFilesystemConfig {
        LocalFilesystemConfig::new(
            root,
            b"stream-placement".to_vec(),
            OpaqueHandle::new(b"disk").unwrap(),
            OpaqueHandle::new(b"key").unwrap(),
            64 * 1024 * 1024,
            SegmentLimits::default(),
        )
    }

    fn empty_staging(&self) {
        assert_eq!(fs::read_dir(self.fabric.staging_dir()).unwrap().count(), 0);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.root);
    }
}

fn envelope(format: GitHashAlgorithm, bytes: &[u8]) -> ObjectEnvelope {
    let id = git_object_id(format, GitObjectKind::Blob, bytes);
    let strong = git_payload_commitment(GitObjectKind::Blob, bytes, CANONICAL_CODEC_VERSION);
    ObjectEnvelope::new(
        b"stream-placement".to_vec(),
        id,
        ObjectKind::Blob,
        bytes.len() as u64,
        strong.digest().as_bytes().try_into().unwrap(),
        b"raw".to_vec(),
        [3; 32],
        None,
        &SegmentLimits::default(),
    )
    .unwrap()
}

fn place(
    fabric: &LocalFilesystemFabric,
    envelope: ObjectEnvelope,
    input: &mut dyn Read,
    limit: u64,
    live: &mut impl FnMut() -> bool,
) -> Result<PutIfAbsent, StoreRefusal> {
    let resources = ResourceVector::from_grades(&[
        (Grade::Bytes, envelope.declared_length().max(1)),
        (Grade::Objects, 1),
    ]);
    let ledger = ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        resources,
    );
    let grant = ledger.grant(resources).unwrap();
    let result = fabric.put_blob_stream_if_absent(
        envelope,
        input,
        limit,
        PlacementAdmission::new(&ledger, grant),
        live,
    );
    assert!(ledger.close().is_quiescent(), "placement leaked its grant");
    result
}

struct ShortReads<'a> {
    bytes: &'a [u8],
    short: usize,
    interrupt: bool,
}

impl Read for ShortReads<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        assert!(out.len() <= CHUNK_BYTES);
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = out.len().min(self.short).min(self.bytes.len());
        out[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn streamed_placement_matches_buffered_bytes_and_reauthenticates_retries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for body in [Vec::new(), vec![91; CHUNK_BYTES + 23]] {
            let fixture = Fixture::new();
            let envelope = envelope(format, &body);
            let mut input = ShortReads {
                bytes: &body,
                short: 71,
                interrupt: true,
            };
            let created = place(
                &fixture.fabric,
                envelope.clone(),
                &mut input,
                1 << 30,
                &mut || true,
            )
            .unwrap();
            assert!(matches!(created, PutIfAbsent::Created { epochs, .. }
                if epochs == PublicationState::new(true, false, true)));
            let whole = fixture
                .fabric
                .read_whole_bounded(envelope.object_identity(), body.len() as u64)
                .unwrap();
            assert_eq!(
                whole.object,
                VerifiedObject::new(envelope.clone(), body.clone()).unwrap()
            );
            let mut expected = Vec::new();
            let encoded = envelope.encode().unwrap();
            expected.extend_from_slice(OBJECT_MAGIC);
            expected.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            expected.extend_from_slice(&encoded);
            expected.extend_from_slice(&body);
            assert_eq!(
                fs::read(fixture.fabric.object_path(envelope.object_identity())).unwrap(),
                expected
            );
            assert!(matches!(
                place(
                    &fixture.fabric,
                    envelope.clone(),
                    &mut Cursor::new(&body),
                    1 << 30,
                    &mut || true
                ),
                Ok(PutIfAbsent::AlreadyPresent { .. })
            ));
            fixture.empty_staging();
        }
    }
}

struct NeverRead;
impl Read for NeverRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("preflight must refuse before source I/O")
    }
}

#[test]
fn namespace_kind_payload_storage_and_quota_limits_refuse_before_reading() {
    let fixture = Fixture::new();
    let original = envelope(GitHashAlgorithm::Sha1, b"blob");
    for case in 0..7 {
        let mut claimed = original.clone();
        let mut maximum = 4;
        match case {
            0 => claimed.namespace = b"foreign".to_vec(),
            1 => claimed.object_kind = ObjectKind::Tree,
            2 => maximum = 3,
            3 => maximum = 0,
            4 => claimed.declared_length = 128 * 1024 * 1024,
            5 => claimed.codec_namespace = vec![7; 1024],
            6 => claimed.codec_namespace = vec![7; 257],
            _ => unreachable!(),
        }
        if case == 4 {
            maximum = claimed.declared_length;
        }
        assert!(
            place(
                &fixture.fabric,
                claimed,
                &mut NeverRead,
                maximum,
                &mut || true
            )
            .is_err()
        );
        fixture.empty_staging();
    }
    let resources = ResourceVector::from_grades(&[(Grade::Bytes, 3), (Grade::Objects, 1)]);
    let ledger = ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        resources,
    );
    let grant = ledger.grant(resources).unwrap();
    assert!(matches!(
        fixture.fabric.put_blob_stream_if_absent(
            original.clone(),
            &mut NeverRead,
            4,
            PlacementAdmission::new(&ledger, grant),
            &mut || true
        ),
        Err(StoreRefusal::Resource(_))
    ));
    assert!(ledger.close().is_quiescent());
    assert!(
        place(
            &fixture.fabric,
            original,
            &mut Cursor::new(b"blob"),
            4,
            &mut || true
        )
        .is_ok()
    );
}

#[test]
fn forged_hashes_short_extra_and_failed_sources_never_link() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for case in 0..6 {
            let fixture = Fixture::new();
            let mut claimed = envelope(format, b"original");
            let mut bytes = b"original".to_vec();
            match case {
                0 => {
                    bytes.pop();
                }
                1 => bytes.push(1),
                2 => bytes[0] ^= 1,
                3 => claimed.payload_commitment[0] ^= 1,
                4 => {
                    claimed.object_identity =
                        git_object_id(format, GitObjectKind::Blob, b"different");
                }
                5 => {}
                _ => unreachable!(),
            }
            let mut cursor = Cursor::new(bytes);
            let mut failing = FailAtEnd(Cursor::new(b"original"));
            let input: &mut dyn Read = if case == 5 { &mut failing } else { &mut cursor };
            assert!(place(&fixture.fabric, claimed.clone(), input, 100, &mut || true).is_err());
            assert!(
                !fixture
                    .fabric
                    .object_path(claimed.object_identity())
                    .exists()
            );
            fixture.empty_staging();
            assert!(
                place(
                    &fixture.fabric,
                    envelope(format, b"original"),
                    &mut Cursor::new(b"original"),
                    100,
                    &mut || true
                )
                .is_ok()
            );
        }
    }
}

struct FailAtEnd<T>(Cursor<T>);
impl<T: AsRef<[u8]>> Read for FailAtEnd<T> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.0.read(out)?;
        if count == 0 {
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(count)
        }
    }
}

#[test]
fn cancellation_at_every_checkpoint_settles_and_identical_retry_converges() {
    let body = vec![27; CHUNK_BYTES + 5];
    let env = envelope(GitHashAlgorithm::Sha256, &body);
    let control = Fixture::new();
    let mut calls = 0;
    place(
        &control.fabric,
        env.clone(),
        &mut Cursor::new(&body),
        1 << 20,
        &mut || {
            calls += 1;
            true
        },
    )
    .unwrap();
    for stop in 1..=calls {
        let fixture = Fixture::new();
        let mut checkpoints = 0;
        assert_eq!(
            place(
                &fixture.fabric,
                env.clone(),
                &mut Cursor::new(&body),
                1 << 20,
                &mut || {
                    checkpoints += 1;
                    checkpoints != stop
                }
            ),
            Err(StoreRefusal::RuntimeCheckpointRejected)
        );
        fixture.empty_staging();
        if fixture.fabric.object_path(env.object_identity()).exists() {
            assert_eq!(
                fixture
                    .fabric
                    .read_whole_bounded(env.object_identity(), 1 << 20)
                    .unwrap()
                    .object
                    .payload(),
                body
            );
        }
        assert!(
            place(
                &fixture.fabric,
                env.clone(),
                &mut Cursor::new(&body),
                1 << 20,
                &mut || true
            )
            .is_ok()
        );
    }
}

#[test]
fn each_durability_interruption_reopens_to_absence_or_verified_placement() {
    for point in [
        LocalCrashPoint::BeforeStageWrite,
        LocalCrashPoint::AfterStageWrite,
        LocalCrashPoint::AfterStageSync,
        LocalCrashPoint::BeforeImmutablePublish,
        LocalCrashPoint::AfterImmutablePublish,
        LocalCrashPoint::AfterPublishDirectorySync,
        LocalCrashPoint::BeforeStageCleanup,
    ] {
        let fixture = Fixture::new();
        let crashing = LocalFilesystemFabric::open(
            Fixture::config(fixture.root.clone()).with_crash_injection(point),
        )
        .unwrap();
        let env = envelope(GitHashAlgorithm::Sha1, b"durable payload");
        assert!(
            place(
                &crashing,
                env.clone(),
                &mut Cursor::new(b"durable payload"),
                100,
                &mut || true
            )
            .is_err()
        );
        fixture.empty_staging();
        let reopened = LocalFilesystemFabric::open(Fixture::config(fixture.root.clone())).unwrap();
        let existed = reopened.object_path(env.object_identity()).exists();
        let result = place(
            &reopened,
            env.clone(),
            &mut Cursor::new(b"durable payload"),
            100,
            &mut || true,
        )
        .unwrap();
        assert_eq!(
            matches!(result, PutIfAbsent::AlreadyPresent { .. }),
            existed
        );
        assert_eq!(
            reopened
                .read_whole_bounded(env.object_identity(), 100)
                .unwrap()
                .object
                .payload(),
            b"durable payload"
        );
    }
}

#[test]
fn existing_collision_or_corruption_is_never_overwritten_or_treated_as_dedup() {
    for corrupt in [false, true] {
        let fixture = Fixture::new();
        let env = envelope(GitHashAlgorithm::Sha256, b"immutable");
        place(
            &fixture.fabric,
            env.clone(),
            &mut Cursor::new(b"immutable"),
            100,
            &mut || true,
        )
        .unwrap();
        let path = fixture.fabric.object_path(env.object_identity());
        let mut next = env.clone();
        if corrupt {
            let mut bytes = fs::read(&path).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            fs::write(&path, bytes).unwrap();
        } else {
            next.codec_namespace = b"other".to_vec();
        }
        let before = fs::read(&path).unwrap();
        assert!(
            place(
                &fixture.fabric,
                next,
                &mut Cursor::new(b"immutable"),
                100,
                &mut || true
            )
            .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), before);
        fixture.empty_staging();
    }
}

struct InvalidRead;
impl Read for InvalidRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        Ok(out.len() + 1)
    }
}

#[test]
fn invalid_reader_counts_refuse_and_release_custody() {
    let fixture = Fixture::new();
    let env = envelope(GitHashAlgorithm::Sha1, b"bytes");
    assert_eq!(
        place(&fixture.fabric, env, &mut InvalidRead, 100, &mut || true),
        Err(StoreRefusal::MalformedStoredObject)
    );
    fixture.empty_staging();
}

#[test]
fn generated_blob_above_buffered_ceiling_uses_only_chunk_buffers() {
    let length = 33 * 1024 * 1024 + 17;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new();
        let placeholder = git_object_id(format, GitObjectKind::Blob, b"");
        let mut native = blob_stream::NativeHash::new(placeholder, length);
        let mut strong = blob_stream::strong_hasher(length).unwrap();
        let chunk = vec![39_u8; CHUNK_BYTES];
        let mut left = length;
        while left != 0 {
            let count = left.min(CHUNK_BYTES as u64) as usize;
            native.update(&chunk[..count]).unwrap();
            strong.update(&chunk[..count]);
            left -= count as u64;
        }
        let id = native.finish().unwrap();
        let env = ObjectEnvelope::new(
            b"stream-placement".to_vec(),
            id,
            ObjectKind::Blob,
            length,
            strong.finish(),
            b"raw".to_vec(),
            [3; 32],
            None,
            &SegmentLimits::default(),
        )
        .unwrap();
        let mut generated = io::repeat(39).take(length);
        place(&fixture.fabric, env, &mut generated, length, &mut || true).unwrap();
        let mut stream = fixture.fabric.open_blob_stream_bounded(id, length).unwrap();
        let mut buffer = vec![0_u8; CHUNK_BYTES];
        let mut read = 0;
        loop {
            let count = stream.read_tentative(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            assert!(buffer[..count].iter().all(|byte| *byte == 39));
            read += count as u64;
        }
        assert_eq!(read, length);
        assert!(stream.is_verified());
        fixture.empty_staging();
    }
}
