use super::*;
use crate::SegmentLimits;
use crate::local::{LocalFilesystemConfig, NEXT_STAGE};
use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_resource::{LeakDisposition, ObligationLedger, ObligationState, OpaqueHandle, RegionId};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm};
use std::io::{self, Cursor};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

struct Fixture {
    root: PathBuf,
    fabric: LocalFilesystemFabric,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "frankengit-synced-blob-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed),
        ));
        let fabric = LocalFilesystemFabric::open(Self::config(root.clone())).unwrap();
        Self { root, fabric }
    }

    fn config(root: PathBuf) -> LocalFilesystemConfig {
        LocalFilesystemConfig::new(
            root,
            b"private-stream".to_vec(),
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
    ObjectEnvelope::new(
        b"private-stream".to_vec(),
        git_object_id(format, GitObjectKind::Blob, bytes),
        crate::ObjectKind::Blob,
        bytes.len() as u64,
        git_payload_commitment(GitObjectKind::Blob, bytes, CANONICAL_CODEC_VERSION)
            .digest()
            .as_bytes()
            .try_into()
            .unwrap(),
        b"raw".to_vec(),
        [9; 32],
        None,
        &SegmentLimits::default(),
    )
    .unwrap()
}

fn ledger(envelope: &ObjectEnvelope) -> (ObligationLedger, ResourceVector) {
    let amount = ResourceVector::from_grades(&[
        (Grade::Bytes, envelope.declared_length().max(1)),
        (Grade::Objects, 1),
    ]);
    (
        ObligationLedger::root(RegionId::new(1), LeakDisposition::FailFast, amount),
        amount,
    )
}

fn attempt(
    fabric: &LocalFilesystemFabric,
    envelope: ObjectEnvelope,
    input: &mut dyn Read,
    maximum: u64,
    live: &mut impl FnMut() -> bool,
) -> (ObligationLedger, Result<SyncedBlob, StoreRefusal>) {
    let (ledger, amount) = ledger(&envelope);
    let grant = ledger.grant(amount).unwrap();
    let result = fabric.stage_synced_blob_stream_if_absent(
        envelope,
        input,
        maximum,
        PlacementAdmission::new(&ledger, grant),
        live,
    );
    (ledger, result)
}

fn stage(
    fixture: &Fixture,
    format: GitHashAlgorithm,
    body: &[u8],
) -> (ObligationLedger, SyncedBlob) {
    let (ledger, result) = attempt(
        &fixture.fabric,
        envelope(format, body),
        &mut Cursor::new(body),
        body.len().max(1) as u64,
        &mut || true,
    );
    (ledger, result.unwrap())
}

fn assert_settled(ledger: ObligationLedger) {
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.granted(), ResourceVector::ZERO);
    assert_eq!(snapshot.reserved(), ResourceVector::ZERO);
    assert_eq!(snapshot.accounted().unwrap(), snapshot.capacity());
    assert!(ledger.outstanding().is_empty());
    assert!(ledger.leaks().is_empty());
    assert!(ledger.close().is_quiescent());
}

fn immediate(fixture: &Fixture, envelope: ObjectEnvelope, body: &[u8]) -> PutIfAbsent {
    let (ledger, amount) = ledger(&envelope);
    let grant = ledger.grant(amount).unwrap();
    let result = fixture.fabric.put_blob_stream_if_absent(
        envelope,
        &mut Cursor::new(body),
        body.len().max(1) as u64,
        PlacementAdmission::new(&ledger, grant),
        &mut || true,
    );
    assert_settled(ledger);
    result.unwrap()
}

fn stored_bytes(envelope: &ObjectEnvelope, payload: &[u8]) -> Vec<u8> {
    let encoded = envelope.encode().unwrap();
    let mut bytes = super::super::OBJECT_MAGIC.to_vec();
    bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn private_reads_are_bounded_and_publication_preserves_bytes_in_both_domains() {
    for format in FORMATS {
        for body in [Vec::new(), vec![37; blob_write::CHUNK_BYTES + 17]] {
            let fixture = Fixture::new();
            let (ledger, owner) = stage(&fixture, format, &body);
            let expected = envelope(format, &body);
            assert_eq!(owner.identity(), expected.object_identity());
            assert_eq!(ledger.outstanding().len(), 1);
            assert_eq!(ledger.snapshot().reserved(), ledger.snapshot().capacity());
            assert!(owner.custody.as_ref().unwrap().stage.stage.file.is_none());
            assert!(!fixture.fabric.object_path(owner.identity()).exists());
            assert_eq!(
                fixture
                    .fabric
                    .read_whole_bounded(owner.identity(), body.len() as u64),
                Err(StoreRefusal::ObjectAbsent)
            );
            assert_eq!(
                owner
                    .read_object_bounded(&fixture.fabric, owner.identity(), body.len() as u64)
                    .unwrap(),
                Some(VerifiedObject::new(expected.clone(), body.clone()).unwrap()),
            );
            let unrelated = git_object_id(format, GitObjectKind::Blob, b"unrelated");
            assert_eq!(
                owner
                    .read_object_bounded(&fixture.fabric, unrelated, 0)
                    .unwrap(),
                None
            );
            if !body.is_empty() {
                assert_eq!(
                    owner.read_object_bounded(
                        &fixture.fabric,
                        owner.identity(),
                        body.len() as u64 - 1
                    ),
                    Err(StoreRefusal::StreamingBudgetExceeded {
                        offered: body.len() as u64,
                        maximum: body.len() as u64 - 1,
                    })
                );
            }
            assert_eq!(
                ledger.outstanding().len(),
                1,
                "a private read does not settle custody"
            );
            let reopened =
                LocalFilesystemFabric::open(Fixture::config(fixture.root.clone())).unwrap();
            let result = reopened.publish_synced_blob(owner, &mut || true).unwrap();
            assert!(matches!(result, PutIfAbsent::Created { epochs, .. }
                if epochs == PublicationState::new(true, false, true)));
            assert_eq!(
                fs::read(reopened.object_path(expected.object_identity())).unwrap(),
                stored_bytes(&expected, &body),
            );
            assert_eq!(
                reopened
                    .read_whole_bounded(expected.object_identity(), body.len() as u64)
                    .unwrap()
                    .object
                    .payload(),
                body,
            );
            fixture.empty_staging();
            assert_settled(ledger);
        }
    }
}

#[test]
fn explicit_abandon_and_drop_remove_private_custody_and_abort_the_reservation() {
    for format in FORMATS {
        for explicit in [false, true] {
            let fixture = Fixture::new();
            let (ledger, owner) = stage(&fixture, format, b"abandoned blob");
            let identity = owner.identity();
            if explicit {
                owner.abandon().unwrap();
            } else {
                drop(owner);
            }
            assert!(!fixture.fabric.object_path(identity).exists());
            assert_eq!(
                ledger.journal().last().unwrap().state(),
                ObligationState::Aborted
            );
            fixture.empty_staging();
            assert_settled(ledger);
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
fn source_and_quota_bounds_are_checked_before_reading() {
    for format in FORMATS {
        for case in 0..7 {
            let fixture = Fixture::new();
            let mut expected = envelope(format, b"blob");
            let mut maximum = 4;
            match case {
                0 => expected.namespace = b"foreign".to_vec(),
                1 => expected.object_kind = crate::ObjectKind::Tree,
                2 => maximum = 3,
                3 => maximum = 0,
                4 => {
                    expected.declared_length = 128 * 1024 * 1024;
                    maximum = expected.declared_length;
                }
                5 => expected.codec_namespace = vec![7; 1024],
                6 => expected.codec_namespace = vec![7; 257],
                _ => unreachable!(),
            }
            let (ledger, result) = attempt(
                &fixture.fabric,
                expected,
                &mut NeverRead,
                maximum,
                &mut || true,
            );
            assert!(result.is_err());
            fixture.empty_staging();
            assert_settled(ledger);
        }
        let fixture = Fixture::new();
        let amount = ResourceVector::from_grades(&[(Grade::Bytes, 3), (Grade::Objects, 1)]);
        let ledger = ObligationLedger::root(RegionId::new(1), LeakDisposition::FailFast, amount);
        let grant = ledger.grant(amount).unwrap();
        assert!(matches!(
            fixture.fabric.stage_synced_blob_stream_if_absent(
                envelope(format, b"blob"),
                &mut NeverRead,
                4,
                PlacementAdmission::new(&ledger, grant),
                &mut || true
            ),
            Err(StoreRefusal::Resource(_))
        ));
        fixture.empty_staging();
        assert_settled(ledger);
    }
}

struct TerminalFailure<'a>(Cursor<&'a [u8]>);

impl Read for TerminalFailure<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        assert!(output.len() <= blob_write::CHUNK_BYTES);
        let count = self.0.read(output)?;
        if count == 0 {
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(count)
        }
    }
}

#[test]
fn forged_commitments_length_and_terminal_source_failures_never_create_an_owner_or_name() {
    for format in FORMATS {
        for case in 0..6 {
            let fixture = Fixture::new();
            let mut expected = envelope(format, b"original");
            let mut payload = b"original".to_vec();
            match case {
                0 => {
                    payload.pop();
                }
                1 => payload.push(0),
                2 => payload[0] ^= 1,
                3 => expected.payload_commitment[0] ^= 1,
                4 => {
                    expected.object_identity = git_object_id(format, GitObjectKind::Blob, b"other");
                }
                5 => {}
                _ => unreachable!(),
            }
            let identity = expected.object_identity();
            let mut input = Cursor::new(payload);
            let mut failing = TerminalFailure(Cursor::new(b"original"));
            let source: &mut dyn Read = if case == 5 { &mut failing } else { &mut input };
            let (ledger, result) = attempt(&fixture.fabric, expected, source, 100, &mut || true);
            assert!(result.is_err());
            assert!(!fixture.fabric.object_path(identity).exists());
            fixture.empty_staging();
            assert_settled(ledger);
        }
    }
}

#[test]
fn changed_private_payloads_and_original_envelopes_are_never_adopted() {
    for format in FORMATS {
        for case in 0..5 {
            let fixture = Fixture::new();
            let (ledger, mut owner) = stage(&fixture, format, b"original");
            let identity = owner.identity();
            let path = owner.custody.as_ref().unwrap().stage.path().to_owned();
            let mut replacement = owner.envelope.clone();
            let mut bytes = stored_bytes(&replacement, b"original");
            match case {
                0 => *bytes.last_mut().unwrap() ^= 1,
                1 => {
                    replacement.codec_namespace = b"other".to_vec();
                    // Self-consistency of replacement bytes is insufficient.
                    VerifiedObject::new(replacement.clone(), b"original".to_vec()).unwrap();
                    bytes = stored_bytes(&replacement, b"original");
                }
                2 => bytes.push(0),
                3 => {
                    bytes.pop();
                }
                4 => bytes[0] ^= 1,
                _ => unreachable!(),
            }
            fs::write(&path, bytes).unwrap();
            assert!(
                owner
                    .read_object_bounded(&fixture.fabric, identity, 100)
                    .is_err()
            );
            // Model bit-rot hidden by otherwise matching file metadata: only
            // this metadata fence is refreshed, never the retained envelope,
            // native identity, strong digest, or verified admission evidence.
            owner.custody.as_mut().unwrap().stage.seal().unwrap();
            assert!(
                owner
                    .read_object_bounded(&fixture.fabric, identity, 100)
                    .is_err()
            );
            assert!(
                fixture
                    .fabric
                    .publish_synced_blob(owner, &mut || true)
                    .is_err()
            );
            assert!(!fixture.fabric.object_path(identity).exists());
            fixture.empty_staging();
            assert_settled(ledger);
        }
    }
}

#[test]
fn replacement_files_and_symlinks_are_refused_and_never_unlinked_as_our_custody() {
    for format in FORMATS {
        for symlink in [false, true] {
            let fixture = Fixture::new();
            let (ledger, owner) = stage(&fixture, format, b"unchanged bytes");
            let identity = owner.identity();
            let path = owner.custody.as_ref().unwrap().stage.path().to_owned();
            let original = fixture.root.join("retained-original");
            fs::rename(&path, &original).unwrap();
            if symlink {
                std::os::unix::fs::symlink(&original, &path).unwrap();
            } else {
                fs::copy(&original, &path).unwrap();
            }
            assert_eq!(
                owner.read_object_bounded(&fixture.fabric, identity, 100),
                Err(StoreRefusal::StoredObjectIdentityCollision)
            );
            assert_eq!(
                fixture.fabric.publish_synced_blob(owner, &mut || true),
                Err(StoreRefusal::StoredObjectIdentityCollision)
            );
            assert!(!fixture.fabric.object_path(identity).exists());
            assert!(
                fs::symlink_metadata(&path).is_ok(),
                "foreign replacement was removed"
            );
            assert_eq!(fs::read(&path).unwrap(), fs::read(&original).unwrap());
            assert_settled(ledger);
        }
    }
}

#[test]
fn missing_private_files_refuse_even_if_a_valid_immutable_copy_exists() {
    for format in FORMATS {
        let fixture = Fixture::new();
        let (ledger, owner) = stage(&fixture, format, b"missing private");
        let identity = owner.identity();
        immediate(&fixture, owner.envelope.clone(), b"missing private");
        let before = fs::read(fixture.fabric.object_path(identity)).unwrap();
        fs::remove_file(owner.custody.as_ref().unwrap().stage.path()).unwrap();
        assert_eq!(
            owner.read_object_bounded(&fixture.fabric, identity, 100),
            Err(StoreRefusal::ObjectAbsent)
        );
        assert_eq!(
            fixture.fabric.publish_synced_blob(owner, &mut || true),
            Err(StoreRefusal::ObjectAbsent)
        );
        assert_eq!(
            fs::read(fixture.fabric.object_path(identity)).unwrap(),
            before
        );
        fixture.empty_staging();
        assert_settled(ledger);
    }
}

#[test]
fn namespace_root_and_placement_profile_remain_bound_to_the_owner() {
    for format in FORMATS {
        for case in 0..3 {
            let fixture = Fixture::new();
            let other_root = Fixture::new();
            let (ledger, owner) = stage(&fixture, format, b"scoped");
            let identity = owner.identity();
            let mut config = Fixture::config(fixture.root.clone());
            match case {
                0 => config.namespace = b"foreign".to_vec(),
                1 => config.root = other_root.root.clone(),
                2 => config.encryption_dependency = OpaqueHandle::new(b"other-key").unwrap(),
                _ => unreachable!(),
            }
            let foreign = LocalFilesystemFabric::open(config).unwrap();
            let expected = if case == 0 {
                StoreRefusal::NamespaceMismatch
            } else {
                StoreRefusal::StoredObjectIdentityCollision
            };
            assert_eq!(
                owner.read_object_bounded(&foreign, identity, 100),
                Err(expected.clone())
            );
            assert_eq!(
                foreign.publish_synced_blob(owner, &mut || true),
                Err(expected)
            );
            assert!(!fixture.fabric.object_path(identity).exists());
            assert!(!foreign.object_path(identity).exists());
            fixture.empty_staging();
            other_root.empty_staging();
            assert_settled(ledger);
        }
    }
}

#[test]
fn concurrent_duplicate_owners_settle_only_after_authenticated_comparison() {
    let body = vec![19; blob_write::CHUNK_BYTES * 2 + 11];
    for format in FORMATS {
        let fixture = Fixture::new();
        let (first_ledger, first) = stage(&fixture, format, &body);
        let (second_ledger, second) = stage(&fixture, format, &body);
        assert!(!fixture.fabric.object_path(first.identity()).exists());
        assert!(matches!(
            fixture.fabric.publish_synced_blob(first, &mut || true),
            Ok(PutIfAbsent::Created { .. })
        ));
        assert_settled(first_ledger);
        assert_eq!(second_ledger.outstanding().len(), 1);
        assert!(matches!(
            fixture.fabric.publish_synced_blob(second, &mut || true),
            Ok(PutIfAbsent::AlreadyPresent { .. })
        ));
        assert_settled(second_ledger);
        let (ledger, existing) = stage(&fixture, format, &body);
        assert!(matches!(
            fixture.fabric.publish_synced_blob(existing, &mut || true),
            Ok(PutIfAbsent::AlreadyPresent { .. })
        ));
        assert_settled(ledger);
        // An existing immutable name never skips the source's terminal check.
        let (ledger, result) = attempt(
            &fixture.fabric,
            envelope(format, &body),
            &mut TerminalFailure(Cursor::new(&body)),
            body.len() as u64,
            &mut || true,
        );
        assert!(result.is_err());
        assert_settled(ledger);
        fixture.empty_staging();
    }
}

#[test]
fn corrupt_or_different_existing_objects_are_not_healed_or_accepted_as_dedup() {
    for format in FORMATS {
        for corrupt in [false, true] {
            let fixture = Fixture::new();
            let (ledger, owner) = stage(&fixture, format, b"existing target");
            let identity = owner.identity();
            let mut existing = owner.envelope.clone();
            if !corrupt {
                existing.codec_namespace = b"different".to_vec();
            }
            immediate(&fixture, existing, b"existing target");
            let path = fixture.fabric.object_path(identity);
            if corrupt {
                let mut bytes = fs::read(&path).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                fs::write(&path, bytes).unwrap();
            }
            let before = fs::read(&path).unwrap();
            assert!(
                fixture
                    .fabric
                    .publish_synced_blob(owner, &mut || true)
                    .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), before);
            fixture.empty_staging();
            assert_settled(ledger);
        }
    }
}

#[test]
fn cancellation_at_every_stage_checkpoint_cleans_private_bytes_and_resources() {
    let body = vec![81; blob_write::CHUNK_BYTES + 5];
    for format in FORMATS {
        let control = Fixture::new();
        let mut calls = 0;
        let (ledger, owner) = attempt(
            &control.fabric,
            envelope(format, &body),
            &mut Cursor::new(&body),
            body.len() as u64,
            &mut || {
                calls += 1;
                true
            },
        );
        owner.unwrap().abandon().unwrap();
        assert_settled(ledger);
        for stop in 1..=calls {
            let fixture = Fixture::new();
            let expected = envelope(format, &body);
            let mut checkpoints = 0;
            let (ledger, result) = attempt(
                &fixture.fabric,
                expected.clone(),
                &mut Cursor::new(&body),
                body.len() as u64,
                &mut || {
                    checkpoints += 1;
                    checkpoints != stop
                },
            );
            assert!(matches!(
                result,
                Err(StoreRefusal::RuntimeCheckpointRejected)
            ));
            assert!(
                !fixture
                    .fabric
                    .object_path(expected.object_identity())
                    .exists()
            );
            fixture.empty_staging();
            assert_settled(ledger);
        }
    }
}

#[test]
fn cancellation_at_every_publish_checkpoint_settles_and_identical_retry_converges() {
    let body = vec![23; blob_write::CHUNK_BYTES + 5];
    for format in FORMATS {
        let control = Fixture::new();
        let (ledger, owner) = stage(&control, format, &body);
        let mut calls = 0;
        control
            .fabric
            .publish_synced_blob(owner, &mut || {
                calls += 1;
                true
            })
            .unwrap();
        assert_settled(ledger);
        for stop in 1..=calls {
            let fixture = Fixture::new();
            let (ledger, owner) = stage(&fixture, format, &body);
            let identity = owner.identity();
            let mut checkpoints = 0;
            assert_eq!(
                fixture.fabric.publish_synced_blob(owner, &mut || {
                    checkpoints += 1;
                    checkpoints != stop
                }),
                Err(StoreRefusal::RuntimeCheckpointRejected)
            );
            fixture.empty_staging();
            assert_settled(ledger);
            if fixture.fabric.object_path(identity).exists() {
                assert_eq!(
                    fixture
                        .fabric
                        .read_whole_bounded(identity, body.len() as u64)
                        .unwrap()
                        .object
                        .payload(),
                    body
                );
            }
            let (ledger, retry) = stage(&fixture, format, &body);
            fixture
                .fabric
                .publish_synced_blob(retry, &mut || true)
                .unwrap();
            fixture.empty_staging();
            assert_settled(ledger);
        }
    }
}

#[test]
fn durability_failures_leave_only_absence_or_verified_unreferenced_placement() {
    for format in FORMATS {
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
            let expected = envelope(format, b"durable candidate");
            let identity = expected.object_identity();
            let (ledger, staged) = attempt(
                &crashing,
                expected,
                &mut Cursor::new(b"durable candidate"),
                100,
                &mut || true,
            );
            let result = staged.and_then(|owner| crashing.publish_synced_blob(owner, &mut || true));
            assert!(result.is_err());
            fixture.empty_staging();
            assert_settled(ledger);
            let reopened =
                LocalFilesystemFabric::open(Fixture::config(fixture.root.clone())).unwrap();
            if reopened.object_path(identity).exists() {
                assert_eq!(
                    reopened
                        .read_whole_bounded(identity, 100)
                        .unwrap()
                        .object
                        .payload(),
                    b"durable candidate"
                );
            }
            let (ledger, retry) = stage(&fixture, format, b"durable candidate");
            reopened.publish_synced_blob(retry, &mut || true).unwrap();
            fixture.empty_staging();
            assert_settled(ledger);
        }
    }
}
