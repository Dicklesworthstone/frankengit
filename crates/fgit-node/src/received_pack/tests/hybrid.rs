//! Hybrid packs preserve independent native identity and dependency oracles.
use super::*;
use crate::pack_spool::{PackSpool, SpooledPack};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackArtifactSink, PackPlanner, PackWriteProfile,
    PackWriteReceipt, PackWriter,
};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn oid(format: GitHashAlgorithm, body: &[u8]) -> GitOid {
    git_object_id(format, GitObjectKind::Blob, body)
}

fn keys(format: GitHashAlgorithm, bodies: &[&[u8]]) -> Vec<PackOrderKey> {
    bodies
        .iter()
        .map(|body| {
            let id = oid(format, body);
            (
                id,
                PackOrderKey {
                    id,
                    object_type: ObjectType::Blob,
                    recency: 0,
                    path_hash: 0,
                },
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn ids(keys: &[PackOrderKey]) -> Vec<GitOid> {
    keys.iter().map(|key| key.id).collect()
}

fn cache(source: &Fixture) -> ReceivedPackCache {
    let cache = ReceivedPackCache::new(512 * 1024);
    retain(&cache, source);
    assert_eq!(cache.retained_entries(), 1);
    cache
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fgit-hybrid-pack-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn assert_empty(&self) {
        assert_eq!(std::fs::read_dir(&self.0).unwrap().count(), 0);
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct NativeSource {
    bodies: BTreeMap<GitOid, Vec<u8>>,
    reads: RefCell<Vec<GitOid>>,
}
impl CanonicalObjectSource for NativeSource {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.reads.borrow_mut().push(*id);
        let body = self
            .bodies
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            ObjectType::Blob,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}

fn native_bytes(
    format: GitHashAlgorithm,
    plan: &super::super::PartialReceivedPack,
    bodies: &[&[u8]],
) -> Result<(Vec<u8>, PackWriteReceipt), PackWriteError> {
    native_bytes_with_profile(
        format,
        plan,
        bodies,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
    )
}

fn native_bytes_with_profile(
    format: GitHashAlgorithm,
    plan: &super::super::PartialReceivedPack,
    bodies: &[&[u8]],
    profile: PackWriteProfile,
) -> Result<(Vec<u8>, PackWriteReceipt), PackWriteError> {
    let source = NativeSource {
        bodies: bodies
            .iter()
            .map(|body| (oid(format, body), body.to_vec()))
            .collect(),
        reads: RefCell::new(Vec::new()),
    };
    let selected = ids(plan.missing_keys());
    let planned = PackPlanner::new(format, profile, plan.native_limits().clone())
    .plan_selected(&source, &selected, &mut || true)?;
    let result = PackWriter::new(plan.native_limits().clone()).write(&planned, &mut || true)?;
    assert_eq!(
        source.reads.borrow().iter().copied().collect::<BTreeSet<_>>(),
        selected.into_iter().collect::<BTreeSet<_>>(),
        "only uncovered native objects may be loaded by the residual writer"
    );
    Ok(result)
}

fn spool(root: &Path, bytes: &[u8]) -> SpooledPack {
    let mut sink = PackSpool::new(root);
    let mut temporary = sink.create_temporary().unwrap();
    sink.write_temporary(&mut temporary, bytes).unwrap();
    sink.promote_temporary(&mut temporary).unwrap();
    sink.into_promoted().unwrap()
}

#[test]
fn partial_reuse_keeps_a_closed_delta_chain_and_only_encodes_the_missing_object() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(
            format,
            &[
                Input::Whole(b"base".to_vec()),
                Input::Ofs(0, literal_delta(4, b"child"), b"child".to_vec()),
            ],
        );
        let cache = cache(&source);
        let selected = keys(format, &[b"base", b"child", b"native"]);
        let limits = PackLimits::default();
        let plan = cache
            .try_reuse_partial(&selected, &limits, &[], &mut || true)
            .unwrap()
            .unwrap();
        assert_eq!(ids(plan.missing_keys()), ids(&keys(format, &[b"native"])));
        assert_eq!(plan.received().object_count(), 2);
        assert_eq!(plan.received().ref_delta_count(), 1);
        assert_eq!(plan.received().ofs_delta_count(), 0);
        assert_eq!(plan.received().external_base_count(), 0);
        let (native, written) = native_bytes(format, &plan, &[b"native"]).unwrap();
        let scratch = Scratch::new();
        let (output, receipt) = plan
            .finish(
                spool(&scratch.0, &native),
                written,
                &scratch.0,
                &mut || true,
            )
            .unwrap();
        let output = output.into_bytes().unwrap();
        assert_eq!(receipt.profile(), "received-pack-hybrid-v1");
        assert_eq!(receipt.object_count(), 3);
        assert_eq!(receipt.reused().object_count(), 2);
        assert_eq!(receipt.written().object_count, 1);
        assert_eq!(receipt.total_object_bytes(), 4 + 5 + 6);
        assert_eq!(receipt.output_bytes(), output.len());
        assert_eq!(receipt.sha256(), &sha256_digest(&output));
        selective::assert_objects(&output, format, &[b"base", b"child", b"native"], &[]);
        let base_member = zlib(b"base");
        let delta_member = zlib(&literal_delta(4, b"child"));
        assert!(
            output
                .windows(base_member.len())
                .any(|bytes| bytes == base_member),
            "the old stored DEFLATE member must survive byte-for-byte"
        );
        assert!(
            output
                .windows(delta_member.len())
                .any(|bytes| bytes == delta_member)
        );
        scratch.assert_empty();
    }
}

#[test]
fn relocating_a_real_native_ofs_delta_run_preserves_its_relative_base_distance() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let retained: &[u8] = b"retained independent blob";
        let source = fixture(format, &[Input::Whole(retained.to_vec())]);
        let cache = cache(&source);
        // Either native-ID order has a 48 KiB common prefix and an almost
        // 48 KiB common suffix. The frozen stored profile must therefore
        // choose one economical prefix/suffix delta against the other blob.
        // Its whole entry also crosses the joiner's 64 KiB copy boundary.
        let first: Vec<u8> = (0..96 * 1024).map(|position| (position % 251) as u8).collect();
        let mut second = first.clone();
        second[48 * 1024] ^= 0x80;
        let bodies = [first.as_slice(), second.as_slice()];
        let selected = keys(format, &[retained, bodies[0], bodies[1]]);
        let plan = cache
            .try_reuse_partial(&selected, &PackLimits::default(), &[], &mut || true)
            .unwrap()
            .unwrap();
        assert_eq!(plan.received().object_count(), 1);
        assert_eq!(ids(plan.missing_keys()), ids(&keys(format, &bodies)));
        let native_run_start = plan.received().output_bytes() - format.digest_len();
        let (native, written) =
            native_bytes_with_profile(format, &plan, &bodies, PackWriteProfile::STORED_V1).unwrap();
        assert_eq!(written.object_count, 2);
        assert_eq!(written.delta_count, 1, "fixture must exercise an actual OFS delta");
        assert!(!written.profile.thin);
        assert!(native.len() > 64 * 1024);
        let parsed = fgit_pack::read_verified_pack(
            &native,
            format,
            plan.native_limits(),
            &mut || true,
            &fgit_pack::NativeChecksumVerifier,
        )
        .unwrap();
        assert_eq!(
            parsed
                .entries()
                .iter()
                .filter(|entry| entry.header.kind == fgit_pack::EntryKind::OfsDelta)
                .count(),
            1
        );
        let scratch = Scratch::new();
        let (output, receipt) = plan
            .finish(
                spool(&scratch.0, &native),
                written,
                &scratch.0,
                &mut || true,
            )
            .unwrap();
        let output = output.into_bytes().unwrap();
        assert_eq!(receipt.object_count(), 3);
        assert_eq!(receipt.reused().object_count(), 1);
        assert_eq!(receipt.written().delta_count, 1);
        assert_eq!(receipt.output_bytes(), output.len());
        assert_eq!(receipt.sha256(), &sha256_digest(&output));
        assert_eq!(
            &output[native_run_start..output.len() - format.digest_len()],
            &native[12..native.len() - format.digest_len()],
            "native entry bytes, including OFS distances, must survive relocation unchanged"
        );
        selective::assert_objects(&output, format, &[retained, bodies[0], bodies[1]], &[]);
        scratch.assert_empty();
    }
}

#[test]
fn an_unavailable_selected_parent_moves_its_delta_to_native_even_with_a_redundant_have() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = oid(format, b"base");
        let source = fixture(
            format,
            &[
                Input::Ref(base, literal_delta(4, b"child"), b"child".to_vec()),
                Input::Whole(b"independent".to_vec()),
            ],
        );
        let cache = cache(&source);
        let selected = keys(format, &[b"base", b"child", b"independent", b"native"]);
        for held in [Vec::new(), vec![(base, ObjectType::Blob)]] {
            let plan = cache
                .try_reuse_partial(&selected, &PackLimits::default(), &held, &mut || true)
                .unwrap()
                .unwrap();
            assert_eq!(
                ids(plan.missing_keys()),
                ids(&keys(format, &[b"base", b"child", b"native"]))
            );
            assert_eq!(plan.received().object_count(), 1);
            assert_eq!(plan.received().external_base_count(), 0);
            let (native, written) =
                native_bytes(format, &plan, &[b"base", b"child", b"native"]).unwrap();
            let scratch = Scratch::new();
            let (output, _) = plan
                .finish(
                    spool(&scratch.0, &native),
                    written,
                    &scratch.0,
                    &mut || true,
                )
                .unwrap();
            selective::assert_objects(
                &output.into_bytes().unwrap(),
                format,
                &[b"base", b"child", b"independent", b"native"],
                &[],
            );
            scratch.assert_empty();
        }
    }
}

#[test]
fn thin_hybrid_requires_current_typed_proof_for_each_unselected_external_base() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = oid(format, b"base");
        let source = fixture(
            format,
            &[
                Input::Ref(base, literal_delta(4, b"child"), b"child".to_vec()),
                Input::Whole(b"independent".to_vec()),
            ],
        );
        let cache = cache(&source);
        let selected = keys(format, &[b"child", b"independent", b"native"]);
        for held in [Vec::new(), vec![(base, ObjectType::Tree)]] {
            let plan = cache
                .try_reuse_partial(&selected, &PackLimits::default(), &held, &mut || true)
                .unwrap()
                .unwrap();
            assert_eq!(
                ids(plan.missing_keys()),
                ids(&keys(format, &[b"child", b"native"]))
            );
            assert_eq!(plan.received().object_count(), 1);
            assert_eq!(plan.received().external_base_count(), 0);
        }
        let plan = cache
            .try_reuse_partial(
                &selected,
                &PackLimits::default(),
                &[(base, ObjectType::Blob)],
                &mut || true,
            )
            .unwrap()
            .unwrap();
        assert_eq!(ids(plan.missing_keys()), ids(&keys(format, &[b"native"])));
        assert_eq!(plan.received().external_base_count(), 1);
        let (native, written) = native_bytes(format, &plan, &[b"native"]).unwrap();
        let scratch = Scratch::new();
        let (output, receipt) = plan
            .finish(
                spool(&scratch.0, &native),
                written,
                &scratch.0,
                &mut || true,
            )
            .unwrap();
        assert_eq!(receipt.profile(), "received-pack-hybrid-thin-v1");
        assert!(!receipt.written().profile.thin);
        selective::assert_objects(
            &output.into_bytes().unwrap(),
            format,
            &[b"child", b"independent", b"native"],
            &[b"base"],
        );
        scratch.assert_empty();
    }
}

#[test]
fn complete_hits_total_misses_and_invalid_selections_do_not_create_hybrid_plans() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(format, &[Input::Whole(b"cached".to_vec())]);
        let cache = cache(&source);
        let valid = keys(format, &[b"cached", b"native"]);
        let mut reversed = valid.clone();
        reversed.reverse();
        let repeated = vec![valid[0], valid[0]];
        let other = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        for selected in [
            Vec::new(),
            source.keys.clone(),
            keys(format, &[b"native"]),
            reversed,
            repeated,
            keys(other, &[b"cached", b"native"]),
        ] {
            assert!(
                cache
                    .try_reuse_partial(&selected, &PackLimits::default(), &[], &mut || true)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            cache
                .try_reuse_partial(&valid, &PackLimits::default(), &[], &mut || true)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn cached_and_native_entries_share_one_expanded_byte_and_object_count_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(format, &[Input::Whole(b"cached".to_vec())]);
        let cache = cache(&source);
        let selected = keys(format, &[b"cached", b"native"]);
        let limits = PackLimits {
            max_entries: 2,
            max_total_expanded_bytes: 12,
            ..PackLimits::default()
        };
        let plan = cache
            .try_reuse_partial(&selected, &limits, &[], &mut || true)
            .unwrap()
            .unwrap();
        assert_eq!(plan.native_limits().max_entries, 1);
        assert_eq!(plan.native_limits().max_total_expanded_bytes, 6);
        assert!(native_bytes(format, &plan, &[b"native"]).is_ok());
        let short = PackLimits {
            max_total_expanded_bytes: 11,
            ..limits.clone()
        };
        let plan = cache
            .try_reuse_partial(&selected, &short, &[], &mut || true)
            .unwrap()
            .unwrap();
        assert!(native_bytes(format, &plan, &[b"native"]).is_err());
        let short = PackLimits {
            max_entries: 1,
            ..limits
        };
        assert!(
            cache
                .try_reuse_partial(&selected, &short, &[], &mut || true)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn corrupt_or_truncated_native_spool_never_becomes_a_completed_hybrid_artifact() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(format, &[Input::Whole(b"cached".to_vec())]);
        let cache = cache(&source);
        let selected = keys(format, &[b"cached", b"native"]);
        for fault in 0..3 {
            let plan = cache
                .try_reuse_partial(&selected, &PackLimits::default(), &[], &mut || true)
                .unwrap()
                .unwrap();
            let (mut native, written) = native_bytes(format, &plan, &[b"native"]).unwrap();
            match fault {
                0 => native[12] ^= 1,
                1 => {
                    native.pop();
                }
                _ => native[11] = 2,
            }
            let scratch = Scratch::new();
            assert!(
                plan.finish(
                    spool(&scratch.0, &native),
                    written,
                    &scratch.0,
                    &mut || true,
                )
                .is_err()
            );
            scratch.assert_empty();
            assert_eq!(cache.retained_entries(), 1);
        }
    }
}

#[test]
fn cancellation_drops_partial_selection_pins_and_never_promotes_a_partial_join() {
    let format = GitHashAlgorithm::Sha256;
    let source = fixture(format, &[Input::Whole(b"cached".to_vec())]);
    let cache = cache(&source);
    let selected = keys(format, &[b"cached", b"native"]);
    let mut checkpoints = 0;
    drop(
        cache
            .try_reuse_partial(&selected, &PackLimits::default(), &[], &mut || {
                checkpoints += 1;
                true
            })
            .unwrap()
            .unwrap(),
    );
    for stop in 1..=checkpoints {
        let mut at = 0;
        assert!(matches!(
            cache.try_reuse_partial(&selected, &PackLimits::default(), &[], &mut || {
                at += 1;
                at < stop
            }),
            Err(PackWriteError::Pack(PackError::DeadlineExceeded))
        ));
        let state = cache.state.lock().unwrap();
        assert_eq!(state.reservations, 0);
        assert_eq!(state.reserved_bytes, 0);
        assert!(
            state
                .entries
                .iter()
                .all(|entry| Arc::strong_count(entry) == 1)
        );
    }
    let plan = cache
        .try_reuse_partial(&selected, &PackLimits::default(), &[], &mut || true)
        .unwrap()
        .unwrap();
    let (native, written) = native_bytes(format, &plan, &[b"native"]).unwrap();
    let scratch = Scratch::new();
    assert!(matches!(
        plan.finish(
            spool(&scratch.0, &native),
            written,
            &scratch.0,
            &mut || false,
        ),
        Err(PackWriteError::Pack(PackError::DeadlineExceeded))
    ));
    scratch.assert_empty();
    assert!(
        cache
            .try_reuse_partial(&selected, &PackLimits::default(), &[], &mut || true)
            .unwrap()
            .is_some()
    );
}
