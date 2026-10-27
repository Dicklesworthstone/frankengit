use super::*;
use crate::writer::{DeltaSearch, cache};
use crate::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, PackArtifactSink, PackError,
    PackOrderKey, PackPlanner, PackWriteReceipt, PackWriter, ThinBase,
};
use fgit_crypto::git_object_id;
use fgit_deflate::DeflateProfile;
use fgit_git_object::ObjectType;

#[derive(Default)]
struct Source(BTreeMap<ObjectId, CanonicalPackObject>);
impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

#[derive(Default)]
struct Sink {
    bytes: Vec<u8>,
    promoted: bool,
    aborted: bool,
}
impl PackArtifactSink for Sink {
    type Temporary = Vec<u8>;
    fn create_temporary(&mut self) -> Result<Vec<u8>, PackWriteError> {
        Ok(Vec::new())
    }
    fn write_temporary(
        &mut self,
        temporary: &mut Vec<u8>,
        bytes: &[u8],
    ) -> Result<(), PackWriteError> {
        temporary.extend_from_slice(bytes);
        Ok(())
    }
    fn promote_temporary(&mut self, temporary: &mut Vec<u8>) -> Result<(), PackWriteError> {
        self.bytes = std::mem::take(temporary);
        self.promoted = true;
        Ok(())
    }
    fn abort_temporary(&mut self, _: Vec<u8>) {
        self.aborted = true;
    }
}

fn corpus(format: ObjectFormat) -> (Source, Vec<PackOrderKey>) {
    let mut source = Source::default();
    let mut order = Vec::new();
    let mut seed = 0x91ef_dd01_u64;
    let mut original = vec![0_u8; 8 * 1024];
    for byte in &mut original {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = seed as u8;
    }
    let bodies = [
        Vec::new(),
        b"a".repeat(16 * 1024),
        original.clone(),
        [&b"shift"[..], original.as_slice()].concat(),
        [
            original[..4000].to_vec(),
            b"changed region".repeat(20),
            original[4200..].to_vec(),
        ]
        .concat(),
        b"unrelated alternate source".repeat(300),
    ];
    for (index, body) in bodies.into_iter().enumerate() {
        let id = git_object_id(format, ObjectType::Blob, &body);
        let object = CanonicalPackObject::new(
            id,
            ObjectType::Blob,
            body,
            Vec::new(),
            100 - index as u64,
            0,
        );
        order.push(PackOrderKey {
            id,
            object_type: ObjectType::Blob,
            recency: object.recency(),
            path_hash: 0,
        });
        source.0.insert(id, object);
    }
    (source, order)
}

fn write(
    source: &Source,
    selected: &[PackOrderKey],
    thin: &[ThinBase],
    profile: PackWriteProfile,
    cache: Option<Arc<PackComputationCache>>,
) -> (Vec<u8>, PackWriteReceipt) {
    let format = selected[0].id.algorithm();
    let limits = PackLimits::default();
    let mut planner = PackPlanner::new(format, profile, limits.clone());
    let mut sink = Sink::default();
    let receipt = match cache {
        Some(cache) => {
            planner = planner.with_computation_cache(cache.clone());
            planner.stream_selected_thin(
                source,
                selected,
                thin,
                &PackWriter::new(limits),
                &mut MemoizedPackEncoder::for_profile(profile, cache),
                &mut sink,
                &mut || true,
            )
        }
        None => planner.stream_selected_thin(
            source,
            selected,
            thin,
            &PackWriter::new(limits),
            &mut DeterministicPackEncoder::for_profile(profile),
            &mut sink,
            &mut || true,
        ),
    }
    .unwrap();
    assert!(sink.promoted);
    assert!(!sink.aborted);
    (sink.bytes, receipt)
}

#[test]
fn cold_warm_evicted_disabled_and_overlapping_selections_match_uncached_writer() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (source, order) = corpus(format);
        for profile in [
            PackWriteProfile::STORED_V1,
            PackWriteProfile::COMPRESSED_V1,
            PackWriteProfile::COMPRESSED_V5,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        ] {
            for capacity in [0, 2048, 4 * 1024 * 1024] {
                let cache = Arc::new(PackComputationCache::new(capacity));
                for selection in [&order[..], &order[..], &order[2..], &order[..4], &order[..]] {
                    let expected = write(&source, selection, &[], profile, None);
                    let actual = write(&source, selection, &[], profile, Some(cache.clone()));
                    assert_eq!(actual, expected, "{format:?} {profile:?} {capacity}");
                    assert!(cache.stats().resident_bytes <= capacity);
                }
                if capacity == 0 {
                    assert_eq!(cache.stats().entries, 0);
                }
                // Oversized entries are intentionally uncached. Dedicated
                // churn tests below force eviction of retainable entries.
                if capacity > 2048 {
                    assert!(cache.stats().compression_hits > 0);
                }
                if capacity > 2048 && profile.delta_window > 0 {
                    assert!(cache.stats().delta_hits > 0);
                }
            }
        }
    }
}

#[test]
fn thin_pack_base_identity_and_exact_limits_remain_in_the_memo_key() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (source, order) = corpus(format);
        let cache = Arc::new(PackComputationCache::new(4 * 1024 * 1024));
        for base in [order[2].id, order[4].id, order[2].id] {
            let offers = [ThinBase::new(order[3].id, base)];
            let expected = write(
                &source,
                &order[3..4],
                &offers,
                PackWriteProfile::COMPRESSED_V5_THIN,
                None,
            );
            assert_eq!(
                write(
                    &source,
                    &order[3..4],
                    &offers,
                    PackWriteProfile::COMPRESSED_V5_THIN,
                    Some(cache.clone())
                ),
                expected
            );
        }
        assert!(cache.stats().delta_hits > 0);
    }
}

#[test]
fn delta_negative_results_never_cross_a_bound_base_target_or_profile() {
    let cache = PackComputationCache::new(4096);
    let base = git_object_id(ObjectFormat::Sha1, ObjectType::Blob, b"base");
    let other = git_object_id(ObjectFormat::Sha1, ObjectType::Blob, b"other base");
    let target = git_object_id(ObjectFormat::Sha1, ObjectType::Blob, b"target");
    let profile = cache::delta_fingerprint(PackWriteProfile::COMPRESSED_V5, &PackLimits::default());
    let changed = cache::delta_fingerprint(
        PackWriteProfile {
            delta_search: DeltaSearch::PrefixSuffix,
            ..PackWriteProfile::COMPRESSED_V5
        },
        &PackLimits::default(),
    );
    let calls = std::cell::Cell::new(0);
    let compute = || {
        calls.set(calls.get() + 1);
        Ok(None)
    };
    assert_eq!(
        delta(&cache, &profile, base, target, 1, compute).unwrap(),
        None
    );
    assert_eq!(
        delta(&cache, &profile, base, target, 1, compute).unwrap(),
        None
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(
        delta(&cache, &profile, base, target, 10, || Ok(Some(vec![1, 2]))).unwrap(),
        Some(vec![1, 2])
    );
    assert_eq!(
        delta(&cache, &profile, other, target, 1, compute).unwrap(),
        None
    );
    assert_eq!(
        delta(&cache, &profile, base, other, 1, compute).unwrap(),
        None
    );
    assert_eq!(
        delta(&cache, &changed, base, target, 1, compute).unwrap(),
        None
    );
    assert_eq!(calls.get(), 4);
}

fn encode(
    encoder: &mut impl PackEntryEncoder,
    input: &[u8],
) -> Result<(Vec<u8>, DeflateReceipt), PackWriteError> {
    let mut output = Vec::new();
    let receipt = encoder.encode_entry(input, &mut || true, &mut |bytes| {
        output.extend_from_slice(bytes);
        Ok(())
    })?;
    Ok((output, receipt))
}

#[test]
fn warm_compression_retains_work_and_changed_work_ceiling_has_identical_refusal() {
    let cache = Arc::new(PackComputationCache::new(1024 * 1024));
    let profile = PackWriteProfile::COMPRESSED_V5;
    let input = b"repeatable content with some runs".repeat(1500);
    let mut cold = MemoizedPackEncoder::for_profile(profile, cache.clone());
    let expected = encode(&mut cold, &input).unwrap();
    assert!(cold.work_units() > 0);
    let mut warm = MemoizedPackEncoder::for_profile(profile, cache.clone());
    assert_eq!(encode(&mut warm, &input).unwrap(), expected);
    assert_eq!(warm.work_units(), cold.work_units());
    assert_eq!(cache.stats().compression_hits, 1);
    for ceiling in [1, cold.work_units() - 1, cold.work_units()] {
        let limits = DeflateLimits {
            max_work_units: ceiling,
            ..DeflateLimits::GIT_OBJECT
        };
        let oracle = encode(
            &mut DeterministicPackEncoder::new(limits, profile.compression),
            &input,
        );
        for _ in 0..2 {
            let cached = encode(
                &mut MemoizedPackEncoder::new(limits, profile, cache.clone()),
                &input,
            );
            assert_eq!(cached, oracle);
        }
    }
}

#[test]
fn identical_profile_name_with_different_constants_cannot_reuse_compression() {
    let cache = Arc::new(PackComputationCache::new(1024 * 1024));
    let input = b"compressible".repeat(2000);
    let original = PackWriteProfile::COMPRESSED_V5;
    let changed = PackWriteProfile {
        compression: DeflateProfile {
            block_bytes: 4096,
            ..original.compression
        },
        ..original
    };
    for profile in [original, changed, original] {
        let oracle = encode(&mut DeterministicPackEncoder::for_profile(profile), &input).unwrap();
        assert_eq!(
            encode(
                &mut MemoizedPackEncoder::for_profile(profile, cache.clone()),
                &input
            )
            .unwrap(),
            oracle
        );
    }
    assert_eq!(cache.stats().compression_hits, 1);
}

#[test]
fn corrupted_payload_or_receipt_is_invalidated_and_recomputed() {
    let cache = Arc::new(PackComputationCache::new(1024 * 1024));
    let profile = PackWriteProfile::COMPRESSED_V5;
    let input = b"native source".repeat(200);
    let expected = encode(
        &mut MemoizedPackEncoder::for_profile(profile, cache.clone()),
        &input,
    )
    .unwrap();
    for metadata in [false, true] {
        {
            let mut state = cache.state.lock().unwrap();
            let entry =
                Arc::get_mut(&mut state.entries.values_mut().next().unwrap().entry).unwrap();
            if metadata {
                if let Value::Compressed { work, .. } = &mut entry.value {
                    *work += 1;
                }
            } else {
                entry.payload[0] ^= 1;
            }
        }
        assert_eq!(
            encode(
                &mut MemoizedPackEncoder::for_profile(profile, cache.clone()),
                &input
            )
            .unwrap(),
            expected
        );
    }
    assert_eq!(cache.stats().invalidations, 2);
}

#[test]
fn warm_cache_cannot_bypass_cancellation_or_object_selection() {
    let (mut source, order) = corpus(ObjectFormat::Sha256);
    let profile = PackWriteProfile::COMPRESSED_V5;
    let cache = Arc::new(PackComputationCache::new(1024 * 1024));
    let _ = write(&source, &order, &[], profile, Some(cache.clone()));
    let limits = PackLimits::default();
    let planner = PackPlanner::new(ObjectFormat::Sha256, profile, limits.clone())
        .with_computation_cache(cache.clone());
    let mut sink = Sink::default();
    let result = planner.stream_selected_thin(
        &source,
        &order,
        &[],
        &PackWriter::new(limits.clone()),
        &mut MemoizedPackEncoder::for_profile(profile, cache.clone()),
        &mut sink,
        &mut || false,
    );
    assert_eq!(
        result,
        Err(PackWriteError::Pack(PackError::DeadlineExceeded))
    );
    assert!(!sink.promoted);
    source.0.remove(&order[0].id);
    let result = planner.stream_selected_thin(
        &source,
        &order,
        &[],
        &PackWriter::new(limits),
        &mut MemoizedPackEncoder::for_profile(profile, cache),
        &mut sink,
        &mut || true,
    );
    assert_eq!(
        result,
        Err(PackWriteError::MissingCanonicalObject(order[0].id))
    );
    assert!(!sink.promoted);
    assert!(sink.aborted);
}

#[test]
fn negative_delta_entries_and_mixed_inputs_remain_bounded() {
    let cache = PackComputationCache::new(2048);
    let profile = cache::delta_fingerprint(PackWriteProfile::COMPRESSED_V5, &PackLimits::default());
    let base = git_object_id(ObjectFormat::Sha1, ObjectType::Blob, b"base");
    for index in 0..1000_u32 {
        let target = git_object_id(ObjectFormat::Sha1, ObjectType::Blob, &index.to_be_bytes());
        delta(&cache, &profile, base, target, 1, || Ok(None)).unwrap();
        assert!(cache.stats().resident_bytes <= 2048);
        assert!(cache.stats().entries <= 4);
    }
    assert_eq!(cache.stats().evictions, 996);
}

fn delta(
    cache: &PackComputationCache,
    fingerprint: &[u8; 32],
    base: ObjectId,
    target: ObjectId,
    bound: usize,
    compute: impl FnOnce() -> Result<Option<Vec<u8>>, PackWriteError>,
) -> Result<Option<Vec<u8>>, PackWriteError> {
    cache.delta(fingerprint, base, target, bound, &mut || true, |_| {
        compute()
    })
}

fn retain_delta(cache: &PackComputationCache, key: [u8; 32], payload: &[u8]) {
    let mut reservation = cache.reserve(ENTRY_OVERHEAD + payload.len()).unwrap();
    assert!(reservation.copy_delta(payload, &mut || true).unwrap());
    reservation
        .insert(key, Value::Delta { present: true }, &mut || true)
        .unwrap();
}

#[test]
fn cached_replay_preserves_the_exact_output_limit_refusal() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (source, order) = corpus(format);
        let profile = PackWriteProfile::STORED_V1;
        let plan = PackPlanner::new(format, profile, PackLimits::default())
            .plan_selected(&source, &[order[0].id], &mut || true)
            .unwrap();
        for warm in [false, true] {
            let cache = Arc::new(PackComputationCache::new(4096));
            if warm {
                write(&source, &order[..1], &[], profile, Some(cache.clone()));
            }
            for ceiling in [14, 15, 23, 24, 25] {
                let writer = PackWriter::new(PackLimits {
                    max_input_bytes: ceiling,
                    ..PackLimits::default()
                });
                let mut oracle_sink = Sink::default();
                let expected = writer.write_into(
                    &plan,
                    &mut || true,
                    &mut DeterministicPackEncoder::for_profile(profile),
                    &mut oracle_sink,
                );
                if ceiling == 14 {
                    assert_eq!(
                        expected,
                        Err(PackWriteError::OutputLimit {
                            attempted: 15,
                            limit: 14
                        })
                    );
                }
                let mut actual_sink = Sink::default();
                let actual = writer.write_into(
                    &plan,
                    &mut || true,
                    &mut MemoizedPackEncoder::for_profile(profile, cache.clone()),
                    &mut actual_sink,
                );
                assert_eq!(actual, expected, "{format:?} warm={warm} ceiling={ceiling}");
                assert!(oracle_sink.aborted && actual_sink.aborted);
                assert!(!oracle_sink.promoted && !actual_sink.promoted);
                assert_eq!(cache.stats().reserved_bytes, 0);
            }
            if warm {
                assert!(cache.stats().compression_hits > 0);
            }
        }
    }
}

#[test]
fn eviction_skips_pinned_entries_and_never_releases_their_charge() {
    let charge = ENTRY_OVERHEAD + 32;
    let cache = PackComputationCache::new(2 * charge);
    retain_delta(&cache, [1; 32], &[1; 32]);
    retain_delta(&cache, [2; 32], &[2; 32]);
    let first = cache.lookup(&[1; 32], &mut || true).unwrap().unwrap();
    retain_delta(&cache, [3; 32], &[3; 32]);
    assert_eq!(first.payload.as_ref(), &[1; 32]);
    assert!(cache.lookup(&[2; 32], &mut || true).unwrap().is_none());
    let third = cache.lookup(&[3; 32], &mut || true).unwrap().unwrap();
    assert_eq!(cache.stats().resident_bytes, 2 * charge);
    assert!(cache.reserve(ENTRY_OVERHEAD).is_none());
    assert_eq!(cache.stats().reserved_bytes, 0);
    drop(third);
    let reservation = cache.reserve(charge).unwrap();
    assert_eq!(cache.stats().resident_bytes, charge);
    assert_eq!(cache.stats().reserved_bytes, charge);
    assert_eq!(first.payload.as_ref(), &[1; 32]);
    drop(reservation);
    drop(first);
    let whole_budget = cache.reserve(2 * charge).unwrap();
    assert_eq!(cache.stats().resident_bytes, 0);
    assert_eq!(cache.stats().reserved_bytes, cache.max_bytes());
    drop(whole_budget);
    assert_eq!(cache.stats().reserved_bytes, 0);
}

#[test]
fn corrupt_but_pinned_entries_remain_charged_until_released() {
    let charge = ENTRY_OVERHEAD + 32;
    let cache = PackComputationCache::new(charge);
    retain_delta(&cache, [1; 32], &[1; 32]);
    let pinned = {
        let mut state = cache.state.lock().unwrap();
        let retained = state.entries.get_mut(&[1; 32]).unwrap();
        Arc::get_mut(&mut retained.entry).unwrap().payload[0] ^= 1;
        Arc::clone(&retained.entry)
    };
    assert!(cache.lookup(&[1; 32], &mut || true).unwrap().is_none());
    assert_eq!(cache.stats().invalidations, 1);
    assert_eq!(cache.stats().resident_bytes, charge);
    assert!(cache.reserve(ENTRY_OVERHEAD).is_none());
    drop(pinned);
    let reservation = cache.reserve(charge).unwrap();
    assert_eq!(cache.stats().resident_bytes, 0);
    assert_eq!(cache.stats().reserved_bytes, charge);
    drop(reservation);
    assert_eq!(cache.stats().reserved_bytes, 0);
}

#[test]
fn concurrent_reservations_share_the_budget_and_drop_releases_it() {
    let cache = PackComputationCache::new(2048);
    let mut first = cache.reserve(1024).unwrap();
    assert!(cache.reserve(1025).is_none());
    let second = cache.reserve(1024).unwrap();
    assert_eq!(cache.stats().reserved_bytes, 2048);
    assert!(!first.grow(1));
    drop(second);
    assert!(first.grow(256));
    assert_eq!(cache.stats().reserved_bytes, 1280);
    drop(first);
    assert_eq!(cache.stats().reserved_bytes, 0);
    assert_eq!(cache.stats().resident_bytes, 0);
}

#[test]
fn full_in_flight_budget_bypasses_retention_without_changing_the_pack() {
    let (source, order) = corpus(ObjectFormat::Sha256);
    let profile = PackWriteProfile::COMPRESSED_V5;
    let cache = Arc::new(PackComputationCache::new(4096));
    let occupied = cache.reserve(cache.max_bytes()).unwrap();
    let expected = write(&source, &order, &[], profile, None);
    assert_eq!(
        write(&source, &order, &[], profile, Some(cache.clone())),
        expected
    );
    assert_eq!(cache.stats().reserved_bytes, cache.max_bytes());
    assert_eq!(cache.stats().entries, 0);
    drop(occupied);
    assert_eq!(cache.stats().reserved_bytes, 0);
}

#[test]
fn failed_emission_releases_payload_and_callback_metadata_reservations() {
    let cache = Arc::new(PackComputationCache::new(4096));
    let mut encoder = MemoizedPackEncoder::for_profile(PackWriteProfile::STORED_V1, cache.clone());
    let mut calls = 0;
    let mut peak_reserved = 0;
    let result = encoder.encode_entry(b"content", &mut || true, &mut |_| {
        calls += 1;
        let stats = cache.stats();
        assert!(stats.resident_bytes + stats.reserved_bytes <= cache.max_bytes());
        peak_reserved = peak_reserved.max(stats.reserved_bytes);
        if calls == 2 {
            Err(PackWriteError::TemporaryWriteRefused)
        } else {
            Ok(())
        }
    });
    assert_eq!(result, Err(PackWriteError::TemporaryWriteRefused));
    // The first callback emitted the two-byte zlib header. Its retained bytes
    // and one callback-length record were charged before the second callback.
    assert_eq!(peak_reserved, ENTRY_OVERHEAD + 2 + size_of::<usize>());
    assert_eq!(cache.stats().reserved_bytes, 0);
    assert_eq!(cache.stats().entries, 0);
}

#[test]
fn insertion_transfers_the_reservation_and_duplicate_completion_releases_it() {
    let cache = PackComputationCache::new(4096);
    let payload = [7; 64];
    let charge = ENTRY_OVERHEAD + payload.len();
    let mut first = cache.reserve(charge).unwrap();
    let mut racing = cache.reserve(charge).unwrap();
    assert!(first.copy_delta(&payload, &mut || true).unwrap());
    assert!(racing.copy_delta(&payload, &mut || true).unwrap());
    first
        .insert([1; 32], Value::Delta { present: true }, &mut || {
            // Checksum probes run without the cache mutex held.
            let stats = cache.stats();
            assert_eq!(stats.resident_bytes, 0);
            assert_eq!(stats.reserved_bytes, 2 * charge);
            true
        })
        .unwrap();
    assert_eq!(cache.stats().resident_bytes, charge);
    assert_eq!(cache.stats().reserved_bytes, charge);
    racing
        .insert([1; 32], Value::Delta { present: true }, &mut || true)
        .unwrap();
    assert_eq!(cache.stats().resident_bytes, charge);
    assert_eq!(cache.stats().reserved_bytes, 0);
    assert_eq!(cache.stats().entries, 1);
}

#[test]
fn cancellation_during_insert_checksum_releases_the_in_flight_reservation() {
    let payload = vec![7; 3 * ENCODER_INPUT_CHUNK_BYTES];
    let cache = PackComputationCache::new(ENTRY_OVERHEAD + payload.len());
    let mut reservation = cache.reserve(cache.max_bytes()).unwrap();
    assert!(reservation.copy_delta(&payload, &mut || true).unwrap());
    let mut probes = 0;
    let result = reservation.insert([1; 32], Value::Delta { present: true }, &mut || {
        probes += 1;
        // Permit the metadata and first payload chunk, then cancel hashing.
        probes < 3
    });
    assert_eq!(
        result,
        Err(PackWriteError::Pack(PackError::DeadlineExceeded))
    );
    assert_eq!(probes, 3);
    assert_eq!(cache.stats().reserved_bytes, 0);
    assert_eq!(cache.stats().resident_bytes, 0);
    assert_eq!(cache.stats().entries, 0);
}

#[test]
fn cancellation_during_lookup_checksum_does_not_invalidate_a_valid_entry() {
    let payload = vec![7; 3 * ENCODER_INPUT_CHUNK_BYTES];
    let cache = PackComputationCache::new(ENTRY_OVERHEAD + payload.len());
    retain_delta(&cache, [1; 32], &payload);
    let before = cache.stats();
    let mut probes = 0;
    let error = cache
        .lookup(&[1; 32], &mut || {
            probes += 1;
            // Lookup, metadata and first payload chunk pass; the next chunk cancels.
            probes < 4
        })
        .unwrap_err();
    assert_eq!(error, PackWriteError::Pack(PackError::DeadlineExceeded));
    assert_eq!(probes, 4);
    assert_eq!(cache.stats(), before);
    assert!(cache.lookup(&[1; 32], &mut || true).unwrap().is_some());
}
