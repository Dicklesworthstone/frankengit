//! Thin reuse requires a fresh, typed proof of every omitted REF base.
use super::*;
use fgit_pack::{ExternalBaseLookup, PackObject, ScalarResolver, read_verified_pack};
use fgit_types::GitOidSha1;

fn thin_source(format: GitHashAlgorithm, base: &[u8], body: &[u8]) -> Fixture {
    fixture(
        format,
        &[Input::Ref(
            git_object_id(format, GitObjectKind::Blob, base),
            literal_delta(base.len(), body),
            body.to_vec(),
        )],
    )
}

fn selected(sources: &[&Fixture]) -> Vec<PackOrderKey> {
    sources
        .iter()
        .flat_map(|source| source.keys.iter().map(|key| (key.id, *key)))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn held_blobs(format: GitHashAlgorithm, bodies: &[&[u8]]) -> Vec<(GitOid, ObjectType)> {
    bodies
        .iter()
        .map(|body| {
            (
                git_object_id(format, GitObjectKind::Blob, body),
                ObjectType::Blob,
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .collect()
}

fn reuse(
    cache: &ReceivedPackCache,
    keys: &[PackOrderKey],
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
) -> Option<ReceivedPackPayload> {
    cache
        .try_reuse_with_held(keys, limits, true, held, &mut || true)
        .unwrap()
}

fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}

struct NativeBases(BTreeMap<GitOid, Vec<u8>>);

impl ExternalBaseLookup for NativeBases {
    fn lookup(&self, id: &GitOid) -> Option<&[u8]> {
        self.0.get(id).map(Vec::as_slice)
    }

    fn lookup_typed(&self, id: &GitOid) -> Option<(ObjectType, &[u8])> {
        self.lookup(id).map(|body| (ObjectType::Blob, body))
    }
}

/// The oracle contains only the explicitly authorized native base bodies.
/// Neither offset-to-ID cache metadata nor inferred delta types are used.
fn assert_native_reconstruction(
    raw: &[u8],
    format: GitHashAlgorithm,
    base_bodies: &[&[u8]],
    expected_bodies: &[&[u8]],
) {
    let limits = PackLimits::default();
    let parsed =
        read_verified_pack(raw, format, &limits, &mut || true, &NativeChecksumVerifier).unwrap();
    assert_eq!(parsed.entries().len(), expected_bodies.len());
    let mut objects = parsed.into_scalar_objects(|_| None).unwrap();
    let oracle = NativeBases(
        base_bodies
            .iter()
            .map(|body| {
                (
                    git_object_id(format, GitObjectKind::Blob, body),
                    body.to_vec(),
                )
            })
            .collect(),
    );
    let mut resolved = BTreeMap::new();
    for _ in 0..objects.len() {
        let resolver = ScalarResolver::new(&objects, &oracle, &limits, &mut || true).unwrap();
        let mut learned = Vec::new();
        for object in &objects {
            let at = offset(object);
            if resolved.contains_key(&at) {
                continue;
            }
            match resolver.resolve_offset_typed(at, &mut || true) {
                Ok((kind, body)) => {
                    assert_eq!(kind, ObjectType::Blob);
                    let id = git_object_id(format, GitObjectKind::Blob, &body);
                    learned.push((at, id, body));
                }
                Err(PackError::MissingDeltaBase) => {}
                Err(error) => panic!("authorized thin reconstruction failed: {error:?}"),
            }
        }
        assert!(
            !learned.is_empty(),
            "the authorized base oracle is incomplete"
        );
        for (at, id, body) in learned {
            match objects
                .iter_mut()
                .find(|object| offset(object) == at)
                .unwrap()
            {
                PackObject::Base { id: slot, .. } | PackObject::TypedBase { id: slot, .. } => {
                    *slot = Some(id);
                }
                PackObject::Delta(delta) => delta.id = Some(id),
            }
            assert!(resolved.insert(at, (id, body)).is_none());
        }
        if resolved.len() == objects.len() {
            break;
        }
    }
    assert_eq!(resolved.len(), expected_bodies.len());
    let mut actual = BTreeMap::new();
    for (id, body) in resolved.into_values() {
        assert!(
            actual.insert(id, body).is_none(),
            "duplicate emitted object"
        );
    }
    let expected: BTreeMap<_, _> = expected_bodies
        .iter()
        .map(|body| {
            (
                git_object_id(format, GitObjectKind::Blob, body),
                body.to_vec(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
}

fn assert_needs_external_base(raw: &[u8], format: GitHashAlgorithm) {
    let limits = PackLimits::default();
    let parsed =
        read_verified_pack(raw, format, &limits, &mut || true, &NativeChecksumVerifier).unwrap();
    let objects = parsed.into_scalar_objects(|_| None).unwrap();
    let resolver = ScalarResolver::new(&objects, &(), &limits, &mut || true).unwrap();
    assert!(objects.iter().any(|object| matches!(
        resolver.resolve_offset_typed(offset(object), &mut || true),
        Err(PackError::MissingDeltaBase)
    )));
}

fn concatenated(format: GitHashAlgorithm, sources: &[&Fixture]) -> Vec<u8> {
    let count: usize = sources.iter().map(|source| source.objects.len()).sum();
    let mut bytes = b"PACK".to_vec();
    bytes.extend(2u32.to_be_bytes());
    bytes.extend(u32::try_from(count).unwrap().to_be_bytes());
    for source in sources {
        bytes.extend_from_slice(&source.raw[12..source.raw.len() - format.digest_len()]);
    }
    match format {
        GitHashAlgorithm::Sha1 => bytes.extend(sha1_digest(&bytes)),
        GitHashAlgorithm::Sha256 => bytes.extend(sha256_digest(&bytes)),
    }
    bytes
}

#[test]
fn one_thin_run_requires_current_typed_held_proof_and_preserves_sender_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = thin_source(format, b"base", b"result");
        let held = held_blobs(format, &[b"base"]);
        let cache = ReceivedPackCache::new(64 * 1024);
        retain(&cache, &source);
        let limits = PackLimits::default();
        assert!(
            payload(&cache, &source).is_none(),
            "thin was not negotiated"
        );
        let other_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        for refused in [
            Vec::new(),
            held_blobs(format, &[b"another base"]),
            vec![(held[0].0, ObjectType::Tree)],
            held_blobs(other_format, &[b"base"]),
        ] {
            assert!(reuse(&cache, &source.keys, &refused, &limits).is_none());
        }
        let reused = cache
            .try_reuse_with_held(&source.keys, &limits, false, &held, &mut || true)
            .unwrap()
            .unwrap();
        let receipt = reused.receipt();
        assert_eq!(receipt.profile(), "received-pack-thin-v1");
        assert_eq!(receipt.external_base_count(), 1);
        assert_eq!(receipt.source_pack_count(), 1);
        assert_eq!(receipt.object_count(), 1);
        assert_eq!(receipt.ref_delta_count(), 1);
        assert_eq!(receipt.ofs_delta_count(), 0);
        assert_eq!(receipt.maximum_delta_depth(), 1);
        assert_eq!(receipt.total_object_bytes(), b"result".len());
        assert_eq!(receipt.output_bytes(), source.raw.len());
        assert_eq!(receipt.checksum(), source.pack.trailer);
        assert_eq!(receipt.sha256(), &sha256_digest(&source.raw));
        let raw = reused.into_bytes().unwrap();
        assert_eq!(raw, source.raw);
        assert_needs_external_base(&raw, format);
        assert_native_reconstruction(&raw, format, &[b"base"], &[b"result"]);
        assert!(reuse(&cache, &source.keys, &[], &limits).is_none());
    }
}

#[test]
fn forward_ref_and_shifted_ofs_chains_count_depth_from_the_omitted_root() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let last = thin_source(format, b"middle", b"last");
        let middle = fixture(
            format,
            &[
                Input::Ref(
                    git_object_id(format, GitObjectKind::Blob, b"base"),
                    literal_delta(4, b"middle"),
                    b"middle".to_vec(),
                ),
                Input::Ofs(0, literal_delta(6, b"sibling"), b"sibling".to_vec()),
            ],
        );
        let cache = ReceivedPackCache::new(64 * 1024);
        retain(&cache, &last);
        retain(&cache, &middle);
        let keys = selected(&[&last, &middle]);
        let held = held_blobs(format, &[b"base"]);
        let limits = PackLimits {
            max_delta_depth: 2,
            ..PackLimits::default()
        };
        let converted = cache
            .try_reuse_with_held(&keys, &limits, false, &held, &mut || true)
            .unwrap()
            .unwrap();
        assert_eq!(
            converted.receipt().profile(),
            "received-pack-select-thin-v1"
        );
        assert_eq!(converted.receipt().ofs_delta_count(), 0);
        assert_eq!(converted.receipt().ref_delta_count(), 3);
        assert_eq!(converted.receipt().maximum_delta_depth(), 2);
        assert_native_reconstruction(
            &converted.into_bytes().unwrap(),
            format,
            &[b"base"],
            &[b"middle", b"last", b"sibling"],
        );
        let too_shallow = PackLimits {
            max_delta_depth: 1,
            ..limits.clone()
        };
        assert!(reuse(&cache, &keys, &held, &too_shallow).is_none());
        let reused = reuse(&cache, &keys, &held, &limits).unwrap();
        assert_eq!(reused.receipt().profile(), "received-pack-concat-thin-v1");
        assert_eq!(reused.receipt().external_base_count(), 1);
        assert_eq!(reused.receipt().source_pack_count(), 2);
        assert_eq!(reused.receipt().maximum_delta_depth(), 2);
        assert_eq!(reused.receipt().ofs_delta_count(), 1);
        assert_eq!(reused.receipt().ref_delta_count(), 2);
        let raw = reused.into_bytes().unwrap();
        assert_eq!(raw, concatenated(format, &[&last, &middle]));
        assert_needs_external_base(&raw, format);
        assert_native_reconstruction(&raw, format, &[b"base"], &[b"middle", b"last", b"sibling"]);
    }
}

#[test]
fn held_objects_neither_widen_nor_complete_the_emitted_selection() {
    let format = GitHashAlgorithm::Sha1;
    let source = thin_source(format, b"base", b"result");
    let base = whole(b"base");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &source);
    let held = held_blobs(format, &[b"base", b"unrelated"]);
    let limits = PackLimits::default();
    assert!(reuse(&cache, &selected(&[&source, &base]), &held, &limits).is_none());
    let thin = reuse(&cache, &source.keys, &held, &limits).unwrap();
    assert_eq!(thin.receipt().object_count(), 1);
    assert_eq!(thin.receipt().external_base_count(), 1);
    assert_eq!(thin.into_bytes().unwrap(), source.raw);
    retain(&cache, &base);
    let full = reuse(&cache, &selected(&[&source, &base]), &held, &limits).unwrap();
    assert_eq!(full.receipt().external_base_count(), 0);
    assert_eq!(full.receipt().profile(), "received-pack-concat-v1");
    assert_native_reconstruction(
        &full.into_bytes().unwrap(),
        format,
        &[],
        &[b"base", b"result"],
    );
    let mixed = fixture(
        format,
        &[
            Input::Ref(
                base.keys[0].id,
                literal_delta(4, b"result"),
                b"result".to_vec(),
            ),
            Input::Whole(b"hidden".to_vec()),
        ],
    );
    let mixed_cache = ReceivedPackCache::new(64 * 1024);
    retain(&mixed_cache, &mixed);
    let subset = reuse(&mixed_cache, &source.keys, &held, &limits).unwrap();
    assert_eq!(subset.receipt().profile(), "received-pack-select-thin-v1");
    assert_native_reconstruction(
        &subset.into_bytes().unwrap(),
        format,
        &[b"base"],
        &[b"result"],
    );
    assert!(reuse(&mixed_cache, &source.keys, &[], &limits).is_none());
    let permitted = reuse(&mixed_cache, &mixed.keys, &held, &limits).unwrap();
    assert_eq!(permitted.receipt().object_count(), 2);
    assert_native_reconstruction(
        &permitted.into_bytes().unwrap(),
        format,
        &[b"base"],
        &[b"result", b"hidden"],
    );
}

#[test]
fn held_proofs_require_one_strictly_ordered_nonzero_native_domain() {
    let source = thin_source(GitHashAlgorithm::Sha1, b"base", b"result");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &source);
    let held = held_blobs(GitHashAlgorithm::Sha1, &[b"base", b"unrelated"]);
    let limits = PackLimits::default();
    assert!(reuse(&cache, &source.keys, &held, &limits).is_some());
    let mut reversed = held.clone();
    reversed.reverse();
    let mut duplicate = held.clone();
    duplicate.insert(0, duplicate[0]);
    let mut mixed = held.clone();
    mixed.extend(held_blobs(GitHashAlgorithm::Sha256, &[b"unrelated"]));
    mixed.sort_by_key(|(id, _)| *id);
    let mut zero = held.clone();
    zero.push((
        GitOid::Sha1(GitOidSha1::from_bytes([0; 20])),
        ObjectType::Blob,
    ));
    zero.sort_by_key(|(id, _)| *id);
    for refused in [reversed, duplicate, mixed, zero] {
        assert!(reuse(&cache, &source.keys, &refused, &limits).is_none());
    }
    let mut wrong_kind = source.keys.clone();
    wrong_kind[0].object_type = ObjectType::Tree;
    let repeated = vec![source.keys[0], source.keys[0]];
    for refused in [Vec::new(), wrong_kind, repeated] {
        assert!(reuse(&cache, &refused, &held, &limits).is_none());
    }
}

#[test]
fn every_external_root_must_be_held_and_shared_roots_are_counted_once() {
    let format = GitHashAlgorithm::Sha256;
    let left = thin_source(format, b"base-a", b"left");
    let right = thin_source(format, b"base-a", b"right");
    let other = thin_source(format, b"base-b", b"other");
    let cache = ReceivedPackCache::new(64 * 1024);
    for source in [&left, &right, &other] {
        retain(&cache, source);
    }
    let keys = selected(&[&left, &right, &other]);
    let limits = PackLimits::default();
    for base in [b"base-a".as_slice(), b"base-b".as_slice()] {
        assert!(reuse(&cache, &keys, &held_blobs(format, &[base]), &limits).is_none());
    }
    let held = held_blobs(format, &[b"base-a", b"base-b", b"unused"]);
    let reused = reuse(&cache, &keys, &held, &limits).unwrap();
    assert_eq!(reused.receipt().external_base_count(), 2);
    assert_eq!(reused.receipt().object_count(), 3);
    assert_eq!(reused.receipt().source_pack_count(), 3);
    assert_native_reconstruction(
        &reused.into_bytes().unwrap(),
        format,
        &[b"base-a", b"base-b"],
        &[b"left", b"right", b"other"],
    );
}

#[test]
fn external_root_fanout_is_global_and_a_later_cover_can_meet_the_limit() {
    let format = GitHashAlgorithm::Sha1;
    let left = thin_source(format, b"base", b"left");
    let right = thin_source(format, b"base", b"right");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &left);
    retain(&cache, &right);
    let keys = selected(&[&left, &right]);
    let held = held_blobs(format, &[b"base"]);
    let tight = PackLimits {
        max_delta_fanout: 1,
        ..PackLimits::default()
    };
    assert!(reuse(&cache, &keys, &held, &tight).is_none());
    let permitted = reuse(&cache, &keys, &held, &PackLimits::default()).unwrap();
    assert_eq!(permitted.receipt().external_base_count(), 1);
    assert_eq!(permitted.receipt().maximum_delta_depth(), 1);
    drop(permitted);
    retain(&cache, &thin_source(format, b"left", b"right"));
    let alternative = reuse(&cache, &keys, &held, &tight).unwrap();
    assert_eq!(alternative.receipt().maximum_delta_depth(), 2);
    assert_eq!(alternative.receipt().external_base_count(), 1);
    assert_native_reconstruction(
        &alternative.into_bytes().unwrap(),
        format,
        &[b"base"],
        &[b"left", b"right"],
    );
}

#[test]
fn external_root_depth_is_not_erased_by_single_source_receipts_or_alternative_search() {
    let format = GitHashAlgorithm::Sha1;
    let middle = thin_source(format, b"base", b"middle");
    let last = thin_source(format, b"middle", b"last");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &last);
    retain(&cache, &middle);
    let held = held_blobs(format, &[b"base"]);
    let zero = PackLimits {
        max_delta_depth: 0,
        ..PackLimits::default()
    };
    assert!(reuse(&cache, &middle.keys, &held, &zero).is_none());
    let one = PackLimits {
        max_delta_depth: 1,
        ..PackLimits::default()
    };
    let singleton = reuse(&cache, &middle.keys, &held, &one).unwrap();
    assert_eq!(singleton.receipt().maximum_delta_depth(), 1);
    drop(singleton);
    let keys = selected(&[&middle, &last]);
    assert!(reuse(&cache, &keys, &held, &one).is_none());
    retain(&cache, &whole(b"last"));
    let alternative = reuse(&cache, &keys, &held, &one).unwrap();
    assert_eq!(alternative.receipt().maximum_delta_depth(), 1);
    assert_eq!(alternative.receipt().external_base_count(), 1);
    assert_native_reconstruction(
        &alternative.into_bytes().unwrap(),
        format,
        &[b"base"],
        &[b"middle", b"last"],
    );
}

#[test]
fn held_membership_cannot_hide_a_cycle_in_the_emitted_graph() {
    // Synthetic individually valid metadata exercises cross-source defensive
    // checks. Native receive does not grant proof merely from these fixtures.
    let format = GitHashAlgorithm::Sha1;
    let left = thin_source(format, b"right", b"left");
    let right = thin_source(format, b"left", b"right");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &left);
    retain(&cache, &right);
    let keys = selected(&[&left, &right]);
    let held = held_blobs(format, &[b"left", b"right"]);
    let limits = PackLimits::default();
    assert!(reuse(&cache, &keys, &held, &limits).is_none());
    retain(&cache, &whole(b"right"));
    let safe = reuse(&cache, &keys, &held, &limits).unwrap();
    assert_eq!(safe.receipt().external_base_count(), 0);
    assert_eq!(safe.receipt().profile(), "received-pack-concat-v1");
    assert_native_reconstruction(
        &safe.into_bytes().unwrap(),
        format,
        &[],
        &[b"left", b"right"],
    );
}

#[test]
fn thin_resource_limits_charge_emitted_entries_and_omit_held_payload_bytes() {
    let base = [b'x'; 64];
    let source = thin_source(GitHashAlgorithm::Sha1, &base, b"four");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &source);
    let held = held_blobs(GitHashAlgorithm::Sha1, &[&base]);
    let exact = PackLimits {
        max_entries: 1,
        max_input_bytes: source.raw.len(),
        max_object_bytes: 7,
        max_total_expanded_bytes: 7,
        max_delta_depth: 1,
        max_delta_fanout: 1,
        ..PackLimits::default()
    };
    let permitted = reuse(&cache, &source.keys, &held, &exact).unwrap();
    assert_eq!(permitted.receipt().total_object_bytes(), 4);
    assert_native_reconstruction(
        &permitted.into_bytes().unwrap(),
        GitHashAlgorithm::Sha1,
        &[&base],
        &[b"four"],
    );
    for refused in [
        PackLimits {
            max_entries: 0,
            ..exact.clone()
        },
        PackLimits {
            max_input_bytes: source.raw.len() - 1,
            ..exact.clone()
        },
        PackLimits {
            max_object_bytes: 6,
            ..exact.clone()
        },
        PackLimits {
            max_total_expanded_bytes: 6,
            ..exact.clone()
        },
        PackLimits {
            max_delta_depth: 0,
            ..exact.clone()
        },
        PackLimits {
            max_delta_fanout: 0,
            ..exact
        },
    ] {
        assert!(reuse(&cache, &source.keys, &held, &refused).is_none());
    }
}

#[test]
fn thin_readers_pin_all_source_runs_until_cursor_ownership_ends() {
    let first = thin_source(GitHashAlgorithm::Sha1, b"base", b"first");
    let second = thin_source(GitHashAlgorithm::Sha1, b"base", b"second");
    let measurement = ReceivedPackCache::new(64 * 1024);
    retain(&measurement, &first);
    retain(&measurement, &second);
    let capacity = measurement.state.lock().unwrap().resident_bytes;
    let cache = ReceivedPackCache::new(capacity);
    retain(&cache, &first);
    retain(&cache, &second);
    let keys = selected(&[&first, &second]);
    let held = held_blobs(GitHashAlgorithm::Sha1, &[b"base"]);
    let limits = PackLimits::default();
    let mut one = reuse(&cache, &keys, &held, &limits).unwrap();
    let two = reuse(&cache, &keys, &held, &limits).unwrap();
    let expected = concatenated(GitHashAlgorithm::Sha1, &[&first, &second]);
    let mut collected = one.next_chunk(5).unwrap().unwrap();
    assert_eq!(collected, expected[..5]);
    retain(&cache, &whole(b"replacement"));
    assert_eq!(cache.retained_entries(), 2);
    while let Some(chunk) = one.next_chunk(3).unwrap() {
        collected.extend(chunk);
    }
    assert_eq!(collected, expected);
    assert_eq!(two.into_bytes().unwrap(), expected);
    drop(one);
    retain(&cache, &whole(b"replacement"));
    assert!(reuse(&cache, &keys, &held, &limits).is_none());
    let state = cache.state.lock().unwrap();
    assert!(state.resident_bytes <= capacity);
    assert_eq!(state.reservations, 0);
}

#[test]
fn every_thin_lookup_checkpoint_cancels_without_pin_or_reservation_leaks() {
    let first = thin_source(GitHashAlgorithm::Sha1, b"base", b"first");
    let second = thin_source(GitHashAlgorithm::Sha1, b"first", b"second");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &first);
    retain(&cache, &second);
    let keys = selected(&[&first, &second]);
    let held = held_blobs(GitHashAlgorithm::Sha1, &[b"base", b"unused-a", b"unused-b"]);
    let limits = PackLimits::default();
    let mut calls = 0;
    drop(
        cache
            .try_reuse_with_held(&keys, &limits, true, &held, &mut || {
                calls += 1;
                true
            })
            .unwrap()
            .unwrap(),
    );
    for stop in 1..=calls {
        let mut at = 0;
        let result = cache.try_reuse_with_held(&keys, &limits, true, &held, &mut || {
            at += 1;
            at < stop
        });
        assert!(
            matches!(
                result,
                Err(PackWriteError::Pack(PackError::DeadlineExceeded))
            ),
            "thin lookup checkpoint {stop} did not preserve cancellation"
        );
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 2);
        assert_eq!(state.reservations, 0);
        assert_eq!(state.reserved_bytes, 0);
        assert!(
            state
                .entries
                .iter()
                .all(|entry| Arc::strong_count(entry) == 1)
        );
    }
    assert!(reuse(&cache, &keys, &held, &limits).is_some());
}

#[test]
fn held_proofs_cannot_bless_corrupted_dependency_metadata() {
    let source = thin_source(GitHashAlgorithm::Sha1, b"base", b"result");
    let held = held_blobs(GitHashAlgorithm::Sha1, &[b"base", b"another"]);
    let other = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"another");
    let limits = PackLimits::default();
    for damaged_parent in [None, Some(other)] {
        let cache = ReceivedPackCache::new(64 * 1024);
        retain(&cache, &source);
        assert!(reuse(&cache, &source.keys, &held, &limits).is_some());
        {
            let mut state = cache.state.lock().unwrap();
            Arc::get_mut(&mut state.entries[0]).unwrap().parents[0] = damaged_parent;
        }
        assert!(reuse(&cache, &source.keys, &held, &limits).is_none());
    }
}

#[test]
fn held_base_candidates_are_unique_parents_of_selected_targets_within_the_held_set() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let local_id = git_object_id(format, GitObjectKind::Blob, b"local");
        let local = fixture(
            format,
            &[
                Input::Whole(b"local".to_vec()),
                Input::Ofs(0, literal_delta(5, b"ofs child"), b"ofs child".to_vec()),
                Input::Ref(
                    local_id,
                    literal_delta(5, b"ref child"),
                    b"ref child".to_vec(),
                ),
                Input::Ref(
                    git_object_id(format, GitObjectKind::Blob, b"shared"),
                    literal_delta(6, b"local thin"),
                    b"local thin".to_vec(),
                ),
            ],
        );
        let first = thin_source(format, b"shared", b"first");
        let second = thin_source(format, b"shared", b"second");
        let other = thin_source(format, b"another", b"third");
        let unheld = thin_source(format, b"unheld", b"fourth");
        // A base in a different cached pack is still external to a source run;
        // that base's pack need not belong to the eventual output selection.
        let shared = fixture(format, &[Input::Whole(b"shared".to_vec())]);
        let cache = ReceivedPackCache::new(128 * 1024);
        for source in [&local, &first, &second, &other, &unheld, &shared] {
            retain(&cache, source);
        }
        assert_eq!(cache.retained_entries(), 6);
        let held: BTreeSet<_> = held_blobs(
            format,
            &[b"local", b"shared", b"another", b"not referenced"],
        )
        .into_iter()
        .map(|(id, _)| id)
        .collect();
        let expected: Vec<_> = held_blobs(format, &[b"shared", b"another"])
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let keys = selected(&[&local, &first, &second, &other, &unheld]);
        let candidates = cache
            .held_base_candidates(&keys, &held, &mut || true)
            .unwrap();
        assert_eq!(candidates, expected);
        assert!(candidates.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(!candidates.contains(&local_id));
        let without_local: Vec<_> = keys
            .iter()
            .copied()
            .filter(|key| key.id != local_id)
            .collect();
        let with_local_root = held_blobs(format, &[b"local", b"shared", b"another"])
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        assert_eq!(
            cache
                .held_base_candidates(&without_local, &held, &mut || true)
                .unwrap(),
            with_local_root
        );
        let irrelevant = BTreeSet::from([local_id]);
        assert!(
            cache
                .held_base_candidates(&keys, &irrelevant, &mut || true)
                .unwrap()
                .is_empty()
        );
        assert!(
            cache
                .held_base_candidates(&keys, &BTreeSet::new(), &mut || true)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn every_held_candidate_scan_checkpoint_cancels_and_releases_snapshot_pins() {
    let format = GitHashAlgorithm::Sha256;
    let first = thin_source(format, b"base-a", b"first");
    let second = thin_source(format, b"base-b", b"second");
    let local = fixture(
        format,
        &[
            Input::Whole(b"local".to_vec()),
            Input::Ofs(0, literal_delta(5, b"local child"), b"local child".to_vec()),
        ],
    );
    let cache = ReceivedPackCache::new(64 * 1024);
    for source in [&first, &local, &second] {
        retain(&cache, source);
    }
    let held: BTreeSet<_> = held_blobs(format, &[b"base-a", b"base-b", b"local", b"unused"])
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let resident = cache.state.lock().unwrap().resident_bytes;
    let keys = selected(&[&first, &local, &second]);
    let mut calls = 0;
    let expected = cache
        .held_base_candidates(&keys, &held, &mut || {
            calls += 1;
            true
        })
        .unwrap();
    assert_eq!(expected.len(), 2);
    for stop in 1..=calls {
        let mut at = 0;
        let result = cache.held_base_candidates(&keys, &held, &mut || {
            at += 1;
            at < stop
        });
        assert!(
            matches!(
                result,
                Err(PackWriteError::Pack(PackError::DeadlineExceeded))
            ),
            "held candidate scan checkpoint {stop} did not preserve cancellation"
        );
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 3);
        assert_eq!(state.resident_bytes, resident);
        assert_eq!(state.reservations, 0);
        assert_eq!(state.reserved_bytes, 0);
        assert!(
            state
                .entries
                .iter()
                .all(|entry| Arc::strong_count(entry) == 1)
        );
    }
    assert_eq!(
        cache
            .held_base_candidates(&keys, &held, &mut || true)
            .unwrap(),
        expected
    );
    let typed = held_blobs(format, &[b"base-a", b"base-b"]);
    let reused = reuse(
        &cache,
        &selected(&[&first, &second]),
        &typed,
        &PackLimits::default(),
    )
    .unwrap();
    assert_eq!(reused.receipt().external_base_count(), 2);
    assert_native_reconstruction(
        &reused.into_bytes().unwrap(),
        format,
        &[b"base-a", b"base-b"],
        &[b"first", b"second"],
    );
}
