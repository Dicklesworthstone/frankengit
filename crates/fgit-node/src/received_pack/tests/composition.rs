//! Composed representations must remain self-contained, exact and bounded.
use super::*;
use fgit_pack::{PackObject, ScalarResolver, read_verified_pack};

fn union_keys(fixtures: &[&Fixture]) -> Vec<PackOrderKey> {
    let mut keys = BTreeMap::new();
    for fixture in fixtures {
        for key in &fixture.keys {
            keys.insert(key.id, *key);
        }
    }
    keys.into_values().collect()
}

fn thin(format: GitHashAlgorithm, base: &[u8], body: &[u8]) -> Fixture {
    fixture(
        format,
        &[Input::Ref(
            git_object_id(format, GitObjectKind::Blob, base),
            literal_delta(base.len(), body),
            body.to_vec(),
        )],
    )
}

fn reuse(
    cache: &ReceivedPackCache,
    keys: &[PackOrderKey],
    limits: &PackLimits,
) -> Option<ReceivedPackPayload> {
    cache.try_reuse(keys, limits, true, &mut || true).unwrap()
}

fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}

/// Discover native IDs from the assembled bytes, without cache metadata or an
/// external-base oracle. A later pass learns forward REF identities from the
/// preceding pass; every result is independently rehashed and compared.
fn assert_reconstructs(raw: &[u8], format: GitHashAlgorithm, bodies: &[&[u8]]) {
    let limits = PackLimits::default();
    let parsed =
        read_verified_pack(raw, format, &limits, &mut || true, &NativeChecksumVerifier).unwrap();
    assert_eq!(parsed.entries().len(), bodies.len());
    let mut objects = parsed.into_scalar_objects(|_| None).unwrap();
    let mut resolved = BTreeMap::new();
    for _ in 0..objects.len() {
        let resolver = ScalarResolver::new(&objects, &(), &limits, &mut || true).unwrap();
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
                Err(error) => panic!("composed native reconstruction failed: {error:?}"),
            }
        }
        assert!(
            !learned.is_empty(),
            "assembled pack has no self-contained resolution"
        );
        for (at, id, body) in learned {
            let object = objects
                .iter_mut()
                .find(|object| offset(object) == at)
                .unwrap();
            match object {
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
    assert_eq!(resolved.len(), objects.len());
    let mut actual = BTreeMap::new();
    for (id, body) in resolved.into_values() {
        assert!(
            actual.insert(id, body).is_none(),
            "duplicate native identity"
        );
    }
    let expected: BTreeMap<_, _> = bodies
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

fn concatenated(format: GitHashAlgorithm, fixtures: &[&Fixture]) -> Vec<u8> {
    let count: usize = fixtures.iter().map(|fixture| fixture.objects.len()).sum();
    let mut bytes = b"PACK".to_vec();
    bytes.extend(2u32.to_be_bytes());
    bytes.extend(u32::try_from(count).unwrap().to_be_bytes());
    for fixture in fixtures {
        bytes.extend_from_slice(&fixture.raw[12..fixture.raw.len() - format.digest_len()]);
    }
    match format {
        GitHashAlgorithm::Sha1 => bytes.extend(sha1_digest(&bytes)),
        GitHashAlgorithm::Sha256 => bytes.extend(sha256_digest(&bytes)),
    }
    bytes
}

#[test]
fn disjoint_packs_have_one_header_trailer_and_exact_native_membership() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let first = fixture(format, &[Input::Whole(b"first".to_vec())]);
        let second = fixture(format, &[Input::Whole(b"second".to_vec())]);
        let unrelated = fixture(format, &[Input::Whole(b"hidden".to_vec())]);
        let cache = ReceivedPackCache::new(64 * 1024);
        for source in [&first, &second, &unrelated] {
            retain(&cache, source);
        }
        let keys = union_keys(&[&first, &second]);
        let expected = concatenated(format, &[&first, &second]);
        let payload = reuse(&cache, &keys, &PackLimits::default()).unwrap();
        assert_eq!(payload.receipt().profile(), "received-pack-concat-v1");
        assert_eq!(payload.receipt().source_pack_count(), 2);
        assert_eq!(payload.receipt().object_count(), 2);
        assert_eq!(payload.receipt().output_bytes(), expected.len());
        assert_eq!(payload.receipt().sha256(), &sha256_digest(&expected));
        let bytes = payload.into_bytes().unwrap();
        assert_eq!(bytes, expected);
        assert_reconstructs(&bytes, format, &[b"first", b"second"]);
        let unchanged = reuse(&cache, &first.keys, &PackLimits::default()).unwrap();
        assert_eq!(unchanged.receipt().profile(), "received-pack-v1");
        assert_eq!(unchanged.receipt().source_pack_count(), 1);
        assert_eq!(unchanged.into_bytes().unwrap(), first.raw);
    }
}

#[test]
fn forward_ref_chains_and_shifted_ofs_runs_reconstruct_without_external_bases() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let last = thin(format, b"middle", b"last");
        let middle = thin(format, b"base", b"middle");
        let root = fixture(
            format,
            &[
                Input::Whole(b"base".to_vec()),
                Input::Ofs(0, literal_delta(4, b"sibling"), b"sibling".to_vec()),
            ],
        );
        let cache = ReceivedPackCache::new(64 * 1024);
        for source in [&last, &middle, &root] {
            retain(&cache, source);
        }
        let keys = union_keys(&[&last, &middle, &root]);
        let payload = reuse(&cache, &keys, &PackLimits::default()).unwrap();
        assert_eq!(payload.receipt().source_pack_count(), 3);
        assert_eq!(payload.receipt().maximum_delta_depth(), 2);
        assert_eq!(payload.receipt().ofs_delta_count(), 1);
        assert_eq!(payload.receipt().ref_delta_count(), 2);
        let raw = payload.into_bytes().unwrap();
        assert_eq!(raw, concatenated(format, &[&last, &middle, &root]));
        assert_reconstructs(&raw, format, &[b"base", b"middle", b"last", b"sibling"]);
        assert!(
            cache
                .try_reuse(&keys, &PackLimits::default(), false, &mut || true)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn overlapping_packs_are_not_a_disjoint_cover_and_an_alternative_can_complete_it() {
    let left = fixture(
        GitHashAlgorithm::Sha1,
        &[Input::Whole(b"a".to_vec()), Input::Whole(b"b".to_vec())],
    );
    let right = fixture(
        GitHashAlgorithm::Sha1,
        &[Input::Whole(b"b".to_vec()), Input::Whole(b"c".to_vec())],
    );
    let tail = whole(b"c");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &left);
    retain(&cache, &right);
    let keys = union_keys(&[&left, &right]);
    assert!(reuse(&cache, &keys, &PackLimits::default()).is_none());
    retain(&cache, &tail);
    let payload = reuse(&cache, &keys, &PackLimits::default()).unwrap();
    assert_eq!(payload.receipt().source_pack_count(), 2);
    assert_reconstructs(
        &payload.into_bytes().unwrap(),
        GitHashAlgorithm::Sha1,
        &[b"a", b"b", b"c"],
    );
    let mut duplicates = keys.clone();
    duplicates.insert(0, keys[0]);
    assert!(reuse(&cache, &duplicates, &PackLimits::default()).is_none());
}

#[test]
fn thin_custody_cannot_disclose_an_unselected_base_or_ignore_a_selected_type() {
    let base = whole(b"outside");
    let delta = thin(GitHashAlgorithm::Sha1, b"outside", b"inside");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &base);
    retain(&cache, &delta);
    assert!(reuse(&cache, &delta.keys, &PackLimits::default()).is_none());
    let mut keys = union_keys(&[&base, &delta]);
    let raw = reuse(&cache, &keys, &PackLimits::default())
        .unwrap()
        .into_bytes()
        .unwrap();
    assert_reconstructs(&raw, GitHashAlgorithm::Sha1, &[b"outside", b"inside"]);
    keys.iter_mut()
        .find(|key| key.id == base.keys[0].id)
        .unwrap()
        .object_type = ObjectType::Tree;
    assert!(reuse(&cache, &keys, &PackLimits::default()).is_none());
}

#[test]
fn different_native_hash_domains_never_form_one_composed_pack() {
    let one = whole(b"sha1");
    let two = fixture(
        GitHashAlgorithm::Sha256,
        &[Input::Whole(b"sha256".to_vec())],
    );
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &one);
    retain(&cache, &two);
    assert!(reuse(&cache, &union_keys(&[&one, &two]), &PackLimits::default()).is_none());
    assert!(reuse(&cache, &one.keys, &PackLimits::default()).is_some());
    assert!(reuse(&cache, &two.keys, &PackLimits::default()).is_some());
}

#[test]
fn composed_output_and_expansion_limits_apply_to_the_whole_selection() {
    let one = whole(b"aaaa");
    let two = whole(b"bb");
    let keys = union_keys(&[&one, &two]);
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &one);
    retain(&cache, &two);
    let exact = PackLimits {
        max_input_bytes: concatenated(GitHashAlgorithm::Sha1, &[&one, &two]).len(),
        max_entries: 2,
        max_object_bytes: 4,
        max_total_expanded_bytes: 6,
        ..PackLimits::default()
    };
    assert!(reuse(&cache, &keys, &exact).is_some());
    for limit in [
        PackLimits {
            max_input_bytes: exact.max_input_bytes - 1,
            ..exact.clone()
        },
        PackLimits {
            max_entries: 1,
            ..exact.clone()
        },
        PackLimits {
            max_object_bytes: 3,
            ..exact.clone()
        },
        PackLimits {
            max_total_expanded_bytes: 5,
            ..exact
        },
    ] {
        assert!(reuse(&cache, &keys, &limit).is_none());
    }
}

#[test]
fn composed_inflated_program_bytes_remain_separate_from_native_body_bytes() {
    let base = whole(b"x");
    let delta = thin(GitHashAlgorithm::Sha1, b"x", b"yz");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &base);
    retain(&cache, &delta);
    let keys = union_keys(&[&base, &delta]);
    let limits = PackLimits {
        max_object_bytes: 5,
        max_total_expanded_bytes: 6,
        ..PackLimits::default()
    };
    let payload = reuse(&cache, &keys, &limits).unwrap();
    assert_eq!(payload.receipt().total_object_bytes(), 3);
    for limit in [
        PackLimits {
            max_object_bytes: 2,
            ..limits.clone()
        },
        PackLimits {
            max_total_expanded_bytes: 5,
            ..limits
        },
    ] {
        assert!(reuse(&cache, &keys, &limit).is_none());
    }
}

#[test]
fn depth_is_global_and_later_safe_covers_are_considered() {
    let base = whole(b"a");
    let middle = thin(GitHashAlgorithm::Sha1, b"a", b"b");
    let last = thin(GitHashAlgorithm::Sha1, b"b", b"c");
    let cache = ReceivedPackCache::new(64 * 1024);
    for source in [&base, &middle, &last] {
        retain(&cache, source);
    }
    let keys = union_keys(&[&base, &middle, &last]);
    let strict = PackLimits {
        max_delta_depth: 1,
        ..PackLimits::default()
    };
    assert!(reuse(&cache, &keys, &strict).is_none());
    assert_eq!(
        reuse(&cache, &keys, &PackLimits::default())
            .unwrap()
            .receipt()
            .maximum_delta_depth(),
        2
    );
    retain(&cache, &whole(b"c"));
    let safe = reuse(&cache, &keys, &strict).unwrap();
    assert_eq!(safe.receipt().maximum_delta_depth(), 1);
    assert_reconstructs(
        &safe.into_bytes().unwrap(),
        GitHashAlgorithm::Sha1,
        &[b"a", b"b", b"c"],
    );
}

#[test]
fn fanout_counts_shared_bases_across_original_pack_boundaries() {
    let base = whole(b"a");
    let left = thin(GitHashAlgorithm::Sha1, b"a", b"b");
    let right = thin(GitHashAlgorithm::Sha1, b"a", b"c");
    let cache = ReceivedPackCache::new(64 * 1024);
    for source in [&base, &left, &right] {
        retain(&cache, source);
    }
    let keys = union_keys(&[&base, &left, &right]);
    let strict = PackLimits {
        max_delta_fanout: 1,
        ..PackLimits::default()
    };
    assert!(reuse(&cache, &keys, &strict).is_none());
    assert!(reuse(&cache, &keys, &PackLimits::default()).is_some());
    retain(&cache, &thin(GitHashAlgorithm::Sha1, b"b", b"c"));
    let safe = reuse(&cache, &keys, &strict).unwrap();
    assert_eq!(safe.receipt().maximum_delta_depth(), 2);
    assert_reconstructs(
        &safe.into_bytes().unwrap(),
        GitHashAlgorithm::Sha1,
        &[b"a", b"b", b"c"],
    );
}

#[test]
fn cross_pack_dependency_cycles_never_establish_a_self_contained_representation() {
    // These synthetic verified-metadata inputs exercise the defensive graph
    // gate; they do not claim the production validator admitted a cyclic pack.
    let left = thin(GitHashAlgorithm::Sha1, b"b", b"a");
    let right = thin(GitHashAlgorithm::Sha1, b"a", b"b");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &left);
    retain(&cache, &right);
    let keys = union_keys(&[&left, &right]);
    assert!(reuse(&cache, &keys, &PackLimits::default()).is_none());
    retain(&cache, &whole(b"b"));
    let permitted = reuse(&cache, &keys, &PackLimits::default()).unwrap();
    assert_reconstructs(
        &permitted.into_bytes().unwrap(),
        GitHashAlgorithm::Sha1,
        &[b"a", b"b"],
    );
}

#[test]
fn dependency_metadata_is_bound_to_the_original_verified_bytes() {
    let base = whole(b"base");
    let delta = thin(GitHashAlgorithm::Sha1, b"base", b"result");
    for parent in [None, Some(delta.keys[0].id)] {
        let cache = ReceivedPackCache::new(64 * 1024);
        retain(&cache, &base);
        retain(&cache, &delta);
        let keys = union_keys(&[&base, &delta]);
        assert!(reuse(&cache, &keys, &PackLimits::default()).is_some());
        {
            let mut state = cache.state.lock().unwrap();
            let entry = Arc::get_mut(&mut state.entries[1]).unwrap();
            entry.parents[0] = parent;
        }
        assert!(reuse(&cache, &keys, &PackLimits::default()).is_none());
    }
}

#[test]
fn every_composition_checkpoint_cancels_without_leaking_reader_pins() {
    let base = whole(b"base");
    let delta = thin(GitHashAlgorithm::Sha1, b"base", b"result");
    let cache = ReceivedPackCache::new(64 * 1024);
    retain(&cache, &base);
    retain(&cache, &delta);
    let keys = union_keys(&[&base, &delta]);
    let mut calls = 0;
    drop(
        cache
            .try_reuse(&keys, &PackLimits::default(), true, &mut || {
                calls += 1;
                true
            })
            .unwrap()
            .unwrap(),
    );
    for stop in 1..=calls {
        let mut at = 0;
        let result = cache.try_reuse(&keys, &PackLimits::default(), true, &mut || {
            at += 1;
            at < stop
        });
        assert!(
            matches!(
                result,
                Err(PackWriteError::Pack(PackError::DeadlineExceeded))
            ),
            "composition checkpoint {stop} did not preserve cancellation"
        );
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 2);
        assert_eq!(state.reservations, 0);
        assert!(
            state
                .entries
                .iter()
                .all(|entry| Arc::strong_count(entry) == 1)
        );
    }
    assert!(reuse(&cache, &keys, &PackLimits::default()).is_some());
}

#[test]
fn composed_readers_pin_all_sources_and_own_independent_cursors() {
    let first = whole(b"first");
    let second = whole(b"second");
    let measurement = ReceivedPackCache::new(64 * 1024);
    retain(&measurement, &first);
    retain(&measurement, &second);
    let capacity = measurement.state.lock().unwrap().resident_bytes;
    let cache = ReceivedPackCache::new(capacity);
    retain(&cache, &first);
    retain(&cache, &second);
    let keys = union_keys(&[&first, &second]);
    let expected = concatenated(GitHashAlgorithm::Sha1, &[&first, &second]);
    let mut one = reuse(&cache, &keys, &PackLimits::default()).unwrap();
    let mut two = reuse(&cache, &keys, &PackLimits::default()).unwrap();
    let first_chunk = one.next_chunk(13).unwrap().unwrap();
    assert!(!first_chunk.is_empty() && first_chunk.len() <= 13);
    assert_eq!(first_chunk, expected[..first_chunk.len()]);
    assert_eq!(two.next_chunk(1).unwrap().unwrap(), expected[..1]);
    retain(&cache, &whole(b"third"));
    assert_eq!(cache.retained_entries(), 2);
    let mut collected = first_chunk;
    while let Some(chunk) = one.next_chunk(3).unwrap() {
        collected.extend(chunk);
    }
    assert_eq!(collected, expected);
    assert!(one.next_chunk(0).is_err());
    assert_eq!(two.into_bytes().unwrap(), expected);
    drop(one);
    retain(&cache, &whole(b"third"));
    assert!(reuse(&cache, &keys, &PackLimits::default()).is_none());
}
