//! Long incremental histories retain bounded, exact-cover pack reuse.
use super::*;
use fgit_pack::{ExternalBaseLookup, PackObject, ScalarResolver, read_verified_pack};

fn bodies(prefix: &str, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| format!("{prefix}-{index:02}").into_bytes())
        .collect()
}

fn whole_sources(format: GitHashAlgorithm, bodies: &[Vec<u8>]) -> Vec<Fixture> {
    bodies
        .iter()
        .map(|body| fixture(format, &[Input::Whole(body.clone())]))
        .collect()
}

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

fn keys<'a>(sources: impl IntoIterator<Item = &'a Fixture>) -> Vec<PackOrderKey> {
    sources
        .into_iter()
        .flat_map(|source| source.keys.iter().map(|key| (key.id, *key)))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn cache_for(sources: &[Fixture]) -> ReceivedPackCache {
    let cache = ReceivedPackCache::new(512 * 1024);
    for source in sources {
        retain(&cache, source);
    }
    assert_eq!(cache.retained_entries(), sources.len());
    cache
}

fn reuse(
    cache: &ReceivedPackCache,
    keys: &[PackOrderKey],
    limits: &PackLimits,
) -> Option<ReceivedPackPayload> {
    cache.try_reuse(keys, limits, true, &mut || true).unwrap()
}

fn assembled<'a>(
    format: GitHashAlgorithm,
    sources: impl IntoIterator<Item = &'a Fixture>,
) -> Vec<u8> {
    let sources: Vec<_> = sources.into_iter().collect();
    let count: usize = sources.iter().map(|source| source.objects.len()).sum();
    let mut raw = b"PACK".to_vec();
    raw.extend(2u32.to_be_bytes());
    raw.extend(u32::try_from(count).unwrap().to_be_bytes());
    for source in sources {
        raw.extend_from_slice(&source.raw[12..source.raw.len() - format.digest_len()]);
    }
    match format {
        GitHashAlgorithm::Sha1 => raw.extend(sha1_digest(&raw)),
        GitHashAlgorithm::Sha256 => raw.extend(sha256_digest(&raw)),
    }
    raw
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
        self.lookup(id).map(|bytes| (ObjectType::Blob, bytes))
    }
}

/// Read IDs from the emitted native bytes, with no cached offset hints. The
/// optional oracle authenticates only explicitly supplied external base bodies.
fn assert_native_objects(
    raw: &[u8],
    format: GitHashAlgorithm,
    expected: &[Vec<u8>],
    bases: &[Vec<u8>],
) {
    let limits = PackLimits::default();
    let parsed =
        read_verified_pack(raw, format, &limits, &mut || true, &NativeChecksumVerifier).unwrap();
    assert_eq!(parsed.entries().len(), expected.len());
    let mut objects = parsed.into_scalar_objects(|_| None).unwrap();
    let oracle = NativeBases(
        bases
            .iter()
            .map(|body| {
                (
                    git_object_id(format, GitObjectKind::Blob, body),
                    body.clone(),
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
                    learned.push((at, git_object_id(format, GitObjectKind::Blob, &body), body));
                }
                Err(PackError::MissingDeltaBase) => {}
                Err(error) => panic!("long-history native reconstruction failed: {error:?}"),
            }
        }
        assert!(
            !learned.is_empty(),
            "the emitted dependency graph has no root"
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
    assert_eq!(resolved.len(), expected.len());
    let mut actual = BTreeMap::new();
    for (id, body) in resolved.into_values() {
        assert!(
            actual.insert(id, body).is_none(),
            "duplicate emitted identity"
        );
    }
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|body| {
            (
                git_object_id(format, GitObjectKind::Blob, body),
                body.clone(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
}

fn source_sets(format: GitHashAlgorithm, universe: &[Vec<u8>], sets: &[u64]) -> Vec<Fixture> {
    sets.iter()
        .map(|set| {
            let inputs: Vec<_> = universe
                .iter()
                .enumerate()
                .filter(|(index, _)| set & (1u64 << index) != 0)
                .map(|(_, body)| Input::Whole(body.clone()))
                .collect();
            fixture(format, &inputs)
        })
        .collect()
}

/// Deliberately small exhaustive reference: no production cover machinery is
/// used to decide the least-source, then least-numeric-mask exact cover.
fn reference_cover(sets: &[u64], target: u64) -> Option<u16> {
    assert!(sets.len() <= 12);
    let mut best = None::<(u32, u16)>;
    for mask in 1u16..1u16 << sets.len() {
        let mut union = 0;
        let mut disjoint = true;
        for (index, set) in sets.iter().enumerate() {
            if mask & (1 << index) != 0 {
                if union & set != 0 {
                    disjoint = false;
                    break;
                }
                union |= set;
            }
        }
        if disjoint && union == target {
            let candidate = (mask.count_ones(), mask);
            if best.is_none_or(|best| candidate < best) {
                best = Some(candidate);
            }
        }
    }
    best.map(|(_, mask)| mask)
}

#[test]
fn nine_and_sixty_four_disjoint_runs_preserve_every_native_object_in_both_formats() {
    assert_eq!(MAX_ENTRIES, 64);
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for count in [9, 64] {
            let bodies = bodies("history", count);
            let sources = whole_sources(format, &bodies);
            let cache = cache_for(&sources);
            let expected = assembled(format, &sources);
            let reused = reuse(&cache, &keys(&sources), &PackLimits::default()).unwrap();
            assert_eq!(reused.receipt().profile(), "received-pack-concat-v1");
            assert_eq!(reused.receipt().source_pack_count(), count);
            assert_eq!(reused.receipt().object_count() as usize, count);
            assert_eq!(reused.receipt().external_base_count(), 0);
            assert_eq!(reused.receipt().maximum_delta_depth(), 0);
            assert_eq!(reused.receipt().output_bytes(), expected.len());
            assert_eq!(reused.receipt().sha256(), &sha256_digest(&expected));
            let raw = reused.into_bytes().unwrap();
            assert_eq!(raw, expected);
            assert_native_objects(&raw, format, &bodies, &[]);
        }
    }
}

#[test]
fn sixty_four_source_ref_chains_reconstruct_at_the_exact_internal_and_external_depth_limits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for external in [false, true] {
            let bodies = bodies("chain", 65);
            let start = usize::from(external);
            let end = start + 64;
            // Every REF points forward in the concatenated representation.
            let sources: Vec<_> = (start..end)
                .rev()
                .map(|index| {
                    if index == 0 {
                        fixture(format, &[Input::Whole(bodies[index].clone())])
                    } else {
                        thin_source(format, &bodies[index - 1], &bodies[index])
                    }
                })
                .collect();
            let cache = cache_for(&sources);
            let selected = keys(&sources);
            let held = if external {
                vec![(
                    git_object_id(format, GitObjectKind::Blob, &bodies[0]),
                    ObjectType::Blob,
                )]
            } else {
                Vec::new()
            };
            let depth = 63 + usize::from(external);
            let exact = PackLimits {
                max_entries: 64,
                max_delta_depth: depth,
                max_delta_fanout: 1,
                ..PackLimits::default()
            };
            let reused = cache
                .try_reuse_with_held(&selected, &exact, false, &held, &mut || true)
                .unwrap()
                .unwrap();
            assert_eq!(reused.receipt().source_pack_count(), 64);
            assert_eq!(reused.receipt().maximum_delta_depth(), depth);
            assert_eq!(
                reused.receipt().external_base_count(),
                usize::from(external)
            );
            assert_eq!(reused.receipt().ref_delta_count(), depth);
            let raw = reused.into_bytes().unwrap();
            assert_eq!(raw, assembled(format, &sources));
            assert_native_objects(
                &raw,
                format,
                &bodies[start..end],
                if external { &bodies[..1] } else { &[] },
            );
            let too_shallow = PackLimits {
                max_delta_depth: depth - 1,
                ..exact
            };
            assert!(
                cache
                    .try_reuse_with_held(&selected, &too_shallow, false, &held, &mut || true)
                    .unwrap()
                    .is_none()
            );
            if external {
                assert!(reuse(&cache, &selected, &PackLimits::default()).is_none());
            }
        }
    }
}

#[test]
fn forced_overlap_removal_propagates_to_new_owners_and_detects_impossible_coverage() {
    let format = GitHashAlgorithm::Sha1;
    for edge_count in [9, 10] {
        let universe = bodies("path", edge_count + 1);
        let sets: Vec<_> = (0..edge_count)
            .map(|index| (1u64 << index) | (1u64 << (index + 1)))
            .collect();
        let sources = source_sets(format, &universe, &sets);
        let cache = cache_for(&sources);
        let result = reuse(&cache, &keys(&sources), &PackLimits::default());
        if edge_count == 10 {
            assert!(result.is_none(), "an odd path has no disjoint edge cover");
        } else {
            let reused = result.unwrap();
            assert_eq!(reused.receipt().source_pack_count(), 5);
            let raw = reused.into_bytes().unwrap();
            assert_eq!(raw, assembled(format, sources.iter().step_by(2)));
            assert_native_objects(&raw, format, &universe, &[]);
        }
    }
}

#[test]
fn forced_spines_and_small_ambiguous_residuals_match_an_independent_exhaustive_oracle() {
    let format = GitHashAlgorithm::Sha1;
    let universe = bodies("oracle", 8);
    for seed in 0..6 {
        let mut residual = vec![1, 2, 4, 8, 3, 12, 5, 10];
        if seed % 2 == 1 {
            residual[0] = 15;
        }
        residual.rotate_left(seed);
        let mut sets = vec![1 << 4, 1 << 5, 1 << 6, 1 << 7];
        sets.extend(residual);
        sets.rotate_left(seed);
        let expected = reference_cover(&sets, 255).unwrap();
        let sources = source_sets(format, &universe, &sets);
        let cache = cache_for(&sources);
        let reused = reuse(&cache, &keys(&sources), &PackLimits::default()).unwrap();
        assert_eq!(
            reused.receipt().source_pack_count(),
            expected.count_ones() as usize
        );
        assert_eq!(
            reused.into_bytes().unwrap(),
            assembled(
                format,
                sources
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| expected & (1 << index) != 0)
                    .map(|(_, source)| source),
            ),
            "cover ordering diverged for deterministic case {seed}"
        );
    }
}

#[test]
fn invalid_residual_delta_cycle_does_not_discard_a_later_valid_cover() {
    let format = GitHashAlgorithm::Sha1;
    let spine_bodies = bodies("spine", 7);
    let mut sources = whole_sources(format, &spine_bodies);
    sources.push(thin_source(format, b"right", b"left"));
    sources.push(thin_source(format, b"left", b"right"));
    sources.push(whole(b"right"));
    let cache = cache_for(&sources);
    let reused = reuse(&cache, &keys(&sources), &PackLimits::default()).unwrap();
    assert_eq!(reused.receipt().source_pack_count(), 9);
    assert_eq!(reused.receipt().maximum_delta_depth(), 1);
    let raw = reused.into_bytes().unwrap();
    assert_eq!(
        raw,
        assembled(format, sources[..8].iter().chain(&sources[9..]))
    );
    let mut expected = spine_bodies;
    expected.extend([b"left".to_vec(), b"right".to_vec()]);
    assert_native_objects(&raw, format, &expected, &[]);
}

#[test]
fn more_than_eight_full_base_variants_still_complete_a_forced_incremental_spine() {
    let format = GitHashAlgorithm::Sha256;
    let permutations = [
        [0, 1, 2, 3],
        [0, 1, 3, 2],
        [0, 2, 1, 3],
        [0, 2, 3, 1],
        [0, 3, 1, 2],
        [0, 3, 2, 1],
        [1, 0, 2, 3],
        [1, 0, 3, 2],
        [1, 2, 0, 3],
    ];
    for invalid_first in [false, true] {
        let base = bodies("base", 4);
        let increments = bodies("increment", 10);
        let mut sources: Vec<_> = permutations
            .iter()
            .enumerate()
            .map(|(variant, order)| {
                let entries: Vec<_> = order
                    .iter()
                    .map(|index| {
                        if invalid_first && variant == 0 && *index == 0 {
                            Input::Ref(
                                git_object_id(format, GitObjectKind::Blob, b"unheld"),
                                literal_delta(6, &base[0]),
                                base[0].clone(),
                            )
                        } else {
                            Input::Whole(base[*index].clone())
                        }
                    })
                    .collect();
                fixture(format, &entries)
            })
            .collect();
        for (index, body) in increments.iter().enumerate() {
            let parent = if index == 0 {
                &base[0]
            } else {
                &increments[index - 1]
            };
            sources.push(thin_source(format, parent, body));
        }
        let cache = cache_for(&sources);
        let reused = reuse(&cache, &keys(&sources), &PackLimits::default()).unwrap();
        assert_eq!(reused.receipt().source_pack_count(), 11);
        assert_eq!(reused.receipt().object_count(), 14);
        assert_eq!(reused.receipt().maximum_delta_depth(), 10);
        assert_eq!(reused.receipt().external_base_count(), 0);
        let raw = reused.into_bytes().unwrap();
        let selected_base = usize::from(invalid_first);
        assert_eq!(
            raw,
            assembled(
                format,
                std::iter::once(&sources[selected_base]).chain(&sources[9..])
            )
        );
        let mut expected = base;
        expected.extend(increments);
        assert_native_objects(&raw, format, &expected, &[]);
    }
}

#[test]
fn rejected_global_singletons_do_not_block_large_covers_and_valid_singletons_keep_fifo_priority() {
    let format = GitHashAlgorithm::Sha1;
    let universe = bodies("singleton", 9);
    let mut sources = whole_sources(format, &universe);
    let mut bad_entries = vec![Input::Ref(
        git_object_id(format, GitObjectKind::Blob, b"missing"),
        literal_delta(7, &universe[0]),
        universe[0].clone(),
    )];
    bad_entries.extend(universe[1..].iter().cloned().map(Input::Whole));
    sources.push(fixture(format, &bad_entries));
    let cache = cache_for(&sources);
    let selected = keys(&sources);
    let reduced = reuse(&cache, &selected, &PackLimits::default()).unwrap();
    assert_eq!(reduced.receipt().source_pack_count(), 9);
    assert_eq!(
        reduced.into_bytes().unwrap(),
        assembled(format, &sources[..9])
    );
    let earlier = fixture(
        format,
        &universe
            .iter()
            .rev()
            .cloned()
            .map(Input::Whole)
            .collect::<Vec<_>>(),
    );
    let later = fixture(
        format,
        &universe
            .iter()
            .cloned()
            .map(Input::Whole)
            .collect::<Vec<_>>(),
    );
    retain(&cache, &earlier);
    retain(&cache, &later);
    let reused = reuse(&cache, &selected, &PackLimits::default()).unwrap();
    assert_eq!(reused.receipt().source_pack_count(), 1);
    assert_eq!(reused.receipt().profile(), "received-pack-v1");
    assert_eq!(reused.into_bytes().unwrap(), earlier.raw);
}

#[test]
fn a_large_cache_preserves_exhaustive_behavior_when_few_sources_match_the_selection() {
    let format = GitHashAlgorithm::Sha1;
    let unrelated = whole_sources(format, &bodies("unrelated", 12));
    let cache = cache_for(&unrelated);
    let left = fixture(
        format,
        &[Input::Whole(b"a".to_vec()), Input::Whole(b"b".to_vec())],
    );
    let overlap = fixture(
        format,
        &[Input::Whole(b"b".to_vec()), Input::Whole(b"c".to_vec())],
    );
    let tail = whole(b"c");
    for source in [&left, &overlap, &tail] {
        retain(&cache, source);
    }
    assert_eq!(cache.retained_entries(), 15);
    let selected = keys([&left, &overlap]);
    let reused = reuse(&cache, &selected, &PackLimits::default()).unwrap();
    assert_eq!(reused.receipt().source_pack_count(), 2);
    assert_eq!(
        reused.into_bytes().unwrap(),
        assembled(format, [&left, &tail])
    );
    let exact = fixture(
        format,
        &[
            Input::Whole(b"c".to_vec()),
            Input::Whole(b"b".to_vec()),
            Input::Whole(b"a".to_vec()),
        ],
    );
    retain(&cache, &exact);
    let reused = reuse(&cache, &selected, &PackLimits::default()).unwrap();
    assert_eq!(reused.receipt().source_pack_count(), 1);
    assert_eq!(reused.into_bytes().unwrap(), exact.raw);
}

#[test]
fn long_cover_membership_never_omits_unknown_keys_or_leaks_unselected_pack_entries() {
    let format = GitHashAlgorithm::Sha1;
    let universe = bodies("selected", 9);
    let sources = whole_sources(format, &universe);
    let cache = cache_for(&sources);
    let selected = keys(&sources);
    let limits = PackLimits::default();
    let ghost = whole(b"unknown");
    let unknown = keys(sources.iter().chain(std::iter::once(&ghost)));
    let mut duplicate = selected.clone();
    duplicate.insert(0, duplicate[0]);
    for refused in [unknown, duplicate] {
        assert!(reuse(&cache, &refused, &limits).is_none());
    }
    let subset = reuse(&cache, &keys(&sources[1..]), &limits).unwrap();
    assert_eq!(subset.receipt().object_count(), 8);
    let extra = fixture(
        format,
        &[
            Input::Whole(universe[0].clone()),
            Input::Whole(b"hidden".to_vec()),
        ],
    );
    let mixed_cache = cache_for(&sources[1..]);
    retain(&mixed_cache, &extra);
    assert!(reuse(&mixed_cache, &selected, &limits).is_none());
    let all = keys(sources[1..].iter().chain(std::iter::once(&extra)));
    let allowed = reuse(&mixed_cache, &all, &limits).unwrap();
    assert_eq!(allowed.receipt().object_count(), 10);
    let mut expected = universe;
    expected.push(b"hidden".to_vec());
    assert_native_objects(&allowed.into_bytes().unwrap(), format, &expected, &[]);
}

#[test]
fn large_non_singleton_ambiguity_is_a_deterministic_bounded_miss() {
    let format = GitHashAlgorithm::Sha1;
    let universe = bodies("ring", 64);
    // Two different 32-source covers exist, but every object has two owners
    // and no remaining source covers the entire residual selection.
    let sets: Vec<_> = (0..64)
        .map(|index| (1u64 << index) | (1u64 << ((index + 1) % 64)))
        .collect();
    let sources = source_sets(format, &universe, &sets);
    let cache = cache_for(&sources);
    let selected = keys(&sources);
    let limits = PackLimits::default();
    let mut observed = None;
    for _ in 0..2 {
        let mut calls = 0;
        let result = cache.try_reuse(&selected, &limits, true, &mut || {
            calls += 1;
            calls < 8192
        });
        assert!(
            matches!(result, Ok(None)),
            "large ambiguity exceeded its bounded selection path"
        );
        assert!(calls < 8192);
        if let Some(previous) = observed {
            assert_eq!(calls, previous);
        }
        observed = Some(calls);
    }
    let permitted = reuse(&cache, &sources[0].keys, &limits).unwrap();
    assert_eq!(permitted.receipt().source_pack_count(), 1);
    assert_eq!(permitted.into_bytes().unwrap(), sources[0].raw);
}

#[test]
fn long_compositions_recheck_aggregate_entry_output_expansion_depth_and_external_fanout_limits() {
    let format = GitHashAlgorithm::Sha1;
    let universe = bodies("bounded", 9);
    let sources = whole_sources(format, &universe);
    let cache = cache_for(&sources);
    let selected = keys(&sources);
    let expected = assembled(format, &sources);
    let total: usize = universe.iter().map(Vec::len).sum();
    let maximum = universe.iter().map(Vec::len).max().unwrap();
    let exact = PackLimits {
        max_entries: 9,
        max_input_bytes: expected.len(),
        max_object_bytes: maximum,
        max_total_expanded_bytes: total,
        max_delta_depth: 0,
        max_delta_fanout: 0,
        ..PackLimits::default()
    };
    assert_eq!(
        reuse(&cache, &selected, &exact)
            .unwrap()
            .into_bytes()
            .unwrap(),
        expected
    );
    for refused in [
        PackLimits {
            max_entries: 8,
            ..exact.clone()
        },
        PackLimits {
            max_input_bytes: exact.max_input_bytes - 1,
            ..exact.clone()
        },
        PackLimits {
            max_object_bytes: maximum - 1,
            ..exact.clone()
        },
        PackLimits {
            max_total_expanded_bytes: total - 1,
            ..exact
        },
    ] {
        assert!(reuse(&cache, &selected, &refused).is_none());
    }
    let deltas: Vec<_> = universe
        .iter()
        .map(|body| thin_source(format, b"root", body))
        .collect();
    let cache = cache_for(&deltas);
    let held = [(
        git_object_id(format, GitObjectKind::Blob, b"root"),
        ObjectType::Blob,
    )];
    let exact = PackLimits {
        max_entries: 9,
        max_delta_fanout: 9,
        max_delta_depth: 1,
        ..PackLimits::default()
    };
    let reused = cache
        .try_reuse_with_held(&selected, &exact, true, &held, &mut || true)
        .unwrap()
        .unwrap();
    assert_eq!(reused.receipt().source_pack_count(), 9);
    assert_eq!(reused.receipt().external_base_count(), 1);
    assert_eq!(reused.receipt().maximum_delta_depth(), 1);
    drop(reused);
    for refused in [
        PackLimits {
            max_delta_fanout: 8,
            ..exact.clone()
        },
        PackLimits {
            max_delta_depth: 0,
            ..exact
        },
    ] {
        assert!(
            cache
                .try_reuse_with_held(&selected, &refused, true, &held, &mut || true)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn sixty_fifth_receive_cannot_evict_a_pinned_full_history_and_then_obeys_fifo() {
    let format = GitHashAlgorithm::Sha1;
    let universe = bodies("fifo", 65);
    let sources = whole_sources(format, &universe);
    let cache = cache_for(&sources[..64]);
    let selected = keys(&sources[..64]);
    let pin = reuse(&cache, &selected, &PackLimits::default()).unwrap();
    retain(&cache, &sources[64]);
    assert_eq!(cache.retained_entries(), 64);
    assert!(payload(&cache, &sources[64]).is_none());
    assert_eq!(pin.into_bytes().unwrap(), assembled(format, &sources[..64]));
    retain(&cache, &sources[64]);
    assert_eq!(cache.retained_entries(), 64);
    assert!(payload(&cache, &sources[0]).is_none());
    assert!(payload(&cache, &sources[64]).is_some());
    assert!(reuse(&cache, &selected, &PackLimits::default()).is_none());
    let remaining = reuse(&cache, &keys(&sources[1..]), &PackLimits::default()).unwrap();
    assert_eq!(remaining.receipt().source_pack_count(), 64);
    assert_eq!(
        remaining.into_bytes().unwrap(),
        assembled(format, &sources[1..])
    );
}

#[test]
fn expanded_source_count_keeps_the_original_byte_budget_and_reader_charges() {
    let format = GitHashAlgorithm::Sha1;
    let sources = whole_sources(format, &bodies("bytes", 10));
    let measurement = cache_for(&sources[..9]);
    let capacity = measurement.state.lock().unwrap().resident_bytes;
    let cache = ReceivedPackCache::new(capacity);
    for source in &sources[..9] {
        retain(&cache, source);
    }
    let pin = reuse(&cache, &keys(&sources[..9]), &PackLimits::default()).unwrap();
    retain(&cache, &sources[9]);
    assert!(payload(&cache, &sources[9]).is_none());
    assert_eq!(cache.retained_entries(), 9);
    drop(pin);
    retain(&cache, &sources[9]);
    assert!(payload(&cache, &sources[0]).is_none());
    assert!(payload(&cache, &sources[9]).is_some());
    let state = cache.state.lock().unwrap();
    assert_eq!(state.entries.len(), 9);
    assert!(state.resident_bytes <= capacity);
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}

#[test]
fn every_forced_and_residual_cover_checkpoint_preserves_cancellation_and_releases_pins() {
    let format = GitHashAlgorithm::Sha1;
    let path: Vec<_> = (0..9)
        .map(|index| (1u64 << index) | (1u64 << (index + 1)))
        .collect();
    let residual = vec![16, 32, 64, 128, 1, 2, 4, 8, 3, 12, 5, 10];
    for sets in [path, residual] {
        let universe = bodies("cancel", 10);
        let sources = source_sets(format, &universe, &sets);
        let cache = cache_for(&sources);
        let selected = keys(&sources);
        let limits = PackLimits::default();
        let resident = cache.state.lock().unwrap().resident_bytes;
        let mut calls = 0;
        drop(
            cache
                .try_reuse(&selected, &limits, true, &mut || {
                    calls += 1;
                    true
                })
                .unwrap()
                .unwrap(),
        );
        for stop in 1..=calls {
            let mut at = 0;
            let result = cache.try_reuse(&selected, &limits, true, &mut || {
                at += 1;
                at < stop
            });
            assert!(
                matches!(
                    result,
                    Err(PackWriteError::Pack(PackError::DeadlineExceeded))
                ),
                "long-history checkpoint {stop} did not preserve cancellation"
            );
            let state = cache.state.lock().unwrap();
            assert_eq!(state.entries.len(), sources.len());
            assert_eq!(state.resident_bytes, resident);
            assert_eq!(state.reserved_bytes, 0);
            assert_eq!(state.reservations, 0);
            assert!(
                state
                    .entries
                    .iter()
                    .all(|entry| Arc::strong_count(entry) == 1)
            );
        }
        assert!(reuse(&cache, &selected, &limits).is_some());
    }
}
