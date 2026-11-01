//! Selected-entry reuse must preserve native objects without disclosing extras.
use super::*;
use fgit_pack::{
    ExternalBaseLookup, PackObject, ScalarResolver, decode_entry_header, read_verified_pack,
};

fn oid(format: GitHashAlgorithm, body: &[u8]) -> GitOid {
    git_object_id(format, GitObjectKind::Blob, body)
}

fn selected(format: GitHashAlgorithm, bodies: &[&[u8]]) -> Vec<PackOrderKey> {
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

fn held(format: GitHashAlgorithm, bodies: &[&[u8]]) -> Vec<(GitOid, ObjectType)> {
    selected(format, bodies)
        .into_iter()
        .map(|key| (key.id, key.object_type))
        .collect()
}

fn cache(sources: &[&Fixture]) -> ReceivedPackCache {
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
    held: &[(GitOid, ObjectType)],
    limits: &PackLimits,
) -> Option<ReceivedPackPayload> {
    cache
        .try_reuse_with_held(keys, limits, false, held, &mut || true)
        .unwrap()
}

struct Bases(BTreeMap<GitOid, Vec<u8>>);

impl ExternalBaseLookup for Bases {
    fn lookup(&self, id: &GitOid) -> Option<&[u8]> {
        self.0.get(id).map(Vec::as_slice)
    }

    fn lookup_typed(&self, id: &GitOid) -> Option<(ObjectType, &[u8])> {
        self.lookup(id).map(|body| (ObjectType::Blob, body))
    }
}

fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}

struct WireBytes {
    kind: EntryKind,
    parent: Option<GitOid>,
    raw: Vec<u8>,
    compressed: Vec<u8>,
}

struct Decoded {
    order: Vec<GitOid>,
    entries: BTreeMap<GitOid, WireBytes>,
}

pub(super) fn assert_objects(
    raw: &[u8],
    format: GitHashAlgorithm,
    expected: &[&[u8]],
    base_bodies: &[&[u8]],
) {
    decode(raw, format, expected, base_bodies);
}

/// Learn every identity from the output itself, with no cached offset hints.
/// An external oracle contains only the explicitly supplied native base bodies.
fn decode(
    raw: &[u8],
    format: GitHashAlgorithm,
    expected: &[&[u8]],
    base_bodies: &[&[u8]],
) -> Decoded {
    let limits = PackLimits::default();
    let parsed =
        read_verified_pack(raw, format, &limits, &mut || true, &NativeChecksumVerifier).unwrap();
    assert_eq!(parsed.entries().len(), expected.len());
    let mut objects = parsed.clone().into_scalar_objects(|_| None).unwrap();
    let bases = Bases(
        base_bodies
            .iter()
            .map(|body| (oid(format, body), body.to_vec()))
            .collect(),
    );
    let mut resolved = BTreeMap::new();
    for _ in 0..objects.len() {
        let resolver = ScalarResolver::new(&objects, &bases, &limits, &mut || true).unwrap();
        let mut learned = Vec::new();
        for object in &objects {
            let at = offset(object);
            if resolved.contains_key(&at) {
                continue;
            }
            match resolver.resolve_offset_typed(at, &mut || true) {
                Ok((kind, body)) => {
                    assert_eq!(kind, ObjectType::Blob);
                    learned.push((at, oid(format, &body), body));
                }
                Err(PackError::MissingDeltaBase) => {}
                Err(error) => panic!("selected output failed native reconstruction: {error:?}"),
            }
        }
        assert!(
            !learned.is_empty(),
            "selected output has no valid dependency root"
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
    for (id, body) in resolved.values() {
        assert!(
            actual.insert(*id, body.clone()).is_none(),
            "duplicate output identity"
        );
    }
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|body| (oid(format, body), body.to_vec()))
        .collect();
    assert_eq!(
        actual, expected,
        "output must contain precisely the authorized objects"
    );
    let mut order = Vec::new();
    let mut entries = BTreeMap::new();
    for (index, entry) in parsed.entries().iter().enumerate() {
        let start = usize::try_from(entry.offset).unwrap();
        let end = parsed
            .entries()
            .get(index + 1)
            .map_or(raw.len() - format.digest_len(), |entry| {
                usize::try_from(entry.offset).unwrap()
            });
        let (_, prefix) = decode_entry_header(&raw[start..end], &limits, &mut || true).unwrap();
        let (parent, base_prefix) = match &entry.delta_base {
            None => (None, 0),
            Some(ParsedDeltaBase::Ref { base, consumed }) => (Some(*base), *consumed),
            Some(ParsedDeltaBase::Ofs {
                base_offset,
                consumed,
            }) => (Some(resolved[base_offset].0), *consumed),
        };
        let id = resolved[&entry.offset].0;
        order.push(id);
        assert!(
            entries
                .insert(
                    id,
                    WireBytes {
                        kind: entry.header.kind,
                        parent,
                        raw: raw[start..end].to_vec(),
                        compressed: raw[start + prefix + base_prefix..end].to_vec(),
                    }
                )
                .is_none()
        );
    }
    Decoded { order, entries }
}

fn original_entry(source: &Fixture, id: GitOid) -> (&[u8], &[u8]) {
    let index = source
        .pack
        .entries()
        .iter()
        .position(|entry| source.offsets[&entry.offset] == id)
        .unwrap();
    let entry = &source.pack.entries()[index];
    let start = usize::try_from(entry.offset).unwrap();
    let end = source.pack.entries().get(index + 1).map_or(
        source.raw.len() - source.pack.format.digest_len(),
        |entry| usize::try_from(entry.offset).unwrap(),
    );
    let (_, prefix) =
        decode_entry_header(&source.raw[start..end], &PackLimits::default(), &mut || {
            true
        })
        .unwrap();
    let base_prefix = match &entry.delta_base {
        None => 0,
        Some(ParsedDeltaBase::Ofs { consumed, .. } | ParsedDeltaBase::Ref { consumed, .. }) => {
            *consumed
        }
    };
    (
        &source.raw[start..end],
        &source.raw[start + prefix + base_prefix..end],
    )
}

fn with_extra(format: GitHashAlgorithm, body: &[u8], extra: &[u8]) -> Fixture {
    fixture(
        format,
        &[Input::Whole(body.to_vec()), Input::Whole(extra.to_vec())],
    )
}

fn ref_with_extra(format: GitHashAlgorithm, base: &[u8], body: &[u8], extra: &[u8]) -> Fixture {
    fixture(
        format,
        &[
            Input::Ref(
                oid(format, base),
                literal_delta(base.len(), body),
                body.to_vec(),
            ),
            Input::Whole(extra.to_vec()),
        ],
    )
}

#[test]
fn whole_subsets_preserve_each_selected_entry_and_do_not_disclose_extras() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(
            format,
            &[
                Input::Whole(b"public-a".to_vec()),
                Input::Whole(b"private-unselected".to_vec()),
                Input::Whole(b"public-b".to_vec()),
            ],
        );
        let cache = cache(&[&source]);
        assert_eq!(
            payload(&cache, &source).unwrap().into_bytes().unwrap(),
            source.raw
        );
        let keys = selected(format, &[b"public-a", b"public-b"]);
        let result = reuse(&cache, &keys, &[], &PackLimits::default()).unwrap();
        let receipt = result.receipt().clone();
        assert_eq!(receipt.profile(), "received-pack-select-v1");
        assert_eq!(receipt.object_count(), 2);
        assert_eq!(receipt.source_pack_count(), 1);
        assert_eq!(receipt.total_object_bytes(), 16);
        assert_eq!(receipt.maximum_delta_depth(), 0);
        assert_eq!(receipt.external_base_count(), 0);
        let raw = result.into_bytes().unwrap();
        assert_eq!(receipt.output_bytes(), raw.len());
        assert_eq!(receipt.sha256(), &sha256_digest(&raw));
        let decoded = decode(&raw, format, &[b"public-a", b"public-b"], &[]);
        assert_eq!(
            decoded.order,
            [oid(format, b"public-a"), oid(format, b"public-b")]
        );
        for key in &keys {
            assert_eq!(
                decoded.entries[&key.id].raw,
                original_entry(&source, key.id).0
            );
        }
        let mut hints = keys.clone();
        for key in &mut hints {
            key.recency = 99;
            key.path_hash = 42;
        }
        assert_eq!(
            reuse(&cache, &hints, &[], &PackLimits::default())
                .unwrap()
                .into_bytes()
                .unwrap(),
            raw
        );
        assert_eq!(
            payload(&cache, &source).unwrap().receipt().profile(),
            "received-pack-v1"
        );
        assert_eq!(
            payload(&cache, &source).unwrap().into_bytes().unwrap(),
            source.raw
        );
    }
}

#[test]
fn removing_gaps_rewrites_ofs_to_ref_without_touching_compressed_programs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(
            format,
            &[
                Input::Whole(b"base".to_vec()),
                Input::Whole(vec![b'h'; 300]),
                Input::Ofs(0, literal_delta(4, b"middle"), b"middle".to_vec()),
                Input::Whole(b"another omitted entry".to_vec()),
                Input::Ref(
                    oid(format, b"middle"),
                    literal_delta(6, b"last"),
                    b"last".to_vec(),
                ),
            ],
        );
        let cache = cache(&[&source]);
        let keys = selected(format, &[b"base", b"middle", b"last"]);
        let result = reuse(&cache, &keys, &[], &PackLimits::default()).unwrap();
        assert_eq!(result.receipt().profile(), "received-pack-select-v1");
        assert_eq!(result.receipt().ofs_delta_count(), 0);
        assert_eq!(result.receipt().ref_delta_count(), 2);
        assert_eq!(result.receipt().maximum_delta_depth(), 2);
        let decoded = decode(
            &result.into_bytes().unwrap(),
            format,
            &[b"base", b"middle", b"last"],
            &[],
        );
        assert_eq!(
            decoded.order,
            [
                oid(format, b"base"),
                oid(format, b"middle"),
                oid(format, b"last")
            ]
        );
        for body in [b"base".as_slice(), b"middle", b"last"] {
            let id = oid(format, body);
            let original = original_entry(&source, id);
            assert_eq!(decoded.entries[&id].compressed, original.1);
            if body != b"middle" {
                assert_eq!(decoded.entries[&id].raw, original.0);
            }
        }
        assert_eq!(
            decoded.entries[&oid(format, b"middle")].kind,
            EntryKind::RefDelta
        );
        assert_eq!(
            decoded.entries[&oid(format, b"middle")].parent,
            Some(oid(format, b"base"))
        );
        assert_eq!(
            decoded.entries[&oid(format, b"last")].parent,
            Some(oid(format, b"middle"))
        );
    }
}

#[test]
fn overlapping_sources_emit_each_native_identity_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let left = fixture(
            format,
            &[Input::Whole(b"a".to_vec()), Input::Whole(b"b".to_vec())],
        );
        let right = fixture(
            format,
            &[Input::Whole(b"b".to_vec()), Input::Whole(b"c".to_vec())],
        );
        let cache = cache(&[&left, &right]);
        let result = reuse(
            &cache,
            &selected(format, &[b"a", b"b", b"c"]),
            &[],
            &PackLimits::default(),
        )
        .unwrap();
        assert_eq!(result.receipt().profile(), "received-pack-select-v1");
        assert_eq!(result.receipt().source_pack_count(), 2);
        assert_eq!(result.receipt().object_count(), 3);
        decode(
            &result.into_bytes().unwrap(),
            format,
            &[b"a", b"b", b"c"],
            &[],
        );
    }
}

#[test]
fn omitted_local_delta_roots_require_current_typed_held_proof() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(
            format,
            &[
                Input::Whole(b"base".to_vec()),
                Input::Whole(b"unselected private".to_vec()),
                Input::Ofs(0, literal_delta(4, b"result"), b"result".to_vec()),
            ],
        );
        let cache = cache(&[&source]);
        let keys = selected(format, &[b"result"]);
        let limits = PackLimits::default();
        assert!(reuse(&cache, &keys, &[], &limits).is_none());
        assert!(reuse(&cache, &keys, &held(format, &[b"unrelated"]), &limits).is_none());
        assert!(
            reuse(
                &cache,
                &keys,
                &[(oid(format, b"base"), ObjectType::Tree)],
                &limits
            )
            .is_none()
        );
        let proof = held(format, &[b"base"]);
        let result = reuse(&cache, &keys, &proof, &limits).unwrap();
        assert_eq!(result.receipt().profile(), "received-pack-select-thin-v1");
        assert_eq!(result.receipt().external_base_count(), 1);
        assert_eq!(result.receipt().maximum_delta_depth(), 1);
        assert_eq!(result.receipt().object_count(), 1);
        assert_eq!(result.receipt().ofs_delta_count(), 0);
        assert_eq!(result.receipt().ref_delta_count(), 1);
        let raw = result.into_bytes().unwrap();
        let decoded = decode(&raw, format, &[b"result"], &[b"base"]);
        assert_eq!(
            decoded.entries[&oid(format, b"result")].compressed,
            original_entry(&source, oid(format, b"result")).1
        );
        let objects =
            read_verified_pack(&raw, format, &limits, &mut || true, &NativeChecksumVerifier)
                .unwrap()
                .into_scalar_objects(|_| None)
                .unwrap();
        let resolver = ScalarResolver::new(&objects, &(), &limits, &mut || true).unwrap();
        assert_eq!(
            resolver.resolve_offset_typed(offset(&objects[0]), &mut || true),
            Err(PackError::MissingDeltaBase)
        );
    }
}

#[test]
fn selected_parents_cannot_be_replaced_by_held_hints_or_cyclic_variants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        // Each source alone has an external root; the combined selected cycle
        // has none. These private fixtures do not grant public receive proof.
        let a = ref_with_extra(format, b"b", b"a", b"extra-a");
        let b = ref_with_extra(format, b"a", b"b", b"extra-b");
        let cache = cache(&[&a, &b]);
        let keys = selected(format, &[b"a", b"b"]);
        let proof = held(format, &[b"a", b"b"]);
        assert!(reuse(&cache, &keys, &proof, &PackLimits::default()).is_none());
        retain(&cache, &with_extra(format, b"a", b"root-extra"));
        let result = reuse(&cache, &keys, &proof, &PackLimits::default()).unwrap();
        assert_eq!(result.receipt().external_base_count(), 0);
        assert_eq!(result.receipt().maximum_delta_depth(), 1);
        decode(&result.into_bytes().unwrap(), format, &[b"a", b"b"], &[]);
        let mut wrong = keys;
        wrong
            .iter_mut()
            .find(|key| key.id == oid(format, b"a"))
            .unwrap()
            .object_type = ObjectType::Tree;
        assert!(reuse(&cache, &wrong, &proof, &PackLimits::default()).is_none());
    }
}

#[test]
fn roots_precede_delta_variants_and_equal_depth_uses_fifo_sources() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let early = fixture(
            format,
            &[
                Input::Whole(b"root".to_vec()),
                Input::Ref(
                    oid(format, b"root"),
                    literal_delta(4, b"target"),
                    b"target".to_vec(),
                ),
                Input::Whole(b"extra-early".to_vec()),
            ],
        );
        let later_root = with_extra(format, b"target", b"extra-later");
        let rooted = cache(&[&early, &later_root]);
        let result = reuse(
            &rooted,
            &selected(format, &[b"root", b"target"]),
            &[],
            &PackLimits::default(),
        )
        .unwrap();
        assert_eq!(result.receipt().maximum_delta_depth(), 0);
        assert_eq!(result.receipt().ref_delta_count(), 0);
        let decoded = decode(
            &result.into_bytes().unwrap(),
            format,
            &[b"root", b"target"],
            &[],
        );
        assert_eq!(
            decoded.entries[&oid(format, b"target")].kind,
            EntryKind::Blob
        );

        let root_a = with_extra(format, b"root-a", b"private-a");
        let root_b = with_extra(format, b"root-b", b"private-b");
        let from_a = ref_with_extra(format, b"root-a", b"target", b"private-c");
        let from_b = ref_with_extra(format, b"root-b", b"target", b"private-d");
        for (first, second, parent) in [
            (&from_a, &from_b, b"root-a".as_slice()),
            (&from_b, &from_a, b"root-b".as_slice()),
        ] {
            let cache = cache(&[&root_a, &root_b, first, second]);
            let result = reuse(
                &cache,
                &selected(format, &[b"root-a", b"root-b", b"target"]),
                &[],
                &PackLimits::default(),
            )
            .unwrap();
            assert_eq!(result.receipt().source_pack_count(), 3);
            let decoded = decode(
                &result.into_bytes().unwrap(),
                format,
                &[b"root-a", b"root-b", b"target"],
                &[],
            );
            assert_eq!(
                decoded.entries[&oid(format, b"target")].parent,
                Some(oid(format, parent))
            );
        }
    }
}

#[test]
fn selected_limits_ignore_omitted_objects_but_bound_every_emitted_byte() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = vec![b'x'; 64];
        let source = fixture(
            format,
            &[
                Input::Whole(vec![b'h'; 4096]),
                Input::Whole(base.clone()),
                Input::Ofs(1, literal_delta(64, b"four"), b"four".to_vec()),
                Input::Ofs(
                    1,
                    literal_delta(64, b"omitted child"),
                    b"omitted child".to_vec(),
                ),
            ],
        );
        let cache = cache(&[&source]);
        let keys = selected(format, &[b"four"]);
        let proof = held(format, &[&base]);
        // Independent one-entry wire construction supplies the exact output
        // size, including the larger REF header replacing the OFS prefix.
        let reference = fixture(
            format,
            &[Input::Ref(
                oid(format, &base),
                literal_delta(64, b"four"),
                b"four".to_vec(),
            )],
        );
        let exact = PackLimits {
            max_entries: 1,
            max_input_bytes: reference.raw.len(),
            max_object_bytes: 7,
            max_total_expanded_bytes: 7,
            max_delta_depth: 1,
            max_delta_fanout: 1,
            ..PackLimits::default()
        };
        let result = reuse(&cache, &keys, &proof, &exact).unwrap();
        assert_eq!(result.receipt().total_object_bytes(), 4);
        assert_eq!(result.into_bytes().unwrap(), reference.raw);
        for refused in [
            PackLimits {
                max_entries: 0,
                ..exact.clone()
            },
            PackLimits {
                max_input_bytes: reference.raw.len() - 1,
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
                ..exact.clone()
            },
        ] {
            assert!(
                reuse(&cache, &keys, &proof, &refused).is_none(),
                "limit: {refused:?}"
            );
        }
        decode(&reference.raw, format, &[b"four"], &[&base]);
    }
}

#[test]
fn compact_delta_programs_still_charge_reconstructed_native_body_sizes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = vec![b'x'; 64];
        let mut result = base.clone();
        result[0] = b'y';
        // Insert y, then copy 63 bytes from base offset 1: seven instructions
        // reconstruct 64 bytes. The oracle resolves the actual copy program.
        let program = vec![64, 64, 1, b'y', 0x91, 1, 63];
        let source = fixture(
            format,
            &[
                Input::Whole(vec![b'h'; 4096]),
                Input::Whole(base.clone()),
                Input::Ofs(1, program, result.clone()),
            ],
        );
        let cache = cache(&[&source]);
        let keys = selected(format, &[&result]);
        let proof = held(format, &[&base]);
        let exact = PackLimits {
            max_object_bytes: 64,
            max_total_expanded_bytes: 64,
            ..PackLimits::default()
        };
        let reused = reuse(&cache, &keys, &proof, &exact).unwrap();
        assert_eq!(reused.receipt().total_object_bytes(), 64);
        decode(&reused.into_bytes().unwrap(), format, &[&result], &[&base]);
        for limited in [
            PackLimits {
                max_object_bytes: 63,
                ..exact.clone()
            },
            PackLimits {
                max_total_expanded_bytes: 63,
                ..exact
            },
        ] {
            assert!(reuse(&cache, &keys, &proof, &limited).is_none());
        }
    }
}

#[test]
fn global_depth_and_fanout_remain_bounds_after_entry_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(
            format,
            &[
                Input::Whole(b"root".to_vec()),
                Input::Whole(b"omitted".to_vec()),
                Input::Ofs(0, literal_delta(4, b"middle"), b"middle".to_vec()),
                Input::Ofs(2, literal_delta(6, b"last"), b"last".to_vec()),
                Input::Ofs(0, literal_delta(4, b"sibling"), b"sibling".to_vec()),
            ],
        );
        let cache = cache(&[&source]);
        let keys = selected(format, &[b"middle", b"last", b"sibling"]);
        let proof = held(format, &[b"root"]);
        let exact = PackLimits {
            max_delta_depth: 2,
            max_delta_fanout: 2,
            ..PackLimits::default()
        };
        let reused = reuse(&cache, &keys, &proof, &exact).unwrap();
        assert_eq!(reused.receipt().maximum_delta_depth(), 2);
        assert_eq!(reused.receipt().external_base_count(), 1);
        decode(
            &reused.into_bytes().unwrap(),
            format,
            &[b"middle", b"last", b"sibling"],
            &[b"root"],
        );
        for limited in [
            PackLimits {
                max_delta_depth: 1,
                ..exact.clone()
            },
            PackLimits {
                max_delta_fanout: 1,
                ..exact
            },
        ] {
            assert!(reuse(&cache, &keys, &proof, &limited).is_none());
        }
    }
}

#[test]
fn unknown_selected_objects_and_invalid_keys_never_become_partial_successes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = with_extra(format, b"known", b"private");
        let cache = cache(&[&source]);
        let limits = PackLimits::default();
        assert!(
            reuse(
                &cache,
                &selected(format, &[b"known", b"unknown"]),
                &held(format, &[b"unknown"]),
                &limits
            )
            .is_none()
        );
        let valid = selected(format, &[b"known"]);
        let mut wrong_kind = valid.clone();
        wrong_kind[0].object_type = ObjectType::Tree;
        let repeated = vec![valid[0], valid[0]];
        let other_format = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        for keys in [
            Vec::new(),
            wrong_kind,
            repeated,
            selected(other_format, &[b"known"]),
        ] {
            assert!(reuse(&cache, &keys, &[], &limits).is_none());
        }
        let raw = reuse(&cache, &valid, &[], &limits)
            .unwrap()
            .into_bytes()
            .unwrap();
        decode(&raw, format, &[b"known"], &[]);
    }
}

#[test]
fn unselected_external_dependencies_do_not_require_client_bases() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = ref_with_extra(format, b"unheld-base", b"unselected-delta", b"public");
        let cache = cache(&[&source]);
        let keys = selected(format, &[b"public"]);
        let result = reuse(&cache, &keys, &[], &PackLimits::default()).unwrap();
        assert_eq!(result.receipt().external_base_count(), 0);
        assert_eq!(result.receipt().ref_delta_count(), 0);
        decode(&result.into_bytes().unwrap(), format, &[b"public"], &[]);
        assert!(reuse(&cache, &source.keys, &[], &PackLimits::default()).is_none());
    }
}

#[test]
fn held_candidate_scans_are_narrowed_to_selected_typed_targets() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = fixture(
            format,
            &[
                Input::Whole(b"local".to_vec()),
                Input::Ofs(0, literal_delta(5, b"child"), b"child".to_vec()),
                Input::Ref(
                    oid(format, b"remote"),
                    literal_delta(6, b"other"),
                    b"other".to_vec(),
                ),
                Input::Whole(b"unrelated".to_vec()),
            ],
        );
        let cache = cache(&[&source]);
        let bases: BTreeSet<_> = held(format, &[b"local", b"remote", b"unrelated"])
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let child = selected(format, &[b"child"]);
        assert_eq!(
            cache
                .held_base_candidates(&child, &bases, &mut || true)
                .unwrap(),
            [oid(format, b"local")]
        );
        assert_eq!(
            cache
                .held_base_candidates(&selected(format, &[b"other"]), &bases, &mut || true)
                .unwrap(),
            [oid(format, b"remote")]
        );
        for keys in [
            selected(format, &[b"unrelated"]),
            selected(format, &[b"local", b"child"]),
            Vec::new(),
        ] {
            assert!(
                cache
                    .held_base_candidates(&keys, &bases, &mut || true)
                    .unwrap()
                    .is_empty()
            );
        }
        let mut wrong_kind = child.clone();
        wrong_kind[0].object_type = ObjectType::Tree;
        assert!(
            cache
                .held_base_candidates(&wrong_kind, &bases, &mut || true)
                .unwrap()
                .is_empty()
        );
        // The same answer is required when the source-side scan is cheaper.
        let mut wide = child;
        wide.extend((0..12).flat_map(|i| selected(format, &[format!("uncached-{i}").as_bytes()])));
        wide.sort_by_key(|key| key.id);
        assert_eq!(
            cache
                .held_base_candidates(&wide, &bases, &mut || true)
                .unwrap(),
            [oid(format, b"local")]
        );
    }
}

#[test]
fn corrupted_omitted_bytes_reject_the_source_and_allow_a_later_verified_variant() {
    struct Permit;
    impl PackTrailerVerifier for Permit {
        fn verify(&self, _: &[u8], _: &[u8], _: GitHashAlgorithm) -> bool {
            true
        }
    }
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = with_extra(format, b"public", b"private-a");
        let changed = with_extra(format, b"public", b"private-b");
        assert_eq!(original.raw.len(), changed.raw.len());
        let cache = cache(&[&original]);
        let keys = selected(format, &[b"public"]);
        let mut raw = changed.raw.clone();
        let trailer = raw.len() - format.digest_len();
        raw[trailer..].copy_from_slice(&original.raw[trailer..]);
        let altered = read_verified_pack_owned(
            raw,
            format,
            &PackLimits::default(),
            &mut || true,
            &Permit,
            MAX_CAPTURE_BYTES,
        )
        .unwrap();
        {
            let mut state = cache.state.lock().unwrap();
            Arc::get_mut(&mut state.entries[0]).unwrap().bytes =
                altered.retained_bytes().unwrap().clone();
        }
        assert!(reuse(&cache, &keys, &[], &PackLimits::default()).is_none());
        retain(&cache, &changed);
        let result = reuse(&cache, &keys, &[], &PackLimits::default()).unwrap();
        assert_eq!(result.receipt().source_pack_count(), 1);
        decode(&result.into_bytes().unwrap(), format, &[b"public"], &[]);
    }
}

#[test]
fn entry_spans_and_omitted_metadata_are_bound_to_verified_source_custody() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source = with_extra(format, b"public", b"private");
        let keys = selected(format, &[b"public"]);
        for damage in 0..9 {
            let cache = cache(&[&source]);
            assert!(reuse(&cache, &keys, &[], &PackLimits::default()).is_some());
            {
                let mut state = cache.state.lock().unwrap();
                let entry = Arc::get_mut(&mut state.entries[0]).unwrap();
                let index = entry
                    .objects
                    .iter()
                    .position(|object| object.id == oid(format, b"private"))
                    .unwrap();
                match damage {
                    0 => entry.wire[index].start += 1,
                    1 => entry.wire[index].header_end += 1,
                    2 => entry.wire[index].payload += 1,
                    3 => entry.wire[index].end -= 1,
                    4 => entry.wire[index].declared_size += 1,
                    5 => entry.wire[index].kind = EntryKind::Tag,
                    6 => entry.wire.swap(0, 1),
                    7 => entry.objects[index].bytes += 1,
                    _ => entry.parents[index] = Some(oid(format, b"public")),
                }
            }
            assert!(
                reuse(&cache, &keys, &[], &PackLimits::default()).is_none(),
                "metadata corruption {damage}"
            );
        }
    }
}

#[test]
fn greedy_fanout_exhaustion_is_a_safe_miss_with_a_permitted_neighbor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut candidates: Vec<_> = (0..16)
            .map(|i| format!("target-{i:02}").into_bytes())
            .collect();
        candidates.sort_by_key(|body| oid(format, body));
        let first = &candidates[0];
        let second = &candidates[15];
        let root_a = with_extra(format, b"root-a", b"extra-a");
        let root_b = with_extra(format, b"root-b", b"extra-b");
        let first_a = ref_with_extra(format, b"root-a", first, b"extra-c");
        let first_b = ref_with_extra(format, b"root-b", first, b"extra-d");
        let second_a = ref_with_extra(format, b"root-a", second, b"extra-e");
        let keys = selected(format, &[b"root-a", b"root-b", first, second]);
        let tight = PackLimits {
            max_delta_fanout: 1,
            ..PackLimits::default()
        };
        let greedy = cache(&[&root_a, &root_b, &first_a, &first_b, &second_a]);
        assert!(reuse(&greedy, &keys, &[], &tight).is_none());
        let broad = reuse(&greedy, &keys, &[], &PackLimits::default()).unwrap();
        decode(
            &broad.into_bytes().unwrap(),
            format,
            &[b"root-a", b"root-b", first, second],
            &[],
        );
        let reordered = cache(&[&root_a, &root_b, &first_b, &first_a, &second_a]);
        let permitted = reuse(&reordered, &keys, &[], &tight).unwrap();
        let decoded = decode(
            &permitted.into_bytes().unwrap(),
            format,
            &[b"root-a", b"root-b", first, second],
            &[],
        );
        assert_eq!(
            decoded.entries[&oid(format, first)].parent,
            Some(oid(format, b"root-b"))
        );
        assert_eq!(
            decoded.entries[&oid(format, second)].parent,
            Some(oid(format, b"root-a"))
        );
    }
}

#[test]
fn selected_readers_pin_every_source_and_stream_independent_small_chunks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let first = with_extra(format, b"base", b"extra-first");
        let second = ref_with_extra(format, b"base", b"result", b"extra-second");
        let measurement = cache(&[&first, &second]);
        let capacity = measurement.state.lock().unwrap().resident_bytes;
        let cache = ReceivedPackCache::new(capacity);
        retain(&cache, &first);
        retain(&cache, &second);
        let keys = selected(format, &[b"base", b"result"]);
        let mut one = reuse(&cache, &keys, &[], &PackLimits::default()).unwrap();
        let two = reuse(&cache, &keys, &[], &PackLimits::default()).unwrap();
        let expected = two.into_bytes().unwrap();
        let mut three = reuse(&cache, &keys, &[], &PackLimits::default()).unwrap();
        assert_eq!(one.next_chunk(1).unwrap().unwrap(), expected[..1]);
        assert_eq!(three.next_chunk(7).unwrap().unwrap(), expected[..7]);
        let replacement = with_extra(format, b"replacement", b"new-private");
        retain(&cache, &replacement);
        assert_eq!(cache.retained_entries(), 2);
        let mut collected = expected[..1].to_vec();
        while let Some(chunk) = one.next_chunk(1).unwrap() {
            collected.extend(chunk);
        }
        assert_eq!(collected, expected);
        assert!(one.next_chunk(1).unwrap().is_none());
        assert!(one.next_chunk(0).is_err());
        drop(one);
        assert!(
            cache
                .state
                .lock()
                .unwrap()
                .entries
                .iter()
                .all(|entry| Arc::strong_count(entry) >= 2)
        );
        drop(three);
        retain(&cache, &replacement);
        assert!(reuse(&cache, &keys, &[], &PackLimits::default()).is_none());
        let state = cache.state.lock().unwrap();
        assert!(state.resident_bytes <= capacity);
        assert_eq!(state.reserved_bytes, 0);
        assert_eq!(state.reservations, 0);
        decode(&expected, format, &[b"base", b"result"], &[]);
    }
}

#[test]
fn every_selected_reuse_checkpoint_cancels_and_releases_all_source_pins() {
    for external in [false, true] {
        let format = GitHashAlgorithm::Sha256;
        let first = with_extra(format, b"base", b"extra-first");
        let second = ref_with_extra(format, b"base", b"middle", b"extra-second");
        let third = ref_with_extra(format, b"middle", b"last", b"extra-third");
        let cache = cache(&[&first, &second, &third]);
        let keys = if external {
            selected(format, &[b"middle", b"last"])
        } else {
            selected(format, &[b"base", b"middle", b"last"])
        };
        let proof = if external {
            held(format, &[b"base"])
        } else {
            Vec::new()
        };
        let limits = PackLimits::default();
        let resident = cache.state.lock().unwrap().resident_bytes;
        let mut calls = 0;
        let result = cache
            .try_reuse_with_held(&keys, &limits, false, &proof, &mut || {
                calls += 1;
                true
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            result.receipt().profile(),
            if external {
                "received-pack-select-thin-v1"
            } else {
                "received-pack-select-v1"
            }
        );
        drop(result);
        for stop in 1..=calls {
            let mut at = 0;
            let result = cache.try_reuse_with_held(&keys, &limits, false, &proof, &mut || {
                at += 1;
                at < stop
            });
            assert!(
                matches!(
                    result,
                    Err(PackWriteError::Pack(PackError::DeadlineExceeded))
                ),
                "selective checkpoint {stop}, external={external}"
            );
            let state = cache.state.lock().unwrap();
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
        assert!(reuse(&cache, &keys, &proof, &limits).is_some());
    }
}
