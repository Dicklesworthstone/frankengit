//! Recent-result retention changes avoided work, never the native answer or
//! the caller's resource envelope. The scalar resolver remains the oracle.

use super::*;
use crate::ObjectFormat;
use fgit_crypto::git_object_id;
use std::collections::BTreeSet;

#[derive(Default)]
struct NoSpill {
    calls: usize,
}

impl CacheSpill for NoSpill {
    fn spill(&mut self, bytes: &[u8]) -> Result<SpillHandle, PackError> {
        self.calls += 1;
        Err(PackError::AllocationFailed {
            requested: bytes.len(),
        })
    }

    fn read(&mut self, handle: SpillHandle) -> Result<Vec<u8>, PackError> {
        self.calls += 1;
        Err(PackError::AllocationFailed {
            requested: handle.length,
        })
    }
}

fn varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn append_program(length: usize, byte: u8) -> Vec<u8> {
    let mut program = Vec::new();
    varint(length, &mut program);
    varint(length + 1, &mut program);
    let mut instruction = 0x80;
    let mut sizes = Vec::new();
    for (flag, shift) in [(0x10, 0), (0x20, 8), (0x40, 16)] {
        let part = u8::try_from((length >> shift) & 0xff).unwrap();
        if part != 0 {
            instruction |= flag;
            sizes.push(part);
        }
    }
    program.push(instruction);
    program.extend(sizes);
    program.extend([1, byte]);
    program
}

fn history(
    format: ObjectFormat,
    base_length: usize,
    depth: usize,
    mixed_references: bool,
) -> (Vec<PackObject>, Vec<Vec<u8>>) {
    let mut bodies: Vec<Vec<u8>> = vec![(0..base_length).map(|at| b"history!"[at % 8]).collect()];
    let mut objects = vec![PackObject::TypedBase {
        offset: 12,
        id: Some(git_object_id(format, ObjectType::Blob, &bodies[0])),
        kind: EntryKind::Blob,
        data: bodies[0].clone(),
    }];
    for step in 1..=depth {
        let previous = bodies.last().unwrap();
        let byte = u8::try_from(step % 251).unwrap();
        let mut next = previous.clone();
        next.push(byte);
        let base = if mixed_references && step % 2 == 0 {
            DeltaBase::Ref(git_object_id(format, ObjectType::Blob, previous))
        } else {
            DeltaBase::Ofs(objects.last().unwrap().offset())
        };
        objects.push(PackObject::Delta(DeltaObject {
            offset: 12 + 100 * u64::try_from(step).unwrap(),
            id: Some(git_object_id(format, ObjectType::Blob, &next)),
            base,
            program: append_program(previous.len(), byte),
        }));
        bodies.push(next);
    }
    (objects, bodies)
}

fn assert_resident_bound<L: ExternalBaseLookup, S: CacheSpill>(
    resolver: &CachedResolver<'_, '_, L, S>,
    maximum_entries: usize,
) {
    assert!(resolver.cached_bytes <= resolver.resident_budget);
    assert_eq!(resolver.cached_bytes, resolver.resident_bytes);
    assert!(resolver.entries.len() <= maximum_entries);
    let mut sum = 0;
    for entry in resolver.entries.values() {
        let StoredBytes::Resident(bytes) = &entry.stored else {
            panic!("recent-result retention must never spill");
        };
        sum += bytes.len();
    }
    assert_eq!(resolver.cached_bytes, sum);
    let recency = resolver.recency.as_ref().unwrap();
    let mut next = recency.oldest;
    let mut previous = None;
    let mut visited = BTreeSet::new();
    while let Some(offset) = next {
        assert!(visited.insert(offset), "recency links must not cycle");
        let entry = resolver.entries.get(&offset).unwrap();
        assert_eq!(entry.older, previous);
        previous = Some(offset);
        next = entry.newer;
    }
    assert_eq!(previous, recency.newest);
    assert_eq!(visited.len(), resolver.entries.len());
}

#[test]
fn long_histories_fit_the_same_work_envelope_after_early_results_are_replaced() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        for mixed in [false, true] {
            let (objects, bodies) = history(format, 1024, 48, mixed);
            let unique: usize = bodies.iter().map(Vec::len).sum();
            for expansion_is_tight in [false, true] {
                let limits = PackLimits {
                    max_entries: u32::try_from(objects.len()).unwrap(),
                    max_object_bytes: bodies.last().unwrap().len(),
                    max_delta_depth: 48,
                    max_total_expanded_bytes: if expansion_is_tight {
                        unique
                    } else {
                        unique * objects.len()
                    },
                    max_delta_work: unique * 3,
                    max_cached_bytes: 2 * bodies.last().unwrap().len(),
                    ..PackLimits::default()
                };
                let mut first = CachedResolver::new(&objects, &(), &limits, &mut || true).unwrap();
                let mut first_budget = ResolutionBudget::new();
                let old = objects.iter().try_for_each(|object| {
                    first
                        .resolve_offset_typed_with_budget(
                            object.offset(),
                            &mut first_budget,
                            &mut || true,
                        )
                        .map(|_| ())
                });
                assert!(
                    matches!(
                        old,
                        Err(PackError::TotalExpandedLimit { .. } | PackError::DeltaWorkLimit { .. })
                    ),
                    "permanent early results repeat the later chains: {old:?}"
                );

                let scalar = ScalarResolver::new(&objects, &(), &limits, &mut || true).unwrap();
                let mut spill = NoSpill::default();
                let mut recent = CachedResolver::with_resident_recency(
                    &objects,
                    &(),
                    &limits,
                    &mut spill,
                    limits.max_cached_bytes,
                    &mut || true,
                )
                .unwrap();
                let mut budget = ResolutionBudget::new();
                for (object, body) in objects.iter().zip(&bodies) {
                    let resolved = recent
                        .resolve_offset_typed_with_budget(object.offset(), &mut budget, &mut || {
                            true
                        })
                        .unwrap();
                    assert_eq!(resolved, (ObjectType::Blob, body.clone()));
                    assert_eq!(
                        resolved,
                        scalar
                            .resolve_offset_typed(object.offset(), &mut || true)
                            .unwrap()
                    );
                    assert_eq!(
                        git_object_id(format, resolved.0, &resolved.1),
                        *object.id().unwrap()
                    );
                    assert_resident_bound(&recent, objects.len());
                }
                assert_eq!(budget.accounting.expanded, unique);
                assert!(budget.accounting.work < unique * 3);
                assert!(!recent.entries.contains_key(&objects[0].offset()));
                assert!(
                    recent
                        .entries
                        .contains_key(&objects.last().unwrap().offset())
                );
                drop(recent);
                assert_eq!(spill.calls, 0);
            }
        }
    }
}

fn independent_bases(length: usize, count: usize) -> Vec<PackObject> {
    (0..count)
        .map(|index| PackObject::TypedBase {
            offset: 12 + u64::try_from(index).unwrap() * 12,
            id: None,
            kind: EntryKind::Blob,
            data: vec![u8::try_from(index).unwrap(); length],
        })
        .collect()
}

#[test]
fn hits_refresh_recency_without_changing_default_retention() {
    let objects = independent_bases(4, 3);
    let limits = PackLimits {
        max_cached_bytes: 8,
        ..PackLimits::default()
    };
    let mut original = CachedResolver::new(&objects, &(), &limits, &mut || true).unwrap();
    let mut recent = CachedResolver::with_resident_recency(
        &objects,
        &(),
        &limits,
        ResidentCache,
        usize::MAX,
        &mut || true,
    )
    .unwrap();
    for index in [0, 1, 0, 2] {
        let at = objects[index].offset();
        assert_eq!(
            recent.resolve_offset_typed(at, &mut || true),
            original.resolve_offset_typed(at, &mut || true)
        );
        assert_resident_bound(&recent, objects.len());
    }
    assert!(original.entries.contains_key(&objects[1].offset()));
    assert!(!original.entries.contains_key(&objects[2].offset()));
    assert!(recent.entries.contains_key(&objects[0].offset()));
    assert!(!recent.entries.contains_key(&objects[1].offset()));
    assert!(recent.entries.contains_key(&objects[2].offset()));
}

#[test]
fn evicted_results_are_recharged_and_refusals_do_not_reset_the_shared_budget() {
    let objects = independent_bases(4, 3);
    let limits = PackLimits {
        max_cached_bytes: 8,
        max_total_expanded_bytes: 16,
        ..PackLimits::default()
    };
    let mut recent = CachedResolver::with_resident_recency(
        &objects,
        &(),
        &limits,
        ResidentCache,
        8,
        &mut || true,
    )
    .unwrap();
    let mut budget = ResolutionBudget::new();
    for index in [0, 1, 2, 0] {
        recent
            .resolve_offset_typed_with_budget(objects[index].offset(), &mut budget, &mut || true)
            .unwrap();
        assert_resident_bound(&recent, objects.len());
    }
    assert_eq!(budget.accounting.expanded, 16);
    assert!(matches!(
        recent.resolve_offset_typed_with_budget(objects[1].offset(), &mut budget, &mut || true),
        Err(PackError::TotalExpandedLimit {
            actual: 20,
            limit: 16
        })
    ));
    assert_eq!(budget.accounting.expanded, 16);
    assert!(
        recent
            .resolve_offset_typed_with_budget(objects[0].offset(), &mut budget, &mut || true)
            .is_ok(),
        "a retained result spends copy work, not fresh expansion"
    );
    assert_eq!(budget.accounting.expanded, 16);
    assert_resident_bound(&recent, objects.len());
}

#[test]
fn zero_and_oversized_results_never_spill_or_exceed_either_capacity() {
    for (length, resident, configured) in [(8, 4, 8), (8, 8, 4), (0, 0, 8), (0, 8, 0)] {
        let objects = independent_bases(length, 2);
        let limits = PackLimits {
            max_cached_bytes: configured,
            ..PackLimits::default()
        };
        let mut spill = NoSpill::default();
        let mut recent = CachedResolver::with_resident_recency(
            &objects,
            &(),
            &limits,
            &mut spill,
            resident,
            &mut || true,
        )
        .unwrap();
        let mut budget = ResolutionBudget::new();
        for _ in 0..2 {
            for object in &objects {
                recent
                    .resolve_offset_typed_with_budget(object.offset(), &mut budget, &mut || true)
                    .unwrap();
                assert_resident_bound(&recent, objects.len());
            }
        }
        assert!(recent.entries.is_empty());
        assert_eq!(budget.accounting.expanded, 4 * length);
        drop(recent);
        assert_eq!(spill.calls, 0);
    }
}

#[test]
fn a_cached_copy_still_spends_the_same_work_budget() {
    let objects = independent_bases(8, 1);
    let limits = PackLimits {
        max_delta_work: 3,
        max_cached_bytes: 8,
        ..PackLimits::default()
    };
    let mut recent = CachedResolver::with_resident_recency(
        &objects,
        &(),
        &limits,
        ResidentCache,
        8,
        &mut || true,
    )
    .unwrap();
    let mut budget = ResolutionBudget::new();
    recent
        .resolve_offset_typed_with_budget(12, &mut budget, &mut || true)
        .unwrap();
    assert!(matches!(
        recent.resolve_offset_typed_with_budget(12, &mut budget, &mut || true),
        Err(PackError::DeltaWorkLimit { .. })
    ));
    assert_eq!(budget.accounting.expanded, 8);
    assert_resident_bound(&recent, objects.len());
}

#[test]
fn arbitrary_resolution_order_matches_the_scalar_and_keeps_links_bounded() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (objects, _) = history(format, 32, 12, true);
        let limits = PackLimits {
            max_cached_bytes: 100,
            ..PackLimits::default()
        };
        let scalar = ScalarResolver::new(&objects, &(), &limits, &mut || true).unwrap();
        let mut recent = CachedResolver::with_resident_recency(
            &objects,
            &(),
            &limits,
            ResidentCache,
            100,
            &mut || true,
        )
        .unwrap();
        let mut budget = ResolutionBudget::new();
        for pass in 0..4 {
            for step in 0..objects.len() {
                let at = objects[(step * 5 + pass * 7) % objects.len()].offset();
                assert_eq!(
                    recent.resolve_offset_typed_with_budget(at, &mut budget, &mut || true),
                    scalar.resolve_offset_typed(at, &mut || true)
                );
                assert_resident_bound(&recent, objects.len());
            }
        }
    }
}

#[test]
fn malformed_cycles_depth_and_fanout_keep_the_scalar_refusal() {
    let (chain, _) = history(ObjectFormat::Sha1, 4, 3, false);
    let mut malformed = chain.clone();
    let PackObject::Delta(delta) = &mut malformed[1] else {
        unreachable!()
    };
    delta.program = vec![4, 5, 0];
    let mut cyclic = chain.clone();
    let last = cyclic.last().unwrap().offset();
    let PackObject::Delta(delta) = &mut cyclic[1] else {
        unreachable!()
    };
    delta.base = DeltaBase::Ofs(last);
    let mut fanout = chain.clone();
    let first = fanout[0].offset();
    let PackObject::Delta(delta) = &mut fanout[2] else {
        unreachable!()
    };
    delta.base = DeltaBase::Ofs(first);
    for (objects, at, maximum_depth, maximum_fanout) in [
        (&malformed, malformed[1].offset(), 64, 4096),
        (&cyclic, last, 64, 4096),
        (&chain, last, 2, 4096),
        (&fanout, fanout[1].offset(), 64, 1),
    ] {
        let limits = PackLimits {
            max_delta_depth: maximum_depth,
            max_delta_fanout: maximum_fanout,
            max_cached_bytes: 8,
            ..PackLimits::default()
        };
        let scalar = ScalarResolver::new(objects, &(), &limits, &mut || true).unwrap();
        let mut recent = CachedResolver::with_resident_recency(
            objects,
            &(),
            &limits,
            ResidentCache,
            8,
            &mut || true,
        )
        .unwrap();
        let expected = scalar.resolve_offset_typed(at, &mut || true);
        assert!(expected.is_err());
        assert_eq!(recent.resolve_offset_typed(at, &mut || true), expected);
        assert_resident_bound(&recent, objects.len());
    }
}

struct TypedExternal {
    id: ObjectId,
    body: Vec<u8>,
    kind: Option<ObjectType>,
}

impl ExternalBaseLookup for TypedExternal {
    fn lookup(&self, id: &ObjectId) -> Option<&[u8]> {
        (*id == self.id).then_some(self.body.as_slice())
    }

    fn lookup_typed(&self, id: &ObjectId) -> Option<(ObjectType, &[u8])> {
        self.kind.zip(self.lookup(id))
    }
}

#[test]
fn external_native_types_and_missing_or_untyped_bases_are_not_inferred() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let base = b"external";
        let id = git_object_id(format, ObjectType::Blob, base);
        let objects = [PackObject::Delta(DeltaObject {
            offset: 12,
            id: None,
            base: DeltaBase::Ref(id),
            program: append_program(base.len(), b'!'),
        })];
        let limits = PackLimits::default();
        for kind in [Some(ObjectType::Blob), None] {
            let external = TypedExternal {
                id,
                body: base.to_vec(),
                kind,
            };
            let scalar = ScalarResolver::new(&objects, &external, &limits, &mut || true).unwrap();
            let mut recent = CachedResolver::with_resident_recency(
                &objects,
                &external,
                &limits,
                ResidentCache,
                16,
                &mut || true,
            )
            .unwrap();
            // Byte-only warming cannot supply a missing original type proof.
            assert_eq!(
                recent.resolve_offset(12, &mut || true).unwrap(),
                b"external!"
            );
            let expected = scalar.resolve_offset_typed(12, &mut || true);
            if kind.is_none() {
                assert_eq!(expected, Err(PackError::UntypedExternalDeltaBase));
            }
            assert_eq!(recent.resolve_offset_typed(12, &mut || true), expected);
            assert_resident_bound(&recent, objects.len());
        }
        let mut missing = CachedResolver::with_resident_recency(
            &objects,
            &(),
            &limits,
            ResidentCache,
            16,
            &mut || true,
        )
        .unwrap();
        assert_eq!(
            missing.resolve_offset_typed(12, &mut || true),
            Err(PackError::MissingDeltaBase)
        );
    }
}

#[test]
fn cancellation_during_resolution_and_replacement_is_a_stop() {
    let (objects, _) = history(ObjectFormat::Sha1, 32, 12, true);
    let limits = PackLimits {
        max_cached_bytes: 80,
        ..PackLimits::default()
    };
    let run = |stop_after: usize| {
        let mut resolver = CachedResolver::with_resident_recency(
            &objects,
            &(),
            &limits,
            ResidentCache,
            80,
            &mut || true,
        )
        .unwrap();
        let mut budget = ResolutionBudget::new();
        let mut checkpoints = 0;
        let result = objects.iter().try_for_each(|object| {
            resolver
                .resolve_offset_typed_with_budget(object.offset(), &mut budget, &mut || {
                    checkpoints += 1;
                    checkpoints <= stop_after
                })
                .map(|_| ())
        });
        assert_resident_bound(&resolver, objects.len());
        (result, checkpoints)
    };
    let (completed, checkpoints) = run(usize::MAX);
    assert!(completed.is_ok());
    for stop in [0, 1, checkpoints / 2, checkpoints - 1] {
        assert_eq!(run(stop).0, Err(PackError::DeadlineExceeded));
    }
}
