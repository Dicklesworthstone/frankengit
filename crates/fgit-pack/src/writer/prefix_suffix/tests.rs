use super::*;
use crate::writer::{
    BaseDeltaIndex, Deadline, DeltaSearch, LivePositions, make_delta_program_with,
    scan_indexed_delta_program,
};
use crate::{PackLimits, apply_delta};

fn noise(length: usize) -> Vec<u8> {
    let mut state = 0x91ef_dd01_u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn check_matches(left: &[u8], right: &[u8]) {
    assert_eq!(common_prefix(left, right), scalar_prefix(left, right));
    let limit = left.len().min(right.len());
    for prefix in [0, limit / 3, limit] {
        assert_eq!(
            common_suffix(left, right, prefix),
            scalar_suffix(left, right, prefix),
            "left={} right={} prefix={prefix}",
            left.len(),
            right.len(),
        );
    }
}

#[test]
fn chunk_matching_equals_scalar_at_every_small_mismatch_and_large_boundary() {
    for length in [
        0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 4_095, 4_096, 4_097,
        65_535, 65_536, 65_537,
    ] {
        let body = noise(length);
        for (left_offset, right_offset) in [(0, 1), (1, 7), (3, 0), (7, 5)] {
            let mut left_storage = vec![0; left_offset];
            left_storage.extend_from_slice(&body);
            let left = &left_storage[left_offset..];
            let mut right_storage = vec![0; right_offset];
            right_storage.extend_from_slice(&body);
            check_matches(left, &right_storage[right_offset..]);
            if length == 0 {
                continue;
            }
            let positions: Vec<_> = if length <= 129 {
                (0..length).collect()
            } else {
                vec![0, 1, 31, 32, 63, 64, 65, length / 2, length - 1]
            };
            for position in positions {
                right_storage[right_offset + position] ^= 0xff;
                check_matches(left, &right_storage[right_offset..]);
                right_storage[right_offset + position] ^= 0xff;
            }
            // Unequal lengths exercise both front- and end-aligned chunking.
            check_matches(left, &right_storage[right_offset + 1..]);
            check_matches(&left[1..], &right_storage[right_offset..]);
            check_matches(left, &right_storage[right_offset..right_storage.len() - 1]);
        }
    }
}

#[test]
fn copy_cost_preserves_instruction_boundaries_and_overflow_refusals() {
    for offset in [
        0,
        1,
        0xff,
        0x100,
        0xffff,
        0x1_0000,
        0xff_ffff,
        0x100_0000,
        u32::MAX as usize - 65_536,
        u32::MAX as usize,
    ] {
        for length in [0, 1, 127, 128, 255, 256, 65_535, 65_536, 65_537, 131_072] {
            let mut encoded = Vec::new();
            let actual = emit_copy_run(offset, length, &mut encoded).map(|()| encoded.len());
            assert_eq!(copy_run_cost(offset, length), actual, "{offset}/{length}");
        }
    }
    if let Some(offset) = (u32::MAX as usize).checked_add(1) {
        assert_eq!(
            copy_run_cost(offset, 0),
            Err(PackError::IntegerOverflow {
                context: "delta copy offset",
            }
            .into()),
        );
    }
    for value in [
        0,
        1,
        127,
        128,
        16_383,
        16_384,
        u32::MAX as usize,
        usize::MAX,
    ] {
        let mut encoded = Vec::new();
        encode_delta_varint(value, &mut encoded).unwrap();
        assert_eq!(varint_cost(value).unwrap(), encoded.len());
    }
}

fn pairs() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut pairs = vec![(Vec::new(), Vec::new()), (b"a".to_vec(), b"b".to_vec())];
    for length in [
        1, 15, 16, 63, 64, 65, 126, 127, 128, 129, 16_384, 65_536, 65_537,
    ] {
        let base = noise(length);
        pairs.push((base.clone(), base.clone()));
        let mut edited = base.clone();
        edited[length / 2] ^= 1;
        pairs.push((base.clone(), edited));
        let mut shifted = b"shift".to_vec();
        shifted.extend_from_slice(&base);
        pairs.push((base.clone(), shifted));
        pairs.push((base, vec![0xff; length]));
    }
    pairs.push((vec![b'x'; 65_537], vec![b'x'; 65_536]));
    pairs
}

#[test]
fn measured_prefix_suffix_bytes_equal_the_eager_scalar_oracle_and_round_trip() {
    for (base, target) in pairs() {
        let measured = PrefixSuffixDelta::new(&base, &target).unwrap();
        let expected = scalar_program(&base, &target).unwrap();
        assert_eq!(measured.len(), expected.len());
        let encoded = measured.encode().unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(
            apply_delta(&base, &encoded, &PackLimits::default(), &mut || true).unwrap(),
            target,
        );
    }
}

// The eager choice at 07587ad2. This retains its allocation/selection order;
// independent scalar construction keeps a wrong size from becoming its oracle.
fn eager_choice(
    base: &[u8],
    target: &[u8],
    search: DeltaSearch,
    index: Option<&BaseDeltaIndex>,
    live: Option<&LivePositions>,
    bound: usize,
    deadline: &mut impl Deadline,
) -> Result<Option<Vec<u8>>, PackWriteError> {
    let fallback = scalar_program(base, target)?;
    let chosen = match (search, index) {
        (DeltaSearch::IndexedBlocks, Some(index)) => scan_indexed_delta_program(
            index,
            base,
            target,
            bound.min(fallback.len()),
            live,
            deadline,
        )?
        .unwrap_or(fallback),
        _ => fallback,
    };
    Ok((chosen.len() < bound).then_some(chosen))
}

#[test]
fn lazy_choice_preserves_strict_bounds_ties_and_live_position_skips() {
    let limits = PackLimits {
        max_index_entries: 256,
        ..PackLimits::default()
    };
    let mut emitted = 0;
    let mut refused = 0;
    for (base, target) in pairs() {
        let index = BaseDeltaIndex::build(&base, &limits, &mut || true).unwrap();
        let live = match &index {
            Some(index) => LivePositions::build(&target, &[index], &mut || true).unwrap(),
            None => None,
        };
        let fallback = scalar_program(&base, &target).unwrap();
        for bound in [
            0,
            1,
            fallback.len().saturating_sub(1),
            fallback.len(),
            fallback.len() + 1,
            target.len(),
            usize::MAX,
        ] {
            for search in [DeltaSearch::PrefixSuffix, DeltaSearch::IndexedBlocks] {
                for positions in [None, live.as_ref()] {
                    let expected = eager_choice(
                        &base,
                        &target,
                        search,
                        index.as_ref(),
                        positions,
                        bound,
                        &mut || true,
                    );
                    let actual = make_delta_program_with(
                        &base,
                        &target,
                        search,
                        index.as_ref(),
                        positions,
                        bound,
                        &mut || true,
                    );
                    assert_eq!(actual, expected, "{search:?} bound={bound}");
                    if actual.unwrap().is_some() {
                        emitted += 1;
                    } else {
                        refused += 1;
                    }
                }
            }
        }
    }
    assert!(emitted > 100 && refused > 100);
}

struct CancelAfter {
    remaining: usize,
    calls: usize,
}

impl Deadline for CancelAfter {
    fn checkpoint(&mut self) -> bool {
        self.calls += 1;
        if self.remaining == 0 {
            false
        } else {
            self.remaining -= 1;
            true
        }
    }
}

#[test]
fn lazy_choice_preserves_cancellation_checkpoints_and_typed_refusals() {
    let base = noise(32 * 1024);
    let mut target = b"shift".to_vec();
    target.extend_from_slice(&base);
    target[8 * 1024] ^= 1;
    let index = BaseDeltaIndex::build(&base, &PackLimits::default(), &mut || true)
        .unwrap()
        .unwrap();
    let live = LivePositions::build(&target, &[&index], &mut || true).unwrap();
    let mut cancellations = 0;
    let mut successes = 0;
    for remaining in 0..16 {
        for positions in [None, live.as_ref()] {
            let mut old = CancelAfter {
                remaining,
                calls: 0,
            };
            let mut new = CancelAfter {
                remaining,
                calls: 0,
            };
            let expected = eager_choice(
                &base,
                &target,
                DeltaSearch::IndexedBlocks,
                Some(&index),
                positions,
                target.len(),
                &mut old,
            );
            let actual = make_delta_program_with(
                &base,
                &target,
                DeltaSearch::IndexedBlocks,
                Some(&index),
                positions,
                target.len(),
                &mut new,
            );
            assert_eq!(actual, expected);
            assert_eq!(new.calls, old.calls);
            match actual {
                Err(PackWriteError::Pack(PackError::DeadlineExceeded)) => cancellations += 1,
                Ok(Some(_)) => successes += 1,
                unexpected => panic!("unexpected selection: {unexpected:?}"),
            }
        }
    }
    assert!(cancellations > 0 && successes > 0);
}
