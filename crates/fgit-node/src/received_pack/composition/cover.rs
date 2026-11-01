//! Bounded exact-cover choices over verified source memberships.
//!
//! Small candidate sets retain count-then-mask ordering. Larger sets first
//! propagate mandatory sources through unique ownership. Each eliminated
//! source's positions are revisited once; queued marks bound live queue space
//! by selected objects. Only eight remaining ambiguous sources are enumerated.

use super::{Candidate, MAX_ENTRIES, check, filled};
use fgit_pack::{Deadline, PackError};
use std::collections::VecDeque;

const EXHAUSTIVE_SOURCES: usize = 8;
const MAX_SUBSETS: usize = (1 << EXHAUSTIVE_SOURCES) - 1;
const _: () = assert!(MAX_ENTRIES <= u64::BITS as usize);

/// The caller already tried exact FIFO singletons with final integrity/graph
/// validation. These choices need that same validation before use.
pub(super) fn choices(
    candidates: &[Candidate],
    object_count: usize,
    live: &mut impl Deadline,
) -> Result<Option<Vec<u64>>, PackError> {
    check(live)?;
    if candidates.is_empty() || candidates.len() > MAX_ENTRIES || object_count == 0 {
        return Ok(None);
    }
    let small = candidates.len() <= EXHAUSTIVE_SOURCES;
    let mut eligible = 0u64;
    let mut memberships = 0usize;
    for (index, candidate) in candidates.iter().enumerate() {
        check(live)?;
        // An already-tried exact singleton overlaps every nonempty source.
        // It cannot join another cover or prevent propagation among the rest.
        if !small && candidate.positions.len() == object_count {
            continue;
        }
        eligible |= 1u64 << index;
        let Some(total) = memberships.checked_add(candidate.positions.len()) else {
            return Ok(None);
        };
        memberships = total;
    }
    if memberships < object_count {
        return Ok(None);
    }
    // A complete cover needs at least this many retained memberships. Check
    // that before allocating per-selected-object arrays: every allocated row
    // is then bounded by the cache's conservative per-object metadata charge.
    let Some(mut owners) = filled(object_count, 0u64) else {
        return Ok(None);
    };
    for (index, candidate) in candidates.iter().enumerate() {
        let bit = 1u64 << index;
        if eligible & bit == 0 {
            continue;
        }
        for &position in &candidate.positions {
            check(live)?;
            owners[position] |= bit;
        }
    }
    let mut overlaps = [0u64; MAX_ENTRIES];
    for (index, candidate) in candidates.iter().enumerate() {
        let bit = 1u64 << index;
        if eligible & bit == 0 {
            continue;
        }
        let mut shared = 0u64;
        for &position in &candidate.positions {
            check(live)?;
            shared |= owners[position];
        }
        overlaps[index] = shared & !bit;
    }
    let mut output = Vec::new();
    if output.try_reserve_exact(MAX_SUBSETS).is_err() {
        return Ok(None);
    }
    if small {
        enumerate(
            candidates,
            object_count,
            &overlaps,
            0,
            eligible,
            &mut output,
            live,
        )?;
        return Ok(Some(output));
    }

    let Some(mut queued) = filled(object_count, false) else {
        return Ok(None);
    };
    let mut pending = VecDeque::new();
    if pending.try_reserve_exact(object_count).is_err() {
        return Ok(None);
    }
    for (position, &mask) in owners.iter().enumerate() {
        check(live)?;
        if mask == 0 {
            return Ok(None);
        }
        if mask.is_power_of_two() {
            queued[position] = true;
            pending.push_back(position);
        }
    }
    let mut forced = 0u64;
    let mut covered = 0usize;
    while let Some(position) = pending.pop_front() {
        check(live)?;
        queued[position] = false;
        if owners[position] & forced != 0 {
            continue;
        }
        let remaining = owners[position] & eligible;
        if remaining == 0 {
            return Ok(None);
        }
        if !remaining.is_power_of_two() {
            continue;
        }
        let index = remaining.trailing_zeros() as usize;
        forced |= remaining;
        let Some(total) = covered.checked_add(candidates[index].positions.len()) else {
            return Ok(None);
        };
        if total > object_count {
            return Ok(None);
        }
        covered = total;
        let mut removed = eligible & (remaining | overlaps[index]);
        eligible &= !removed;
        // Eligibility only shrinks, so each source enters this loop once.
        // Recheck only memberships changed by those removals, not the whole
        // object set after each forced choice.
        while removed != 0 {
            let discarded = removed.trailing_zeros() as usize;
            removed &= removed - 1;
            for &affected in &candidates[discarded].positions {
                check(live)?;
                if owners[affected] & forced != 0 {
                    continue;
                }
                let remaining = owners[affected] & eligible;
                if remaining == 0 {
                    return Ok(None);
                }
                if remaining.is_power_of_two() && !queued[affected] {
                    queued[affected] = true;
                    pending.push_back(affected);
                }
            }
        }
    }
    check(live)?;
    if covered == object_count {
        output.push(forced);
        return Ok(Some(output));
    }

    // Repeated representations of the whole remaining base history need no
    // exponential search. Each forced+singleton cover has the optimal source
    // count; final graph validation may reject one and try the next FIFO twin.
    let missing = object_count - covered;
    for (index, candidate) in candidates.iter().enumerate() {
        check(live)?;
        let bit = 1u64 << index;
        if eligible & bit != 0 && candidate.positions.len() == missing {
            output.push(forced | bit);
        }
    }
    if eligible.count_ones() as usize > EXHAUSTIVE_SOURCES {
        return Ok(Some(output));
    }
    enumerate(
        candidates,
        object_count,
        &overlaps,
        forced,
        eligible,
        &mut output,
        live,
    )?;
    Ok(Some(output))
}

/// Singleton covers were already offered. Enumerate at most 255 distinct
/// nonempty residual subsets, preserving count then original FIFO mask order.
fn enumerate(
    candidates: &[Candidate],
    object_count: usize,
    overlaps: &[u64; MAX_ENTRIES],
    forced: u64,
    eligible: u64,
    output: &mut Vec<u64>,
    live: &mut impl Deadline,
) -> Result<(), PackError> {
    let mut bits = [0u64; EXHAUSTIVE_SOURCES];
    let mut count = 0usize;
    let mut remaining = eligible;
    while remaining != 0 {
        check(live)?;
        let index = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1;
        bits[count] = 1u64 << index;
        count += 1;
    }
    // count is at most eight, even when original source bit 63 participates.
    let end = 1u16 << count;
    for chosen in 2..=count {
        for local in 1u16..end {
            check(live)?;
            if local.count_ones() as usize != chosen {
                continue;
            }
            let mut mask = forced;
            for (index, bit) in bits[..count].iter().enumerate() {
                if local & (1u16 << index) != 0 {
                    mask |= *bit;
                }
            }
            let mut objects = 0usize;
            let mut disjoint = true;
            for (index, candidate) in candidates.iter().enumerate() {
                check(live)?;
                if mask & (1u64 << index) == 0 {
                    continue;
                }
                if mask & overlaps[index] != 0 {
                    disjoint = false;
                    break;
                }
                objects = objects.saturating_add(candidate.positions.len());
            }
            if disjoint && objects == object_count {
                output.push(mask);
            }
        }
    }
    Ok(())
}
