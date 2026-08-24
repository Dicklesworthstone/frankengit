#![forbid(unsafe_code)]
//! Distributed SLO, capacity and economics measurement over the multi-cell
//! substrate (`frankengit-fg036c`).
//!
//! # What this crate exists to prevent
//!
//! Measuring a system is easy; measuring it in a way that cannot fabricate a
//! result is not. Each piece here exists because an earlier version of this
//! harness produced a plausible, tidy, wrong number:
//!
//! * **The raw series is never sorted.** Arrival order is the only thing that
//!   can show warmup, accumulation or a leak. Sorting it once turned a warmup
//!   decay into what looked like unbounded accumulation.
//! * **States are reached by a legal path.** Walking one cell through the state
//!   list measures a *path* and silently skipped three of ten states; opening a
//!   fresh cell per state reached only four, because most states need several
//!   hops. [`legal_path`] plans over [`CellState::may_transition_to`], a pure
//!   predicate, so coverage is a fact rather than an accident of loop order.
//! * **Open cost is timed apart from read cost.** Fresh-open-per-state numbers
//!   ran roughly ten times the warm-cell numbers for identical calls. Folding
//!   them together reports *node open* cost under the label "read latency" —
//!   which points at the wrong subsystem entirely.
//! * **Every comparison is gated on a measured A/A floor.** The same
//!   configuration sampled twice, back to back, through the identical function.
//!   A difference between two *different* configurations that does not clear
//!   that floor is not a result. This is not a formality: it is what
//!   established that read modes are *not* distinguishable by latency here.
//!
//! # Claim class
//!
//! Benchmark, and nothing above it. Latency figures from one run are comparable
//! only *within* that run against that run's own A/A floor — never across runs.
//! Exact counts (storage bytes, served-versus-refused) are not timings and do
//! not carry that restriction.

use std::collections::VecDeque;
use std::path::Path;
use std::time::Instant;

use fgit_node::OneNode;
use fgit_types::cell::{CellState, ReadLabel, StalenessBound, StalenessObservation};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;

use core::time::Duration;

/// Every cell state, listed so a sweep cannot silently shrink when the enum
/// grows. A test pins this length against the vocabulary itself.
pub const STATES: [CellState; 10] = [
    CellState::Bootstrapping,
    CellState::VerifiedReadOnly,
    CellState::Serving,
    CellState::StagingOnly,
    CellState::Draining,
    CellState::DegradedRead,
    CellState::Repairing,
    CellState::Evacuating,
    CellState::Failed,
    CellState::Retired,
];

/// A bounded-stale label comfortably inside its bound.
///
/// # Panics
///
/// If the observation is outside the bound, which would be a bug in these
/// constants rather than a runtime condition.
#[must_use]
pub fn bounded_stale_label() -> ReadLabel {
    ReadLabel::bounded_stale(
        StalenessBound::new(Duration::from_secs(30), 5),
        StalenessObservation::new(Duration::from_secs(3), 1),
    )
    .expect("the fixed observation is inside the fixed bound")
}

/// The four read modes with the label a client would actually send.
#[must_use]
pub fn labels() -> Vec<(&'static str, ReadLabel)> {
    vec![
        ("current", ReadLabel::current()),
        ("bounded_stale", bounded_stale_label()),
        ("snapshot", ReadLabel::snapshot()),
        ("offline", ReadLabel::offline()),
    ]
}

/// Shortest legal path from `from` to `target`, planned over the pure legality
/// predicate rather than by trial and error against a live node.
///
/// Returns the hops to apply, excluding `from`; an empty vector when already
/// there. `None` means no legal path exists, which is a fact about the
/// transition graph and is reported as such rather than treated as a failure.
#[must_use]
pub fn legal_path(from: CellState, target: CellState) -> Option<Vec<CellState>> {
    if from == target {
        return Some(Vec::new());
    }
    let mut queue = VecDeque::new();
    queue.push_back((from, Vec::new()));
    let mut seen = vec![from];
    while let Some((state, path)) = queue.pop_front() {
        for next in STATES {
            if seen.contains(&next) || !state.may_transition_to(next) {
                continue;
            }
            let mut extended = path.clone();
            extended.push(next);
            if next == target {
                return Some(extended);
            }
            seen.push(next);
            queue.push_back((next, extended));
        }
    }
    None
}

/// Median of a copy, leaving the caller's arrival order intact.
///
/// Taking a copy is the point. Ranking in place would destroy arrival order,
/// and arrival order is the only evidence of warmup or accumulation.
#[must_use]
pub fn median_of(values: &[u128]) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let mut ranked = values.to_vec();
    ranked.sort_unstable();
    ranked[ranked.len() / 2]
}

/// Total bytes and file count under a directory tree.
///
/// Walked by hand because the node exposes no footprint accessor. Symlinks are
/// deliberately not followed: counting a link target twice inflates the number,
/// and an inflated storage figure is exactly the kind of result that looks like
/// a finding.
#[must_use]
pub fn tree_footprint(root: &Path) -> (u64, u64) {
    let mut bytes = 0_u64;
    let mut files = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                bytes += metadata.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

/// One block of samples: `(served count, arrival-ordered nanoseconds)`.
///
/// Factored out precisely so an A/A control can run the identical code path
/// twice. An A/A whose two arms differ even slightly measures the difference
/// between the arms rather than the host.
#[must_use]
pub fn sample_block(
    cell: &OneNode,
    visibility: &RefVisibility,
    limits: &WireLimits,
    label: ReadLabel,
    samples: u32,
) -> (u32, Vec<u128>) {
    let mut arrival = Vec::new();
    let mut served = 0_u32;
    for _ in 0..samples {
        let started = Instant::now();
        let outcome = cell.runtime().block_on(cell.labelled_advertisement_in(
            &cell.request_context(),
            visibility,
            limits,
            label,
        ));
        let elapsed = started.elapsed().as_nanos();
        if outcome.is_ok() {
            served += 1;
            arrival.push(elapsed);
        }
    }
    (served, arrival)
}

/// Whether a measured gap clears the noise floor it must clear to be a result.
///
/// The whole discipline of this crate in one predicate. A gap smaller than the
/// A/A floor measured on the same configurations is indistinguishable from the
/// host's own variation, and reporting it as an effect is fabrication.
#[must_use]
pub const fn clears_floor(gap_ns: u128, aa_floor_ns: u128) -> bool {
    gap_ns > aa_floor_ns
}

/// Aggregate throughput of `concurrency` readers issuing `per_reader` reads.
///
/// Returns `(served, elapsed_nanos)`. Readers are spread across the supplied
/// cells round-robin, so a sweep at N cells exercises N cells rather than
/// hammering one and calling it a deployment.
///
/// # Why this exists separately from [`sample_block`]
///
/// A saturation point is where adding concurrency stops adding throughput. That
/// is invisible to a single-threaded latency sample no matter how many times it
/// is repeated: per-call latency and aggregate throughput are different
/// quantities, and reporting the first as a capacity model is proof-class
/// inflation.
#[must_use]
pub fn throughput_block(
    cells: &[OneNode],
    visibility: &RefVisibility,
    limits: &WireLimits,
    label: ReadLabel,
    concurrency: usize,
    per_reader: u32,
) -> (u64, u128) {
    let started = Instant::now();
    let served = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for index in 0..concurrency {
            let cell = &cells[index % cells.len()];
            handles.push(scope.spawn(move || {
                let mut ok = 0_u64;
                for _ in 0..per_reader {
                    let outcome = cell.runtime().block_on(cell.labelled_advertisement_in(
                        &cell.request_context(),
                        visibility,
                        limits,
                        label,
                    ));
                    if outcome.is_ok() {
                        ok += 1;
                    }
                }
                ok
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or(0))
            .sum::<u64>()
    });
    (served, started.elapsed().as_nanos())
}

/// Operations per second, or `0` when nothing was served or no time passed.
///
/// Integer arithmetic on purpose: a float here would invite a printed rate with
/// more precision than the measurement supports.
#[must_use]
pub const fn ops_per_second(served: u64, elapsed_ns: u128) -> u64 {
    if elapsed_ns == 0 {
        return 0;
    }
    let rate = (served as u128).saturating_mul(1_000_000_000) / elapsed_ns;
    rate as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rate_is_zero_when_nothing_was_served_or_no_time_passed() {
        assert_eq!(ops_per_second(0, 1_000_000_000), 0);
        // A zero elapsed time must not divide by zero, and must not report an
        // infinite rate either.
        assert_eq!(ops_per_second(10, 0), 0);
        assert_eq!(ops_per_second(5, 1_000_000_000), 5);
        // Sub-second windows scale up rather than truncating to zero.
        assert_eq!(ops_per_second(1, 500_000_000), 2);
    }

    #[test]
    fn a_rate_does_not_overflow_on_a_large_count() {
        // The multiply is done in u128 precisely so a large served count in a
        // short window cannot wrap into a small, plausible-looking rate.
        let rate = ops_per_second(u64::MAX, 1_000_000_000);
        assert_eq!(rate, u64::MAX);
    }

    #[test]
    fn every_state_is_reachable_from_bootstrapping_by_a_legal_path() {
        // Coverage is a fact about the graph, and this pins it. An earlier
        // harness reported three states unreachable and then, after a "fix",
        // six — both were artifacts of how the sweep walked, not of the graph.
        for target in STATES {
            let path = legal_path(CellState::Bootstrapping, target)
                .unwrap_or_else(|| panic!("{target:?} must be reachable"));
            assert!(
                path.len() <= 3,
                "{target:?} took {} hops, which is longer than the graph requires",
                path.len()
            );
        }
    }

    #[test]
    fn a_path_is_legal_edge_by_edge_and_ends_where_asked() {
        // A path that merely ENDS at the target is not enough: every edge along
        // it must be one the vocabulary admits, or the walk would be refused
        // partway and the state actually measured would not be the one named.
        for target in STATES {
            let path = legal_path(CellState::Bootstrapping, target).expect("reachable");
            let mut here = CellState::Bootstrapping;
            for hop in &path {
                assert!(
                    here.may_transition_to(*hop),
                    "illegal edge {here:?} -> {hop:?} in the path to {target:?}"
                );
                here = *hop;
            }
            assert_eq!(here, target, "the path must end at the target");
        }
    }

    #[test]
    fn an_unreachable_target_returns_none_rather_than_a_wrong_path() {
        // PRESENCE CASE for the None branch. Terminal states admit no outgoing
        // edge, so nothing is reachable from one. Without this, `legal_path`
        // returning Some for everything would look identical to a correct
        // implementation.
        let terminal = CellState::Retired;
        assert!(
            !terminal.may_transition_to(CellState::Serving),
            "this test needs a genuinely terminal state to be meaningful"
        );
        assert!(legal_path(terminal, CellState::Serving).is_none());
        // The permitted twin: from the same state, the zero-hop path to itself
        // still resolves, so `None` means unreachable and not merely terminal.
        assert_eq!(legal_path(terminal, terminal), Some(Vec::new()));
    }

    #[test]
    fn the_state_table_matches_the_vocabulary_it_mirrors() {
        // A hand-maintained list beside a closed enum drifts silently. Every
        // entry must be distinct, and the count is pinned so that adding a
        // variant upstream fails here rather than shrinking the sweep.
        let mut seen = Vec::new();
        for state in STATES {
            assert!(!seen.contains(&state), "{state:?} listed twice");
            seen.push(state);
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn median_does_not_disturb_the_callers_arrival_order() {
        // The defect this guards against is real: sorting the raw series in
        // place once turned a warmup decay into an apparent leak.
        let arrival = vec![900_u128, 100, 500];
        let before = arrival.clone();
        assert_eq!(median_of(&arrival), 500);
        assert_eq!(arrival, before, "median_of must not reorder its input");
        assert_eq!(median_of(&[]), 0);
        assert_eq!(median_of(&[7]), 7);
    }

    #[test]
    fn a_gap_inside_the_noise_floor_is_not_a_result() {
        assert!(
            !clears_floor(5, 10),
            "a gap under the floor is not an effect"
        );
        assert!(
            !clears_floor(10, 10),
            "a gap EQUAL to the floor is not an effect either"
        );
        assert!(clears_floor(11, 10), "and one above it is");
    }

    #[test]
    fn the_footprint_walker_counts_files_and_ignores_directories() {
        let root = std::env::temp_dir().join(format!("fgit-slo-footprint-{}", std::process::id()));
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).expect("scratch tree");
        std::fs::write(root.join("one"), b"12345").expect("write");
        std::fs::write(nested.join("two"), b"123").expect("write");

        let (bytes, files) = tree_footprint(&root);
        assert_eq!(files, 2, "directories are not files");
        assert_eq!(bytes, 8, "and the byte count is the sum of file lengths");

        // An absent tree is zero rather than a panic: a caller measuring a
        // storage root that was never created must get a number, not a crash.
        let (bytes, files) = tree_footprint(&root.join("does-not-exist"));
        assert_eq!((bytes, files), (0, 0));

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn the_four_labels_are_the_four_distinct_modes() {
        let labels = labels();
        assert_eq!(labels.len(), 4);
        let mut points: Vec<u16> = labels
            .iter()
            .map(|(_, label)| label.mode().code_point())
            .collect();
        points.sort_unstable();
        points.dedup();
        assert_eq!(points.len(), 4, "each label must be a distinct read mode");
    }
}
