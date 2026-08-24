//! FG-028c: the authority arm actually publishes, and its ratio is measured.
//!
//! The workload's value is a number, so the thing worth testing is not that it
//! runs but that the number is the one the batch carried. Each case therefore
//! fixes `decisions_per_batch` and requires the measured `decisions` to equal
//! it — a workload that silently published a different count would pass a
//! "it ran" test and fail these.

use std::path::PathBuf;

use fgit_authority::StoreInstanceId;
use fgit_benchmark::BenchmarkWorkload;
use fgit_benchmark::authority::{AuthorityPublicationConfig, AuthorityPublicationWorkload};
use fgit_types::TenantId;

/// A store directory unique to one test, under the crate's target dir.
fn scratch(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    path.push(format!("fg028c-authority-{name}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path.push("authority.sqlite3");
    path
}

fn config(name: &str, decisions_per_batch: usize) -> AuthorityPublicationConfig {
    AuthorityPublicationConfig {
        store_path: scratch(name),
        decisions_per_batch,
        tenant_id: TenantId::from_bytes([0x11; 16]),
        instance_id: StoreInstanceId::from_raw(1),
    }
}

#[test]
fn one_round_publishes_every_decision_in_its_batch() {
    let mut workload =
        AuthorityPublicationWorkload::open(config("single", 3)).expect("the store opens");

    let (sample, metrics) = workload.measure().expect("a round publishes");

    assert_eq!(sample.indexed, 3, "every decision in the batch is indexed");
    assert_eq!(
        metrics.decisions, 3,
        "the reported numerator is the published count, not the requested one"
    );
    assert_eq!(
        metrics.cas_attempts, 2,
        "one committing publication plus one deliberately stale republication"
    );

    workload
        .verify(&sample)
        .expect("the oracle accepts the round");
}

/// The contention half, which is the reason the second publication exists.
///
/// Without it the workload would report a ratio with no losing CAS in the
/// denominator, which is a different and much less interesting measurement.
#[test]
fn the_stale_republication_loses_its_token() {
    let mut workload =
        AuthorityPublicationWorkload::open(config("contention", 1)).expect("the store opens");

    let (sample, _) = workload.measure().expect("a round publishes");

    assert_eq!(
        sample.predecessor_mismatches, 1,
        "republishing from the round's opening token must lose after that token was replaced"
    );
}

/// The numerator has to move with the batch, or it is not a measurement.
///
/// A workload that hard-coded its decision count would pass the single-round
/// case above. Two different batch sizes in one test is what makes that
/// impossible.
#[test]
fn the_measured_ratio_tracks_the_batch_size() {
    let mut one =
        AuthorityPublicationWorkload::open(config("size-one", 1)).expect("the store opens");
    let mut five =
        AuthorityPublicationWorkload::open(config("size-five", 5)).expect("the store opens");

    let (small, small_metrics) = one.measure().expect("a round publishes");
    let (large, large_metrics) = five.measure().expect("a round publishes");

    assert_eq!(small.indexed, 1);
    assert_eq!(large.indexed, 5);
    assert_ne!(
        small_metrics.decisions, large_metrics.decisions,
        "two batch sizes must not report the same numerator"
    );
    assert_eq!(
        small_metrics.cas_attempts, large_metrics.cas_attempts,
        "the denominator is per-round and does not vary with batch size"
    );
}

/// Successive rounds must keep publishing rather than replaying.
///
/// Transaction identities are minted per `(round, slot)`. If that uniqueness
/// broke, the publication path would answer the second round as an idempotent
/// replay and `measure` would refuse — so this is the guard on the identity
/// scheme, not on the store.
#[test]
fn successive_rounds_publish_rather_than_replay() {
    let mut workload =
        AuthorityPublicationWorkload::open(config("rounds", 2)).expect("the store opens");

    let (first, _) = workload.measure().expect("round one publishes");
    let (second, _) = workload
        .measure()
        .expect("round two publishes, it does not replay");

    assert_eq!(first.indexed, 2);
    assert_eq!(second.indexed, 2);
    assert!(
        second.generation_after > first.generation_after,
        "each published round advances the head generation: {} then {}",
        first.generation_after,
        second.generation_after
    );
}
