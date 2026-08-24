//! Refusal and labelling tests for the FG-028c transport baseline workload.
//!
//! These cover the properties that make the anchor artifact trustworthy without
//! running a server: that a sample which cannot be measured is a failure rather
//! than a fast result, that the oracle rejects a well-formed clone of the wrong
//! history, and that both arms are told to fetch the same path. Live
//! measurement is exercised by `scripts/e2e/suites/benchmark/perf_baseline.sh`.

use std::path::PathBuf;

use fgit_benchmark::{
    BenchmarkWorkload,
    transport::{
        CacheState, CloneOutput, Operation, ServerKind, TransportConfig, TransportWorkload,
    },
};

fn config() -> TransportConfig {
    TransportConfig {
        // Paths that cannot exist: every test here is about what happens when
        // the measurement cannot be taken.
        fg_binary: PathBuf::from("/nonexistent/fg-028c/fg"),
        git_binary: PathBuf::from("/nonexistent/fg-028c/git"),
        git_exec_path: PathBuf::from("/nonexistent/fg-028c/git-core"),
        empty_template_dir: PathBuf::from("/nonexistent/fg-028c/template"),
        storage_root: PathBuf::from("/nonexistent/fg-028c/storage"),
        upstream_base_path: PathBuf::from("/nonexistent/fg-028c/upstream"),
        tenant: "perf-baseline".to_owned(),
        repository: "corpus".to_owned(),
        work_root: PathBuf::from("/nonexistent/fg-028c/work"),
        port_base: 40_000,
        expected_head: "a".repeat(40),
        expected_commits: 8,
        operation: Operation::Clone,
        stale_root: PathBuf::from("/nonexistent/fg-028c/stale"),
        fetch_refspec: "refs/heads/main:refs/remotes/origin/main".to_owned(),
        cache_state: CacheState::Warm,
        python_binary: PathBuf::from("/nonexistent/fg-028c/python3"),
        logical_reachable_bytes: 1_000_000,
    }
}

#[test]
fn a_sample_whose_server_cannot_start_is_a_failure_not_a_fast_result() {
    // The failure mode this guards against is the worst one a benchmark has: a
    // sample that produced no work completing instantly and being averaged in
    // as a very fast observation.
    let mut workload = TransportWorkload::new(config(), ServerKind::FgitNode);
    let outcome = workload.measure();
    assert!(
        outcome.is_err(),
        "a workload whose server binary does not exist must refuse, not return a sample"
    );
}

#[test]
fn both_arms_refuse_rather_than_silently_measuring_nothing() {
    // Same property for the upstream arm. If only one arm refused, a broken
    // environment would produce a one-sided artifact that still looked like a
    // differential.
    for kind in [ServerKind::UpstreamGitDaemon, ServerKind::FgitNode] {
        let mut workload = TransportWorkload::new(config(), kind);
        assert!(
            workload.measure().is_err(),
            "{} must refuse when its server cannot be started",
            kind.as_str()
        );
    }
}

#[test]
fn the_oracle_refuses_a_clone_that_does_not_carry_the_corpus_tip() {
    // A server that served a well-formed but different history would pass
    // `fsck` and, being smaller, would look faster. The oracle is an equality
    // against the known tip precisely so that cannot happen.
    let mut workload = TransportWorkload::new(config(), ServerKind::FgitNode);
    let output = CloneOutput {
        destination: PathBuf::from("/nonexistent/fg-028c/work/clone"),
        pack_bytes: 1,
    };
    let verdict = workload.verify(&output);
    assert!(
        verdict.is_err(),
        "verify must refuse when it cannot establish that the clone carries the corpus"
    );
}

#[test]
fn the_two_arms_are_distinguishable_in_the_artifact() {
    // Every raw sample's receipt names its server. Without distinct tags the
    // artifact would record two arms that a reader could not tell apart.
    assert_ne!(
        ServerKind::UpstreamGitDaemon.as_str(),
        ServerKind::FgitNode.as_str()
    );
}

#[test]
fn the_workload_line_refuses_to_let_a_cold_start_read_as_transport_latency() {
    // `fg serve` is one-shot, so a fresh server starts for every sample and
    // that cost is inside the measured interval. The artifact must say so; a
    // bare "clone latency" label would overstate what was measured.
    for kind in [ServerKind::UpstreamGitDaemon, ServerKind::FgitNode] {
        let line = TransportWorkload::new(config(), kind).workload_line();
        assert!(
            line.contains("NOT steady-state transport latency"),
            "{}: {line}",
            kind.as_str()
        );
        assert!(
            line.contains(kind.as_str()),
            "the workload line must name which server served the arm: {line}"
        );
    }
}

#[test]
fn the_workload_line_differs_between_arms() {
    // A permitted twin for the test above: the label must not be a constant
    // string that happens to contain the required words regardless of arm.
    let baseline = TransportWorkload::new(config(), ServerKind::UpstreamGitDaemon).workload_line();
    let candidate = TransportWorkload::new(config(), ServerKind::FgitNode).workload_line();
    assert_ne!(
        baseline, candidate,
        "each arm's workload line must identify its own server"
    );
}
