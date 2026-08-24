//! FG-028c acceptance: the baseline e2e script is registered with the runner.
//!
//! `scripts/e2e/run_all.sh` discovers suites rather than listing them, so
//! nothing in the repository states that the FG-028c baseline is part of the
//! suite. Discovery-by-convention means a script can stop being collected
//! without any file changing to say so, and an anchor artifact that runs
//! nowhere is worse than a missing one: later beads are told to compare
//! against it.
//!
//! This asserts the registration directly, against the real runner at its
//! pre-execution entry point (`--list`), so the check costs nothing and
//! starts no servers.
//!
//! WHAT THIS CATCHES: the script being moved out of `suites/`, renamed, or
//! deleted, and any change to `ra_script_id` that alters the id this suite is
//! recorded under.
//!
//! WHAT THIS DOES NOT CATCH, measured rather than assumed: loss of the
//! executable bit. Discovery is `find "$root" -type f -name '*.sh'`
//! (run_all.sh:254) with no permission predicate, and a scratch tree
//! containing a chmod -x script listed it just the same. The header comment
//! on run_all.sh describes an executable convention that discovery does not
//! enforce, so do not read this test as guarding it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The id `run_all.sh` records this suite under: `suites-<area>-<name>`.
const EXPECTED_ID: &str = "suites-benchmark-perf_baseline";

fn repository_root() -> PathBuf {
    // crates/fgit-benchmark -> crates -> repository root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("manifest directory has a repository root two levels up")
        .to_path_buf()
}

/// Runs the real runner in list-only mode and returns its discovered ids.
fn discovered_ids() -> Vec<String> {
    let root = repository_root();
    let runner = root.join("scripts/e2e/run_all.sh");
    assert!(
        runner.is_file(),
        "e2e runner is missing at {}; this test locates it relative to \
         CARGO_MANIFEST_DIR and that assumption has broken",
        runner.display()
    );

    let output = Command::new("bash")
        .arg(&runner)
        .arg("--list")
        .current_dir(&root)
        .output()
        .expect("run the e2e runner in list-only mode");

    assert!(
        output.status.success(),
        "run_all.sh --list exited {:?}; stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // `--list` emits `<id>\t<absolute path>` per discovered script.
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split('\t').next())
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn baseline_suite_is_registered_with_the_e2e_runner() {
    let ids = discovered_ids();
    assert!(
        ids.iter().any(|id| id == EXPECTED_ID),
        "{EXPECTED_ID} is not discovered by scripts/e2e/run_all.sh, so the \
         FG-028c baseline runs nowhere. Discovered {} suites; benchmark-area \
         ids present: {:?}",
        ids.len(),
        ids.iter()
            .filter(|id| id.starts_with("suites-benchmark-"))
            .collect::<Vec<_>>()
    );
}

/// The presence assertion above is only worth its green if the matcher can
/// report absence. An id that is deliberately not in the tree proves the
/// comparison discriminates rather than matching anything it is handed.
#[test]
fn discovery_check_can_report_an_absent_suite() {
    let ids = discovered_ids();
    let absent = "suites-benchmark-this_suite_does_not_exist";
    assert!(
        !ids.iter().any(|id| id == absent),
        "{absent} was reported as discovered; the registration check cannot \
         distinguish present from absent and its green means nothing"
    );
    assert!(
        !ids.is_empty(),
        "run_all.sh --list discovered nothing at all, so the presence check \
         above would fail for a reason unrelated to this suite"
    );
}
