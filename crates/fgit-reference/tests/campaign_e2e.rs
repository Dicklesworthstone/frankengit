//! The campaign worker the FG-003c end-to-end suite drives.
//!
//! This is `#[ignore]`d so an ordinary `cargo test` run never pays for it. The
//! e2e suite runs it explicitly with `-- --ignored`, which is the same shape
//! the deflate differential worker uses, and reads the NDJSON receipt it
//! writes.
//!
//! ## Why the receipt exists
//!
//! A bounded model result is only evidence if it states its bounds. The receipt
//! carries the declared bounds, the states and transitions actually explored,
//! how many offered inputs the model refused as structurally impossible, and
//! whether the walk was truncated — so a reader can tell an exhausted space
//! from one that hit its ceiling. `AGENTS.md` §16.3 permits a process artifact
//! only when it gates a named feature: this one is the evidence FG-003c's
//! acceptance is written against, and it is consumed by
//! `scripts/e2e/suites/model/model_campaign.sh`.

use std::path::PathBuf;

use fgit_reference::campaign::{Bounds, Property, Universe, run};

/// Where the suite asks for the receipt.
const ARTIFACT_DIR: &str = "FGIT_REFERENCE_CAMPAIGN_ARTIFACT_DIR";

/// Set to `deep` to run the documented wider bounds.
const MODE: &str = "FGIT_REFERENCE_CAMPAIGN_MODE";

#[test]
#[ignore = "driven by scripts/e2e/suites/model/model_campaign.sh"]
fn model_campaign() {
    let deep = std::env::var(MODE).is_ok_and(|value| value == "deep");
    let bounds = if deep { Bounds::DEEP } else { Bounds::DEFAULT };
    let universe = Universe::new(bounds);
    let report = run(&universe);

    let receipt = report.to_ndjson();
    if let Some(directory) = std::env::var_os(ARTIFACT_DIR) {
        let directory = PathBuf::from(directory);
        std::fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", directory.display()));
        let path = directory.join("receipt.ndjson");
        // One record, newline-terminated, so the file is valid NDJSON.
        std::fs::write(&path, format!("{receipt}\n"))
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
    }

    // Print unconditionally so a failing run is diagnosable from the captured
    // output even when no artifact directory was supplied.
    println!("{receipt}");

    for violation in &report.violations {
        println!(
            "violation: property={} detail={} path_len={}",
            violation.property.as_str(),
            violation.detail,
            violation.path.len()
        );
        match violation.to_trace_steps(universe.genesis()) {
            Ok(steps) => {
                for (index, step) in steps.iter().enumerate() {
                    println!(
                        "  step {index}: {} -> {}",
                        fgit_reference::trace::input_kind(&step.input),
                        step.observed.kind()
                    );
                }
            }
            Err(breach) => println!("  counterexample could not be replayed: {breach}"),
        }
    }

    assert!(
        report.violations.is_empty(),
        "the bounded campaign found {} violation(s); see the trace above",
        report.violations.len()
    );
    assert!(
        !report.truncated,
        "the walk hit its {} state ceiling before exhausting the space, so this is \
         not an exhaustive result for the declared bounds",
        bounds.max_states
    );
    // A campaign that explored almost nothing would satisfy both assertions
    // above while proving nothing at all.
    assert!(
        report.states_explored > 20,
        "only {} states explored; the campaign is not covering the space",
        report.states_explored
    );
    assert!(
        report.refused_transitions > 0,
        "the walk never offered a structurally impossible input, so it never \
         established that illegal calls fail closed"
    );
    assert_eq!(Property::ALL.len(), 5);
}
