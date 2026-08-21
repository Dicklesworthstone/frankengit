//! The reported runtime identity must match the runtime actually linked.
//!
//! [`fgit_runtime::boot::ASUPERSYNC_VERSION`] and
//! [`fgit_runtime::boot::ASUPERSYNC_FEATURES`] are what a node writes into its
//! evidence. If either drifts from the manifest, every replay record this node
//! produces is wrong in a way nothing else would catch — the code still
//! compiles, the tests still pass, and the identity quietly lies.

use std::fs;
use std::path::Path;

use fgit_runtime::boot::{ASUPERSYNC_FEATURES, ASUPERSYNC_VERSION, RuntimeProfile};

fn manifest() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the crate manifest is readable")
}

/// The `asupersync = { ... }` dependency line.
fn asupersync_dependency_line() -> String {
    manifest()
        .lines()
        .find(|line| line.trim_start().starts_with("asupersync"))
        .unwrap_or_else(|| panic!("the manifest must declare an asupersync dependency"))
        .to_owned()
}

#[test]
fn reported_version_matches_the_declared_dependency() {
    let line = asupersync_dependency_line();
    assert!(
        line.contains(&format!("version = \"{ASUPERSYNC_VERSION}\"")),
        "ASUPERSYNC_VERSION is `{ASUPERSYNC_VERSION}` but the manifest declares: {line}"
    );
}

#[test]
fn the_dependency_disables_default_features() {
    let line = asupersync_dependency_line();
    assert!(
        line.contains("default-features = false"),
        "the runtime dependency must disable default features, which pull in \
         proc-macros and nightly-outcome-try: {line}"
    );
}

#[test]
fn reported_feature_set_matches_the_declared_features() {
    let line = asupersync_dependency_line();

    if ASUPERSYNC_FEATURES.is_empty() {
        assert!(
            !line.contains("features = ["),
            "ASUPERSYNC_FEATURES is empty but the manifest selects features: {line}"
        );
    } else {
        for feature in ASUPERSYNC_FEATURES {
            assert!(
                line.contains(&format!("\"{feature}\"")),
                "ASUPERSYNC_FEATURES names `{feature}` but the manifest does not select it: {line}"
            );
        }
    }
}

#[test]
fn the_manifest_declares_no_second_runtime_and_no_path_dependency() {
    let text = manifest();
    for forbidden in ["tokio", "async-std", "smol", "glommio", "monoio"] {
        assert!(
            !text.contains(forbidden),
            "`{forbidden}` must never appear in this crate's manifest"
        );
    }
    assert!(
        !text.contains("path = "),
        "a release-facing crate may not commit a local path dependency"
    );
    assert!(
        !text.contains("[patch"),
        "[patch] bypasses the closed dependency universe"
    );
    assert!(
        !text.contains("build = "),
        "this crate declares no build script"
    );
}

#[test]
fn a_built_profile_reports_the_linked_version() {
    // End to end: the constant, the manifest, and what a live node reports.
    let identity = RuntimeProfile::deterministic().identity();
    assert_eq!(identity.asupersync_version, ASUPERSYNC_VERSION);
    assert!(
        identity
            .canonical_descriptor()
            .contains(&format!("asupersync={ASUPERSYNC_VERSION}"))
    );
}
