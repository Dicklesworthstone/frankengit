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
    // NOTE: this checks the DECLARATION only. Cargo unifies features across the
    // whole graph, so a manifest saying `default-features = false` can still be
    // built with defaults on because some other crate asked for them. That is
    // not hypothetical here — see `reported_feature_set_matches_the_resolved_graph`
    // below, which is the check that actually constrains the built artifact.
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

/// The features Cargo actually resolved for `asupersync`, from `Cargo.lock`'s
/// sibling record in the workspace metadata.
///
/// Read from the lockfile's resolved graph rather than from any manifest,
/// because the declaration is not what gets linked.
fn resolved_asupersync_features() -> Option<Vec<String>> {
    // `cargo metadata` is not available to a test without spawning cargo, which
    // a unit test must not do. What *is* available cheaply and offline is the
    // lockfile: if `asupersync-macros` resolved, then the `proc-macros` feature
    // is on, because that is the only thing that pulls it.
    let lock = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .parent()?
            .join("Cargo.lock"),
    )
    .ok()?;
    let mut features = Vec::new();
    if lock.contains("name = \"asupersync-macros\"") {
        features.push("proc-macros".to_owned());
    }
    Some(features)
}

#[test]
fn reported_feature_set_matches_the_resolved_graph() {
    // The check that constrains the built artifact rather than the declaration.
    //
    // `ProfileIdentity` reports `ASUPERSYNC_FEATURES` into evidence. If the
    // resolved graph enables a feature this crate did not declare — which
    // Cargo's workspace-wide feature unification lets any *other* crate do —
    // then every replay record this node writes names a feature set that was
    // not the one linked. An identity that quietly disagrees with the build is
    // worse than no identity, because it is trusted.
    let Some(resolved) = resolved_asupersync_features() else {
        // No lockfile reachable (crate built outside the workspace); the
        // declaration check above is the only one available, and it already ran.
        return;
    };

    for feature in &resolved {
        assert!(
            ASUPERSYNC_FEATURES.contains(&feature.as_str()),
            "the resolved graph enables asupersync feature `{feature}`, but \
             ASUPERSYNC_FEATURES reports {ASUPERSYNC_FEATURES:?}. Some crate in \
             this workspace is enabling it through Cargo's feature unification, \
             so the profile identity written into evidence does not describe the \
             build that actually linked. Fix the crate that widened it, or \
             update ASUPERSYNC_FEATURES to tell the truth."
        );
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
