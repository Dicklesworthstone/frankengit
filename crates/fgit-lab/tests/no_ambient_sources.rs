//! Structural guards over the laboratory's own sources.
//!
//! The lab's determinism claim rests on it owning time and entropy. Two things
//! enforce that: the capability mask (checked in `harness`'s unit tests, which
//! is a runtime property) and this file, which checks the *source* — because a
//! call to `SystemTime::now()` inside the lab would compile perfectly well and
//! quietly destroy replay for everyone downstream.
//!
//! These are guard tests, not process artifacts: the build fails when the
//! invariant breaks, and they exist because the defect class they catch is
//! invisible in review and only shows up as an unreproducible run weeks later.

use std::fs;
use std::path::{Path, PathBuf};

fn production_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(!files.is_empty(), "no sources under {}", root.display());
    files.sort();
    files
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("readable entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// File contents with comment-only lines removed.
///
/// Prose may name a forbidden source; code may not.
fn code_of(path: &Path) -> String {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The portion of a file outside its `#[cfg(test)]` module.
fn non_test_code(path: &Path) -> String {
    let code = code_of(path);
    match code.find("#[cfg(test)]") {
        Some(index) => code[..index].to_owned(),
        None => code,
    }
}

#[test]
fn no_production_source_reads_an_ambient_clock() {
    // Every one of these returns a value that differs run to run, which is
    // precisely what a replayable trace cannot contain.
    const FORBIDDEN: [&str; 6] = [
        "SystemTime",
        "Instant::now",
        "UNIX_EPOCH",
        "elapsed()",
        "std::time::Instant",
        "chrono",
    ];

    for path in production_sources() {
        let code = non_test_code(&path);
        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "ambient clock `{needle}` used in {}; the lab's only clock is VirtualClock",
                path.display()
            );
        }
    }
}

#[test]
fn no_production_source_draws_ambient_entropy() {
    const FORBIDDEN: [&str; 7] = [
        "getrandom",
        "thread_rng",
        "OsRng",
        "random()",
        "from_entropy",
        "RandomState",
        "DefaultHasher",
    ];

    for path in production_sources() {
        let code = non_test_code(&path);
        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "ambient entropy `{needle}` used in {}; the lab's only source is SeededEntropy",
                path.display()
            );
        }
    }
}

#[test]
fn no_production_source_iterates_an_unordered_collection() {
    // `HashMap`/`HashSet` iteration order is randomised per process, so a
    // trace built by walking one is not reproducible even with a fixed seed.
    // The lab uses `BTreeMap`/`BTreeSet` throughout for exactly this reason.
    const FORBIDDEN: [&str; 2] = ["HashMap", "HashSet"];

    for path in production_sources() {
        let code = non_test_code(&path);
        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "`{needle}` in {} has nondeterministic iteration order; use the BTree equivalent",
                path.display()
            );
        }
    }
}

#[test]
fn no_production_source_contains_a_placeholder_marker() {
    const MARKERS: [&str; 2] = ["todo!(", "unimplemented!("];

    for path in production_sources() {
        let code = non_test_code(&path);
        for marker in MARKERS {
            assert!(
                !code.contains(marker),
                "placeholder marker `{marker}` in {}",
                path.display()
            );
        }
    }
}

#[test]
fn the_crate_root_forbids_unsafe_code_in_its_first_lines() {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("crate root is readable");
    assert!(
        lib.lines()
            .take(20)
            .any(|line| line.trim() == "#![forbid(unsafe_code)]"),
        "the crate root must declare #![forbid(unsafe_code)] within its first 20 lines"
    );
}

#[test]
fn the_crate_root_states_the_evidence_boundary() {
    // The bead requires the evidence boundary to be stated in the crate docs.
    // Asserting it mechanically stops it from being trimmed away later by
    // someone tidying the module header, which is exactly how a scoping
    // caveat quietly becomes an overclaim.
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("crate root is readable");

    assert!(
        lib.contains("Evidence boundary"),
        "the crate docs must carry an explicit evidence-boundary section"
    );
    for required in [
        "logical interleavings",
        "worker parking",
        "blocking-pool",
        "signal",
        "FG-011b",
    ] {
        assert!(
            lib.contains(required),
            "the evidence boundary must name `{required}`"
        );
    }
    assert!(
        lib.contains("Neither class substitutes for the"),
        "the boundary must say the two evidence classes do not substitute for each other"
    );
}

#[test]
fn the_manifest_declares_no_second_runtime_and_no_path_dependency() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("manifest is readable");

    for forbidden in ["tokio", "async-std", "smol", "glommio", "monoio"] {
        assert!(
            !manifest.contains(forbidden),
            "`{forbidden}` must never appear in this crate's manifest"
        );
    }
    assert!(
        !manifest.contains("path = "),
        "first-party deps are wired through [workspace.dependencies], not relative paths"
    );
    assert!(
        !manifest.contains("[patch"),
        "[patch] bypasses the closed dependency universe"
    );
    assert!(
        !manifest.contains("build = "),
        "this crate declares no build script"
    );
    assert!(
        manifest.contains("default-features = false"),
        "the runtime dependency must disable default features"
    );
}
