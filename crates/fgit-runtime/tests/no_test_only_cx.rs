//! Structural guards over this crate's own production sources.
//!
//! The acceptance line "no test-only/detached `Cx` constructor occurs in a
//! production target" is not something a unit test can observe from inside the
//! program: by the time a test runs, the wrong constructor has already been
//! compiled in. So it is checked the only way it can be — by reading the
//! crate's sources and asserting the shape.
//!
//! These are guard tests, not process artifacts: they fail the build when the
//! invariant is broken, and they exist because the invariant is one an
//! ordinary reviewer misses.

use std::fs;
use std::path::{Path, PathBuf};

/// Every `.rs` file under `src/`.
fn production_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(
        !files.is_empty(),
        "no sources found under {}",
        root.display()
    );
    files.sort();
    files
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The file's code with comment-only lines removed.
///
/// Prose is allowed to mention a forbidden constructor; code is not.
fn code_of(path: &Path) -> String {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    text.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The portion of a file outside its `#[cfg(test)]` module.
///
/// The test module is the last item in every file in this crate, so cutting at
/// the `#[cfg(test)]` attribute yields exactly the production half.
fn non_test_code(path: &Path) -> String {
    let code = code_of(path);
    match code.find("#[cfg(test)]") {
        Some(index) => code[..index].to_owned(),
        None => code,
    }
}

#[test]
fn no_test_only_or_detached_context_constructor_in_production_code() {
    // `Cx::for_testing` is the constructor the integration profile names
    // explicitly; `LabRuntime` is the other way to obtain a context without a
    // production runtime.
    const FORBIDDEN: [&str; 4] = ["for_testing", "LabRuntime", "LabConfig", "Cx::detached"];

    for path in production_sources() {
        let code = non_test_code(&path);
        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "`{needle}` appears in production code in {}; production contexts come from \
                 Runtime/RuntimeHandle::request_cx_with_budget",
                path.display()
            );
        }
    }
}

#[test]
fn contexts_are_minted_only_by_the_production_factory_module() {
    // Every call into Asupersync's context factories must live in `boot.rs`,
    // which is the module that owns the node runtime. If a second module
    // starts minting contexts, the single production entry point has been
    // bypassed even if it used the right function.
    const FACTORIES: [&str; 2] = ["request_cx_with_budget", "try_request_cx_with_budget"];

    let mut minting_files = Vec::new();
    for path in production_sources() {
        let code = non_test_code(&path);
        if FACTORIES.iter().any(|factory| code.contains(factory)) {
            minting_files.push(
                path.file_name()
                    .expect("source file has a name")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }

    assert_eq!(
        minting_files,
        vec!["boot.rs".to_owned()],
        "exactly one module may mint production contexts"
    );
}

#[test]
fn the_production_factory_uses_both_runtime_owned_constructors() {
    // The profile names both: the panicking one for callers that own the
    // runtime, and the fallible one for callers racing teardown.
    let boot = non_test_code(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/boot.rs"));
    assert!(
        boot.contains("request_cx_with_budget"),
        "boot.rs must use Runtime::request_cx_with_budget"
    );
    assert!(
        boot.contains("try_request_cx_with_budget"),
        "boot.rs must use RuntimeHandle::try_request_cx_with_budget"
    );
}

#[test]
fn crate_root_forbids_unsafe_code_in_its_first_lines() {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("crate root is readable");
    let position = lib
        .lines()
        .take(20)
        .position(|line| line.trim() == "#![forbid(unsafe_code)]");
    assert!(
        position.is_some(),
        "the crate root must declare #![forbid(unsafe_code)] within its first 20 lines"
    );
}

#[test]
fn no_production_source_contains_an_unimplemented_marker() {
    // Placeholder markers are forbidden in commits; this makes that mechanical
    // rather than a review promise.
    const MARKERS: [&str; 3] = ["todo!(", "unimplemented!(", "unreachable!(\"TODO"];

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
