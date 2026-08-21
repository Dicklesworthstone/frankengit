//! The crate's dependency footprint is part of its contract.
//!
//! The constitutional checker enforces the *closed* dependency universe: every
//! crate in `Cargo.lock` must match an active allow row. It cannot enforce this
//! crate's stricter promise, because `DEP-013` admits any `fgit-*` crate, so a
//! future first-party dependency would pass the registry and still change what
//! `fgit-authority` is. The authority contract is meant to be implementable by
//! a backend with essentially nothing linked in; this test is the guard that
//! keeps it that way.

use std::path::Path;

/// The exact set this crate is allowed to depend on.
///
/// `fgit-types` supplies the one canonical `HeadGeneration` counter. Everything
/// else the contract needs — keys, tokens, outcomes, refusals — is either `std`
/// or owned here.
const PERMITTED: [&str; 1] = ["fgit-types"];

#[test]
fn the_crate_declares_only_its_permitted_dependencies() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", manifest_path.display()));

    let mut declared = Vec::new();
    let mut in_dependency_section = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependency_section = line == "[dependencies]"
                || line == "[dev-dependencies]"
                || line == "[build-dependencies]"
                || line.starts_with("[target.");
            continue;
        }
        if !in_dependency_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            declared.push(name.trim().trim_matches('"').to_owned());
        }
    }

    for name in &declared {
        assert!(
            PERMITTED.contains(&name.as_str()),
            "fgit-authority grew an undeclared dependency `{name}`; the authority contract is \
             std plus {PERMITTED:?} by design, so widening it is a contract change, not a tidy-up"
        );
    }
}

#[test]
fn the_crate_declares_no_build_script_or_proc_macro() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", manifest_path.display()));

    for line in manifest.lines() {
        let line = line.trim();
        assert!(
            !(line.starts_with("build =")
                || line.starts_with("links =")
                || line == "proc-macro = true"),
            "a build script, native link, or proc macro would expand the trusted build surface: \
             {line}"
        );
    }
}
