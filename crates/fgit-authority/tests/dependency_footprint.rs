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
/// Each entry is here for one capability that must not be reimplemented:
///
/// * `fgit-types` — the canonical identity, counter, and refusal vocabularies.
///   A parallel `HeadGeneration` or a locally invented refusal code would be a
///   second contract.
/// * `fgit-codec` — canonical byte encoding and the seal, decision, batch, and
///   head schemas. Transaction identity is a digest over canonical bytes, so
///   hand-rolling the encoding here would fork the identity.
/// * `fgit-crypto` — domain-separated digests and the closed identity-domain
///   registry. Domain separation is a security property, not a formatting
///   choice, and it belongs to one owner.
///
/// The storage contract itself — keys, version tokens, outcomes, ambiguity,
/// fault injection — remains `std` only. Adding anything to this list is a
/// contract change and needs a reason of the same kind.
const PERMITTED: [&str; 3] = ["fgit-types", "fgit-codec", "fgit-crypto"];

/// The dependency name a manifest line declares, if it declares one.
///
/// Cargo spells one dependency several ways, and they must all resolve to the
/// same name:
///
/// ```text
/// fgit-types.workspace = true          // dotted sub-key
/// fgit-types = { workspace = true }    // inline table
/// fgit-types = "1"                     // bare version
/// ```
///
/// The dotted form is the one that caught this guard out: splitting on `=`
/// alone yields `fgit-types.workspace`, which matches no permitted name and
/// makes the guard fail for the wrong reason. A crate name cannot contain a
/// dot, so everything from the first dot onwards is a sub-key.
fn dependency_name(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
        return None;
    }
    let (key, _) = line.split_once('=')?;
    // Split the sub-key off *before* stripping quotes. A quoted dotted key
    // spells the closing quote in the middle -- `"fgit-types".workspace` -- so
    // trimming first leaves it stranded on the name.
    let key = key.trim();
    let name = key.split_once('.').map_or(key, |(head, _)| head);
    let name = name.trim().trim_matches('"');
    if name.is_empty() {
        return None;
    }
    Some(name.to_owned())
}

#[test]
fn the_dependency_name_parser_handles_every_cargo_spelling() {
    assert_eq!(
        dependency_name("fgit-types.workspace = true").as_deref(),
        Some("fgit-types"),
        "the dotted sub-key form must resolve to the crate name"
    );
    assert_eq!(
        dependency_name("fgit-types = { workspace = true }").as_deref(),
        Some("fgit-types")
    );
    assert_eq!(
        dependency_name("fgit-types = \"0.0.1\"").as_deref(),
        Some("fgit-types")
    );
    assert_eq!(
        dependency_name("\"fgit-types\".workspace = true").as_deref(),
        Some("fgit-types"),
        "a quoted key is still the same dependency"
    );
    assert_eq!(dependency_name("# a comment"), None);
    assert_eq!(dependency_name("[dependencies]"), None);
    assert_eq!(dependency_name(""), None);
    assert_eq!(dependency_name("no-equals-sign"), None);
}

#[test]
fn the_crate_declares_only_its_permitted_dependencies() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", manifest_path.display()));

    let mut declared = Vec::new();
    let mut in_dependency_section = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependency_section = trimmed == "[dependencies]"
                || trimmed == "[dev-dependencies]"
                || trimmed == "[build-dependencies]"
                || trimmed.starts_with("[target.");
            continue;
        }
        if !in_dependency_section {
            continue;
        }
        if let Some(name) = dependency_name(trimmed) {
            declared.push(name);
        }
    }

    assert!(
        !declared.is_empty(),
        "the guard parsed no dependencies at all, which means it is watching nothing; \
         the manifest declares at least {PERMITTED:?}"
    );
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
