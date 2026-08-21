//! The forbidden feature and source graph, as a guard rather than a promise.
//!
//! The bead names this test, and it earns its place for a specific reason: the
//! `fsqlite` dependency line is the single place where this crate could quietly
//! acquire a C SQLite, a second async runtime, or an extension nobody admitted,
//! and the failure would be a `default-features` slip rather than anything a
//! reader would notice in a diff.
//!
//! The `fsqlite` line is **not present yet** — it lands with its registry rows —
//! so the feature assertions are written to activate the moment it appears. A
//! guard that silently passes because it found nothing is worse than no guard,
//! so each test that could be vacuous says so and asserts it is not.
//!
//! # What this test cannot check, and why that is recorded here
//!
//! It reads a manifest, so it sees *declared* features, not *resolved* ones. It
//! therefore cannot catch a sub-crate enabling a feature on its own behalf —
//! which is exactly how `linux-asupersync-uring` ends up on despite being
//! absent from our line (`fsqlite-vfs` defines `native` to include it). That
//! gap is real, it is documented in the crate root, and closing it needs a
//! resolved-graph check in the constellation tooling rather than a unit test
//! here.

use std::path::Path;

/// The only `fsqlite` features this profile admits.
const ADMITTED_FSQLITE_FEATURES: [&str; 2] = ["async-api", "native"];

/// Features that must never appear in the dependency line.
///
/// `linux-asupersync-uring` is listed even though it cannot be disabled
/// transitively: keeping it out of *our* line keeps the intent legible and
/// means the day `fsqlite-vfs` stops forcing it, nothing here has to change.
const FORBIDDEN_FSQLITE_FEATURES: [&str; 10] = [
    "default",
    "linux-asupersync-uring",
    "json",
    "fts3",
    "fts5",
    "rtree",
    "icu",
    "misc",
    "session",
    "wasm",
];

/// Crate names that may never appear in this crate's manifest.
const FORBIDDEN_CRATES: [&str; 12] = [
    "rusqlite",
    "libsqlite3-sys",
    "sqlite3-sys",
    "sqlite",
    "tokio",
    "async-std",
    "smol",
    "glommio",
    "monoio",
    "git2",
    "libgit2-sys",
    "gix",
];

/// The dependency name a manifest line declares, if it declares one.
///
/// The sub-key is split off *before* quotes are stripped. A quoted dotted key
/// spells its closing quote in the middle (`"fsqlite".workspace`), so trimming
/// first strands it on the name — a bug this project has already shipped once.
fn dependency_name(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
        return None;
    }
    let (key, _) = line.split_once('=')?;
    let key = key.trim();
    let name = key.split_once('.').map_or(key, |(head, _)| head);
    let name = name.trim().trim_matches('"');
    if name.is_empty() {
        return None;
    }
    Some(name.to_owned())
}

fn manifest() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn dependency_lines(manifest: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed == "[dependencies]"
                || trimmed == "[dev-dependencies]"
                || trimmed == "[build-dependencies]"
                || trimmed.starts_with("[target.");
            continue;
        }
        if inside && !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed.to_owned());
        }
    }
    lines
}

#[test]
fn the_parser_survives_every_spelling_of_the_fsqlite_line() {
    for (line, expected) in [
        ("fsqlite.workspace = true", Some("fsqlite")),
        (
            r#"fsqlite = { version = "0.3.7", default-features = false }"#,
            Some("fsqlite"),
        ),
        (r#""fsqlite".workspace = true"#, Some("fsqlite")),
        ("# fsqlite = ...", None),
        ("[dependencies]", None),
    ] {
        assert_eq!(
            dependency_name(line).as_deref(),
            expected,
            "the guard misread {line:?}, so anything it says about that line is worthless"
        );
    }
}

#[test]
fn no_forbidden_crate_appears_in_the_manifest() {
    let manifest = manifest();
    let lines = dependency_lines(&manifest);
    assert!(
        !lines.is_empty(),
        "the guard parsed no dependency lines at all, so it is watching nothing"
    );

    for line in &lines {
        let Some(name) = dependency_name(line) else {
            continue;
        };
        assert!(
            !FORBIDDEN_CRATES.contains(&name.as_str()),
            "`{name}` is forbidden: a C SQLite, an alternate async runtime, or a foreign Git \
             engine may never enter this crate's graph"
        );
    }
    // Also catch a forbidden crate named inside an inline table or a renamed
    // dependency, where it is not the key.
    for forbidden in FORBIDDEN_CRATES {
        let needle = format!("\"{forbidden}\"");
        assert!(
            !manifest.contains(&needle),
            "`{forbidden}` is named in the manifest; a rename does not make it admissible"
        );
    }
}

#[test]
fn the_manifest_declares_no_path_dependency_or_patch_section() {
    let manifest = manifest();
    for line in manifest.lines() {
        let trimmed = line.trim();
        assert!(
            !trimmed.starts_with("[patch") && !trimmed.starts_with("[replace"),
            "a patch or replace section bypasses the closed dependency universe: {trimmed}"
        );
    }
    for line in dependency_lines(&manifest) {
        assert!(
            !line.contains("path ="),
            "an unpublished path dependency may not enter a release-facing crate: {line}"
        );
    }
}

#[test]
fn the_manifest_declares_no_build_script_or_proc_macro() {
    for line in manifest().lines() {
        let trimmed = line.trim();
        assert!(
            !(trimmed.starts_with("build =")
                || trimmed.starts_with("links =")
                || trimmed == "proc-macro = true"),
            "a build script, native link, or proc macro expands the trusted build surface: \
             {trimmed}"
        );
    }
}

/// The `fsqlite` dependency line, once it exists.
fn fsqlite_line(manifest: &str) -> Option<String> {
    dependency_lines(manifest)
        .into_iter()
        .find(|line| dependency_name(line).as_deref() == Some("fsqlite"))
}

#[test]
fn the_fsqlite_line_if_present_admits_exactly_the_reviewed_features() {
    let manifest = manifest();
    let Some(line) = fsqlite_line(&manifest) else {
        // Not yet added: it lands with its registry rows. The assertions below
        // activate the moment it does, which is the point of writing them now.
        return;
    };

    assert!(
        line.contains("default-features = false"),
        "the fsqlite default feature set pulls json, fts5, rtree, icu, misc and the uring \
         profile; it must be off explicitly: {line}"
    );

    for forbidden in FORBIDDEN_FSQLITE_FEATURES {
        let quoted = format!("\"{forbidden}\"");
        assert!(
            !line.contains(&quoted),
            "feature `{forbidden}` is not admitted by the reviewed profile: {line}"
        );
    }
    for admitted in ADMITTED_FSQLITE_FEATURES {
        let quoted = format!("\"{admitted}\"");
        assert!(
            line.contains(&quoted),
            "feature `{admitted}` is required by the reviewed profile but absent: {line}"
        );
    }
}

#[test]
fn the_admitted_feature_set_is_the_one_the_crate_documents() {
    // Two statements of the same fact drift. This ties the constant to the
    // crate documentation so a change to one fails until the other follows.
    let lib = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("lib.rs"),
    )
    .expect("the crate root is readable");

    for admitted in ADMITTED_FSQLITE_FEATURES {
        assert!(
            lib.contains(admitted),
            "the crate root does not mention the admitted feature `{admitted}`"
        );
    }
    assert!(
        lib.contains("linux-asupersync-uring"),
        "the crate root must keep explaining why the uring feature cannot be disabled; \
         deleting that paragraph would restore a claim we know to be false"
    );
    assert!(
        lib.contains("default-features = false"),
        "the crate root must state the default feature set is off"
    );
}

// ---------------------------------------------------------------------------
// The BLAKE3 force point (FG-069a / GoldLotus ruling 7613).
//
// This crate declares `blake3` and never imports it. That is deliberate: the
// edge exists so Cargo's feature unification applies `pure` across the fsqlite
// closure, which is what keeps blake3 off its host-assembled path. An unused
// dependency is also precisely the thing a later reader deletes while tidying,
// and deleting this one silently restores native assembly with nothing failing.
// So it is pinned here.
// ---------------------------------------------------------------------------

/// The workspace manifest, which is where the `pure` feature is actually set.
///
/// This crate inherits with `blake3.workspace = true`, so the feature list lives
/// two directories up. Read rather than assumed: a guard that only checked the
/// local line would pass while the feature it exists to pin had been dropped.
fn workspace_manifest() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("Cargo.toml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn the_blake3_force_point_is_declared_by_this_crate() {
    let manifest = manifest();
    let names: Vec<String> = dependency_lines(&manifest)
        .iter()
        .filter_map(|line| dependency_name(line))
        .collect();
    assert!(
        !names.is_empty(),
        "the guard parsed no dependency lines, so it is watching nothing"
    );
    assert!(
        names.iter().any(|name| name == "blake3"),
        "the blake3 edge is gone. It is not unused: it is the force point that \
         applies `pure` across the fsqlite closure, and without it blake3 links \
         its host-assembled path again. Restore it rather than deleting this test"
    );
}

#[test]
fn the_workspace_blake3_entry_still_carries_pure() {
    let workspace = workspace_manifest();
    assert!(
        workspace.contains("[workspace.dependencies]"),
        "the workspace manifest has no [workspace.dependencies] table; this guard \
         read the wrong file and proves nothing"
    );

    let line = workspace
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("blake3"))
        .expect("the workspace must declare blake3; this crate inherits it");

    assert!(
        line.contains("\"pure\""),
        "the workspace blake3 entry no longer enables `pure`, so the force point \
         this crate carries has nothing to force: {line}"
    );
}

#[test]
fn neon_is_never_enabled_because_it_panics_the_build() {
    // Not a style rule. blake3's build.rs aborts outright:
    //
    //     if is_pure() && is_neon() { panic!("It doesn't make sense to enable
    //     both \"pure\" and \"neon\"."); }
    //
    // Feature unification is additive and graph-wide, so a `neon` enabled
    // anywhere combines with our `pure` and kills the build rather than
    // degrading to a slower hash. Caught here for the two manifests we own; a
    // `neon` arriving from a third-party crate needs the resolved-graph check,
    // for the same reason this file cannot see `linux-asupersync-uring`.
    for (label, text) in [
        ("this crate", manifest()),
        ("the workspace", workspace_manifest()),
    ] {
        for line in text.lines().map(str::trim) {
            if line.starts_with('#') || !line.starts_with("blake3") {
                continue;
            }
            assert!(
                !line.contains("\"neon\""),
                "{label} enables blake3/neon alongside `pure`; blake3's build script \
                 panics on that combination rather than picking one: {line}"
            );
        }
    }
}
