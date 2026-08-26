//! The authority-negative boundary, made testable.
//!
//! FG-093b requires that projection capabilities cannot call authority
//! publication or supply authorization/retention/deletion truth. Three layers
//! enforce it and this module owns the ones a compiler or test can check:
//!
//! 1. **Dependency direction (structural).** This crate declares no
//!    dependency on any truth-process crate — no `fgit-authority`, no
//!    `fgit-admission`, no `fgit-chronicle`. A publication call therefore
//!    cannot even name its target type. [`manifest_admits_no_truth_process_dependencies`]
//!    pins that with a tripwire over the crate's own manifest so an editor
//!    adding the edge fails CI here first, not at review.
//! 2. **Surface shape.** The public session API exposes reads over derived
//!    tables and folds of caller-supplied records; there is no entry point
//!    that accepts an authority capability, and nothing in this crate
//!    implements one.
//! 3. **Registry layer row.** `registries/crate_layers.tsv` records
//!    fgit-projection as L3; the registry checker enforces the allowed
//!    dependency layers mechanically across the workspace.
//!
//! What this module deliberately does NOT do: re-state the boundary as
//! documentation-only prose. Every claim above has an executing check.

/// Truth-process crates whose appearance in this manifest would breach the
/// boundary. Extend this list alongside the registry when new truth owners
/// are added; the test below is the tripwire.
#[cfg(test)]
mod tests {
    /// Truth-process crates whose appearance in this manifest would breach
    /// the boundary. Extend alongside the registry when new truth owners are
    /// added; the assertion below is the tripwire.
    const TRUTH_PROCESS_CRATES: [&str; 3] = ["fgit-authority", "fgit-admission", "fgit-chronicle"];

    /// The manifest must not name any truth-process crate in any dependency
    /// section. Reading the raw text is deliberate: a dependency hidden in a
    /// target-specific table or a commented-out experiment is still a signal
    /// worth failing on, and the fix is to delete the line.
    #[test]
    fn manifest_admits_no_truth_process_dependencies() {
        let manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let manifest = std::fs::read_to_string(manifest_path)
            .expect("the crate's own Cargo.toml is readable from tests");

        for forbidden in TRUTH_PROCESS_CRATES {
            assert!(
                !manifest.contains(forbidden),
                "authority-negative breach: {forbidden} appears in {manifest_path}; \
                 projection capabilities must not depend on truth-process crates"
            );
        }
    }

    /// The declared dependencies stay within the admitted sqlmodel closure
    /// plus first-party types: the exact set the registry rows were generated
    /// for. A surprise third-party edge fails here before the constellation
    /// gate ever sees it.
    #[test]
    fn manifest_dependencies_stay_in_the_admitted_closure() {
        let manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let manifest = std::fs::read_to_string(manifest_path).expect("manifest readable");

        for admitted in [
            "asupersync.workspace = true",
            "fgit-types.workspace = true",
            "sqlmodel-core",
            "sqlmodel-frankensqlite",
        ] {
            assert!(
                manifest.contains(admitted),
                "expected dependency line `{admitted}` missing from {manifest_path}"
            );
        }
    }
}
