//! FG-069: enumeration of the *enabled* build-script and proc-macro surface.
//!
//! `docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md` section 6 requires that
//! "the local verifier enumerates every enabled build script and proc macro and
//! compares it with the dependency registry". The pre-existing checks are a
//! different obligation: they refuse a build script or proc macro declared by a
//! *first-party* manifest. Neither one looks at what the resolved third-party
//! graph actually builds.
//!
//! Enabled is not the same set as present. `cargo metadata` without a platform
//! filter lists every package in `Cargo.lock`, including the Windows, wasm and
//! macOS packages that never build here. Measured at `e5c745a`: 37 build scripts
//! and 14 proc macros unfiltered, against 29 and 10 actually enabled on
//! `x86_64-unknown-linux-gnu`. Reporting the unfiltered number would overstate
//! the audited surface by eight build scripts, so this module resolves the
//! enabled set itself rather than reusing the unfiltered snapshot.
//!
//! The unfiltered snapshot is still needed, to tell `disabled` (the package has
//! a build script, but not on this platform) from `absent` (it has none at all).
//! Collapsing those two would let a package acquire a build script with no
//! registry signal at all, which is the drift this gate exists to refuse.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use crate::{
    MetadataSnapshot, Report, dependency_pattern_matches, json_array_objects,
    json_string_array_field, json_string_field, manifest_dependency_names,
};

/// Where one package's build script or proc macro stands in the resolved graph.
///
/// Four states rather than a boolean, because a boolean cannot distinguish "has
/// none" from "has one that this platform does not build", and that distinction
/// is the whole point of the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SurfaceState {
    /// The row governs no package in the lock at all: `std`, the deny patterns
    /// that correctly match nothing, and the external-tool rows.
    NotApplicable,
    /// No package this row governs declares one on any platform.
    Absent,
    /// Declared, but not built for the host platform.
    Disabled,
    /// Built for the host platform.
    Enabled,
}

impl SurfaceState {
    pub(crate) fn as_registry_word(self) -> &'static str {
        match self {
            SurfaceState::NotApplicable => "not_applicable",
            SurfaceState::Absent => "absent",
            SurfaceState::Disabled => "disabled",
            SurfaceState::Enabled => "enabled",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "not_applicable" => Some(SurfaceState::NotApplicable),
            "absent" => Some(SurfaceState::Absent),
            "disabled" => Some(SurfaceState::Disabled),
            "enabled" => Some(SurfaceState::Enabled),
            _ => None,
        }
    }
}

/// The enabled surface of the resolved graph, resolved for one host triple.
#[derive(Debug, Default)]
pub(crate) struct EnabledSurface {
    pub(crate) triple: String,
    pub(crate) build_scripts: BTreeSet<String>,
    pub(crate) proc_macros: BTreeSet<String>,
    /// Packages that emit `cargo:rustc-link-lib` / `rustc-link-search`, keyed by
    /// package name. Populated only for packages whose build script has already
    /// run, so this is evidence when present and silence when absent — never a
    /// proof of absence. See `linkage_is_observed`.
    pub(crate) native_linkage: BTreeMap<String, BTreeSet<String>>,
    pub(crate) linkage_is_observed: bool,
    /// Package name -> the proc-macro packages it depends on directly, at its
    /// resolved features. This is what makes the derive guard feature-aware:
    /// plain `zerocopy` maps to an empty set, `zerocopy` with `derive` maps to
    /// `zerocopy-derive`.
    pub(crate) proc_macro_vendors: BTreeMap<String, BTreeSet<String>>,
}

/// `--filter-platform` needs a concrete triple and the checker must not guess
/// one. `std::env::consts` gives arch and OS but not the vendor/env fields, and
/// `env!("TARGET")` would require a build script, which first-party crates are
/// forbidden. Asking rustc is the remaining honest option.
fn host_triple() -> Result<String, String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg("-vV")
        .output()
        .map_err(|error| format!("cannot execute rustc -vV: {error}"))?;
    if !output.status.success() {
        return Err(format!("rustc -vV failed (status {})", output.status));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("rustc -vV emitted non-UTF-8 output: {error}"))?;
    for line in text.lines() {
        if let Some(triple) = line.strip_prefix("host: ") {
            let triple = triple.trim();
            if triple.is_empty() {
                return Err("rustc -vV reported an empty host triple".to_owned());
            }
            return Ok(triple.to_owned());
        }
    }
    Err("rustc -vV output lacks a `host:` line".to_owned())
}

/// Resolve the enabled surface: platform-filtered, then reachability-filtered.
///
/// Platform filtering alone is not sufficient in principle. A package can sit in
/// the filtered graph while no workspace member reaches it, once optional
/// features prune an edge. Today the two agree exactly on this host, and that
/// agreement is worth re-deriving on every run rather than assuming.
///
/// Development edges are followed only out of workspace members. A dependency's
/// own dev-dependencies are never built, so counting them would inflate the
/// audited surface with packages that cannot run at all.
pub(crate) fn resolve_enabled_surface(root: &Path) -> Result<EnabledSurface, String> {
    let triple = host_triple()?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version=1",
            "--filter-platform",
        ])
        .arg(&triple)
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot execute cargo metadata --filter-platform: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata --filter-platform {triple} failed (status {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("cargo metadata emitted non-UTF-8 JSON: {error}"))?;
    let mut surface = parse_enabled_surface(&text, triple)?;
    let (linkage, observed) = collect_native_linkage(&cargo_target_root(root));
    surface.native_linkage = linkage;
    surface.linkage_is_observed = observed;
    Ok(surface)
}

/// Where cargo leaves build-script output for this workspace.
fn cargo_target_root(root: &Path) -> std::path::PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => root.join("target"),
    }
}

/// Harvest `cargo:rustc-link-lib` / `rustc-link-search` emissions from the
/// build-script `output` files cargo writes under the target directory.
///
/// This is the only honest oracle available to a checker that must not build:
/// whether a build script links native object code is decided when it RUNS, not
/// by anything readable in its manifest. So the evidence exists exactly when
/// someone has already built, and the second return value records whether any
/// was found. Callers must not read an empty map as "nothing links".
///
/// Both cargo layouts are handled: `build/<pkg>-<hash>/output` and the newer
/// `build/<pkg>/<hash>/output`.
fn collect_native_linkage(target_root: &Path) -> (BTreeMap<String, BTreeSet<String>>, bool) {
    let mut linkage: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut observed = false;
    let Ok(profiles) = std::fs::read_dir(target_root) else {
        return (linkage, observed);
    };
    for profile in profiles.flatten() {
        let build = profile.path().join("build");
        let Ok(entries) = std::fs::read_dir(&build) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(dir_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            // `build/<pkg>-<hash>/output`
            let direct = path.join("output");
            if direct.is_file() {
                observed = true;
                absorb_output(&direct, strip_build_hash(dir_name), &mut linkage);
            }
            // `build/<pkg>/<hash>/output`
            if let Ok(nested) = std::fs::read_dir(&path) {
                for hash_dir in nested.flatten() {
                    let candidate = hash_dir.path().join("output");
                    if candidate.is_file() {
                        observed = true;
                        absorb_output(&candidate, dir_name, &mut linkage);
                    }
                }
            }
        }
    }
    (linkage, observed)
}

/// `serde-1a2b3c4d5e6f7788` -> `serde`. The hash suffix is hex and fixed-width,
/// while package names may themselves contain `-`, so trim only a trailing
/// all-hex segment rather than splitting on the first dash.
fn strip_build_hash(dir_name: &str) -> &str {
    match dir_name.rsplit_once('-') {
        Some((name, suffix))
            if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            name
        }
        _ => dir_name,
    }
}

fn absorb_output(path: &Path, package: &str, linkage: &mut BTreeMap<String, BTreeSet<String>>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for value in parse_linkage_lines(&text) {
        linkage.entry(package.to_owned()).or_default().insert(value);
    }
}

/// Cargo accepts both the `cargo:` and newer `cargo::` emission prefixes, and a
/// build script may use either; blake3 mixes them in one file.
pub(crate) fn parse_linkage_lines(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        for prefix in ["cargo::", "cargo:"] {
            let Some(rest) = line.strip_prefix(prefix) else {
                continue;
            };
            for key in ["rustc-link-lib=", "rustc-link-search="] {
                if let Some(value) = rest.strip_prefix(key)
                    && !value.is_empty()
                {
                    // `key` already ends with '='; trimming it here dropped the
                    // separator and produced `rustc-link-libstatic=...`.
                    found.insert(format!("{key}{value}"));
                }
            }
            break;
        }
    }
    found
}

/// Split out from the subprocess so the reachability walk is directly testable
/// against pinned JSON rather than only against whatever this host resolves.
pub(crate) fn parse_enabled_surface(text: &str, triple: String) -> Result<EnabledSurface, String> {
    let mut has_build_script = BTreeMap::new();
    let mut has_proc_macro = BTreeMap::new();
    let mut name_of = BTreeMap::new();

    for package in json_array_objects(text, "packages")? {
        let name = json_string_field(package, "name")
            .ok_or_else(|| "cargo metadata package lacks name".to_owned())?;
        let id = json_string_field(package, "id")
            .ok_or_else(|| format!("cargo metadata package `{name}` lacks id"))?;
        let mut build_script = false;
        let mut proc_macro = false;
        for target in json_array_objects(package, "targets")? {
            let kinds = json_string_array_field(target, "kind")?;
            build_script |= kinds.contains("custom-build");
            proc_macro |= kinds.contains("proc-macro");
        }
        has_build_script.insert(id.clone(), build_script);
        has_proc_macro.insert(id.clone(), proc_macro);
        name_of.insert(id, name);
    }

    let members = json_string_array_field(text, "workspace_members")?;
    let mut edges: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    for node in json_array_objects(text, "nodes")? {
        let id = json_string_field(node, "id")
            .ok_or_else(|| "cargo metadata resolve node lacks id".to_owned())?;
        let mut out = Vec::new();
        for dep in json_array_objects(node, "deps")? {
            let Some(pkg) = json_string_field(dep, "pkg") else {
                continue;
            };
            // `dep_kinds` entries carry `"kind": null` for a normal edge, so an
            // absent string field means normal rather than malformed.
            let mut dev_only = true;
            for kind in json_array_objects(dep, "dep_kinds")? {
                match json_string_field(kind, "kind").as_deref() {
                    Some("development") => {}
                    _ => dev_only = false,
                }
            }
            out.push((pkg, dev_only));
        }
        edges.insert(id, out);
    }

    let mut reachable = BTreeSet::new();
    let mut stack: Vec<(String, bool)> = members.iter().map(|id| (id.clone(), true)).collect();
    while let Some((id, is_member)) = stack.pop() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        for (pkg, dev_only) in edges.get(&id).into_iter().flatten() {
            if *dev_only && !is_member {
                continue;
            }
            stack.push((pkg.clone(), false));
        }
    }

    let mut surface = EnabledSurface {
        triple,
        ..EnabledSurface::default()
    };
    for id in &reachable {
        let Some(name) = name_of.get(id) else {
            continue;
        };
        if has_build_script.get(id).copied().unwrap_or(false) {
            surface.build_scripts.insert(name.clone());
        }
        if has_proc_macro.get(id).copied().unwrap_or(false) {
            surface.proc_macros.insert(name.clone());
        }
    }

    // Direct proc-macro edges, for the derive guard. Computed over the same
    // filtered graph, so a proc macro a platform never builds cannot make a
    // dependency look like it hands over a derive here.
    for (id, out) in &edges {
        let Some(name) = name_of.get(id) else {
            continue;
        };
        let mut macros = BTreeSet::new();
        for (pkg, dev_only) in out {
            if *dev_only {
                continue;
            }
            if has_proc_macro.get(pkg).copied().unwrap_or(false)
                && let Some(macro_name) = name_of.get(pkg)
            {
                macros.insert(macro_name.clone());
            }
        }
        surface.proc_macro_vendors.insert(name.clone(), macros);
    }
    Ok(surface)
}

/// One dependency-registry row, reduced to the fields this gate reads.
#[derive(Debug, Clone)]
pub(crate) struct SurfaceRow {
    pub(crate) id: String,
    pub(crate) crate_pattern: String,
    pub(crate) ffi_policy: String,
    pub(crate) build_script: SurfaceState,
    pub(crate) proc_macro: SurfaceState,
}

/// Pick the row that governs `package`.
///
/// MUST stay in agreement with `active_policy_for_package`: exact pattern first,
/// then longest pattern, then lowest identifier. The duplication is deliberate
/// and temporary — this module owns the registry's two new columns while
/// `active_policy_for_package` owns the unsafe-policy columns, and factoring the
/// ordering into one shared helper is a follow-up for the checker's owner rather
/// than something this gate should do to a function it does not own. If the two
/// ever disagree, the bug is here.
pub(crate) fn governing_row<'a>(rows: &'a [SurfaceRow], package: &str) -> Option<&'a SurfaceRow> {
    rows.iter()
        .filter(|row| dependency_pattern_matches(&row.crate_pattern, package))
        .min_by(|left, right| {
            let left_exact = left.crate_pattern == package;
            let right_exact = right.crate_pattern == package;
            right_exact
                .cmp(&left_exact)
                .then_with(|| right.crate_pattern.len().cmp(&left.crate_pattern.len()))
                .then_with(|| left.id.cmp(&right.id))
        })
}

/// Compare the enabled surface with the registry and refuse on drift.
///
/// Drift is refused in both directions. A package that acquires a build script
/// with no registry row is the obvious direction; a row that claims a build
/// script the graph no longer has is the direction that quietly rots, because
/// nothing else in the lane ever reads it again.
pub(crate) fn check_enabled_macro_surface(
    unfiltered: &MetadataSnapshot,
    surface: &EnabledSurface,
    rows: &[SurfaceRow],
    governed: &BTreeMap<String, Vec<String>>,
    report: &mut Report,
) {
    for (row_id, packages) in governed {
        let Some(row) = rows.iter().find(|row| &row.id == row_id) else {
            continue;
        };
        let expected_build =
            observed_state(packages, &surface.build_scripts, &unfiltered.build_scripts);
        let expected_macro =
            observed_state(packages, &surface.proc_macros, &unfiltered.proc_macros);

        if row.build_script != expected_build {
            report.error(format!(
                "dependency registry row `{row_id}` ({}) records build_script `{}`, but the resolved graph for {} observes `{}`",
                row.crate_pattern,
                row.build_script.as_registry_word(),
                surface.triple,
                expected_build.as_registry_word(),
            ));
        }
        if row.proc_macro != expected_macro {
            report.error(format!(
                "dependency registry row `{row_id}` ({}) records proc_macro `{}`, but the resolved graph for {} observes `{}`",
                row.crate_pattern,
                row.proc_macro.as_registry_word(),
                surface.triple,
                expected_macro.as_registry_word(),
            ));
        }
    }

    // The literal constitution line-138 direction: an enabled build script or
    // proc macro that no active row governs at all.
    for package in surface
        .build_scripts
        .iter()
        .chain(surface.proc_macros.iter())
    {
        if governing_row(rows, package).is_none() {
            report.error(format!(
                "package `{package}` has an enabled build script or proc macro on {} but matches no active dependency-registry row",
                surface.triple,
            ));
        }
    }
}

/// Public wrapper so the admission-ledger generator can stamp a freshly admitted
/// row with the same value this gate will later demand of it.
pub(crate) fn observed_state_for(
    packages: &[String],
    enabled: &BTreeSet<String>,
    present: &BTreeSet<String>,
) -> SurfaceState {
    observed_state(packages, enabled, present)
}

/// Parse the two FG-069 columns out of the dependency registry.
fn load_surface_rows(root: &Path) -> Result<Vec<SurfaceRow>, String> {
    let path = root.join("registries").join("dependency_policy.tsv");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let Some(fields) = crate::dependency_policy_fields(line) else {
            // Arity is already enforced with a precise message by
            // `load_active_dependency_policies`; duplicating the error here
            // would report the same defect twice from two gates.
            continue;
        };
        if fields[9] != "active" {
            continue;
        }
        let build_script = SurfaceState::parse(fields[10]).ok_or_else(|| {
            format!(
                "dependency registry row `{}` has build_script `{}`; expected one of enabled, disabled, absent, not_applicable",
                fields[0], fields[10]
            )
        })?;
        let proc_macro = SurfaceState::parse(fields[11]).ok_or_else(|| {
            format!(
                "dependency registry row `{}` has proc_macro `{}`; expected one of enabled, disabled, absent, not_applicable",
                fields[0], fields[11]
            )
        })?;
        rows.push(SurfaceRow {
            id: fields[0].to_owned(),
            crate_pattern: fields[1].to_owned(),
            ffi_policy: fields[8].to_owned(),
            build_script,
            proc_macro,
        });
    }
    Ok(rows)
}

/// Which packages each row actually governs, under the registry's precedence.
fn governed_packages(
    rows: &[SurfaceRow],
    packages: &BTreeSet<String>,
) -> BTreeMap<String, Vec<String>> {
    let mut governed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        governed.entry(row.id.clone()).or_default();
    }
    for package in packages {
        if let Some(row) = governing_row(rows, package) {
            governed
                .entry(row.id.clone())
                .or_default()
                .push(package.clone());
        }
    }
    governed
}

/// The FG-069 constitution gate: enumerate the enabled macro surface, compare it
/// with the dependency registry, and refuse a first-party crate that acquires a
/// third-party derive macro.
pub(crate) fn check_macro_surface(root: &Path, report: &mut Report) {
    let unfiltered = match crate::cargo_metadata(root) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            report.error(format!(
                "enabled-macro enumeration needs cargo metadata: {error}"
            ));
            return;
        }
    };
    let surface = match resolve_enabled_surface(root) {
        Ok(surface) => surface,
        Err(error) => {
            report.error(format!("cannot resolve the enabled macro surface: {error}"));
            return;
        }
    };
    let rows = match load_surface_rows(root) {
        Ok(rows) => rows,
        Err(error) => {
            report.error(error);
            return;
        }
    };

    let all_packages: BTreeSet<String> = unfiltered
        .package_sources
        .keys()
        .map(|(name, _)| name.clone())
        .collect();
    let governed = governed_packages(&rows, &all_packages);
    check_enabled_macro_surface(&unfiltered, &surface, &rows, &governed, report);
    check_native_linkage_policy(&surface, &rows, report);
    check_first_party_derive_acquisition(root, &surface, report);
}

/// GoldLotus ruling 3: linking native object code is a property of the build,
/// not of the manifest, so a manifest cannot be the oracle for it. A build
/// script that emits `cargo:rustc-link-lib` or `rustc-link-search` for a package
/// whose registry `ffi_policy` denies a foreign engine is a refusal.
///
/// This gate is evidence-when-present and silent-when-absent: emissions are only
/// observable once a build script has actually run. It therefore never reports
/// "no native linkage" as a proven fact, and `linkage_is_observed` records which
/// case produced the result.
fn check_native_linkage_policy(surface: &EnabledSurface, rows: &[SurfaceRow], report: &mut Report) {
    if !surface.linkage_is_observed {
        // Silence here would be indistinguishable from "nothing links native
        // code", which is the exact overstatement this gate exists to prevent.
        // Say so in lane output instead.
        report.notes.push(format!(
            "native-linkage policy not evaluated: no build-script output found under the target directory for {}; build once to make this gate effective",
            surface.triple,
        ));
        return;
    }
    for (package, libraries) in &surface.native_linkage {
        if libraries.is_empty() {
            continue;
        }
        let Some(row) = governing_row(rows, package) else {
            continue;
        };
        if row.ffi_policy == "no_foreign_engine_declared" || row.ffi_policy == "no_ffi" {
            report.error(format!(
                "package `{package}` links native object code ({}) but dependency registry row `{}` declares ffi_policy `{}`",
                libraries.iter().cloned().collect::<Vec<_>>().join(", "),
                row.id,
                row.ffi_policy,
            ));
        }
    }
}

/// Deliverable 2's gate over every first-party manifest.
fn check_first_party_derive_acquisition(
    root: &Path,
    surface: &EnabledSurface,
    report: &mut Report,
) {
    let mut discovery = Report::new();
    let first_party: BTreeSet<String> = crate::workspace_crate_names(root, &mut discovery)
        .into_keys()
        .collect();
    for manifest in crate::workspace_manifest_paths(root, &mut discovery) {
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        for (dependency, reason) in derive_acquisitions(
            &text,
            &surface.proc_macros,
            &surface.proc_macro_vendors,
            &first_party,
        ) {
            report.error(format!(
                "first-party manifest {} acquires a third-party derive macro: `{dependency}` {reason}",
                crate::relative(root, &manifest),
            ));
        }
    }
}

/// Reduce one row's governed packages to the single state the row must record.
///
/// The states are ordered, so the strongest wins. A row whose governed packages
/// disagree would be a row that cannot be described honestly by one cell; none
/// exist today, and if one appears the strongest state is the safe reading
/// because it never under-reports the surface.
fn observed_state(
    packages: &[String],
    enabled: &BTreeSet<String>,
    present: &BTreeSet<String>,
) -> SurfaceState {
    if packages.is_empty() {
        return SurfaceState::NotApplicable;
    }
    packages
        .iter()
        .map(|package| {
            if enabled.contains(package) {
                SurfaceState::Enabled
            } else if present.contains(package) {
                SurfaceState::Disabled
            } else {
                SurfaceState::Absent
            }
        })
        .max()
        .unwrap_or(SurfaceState::Absent)
}

/// Deliverable 2 (GoldLotus ruling 5): refuse a first-party crate acquiring a
/// third-party derive macro.
///
/// The original bead asked for golden expansions of serde derives on the fg002
/// identity types. That premise is empty: first-party crates declare exactly
/// three third-party dependencies across every manifest — `asupersync`,
/// `fsqlite`, `fsqlite-types` — and `fgit-types` derives only std traits. There
/// is nothing to pin. Asserting the invariant directly is both cheaper and
/// stronger than pinning an empty set, and it keeps holding as the tree grows.
///
/// The rule is mechanical and needs no denylist of "crates that have derives".
/// A first-party manifest must not declare a direct dependency on a package that
/// either IS a proc macro, or — at its resolved features — directly depends on
/// one. Those are exactly the packages that can hand a derive to first-party
/// code. Measured at `e5c745a`: `asupersync`, `fsqlite` and `fsqlite-types` have
/// zero direct proc-macro dependencies and pass; `serde`, `thiserror`, `prost`,
/// `pin-project` and `bincode-next` all have one and would be refused.
///
/// Reading the *resolved* graph rather than a name list makes the rule
/// feature-aware for free. Plain `zerocopy` acquires no derive and is allowed;
/// `zerocopy` with the `derive` feature pulls `zerocopy-derive` and is refused.
/// A name list could not tell those apart.
pub(crate) fn derive_acquisitions(
    manifest_text: &str,
    proc_macros: &BTreeSet<String>,
    vendors: &BTreeMap<String, BTreeSet<String>>,
    first_party: &BTreeSet<String>,
) -> Vec<(String, String)> {
    let mut findings = Vec::new();
    // `manifest_dependency_names` already reads [dependencies],
    // [dev-dependencies], [build-dependencies] and [workspace.dependencies], in
    // both inline and [dependencies.NAME] table form, and resolves `package =`
    // renames to the real crate. A derive macro reaches first-party code through
    // a test fixture's dependency section long before it reaches src/, so the
    // dev and build sections are not optional here.
    for dependency in manifest_dependency_names(manifest_text) {
        if first_party.contains(&dependency) {
            continue;
        }
        if proc_macros.contains(&dependency) {
            findings.push((dependency.clone(), "is a proc-macro crate".to_owned()));
            continue;
        }
        if let Some(macros) = vendors.get(&dependency)
            && !macros.is_empty()
        {
            findings.push((
                dependency.clone(),
                format!(
                    "hands over the derive macro(s) {} at its resolved features",
                    macros.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const NORMAL_AND_DEV: &str = r#"{
      "packages": [
        {"name":"root","id":"path+file:///w#root@0.1.0","targets":[{"kind":["lib"]}]},
        {"name":"buildy","id":"registry+x#buildy@1.0.0","targets":[{"kind":["lib"]},{"kind":["custom-build"]}]},
        {"name":"macroy","id":"registry+x#macroy@1.0.0","targets":[{"kind":["proc-macro"]}]},
        {"name":"devonly","id":"registry+x#devonly@1.0.0","targets":[{"kind":["lib"]},{"kind":["custom-build"]}]},
        {"name":"buried","id":"registry+x#buried@1.0.0","targets":[{"kind":["lib"]},{"kind":["custom-build"]}]}
      ],
      "workspace_members": ["path+file:///w#root@0.1.0"],
      "resolve": {"nodes": [
        {"id":"path+file:///w#root@0.1.0","deps":[
          {"pkg":"registry+x#buildy@1.0.0","dep_kinds":[{"kind":null,"target":null}]},
          {"pkg":"registry+x#macroy@1.0.0","dep_kinds":[{"kind":"build","target":null}]},
          {"pkg":"registry+x#devonly@1.0.0","dep_kinds":[{"kind":"development","target":null}]}
        ]},
        {"id":"registry+x#buildy@1.0.0","deps":[
          {"pkg":"registry+x#buried@1.0.0","dep_kinds":[{"kind":"development","target":null}]}
        ]},
        {"id":"registry+x#macroy@1.0.0","deps":[]},
        {"id":"registry+x#devonly@1.0.0","deps":[]},
        {"id":"registry+x#buried@1.0.0","deps":[]}
      ]}
    }"#;

    #[test]
    fn dev_edges_are_followed_from_members_and_only_from_members() {
        let surface = parse_enabled_surface(NORMAL_AND_DEV, "test-triple".to_owned()).unwrap();
        // A member's own dev-dependency IS built (its tests run here).
        assert!(surface.build_scripts.contains("devonly"));
        // A dependency's dev-dependency is never built, so it must not inflate
        // the audited surface even though it sits in the lock.
        assert!(!surface.build_scripts.contains("buried"));
        assert!(surface.build_scripts.contains("buildy"));
        assert!(surface.proc_macros.contains("macroy"));
    }

    #[test]
    fn build_edges_count_as_enabled() {
        let surface = parse_enabled_surface(NORMAL_AND_DEV, "test-triple".to_owned()).unwrap();
        // `macroy` is reached only through a build edge; a proc macro that runs
        // at build time is exactly what this gate must enumerate.
        assert!(surface.proc_macros.contains("macroy"));
    }

    fn rows() -> Vec<SurfaceRow> {
        vec![
            SurfaceRow {
                id: "DEP-003".to_owned(),
                crate_pattern: "serde*".to_owned(),
                ffi_policy: "no_ffi".to_owned(),
                build_script: SurfaceState::Enabled,
                proc_macro: SurfaceState::Absent,
            },
            SurfaceRow {
                id: "DEP-219".to_owned(),
                crate_pattern: "serde_derive".to_owned(),
                ffi_policy: "no_foreign_engine_declared".to_owned(),
                build_script: SurfaceState::Absent,
                proc_macro: SurfaceState::Enabled,
            },
        ]
    }

    #[test]
    fn exact_row_beats_glob_row_for_the_same_package() {
        // DEP-003 `serde*` and DEP-219 `serde_derive` both match, and they carry
        // contradictory values. Precedence is what makes one cell per row honest;
        // without it DEP-003 would have to claim proc_macro=enabled, which is
        // false for serde, serde_core and serde_json.
        let rows = rows();
        let chosen = governing_row(&rows, "serde_derive").unwrap();
        assert_eq!(chosen.id, "DEP-219");
        let chosen = governing_row(&rows, "serde_json").unwrap();
        assert_eq!(chosen.id, "DEP-003");
    }

    #[test]
    fn a_row_governing_no_package_is_not_applicable() {
        assert_eq!(
            observed_state(&[], &BTreeSet::new(), &BTreeSet::new()),
            SurfaceState::NotApplicable
        );
    }

    #[test]
    fn present_but_not_enabled_is_disabled_not_absent() {
        let enabled = BTreeSet::new();
        let present: BTreeSet<String> = ["winapi".to_owned()].into_iter().collect();
        let packages = vec!["winapi".to_owned()];
        // Collapsing this to `absent` would let a package acquire a build script
        // on another platform with no registry signal at all.
        assert_eq!(
            observed_state(&packages, &enabled, &present),
            SurfaceState::Disabled
        );
    }

    #[test]
    fn enabled_wins_over_disabled_within_one_governed_set() {
        let enabled: BTreeSet<String> = ["serde".to_owned()].into_iter().collect();
        let present: BTreeSet<String> = ["serde".to_owned(), "serde_x".to_owned()]
            .into_iter()
            .collect();
        let packages = vec!["serde_x".to_owned(), "serde".to_owned()];
        assert_eq!(
            observed_state(&packages, &enabled, &present),
            SurfaceState::Enabled
        );
    }

    fn derive_world() -> (
        BTreeSet<String>,
        BTreeMap<String, BTreeSet<String>>,
        BTreeSet<String>,
    ) {
        let proc_macros: BTreeSet<String> =
            ["serde_derive".to_owned(), "thiserror-impl".to_owned()]
                .into_iter()
                .collect();
        let mut vendors = BTreeMap::new();
        vendors.insert(
            "serde".to_owned(),
            ["serde_derive".to_owned()].into_iter().collect(),
        );
        vendors.insert(
            "thiserror".to_owned(),
            ["thiserror-impl".to_owned()].into_iter().collect(),
        );
        // The three third-party dependencies first-party crates actually
        // declare, all with zero direct proc-macro edges at e5c745a.
        vendors.insert("asupersync".to_owned(), BTreeSet::new());
        vendors.insert("fsqlite".to_owned(), BTreeSet::new());
        vendors.insert("fsqlite-types".to_owned(), BTreeSet::new());
        // Plain zerocopy acquires no derive; the `derive` feature would.
        vendors.insert("zerocopy".to_owned(), BTreeSet::new());
        let first_party: BTreeSet<String> = ["fgit-types".to_owned(), "fgit-codec".to_owned()]
            .into_iter()
            .collect();
        (proc_macros, vendors, first_party)
    }

    /// The tree as it stands must pass, or the guard is useless: a gate that
    /// fires on the current tree gets weakened rather than obeyed.
    #[test]
    fn the_real_first_party_manifest_shape_passes() {
        let (pm, vendors, fp) = derive_world();
        let manifest = r#"
[package]
name = "fgit-chronicle"

[dependencies]
asupersync.workspace = true
fgit-types.workspace = true

[dev-dependencies]
fsqlite = { version = "0.3.7", default-features = false, features = ["native"] }
"#;
        assert!(derive_acquisitions(manifest, &pm, &vendors, &fp).is_empty());
    }

    /// YellowLotus: a guard nobody has seen fail is not yet a guard. Plant a
    /// row in every section, in both inline and table form, and require each
    /// one to be caught individually.
    #[test]
    fn a_planted_derive_is_caught_in_every_section_and_both_forms() {
        let (pm, vendors, fp) = derive_world();
        let planted = [
            (
                "dependencies inline",
                "[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\n",
            ),
            (
                "dev-dependencies inline",
                "[dev-dependencies]\nserde = \"1\"\n",
            ),
            (
                "build-dependencies inline",
                "[build-dependencies]\nserde = \"1\"\n",
            ),
            (
                "dependencies table",
                "[dependencies.serde]\nversion = \"1\"\n",
            ),
            (
                "dev-dependencies table",
                "[dev-dependencies.serde]\nversion = \"1\"\n",
            ),
            (
                "build-dependencies table",
                "[build-dependencies.serde]\nversion = \"1\"\n",
            ),
            (
                "workspace.dependencies inline",
                "[workspace.dependencies]\nserde = \"1\"\n",
            ),
        ];
        for (label, section) in planted {
            let manifest = format!("[package]\nname = \"fgit-x\"\n\n{section}");
            let found = derive_acquisitions(&manifest, &pm, &vendors, &fp);
            assert_eq!(
                found.len(),
                1,
                "{label}: expected exactly one finding, got {found:?}"
            );
            assert_eq!(found[0].0, "serde", "{label}");
        }
    }

    /// A rename must not launder the dependency past the guard.
    #[test]
    fn a_renamed_derive_dependency_is_still_caught() {
        let (pm, vendors, fp) = derive_world();
        let inline = "[dependencies]\nharmless = { version = \"1\", package = \"serde\" }\n";
        let found = derive_acquisitions(inline, &pm, &vendors, &fp);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "serde");

        let table = "[dependencies.harmless]\nversion = \"1\"\npackage = \"serde\"\n";
        let found = derive_acquisitions(table, &pm, &vendors, &fp);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "serde");
    }

    /// A direct dependency on the proc-macro crate itself, not via a re-exporter.
    #[test]
    fn a_direct_proc_macro_dependency_is_caught() {
        let (pm, vendors, fp) = derive_world();
        let manifest = "[dependencies]\nserde_derive = \"1\"\n";
        let found = derive_acquisitions(manifest, &pm, &vendors, &fp);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "serde_derive");
        assert!(found[0].1.contains("proc-macro crate"), "{:?}", found[0].1);
    }

    /// The rule is feature-aware because it reads the resolved graph. A name
    /// list could not permit plain zerocopy while refusing zerocopy+derive.
    #[test]
    fn a_dependency_with_no_resolved_derive_edge_is_permitted() {
        let (pm, mut vendors, fp) = derive_world();
        let manifest = "[dependencies]\nzerocopy = { version = \"0.8\", features = [\"simd\"] }\n";
        assert!(derive_acquisitions(manifest, &pm, &vendors, &fp).is_empty());

        // Same crate, same manifest line shape, derive feature resolved on.
        vendors.insert(
            "zerocopy".to_owned(),
            ["zerocopy-derive".to_owned()].into_iter().collect(),
        );
        let found = derive_acquisitions(manifest, &pm, &vendors, &fp);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "zerocopy");
    }

    /// The emissions blake3 actually produced before the `pure` override was
    /// pinned. Taken from a real build-script output file, mixed `cargo:` and
    /// `cargo::` prefixes included, because that is what the parser must survive.
    const REAL_BLAKE3_OUTPUT: &str = "\
cargo::rustc-cfg=blake3_sse2_ffi
cargo::rustc-cfg=blake3_sse41_ffi
cargo:rustc-link-lib=static=blake3_sse2_sse41_avx2_assembly
cargo:rustc-link-search=native=/tmp/out
cargo::rustc-cfg=blake3_avx512_ffi
cargo:rustc-link-lib=static=blake3_avx512_assembly
";

    #[test]
    fn linkage_lines_are_parsed_under_both_cargo_prefixes() {
        let found = parse_linkage_lines(REAL_BLAKE3_OUTPUT);
        assert!(found.contains("rustc-link-lib=static=blake3_sse2_sse41_avx2_assembly"));
        assert!(found.contains("rustc-link-lib=static=blake3_avx512_assembly"));
        assert!(found.contains("rustc-link-search=native=/tmp/out"));
        // cfg emissions are not linkage and must not be swept in.
        assert_eq!(found.len(), 3, "{found:?}");
    }

    #[test]
    fn a_build_script_that_links_nothing_yields_no_linkage() {
        let found = parse_linkage_lines("cargo:rustc-cfg=foo\ncargo::rustc-check-cfg=cfg(bar)\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn build_hash_suffixes_are_trimmed_but_dashed_names_survive() {
        assert_eq!(strip_build_hash("serde-1a2b3c4d5e6f7788"), "serde");
        // A package whose own name contains a dash must not be truncated at the
        // first dash; only a trailing all-hex segment is a cargo hash.
        assert_eq!(
            strip_build_hash("bincode_derive-next"),
            "bincode_derive-next"
        );
        assert_eq!(
            strip_build_hash("crossbeam-utils-0011aabb"),
            "crossbeam-utils"
        );
        assert_eq!(strip_build_hash("blake3"), "blake3");
    }

    /// The gate must REFUSE when observed linkage contradicts the registry.
    #[test]
    fn observed_linkage_against_a_no_ffi_row_is_refused() {
        let rows = vec![SurfaceRow {
            id: "DEP-181".to_owned(),
            crate_pattern: "blake3".to_owned(),
            ffi_policy: "no_foreign_engine_declared".to_owned(),
            build_script: SurfaceState::Enabled,
            proc_macro: SurfaceState::Absent,
        }];
        let mut surface = EnabledSurface {
            triple: "x86_64-unknown-linux-gnu".to_owned(),
            linkage_is_observed: true,
            ..EnabledSurface::default()
        };
        surface
            .native_linkage
            .insert("blake3".to_owned(), parse_linkage_lines(REAL_BLAKE3_OUTPUT));
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &rows, &mut report);
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        assert!(report.errors[0].contains("blake3"));
        assert!(report.errors[0].contains("no_foreign_engine_declared"));
    }

    /// Absence of evidence must be VISIBLE, never a silent pass. This is the
    /// defect the first landed version had: the check early-returned and the
    /// lane looked clean.
    #[test]
    fn missing_linkage_evidence_is_reported_as_a_note_not_a_silent_pass() {
        let rows = Vec::new();
        let surface = EnabledSurface {
            triple: "x86_64-unknown-linux-gnu".to_owned(),
            linkage_is_observed: false,
            ..EnabledSurface::default()
        };
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &rows, &mut report);
        assert!(report.errors.is_empty());
        assert_eq!(report.notes.len(), 1, "{:?}", report.notes);
        assert!(report.notes[0].contains("not evaluated"));
    }

    /// A package that links native code but whose row permits it must pass.
    #[test]
    fn observed_linkage_against_a_permissive_row_is_allowed() {
        let rows = vec![SurfaceRow {
            id: "DEP-999".to_owned(),
            crate_pattern: "blake3".to_owned(),
            ffi_policy: "links_native_objects".to_owned(),
            build_script: SurfaceState::Enabled,
            proc_macro: SurfaceState::Absent,
        }];
        let mut surface = EnabledSurface {
            triple: "t".to_owned(),
            linkage_is_observed: true,
            ..EnabledSurface::default()
        };
        surface
            .native_linkage
            .insert("blake3".to_owned(), parse_linkage_lines(REAL_BLAKE3_OUTPUT));
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &rows, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
    }

    #[test]
    fn surface_state_words_round_trip() {
        for state in [
            SurfaceState::NotApplicable,
            SurfaceState::Absent,
            SurfaceState::Disabled,
            SurfaceState::Enabled,
        ] {
            assert_eq!(SurfaceState::parse(state.as_registry_word()), Some(state));
        }
        assert_eq!(SurfaceState::parse("true"), None);
    }
}
