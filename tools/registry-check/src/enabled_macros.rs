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
use std::io::Read;
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
pub enum SurfaceState {
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
    pub const fn as_registry_word(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Absent => "absent",
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "not_applicable" => Some(Self::NotApplicable),
            "absent" => Some(Self::Absent),
            "disabled" => Some(Self::Disabled),
            "enabled" => Some(Self::Enabled),
            _ => None,
        }
    }
}

/// The enabled surface of the resolved graph, resolved for one host triple.
#[derive(Debug, Default)]
pub struct EnabledSurface {
    pub(crate) triple: String,
    pub(crate) build_scripts: BTreeSet<String>,
    /// Exact custom-build source paths from the enabled Cargo package IDs.
    pub(crate) build_script_sources: BTreeMap<String, BTreeSet<String>>,
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
pub fn resolve_enabled_surface(root: &Path) -> Result<EnabledSurface, String> {
    let host = host_triple()?;
    let configured_target = std::env::var("CARGO_BUILD_TARGET").ok();
    let triple = configured_target.clone().unwrap_or(host);
    let profile = std::env::var("FGIT_LINKAGE_PROFILE").unwrap_or_else(|_| "debug".to_owned());
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
    let build_root = linkage_build_root(
        &cargo_target_root(root),
        configured_target.as_deref(),
        &profile,
    )?;
    let linkage = collect_native_linkage(&build_root, &surface.build_scripts)?;
    let linkage = bind_linkage_instances(&build_root, &surface.build_script_sources, linkage)?;
    let observed = !linkage.is_empty();
    surface.native_linkage = linkage;
    surface.linkage_is_observed = observed;
    Ok(surface)
}

/// Where cargo leaves build-script output for this workspace.
fn cargo_target_root(root: &Path) -> std::path::PathBuf {
    root.join(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()))
}

fn linkage_build_root(
    target_root: &Path,
    target: Option<&str>,
    profile: &str,
) -> Result<std::path::PathBuf, String> {
    // An explicit target puts even a host build below target/<triple>. Never
    // scan sibling target/profile directories and attribute them to this run.
    for value in target.into_iter().chain(std::iter::once(profile)) {
        if value.is_empty()
            || value == "."
            || value == ".."
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(format!(
                "invalid native-linkage target/profile component `{value}`"
            ));
        }
    }
    let root = target.map_or_else(|| target_root.to_owned(), |triple| target_root.join(triple));
    Ok(root.join(profile).join("build"))
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
/// Read all supported Cargo layouts within one selected target/profile:
/// `build/<pkg>-<hash>/output`, `build/<pkg>/<hash>/output`, and the pinned
/// nightly's `build/<pkg>/<hash>/run/stdout`. These are cached observations,
/// not a current-build or release attestation. In particular, a matching name
/// does not prove that the package version, features or source revision match.
fn collect_native_linkage(
    build_root: &Path,
    enabled: &BTreeSet<String>,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut linkage: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in read_build_directory(build_root)? {
        let path = entry.path();
        let Some(dir_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if enabled.contains(dir_name) {
            for hash_dir in read_build_directory(&path)? {
                if hash_dir
                    .file_type()
                    .map_err(|error| error.to_string())?
                    .is_dir()
                {
                    absorb_output(&hash_dir.path().join("output"), dir_name, &mut linkage)?;
                    absorb_output(&hash_dir.path().join("run/stdout"), dir_name, &mut linkage)?;
                }
            }
        } else {
            let package = strip_build_hash(dir_name);
            if package != dir_name && enabled.contains(package) {
                absorb_output(&path.join("output"), package, &mut linkage)?;
            }
        }
    }
    Ok(linkage)
}

fn read_build_directory(path: &Path) -> Result<Vec<std::fs::DirEntry>, String> {
    match std::fs::read_dir(path) {
        Ok(entries) => {
            let entries = entries
                .take(100_001)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    format!(
                        "cannot enumerate native-linkage evidence at {}: {error}",
                        path.display()
                    )
                })?;
            if entries.len() > 100_000 {
                return Err(format!(
                    "native-linkage directory limit exceeded at {}",
                    path.display()
                ));
            }
            Ok(entries)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!(
            "cannot read native-linkage evidence at {}: {error}",
            path.display()
        )),
    }
}

/// Resolve a run fingerprint back to the compiled build script and its exact
/// Cargo metadata source path. A stale version with the same package name is
/// not evidence about the enabled package instance. This checks Cargo's pinned
/// cache format, not build freshness or the authenticity of a release artifact.
fn bind_linkage_instances(
    build_root: &Path,
    sources: &BTreeMap<String, BTreeSet<String>>,
    candidates: BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut bound = BTreeMap::new();
    for (package, paths) in sources {
        if !candidates.contains_key(package) {
            continue;
        }
        let instances = package_cache_instances(build_root, package)?;
        let mut compiled = BTreeSet::new();
        for (instance, fingerprint) in &instances {
            let hash_path = fingerprint.join("build-script-build-script-build");
            let Some(hash) = read_linkage_text(&hash_path)? else {
                continue;
            };
            let Some(hash) = cargo_fingerprint_word(hash.trim()) else {
                continue;
            };
            // The old layout puts .d beside the binary; the pinned layout uses
            // out/. Check the zero-rule source lines, not substring matches.
            for directory in [instance.clone(), instance.join("out")] {
                for file in read_build_directory(&directory)? {
                    if file.path().extension().is_some_and(|ext| ext == "d") {
                        let Some(text) = read_linkage_text(&file.path())? else {
                            continue;
                        };
                        if paths.iter().any(|source| {
                            text.lines()
                                .any(|line| line == format!("{}:", source.replace(' ', "\\ ")))
                        }) {
                            compiled.insert(hash);
                        }
                    }
                }
            }
        }
        for (instance, fingerprint) in &instances {
            let run = fingerprint.join("run-build-script-build-script-build.json");
            let Some(run) = read_linkage_text(&run)? else {
                continue;
            };
            if run_build_fingerprint(&run).is_some_and(|hash| compiled.contains(&hash)) {
                absorb_output(&instance.join("output"), package, &mut bound)?;
                absorb_output(&instance.join("run/stdout"), package, &mut bound)?;
            }
        }
    }
    Ok(bound)
}

fn package_cache_instances(
    build_root: &Path,
    package: &str,
) -> Result<Vec<(std::path::PathBuf, std::path::PathBuf)>, String> {
    let mut instances = Vec::new();
    for entry in read_build_directory(build_root)? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == package {
            for nested in read_build_directory(&entry.path())? {
                if nested
                    .file_type()
                    .map_err(|error| error.to_string())?
                    .is_dir()
                {
                    instances.push((nested.path(), nested.path().join("fingerprint")));
                }
            }
        } else if strip_build_hash(name) == package {
            let profile = build_root
                .parent()
                .ok_or("native linkage build root lacks a profile")?;
            instances.push((entry.path(), profile.join(".fingerprint").join(name)));
        }
    }
    Ok(instances)
}

fn cargo_fingerprint_word(text: &str) -> Option<u64> {
    if text.len() != 16 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0_u8; 8];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(u64::from_le_bytes(bytes))
}

fn run_build_fingerprint(text: &str) -> Option<u64> {
    // The pinned run fingerprint contains a single build_script_build tuple:
    // [package-id-hash, "build_script_build", public, compiled-fingerprint].
    // Reject duplicates and unknown shapes instead of guessing which compiled
    // instance an unrecognized Cargo cache format means.
    let (_, deps) = text.split_once("\"deps\"")?;
    let deps = deps
        .trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('[')?
        .trim_start()
        .strip_prefix('[')?;
    let (entry, tail) = deps.split_once(']')?;
    if !tail.trim_start().starts_with(']') {
        return None;
    }
    let fields = entry.split(',').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 4
        || fields[1] != "\"build_script_build\""
        || !matches!(fields[2], "true" | "false")
    {
        return None;
    }
    fields[0].parse::<u64>().ok()?;
    fields[3].parse().ok()
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

fn absorb_output(
    path: &Path,
    package: &str,
    linkage: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<(), String> {
    let Some(text) = read_linkage_text(path)? else {
        return Ok(());
    };
    // Empty output is an observed script, not missing evidence. A malformed or
    // unreadable file, conversely, must never establish an observed empty set.
    linkage
        .entry(package.to_owned())
        .or_default()
        .extend(parse_linkage_lines(&text));
    Ok(())
}

const MAX_LINKAGE_TEXT_BYTES: u64 = 16 * 1024 * 1024;

fn read_linkage_text(path: &Path) -> Result<Option<String>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "cannot read native-linkage evidence at {}: {error}",
                path.display()
            ));
        }
    };
    let mut text = String::new();
    file.take(MAX_LINKAGE_TEXT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| {
            format!(
                "cannot read native-linkage evidence at {}: {error}",
                path.display()
            )
        })?;
    if text.len() as u64 > MAX_LINKAGE_TEXT_BYTES {
        return Err(format!(
            "native-linkage output limit exceeded at {}",
            path.display()
        ));
    }
    Ok(Some(text))
}

/// Cargo accepts both the `cargo:` and newer `cargo::` emission prefixes, and a
/// build script may use either; blake3 mixes them in one file.
pub fn parse_linkage_lines(text: &str) -> BTreeSet<String> {
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
pub fn parse_enabled_surface(text: &str, triple: String) -> Result<EnabledSurface, String> {
    let mut has_build_script = BTreeMap::new();
    let mut has_proc_macro = BTreeMap::new();
    let mut name_of = BTreeMap::new();
    let mut script_source_of = BTreeMap::new();

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
            if kinds.contains("custom-build")
                && let Some(source) = json_string_field(target, "src_path")
            {
                script_source_of.insert(id.clone(), source);
            }
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
            if let Some(source) = script_source_of.get(id) {
                surface
                    .build_script_sources
                    .entry(name.clone())
                    .or_default()
                    .insert(source.clone());
            }
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
pub struct SurfaceRow {
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
pub fn governing_row<'a>(rows: &'a [SurfaceRow], package: &str) -> Option<&'a SurfaceRow> {
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
pub fn check_enabled_macro_surface(
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
pub fn observed_state_for(
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
pub fn check_macro_surface(root: &Path, report: &mut Report) {
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

/// `GoldLotus` ruling 3: linking native object code is a property of the build,
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
    report.notes.push(format!(
        "native-linkage policy evaluated against cached build-script observations for {}; these do not attest the current package instances, features, source revision or release build",
        surface.triple,
    ));
    for (package, libraries) in &surface.native_linkage {
        if libraries.is_empty() {
            continue;
        }
        // Only a build script can emit link directives, so a package without an
        // ENABLED build script in our own resolved graph cannot have produced
        // this output for us. The target directory is not necessarily ours
        // alone: `CARGO_TARGET_DIR` is commonly shared across checkouts, and on
        // the machine this was written it held 471 build directories against a
        // 206-package graph, nine of them emitting native linkage for packages
        // FrankenGit does not depend on at all. Judging our registry against
        // another project's build would make this gate's verdict depend on what
        // else someone happened to compile - the same reproducibility defect
        // this gate exists to refuse.
        if !surface.build_scripts.contains(package) {
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

/// Deliverable 2 (`GoldLotus` ruling 5): refuse a first-party crate acquiring a
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
pub fn derive_acquisitions(
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

    struct LinkageTree(std::path::PathBuf);

    impl LinkageTree {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("fgit-linkage-{}-{sequence}", std::process::id()));
            std::fs::create_dir(&path).expect("unique linkage test directory");
            Self(path)
        }

        fn output(&self, path: &str, text: &[u8]) {
            let path = self.0.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        fn read(&self, target: Option<&str>, profile: &str) -> BTreeMap<String, BTreeSet<String>> {
            let root = linkage_build_root(&self.0, target, profile).unwrap();
            collect_native_linkage(&root, &BTreeSet::from(["crossbeam-utils".to_owned()])).unwrap()
        }
    }

    impl Drop for LinkageTree {
        fn drop(&mut self) {
            // Each test owns a create-new, process/sequence-specific tree.
            std::fs::remove_dir_all(&self.0).expect("remove owned linkage fixture");
        }
    }

    #[test]
    fn all_cargo_layouts_reach_the_linkage_policy_with_a_permitted_twin() {
        for output in [
            "debug/build/crossbeam-utils-0123456789abcdef/output",
            "debug/build/crossbeam-utils/0123456789abcdef/output",
            "debug/build/crossbeam-utils/0123456789abcdef/run/stdout",
        ] {
            let tree = LinkageTree::new();
            tree.output(output, b"cargo::rustc-link-lib=static=forbidden_engine\n");
            let observed = tree.read(None, "debug");
            assert_eq!(observed.len(), 1, "{output}");
            let surface = EnabledSurface {
                triple: "x86_64-unknown-linux-gnu".to_owned(),
                build_scripts: BTreeSet::from(["crossbeam-utils".to_owned()]),
                native_linkage: observed,
                linkage_is_observed: true,
                ..EnabledSurface::default()
            };
            let mut row = SurfaceRow {
                id: "DEP-TEST".to_owned(),
                crate_pattern: "crossbeam-utils".to_owned(),
                ffi_policy: "no_ffi".to_owned(),
                build_script: SurfaceState::Enabled,
                proc_macro: SurfaceState::Absent,
            };
            let mut denied = Report::new();
            check_native_linkage_policy(&surface, &[row.clone()], &mut denied);
            assert_eq!(denied.errors.len(), 1, "{output}: {:?}", denied.errors);
            assert!(denied.errors[0].contains("forbidden_engine"));
            row.ffi_policy = "dependency_reviewed_boundary".to_owned();
            let mut allowed = Report::new();
            check_native_linkage_policy(&surface, &[row], &mut allowed);
            assert!(allowed.errors.is_empty(), "{:?}", allowed.errors);
            assert!(
                allowed
                    .notes
                    .iter()
                    .any(|note| note.contains("do not attest"))
            );
        }
    }

    #[test]
    fn empty_output_is_observed_but_missing_and_unrelated_outputs_are_not() {
        let tree = LinkageTree::new();
        assert!(tree.read(None, "debug").is_empty());
        tree.output("debug/build/unrelated/0123456789abcdef/run/stdout", b"");
        assert!(tree.read(None, "debug").is_empty());
        tree.output(
            "debug/build/crossbeam-utils/0123456789abcdef/run/stdout",
            b"",
        );
        let found = tree.read(None, "debug");
        assert_eq!(found.len(), 1);
        assert!(found["crossbeam-utils"].is_empty());
    }

    #[test]
    fn selected_target_and_profile_do_not_mix_sibling_builds() {
        let tree = LinkageTree::new();
        tree.output(
            "release/build/crossbeam-utils/0123456789abcdef/run/stdout",
            b"cargo:rustc-link-lib=release_only\n",
        );
        tree.output(
            "other-target/debug/build/crossbeam-utils/0123456789abcdef/run/stdout",
            b"cargo:rustc-link-lib=other_target\n",
        );
        assert!(tree.read(None, "debug").is_empty());
        tree.output(
            "debug/build/crossbeam-utils/0123456789abcdef/run/stdout",
            b"cargo:rustc-link-lib=host_debug\n",
        );
        let selected = tree.read(None, "debug");
        assert_eq!(
            selected["crossbeam-utils"],
            BTreeSet::from(["rustc-link-lib=host_debug".to_owned()])
        );
        let cross = tree.read(Some("other-target"), "debug");
        assert_eq!(
            cross["crossbeam-utils"],
            BTreeSet::from(["rustc-link-lib=other_target".to_owned()])
        );
        assert!(tree.read(Some("host-target"), "debug").is_empty());
    }

    #[test]
    fn invalid_target_and_profile_paths_are_refused() {
        let tree = LinkageTree::new();
        for invalid in ["", ".", "..", "../release", "/tmp/other", "a/b", "a\\b"] {
            assert!(linkage_build_root(&tree.0, None, invalid).is_err());
            assert!(linkage_build_root(&tree.0, Some(invalid), "debug").is_err());
        }
        assert!(linkage_build_root(&tree.0, Some("x86_64-unknown-linux-gnu"), "release").is_ok());
    }

    #[test]
    fn corrupt_and_non_file_output_cannot_count_as_empty_evidence() {
        let tree = LinkageTree::new();
        let root = linkage_build_root(&tree.0, None, "debug").unwrap();
        let enabled = BTreeSet::from(["crossbeam-utils".to_owned()]);
        let output = "debug/build/crossbeam-utils/0123456789abcdef/run/stdout";
        tree.output(output, &[0xff]);
        assert!(
            collect_native_linkage(&root, &enabled)
                .unwrap_err()
                .contains("cannot read")
        );
        std::fs::remove_file(tree.0.join(output)).unwrap();
        std::fs::create_dir(tree.0.join(output)).unwrap();
        assert!(collect_native_linkage(&root, &enabled).is_err());
    }

    #[test]
    fn evidence_read_bound_accepts_the_limit_and_refuses_one_more_byte() {
        let tree = LinkageTree::new();
        let path = tree.0.join("bounded-output");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_LINKAGE_TEXT_BYTES).unwrap();
        assert_eq!(
            read_linkage_text(&path).unwrap().unwrap().len() as u64,
            MAX_LINKAGE_TEXT_BYTES
        );
        file.set_len(MAX_LINKAGE_TEXT_BYTES + 1).unwrap();
        assert!(
            read_linkage_text(&path)
                .unwrap_err()
                .contains("output limit exceeded")
        );
    }

    #[test]
    fn repeated_observation_is_deterministic_and_never_attests_a_release() {
        let tree = LinkageTree::new();
        tree.output(
            "debug/build/crossbeam-utils/ffffffffffffffff/run/stdout",
            b"cargo:rustc-link-lib=z\ncargo:rustc-link-lib=a\n",
        );
        tree.output(
            "debug/build/crossbeam-utils/0000000000000000/output",
            b"cargo::rustc-link-lib=a\n",
        );
        let first = tree.read(None, "debug");
        assert_eq!(first, tree.read(None, "debug"));
        assert_eq!(first["crossbeam-utils"].len(), 2);
        let surface = EnabledSurface {
            triple: "test-target".to_owned(),
            native_linkage: first,
            linkage_is_observed: true,
            ..EnabledSurface::default()
        };
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &[], &mut report);
        assert!(report.notes[0].contains("cached"));
        assert!(report.notes[0].contains("do not attest the current package instances"));
    }

    #[test]
    fn cached_output_is_bound_to_the_enabled_package_source_in_each_layout() {
        for layout in 0..3 {
            let tree = LinkageTree::new();
            let source = tree.0.join("registry/crossbeam-utils-1.0.0/build.rs");
            let old_source = tree.0.join("registry/crossbeam-utils-0.9.0/build.rs");
            let build_root = linkage_build_root(&tree.0, None, "debug").unwrap();
            let sources = BTreeMap::from([(
                "crossbeam-utils".to_owned(),
                BTreeSet::from([source.display().to_string()]),
            )]);
            for (version, source, directive) in
                [(1_u64, &source, "current"), (2_u64, &old_source, "stale")]
            {
                let compiled_name = format!("{version:016x}");
                let run_name = format!("{:016x}", version + 10);
                let (compiled, run, compiled_fp, run_fp) = if layout == 0 {
                    (
                        format!("debug/build/crossbeam-utils-{compiled_name}"),
                        format!("debug/build/crossbeam-utils-{run_name}"),
                        format!("debug/.fingerprint/crossbeam-utils-{compiled_name}"),
                        format!("debug/.fingerprint/crossbeam-utils-{run_name}"),
                    )
                } else {
                    let compiled = format!("debug/build/crossbeam-utils/{compiled_name}");
                    let run = format!("debug/build/crossbeam-utils/{run_name}");
                    let compiled_fp = format!("{compiled}/fingerprint");
                    let run_fp = format!("{run}/fingerprint");
                    (compiled, run, compiled_fp, run_fp)
                };
                let hash = version
                    .to_le_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                tree.output(
                    &format!("{compiled_fp}/build-script-build-script-build"),
                    hash.as_bytes(),
                );
                let dep_info = format!("{}:\n", source.display());
                tree.output(
                    &format!("{compiled}/out/build_script_build.d"),
                    dep_info.as_bytes(),
                );
                let run_body =
                    format!("{{\"deps\":[[123,\"build_script_build\",false,{version}]]}}");
                tree.output(
                    &format!("{run_fp}/run-build-script-build-script-build.json"),
                    run_body.as_bytes(),
                );
                let output = if layout == 2 { "run/stdout" } else { "output" };
                tree.output(
                    &format!("{run}/{output}"),
                    format!("cargo:rustc-link-lib={directive}\n").as_bytes(),
                );
            }
            let cached = tree.read(None, "debug");
            assert_eq!(cached["crossbeam-utils"].len(), 2);
            let bound = bind_linkage_instances(&build_root, &sources, cached.clone()).unwrap();
            assert_eq!(
                bound["crossbeam-utils"],
                BTreeSet::from(["rustc-link-lib=current".to_owned()])
            );
            let wrong_source = BTreeMap::from([(
                "crossbeam-utils".to_owned(),
                BTreeSet::from(["/unrelated/build.rs".to_owned()]),
            )]);
            assert!(
                bind_linkage_instances(&build_root, &wrong_source, cached)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn unknown_or_ambiguous_fingerprints_do_not_bind_a_cached_instance() {
        assert_eq!(
            cargo_fingerprint_word("3bcfd4713472b2cc"),
            Some(14_749_977_299_165_433_659)
        );
        for invalid in ["", "ff", "xxxxxxxxxxxxxxxx", "3bcfd4713472b2cc00"] {
            assert_eq!(cargo_fingerprint_word(invalid), None);
        }
        assert_eq!(
            run_build_fingerprint(r#"{"deps":[[123,"build_script_build",false,42]]}"#),
            Some(42)
        );
        for invalid in [
            r#"{"deps":[]}"#,
            r#"{"deps":[[123,"build_script_build",null,42]]}"#,
            r#"{"deps":[[123,"build_script_build",false,"42"]]}"#,
            r#"{"deps":[[123,"build_script_build",false,42],[124,"build_script_build",false,43]]}"#,
        ] {
            assert_eq!(run_build_fingerprint(invalid), None, "{invalid}");
        }
    }

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
        let present: BTreeSet<String> = std::iter::once("winapi".to_owned()).collect();
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
        let enabled: BTreeSet<String> = std::iter::once("serde".to_owned()).collect();
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
            std::iter::once("serde_derive".to_owned()).collect(),
        );
        vendors.insert(
            "thiserror".to_owned(),
            std::iter::once("thiserror-impl".to_owned()).collect(),
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
        assert_eq!(
            derive_acquisitions(manifest, &pm, &vendors, &fp),
            Vec::new()
        );
    }

    /// `YellowLotus`: a guard nobody has seen fail is not yet a guard. Plant a
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
        assert_eq!(
            derive_acquisitions(manifest, &pm, &vendors, &fp),
            Vec::new()
        );

        // Same crate, same manifest line shape, derive feature resolved on.
        vendors.insert(
            "zerocopy".to_owned(),
            std::iter::once("zerocopy-derive".to_owned()).collect(),
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
        // blake3 must be in OUR graph for its linkage to be judged at all.
        surface.build_scripts.insert("blake3".to_owned());
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
        assert_eq!(report.errors, Vec::<String>::new());
        assert_eq!(report.notes.len(), 1, "{:?}", report.notes);
        assert!(report.notes[0].contains("not evaluated"));
    }

    /// Linkage from a package that is NOT in our resolved graph must be ignored.
    ///
    /// `CARGO_TARGET_DIR` is commonly shared between checkouts. Without this
    /// filter the gate judges our registry against whatever else happened to be
    /// compiled on the machine, which is both a false-refusal source and a
    /// reproducibility defect.
    #[test]
    fn linkage_from_a_package_outside_our_graph_is_ignored() {
        let rows = vec![SurfaceRow {
            id: "DEP-003".to_owned(),
            crate_pattern: "serde*".to_owned(),
            ffi_policy: "no_ffi".to_owned(),
            build_script: SurfaceState::Enabled,
            proc_macro: SurfaceState::Absent,
        }];
        let mut surface = EnabledSurface {
            triple: "x86_64-unknown-linux-gnu".to_owned(),
            linkage_is_observed: true,
            ..EnabledSurface::default()
        };
        // Observed in a shared target dir, but `serde` has no enabled build
        // script in THIS surface, so the output cannot be ours.
        surface
            .native_linkage
            .insert("serde".to_owned(), parse_linkage_lines(REAL_BLAKE3_OUTPUT));
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &rows, &mut report);
        assert!(
            report.errors.is_empty(),
            "foreign build output must not be judged against our registry: {:?}",
            report.errors
        );

        // Same package, same emissions, but now it IS in our graph: refuse.
        surface.build_scripts.insert("serde".to_owned());
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &rows, &mut report);
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
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
        // blake3 must be in OUR graph for its linkage to be judged at all.
        surface.build_scripts.insert("blake3".to_owned());
        surface
            .native_linkage
            .insert("blake3".to_owned(), parse_linkage_lines(REAL_BLAKE3_OUTPUT));
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &rows, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);

        // Guard against this passing vacuously: with the package in the graph
        // and the same emissions, a denying row MUST refuse. Otherwise a future
        // change that stops evaluating anything would keep this test green.
        let denying = vec![SurfaceRow {
            ffi_policy: "no_ffi".to_owned(),
            ..rows.into_iter().next().expect("one row")
        }];
        let mut report = Report::new();
        check_native_linkage_policy(&surface, &denying, &mut report);
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
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
