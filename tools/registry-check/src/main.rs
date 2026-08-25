#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod claims;
mod enabled_macros;

const REGISTRY_MARKER_V1: &str = "# franken-registry-v1";
const DEPENDENCY_POLICY_MARKER_V2: &str = "# franken-registry-v2";

/// Column count of `registries/dependency_policy.tsv` after FG-069 added
/// `build_script` and `proc_macro`. Named rather than repeated so a future
/// column cannot be added to `registry_schemas` while a length gate elsewhere
/// silently keeps skipping every row.
const DEPENDENCY_POLICY_COLUMNS: usize = 12;
const CONSTELLATION_MARKER: &str = "# franken-constellation-v1";
const LAYER_REPORT_MARKER: &str = "# franken-layer-report-v1";
const CRATE_LAYERS_FILE: &str = "registries/crate_layers.tsv";
const CRATE_LAYERS_COLUMNS: [&str; 5] = [
    "crate",
    "layer",
    "allowed_dependency_layers",
    "owner",
    "status",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckSet {
    All,
    Docs,
    Registries,
    Constitution,
    Constellation,
    CrateGraph,
    Claims,
    ClaimsStatus,
    LayerReport,
    LedgerPolicy,
    LedgerFsqlitePolicy,
    LedgerConstellation,
    LedgerUnsafe,
}

impl CheckSet {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("all") {
            "all" => Ok(Self::All),
            "docs" => Ok(Self::Docs),
            "registries" => Ok(Self::Registries),
            "constitution" => Ok(Self::Constitution),
            "constellation" => Ok(Self::Constellation),
            "crate-graph" => Ok(Self::CrateGraph),
            "claims" => Ok(Self::Claims),
            "claims-status" => Ok(Self::ClaimsStatus),
            "layer-report" => Ok(Self::LayerReport),
            "ledger-policy" => Ok(Self::LedgerPolicy),
            "ledger-fsqlite-policy" => Ok(Self::LedgerFsqlitePolicy),
            "ledger-constellation" => Ok(Self::LedgerConstellation),
            "ledger-unsafe" => Ok(Self::LedgerUnsafe),
            other => Err(format!(
                "unknown command `{other}`; expected all, docs, registries, constitution, constellation, crate-graph, claims, claims-status, layer-report, ledger-policy, ledger-fsqlite-policy, ledger-constellation, or ledger-unsafe"
            )),
        }
    }

    const fn includes_docs(self) -> bool {
        matches!(self, Self::All | Self::Docs)
    }

    const fn includes_registries(self) -> bool {
        matches!(self, Self::All | Self::Docs | Self::Registries)
    }

    const fn includes_constitution(self) -> bool {
        matches!(self, Self::All | Self::Constitution)
    }

    const fn is_ledger(self) -> bool {
        matches!(
            self,
            Self::LedgerPolicy
                | Self::LedgerFsqlitePolicy
                | Self::LedgerConstellation
                | Self::LedgerUnsafe
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    check_set: CheckSet,
    json: bool,
    root_override: Option<PathBuf>,
}

fn parse_invocation(arguments: impl IntoIterator<Item = String>) -> Result<Invocation, String> {
    let mut positional = Vec::new();
    let mut json = false;
    let mut root_override = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--json" => json = true,
            "--root" => {
                let Some(value) = arguments.next() else {
                    return Err("--root requires a directory path".to_owned());
                };
                if root_override.replace(PathBuf::from(value)).is_some() {
                    return Err("--root may be provided only once".to_owned());
                }
            }
            _ => positional.push(argument),
        }
    }
    let check_set = CheckSet::parse(positional.first().map(String::as_str))?;
    if positional.len() > 1 {
        return Err(format!(
            "unexpected positional arguments: {:?}",
            &positional[1..]
        ));
    }
    Ok(Invocation {
        check_set,
        json,
        root_override,
    })
}

#[derive(Debug)]
struct Report {
    errors: Vec<String>,
    notes: Vec<String>,
    markdown_files: usize,
    registry_rows: usize,
    rust_files: usize,
}

impl Report {
    const fn new() -> Self {
        Self {
            errors: Vec::new(),
            notes: Vec::new(),
            markdown_files: 0,
            registry_rows: 0,
            rust_files: 0,
        }
    }

    fn error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }
}

fn main() -> ExitCode {
    let invocation = match parse_invocation(env::args().skip(1)) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };

    let root = match invocation.root_override {
        Some(path) => match explicit_workspace_root(path) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(2);
            }
        },
        None => workspace_root(),
    };
    if invocation.check_set.is_ledger() {
        return match generate_admission_ledger(&root, invocation.check_set) {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("admission ledger generation failed: {error}");
                ExitCode::from(1)
            }
        };
    }
    if invocation.check_set == CheckSet::ClaimsStatus {
        return match claims::render_status(&root) {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("claim-status generation failed: {error}");
                ExitCode::from(1)
            }
        };
    }
    if invocation.check_set == CheckSet::LayerReport {
        let mut report = Report::new();
        let layer_report = evaluate_crate_layers(&root, &mut report);
        report.errors.sort();
        report.errors.dedup();
        print!("{}", layer_report.render());
        if report.errors.is_empty() {
            return ExitCode::SUCCESS;
        }
        for error in report.errors {
            eprintln!("layer-report error: {error}");
        }
        return ExitCode::from(1);
    }
    let mut report = Report::new();
    if invocation.check_set == CheckSet::Constellation {
        check_constellation_manifests(&root, &mut report);
        check_constellation(&root, &mut report);
    } else if invocation.check_set == CheckSet::CrateGraph {
        check_workspace_crate_graph(&root, &mut report);
        check_forbidden_artifacts(&root, &mut report);
    } else if invocation.check_set == CheckSet::Claims {
        claims::check(&root, &mut report);
        claims::check_readme(&root, &mut report);
    } else {
        check_required_files(&root, &mut report);
        // Hoisted out of `check_registries` deliberately. The pin compares a
        // Rust source constant against a document, so it belongs to BOTH the
        // registry lane (which enforces the vocabulary) and the constitution
        // lane (which is where `KNOWN_STATUSES` actually lives). Running it
        // only under `includes_registries` left `verify.sh constitution` blind
        // to a divergence introduced by editing Rust -- measured, not inferred:
        // with a seventh value planted in the ledger, constitution exited 0
        // while docs exited 1. The `||` rather than a call in each branch is
        // what keeps `All` from reporting every divergence twice.
        if invocation.check_set.includes_registries()
            || invocation.check_set.includes_constitution()
        {
            check_status_vocabulary_pin(&root, &mut report);
        }
        if invocation.check_set.includes_registries() {
            check_registries(&root, &mut report);
        }
        if invocation.check_set.includes_docs() {
            check_markdown(&root, &mut report);
            claims::check_readme(&root, &mut report);
            check_workflows(&root, &mut report);
            check_contract_phrases(&root, &mut report);
        }
        if invocation.check_set.includes_constitution() {
            check_rust_sources(&root, &mut report);
            check_workspace_crate_graph(&root, &mut report);
            let _ = evaluate_crate_layers(&root, &mut report);
            check_manifests(&root, &mut report);
            check_constellation(&root, &mut report);
            check_unsafe_ledger_policies(&root, &mut report);
            enabled_macros::check_macro_surface(&root, &mut report);
            check_toolchain(&root, &mut report);
        }
        check_forbidden_artifacts(&root, &mut report);
    }

    report.errors.sort();
    report.errors.dedup();
    if invocation.json {
        print_json(&report);
    } else {
        print_human(&report);
    }

    if report.errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn explicit_workspace_root(path: PathBuf) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("cannot resolve --root `{}`: {error}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!(
            "--root `{}` is not a directory",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// Resolves the repository root at runtime so a relocated binary can never
/// silently validate the checkout it was built from: prefer Cargo's runtime
/// manifest-dir variable, then walk upward from the current directory to the
/// repository sentinels, and fail closed otherwise.
fn workspace_root() -> PathBuf {
    if let Some(dir) = env::var_os("CARGO_MANIFEST_DIR")
        && let Some(root) = Path::new(&dir).parent().and_then(Path::parent)
        && root.join("registries").is_dir()
    {
        return root.to_path_buf();
    }
    let mut current = env::current_dir().expect("cannot read the current directory");
    loop {
        if current.join("registries/verification_lanes.tsv").is_file()
            && current.join("VERIFY_SPEC.md").is_file()
        {
            return current;
        }
        assert!(
            current.pop(),
            "cannot locate the FrankenGit repository root from the current directory"
        );
    }
}

fn check_required_files(root: &Path, report: &mut Report) {
    const REQUIRED: &[&str] = &[
        "Cargo.toml",
        "Cargo.lock",
        "constellation.lock",
        "rust-toolchain.toml",
        "LICENSE",
        "README.md",
        "ARCHITECTURE.md",
        "AGENTS.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md",
        "VERIFY_SPEC.md",
        "SECURITY_THREAT_MODEL.md",
        "docs/ADR-0001-CANONICAL-STATE.md",
        "docs/AGENT_PROTOCOL.md",
        "docs/ATP_GIT_PROFILE.md",
        "docs/CALM_AND_OBLIGATIONS.md",
        "docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md",
        "docs/FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md",
        "docs/FRESH_EYES_AUDIT_2026-08-19.md",
        "docs/FRANKENSUITE_DEEP_AUDIT_2026-08-19.md",
        "docs/GIT_COMPATIBILITY_MATRIX.md",
        "docs/GIT_TREE_FS.md",
        "docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md",
        "docs/INITIAL_ISSUE_BACKLOG.md",
        "docs/LICENSING_DECISION.md",
        "docs/LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md",
        "docs/NEGATIVE_EVIDENCE_LEDGER.md",
        "docs/NORMATIVE_PROTOCOL_CONTRACTS.md",
        "docs/OBJECT_STORE_DECISION_LOG.md",
        "docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md",
        "docs/RAPTORQ_PERMEATION_MAP.md",
        "docs/RESEARCH_PROVENANCE.md",
        "registries/README.md",
        "registries/calm_operations.tsv",
        "registries/claim_classes.tsv",
        "registries/claims.tsv",
        "registries/crate_layers.tsv",
        "registries/dependency_policy.tsv",
        "registries/durable_objects.tsv",
        "registries/evidence_packs.tsv",
        "registries/graph_views.tsv",
        "registries/invariants.tsv",
        "registries/negative_evidence.tsv",
        "registries/publication_primitives.tsv",
        "registries/verification_lanes.tsv",
        ".github/workflows/docs-integrity.yml",
        "ops/dsr/frankengit.yaml.example",
        "scripts/verify.sh",
        "tools/registry-check/Cargo.toml",
        "tools/registry-check/src/main.rs",
    ];

    for relative in REQUIRED {
        if !root.join(relative).is_file() {
            report.error(format!("missing required file: {relative}"));
        }
    }
}

/// How many coordination classes `docs/CALM_AND_OBLIGATIONS.md` section 1 declares.
const CALM_CLASS_COUNT: usize = 7;

fn registry_schemas() -> BTreeMap<&'static str, &'static [&'static str]> {
    BTreeMap::from([
        (
            "calm_operations.tsv",
            &[
                "id",
                "operation",
                "class",
                "authority",
                "proof",
                "fallback",
                "status",
            ][..],
        ),
        (
            "claim_classes.tsv",
            &[
                "id",
                "rank",
                "stronger_than",
                "required_evidence",
                "forbidden_upgrade",
                "status",
            ][..],
        ),
        (
            "claims.tsv",
            &[
                "id",
                "claim_class",
                "scope",
                "owner_invariant",
                "required_artifacts",
                "evidence_class",
                "status",
                "source_revision",
                "toolchain",
                "target_profile",
                "assumptions",
                "non_claims",
                "revalidation",
                "fallback_wording",
            ][..],
        ),
        (
            "crate_layers.tsv",
            &[
                "crate",
                "layer",
                "allowed_dependency_layers",
                "owner",
                "status",
            ][..],
        ),
        (
            "dependency_policy.tsv",
            &[
                "id",
                "crate_pattern",
                "scope",
                "decision",
                "owner",
                "rationale",
                "feature_policy",
                "unsafe_policy",
                "ffi_policy",
                "status",
                // FG-069 moves only dependency_policy.tsv to its v2 schema.
                // Other registries remain v1 until their own schema migration.
                "build_script",
                "proc_macro",
            ][..],
        ),
        (
            "durable_objects.tsv",
            &[
                "id",
                "object_class",
                "canonical_identity",
                "raptorq_profile",
                "encoding_class",
                "post_decode_verification",
                "retention_owner",
                "status",
            ][..],
        ),
        (
            "evidence_packs.tsv",
            &[
                "id",
                "body_family",
                "source_path",
                "completeness_field",
                "allowed_classes",
                "status",
            ][..],
        ),
        (
            "graph_views.tsv",
            &[
                "id",
                "authority_class",
                "source",
                "builder",
                "allowed_decisions",
                "forbidden_decisions",
                "status",
            ][..],
        ),
        (
            "invariants.tsv",
            &[
                "id",
                "owner",
                "statement",
                "verification",
                "release_blocking",
                "status",
            ][..],
        ),
        (
            "negative_evidence.tsv",
            &[
                "id",
                "class",
                "hypothesis",
                "disposition",
                "evidence",
                "revisit_condition",
                "status",
            ][..],
        ),
        (
            "publication_primitives.tsv",
            &[
                "id",
                "object_class",
                "body_store",
                "authority_key",
                "primitive",
                "linearization",
                "recovery",
                "status",
            ][..],
        ),
        (
            "verification_lanes.tsv",
            &[
                "id",
                "command",
                "execution",
                "artifacts",
                "release_blocking",
                "status",
            ][..],
        ),
    ])
}

fn registry_marker_for(file_name: &str) -> &'static str {
    match file_name {
        "dependency_policy.tsv" => DEPENDENCY_POLICY_MARKER_V2,
        _ => REGISTRY_MARKER_V1,
    }
}

/// The closed set of CALM coordination classes, parsed from the one document
/// that defines them.
///
/// Deliberately parsed rather than restated here. A hard-coded list in this
/// checker would be a second source of truth for a closed set that already has
/// an authoritative home, and the two would drift the first time someone edited
/// one of them -- which is exactly the failure this check exists to prevent one
/// layer down, in the registry.
fn calm_coordination_classes(root: &Path, report: &mut Report) -> BTreeSet<String> {
    let path = root.join("docs/CALM_AND_OBLIGATIONS.md");
    let display = relative(root, &path);
    let mut classes = BTreeSet::new();
    let text = match fs::read_to_string(&path) {
        Ok(value) => value,
        Err(error) => {
            report.error(format!("cannot read {display}: {error}"));
            return classes;
        }
    };
    let mut in_section = false;
    for line in text.lines() {
        if line.starts_with("## 1.") {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("## ") {
            break;
        }
        if !in_section {
            continue;
        }
        if let Some(rest) = line.strip_prefix("- `")
            && let Some((name, _)) = rest.split_once("`:")
        {
            classes.insert(name.to_owned());
        }
    }
    // Non-vacuity guard. If a documentation restructure breaks this parse, the
    // set goes empty and every registry value would match nothing -- or worse,
    // an empty set would be treated as "no constraint". Fail loudly instead: a
    // closed-set check that silently stopped constraining anything is the
    // decorative-gate failure this project keeps finding.
    if classes.len() != CALM_CLASS_COUNT {
        report.error(format!(
            "expected {CALM_CLASS_COUNT} coordination classes in {display} section 1, parsed {}; \
             the calm_operations class check would be vacuous",
            classes.len()
        ));
    }
    classes
}

fn check_registries(root: &Path, report: &mut Report) {
    let schemas = registry_schemas();
    let calm_classes = calm_coordination_classes(root, report);
    let registry_dir = root.join("registries");
    for (file_name, expected_header) in schemas {
        let path = registry_dir.join(file_name);
        let display = relative(root, &path);
        let text = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(error) => {
                report.error(format!("cannot read registry {display}: {error}"));
                continue;
            }
        };
        let mut meaningful = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty());
        let Some((marker_line, marker)) = meaningful.next() else {
            report.error(format!("empty registry: {display}"));
            continue;
        };
        let expected_marker = registry_marker_for(file_name);
        if marker.trim() != expected_marker {
            report.error(format!(
                "registry marker mismatch at {display}:{}: expected `{expected_marker}`",
                marker_line + 1
            ));
        }
        let Some((header_line, header)) =
            meaningful.find(|(_, line)| !line.trim().starts_with('#'))
        else {
            report.error(format!("registry has no header: {display}"));
            continue;
        };
        let actual_header = header.split('\t').collect::<Vec<_>>();
        if actual_header != expected_header {
            report.error(format!(
                "registry header mismatch at {display}:{}: expected {:?}, observed {:?}",
                header_line + 1,
                expected_header,
                actual_header
            ));
            continue;
        }

        let status_index = actual_header.iter().position(|field| *field == "status");
        // Only `calm_operations.tsv` carries a coordination class; every other
        // registry's `class`-like column means something else.
        let class_index = if file_name == "calm_operations.tsv" {
            actual_header.iter().position(|field| *field == "class")
        } else {
            None
        };
        let id_index = actual_header
            .iter()
            .position(|field| *field == "id")
            .unwrap_or(0);
        let mut ids = BTreeSet::new();
        let mut previous_id: Option<String> = None;
        for (line_index, line) in text.lines().enumerate().skip(header_line + 1) {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != actual_header.len() {
                report.error(format!(
                    "registry column count mismatch at {display}:{}: expected {}, observed {}",
                    line_index + 1,
                    actual_header.len(),
                    fields.len()
                ));
                continue;
            }
            for (index, value) in fields.iter().enumerate() {
                if value.trim().is_empty() {
                    report.error(format!(
                        "empty registry field `{}` at {display}:{}",
                        actual_header[index],
                        line_index + 1
                    ));
                }
            }
            // FG-012 acceptance 5a: the coordination class must be one of the
            // seven declared classes. This is what makes the registry rows
            // load-bearing today -- running code branches on them -- rather
            // than a design-time note nothing validates.
            if let Some(index) = class_index
                && let Some(value) = fields.get(index)
            {
                let value = value.trim();
                if !calm_classes.is_empty() && !calm_classes.contains(value) {
                    report.error(format!(
                        "unknown coordination class `{value}` at {display}:{}: \
                         docs/CALM_AND_OBLIGATIONS.md section 1 declares only {:?}",
                        line_index + 1,
                        calm_classes
                    ));
                }
            }
            let id = fields[id_index].to_owned();
            if !ids.insert(id.clone()) {
                report.error(format!(
                    "duplicate registry id `{id}` at {display}:{}",
                    line_index + 1
                ));
            }
            if let Some(previous) = &previous_id
                && id < *previous
            {
                report.error(format!(
                    "registry IDs are not strictly sorted at {display}:{}: `{id}` follows `{previous}`",
                    line_index + 1
                ));
            }
            previous_id = Some(id);

            if let Some(index) = status_index
                && !is_known_status(fields[index])
            {
                report.error(format!(
                    "unknown status `{}` at {display}:{}",
                    fields[index],
                    line_index + 1
                ));
            }
            report.registry_rows += 1;
        }
    }

    let dependency = root.join("registries/dependency_policy.tsv");
    if let Ok(text) = fs::read_to_string(dependency) {
        for required in ["asupersync", "tokio*", "libgit2*", "upstream-git"] {
            if !text
                .lines()
                .any(|line| line.split('\t').nth(1) == Some(required))
            {
                report.error(format!(
                    "dependency registry lacks required constitutional row `{required}`"
                ));
            }
        }
    }
    check_evidence_packs(root, report);
    claims::check(root, report);
}

/// The four classes that VERIFY_SPEC §4 makes a closed per-pack declaration.
///
/// This is intentionally a protocol vocabulary in the checker, rather than a
/// free-form registry field: admitting a fifth spelling or omitting one would
/// make a pack's declared replay contract ambiguous at the release gate.
const REPLAY_COMPLETENESS_CLASSES: [&str; 4] = [
    "replayable",
    "structural-replay",
    "verifiable-with-named-artifacts",
    "audit-only",
];

/// Refuses an evidence-pack registry row unless it names the body that emits
/// it, the required canonical field, and exactly the four closed replay
/// classes. It also checks the body source, so a registry row cannot keep the
/// gate green after the encoder stops carrying that declaration.
fn check_evidence_packs(root: &Path, report: &mut Report) {
    let registry_path = root.join("registries/evidence_packs.tsv");
    let display = relative(root, &registry_path);
    let registry = match fs::read_to_string(&registry_path) {
        Ok(value) => value,
        Err(_) => return, // The generic registry gate reports the missing file.
    };
    let mut registered = BTreeMap::<String, String>::new();
    let expected_classes = REPLAY_COMPLETENESS_CLASSES
        .iter()
        .map(|class| (*class).to_owned())
        .collect::<BTreeSet<_>>();

    for (line_index, line) in registry.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') || line.starts_with("id\t")
        {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 6 {
            continue; // The generic registry gate reports the malformed row.
        }
        let family = fields[1].trim();
        let source_path = fields[2].trim();
        let field = fields[3].trim();
        let classes = fields[4]
            .split(',')
            .map(str::trim)
            .filter(|class| !class.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let line_number = line_index + 1;

        if field != "replay_completeness" {
            report.error(format!(
                "evidence pack `{family}` at {display}:{line_number} declares completeness field `{field}`, \
                 but every evidence pack must declare `replay_completeness`"
            ));
        }
        if classes != expected_classes {
            report.error(format!(
                "evidence pack `{family}` at {display}:{line_number} must declare exactly replay classes {:?}, observed {:?}",
                expected_classes, classes
            ));
        }

        let relative_source = Path::new(source_path);
        if relative_source.is_absolute()
            || relative_source
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || !relative_source.starts_with("crates/fgit-evidence/src/")
        {
            report.error(format!(
                "evidence pack `{family}` at {display}:{line_number} has invalid fgit-evidence source path `{source_path}`"
            ));
            continue;
        }
        let source = root.join(relative_source);
        let source_text = match fs::read_to_string(&source) {
            Ok(value) => value,
            Err(error) => {
                report.error(format!(
                    "evidence pack `{family}` at {display}:{line_number} cannot read {source_path}: {error}"
                ));
                continue;
            }
        };
        let family_marker =
            format!("const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static(\"{family}\");");
        if !source_text.contains(&family_marker) {
            report.error(format!(
                "evidence pack `{family}` at {display}:{line_number} is not emitted by `{source_path}`"
            ));
        }
        for marker in [
            "pub enum ReplayCompleteness",
            "Replayable",
            "Structural",
            "VerifiableIfSupplied",
            "AuditOnly",
            "replay_completeness: ReplayCompleteness",
            "out.write_raw_byte(self.context.replay_completeness.code())",
            "ReplayCompleteness::from_code(",
        ] {
            if !source_text.contains(marker) {
                report.error(format!(
                    "evidence pack `{family}` at {display}:{line_number} source `{source_path}` \
                     does not encode required replay completeness marker `{marker}`"
                ));
            }
        }
        registered.insert(family.to_owned(), source_path.to_owned());
    }

    let mut emitted = BTreeSet::new();
    let mut sources = Vec::new();
    collect_files(&root.join("crates/fgit-evidence/src"), &mut sources);
    sources.sort();
    for source in sources.into_iter().filter(|source| {
        source
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| extension == "rs")
    }) {
        let source_display = relative(root, &source);
        let source_text = match fs::read_to_string(&source) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for family in canonical_body_families(&source_text, &source_display, report) {
            emitted.insert(family);
        }
    }
    let registered_families = registered.keys().cloned().collect::<BTreeSet<_>>();
    for family in emitted.difference(&registered_families) {
        report.error(format!(
            "fgit-evidence emits canonical evidence pack family `{family}` without a replay-completeness declaration in registries/evidence_packs.tsv"
        ));
    }
    for family in registered.keys() {
        if !emitted.contains(family) {
            report.error(format!(
                "registries/evidence_packs.tsv declares `{family}`, but its source does not emit that canonical evidence pack"
            ));
        }
    }
}

/// Extract direct `CanonicalBody` family literals from one evidence source.
/// A body whose family is indirect is refused: the registry must bind the
/// concrete family used in its canonical frame, not an alias a textual gate
/// cannot prove belongs to this body.
fn canonical_body_families(source: &str, display: &str, report: &mut Report) -> BTreeSet<String> {
    const IMPLEMENTATION: &str = "impl CanonicalBody for";
    const FAMILY: &str = "const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static(\"";
    let mut families = BTreeSet::new();
    let mut remainder = source;
    while let Some(offset) = remainder.find(IMPLEMENTATION) {
        remainder = &remainder[offset + IMPLEMENTATION.len()..];
        let Some(end) = remainder.find("fn write_payload") else {
            report.error(format!(
                "canonical evidence body in {display} has no write_payload implementation"
            ));
            break;
        };
        let implementation = &remainder[..end];
        let Some(family_offset) = implementation.find(FAMILY) else {
            report.error(format!(
                "canonical evidence body in {display} has no direct SCHEMA_FAMILY literal"
            ));
            continue;
        };
        let literal = &implementation[family_offset + FAMILY.len()..];
        let Some(end) = literal.find("\")") else {
            report.error(format!(
                "canonical evidence body in {display} has an unterminated SCHEMA_FAMILY literal"
            ));
            continue;
        };
        families.insert(literal[..end].to_owned());
    }
    families
}

/// The one in-code source of the registry status vocabulary.
///
/// `docs/NEGATIVE_EVIDENCE_LEDGER.md` §6.2 publishes the same list in a
/// machine-read block, and [`check_status_vocabulary_pin`] asserts the two are
/// equal in both directions. Adding a value here without adding it there (or
/// the reverse) is a verification failure, which is the drift this pin exists
/// to make impossible.
const KNOWN_STATUSES: &[&str] = &[
    "active",
    "specified",
    "implemented",
    "verified",
    "experimental",
    "rejected",
];

fn is_known_status(value: &str) -> bool {
    KNOWN_STATUSES.contains(&value)
}

/// Parses the status vocabulary the ledger publishes for machine reading.
///
/// Returns `None` when the block is absent or unparseable, so the caller can
/// distinguish "the document disagrees" from "the document lost its block" --
/// collapsing those would let a deleted block read as an empty set and pass by
/// vacuity.
fn ledger_status_vocabulary(text: &str) -> Option<BTreeSet<String>> {
    const BEGIN: &str = "<!-- registry-status-vocabulary:begin -->";
    const END: &str = "<!-- registry-status-vocabulary:end -->";
    let start = text.find(BEGIN)? + BEGIN.len();
    let end = text[start..].find(END)? + start;
    let mut values = BTreeSet::new();
    for line in text[start..end].lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("- ") else {
            continue;
        };
        let value = rest.trim().trim_matches('`');
        if !value.is_empty() {
            values.insert(value.to_owned());
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// The pin: the ledger's published vocabulary and the checker's own set must be
/// the same set, in both directions.
fn check_status_vocabulary_pin(root: &Path, report: &mut Report) {
    let path = root.join("docs/NEGATIVE_EVIDENCE_LEDGER.md");
    let display = relative(root, &path);
    let text = match fs::read_to_string(&path) {
        Ok(value) => value,
        Err(error) => {
            report.error(format!("cannot read {display}: {error}"));
            return;
        }
    };
    let Some(documented) = ledger_status_vocabulary(&text) else {
        report.error(format!(
            "{display} §6.2 must publish the registry status vocabulary between \
             the `registry-status-vocabulary` markers; the block is missing or empty"
        ));
        return;
    };
    let enforced: BTreeSet<String> = KNOWN_STATUSES.iter().map(|s| (*s).to_owned()).collect();
    for value in documented.difference(&enforced) {
        report.error(format!(
            "{display} §6.2 documents status `{value}`, which `is_known_status` does not admit"
        ));
    }
    for value in enforced.difference(&documented) {
        report.error(format!(
            "`is_known_status` admits status `{value}`, which {display} §6.2 does not document"
        ));
    }
}

fn check_markdown(root: &Path, report: &mut Report) {
    let mut files = Vec::new();
    collect_files(root, &mut files);
    files.sort();
    let root_canonical = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut tx_formula_locations = Vec::new();

    for path in files
        .iter()
        .filter(|path| path.extension() == Some(OsStr::new("md")))
    {
        report.markdown_files += 1;
        let display = relative(root, path);
        let text = match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) => {
                report.error(format!("cannot read Markdown {display}: {error}"));
                continue;
            }
        };
        check_fences(&display, &text, report);
        check_links(root, &root_canonical, path, &display, &text, report);

        for (line_number, line) in text.lines().enumerate() {
            if contains_txid_formula(line) {
                tx_formula_locations.push(format!("{display}:{}", line_number + 1));
            }
            let lowered = line.to_ascii_lowercase();
            if lowered.contains("protocol v2 push")
                && ![
                    "not",
                    "fictional",
                    "incorrect",
                    "no standardized",
                    "does not",
                ]
                .iter()
                .any(|guard| contains_guard(&lowered, guard))
            {
                report.error(format!(
                    "positive/ambiguous `protocol v2 push` claim at {display}:{}",
                    line_number + 1
                ));
            }
        }
    }

    if tx_formula_locations.len() != 1 {
        report.error(format!(
            "expected exactly one canonical TxId formula, observed {tx_formula_locations:?}"
        ));
    }
}

/// Matches `TxId`, optional whitespace, `=`, optional whitespace, `H`,
/// optional whitespace, `(` — so a competing formula cannot hide behind
/// spacing differences.
fn contains_txid_formula(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut search = 0;
    while let Some(pos) = line[search..].find("TxId") {
        let start = search + pos;
        search = start + 4;
        if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            continue;
        }
        let mut index = start + 4;
        let expect = |target: u8, index: &mut usize| {
            while *index < bytes.len() && bytes[*index].is_ascii_whitespace() {
                *index += 1;
            }
            if *index < bytes.len() && bytes[*index] == target {
                *index += 1;
                true
            } else {
                false
            }
        };
        if expect(b'=', &mut index) && expect(b'H', &mut index) && expect(b'(', &mut index) {
            return true;
        }
    }
    false
}

/// Multi-word guards match as substrings; single-word guards require word
/// boundaries so "not" cannot be satisfied by "nothing" or "annotation".
fn contains_guard(lowered: &str, guard: &str) -> bool {
    if guard.contains(' ') {
        return lowered.contains(guard);
    }
    lowered
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|word| word == guard)
}

/// Fence state shared by the fence-balance and link checks so the two can
/// never disagree about what is code. Delimiters follow the `CommonMark` rules
/// that matter here: a fence is three or more of one family indented at most
/// three spaces, and a closing fence must be at least as long as its opener,
/// so a three-backtick example inside a four-backtick fence stays content and
/// a triple-backtick line inside a four-space-indented code block is not a
/// delimiter.
struct FenceTracker {
    open: Option<(char, usize, usize)>,
}

impl FenceTracker {
    const fn new() -> Self {
        Self { open: None }
    }

    /// Consumes one line; returns true when the line is fence content or a
    /// fence delimiter (either way, content scanners must skip it).
    fn consume(&mut self, line_number: usize, line: &str) -> bool {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent <= 3
            && let Some(family) = trimmed.chars().next().filter(|c| *c == '`' || *c == '~')
        {
            let run = trimmed.chars().take_while(|c| *c == family).count();
            if run >= 3 {
                match self.open {
                    None => {
                        self.open = Some((family, run, line_number));
                        return true;
                    }
                    Some((current, length, _)) if current == family && run >= length => {
                        self.open = None;
                        return true;
                    }
                    Some(_) => return true,
                }
            }
        }
        self.open.is_some()
    }
}

fn check_fences(display: &str, text: &str, report: &mut Report) {
    let mut tracker = FenceTracker::new();
    for (index, line) in text.lines().enumerate() {
        tracker.consume(index + 1, line);
    }
    if let Some((_, _, line)) = tracker.open {
        report.error(format!("unbalanced code fence at {display}:{line}"));
    }
}

fn check_links(
    root: &Path,
    root_canonical: &Path,
    path: &Path,
    display: &str,
    text: &str,
    report: &mut Report,
) {
    let mut tracker = FenceTracker::new();
    for (index, line) in text.lines().enumerate() {
        if tracker.consume(index + 1, line) {
            continue;
        }
        for segment in outside_inline_code(line) {
            check_line_links(root, root_canonical, path, display, &segment, report);
            check_reference_definition(root, root_canonical, path, display, &segment, report);
        }
    }
}

/// Splitting on backticks, even-indexed segments are outside inline code.
/// Markdown-escaped backticks (`\\` followed by a backtick) are literal text,
/// not delimiters, so they are blanked before splitting. A line with
/// unbalanced backticks falls back to being scanned whole.
fn outside_inline_code(line: &str) -> Vec<String> {
    let sanitized = line.replace("\\`", "  ");
    let segments: Vec<&str> = sanitized.split('`').collect();
    if segments.len().is_multiple_of(2) {
        return vec![sanitized];
    }
    segments.into_iter().step_by(2).map(str::to_owned).collect()
}

fn check_line_links(
    root: &Path,
    root_canonical: &Path,
    path: &Path,
    display: &str,
    line: &str,
    report: &mut Report,
) {
    let mut cursor = 0;
    while let Some(offset) = line[cursor..].find("](") {
        let start = cursor + offset + 2;
        cursor = start;
        let Some(end_offset) = line[start..].find(')') else {
            continue;
        };
        let raw = line[start..start + end_offset].trim();
        cursor = start + end_offset + 1;
        validate_link_target(root, root_canonical, path, display, raw, report);
    }
}

/// Validates reference-style definitions of the form `[label]: target`.
fn check_reference_definition(
    root: &Path,
    root_canonical: &Path,
    path: &Path,
    display: &str,
    line: &str,
    report: &mut Report,
) {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('[') {
        return;
    }
    let Some(close) = trimmed.find("]:") else {
        return;
    };
    let raw = trimmed[close + 2..].trim();
    validate_link_target(root, root_canonical, path, display, raw, report);
}

fn validate_link_target(
    root: &Path,
    root_canonical: &Path,
    path: &Path,
    display: &str,
    raw: &str,
    report: &mut Report,
) {
    if raw.is_empty() || raw.starts_with('#') || raw.starts_with("mailto:") {
        return;
    }
    let target = raw.strip_prefix('<').map_or_else(
        || raw.split_whitespace().next().unwrap_or(""),
        |rest| rest.split('>').next().unwrap_or(""),
    );
    if target.is_empty()
        || target.starts_with('#')
        || target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("mailto:")
        || target.starts_with("data:")
        || target.starts_with("//")
    {
        return;
    }
    let file_part = target.split('#').next().unwrap_or("");
    if file_part.is_empty() {
        return;
    }
    let decoded = percent_decode(file_part);
    let candidate = path.parent().unwrap_or(root).join(decoded);
    if !candidate.exists() {
        report.error(format!("broken relative link: {display} -> {target}"));
        return;
    }
    if let Ok(canonical) = fs::canonicalize(&candidate)
        && !canonical.starts_with(root_canonical)
    {
        report.error(format!(
            "relative link escapes repository: {display} -> {target}"
        ));
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            output.push(high * 16 + low);
            index += 3;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn check_workflows(root: &Path, report: &mut Report) {
    let workflow_dir = root.join(".github/workflows");
    let mut files = Vec::new();
    collect_files(&workflow_dir, &mut files);
    for path in files {
        if !matches!(
            path.extension().and_then(OsStr::to_str),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let display = relative(root, &path);
        let Ok(text) = fs::read_to_string(&path) else {
            report.error(format!("cannot read workflow {display}"));
            continue;
        };
        if !text.contains("./scripts/verify.sh") {
            report.error(format!(
                "workflow {display} must delegate to repository-owned ./scripts/verify.sh"
            ));
        }
        if !text.lines().any(|line| {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            trimmed == "workflow_dispatch:"
                || trimmed == "workflow_dispatch"
                || trimmed == "- workflow_dispatch"
                || (trimmed.starts_with("on:") && trimmed.contains("workflow_dispatch"))
        }) {
            report.error(format!(
                "workflow {display} must expose workflow_dispatch for local DSR/act execution"
            ));
        }
        for (line_number, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if is_hosted_trigger_line(trimmed) {
                report.error(format!(
                    "workflow {display}:{} enables hosted automatic execution; FrankenGit workflows are local/dispatch manifests",
                    line_number + 1
                ));
            }
            // Normalize the YAML list form `- uses: ...` before matching.
            let item = trimmed.strip_prefix("- ").map_or(trimmed, str::trim_start);
            let Some(action) = item.strip_prefix("uses:") else {
                continue;
            };
            let action = action.split('#').next().unwrap_or("").trim();
            if !is_sha_pinned_action(action) {
                report.error(format!(
                    "workflow action is not pinned to a full SHA at {display}:{}: {action}",
                    line_number + 1
                ));
            }
        }
    }
}

/// Detects hosted automatic triggers in block form (`push:`), bare-scalar and
/// list forms (`push`, `- push`), and inline form (`on: push`,
/// `on: [push, pull_request]`, `on: {push: ...}`). YAML comments are stripped
/// first so `push: # disabled` cannot slip through and a comment mentioning
/// `push` cannot false-positive. Conservative: any of these anywhere in a
/// workflow file is refused, because these workflows are dispatch-only
/// manifests.
fn is_hosted_trigger_line(line: &str) -> bool {
    // Automatic triggers the `on:` tokenizer preserves verbatim (underscores
    // survive) must each be named: `pull_request_target` never matches
    // `pull_request`, and each of these grants hosted-runner execution.
    const BANNED: [&str; 13] = [
        "push",
        "pull_request",
        "pull_request_target",
        "schedule",
        "workflow_run",
        "repository_dispatch",
        "issue_comment",
        "discussion_comment",
        "deployment",
        "deployment_status",
        "release",
        "registry_package",
        "check_suite",
    ];
    let trimmed = line.split('#').next().unwrap_or("").trim();
    for trigger in BANNED {
        if trimmed == trigger
            || trimmed == format!("{trigger}:")
            || trimmed == format!("- {trigger}")
        {
            return true;
        }
    }
    if let Some(rest) = trimmed.strip_prefix("on:") {
        return rest
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| BANNED.contains(&token));
    }
    false
}

fn is_sha_pinned_action(value: &str) -> bool {
    let Some((name, revision)) = value.rsplit_once('@') else {
        return false;
    };
    !name.is_empty()
        && revision.len() == 40
        && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn check_contract_phrases(root: &Path, report: &mut Report) {
    let normative =
        fs::read_to_string(root.join("docs/NORMATIVE_PROTOCOL_CONTRACTS.md")).unwrap_or_default();
    for phrase in [
        "There is exactly one normative derivation",
        "RepositoryAuthorityHead",
        "RepositoryDecisionBatch",
        "successful conditional replacement of the repository head",
        "push negotiates with `git-receive-pack`",
        "RaptorQ is an erasure-recovery mechanism",
        "production implementation is pure Rust",
        "staged, visible, and durable",
        "Asupersync is the sole async runtime",
    ] {
        if !normative.contains(phrase) {
            report.error(format!("normative contract missing phrase: {phrase}"));
        }
    }
    for stale in [
        "The mutation linearizes at the serializable metadata commit",
        "one canonical writer epoch",
        "repository home cell",
    ] {
        if normative.contains(stale) {
            report.error(format!(
                "normative contract contains superseded architecture phrase: {stale}"
            ));
        }
    }

    let readme = fs::read_to_string(root.join("README.md")).unwrap_or_default();
    let lowered = readme.to_ascii_lowercase();
    if !lowered.contains("pre-implementation") && !lowered.contains("spec-first") {
        report.error("README must state pre-implementation/spec-first status");
    }
    if !lowered.contains("source-available") {
        report.error("README must truthfully state current source-available licensing status");
    }
    for required in [
        "docs/FRANKEN_SUITE_DEEP_DIVE_SYNTHESIS.md",
        "docs/FRESH_EYES_AUDIT_2026-08-19.md",
        "docs/FRANKENSUITE_DEEP_AUDIT_2026-08-19.md",
        "docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md",
    ] {
        if !readme.contains(required) {
            report.error(format!("README must link {required}"));
        }
    }

    let plan = fs::read_to_string(root.join("COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md"))
        .unwrap_or_default();
    for required in [
        "docs/NORMATIVE_PROTOCOL_CONTRACTS.md",
        "docs/OBJECT_STORE_DECISION_LOG.md",
        "docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md",
        "docs/LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md",
        "docs/FRESH_EYES_AUDIT_2026-08-19.md",
        "docs/FRANKENSUITE_DEEP_AUDIT_2026-08-19.md",
    ] {
        if !plan.contains(required) {
            report.error(format!("comprehensive plan must link {required}"));
        }
    }

    let agent = fs::read_to_string(root.join("docs/AGENT_PROTOCOL.md")).unwrap_or_default();
    for phrase in [
        "AuthorityReadReceipt",
        "Git TreeFS workspace",
        "Effect broker and obligation ledger",
        "successful head CAS",
    ] {
        if !agent.contains(phrase) {
            report.error(format!("agent protocol missing v3 phrase: {phrase}"));
        }
    }

    let raptor =
        fs::read_to_string(root.join("docs/RAPTORQ_PERMEATION_MAP.md")).unwrap_or_default();
    for phrase in [
        "current authority revalidation",
        "RepairIntentPrepared",
        "staged, visible, and durable",
    ] {
        if !raptor
            .to_ascii_lowercase()
            .contains(&phrase.to_ascii_lowercase())
        {
            report.error(format!(
                "RaptorQ permeation map missing v3 repair phrase: {phrase}"
            ));
        }
    }

    let backlog =
        fs::read_to_string(root.join("docs/INITIAL_ISSUE_BACKLOG.md")).unwrap_or_default();
    for issue in ["FG-022", "FG-025", "FG-026", "FG-031", "FG-035", "FG-036"] {
        if !backlog.contains(issue) {
            report.error(format!(
                "initial backlog lacks deep-synthesis issue {issue}"
            ));
        }
    }

    let verify_script = fs::read_to_string(root.join("scripts/verify.sh")).unwrap_or_default();
    if !verify_script.contains("typed pre-implementation refusal")
        || !verify_script.contains("exit 3")
    {
        report
            .error("full/release verification lanes must refuse while dormant, not return success");
    }

    let dsr = fs::read_to_string(root.join("ops/dsr/frankengit.yaml.example")).unwrap_or_default();
    if !dsr.contains("workflow: .github/workflows/docs-integrity.yml") {
        report.error("DSR example must point to the checked-in local workflow manifest");
    }
}

/// Runs the focused first-party crate-graph scan. It is also the implementation
/// that the constitution lane adopts once every existing workspace member is
/// known to satisfy its concrete findings; keeping the command separately
/// invocable makes that transition observable rather than silently weakening
/// the new checks around in-progress crates.
fn check_workspace_crate_graph(root: &Path, report: &mut Report) {
    for manifest in workspace_manifest_paths(root, report) {
        let crate_dir = manifest.parent().unwrap_or(root);
        let crate_display = relative(root, crate_dir);
        let source_dir = crate_dir.join("src");
        let sources = production_rust_source_files(&source_dir);
        if sources.is_empty() {
            report.error(format!(
                "workspace crate `{crate_display}` has no production Rust target under {crate_display}/src"
            ));
            continue;
        }

        let mut has_production_item = false;
        let mut has_cfg_test_item = false;
        let mut lib_is_reexport_only = false;
        for path in &sources {
            let display = relative(root, path);
            let Ok(text) = fs::read_to_string(path) else {
                report.error(format!("cannot read first-party Rust source {display}"));
                continue;
            };
            let assessment = assess_first_party_source(&text);
            has_production_item |= assessment.has_production_item();
            has_cfg_test_item |= assessment.has_cfg_test_item();
            if path.file_name() == Some(OsStr::new("lib.rs"))
                && assessment.has_item()
                && !assessment.has_non_reexport_item()
            {
                lib_is_reexport_only = true;
            }
            for placeholder in assessment.placeholders {
                report.error(format!(
                    "placeholder `{placeholder}` in non-test first-party source {display}"
                ));
            }
            if let Some(relaxation) = assessment.lint_relaxation {
                report.error(format!(
                    "forbidden first-party lint relaxation `{relaxation}` in {display}"
                ));
            }
        }
        if !has_production_item {
            let reason = if has_cfg_test_item {
                "contains only cfg(test)-gated behavior"
            } else {
                "contains no real production item"
            };
            report.error(format!("workspace crate `{crate_display}` {reason}"));
        }
        if lib_is_reexport_only {
            report.error(format!(
                "workspace crate `{crate_display}` lib.rs only re-exports symbols and contains no implementation item"
            ));
        }
    }
}

#[derive(Debug, Default)]
struct SourceAssessment {
    item_flags: u8,
    placeholders: Vec<String>,
    lint_relaxation: Option<String>,
}

impl SourceAssessment {
    const HAS_ITEM: u8 = 1;
    const HAS_NON_REEXPORT_ITEM: u8 = 1 << 1;
    const HAS_PRODUCTION_ITEM: u8 = 1 << 2;
    const HAS_CFG_TEST_ITEM: u8 = 1 << 3;

    const fn contains(&self, flag: u8) -> bool {
        self.item_flags & flag != 0
    }

    const fn has_item(&self) -> bool {
        self.contains(Self::HAS_ITEM)
    }

    const fn has_non_reexport_item(&self) -> bool {
        self.contains(Self::HAS_NON_REEXPORT_ITEM)
    }

    const fn has_production_item(&self) -> bool {
        self.contains(Self::HAS_PRODUCTION_ITEM)
    }

    const fn has_cfg_test_item(&self) -> bool {
        self.contains(Self::HAS_CFG_TEST_ITEM)
    }
}

fn production_rust_source_files(source_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files(source_dir, &mut files);
    files.retain(|path| {
        path.extension() == Some(OsStr::new("rs")) && !is_test_only_rust_path(source_dir, path)
    });
    files.sort();
    files
}

fn is_test_only_rust_path(source_dir: &Path, path: &Path) -> bool {
    path.strip_prefix(source_dir).is_ok_and(|relative_path| {
        relative_path.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("tests" | "examples" | "benches")
            )
        })
    })
}

fn assess_first_party_source(text: &str) -> SourceAssessment {
    let production_text = strip_cfg_test_items(text);
    let code = strip_rust_comments(&production_text);
    let mut assessment = SourceAssessment {
        item_flags: u8::from(text.contains("#[cfg(test)]")) * SourceAssessment::HAS_CFG_TEST_ITEM,
        placeholders: find_placeholder_constructs(&code),
        lint_relaxation: find_forbidden_lint_relaxation(&code),
    };
    for line in code.lines().map(str::trim) {
        let Some(item) = source_item_kind(line) else {
            continue;
        };
        assessment.item_flags |= SourceAssessment::HAS_ITEM;
        if item == SourceItemKind::Reexport {
            continue;
        }
        assessment.item_flags |=
            SourceAssessment::HAS_NON_REEXPORT_ITEM | SourceAssessment::HAS_PRODUCTION_ITEM;
    }
    assessment
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceItemKind {
    Reexport,
    Implementation,
}

fn source_item_kind(line: &str) -> Option<SourceItemKind> {
    let line = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    if line.starts_with("use ") {
        return Some(SourceItemKind::Reexport);
    }
    for prefix in [
        "mod ",
        "struct ",
        "enum ",
        "trait ",
        "fn ",
        "const ",
        "static ",
        "type ",
        "impl",
        "macro_rules!",
    ] {
        if line.starts_with(prefix) {
            return Some(SourceItemKind::Implementation);
        }
    }
    None
}

/// Removes straightforward `cfg(test)` items before the production-source
/// pass. This is intentionally a detector, not a Rust parser: nested or
/// conditional macro-generated items remain a human-review obligation. It
/// nevertheless carries a small lexical state while skipping an item so a
/// brace in a string or comment cannot end a test module early.
fn strip_cfg_test_items(text: &str) -> String {
    let mut output = String::new();
    let mut pending_cfg_test = false;
    let mut skipped_item: Option<SkippedCfgTestItem> = None;
    for raw_line in text.lines() {
        if let Some(item) = skipped_item.as_mut() {
            if item.consume(raw_line) {
                skipped_item = None;
            }
            continue;
        }
        let line = raw_line.trim();
        if let Some(tail) = cfg_test_attribute_tail(line) {
            pending_cfg_test = true;
            if !tail.trim().is_empty() {
                let mut item = SkippedCfgTestItem::default();
                if !item.consume(tail) {
                    skipped_item = Some(item);
                }
                pending_cfg_test = false;
            }
            continue;
        }
        if pending_cfg_test {
            if line.is_empty()
                || line.starts_with("#[")
                || line.starts_with("//")
                || line.starts_with("///")
            {
                continue;
            }
            let mut item = SkippedCfgTestItem::default();
            if !item.consume(raw_line) {
                skipped_item = Some(item);
            }
            pending_cfg_test = false;
            continue;
        }
        output.push_str(raw_line);
        output.push('\n');
    }
    output
}

fn cfg_test_attribute_tail(line: &str) -> Option<&str> {
    line.strip_prefix("#[cfg(test)]").filter(|tail| {
        tail.is_empty()
            || tail.starts_with("#[")
            || tail.chars().next().is_some_and(char::is_whitespace)
    })
}

#[derive(Default)]
struct SkippedCfgTestItem {
    lexical_state: RustLexicalState,
    brace_depth: usize,
    opened_brace: bool,
}

impl SkippedCfgTestItem {
    /// Returns true only after the whole item is skipped. A declaration with
    /// no body ends at its top-level semicolon; a body ends when its lexical
    /// brace depth returns to zero.
    fn consume(&mut self, line: &str) -> bool {
        let delimiters = scan_rust_item_delimiters(line, &mut self.lexical_state);
        self.brace_depth = self
            .brace_depth
            .saturating_add(delimiters.open_braces)
            .saturating_sub(delimiters.close_braces);
        self.opened_brace |= delimiters.open_braces > 0;
        (self.opened_brace && self.brace_depth == 0)
            || (!self.opened_brace && delimiters.top_level_semicolon)
    }
}

#[derive(Default)]
struct RustItemDelimiters {
    open_braces: usize,
    close_braces: usize,
    top_level_semicolon: bool,
}

#[derive(Default)]
enum RustLexicalState {
    #[default]
    Code,
    BlockComment {
        depth: usize,
    },
    String {
        escaped: bool,
    },
    Character {
        escaped: bool,
    },
    RawString {
        hashes: usize,
    },
}

/// Counts item delimiters only while Rust is in code. It deliberately covers
/// ordinary/raw strings and nested block comments, which are enough to keep a
/// lexical production check from treating test-only text as an item boundary.
fn scan_rust_item_delimiters(line: &str, state: &mut RustLexicalState) -> RustItemDelimiters {
    let bytes = line.as_bytes();
    let mut delimiters = RustItemDelimiters::default();
    let mut index = 0;
    while index < bytes.len() {
        match state {
            RustLexicalState::Code => match bytes[index] {
                b'/' if bytes.get(index + 1) == Some(&b'/') => break,
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    *state = RustLexicalState::BlockComment { depth: 1 };
                    index += 2;
                }
                b'"' => {
                    *state = RustLexicalState::String { escaped: false };
                    index += 1;
                }
                b'\''
                    if !bytes
                        .get(index + 1)
                        .is_some_and(|next| next.is_ascii_alphanumeric() || *next == b'_') =>
                {
                    *state = RustLexicalState::Character { escaped: false };
                    index += 1;
                }
                b'r' if let Some(hashes) = raw_string_hashes(bytes, index) => {
                    *state = RustLexicalState::RawString { hashes };
                    index += hashes + 2;
                }
                b'{' => {
                    delimiters.open_braces = delimiters.open_braces.saturating_add(1);
                    index += 1;
                }
                b'}' => {
                    delimiters.close_braces = delimiters.close_braces.saturating_add(1);
                    index += 1;
                }
                b';' => {
                    delimiters.top_level_semicolon = true;
                    index += 1;
                }
                _ => index += 1,
            },
            RustLexicalState::BlockComment { depth } => {
                if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    *depth = depth.saturating_add(1);
                    index += 2;
                } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    if *depth == 1 {
                        *state = RustLexicalState::Code;
                    } else {
                        *depth = depth.saturating_sub(1);
                    }
                    index += 2;
                } else {
                    index += 1;
                }
            }
            RustLexicalState::String { escaped } => {
                if *escaped {
                    *escaped = false;
                } else if bytes[index] == b'\\' {
                    *escaped = true;
                } else if bytes[index] == b'"' {
                    *state = RustLexicalState::Code;
                }
                index += 1;
            }
            RustLexicalState::Character { escaped } => {
                if *escaped {
                    *escaped = false;
                } else if bytes[index] == b'\\' {
                    *escaped = true;
                } else if bytes[index] == b'\'' {
                    *state = RustLexicalState::Code;
                }
                index += 1;
            }
            RustLexicalState::RawString { hashes } => {
                let closing_hashes = *hashes;
                if bytes[index] == b'"'
                    && bytes[index + 1..]
                        .iter()
                        .take_while(|byte| **byte == b'#')
                        .count()
                        == closing_hashes
                {
                    *state = RustLexicalState::Code;
                    index += closing_hashes.saturating_add(1);
                } else {
                    index += 1;
                }
            }
        }
    }
    delimiters
}

fn raw_string_hashes(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = index.saturating_add(1);
    while bytes.get(cursor) == Some(&b'#') {
        cursor = cursor.saturating_add(1);
    }
    (bytes.get(cursor) == Some(&b'"')).then_some(cursor.saturating_sub(index + 1))
}

/// Removes line and block comments while retaining quoted messages, which are
/// needed to distinguish `panic!(\"TODO\")` from an ordinary panic. It is
/// deliberately lexical and reports its limits through the check description.
fn strip_rust_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    let mut block_depth = 0usize;
    while let Some(character) = characters.next() {
        if block_depth > 0 {
            if character == '*' && characters.peek() == Some(&'/') {
                characters.next();
                block_depth -= 1;
            } else if character == '/' && characters.peek() == Some(&'*') {
                characters.next();
                block_depth += 1;
            } else if character == '\n' {
                output.push('\n');
            }
            continue;
        }
        if in_string {
            output.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            output.push(character);
        } else if character == '/' && characters.peek() == Some(&'/') {
            characters.next();
            for next in characters.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
            }
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            block_depth = 1;
        } else {
            output.push(character);
        }
    }
    output
}

fn find_placeholder_constructs(text: &str) -> Vec<String> {
    let mut constructs = Vec::new();
    for (name, marker) in [
        ("todo", concat!("to", "do!")),
        ("unimplemented", concat!("un", "implemented!")),
    ] {
        if contains_macro_invocation(text, marker) {
            constructs.push(format!("{name}!"));
        }
    }
    for name in ["panic", "unreachable"] {
        if contains_todo_message(text, name) {
            constructs.push(format!("{name}!(\"TODO…\")"));
        }
    }
    constructs
}

fn contains_macro_invocation(text: &str, marker: &str) -> bool {
    let bytes = text.as_bytes();
    let mut offset = 0usize;
    while let Some(found) = text[offset..].find(marker) {
        let start = offset + found;
        let end = start + marker.len();
        offset = end;
        let before_is_ident =
            start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        if !before_is_ident {
            return true;
        }
    }
    false
}

fn contains_todo_message(text: &str, macro_name: &str) -> bool {
    let marker = format!("{macro_name}!");
    let mut offset = 0usize;
    while let Some(found) = text[offset..].find(&marker) {
        let start = offset + found;
        offset = start + marker.len();
        let tail = text[offset..].trim_start();
        let Some(tail) = tail.strip_prefix('(') else {
            continue;
        };
        let tail = tail.trim_start();
        if tail.starts_with("\"TODO") {
            return true;
        }
    }
    false
}

/// First attribute opener, outer `#[` or inner `#![`, whichever comes first.
///
/// Inner attributes were previously invisible to this scan: `"#!["` does not
/// contain the `"#["` needle, so a crate-root `#![allow(clippy::everything)]`
/// bypassed the relaxation gate entirely.
fn position_of_attribute_open(text: &str) -> Option<usize> {
    match (text.find("#["), text.find("#![")) {
        (Some(outer), Some(inner)) => Some(outer.min(inner)),
        (outer, inner) => outer.or(inner),
    }
}

fn find_forbidden_lint_relaxation(text: &str) -> Option<String> {
    let mut remaining = text;
    while let Some(open) = position_of_attribute_open(remaining) {
        let attribute = &remaining[open..];
        let Some(close) = attribute.find(']') else {
            return Some("unterminated attribute".to_owned());
        };
        let attribute = &attribute[..=close];
        remaining = &remaining[open + close + 1..];
        if !attribute.contains("allow") {
            continue;
        }
        if attribute.contains("unsafe_code") {
            return Some("unsafe_code".to_owned());
        }
        if let Some(position) = attribute.find("clippy::") {
            let tail = &attribute[position..];
            let lint = tail
                .trim_end_matches(']')
                .trim_end_matches(')')
                .split(',')
                .next()
                .unwrap_or(tail)
                .trim();
            return Some(lint.to_owned());
        }
    }
    None
}

fn check_rust_sources(root: &Path, report: &mut Report) {
    let mut files = Vec::new();
    collect_files(root, &mut files);
    for path in files
        .iter()
        .filter(|path| path.extension() == Some(OsStr::new("rs")))
    {
        report.rust_files += 1;
        let display = relative(root, path);
        let text = match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) => {
                report.error(format!("cannot read Rust source {display}: {error}"));
                continue;
            }
        };
        if path.file_name() == Some(OsStr::new("build.rs")) {
            report.error(format!(
                "first-party build script requires an explicit constitutional exception: {display}"
            ));
        }
        let is_named_root = matches!(
            path.file_name().and_then(OsStr::to_str),
            Some("main.rs" | "lib.rs")
        );
        let is_bin_root = path.parent().and_then(Path::file_name) == Some(OsStr::new("bin"))
            && path
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                == Some(OsStr::new("src"));
        if (is_named_root || is_bin_root)
            && !text
                .lines()
                .take(20)
                .any(|line| line.contains("#![forbid(unsafe_code)]"))
        {
            report.error(format!(
                "crate root lacks #![forbid(unsafe_code)]: {display}"
            ));
        }
        // Production source only. `tests/` is NOT swept today because
        // `crates/fgit-pack/tests/writer_benchmark.rs` computes percentiles in
        // `f64` -- measurement, not canonical bytes, and legitimate. Permitting
        // it by path would be a hardcoded exemption; permitting `tests/`
        // wholesale would miss the case this check exists for, a mechanism's own
        // unit test accumulating in float. Scoping to `src/` is the honest first
        // slice, and the gap is named rather than papered over.
        let is_production_source = path
            .components()
            .any(|component| component.as_os_str() == OsStr::new("src"));
        if is_production_source && let Some(token) = find_floating_point_construct(&text) {
            report.error(format!(
                "floating point is excluded from canonical scalars; \
                 forbidden construct `{token}` in {display}"
            ));
        }
        if let Some(token) = find_unsafe_construct(&text) {
            report.error(format!("forbidden Rust construct `{token}` in {display}"));
        }
        if let Some(token) = find_inline_assembly_construct(&text) {
            report.error(format!("forbidden Rust construct `{token}` in {display}"));
        }
        // Quote-free patterns are split with concat! so this checker's own
        // source does not contain the forbidden byte sequences it scans for.
        for forbidden in [
            concat!("#!", "[allow(uns", "afe_code)]"),
            concat!("#", "[allow(uns", "afe_code)]"),
            concat!("extern ", "\"C\""),
            "Command::new(\"git\")",
            "Command::new(\"libgit2\")",
        ] {
            if text.contains(forbidden) {
                report.error(format!(
                    "forbidden Rust construct `{forbidden}` in {display}"
                ));
            }
        }
    }
}

/// Scans production Rust for floating-point, which `CanonicalScalar` excludes
/// by construction so canonical bytes never depend on rounding mode, NaN
/// payload, signed zero, or host width.
///
/// COMMENT-AWARE ON PURPOSE. This repository documents the prohibition in
/// prose -- `fgit-types`, `fgit-witness` and `fgit-statistics` all carry doc
/// comments that NAME `f64` in order to forbid it. A line scan would flag every
/// one of them, and a checker whose output is mostly false positives gets muted
/// or weakened, which is how enforcement dies. So comments are stripped before
/// the scan rather than filtered out of its results, reusing the existing
/// [`strip_rust_comments`] rather than adding a second stripper -- that one is
/// already string-aware and handles nested blocks, which a fresh one would have
/// had to relearn.
///
/// DELIBERATELY NOT A FLOAT-LITERAL CHECK. `33.4` is lexically identical to a
/// float literal, and this codebase cites clauses like that constantly
/// (`section 33.4`, `16.1`, `5.2`) -- in a crate whose clause density is
/// increasing. A literal scan needs real token positions; until it has them it
/// would produce noise, not evidence. The type and the arithmetic are what a
/// mechanism accumulating in float actually needs, and both are caught here.
fn find_floating_point_construct(text: &str) -> Option<String> {
    let code = strip_rust_comments(text);
    let bytes = code.as_bytes();
    // Split with concat! for the same reason the forbidden-construct list above
    // is: `strip_rust_comments` deliberately keeps string literals, so a needle
    // written whole would make this function trip on its own source. It did,
    // on the first run.
    for needle in [concat!("f", "64"), concat!("f", "32")] {
        let mut search = 0;
        while let Some(pos) = code[search..].find(needle) {
            let start = search + pos;
            let end = start + needle.len();
            search = end;
            let prev_is_ident =
                start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
            let next_is_ident =
                end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
            if prev_is_ident || next_is_ident {
                continue;
            }
            return Some(needle.to_owned());
        }
    }
    // Transcendental and power arithmetic reaches the same place by another
    // road: a mechanism can hold its state in an integer newtype and still
    // accumulate through `sqrt`/`ln`/`exp`, which are float-only.
    for method in [
        concat!(".sq", "rt()"),
        concat!(".", "ln()"),
        concat!(".e", "xp()"),
        concat!(".po", "wf("),
        concat!(".lo", "g2()"),
        concat!(".lo", "g10()"),
        concat!(".ln", "_1p()"),
        concat!(".ex", "p_m1()"),
        concat!(".cb", "rt()"),
        concat!(".hy", "pot("),
    ] {
        if code.contains(method) {
            return Some(method.to_owned());
        }
    }
    None
}

/// Whitespace-tolerant scan for the `unsafe` keyword introducing a block,
/// function, impl, trait, or extern item. The needle is concat!-split so this
/// file does not contain it; identifier continuations (as in the phrase
/// checks above) are skipped via word-boundary tests.
fn find_unsafe_construct(text: &str) -> Option<String> {
    const NEEDLE: &str = concat!("uns", "afe");
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(pos) = text[search..].find(NEEDLE) {
        let start = search + pos;
        let end = start + NEEDLE.len();
        search = end;
        let prev_is_ident =
            start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let next_is_ident =
            end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if prev_is_ident || next_is_ident {
            continue;
        }
        let mut index = end;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let rest = &text[index..];
        for follower in ["{", "fn", "impl", "trait", "extern"] {
            if rest.starts_with(follower) {
                return Some(format!("{NEEDLE} {follower}"));
            }
        }
    }
    None
}

fn find_inline_assembly_construct(text: &str) -> Option<String> {
    for (name, marker) in [
        ("asm", concat!("as", "m!")),
        ("global_asm", concat!("global_as", "m!")),
    ] {
        if contains_macro_invocation(text, marker) {
            return Some(format!("{name}!"));
        }
    }
    None
}

fn check_manifests(root: &Path, report: &mut Report) {
    let allowed = load_allowed_dependency_patterns(root, report);
    let workspace_manifests = workspace_manifest_paths(root, report)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut files = Vec::new();
    collect_files(root, &mut files);

    for path in files
        .iter()
        .filter(|path| path.file_name() == Some(OsStr::new("Cargo.toml")))
    {
        let display = relative(root, path);
        let Ok(text) = fs::read_to_string(path) else {
            report.error(format!("cannot read manifest {display}"));
            continue;
        };

        check_first_party_manifest_declarations(&display, &text, report);

        check_manifest_overrides(&display, &text, report);

        if path == &root.join("Cargo.toml") || workspace_manifests.contains(path) {
            check_manifest_dependency_sources(root, path, &display, &text, report);
        }

        for dependency in manifest_dependency_names(&text) {
            if !allowed
                .iter()
                .any(|pattern| dependency_pattern_matches(pattern, &dependency))
            {
                report.error(format!(
                    "unregistered Cargo dependency `{dependency}` in {display}; add an explicit active allow row to registries/dependency_policy.tsv"
                ));
            }
        }
    }

    check_lockfile(root, &allowed, report);
}

fn check_first_party_manifest_declarations(display: &str, text: &str, report: &mut Report) {
    if text.lines().any(|line| {
        let line = line.trim();
        line.starts_with("build =") || line.starts_with("links =") || line == "proc-macro = true"
    }) {
        report.error(format!(
            "manifest {display} declares a build script, native links, or first-party proc macro without a registered constitutional exception"
        ));
    }
}

fn check_manifest_overrides(display: &str, text: &str, report: &mut Report) {
    for line in text.lines().map(str::trim) {
        if line.starts_with("[patch") || line.starts_with("[replace") {
            report.error(format!(
                "manifest {display} declares a [patch]/[replace] section, which bypasses the closed dependency universe"
            ));
        }
    }
}

/// The focused E2E command exercises only release-source and override
/// prohibitions. The normal `constitution` command remains the authoritative
/// whole-tree lane and additionally enforces every registered dependency.
fn check_constellation_manifests(root: &Path, report: &mut Report) {
    let mut paths = workspace_manifest_paths(root, report);
    paths.push(root.join("Cargo.toml"));
    for path in paths {
        let display = relative(root, &path);
        let Ok(text) = fs::read_to_string(&path) else {
            report.error(format!("cannot read manifest {display}"));
            continue;
        };
        check_manifest_overrides(&display, &text, report);
        check_manifest_dependency_sources(root, &path, &display, &text, report);
    }
}

/// Refuse every local or floating Git dependency in a release-facing
/// manifest. Cargo accepts these forms, but neither can be represented as a
/// reproducible, registry-resolvable release source. This is deliberately a
/// manifest check as `Cargo.lock` erases ordinary `path =` edges.
fn check_manifest_dependency_sources(
    root: &Path,
    manifest_path: &Path,
    display: &str,
    text: &str,
    report: &mut Report,
) {
    let mut in_workspace_dependencies = false;
    let mut in_dependency_section = false;
    let mut table_dependency: Option<DependencySource> = None;
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(dependency) = table_dependency.take() {
                check_dependency_source(root, manifest_path, display, &dependency, report);
            }
            let section = line.trim_matches(['[', ']']);
            in_workspace_dependencies = section == "workspace.dependencies"
                || section.starts_with("workspace.dependencies.");
            in_dependency_section = is_dependency_section(section);
            table_dependency = dependency_table_alias(section).map(|name| DependencySource {
                name: name.to_owned(),
                in_workspace_dependencies,
                path: None,
                path_line: None,
                git: None,
                git_line: None,
                rev: None,
            });
            continue;
        }
        if let Some(dependency) = table_dependency.as_mut() {
            dependency.capture_table_field(line, line_number + 1);
            continue;
        }
        if !in_dependency_section || !looks_like_dependency_declaration(line) {
            continue;
        }
        let Some((raw_name, value)) = line.split_once('=') else {
            continue;
        };
        let name = raw_name.trim().trim_matches('"');
        check_dependency_source(
            root,
            manifest_path,
            display,
            &DependencySource {
                name: name.to_owned(),
                in_workspace_dependencies,
                path: extract_inline_string_field(value, "path"),
                path_line: Some(line_number + 1),
                git: extract_inline_string_field(value, "git"),
                git_line: Some(line_number + 1),
                rev: extract_inline_string_field(value, "rev"),
            },
            report,
        );
    }
    if let Some(dependency) = table_dependency.take() {
        check_dependency_source(root, manifest_path, display, &dependency, report);
    }
}

#[derive(Debug, Clone)]
struct DependencySource {
    name: String,
    in_workspace_dependencies: bool,
    path: Option<String>,
    path_line: Option<usize>,
    git: Option<String>,
    git_line: Option<usize>,
    rev: Option<String>,
}

impl DependencySource {
    fn capture_table_field(&mut self, line: &str, line_number: usize) {
        let Some((raw_key, value)) = line.split_once('=') else {
            return;
        };
        let key = raw_key.trim().trim_matches('"');
        let Some(value) = extract_string_value(value) else {
            return;
        };
        match key {
            "path" => {
                self.path = Some(value);
                self.path_line = Some(line_number);
            }
            "git" => {
                self.git = Some(value);
                self.git_line = Some(line_number);
            }
            "rev" => self.rev = Some(value),
            _ => {}
        }
    }
}

fn check_dependency_source(
    root: &Path,
    manifest_path: &Path,
    display: &str,
    dependency: &DependencySource,
    report: &mut Report,
) {
    if let Some(path) = dependency.path.as_deref()
        && !is_first_party_workspace_path(
            root,
            manifest_path,
            dependency.in_workspace_dependencies,
            &dependency.name,
            path,
        )
    {
        report.error(format!(
            "unpublished path dependency `{path}` in {display}:{}; release-facing dependencies must resolve from a pinned release source",
            dependency.path_line.unwrap_or(0)
        ));
    }
    if let Some(git) = dependency.git.as_deref()
        && (!git.starts_with("https://") || dependency.rev.is_none())
    {
        report.error(format!(
            "unresolved Git dependency `{git}` in {display}:{}; require HTTPS plus an exact rev or use a registry release",
            dependency.git_line.unwrap_or(0)
        ));
    }
}

fn is_dependency_section(section: &str) -> bool {
    matches!(
        section,
        "dependencies" | "dev-dependencies" | "build-dependencies" | "workspace.dependencies"
    ) || section.ends_with(".dependencies")
        || section.ends_with(".dev-dependencies")
        || section.ends_with(".build-dependencies")
        || dependency_table_alias(section).is_some()
}

/// Cargo permits a dependency to use its own table, including inside a target
/// dependency section. Keep this deliberately lexical parser aligned with the
/// forms accepted by Cargo so a `path` or `git` source cannot hide below a
/// table header that the closed-world checker treats as unrelated metadata.
fn dependency_table_alias(section: &str) -> Option<&str> {
    for prefix in [
        "workspace.dependencies.",
        "dependencies.",
        "dev-dependencies.",
        "build-dependencies.",
    ] {
        if let Some(candidate) = section
            .strip_prefix(prefix)
            .map(|tail| tail.trim_matches('"'))
            && !candidate.is_empty()
        {
            return Some(candidate);
        }
    }
    if !section.starts_with("target.") {
        return None;
    }
    for marker in ["dependencies.", "dev-dependencies.", "build-dependencies."] {
        if let Some(index) = section.rfind(marker) {
            let candidate = section[index + marker.len()..].trim_matches('"');
            if !candidate.is_empty() {
                return Some(candidate);
            }
        }
    }
    None
}

/// A first-party workspace package is not an unpublished external sibling:
/// the root manifest owns the one internal path edge, and member manifests use
/// `.workspace = true`. This narrow exemption does not allow arbitrary member
/// paths, external sibling checkouts, absolute paths, or nested overrides.
fn is_first_party_workspace_path(
    root: &Path,
    manifest_path: &Path,
    in_workspace_dependencies: bool,
    local_name: &str,
    path: &str,
) -> bool {
    if manifest_path != root.join("Cargo.toml")
        || !in_workspace_dependencies
        || !local_name.starts_with("fgit-")
        || Path::new(path).is_absolute()
    {
        return false;
    }
    let Ok(root_crates) = fs::canonicalize(root.join("crates")) else {
        return false;
    };
    let Ok(candidate) = fs::canonicalize(root.join(path)) else {
        return false;
    };
    if !candidate.starts_with(root_crates) || !candidate.join("Cargo.toml").is_file() {
        return false;
    }
    let Ok(root_manifest) = fs::read_to_string(root.join("Cargo.toml")) else {
        return false;
    };
    workspace_member_path_is_declared(
        &extract_workspace_string_list(&root_manifest, "members"),
        path,
    )
}

/// Cargo workspace globs are legitimate only for direct child crate
/// directories here. Supporting exactly that documented shape keeps the
/// first-party path exemption narrow while allowing the root's `crates/*`
/// membership form to mean the same thing as its expanded member list.
fn workspace_member_path_is_declared(members: &[String], path: &str) -> bool {
    members.iter().any(|member| {
        if member == path {
            return true;
        }
        let Some(parent) = member.strip_suffix("/*") else {
            return false;
        };
        path.strip_prefix(parent)
            .and_then(|tail| tail.strip_prefix('/'))
            .is_some_and(|tail| !tail.is_empty() && !tail.contains('/'))
    })
}

fn looks_like_dependency_declaration(line: &str) -> bool {
    inline_field_value(line, "path").is_some() || inline_field_value(line, "git").is_some()
}

/// Closed-world check over the full resolved graph: every package in
/// Cargo.lock — including transitive dependencies, which manifests alone
/// cannot reveal — must match an active allow row.
fn check_lockfile(root: &Path, allowed: &[String], report: &mut Report) {
    let Ok(text) = fs::read_to_string(root.join("Cargo.lock")) else {
        report.error("cannot read Cargo.lock for closed-world dependency verification");
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("name") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let name = rest.trim().trim_matches('"');
        if name.is_empty() {
            continue;
        }
        if !allowed
            .iter()
            .any(|pattern| dependency_pattern_matches(pattern, name))
        {
            report.error(format!(
                "unregistered resolved dependency `{name}` in Cargo.lock; the closed dependency universe covers the transitive graph"
            ));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    dependencies: Vec<String>,
}

/// Cargo.lock is TOML, but this deliberately handles only its package-array
/// shape. The checker fails closed if a package omits a name or version rather
/// than silently accepting a future lockfile grammar change.
fn parse_lock_packages(text: &str) -> Result<Vec<LockPackage>, String> {
    let mut packages = Vec::new();
    let mut current: Option<LockPackage> = None;
    let mut reading_dependencies = false;

    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line == "[[package]]" {
            if let Some(package) = current.take() {
                if package.name.is_empty() || package.version.is_empty() {
                    return Err(format!(
                        "Cargo.lock package before line {} lacks a name or version",
                        line_number + 1
                    ));
                }
                packages.push(package);
            }
            current = Some(LockPackage {
                name: String::new(),
                version: String::new(),
                source: None,
                checksum: None,
                dependencies: Vec::new(),
            });
            reading_dependencies = false;
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if reading_dependencies {
            if line == "]" {
                reading_dependencies = false;
                continue;
            }
            if let Some(value) = extract_string_value(line.trim_end_matches(',')) {
                package
                    .dependencies
                    .push(lock_dependency_name(&value).to_owned());
            }
            continue;
        }
        if line == "dependencies = [" {
            reading_dependencies = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(value) = extract_string_value(value) else {
            continue;
        };
        match key.trim() {
            "name" => package.name = value,
            "version" => package.version = value,
            "source" => package.source = Some(value),
            "checksum" => package.checksum = Some(value),
            _ => {}
        }
    }
    if let Some(package) = current {
        if package.name.is_empty() || package.version.is_empty() {
            return Err("Cargo.lock final package lacks a name or version".to_owned());
        }
        packages.push(package);
    }
    Ok(packages)
}

fn lock_dependency_name(value: &str) -> &str {
    value.split_ascii_whitespace().next().unwrap_or(value)
}

/// Emits deterministic, reviewable policy rows for an exact admitted closure.
/// It deliberately emits rows rather than editing the registry: a reviewer can
/// inspect every generated rationale and policy before the rows are applied
/// under the registry reservation.
fn generate_admission_ledger(root: &Path, command: CheckSet) -> Result<String, String> {
    let lock_text = fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|error| format!("cannot read Cargo.lock: {error}"))?;
    let packages = parse_lock_packages(&lock_text)?;
    let runtime = packages
        .iter()
        .filter(|package| package.name == "asupersync")
        .collect::<Vec<_>>();
    if runtime.len() != 1 || runtime[0].version != "0.4.9" {
        return Err(format!(
            "expected exactly one asupersync 0.4.9 package before ledger generation, observed {:?}",
            runtime
                .iter()
                .map(|package| package.version.as_str())
                .collect::<Vec<_>>()
        ));
    }
    if command == CheckSet::LedgerConstellation {
        let mut report = Report::new();
        let dependencies = workspace_dependencies(root, &mut report);
        if let Some(error) = report.errors.into_iter().next() {
            return Err(format!(
                "cannot derive workspace dependency evidence for constellation ledger: {error}"
            ));
        }
        return generate_constellation_ledger(&packages, &cargo_metadata(root)?, &dependencies);
    }
    if command == CheckSet::LedgerUnsafe {
        return generate_unsafe_ledger(root, &packages, &cargo_metadata(root)?);
    }
    let config = admission_ledger_config(command)
        .ok_or_else(|| "requested command does not emit admission policy rows".to_owned())?;
    let roots = packages
        .iter()
        .filter(|package| package.name == config.root_package)
        .collect::<Vec<_>>();
    if roots.len() != 1 || roots[0].version != config.root_version {
        return Err(format!(
            "expected exactly one {} {} package before ledger generation, observed {:?}",
            config.root_package,
            config.root_version,
            roots
                .iter()
                .map(|package| package.version.as_str())
                .collect::<Vec<_>>()
        ));
    }
    let closure = dependency_closure(&packages, config.root_package);
    let baseline_allowed = baseline_dependency_patterns(root, config.decision)?;
    let metadata = cargo_metadata(root)?;
    let parent_edges = direct_parent_edges(&packages, &closure);
    let unresolved = packages
        .iter()
        .filter(|package| closure.contains(&package.name))
        .filter(|package| package.source.is_some())
        .filter(|package| {
            !baseline_allowed
                .iter()
                .any(|pattern| dependency_pattern_matches(pattern, &package.name))
        })
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    let surface = enabled_macros::resolve_enabled_surface(root)?;
    let mut output = String::new();
    for (next_id, name) in
        (next_admission_policy_id(root, config, unresolved.len())?..).zip(&unresolved)
    {
        let packages_for_name = packages
            .iter()
            .filter(|package| package.name == *name)
            .collect::<Vec<_>>();
        let feature_policy = resolved_feature_policy(&packages_for_name, &metadata);
        let parent = parent_edges
            .get(name)
            .map_or(config.root_package, String::as_str);
        let proc_macro = packages_for_name
            .iter()
            .any(|package| metadata.proc_macros.contains(&package.name));
        let unsafe_policy = generated_unsafe_policy(name, proc_macro);
        let ffi_policy = generated_ffi_policy(name, proc_macro);
        // FG-069: a generated row must be born with the same values the
        // enumeration gate will demand of it. Emitting a placeholder here would
        // make every freshly admitted dependency fail the lane on its first run,
        // which trains people to hand-patch generated rows.
        let build_script_state = enabled_macros::observed_state_for(
            std::slice::from_ref(name),
            &surface.build_scripts,
            &metadata.build_scripts,
        );
        let proc_macro_state = enabled_macros::observed_state_for(
            std::slice::from_ref(name),
            &surface.proc_macros,
            &metadata.proc_macros,
        );
        writeln!(
            output,
            "DEP-{next_id:03}\t{name}\tproduction\t{}\t{}\t{}_{}_transitive_direct_parent_{parent}\t{feature_policy}\t{unsafe_policy}\t{ffi_policy}\tactive\t{}\t{}",
            config.decision,
            config.owner,
            config.root_package,
            config.root_version,
            build_script_state.as_registry_word(),
            proc_macro_state.as_registry_word(),
        )
        .map_err(|error| format!("cannot render policy row: {error}"))?;
    }
    Ok(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmissionLedgerConfig {
    root_package: &'static str,
    root_version: &'static str,
    decision: &'static str,
    owner: &'static str,
}

const fn admission_ledger_config(command: CheckSet) -> Option<AdmissionLedgerConfig> {
    match command {
        CheckSet::LedgerPolicy => Some(AdmissionLedgerConfig {
            root_package: "asupersync",
            root_version: "0.4.9",
            decision: "allow_transitive_admitted_runtime",
            owner: "concurrency",
        }),
        CheckSet::LedgerFsqlitePolicy => Some(AdmissionLedgerConfig {
            root_package: "fsqlite",
            root_version: "0.3.7",
            decision: "allow_transitive_admitted_fsqlite",
            owner: "storage",
        }),
        _ => None,
    }
}

/// Generated rows must remain reproducible after they have been admitted. The
/// baseline is therefore every active allow row except the generator's own
/// decision; using the full active registry would make a second invocation
/// emit nothing and hide drift.
fn baseline_dependency_patterns(
    root: &Path,
    generated_decision: &str,
) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(root.join("registries/dependency_policy.tsv"))
        .map_err(|error| format!("cannot read dependency policy registry: {error}"))?;
    let mut patterns = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != DEPENDENCY_POLICY_COLUMNS {
            continue;
        }
        if fields[9] == "active"
            && fields[3].starts_with("allow")
            && fields[3] != generated_decision
        {
            patterns.push(fields[1].to_owned());
        }
    }
    Ok(patterns)
}

fn dependency_closure(packages: &[LockPackage], root_name: &str) -> BTreeSet<String> {
    let mut by_name = BTreeMap::<String, Vec<&LockPackage>>::new();
    for package in packages {
        by_name
            .entry(package.name.clone())
            .or_default()
            .push(package);
    }
    let mut closure = BTreeSet::from([root_name.to_owned()]);
    let mut pending = vec![root_name.to_owned()];
    while let Some(name) = pending.pop() {
        for package in by_name.get(&name).into_iter().flatten() {
            for dependency in &package.dependencies {
                if closure.insert(dependency.clone()) {
                    pending.push(dependency.clone());
                }
            }
        }
    }
    closure
}

fn direct_parent_edges(
    packages: &[LockPackage],
    closure: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut parents = BTreeMap::new();
    for package in packages {
        if !closure.contains(&package.name) {
            continue;
        }
        for dependency in &package.dependencies {
            if closure.contains(dependency) {
                parents
                    .entry(dependency.clone())
                    .or_insert_with(|| package.name.clone());
            }
        }
    }
    parents
}

/// A generated admission block retains its first assigned ID even if a later,
/// unrelated policy row is appended. On a fresh registry it starts at the next
/// free ID; once present it is identified by its exact closure identity rather
/// than by the registry tail.
fn next_admission_policy_id(
    root: &Path,
    config: AdmissionLedgerConfig,
    generated_row_count: usize,
) -> Result<usize, String> {
    let text = fs::read_to_string(root.join("registries/dependency_policy.tsv"))
        .map_err(|error| format!("cannot read dependency policy registry: {error}"))?;
    let rows = text
        .lines()
        .filter_map(dependency_policy_fields)
        .filter_map(|fields| {
            fields[0]
                .strip_prefix("DEP-")
                .and_then(|number| number.parse::<usize>().ok())
                .map(|id| (id, admission_policy_row_matches_config(&fields, config)))
        })
        .collect::<Vec<_>>();
    let generated_start = rows
        .iter()
        .filter_map(|(id, matches_config)| (*matches_config).then_some(*id))
        .min();
    if let Some(start) = generated_start {
        let end = start
            .checked_add(generated_row_count)
            .ok_or_else(|| "admission policy ID range overflows usize".to_owned())?;
        for next in start..end {
            if rows
                .iter()
                .any(|(id, matches_config)| *id == next && !*matches_config)
            {
                return Err(format!(
                    "cannot regenerate admission policy rows: DEP-{next:03} is occupied by an unrelated policy; reserve a fresh contiguous ID range before regeneration"
                ));
            }
        }
        return Ok(start);
    }
    let largest = rows.iter().map(|(id, _)| *id).max().unwrap_or(0);
    Ok(largest + 1)
}

fn admission_policy_row_matches_config(
    fields: &[&str; DEPENDENCY_POLICY_COLUMNS],
    config: AdmissionLedgerConfig,
) -> bool {
    fields[3] == config.decision
        && fields[4] == config.owner
        && fields[5].starts_with(&format!(
            "{}_{}_transitive_direct_parent_",
            config.root_package, config.root_version
        ))
}

fn dependency_policy_fields(line: &str) -> Option<[&str; 12]> {
    let fields = line.split('\t').collect::<Vec<_>>();
    (fields.len() == DEPENDENCY_POLICY_COLUMNS).then(|| {
        [
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7],
            fields[8], fields[9], fields[10], fields[11],
        ]
    })
}

fn resolved_feature_policy(packages: &[&LockPackage], metadata: &MetadataSnapshot) -> String {
    let mut features = BTreeSet::new();
    for package in packages {
        if let Some(resolved) = metadata
            .feature_closures
            .get(&(package.name.clone(), package.version.clone()))
        {
            features.extend(resolved.iter().cloned());
        }
    }
    if features.is_empty() {
        "resolved_none".to_owned()
    } else {
        format!(
            "resolved_{}",
            features.into_iter().collect::<Vec<_>>().join("+")
        )
    }
}

fn generated_unsafe_policy(name: &str, proc_macro: bool) -> String {
    expected_unsafe_policy(name, proc_macro)
}

fn generated_ffi_policy(name: &str, proc_macro: bool) -> &'static str {
    if generated_unsafe_policy(name, proc_macro) == "os_abi" {
        "os_abi_shim_no_foreign_engine"
    } else {
        "no_foreign_engine_declared"
    }
}

/// Renders the four currently resolved `FrankenSuite` rows from `Cargo`'s lock and
/// metadata rather than accepting human-invented evidence digests. The public
/// contract fingerprint is a canonical source-level inventory of public-item
/// candidates; it is deliberately not a claim that this lexical pass is a
/// semantic `Rust` API proof. The unsafe digest similarly records a canonical
/// lexical inventory over the package's resolved transitive closure.
fn generate_constellation_ledger(
    packages: &[LockPackage],
    metadata: &MetadataSnapshot,
    dependencies: &[WorkspaceDependency],
) -> Result<String, String> {
    let mut output = String::new();
    for package in packages
        .iter()
        .filter(|package| is_constellation_package(&package.name))
    {
        let source = package.source.as_deref().ok_or_else(|| {
            format!(
                "constellation package `{}` has no release source",
                package.name
            )
        })?;
        if !source.starts_with("registry+") {
            return Err(format!(
                "constellation package `{}` is not a registry release: `{source}`",
                package.name
            ));
        }
        let checksum = package
            .checksum
            .as_deref()
            .filter(|checksum| is_hex_digest(checksum, 64))
            .ok_or_else(|| {
                format!(
                    "constellation package `{}` has no 64-hex checksum",
                    package.name
                )
            })?;
        let package_source = metadata
            .package_sources
            .get(&(package.name.clone(), package.version.clone()))
            .ok_or_else(|| {
                format!(
                    "cargo metadata lacks source evidence for constellation package `{}` {}",
                    package.name, package.version
                )
            })?;
        let license = package_license_evidence(package_source).map_err(|error| {
            format!(
                "cargo metadata lacks license evidence for constellation package `{}` {}: {error}",
                package.name, package.version
            )
        })?;
        let features = metadata
            .feature_closures
            .get(&(package.name.clone(), package.version.clone()))
            .ok_or_else(|| {
                format!(
                    "cargo metadata lacks resolved features for constellation package `{}` {}",
                    package.name, package.version
                )
            })?;
        let public_contract_fingerprint = public_contract_fingerprint(package, metadata)?;
        let transitive_unsafe_digest = transitive_unsafe_digest(package, packages, metadata)?;
        let build_scripts = if metadata.build_scripts.contains(&package.name) {
            "enabled"
        } else {
            "disabled"
        };
        let proc_macros = if metadata.proc_macros.contains(&package.name) {
            "enabled"
        } else {
            "disabled"
        };
        let default_features = constellation_default_features(package, dependencies)?;
        let features = canonical_feature_list(features);
        writeln!(
            output,
            "{}\t{source}\t{}\tnot_applicable\t{checksum}\t{features}\t{default_features}\t{public_contract_fingerprint}\tall-cargo-lock-targets\t{}\t{build_scripts}\t{proc_macros}\t{transitive_unsafe_digest}\tadmitted\tdocs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md#7-dependency-admission-procedure",
            package.name, package.version, license,
        )
        .map_err(|error| format!("cannot render constellation row: {error}"))?;
    }
    if output.is_empty() {
        return Err("Cargo.lock has no resolved constellation package".to_owned());
    }
    Ok(output)
}

fn constellation_default_features(
    package: &LockPackage,
    dependencies: &[WorkspaceDependency],
) -> Result<String, String> {
    let direct_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.package == package.name)
        .collect::<Vec<_>>();
    let states = direct_dependencies
        .iter()
        .map(|dependency| dependency.default_features.as_str())
        .collect::<BTreeSet<_>>();
    match states.len() {
        0 => Ok("not_applicable".to_owned()),
        1 => states
            .first()
            .map(|state| (*state).to_owned())
            .ok_or_else(|| "default-feature state collection unexpectedly empty".to_owned()),
        _ => Err(format!(
            "constellation package `{}` has conflicting direct default-feature states: {:?}; declarations: {}",
            package.name,
            states,
            direct_dependencies
                .iter()
                .map(|dependency| format!(
                    "{}@{}={}",
                    dependency.manifest,
                    dependency.version.as_deref().unwrap_or("unversioned"),
                    dependency.default_features
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn canonical_feature_list(features: &BTreeSet<String>) -> String {
    if features.is_empty() {
        "none".to_owned()
    } else {
        features.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

fn public_contract_fingerprint(
    package: &LockPackage,
    metadata: &MetadataSnapshot,
) -> Result<String, String> {
    let source = package_source(package, metadata)?;
    let source_root = source_root(source)?;
    let files = rust_source_files(&source_root)?;
    let mut inventory = format!(
        "frankengit.public-contract-candidate-inventory.v1\n{}@{}\n",
        package.name, package.version
    );
    for path in files {
        let text = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read source `{}`: {error}", path.display()))?;
        let display = relative(&source_root, &path);
        for (line_number, line) in text.lines().enumerate() {
            let candidate = line.trim();
            if is_public_contract_candidate(candidate) {
                writeln!(inventory, "{display}:{}:{candidate}", line_number + 1)
                    .map_err(|error| format!("cannot render public inventory: {error}"))?;
            }
        }
    }
    Ok(sha256_hex(inventory.as_bytes()))
}

fn transitive_unsafe_digest(
    package: &LockPackage,
    packages: &[LockPackage],
    metadata: &MetadataSnapshot,
) -> Result<String, String> {
    let closure = dependency_closure(packages, &package.name);
    let mut inventory = format!(
        "frankengit.transitive-lexical-unsafe-inventory.v1\nroot={}@{}\n",
        package.name, package.version
    );
    for dependency in packages
        .iter()
        .filter(|dependency| closure.contains(&dependency.name))
    {
        let source = dependency.source.as_deref().unwrap_or("workspace");
        let checksum = dependency.checksum.as_deref().unwrap_or("not_applicable");
        writeln!(
            inventory,
            "package={}@{}\tsource={source}\tchecksum={checksum}",
            dependency.name, dependency.version
        )
        .map_err(|error| format!("cannot render unsafe inventory package: {error}"))?;
        let source_root = source_root(package_source(dependency, metadata)?)?;
        for path in rust_source_files(&source_root)? {
            let text = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read source `{}`: {error}", path.display()))?;
            let display = relative(&source_root, &path);
            for (line_number, line) in text.lines().enumerate() {
                if let Some(token) = find_unsafe_construct(line) {
                    writeln!(
                        inventory,
                        "lexical-candidate={}@{}:{display}:{}:{token}",
                        dependency.name,
                        dependency.version,
                        line_number + 1
                    )
                    .map_err(|error| format!("cannot render unsafe inventory item: {error}"))?;
                }
            }
        }
    }
    Ok(sha256_hex(inventory.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveDependencyPolicy {
    id: String,
    crate_pattern: String,
    unsafe_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnsafeLedgerRow {
    name: String,
    version: String,
    source: String,
    checksum: String,
    rust_files: usize,
    unsafe_tokens: usize,
    build_script: bool,
    proc_macro: bool,
    expected_policy: String,
    registry_policy: String,
}

/// Emits the resolved-lock lexical unsafe inventory. It is evidence about the
/// source tree Cargo selected, not a reachability or soundness proof: generated
/// expansion and target-specific dead code remain explicitly visible limits.
fn generate_unsafe_ledger(
    root: &Path,
    packages: &[LockPackage],
    metadata: &MetadataSnapshot,
) -> Result<String, String> {
    let policies = load_active_dependency_policies(root)?;
    let rows = unsafe_ledger_rows(packages, metadata, &policies)?;
    let mut output = String::from(
        "# franken-unsafe-ledger-v1\npackage\tversion\tsource\tchecksum\trust_files\tunsafe_tokens\tbuild_script\tproc_macro\texpected_unsafe_policy\tregistry_unsafe_policy\tpolicy_match\n",
    );
    for row in rows {
        let policy_match = unsafe_policy_matches(&row.expected_policy, &row.registry_policy);
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.name,
            row.version,
            row.source,
            row.checksum,
            row.rust_files,
            row.unsafe_tokens,
            bool_word(row.build_script),
            bool_word(row.proc_macro),
            row.expected_policy,
            row.registry_policy,
            bool_word(policy_match),
        )
        .map_err(|error| format!("cannot render unsafe ledger row: {error}"))?;
    }
    Ok(output)
}

/// Treats unsafe-policy drift as a constitutional finding. The emitted ledger
/// remains separately reviewable, while this gate makes an unacknowledged
/// resolved package incapable of passing the constitution lane.
fn check_unsafe_ledger_policies(root: &Path, report: &mut Report) {
    let lock_text = match fs::read_to_string(root.join("Cargo.lock")) {
        Ok(value) => value,
        Err(error) => {
            report.error(format!(
                "cannot read Cargo.lock for unsafe ledger verification: {error}"
            ));
            return;
        }
    };
    let packages = match parse_lock_packages(&lock_text) {
        Ok(value) => value,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    let metadata = match cargo_metadata(root) {
        Ok(value) => value,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    let policies = match load_active_dependency_policies(root) {
        Ok(value) => value,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    let rows = match unsafe_ledger_rows(&packages, &metadata, &policies) {
        Ok(value) => value,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    report_unsafe_ledger_policy_mismatches(&rows, report);
}

fn report_unsafe_ledger_policy_mismatches(rows: &[UnsafeLedgerRow], report: &mut Report) {
    for row in rows {
        if !unsafe_policy_matches(&row.expected_policy, &row.registry_policy) {
            report.error(format!(
                "unsafe ledger policy mismatch for resolved package `{} {}`: expected `{}`, registry declares `{}`",
                row.name, row.version, row.expected_policy, row.registry_policy
            ));
        }
    }
}

fn load_active_dependency_policies(root: &Path) -> Result<Vec<ActiveDependencyPolicy>, String> {
    let text = fs::read_to_string(root.join("registries/dependency_policy.tsv"))
        .map_err(|error| format!("cannot read dependency policy registry: {error}"))?;
    let mut policies = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != DEPENDENCY_POLICY_COLUMNS {
            return Err(format!(
                "dependency policy line {} has {} columns; expected {DEPENDENCY_POLICY_COLUMNS}",
                line_number + 1,
                fields.len()
            ));
        }
        if fields[9] == "active" {
            policies.push(ActiveDependencyPolicy {
                id: fields[0].to_owned(),
                crate_pattern: fields[1].to_owned(),
                unsafe_policy: fields[7].to_owned(),
            });
        }
    }
    policies.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(policies)
}

fn unsafe_ledger_rows(
    packages: &[LockPackage],
    metadata: &MetadataSnapshot,
    policies: &[ActiveDependencyPolicy],
) -> Result<Vec<UnsafeLedgerRow>, String> {
    let mut ordered = packages.to_vec();
    ordered.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    let mut rows = Vec::with_capacity(ordered.len());
    for package in &ordered {
        let policy = active_policy_for_package(policies, &package.name).ok_or_else(|| {
            format!(
                "unsafe ledger lacks an active dependency policy for resolved package `{}` {}",
                package.name, package.version
            )
        })?;
        let package_source = package_source(package, metadata)?;
        let source_root = source_root(package_source)?;
        let source_files = rust_source_files(&source_root)?;
        let mut unsafe_tokens = 0usize;
        for path in &source_files {
            let text = fs::read_to_string(path)
                .map_err(|error| format!("cannot read source `{}`: {error}", path.display()))?;
            unsafe_tokens = unsafe_tokens.saturating_add(count_unsafe_constructs(&text));
        }
        let proc_macro = metadata.proc_macros.contains(&package.name);
        let expected_policy = expected_unsafe_policy(&package.name, proc_macro);
        rows.push(UnsafeLedgerRow {
            name: package.name.clone(),
            version: package.version.clone(),
            source: package
                .source
                .clone()
                .unwrap_or_else(|| "workspace".to_owned()),
            checksum: package
                .checksum
                .clone()
                .unwrap_or_else(|| "not_applicable".to_owned()),
            rust_files: source_files.len(),
            unsafe_tokens,
            build_script: metadata.build_scripts.contains(&package.name),
            proc_macro,
            expected_policy,
            registry_policy: policy.unsafe_policy.clone(),
        });
    }
    Ok(rows)
}

fn active_policy_for_package<'a>(
    policies: &'a [ActiveDependencyPolicy],
    package: &str,
) -> Option<&'a ActiveDependencyPolicy> {
    policies
        .iter()
        .filter(|policy| dependency_pattern_matches(&policy.crate_pattern, package))
        .min_by(|left, right| {
            let left_exact = left.crate_pattern == package;
            let right_exact = right.crate_pattern == package;
            right_exact
                .cmp(&left_exact)
                .then_with(|| right.crate_pattern.len().cmp(&left.crate_pattern.len()))
                .then_with(|| left.id.cmp(&right.id))
        })
}

fn expected_unsafe_policy(package: &str, proc_macro: bool) -> String {
    if package.starts_with("fgit-") {
        "must_forbid_first_party_unsafe".to_owned()
    } else if package.starts_with("franken-")
        || package.starts_with("franken_")
        || package == "fsqlite"
        || package.starts_with("fsqlite-")
        || package == "frankensqlite"
    {
        "must_match_sibling_contract".to_owned()
    } else if proc_macro
        || package.starts_with("wasm-bindgen")
        || matches!(package, "proc-macro2" | "quote" | "syn" | "tinyvec_macros")
    {
        "proc_macro_transitive".to_owned()
    } else if matches!(
        package,
        "dispatch2"
            | "hermit-abi"
            | "libc"
            | "nix"
            | "ntapi"
            | "r-efi"
            | "redox_syscall"
            | "rustix"
            | "socket2"
            | "wasi"
            | "windows"
            | "windows-sys"
            | "winapi"
    ) || package.starts_with("windows-")
        || package.starts_with("winapi")
        || package.starts_with("objc2")
    {
        "os_abi".to_owned()
    } else {
        "ledgered_transitive".to_owned()
    }
}

fn unsafe_policy_matches(expected: &str, observed: &str) -> bool {
    expected == observed
}

fn count_unsafe_constructs(text: &str) -> usize {
    let mut remaining = text;
    let mut count = 0usize;
    while let Some(token) = find_unsafe_construct(remaining) {
        count = count.saturating_add(1);
        let marker = token.split_ascii_whitespace().next().unwrap_or_default();
        let Some(position) = remaining.find(marker) else {
            break;
        };
        remaining = &remaining[position + marker.len()..];
    }
    count
}

const fn bool_word(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn package_source<'a>(
    package: &LockPackage,
    metadata: &'a MetadataSnapshot,
) -> Result<&'a PackageSource, String> {
    metadata
        .package_sources
        .get(&(package.name.clone(), package.version.clone()))
        .ok_or_else(|| {
            format!(
                "cargo metadata lacks source evidence for package `{}` {}",
                package.name, package.version
            )
        })
}

fn source_root(source: &PackageSource) -> Result<PathBuf, String> {
    let root = source
        .manifest_path
        .parent()
        .ok_or_else(|| {
            format!(
                "manifest `{}` has no parent",
                source.manifest_path.display()
            )
        })?
        .join("src");
    if !root.is_dir() {
        return Err(format!(
            "package source directory `{}` is missing",
            root.display()
        ));
    }
    Ok(root)
}

fn rust_source_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_files(root, &mut files);
    files.retain(|path| path.extension() == Some(OsStr::new("rs")));
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "package source directory `{}` has no Rust files",
            root.display()
        ));
    }
    Ok(files)
}

fn is_public_contract_candidate(line: &str) -> bool {
    line.starts_with("pub ") || line.starts_with("pub(")
}

const SHA256_INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn sha256_hex(bytes: &[u8]) -> String {
    let bit_length = u64::try_from(bytes.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len().rem_euclid(64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = SHA256_INITIAL;
    let (blocks, trailing_bytes) = padded.as_chunks::<64>();
    assert!(
        trailing_bytes.is_empty(),
        "SHA-256 padding must be block-aligned"
    );
    for chunk in blocks {
        let mut words = [0_u32; 64];
        let (initial_words, trailing_bytes) = chunk.as_chunks::<4>();
        assert!(
            trailing_bytes.is_empty(),
            "SHA-256 block must split into 32-bit words"
        );
        for (index, bytes) in initial_words.iter().enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..words.len() {
            let sigma0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let sigma1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(sigma1);
        }
        let [
            mut hash_a,
            mut hash_b,
            mut hash_c,
            mut hash_d,
            mut hash_e,
            mut hash_f,
            mut hash_g,
            mut hash_h,
        ] = state;
        for (index, constant) in SHA256_ROUND_CONSTANTS.iter().enumerate() {
            let sigma1 = hash_e.rotate_right(6) ^ hash_e.rotate_right(11) ^ hash_e.rotate_right(25);
            let choose = (hash_e & hash_f) ^ ((!hash_e) & hash_g);
            let temp1 = hash_h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(words[index]);
            let sigma0 = hash_a.rotate_right(2) ^ hash_a.rotate_right(13) ^ hash_a.rotate_right(22);
            let majority = (hash_a & hash_b) ^ (hash_a & hash_c) ^ (hash_b & hash_c);
            let temp2 = sigma0.wrapping_add(majority);
            hash_h = hash_g;
            hash_g = hash_f;
            hash_f = hash_e;
            hash_e = hash_d.wrapping_add(temp1);
            hash_d = hash_c;
            hash_c = hash_b;
            hash_b = hash_a;
            hash_a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(hash_a);
        state[1] = state[1].wrapping_add(hash_b);
        state[2] = state[2].wrapping_add(hash_c);
        state[3] = state[3].wrapping_add(hash_d);
        state[4] = state[4].wrapping_add(hash_e);
        state[5] = state[5].wrapping_add(hash_f);
        state[6] = state[6].wrapping_add(hash_g);
        state[7] = state[7].wrapping_add(hash_h);
    }
    let mut output = String::with_capacity(64);
    for word in state {
        write!(output, "{word:08x}").expect("writing to a String cannot fail");
    }
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstellationState {
    Dormant,
    Candidate,
    Admitted,
}

impl ConstellationState {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "dormant" => Ok(Self::Dormant),
            "candidate" => Ok(Self::Candidate),
            "admitted" => Ok(Self::Admitted),
            other => Err(format!(
                "constellation.lock state `{other}` is invalid; expected dormant, candidate, or admitted"
            )),
        }
    }
}

const CONSTELLATION_COLUMNS: [&str; 15] = [
    "package",
    "source",
    "version",
    "revision",
    "checksum",
    "features",
    "default_features",
    "public_contract_fingerprint",
    "target_support",
    "license",
    "build_scripts",
    "proc_macros",
    "transitive_unsafe_digest",
    "evidence_class",
    "removal_update_path",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConstellationEntry {
    package: String,
    source: String,
    version: String,
    revision: String,
    checksum: String,
    features: BTreeSet<String>,
    default_features: String,
    public_contract_fingerprint: String,
    target_support: String,
    license: String,
    build_scripts: String,
    proc_macros: String,
    transitive_unsafe_digest: String,
    evidence_class: String,
    removal_update_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConstellationLock {
    state: ConstellationState,
    entries: BTreeMap<String, ConstellationEntry>,
}

fn parse_constellation_lock(text: &str) -> Result<ConstellationLock, String> {
    let meaningful = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>();
    if meaningful.is_empty() {
        return Err("constellation.lock is empty".to_owned());
    }
    if !text.lines().any(|line| line.trim() == CONSTELLATION_MARKER) {
        return Err(format!(
            "constellation.lock marker mismatch; expected `{CONSTELLATION_MARKER}`"
        ));
    }
    if meaningful.len() < 2 {
        return Err("constellation.lock lacks state or header".to_owned());
    }
    let (state_line, state) = meaningful[0];
    let Some((key, value)) = state.split_once('\t') else {
        return Err(format!(
            "constellation.lock:{} must declare `state<TAB>...`",
            state_line + 1
        ));
    };
    if key != "state" {
        return Err(format!(
            "constellation.lock:{} must start with `state`",
            state_line + 1
        ));
    }
    let state = ConstellationState::parse(value)?;
    let (header_line, header) = meaningful[1];
    let observed = header.split('\t').collect::<Vec<_>>();
    if observed != CONSTELLATION_COLUMNS {
        return Err(format!(
            "constellation.lock:{} header mismatch: expected {:?}, observed {:?}",
            header_line + 1,
            CONSTELLATION_COLUMNS,
            observed
        ));
    }

    let mut entries = BTreeMap::new();
    for (line_number, line) in meaningful.into_iter().skip(2) {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != CONSTELLATION_COLUMNS.len() {
            return Err(format!(
                "constellation.lock:{} column count mismatch: expected {}, observed {}",
                line_number + 1,
                CONSTELLATION_COLUMNS.len(),
                fields.len()
            ));
        }
        for (index, value) in fields.iter().enumerate() {
            if value.trim().is_empty() {
                return Err(format!(
                    "constellation.lock:{} empty `{}` evidence field",
                    line_number + 1,
                    CONSTELLATION_COLUMNS[index]
                ));
            }
        }
        let entry = ConstellationEntry {
            package: fields[0].to_owned(),
            source: fields[1].to_owned(),
            version: fields[2].to_owned(),
            revision: fields[3].to_owned(),
            checksum: fields[4].to_owned(),
            features: parse_canonical_list(fields[5], "features", line_number + 1)?,
            default_features: fields[6].to_owned(),
            public_contract_fingerprint: fields[7].to_owned(),
            target_support: fields[8].to_owned(),
            license: fields[9].to_owned(),
            build_scripts: fields[10].to_owned(),
            proc_macros: fields[11].to_owned(),
            transitive_unsafe_digest: fields[12].to_owned(),
            evidence_class: fields[13].to_owned(),
            removal_update_path: fields[14].to_owned(),
        };
        if entries.insert(entry.package.clone(), entry).is_some() {
            return Err(format!(
                "constellation.lock:{} duplicates a package row",
                line_number + 1
            ));
        }
    }
    Ok(ConstellationLock { state, entries })
}

fn parse_canonical_list(
    value: &str,
    field: &str,
    line_number: usize,
) -> Result<BTreeSet<String>, String> {
    if value == "none" {
        return Ok(BTreeSet::new());
    }
    let values = value.split(',').map(str::to_owned).collect::<Vec<_>>();
    if values.iter().any(|item| item.is_empty()) {
        return Err(format!(
            "constellation.lock:{line_number} `{field}` has an empty list item"
        ));
    }
    let canonical = values.iter().collect::<BTreeSet<_>>();
    if canonical.len() != values.len() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!(
            "constellation.lock:{line_number} `{field}` must be sorted, unique, comma-separated values or `none`"
        ));
    }
    Ok(values.into_iter().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CrateLayer {
    L0,
    L1,
    L2,
    L3,
    L4,
}

impl CrateLayer {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "L0" => Some(Self::L0),
            "L1" => Some(Self::L1),
            "L2" => Some(Self::L2),
            "L3" => Some(Self::L3),
            "L4" => Some(Self::L4),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
            Self::L4 => "L4",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CrateLayerEntry {
    crate_name: String,
    layer: CrateLayer,
    allowed_dependency_layers: BTreeSet<CrateLayer>,
    owner: String,
    status: String,
}

#[derive(Debug, Default)]
struct CrateLayerRegistry {
    entries: BTreeMap<String, CrateLayerEntry>,
}

#[derive(Debug, Default)]
struct LayerReport {
    rows: Vec<String>,
}

impl LayerReport {
    fn render(&self) -> String {
        let mut output = String::from(LAYER_REPORT_MARKER);
        output.push('\n');
        output.push_str(
            "record\tcrate\tlayer\towner\tstatus\tdependency\tdependency_layer\tallowed_dependency_layers\toutcome\n",
        );
        for row in &self.rows {
            output.push_str(row);
            output.push('\n');
        }
        output
    }
}

fn evaluate_crate_layers(root: &Path, report: &mut Report) -> LayerReport {
    let registry = load_crate_layer_registry(root, report);
    let workspace_crates = workspace_crate_names(root, report);
    let mut layer_report = LayerReport::default();

    for (crate_name, manifest) in &workspace_crates {
        if !registry.entries.contains_key(crate_name) {
            report.error(format!(
                "crate-layer registry lacks workspace crate `{crate_name}` declared by {manifest}"
            ));
        }
    }
    for crate_name in registry.entries.keys() {
        if !workspace_crates.contains_key(crate_name) {
            report.error(format!(
                "crate-layer registry declares non-workspace crate `{crate_name}`"
            ));
        }
    }

    for entry in registry.entries.values() {
        layer_report.rows.push(format!(
            "crate\t{}\t{}\t{}\t{}\t-\t-\t{}\tregistered",
            entry.crate_name,
            entry.layer.as_str(),
            entry.owner,
            entry.status,
            render_allowed_layers(&entry.allowed_dependency_layers)
        ));
    }

    let mut edges = workspace_declared_dependency_edges(root, &workspace_crates, report)
        .into_iter()
        .filter(|(_, dependency)| registry.entries.contains_key(dependency))
        .collect::<Vec<_>>();
    edges.sort();
    edges.dedup();

    for (source, dependency) in edges {
        let Some(source_entry) = registry.entries.get(&source) else {
            continue;
        };
        let Some(dependency_entry) = registry.entries.get(&dependency) else {
            continue;
        };
        let allowed = render_allowed_layers(&source_entry.allowed_dependency_layers);
        let outcome = if dependency_entry.layer > source_entry.layer {
            report.error(format!(
                "crate-layer violation `{source}` ({}) -> `{dependency}` ({}): a crate may not depend on a higher layer; raise the source crate layer to at least {}",
                source_entry.layer.as_str(),
                dependency_entry.layer.as_str(),
                dependency_entry.layer.as_str(),
            ));
            "upward_layer_violation"
        } else if source_entry.layer == CrateLayer::L3 && dependency_entry.layer == CrateLayer::L3 {
            report.error(format!(
                "crate-layer violation `{source}` (L3) -> `{dependency}` (L3): L3 siblings may not depend on one another"
            ));
            "l3_sibling_violation"
        } else if !source_entry
            .allowed_dependency_layers
            .contains(&dependency_entry.layer)
        {
            report.error(format!(
                "crate-layer violation `{source}` ({}) -> `{dependency}` ({}): target layer is absent from declared allowed layers `{allowed}`",
                source_entry.layer.as_str(),
                dependency_entry.layer.as_str(),
            ));
            "undeclared_layer_violation"
        } else {
            "permitted"
        };
        layer_report.rows.push(format!(
            "edge\t{source}\t{}\t{}\t{}\t{dependency}\t{}\t{allowed}\t{outcome}",
            source_entry.layer.as_str(),
            source_entry.owner,
            source_entry.status,
            dependency_entry.layer.as_str(),
        ));
    }

    layer_report
}

fn workspace_declared_dependency_edges(
    root: &Path,
    workspace_crates: &BTreeMap<String, String>,
    report: &mut Report,
) -> Vec<(String, String)> {
    let mut edges = Vec::new();
    for (crate_name, manifest) in workspace_crates {
        let path = root.join(manifest);
        let Ok(text) = fs::read_to_string(&path) else {
            report.error(format!("cannot read workspace manifest {manifest}"));
            continue;
        };
        edges.extend(
            manifest_dependency_names(&text)
                .into_iter()
                .map(|dependency| (crate_name.clone(), dependency)),
        );
    }
    edges
}

fn load_crate_layer_registry(root: &Path, report: &mut Report) -> CrateLayerRegistry {
    let path = root.join(CRATE_LAYERS_FILE);
    let display = relative(root, &path);
    let Ok(text) = fs::read_to_string(&path) else {
        report.error(format!("cannot read crate-layer registry {display}"));
        return CrateLayerRegistry::default();
    };
    let mut non_empty = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty());
    let Some((marker_line, marker)) = non_empty.next() else {
        report.error(format!("empty crate-layer registry {display}"));
        return CrateLayerRegistry::default();
    };
    let expected_marker = registry_marker_for("crate_layers.tsv");
    if marker.trim() != expected_marker {
        report.error(format!(
            "crate-layer registry marker mismatch at {display}:{}: expected `{expected_marker}`",
            marker_line + 1
        ));
    }
    let Some((header_line, header)) =
        non_empty.find(|(_, line)| !line.trim_start().starts_with('#'))
    else {
        report.error(format!("crate-layer registry has no header: {display}"));
        return CrateLayerRegistry::default();
    };
    let observed_header = header.split('\t').collect::<Vec<_>>();
    if observed_header != CRATE_LAYERS_COLUMNS {
        report.error(format!(
            "crate-layer registry header mismatch at {display}:{}: expected {:?}, observed {:?}",
            header_line + 1,
            CRATE_LAYERS_COLUMNS,
            observed_header
        ));
        return CrateLayerRegistry::default();
    }

    let mut registry = CrateLayerRegistry::default();
    let mut previous_name: Option<String> = None;
    for (line_index, line) in text.lines().enumerate().skip(header_line + 1) {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != CRATE_LAYERS_COLUMNS.len() {
            report.error(format!(
                "crate-layer registry column count mismatch at {display}:{}: expected {}, observed {}",
                line_index + 1,
                CRATE_LAYERS_COLUMNS.len(),
                fields.len()
            ));
            continue;
        }
        if fields.iter().any(|field| field.trim().is_empty()) {
            report.error(format!(
                "crate-layer registry has an empty field at {display}:{}",
                line_index + 1
            ));
            continue;
        }
        let crate_name = fields[0].to_owned();
        if !crate_name.starts_with("fgit-") {
            report.error(format!(
                "crate-layer registry crate `{crate_name}` at {display}:{} is not first-party",
                line_index + 1
            ));
        }
        if let Some(previous) = &previous_name
            && crate_name <= *previous
        {
            report.error(format!(
                "crate-layer registry crate names are not strictly sorted at {display}:{}: `{crate_name}` follows `{previous}`",
                line_index + 1
            ));
        }
        previous_name = Some(crate_name.clone());
        let Some(layer) = CrateLayer::parse(fields[1]) else {
            report.error(format!(
                "crate-layer registry `{crate_name}` at {display}:{} has unknown layer `{}`",
                line_index + 1,
                fields[1]
            ));
            continue;
        };
        let allowed_dependency_layers = match parse_allowed_layers(fields[2]) {
            Ok(value) => value,
            Err(error) => {
                report.error(format!(
                    "crate-layer registry `{crate_name}` at {display}:{} {error}",
                    line_index + 1
                ));
                continue;
            }
        };
        if !is_known_status(fields[4]) {
            report.error(format!(
                "crate-layer registry `{crate_name}` at {display}:{} has unknown status `{}`",
                line_index + 1,
                fields[4]
            ));
        }
        let entry = CrateLayerEntry {
            crate_name: crate_name.clone(),
            layer,
            allowed_dependency_layers,
            owner: fields[3].to_owned(),
            status: fields[4].to_owned(),
        };
        if registry.entries.insert(crate_name, entry).is_some() {
            report.error(format!(
                "crate-layer registry duplicates a crate row at {display}:{}",
                line_index + 1
            ));
        }
    }
    registry
}

fn parse_allowed_layers(value: &str) -> Result<BTreeSet<CrateLayer>, String> {
    if value == "none" {
        return Ok(BTreeSet::new());
    }
    let mut layers = BTreeSet::new();
    for raw_layer in value.split(',') {
        let Some(layer) = CrateLayer::parse(raw_layer) else {
            return Err(format!(
                "has unknown allowed dependency layer `{raw_layer}`"
            ));
        };
        if !layers.insert(layer) {
            return Err(format!("duplicates allowed dependency layer `{raw_layer}`"));
        }
    }
    if render_allowed_layers(&layers) != value {
        return Err("allowed dependency layers must be sorted and comma-separated".to_owned());
    }
    Ok(layers)
}

fn render_allowed_layers(layers: &BTreeSet<CrateLayer>) -> String {
    if layers.is_empty() {
        "none".to_owned()
    } else {
        layers
            .iter()
            .map(|layer| layer.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn workspace_crate_names(root: &Path, report: &mut Report) -> BTreeMap<String, String> {
    let mut crates = BTreeMap::new();
    for path in workspace_manifest_paths(root, report) {
        let display = relative(root, &path);
        let Ok(text) = fs::read_to_string(&path) else {
            report.error(format!("cannot read workspace manifest {display}"));
            continue;
        };
        let Some(crate_name) = parse_manifest_package_name(&text) else {
            report.error(format!(
                "workspace manifest {display} lacks a package name for crate-layer validation"
            ));
            continue;
        };
        if let Some(previous) = crates.insert(crate_name.clone(), display.clone()) {
            report.error(format!(
                "workspace crate `{crate_name}` has duplicate manifests `{previous}` and `{display}`"
            ));
        }
    }
    crates
}

fn parse_manifest_package_name(text: &str) -> Option<String> {
    let mut in_package = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "name" {
            return extract_string_value(value);
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceDependency {
    package: String,
    manifest: String,
    version: Option<String>,
    default_features: String,
    declared_features: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceDependencyTemplate {
    package: String,
    version: Option<String>,
    default_features: String,
    declared_features: BTreeSet<String>,
}

/// Only manifests actually listed in the root workspace define the
/// release-facing graph. This prevents an untracked sibling worktree or a
/// checker fixture from turning the shared constitutional lane red before its
/// owner has joined it to the workspace and resolved its lockfile.
fn workspace_manifest_paths(root: &Path, report: &mut Report) -> Vec<PathBuf> {
    let root_manifest = root.join("Cargo.toml");
    let Ok(text) = fs::read_to_string(&root_manifest) else {
        report.error("cannot read root Cargo.toml for workspace membership");
        return Vec::new();
    };
    let mut members = extract_workspace_string_list(&text, "members");
    members.sort();
    members.dedup();
    let mut manifests = Vec::new();
    for member in members {
        if let Some(parent) = member.strip_suffix("/*") {
            let directory = root.join(parent);
            let Ok(entries) = fs::read_dir(&directory) else {
                report.error(format!(
                    "workspace member glob directory cannot be read: {}",
                    relative(root, &directory)
                ));
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path().join("Cargo.toml");
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) && path.is_file() {
                    manifests.push(path);
                }
            }
            continue;
        }
        let path = root.join(member).join("Cargo.toml");
        if path.is_file() {
            manifests.push(path);
        } else {
            report.error(format!(
                "workspace member lacks Cargo.toml: {}",
                relative(root, &path)
            ));
        }
    }
    manifests.sort();
    manifests.dedup();
    manifests
}

fn extract_workspace_string_list(text: &str, key: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut collecting = false;
    let mut body = String::new();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line == "[workspace]" {
            collecting = true;
            continue;
        }
        if collecting && line.starts_with('[') {
            break;
        }
        if !collecting {
            continue;
        }
        if body.is_empty() {
            let Some(value) = line
                .strip_prefix(key)
                .and_then(|rest| rest.trim_start().strip_prefix('='))
            else {
                continue;
            };
            body.push_str(value);
        } else {
            body.push(' ');
            body.push_str(line);
        }
        if !body.contains(']') {
            continue;
        }
        let Some(open) = body.find('[') else {
            return result;
        };
        let Some(close) = body.rfind(']') else {
            return result;
        };
        let values = &body[open + 1..close];
        for item in values.split(',') {
            if let Some(value) = extract_string_value(item) {
                result.push(value);
            }
        }
        return result;
    }
    result
}

fn workspace_dependencies(root: &Path, report: &mut Report) -> Vec<WorkspaceDependency> {
    let root_dependencies = workspace_dependency_templates(root, report);
    let mut dependencies = Vec::new();
    for path in workspace_manifest_paths(root, report) {
        let display = relative(root, &path);
        let Ok(text) = fs::read_to_string(&path) else {
            report.error(format!("cannot read workspace manifest {display}"));
            continue;
        };
        dependencies.extend(parse_manifest_dependencies(
            &display,
            &text,
            &root_dependencies,
            report,
        ));
    }
    dependencies
}

fn workspace_dependency_templates(
    root: &Path,
    report: &mut Report,
) -> BTreeMap<String, WorkspaceDependencyTemplate> {
    let path = root.join("Cargo.toml");
    let Ok(text) = fs::read_to_string(&path) else {
        report.error("cannot read root Cargo.toml for workspace dependency inheritance");
        return BTreeMap::new();
    };
    parse_workspace_dependency_templates(&text, report)
}

fn parse_workspace_dependency_templates(
    text: &str,
    report: &mut Report,
) -> BTreeMap<String, WorkspaceDependencyTemplate> {
    let mut templates = BTreeMap::new();
    let mut in_workspace_dependencies = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_workspace_dependencies = line == "[workspace.dependencies]";
            continue;
        }
        if !in_workspace_dependencies || line.is_empty() {
            continue;
        }
        let Some((raw_name, value)) = line.split_once('=') else {
            continue;
        };
        let name = raw_name.trim().trim_matches('"');
        if name.is_empty() {
            continue;
        }
        let template = dependency_template(name, value);
        if templates.insert(name.to_owned(), template).is_some() {
            report.error(format!(
                "root [workspace.dependencies] declares `{name}` more than once"
            ));
        }
    }
    templates
}

fn parse_manifest_dependencies(
    display: &str,
    text: &str,
    root_dependencies: &BTreeMap<String, WorkspaceDependencyTemplate>,
    report: &mut Report,
) -> Vec<WorkspaceDependency> {
    let mut dependencies = Vec::new();
    let mut in_dependencies = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            in_dependencies = is_dependency_section(section);
            continue;
        }
        if !in_dependencies || line.is_empty() {
            continue;
        }
        let Some((raw_name, value)) = line.split_once('=') else {
            continue;
        };
        let raw_name = raw_name.trim().trim_matches('"');
        let (name, dotted_workspace) = raw_name
            .strip_suffix(".workspace")
            .map_or((raw_name, false), |name| (name, true));
        if name.is_empty() {
            continue;
        }
        let inherited = dotted_workspace && extract_bool_value(value) == Some(true)
            || extract_inline_bool_field(value, "workspace") == Some(true);
        let template = if inherited {
            match root_dependencies.get(name) {
                Some(template) => template.clone(),
                None => {
                    report.error(format!(
                        "workspace dependency `{name}` in {display} is absent from root [workspace.dependencies]"
                    ));
                    continue;
                }
            }
        } else {
            dependency_template(name, value)
        };
        let mut declared_features = template.declared_features;
        if inherited {
            declared_features.extend(extract_inline_string_list(value, "features"));
        }
        dependencies.push(WorkspaceDependency {
            package: template.package,
            manifest: display.to_owned(),
            version: template.version,
            default_features: template.default_features,
            declared_features,
        });
    }
    dependencies
}

fn dependency_template(name: &str, value: &str) -> WorkspaceDependencyTemplate {
    WorkspaceDependencyTemplate {
        package: extract_inline_string_field(value, "package").unwrap_or_else(|| name.to_owned()),
        version: extract_inline_string_field(value, "version")
            .or_else(|| extract_string_value(value)),
        default_features: if extract_inline_bool_field(value, "default-features") == Some(false) {
            "disabled".to_owned()
        } else {
            "enabled".to_owned()
        },
        declared_features: extract_inline_string_list(value, "features"),
    }
}

fn extract_bool_value(value: &str) -> Option<bool> {
    match value.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn extract_inline_bool_field(value: &str, field: &str) -> Option<bool> {
    let tail = inline_field_value(value, field)?;
    extract_bool_value(tail.split([',', '}']).next()?)
}

fn extract_inline_string_list(value: &str, field: &str) -> BTreeSet<String> {
    let Some(after_equals) = inline_field_value(value, field) else {
        return BTreeSet::new();
    };
    let Some(open) = after_equals.find('[') else {
        return BTreeSet::new();
    };
    let Some(close) = after_equals[open + 1..].find(']') else {
        return BTreeSet::new();
    };
    after_equals[open + 1..open + 1 + close]
        .split(',')
        .filter_map(extract_string_value)
        .collect()
}

fn is_constellation_package(name: &str) -> bool {
    name == "asupersync"
        || name == "fsqlite"
        || name == "frankensqlite"
        || name.starts_with("franken-")
        || name.starts_with("franken_")
        || name.starts_with("fastapi")
        || name.starts_with("sqlmodel")
        || name.starts_with("frankentui")
        || name.starts_with("ftui")
}

fn is_alternate_runtime(name: &str) -> bool {
    matches!(
        name,
        "async-std" | "smol" | "glommio" | "monoio" | "executor-lite" | "futures-executor"
    ) || name == "tokio"
        || name.starts_with("tokio-")
}

fn is_forbidden_sqlmodel_backend(name: &str, features: &BTreeSet<String>) -> bool {
    // `frankensqlite` contains the `sqlite` needle as a substring, so the name
    // scan below would refuse the ONE backend ADR-0012 admits. Exempt it
    // first; every other sqlmodel* package matching a backend needle, and any
    // sqlmodel* crate requesting a C-backend feature closure, stays refused.
    if name.starts_with("sqlmodel") && name.contains("frankensqlite") {
        return false;
    }
    let forbidden_name = ["sqlite", "postgres", "mysql", "c-sqlite", "native"]
        .iter()
        .any(|needle| name.starts_with("sqlmodel") && name.contains(needle));
    let forbidden_feature = features.iter().any(|feature| {
        matches!(
            feature.as_str(),
            "sqlite" | "postgres" | "mysql" | "c-sqlite" | "native-sqlite"
        )
    });
    forbidden_name || forbidden_feature
}

fn is_forbidden_ftui_surface(name: &str, features: &BTreeSet<String>) -> bool {
    (name.starts_with("ftui") || name.starts_with("frankentui"))
        && (name.contains("demo")
            || name.contains("showcase")
            || name.contains("extras")
            || features.iter().any(|feature| {
                matches!(
                    feature.as_str(),
                    "demo" | "showcase" | "extras" | "telemetry"
                )
            }))
}

/// Telemetry exporters that open their own egress path out of a truth process.
///
/// FG-094a excludes "blocking telemetry exporters" from the `FrankenTUI` kernel
/// closure. The rule is deliberately narrow: it names the OpenTelemetry export
/// family only. `tracing`, `tracing-core` and `log` are pure-Rust facades
/// already resolved in this workspace and are NOT exporters, so banning them
/// would break the shared checkout to punish the wrong thing.
/// `tracing-subscriber` is likewise not an exporter; the `telemetry` feature
/// that pulls it is refused by [`is_forbidden_ftui_surface`] instead, which
/// catches the whole set at the manifest rather than one crate at the lock.
fn is_forbidden_telemetry_exporter(name: &str) -> bool {
    name.starts_with("opentelemetry") || name == "tracing-opentelemetry"
}

/// GPU, windowing, and native font shims that a terminal kernel must not drag in.
///
/// Every entry links a C or system library, so each is already an `AGENTS.md`
/// section 3.1 violation; this rule is what makes that sentence enforceable for
/// the FG-094a closure. Pure-Rust image codecs are deliberately absent: whether
/// `png` or `image` belongs in the universe is a policy question for an ADR,
/// not a refusal to smuggle in behind a TUI admission bead.
fn is_forbidden_native_media(name: &str) -> bool {
    matches!(
        name,
        "wgpu"
            | "wgpu-core"
            | "wgpu-hal"
            | "glutin"
            | "glow"
            | "skia-safe"
            | "cairo-sys-rs"
            | "freetype-sys"
            | "fontconfig-sys"
            | "servo-fontconfig"
            | "servo-fontconfig-sys"
    )
}

/// Alternate HTTP runtimes, reactors, and native TLS/compression backends that
/// must never enter the resolved closure, whichever sibling drags them in.
///
/// `AGENTS.md` section 3.1 already forbids linking C/C++ libraries to obtain
/// TLS or compression behaviour, and section 3.2 forbids a second runtime.
/// Before this rule those sentences were enforced only for the handful of
/// names [`is_alternate_runtime`] happens to list, so a reactor arriving under
/// a different name -- `hyper`, `actix-rt` -- or a C backend arriving as
/// `openssl-sys` passed the preflight. A gateway framework is the realistic
/// way such a package enters, so the constellation preflight is where it is
/// caught, before any per-entry bookkeeping runs.
///
/// Pure-Rust compression is admissible and deliberately absent here:
/// `miniz_oxide` and `flate2`'s default backend are not forbidden; only the
/// `-sys` shims that link a C library are.
fn is_forbidden_native_transport(name: &str) -> bool {
    matches!(
        name,
        "hyper"
            | "hyper-util"
            | "h2"
            | "axum"
            | "axum-core"
            | "warp"
            | "tide"
            | "rocket"
            | "salvo"
            | "poem"
            | "ntex"
            | "native-tls"
            | "openssl"
            | "openssl-sys"
            | "openssl-probe"
            | "schannel"
            | "security-framework"
            | "security-framework-sys"
            | "libz-sys"
            | "libz-ng-sys"
            | "zlib-ng"
            | "bzip2-sys"
            | "lzma-sys"
            | "zstd-sys"
    ) || name.starts_with("actix")
}

/// fastapi surfaces refused even once the family is otherwise admitted.
///
/// Demo and example packages carry sample servers that would become a second
/// unowned entrypoint. The feature names are the ones that switch fastapi onto
/// a foreign reactor or a native TLS/compression backend; refusing the feature
/// closure catches the switch at the manifest, where the resulting package may
/// not yet be in `Cargo.lock`.
fn is_forbidden_fastapi_surface(name: &str, features: &BTreeSet<String>) -> bool {
    if !name.starts_with("fastapi") {
        return false;
    }
    name.contains("demo")
        || name.contains("example")
        || name.contains("showcase")
        || features.iter().any(|feature| {
            matches!(
                feature.as_str(),
                "tokio" | "hyper" | "native-tls" | "default-tls" | "compression-native"
            )
        })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MetadataSnapshot {
    feature_closures: BTreeMap<(String, String), BTreeSet<String>>,
    build_scripts: BTreeSet<String>,
    proc_macros: BTreeSet<String>,
    package_sources: BTreeMap<(String, String), PackageSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageSource {
    manifest_path: PathBuf,
    license: String,
    license_file: Option<PathBuf>,
}

const MIT_OPENAI_ANTHROPIC_RIDER: &str = "LicenseRef-MIT-OpenAI-Anthropic-Rider";
/// The repository-canonical LICENSE carries a leading
/// `SPDX-License-Identifier: LicenseRef-MIT-OpenAI-Anthropic-Rider` marker
/// line; crates.io-published family members ship the identical rider text
/// without that repository-local line. Both forms are byte-pinned.
const MIT_OPENAI_ANTHROPIC_RIDER_SHA256: &str =
    "bbcd5ea29292d9d5df0bb055ceed2ddd846731717ff294d32ddd1349d541ef42";
const MIT_OPENAI_ANTHROPIC_RIDER_CRATES_IO_SHA256: &str =
    "32a82e0a5754e72e51fae44b65a936c831c07376f21c90f5fb9e76897fcc3509";

/// Cargo permits a package to state its license through `license-file` instead
/// of the SPDX-like `license` metadata field. The constellation schema keeps
/// an explicit identifier, so file evidence is accepted only for a byte-pinned
/// known license text; every other file fails closed pending an explicit
/// admission decision.
fn package_license_evidence(source: &PackageSource) -> Result<String, String> {
    if source.license != "missing" {
        return Ok(source.license.clone());
    }
    let license_file = source
        .license_file
        .as_deref()
        .ok_or_else(|| "metadata supplies neither `license` nor `license_file`".to_owned())?;
    if license_file.is_absolute()
        || license_file
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "license-file `{}` is not a package-relative file",
            license_file.display()
        ));
    }
    let package_root = source.manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest `{}` has no parent for license-file evidence",
            source.manifest_path.display()
        )
    })?;
    let license_path = package_root.join(license_file);
    let license_bytes = fs::read(&license_path).map_err(|error| {
        format!(
            "cannot read license-file `{}`: {error}",
            license_path.display()
        )
    })?;
    let digest = sha256_hex(&license_bytes);
    if digest == MIT_OPENAI_ANTHROPIC_RIDER_SHA256
        || digest == MIT_OPENAI_ANTHROPIC_RIDER_CRATES_IO_SHA256
    {
        return Ok(MIT_OPENAI_ANTHROPIC_RIDER.to_owned());
    }
    Err(format!(
        "license-file `{}` has unrecognized SHA-256 `{digest}`; require an explicit licensed admission",
        license_path.display()
    ))
}

fn cargo_metadata(root: &Path) -> Result<MetadataSnapshot, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--locked", "--offline", "--format-version=1"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot execute cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata --locked --offline failed (status {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("cargo metadata emitted non-UTF-8 JSON: {error}"))?;
    parse_cargo_metadata(&text)
}

/// Cargo metadata is JSON, but adding a general-purpose JSON dependency would
/// contradict the checker's deliberately std-only dependency surface. These
/// bounded extractors handle the three stable arrays this gate needs and reject
/// malformed JSON rather than guessing.
fn parse_cargo_metadata(text: &str) -> Result<MetadataSnapshot, String> {
    let mut snapshot = MetadataSnapshot::default();
    for package in json_array_objects(text, "packages")? {
        let name = json_string_field(package, "name")
            .ok_or_else(|| "cargo metadata package lacks name".to_owned())?;
        let version = json_string_field(package, "version")
            .ok_or_else(|| format!("cargo metadata package `{name}` lacks version"))?;
        let manifest_path = json_string_field(package, "manifest_path")
            .ok_or_else(|| format!("cargo metadata package `{name}` lacks manifest_path"))?;
        let license = json_string_field(package, "license").unwrap_or_else(|| "missing".to_owned());
        let license_file = json_string_field(package, "license_file").map(PathBuf::from);
        snapshot.package_sources.insert(
            (name.clone(), version),
            PackageSource {
                manifest_path: PathBuf::from(manifest_path),
                license,
                license_file,
            },
        );
        for target in json_array_objects(package, "targets")? {
            let kinds = json_string_array_field(target, "kind")?;
            if kinds.contains("custom-build") {
                snapshot.build_scripts.insert(name.clone());
            }
            if kinds.contains("proc-macro") {
                snapshot.proc_macros.insert(name.clone());
            }
        }
    }
    for node in json_array_objects(text, "nodes")? {
        let id = json_string_field(node, "id")
            .ok_or_else(|| "cargo metadata resolve node lacks id".to_owned())?;
        let Some((package, version)) = package_name_and_version_from_metadata_id(&id) else {
            continue;
        };
        snapshot.feature_closures.insert(
            (package, version),
            json_string_array_field(node, "features")?,
        );
    }
    Ok(snapshot)
}

fn package_name_and_version_from_metadata_id(id: &str) -> Option<(String, String)> {
    let (_, tail) = id.rsplit_once('#')?;
    let (package, version) = tail.rsplit_once('@')?;
    if package.is_empty() || version.is_empty() {
        return None;
    }
    Some((package.to_owned(), version.to_owned()))
}

fn json_array_objects<'a>(text: &'a str, key: &str) -> Result<Vec<&'a str>, String> {
    let needle = format!("\"{key}\"");
    let Some(start) = text.find(&needle) else {
        return Ok(Vec::new());
    };
    let after_key = &text[start + needle.len()..];
    let Some(colon) = after_key.find(':') else {
        return Err(format!("cargo metadata JSON key `{key}` lacks colon"));
    };
    let after_colon = after_key[colon + 1..].trim_start();
    if !after_colon.starts_with('[') {
        return Err(format!("cargo metadata JSON key `{key}` is not an array"));
    }
    let mut objects = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut object_start = None;
    for (offset, character) in after_colon.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    object_start = Some(offset);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    return Err(format!("cargo metadata JSON key `{key}` has unmatched }}"));
                }
                depth -= 1;
                if depth == 0 {
                    let Some(object_start) = object_start.take() else {
                        return Err(format!(
                            "cargo metadata JSON key `{key}` has no object start"
                        ));
                    };
                    objects.push(&after_colon[object_start..=offset]);
                }
            }
            ']' if depth == 0 => return Ok(objects),
            _ => {}
        }
    }
    Err(format!(
        "cargo metadata JSON key `{key}` has an unclosed array"
    ))
}

fn json_string_field(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)? + needle.len();
    let tail = text[start..].trim_start();
    let tail = tail.strip_prefix(':')?.trim_start();
    let quoted = tail.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;
    for character in quoted.chars() {
        if escaped {
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(output);
        } else {
            output.push(character);
        }
    }
    None
}

fn json_string_array_field(text: &str, key: &str) -> Result<BTreeSet<String>, String> {
    let needle = format!("\"{key}\"");
    let Some(start) = text.find(&needle) else {
        return Ok(BTreeSet::new());
    };
    let tail = text[start + needle.len()..].trim_start();
    let Some(tail) = tail.strip_prefix(':') else {
        return Err(format!("cargo metadata JSON key `{key}` lacks colon"));
    };
    let tail = tail.trim_start();
    let Some(tail) = tail.strip_prefix('[') else {
        return Err(format!(
            "cargo metadata JSON key `{key}` is not a string array"
        ));
    };
    let Some(close) = tail.find(']') else {
        return Err(format!(
            "cargo metadata JSON key `{key}` has an unclosed array"
        ));
    };
    let mut values = BTreeSet::new();
    for raw in tail[..close].split(',') {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        let Some(value) = extract_string_value(value) else {
            return Err(format!(
                "cargo metadata JSON key `{key}` contains a non-string value"
            ));
        };
        values.insert(value);
    }
    Ok(values)
}

fn check_constellation(root: &Path, report: &mut Report) {
    let path = root.join("constellation.lock");
    let Ok(text) = fs::read_to_string(&path) else {
        report.error("cannot read constellation.lock");
        return;
    };
    let constellation = match parse_constellation_lock(&text) {
        Ok(value) => value,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    let lock_text = match fs::read_to_string(root.join("Cargo.lock")) {
        Ok(value) => value,
        Err(error) => {
            report.error(format!(
                "cannot read Cargo.lock for constellation verification: {error}"
            ));
            return;
        }
    };
    let packages = match parse_lock_packages(&lock_text) {
        Ok(value) => value,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    let dependencies = workspace_dependencies(root, report);
    let error_count_before_preflight = report.errors.len();
    check_runtime_universe(&packages, report);
    check_forbidden_constellation_surfaces(&packages, &dependencies, report);
    if report.errors.len() > error_count_before_preflight {
        return;
    }
    let metadata = if constellation.state == ConstellationState::Dormant {
        None
    } else {
        match cargo_metadata(root) {
            Ok(value) => Some(value),
            Err(error) => {
                report.error(error);
                return;
            }
        }
    };
    check_constellation_model(
        &constellation,
        &packages,
        &dependencies,
        metadata.as_ref(),
        report,
    );
}

fn check_constellation_model(
    constellation: &ConstellationLock,
    packages: &[LockPackage],
    dependencies: &[WorkspaceDependency],
    metadata: Option<&MetadataSnapshot>,
    report: &mut Report,
) {
    let selected = packages
        .iter()
        .filter(|package| is_constellation_package(&package.name))
        .collect::<Vec<_>>();
    let linked = dependencies
        .iter()
        .filter(|dependency| is_constellation_package(&dependency.package))
        .collect::<Vec<_>>();
    check_runtime_universe(packages, report);
    check_forbidden_constellation_surfaces(packages, dependencies, report);

    if constellation.state == ConstellationState::Dormant {
        if selected.is_empty() && linked.is_empty() && constellation.entries.is_empty() {
            report
                .notes
                .push("constellation.lock is explicitly dormant: no workspace-resolved adopted sibling is linked".to_owned());
        } else {
            report.error(
                "constellation.lock is dormant while an adopted dependency is linked; add exact candidate/admitted rows after upstream convergence"
                    .to_owned(),
            );
        }
        return;
    }
    if selected.is_empty() && linked.is_empty() {
        report.error(
            "constellation.lock has candidate/admitted rows but no workspace-resolved adopted dependency; use state=dormant"
                .to_owned(),
        );
        return;
    }
    if constellation.state == ConstellationState::Candidate {
        report.error(
            "constellation.lock state=candidate is not a release admission; required sibling convergence remains blocked"
                .to_owned(),
        );
    }
    let Some(metadata) = metadata else {
        report.error(
            "constellation metadata is required for candidate/admitted feature and code-generation verification"
                .to_owned(),
        );
        return;
    };
    check_sqlmodel_substrate_feature_profile(packages, metadata, report);
    check_constellation_exact(constellation, packages, dependencies, metadata, report);
    check_generated_constellation_evidence(constellation, packages, metadata, dependencies, report);
}

/// Admission records are not arbitrary digest-shaped strings: whenever `Cargo`
/// supplied package source paths, reconstruct the deterministic evidence and
/// require the checked-in rows to match it exactly. Hand-built unit metadata
/// deliberately omits package paths, so those small model tests exercise the
/// independent schema checks without depending on the local Cargo cache.
fn check_generated_constellation_evidence(
    constellation: &ConstellationLock,
    packages: &[LockPackage],
    metadata: &MetadataSnapshot,
    dependencies: &[WorkspaceDependency],
    report: &mut Report,
) {
    if constellation.state != ConstellationState::Admitted || metadata.package_sources.is_empty() {
        return;
    }
    let rows = match generate_constellation_ledger(packages, metadata, dependencies) {
        Ok(rows) => rows,
        Err(error) => {
            report.error(format!(
                "cannot reconstruct constellation admission evidence: {error}"
            ));
            return;
        }
    };
    let generated = format!(
        "{CONSTELLATION_MARKER}\nstate\tadmitted\n{}\n{rows}",
        CONSTELLATION_COLUMNS.join("\t")
    );
    let expected = match parse_constellation_lock(&generated) {
        Ok(lock) => lock,
        Err(error) => {
            report.error(format!(
                "generated constellation admission evidence is malformed: {error}"
            ));
            return;
        }
    };
    for (package, expected_entry) in expected.entries {
        match constellation.entries.get(&package) {
            Some(actual) if actual == &expected_entry => {}
            Some(_) => report.error(format!(
                "constellation generated-evidence drift for `{package}`; rerun `fgit-registry-check ledger-constellation`"
            )),
            None => {}
        }
    }
}

fn check_runtime_universe(packages: &[LockPackage], report: &mut Report) {
    let runtime_versions = packages
        .iter()
        .filter(|package| package.name == "asupersync")
        .map(|package| package.version.clone())
        .collect::<BTreeSet<_>>();
    if runtime_versions.len() > 1 {
        report.error(format!(
            "multiple Asupersync 0.x type universes resolved in Cargo.lock: {:?}; exactly one version is permitted",
            runtime_versions
        ));
    }
    for package in packages {
        if is_alternate_runtime(&package.name) {
            report.error(format!(
                "alternate async runtime `{}` resolved in Cargo.lock; Asupersync is the sole runtime",
                package.name
            ));
        }
    }
}

fn check_forbidden_constellation_surfaces(
    packages: &[LockPackage],
    dependencies: &[WorkspaceDependency],
    report: &mut Report,
) {
    for package in packages {
        if is_forbidden_sqlmodel_backend(&package.name, &BTreeSet::new()) {
            report.error(format!(
                "forbidden sqlmodel backend `{}` resolved in Cargo.lock; only the FrankenSQLite projection closure is admissible",
                package.name
            ));
        }
        if is_forbidden_ftui_surface(&package.name, &BTreeSet::new()) {
            report.error(format!(
                "forbidden ftui demo/showcase package `{}` resolved in Cargo.lock",
                package.name
            ));
        }
        if is_forbidden_fastapi_surface(&package.name, &BTreeSet::new()) {
            report.error(format!(
                "forbidden fastapi demo/example package `{}` resolved in Cargo.lock",
                package.name
            ));
        }
        if is_forbidden_native_transport(&package.name) {
            report.error(format!(
                "forbidden native transport `{}` resolved in Cargo.lock; Asupersync owns the reactor and TLS/compression must be pure Rust",
                package.name
            ));
        }
        if is_forbidden_telemetry_exporter(&package.name) {
            report.error(format!(
                "forbidden telemetry exporter `{}` resolved in Cargo.lock; a truth process does not own its own egress path",
                package.name
            ));
        }
        if is_forbidden_native_media(&package.name) {
            report.error(format!(
                "forbidden native media/GPU dependency `{}` resolved in Cargo.lock",
                package.name
            ));
        }
    }
    for dependency in dependencies {
        if is_forbidden_sqlmodel_backend(&dependency.package, &dependency.declared_features) {
            report.error(format!(
                "forbidden sqlmodel backend feature closure for `{}` in {}",
                dependency.package, dependency.manifest
            ));
        }
        if is_forbidden_ftui_surface(&dependency.package, &dependency.declared_features) {
            report.error(format!(
                "forbidden ftui demo/showcase feature closure for `{}` in {}",
                dependency.package, dependency.manifest
            ));
        }
        if is_forbidden_fastapi_surface(&dependency.package, &dependency.declared_features) {
            report.error(format!(
                "forbidden fastapi feature closure for `{}` in {}",
                dependency.package, dependency.manifest
            ));
        }
        if is_forbidden_native_transport(&dependency.package) {
            report.error(format!(
                "forbidden native transport dependency `{}` declared in {}",
                dependency.package, dependency.manifest
            ));
        }
        if is_forbidden_telemetry_exporter(&dependency.package) {
            report.error(format!(
                "forbidden telemetry exporter dependency `{}` declared in {}",
                dependency.package, dependency.manifest
            ));
        }
        if is_forbidden_native_media(&dependency.package) {
            report.error(format!(
                "forbidden native media/GPU dependency `{}` declared in {}",
                dependency.package, dependency.manifest
            ));
        }
    }
}

/// FrankenSQLite surface markers that ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md
/// §3.2 keeps off unless a named consumer proves marginal need: the extension
/// set, session support, and the Linux io_uring profile. Matched as exact
/// resolved feature names against every `fsqlite*` package closure.
const FSQLITE_CALLER_PROFILE_EXCLUSIONS: [&str; 9] = [
    "extensions",
    "json",
    "fts5",
    "rtree",
    "icu",
    "misc",
    "session",
    "linux-asupersync-uring",
    "wasm",
];

/// The sqlmodel projection substrate may enter only alongside the minimal
/// FrankenSQLite caller profile. The published `sqlmodel-frankensqlite` 0.4.x
/// requests the fsqlite family WITHOUT `default-features = false`, so wiring
/// it today would silently widen every workspace consumer's resolved fsqlite
/// surface -- including the authority adapter pinned at DEP-176..218 -- to
/// json/fts5/rtree/icu/misc plus an unconditional io_uring profile. Cargo has
/// no consumer-side feature downgrade, so this gate turns that widening into a
/// typed refusal naming the upstream prerequisite instead of unnoticed
/// evidence drift, and goes quiet on its own the moment upstream publishes
/// minimal-profile requests; no checker edit ships with the fix.
fn check_sqlmodel_substrate_feature_profile(
    packages: &[LockPackage],
    metadata: &MetadataSnapshot,
    report: &mut Report,
) {
    let substrate_linked = packages
        .iter()
        .any(|package| package.name == "sqlmodel-frankensqlite");
    if !substrate_linked {
        return;
    }
    let exclusions: BTreeSet<&str> = FSQLITE_CALLER_PROFILE_EXCLUSIONS.into_iter().collect();
    for package in packages {
        if !package.name.starts_with("fsqlite") {
            continue;
        }
        let Some(resolved) = metadata
            .feature_closures
            .get(&(package.name.clone(), package.version.clone()))
        else {
            continue;
        };
        // Iterating the sorted resolved set keeps diagnostics deterministic.
        for feature in resolved {
            if exclusions.contains(feature.as_str()) {
                report.error(format!(
                    "sqlmodel projection substrate requires the minimal FrankenSQLite caller \
                     profile: `{}` resolved with excluded feature `{feature}`; integration \
                     profile §3.2 keeps extensions, session, and io_uring off unless a named \
                     consumer proves need, so upstream must publish sqlmodel-frankensqlite \
                     requesting the fsqlite family with default-features = false",
                    package.name
                ));
            }
        }
    }
}

fn check_constellation_exact(
    constellation: &ConstellationLock,
    packages: &[LockPackage],
    dependencies: &[WorkspaceDependency],
    metadata: &MetadataSnapshot,
    report: &mut Report,
) {
    let selected = packages
        .iter()
        .filter(|package| is_constellation_package(&package.name))
        .collect::<Vec<_>>();
    let selected_names = selected
        .iter()
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    for package in &selected_names {
        if !constellation.entries.contains_key(package) {
            report.error(format!(
                "constellation.lock lacks a row for resolved adopted package `{package}`"
            ));
        }
    }
    for package in constellation.entries.keys() {
        if !selected_names.contains(package) {
            report.error(format!(
                "constellation.lock records `{package}`, but Cargo.lock has no resolved adopted package by that name"
            ));
        }
    }
    for dependency in dependencies
        .iter()
        .filter(|dependency| is_constellation_package(&dependency.package))
    {
        if !selected_names.contains(&dependency.package) {
            report.error(format!(
                "adopted dependency `{}` in {} is absent from Cargo.lock; resolve the exact release source before admission",
                dependency.package, dependency.manifest
            ));
        }
    }

    for package in selected {
        let Some(entry) = constellation.entries.get(&package.name) else {
            continue;
        };
        check_constellation_entry(entry, package, dependencies, metadata, report);
    }
}

fn check_constellation_entry(
    entry: &ConstellationEntry,
    package: &LockPackage,
    dependencies: &[WorkspaceDependency],
    metadata: &MetadataSnapshot,
    report: &mut Report,
) {
    if entry.version != package.version {
        report.error(format!(
            "constellation version drift for `{}`: lock has `{}`, constellation records `{}`",
            package.name, package.version, entry.version
        ));
    }
    let source = package.source.as_deref().unwrap_or("workspace");
    if entry.source != source {
        report.error(format!(
            "constellation source drift for `{}`: lock has `{source}`, constellation records `{}`",
            package.name, entry.source
        ));
    }
    if source.starts_with("path+") || source == "workspace" {
        report.error(format!(
            "adopted package `{}` has unpublished source `{source}` in Cargo.lock",
            package.name
        ));
    }
    if source.starts_with("git+") {
        let revision = source.rsplit('#').next().unwrap_or("");
        if !is_hex_digest(revision, 40) || entry.revision != revision {
            report.error(format!(
                "constellation revision drift for `{}`: Git source requires exact revision `{revision}`",
                package.name
            ));
        }
        if entry.checksum != "not_applicable" {
            report.error(format!(
                "constellation checksum for Git package `{}` must be `not_applicable`",
                package.name
            ));
        }
    } else if source.starts_with("registry+") {
        if entry.revision != "not_applicable" {
            report.error(format!(
                "constellation revision for registry package `{}` must be `not_applicable`",
                package.name
            ));
        }
        let checksum = package.checksum.as_deref().unwrap_or("");
        if !is_hex_digest(checksum, 64) || entry.checksum != checksum {
            report.error(format!(
                "constellation checksum drift for `{}`: registry source must match Cargo.lock exactly",
                package.name
            ));
        }
    } else {
        report.error(format!(
            "adopted package `{}` uses non-release source `{source}`",
            package.name
        ));
    }

    match metadata
        .feature_closures
        .get(&(package.name.clone(), package.version.clone()))
    {
        Some(actual) if actual != &entry.features => report.error(format!(
            "constellation feature closure drift for `{}`: metadata {:?}, constellation {:?}",
            package.name, actual, entry.features
        )),
        None => report.error(format!(
            "cargo metadata lacks the resolved feature closure for `{}` {}",
            package.name, package.version
        )),
        _ => {}
    }
    for dependency in dependencies
        .iter()
        .filter(|dependency| dependency.package == package.name)
    {
        if entry.default_features != dependency.default_features {
            report.error(format!(
                "constellation default-feature drift for `{}` in {}: manifest is {}, constellation is {}",
                package.name,
                dependency.manifest,
                dependency.default_features,
                entry.default_features
            ));
        }
    }
    let expected_build_script = if metadata.build_scripts.contains(&package.name) {
        "enabled"
    } else {
        "disabled"
    };
    if entry.build_scripts != expected_build_script {
        report.error(format!(
            "constellation build-script evidence drift for `{}`: metadata is {expected_build_script}, constellation is {}",
            package.name, entry.build_scripts
        ));
    }
    let expected_proc_macro = if metadata.proc_macros.contains(&package.name) {
        "enabled"
    } else {
        "disabled"
    };
    if entry.proc_macros != expected_proc_macro {
        report.error(format!(
            "constellation proc-macro evidence drift for `{}`: metadata is {expected_proc_macro}, constellation is {}",
            package.name, entry.proc_macros
        ));
    }
    check_entry_evidence(entry, package, report);
}

fn check_entry_evidence(entry: &ConstellationEntry, package: &LockPackage, report: &mut Report) {
    if !matches!(
        entry.default_features.as_str(),
        "enabled" | "disabled" | "not_applicable"
    ) {
        report.error(format!(
            "constellation default_features for `{}` must be enabled, disabled, or not_applicable",
            package.name
        ));
    }
    if !matches!(entry.build_scripts.as_str(), "enabled" | "disabled") {
        report.error(format!(
            "constellation build_scripts for `{}` must be enabled or disabled",
            package.name
        ));
    }
    if !matches!(entry.proc_macros.as_str(), "enabled" | "disabled") {
        report.error(format!(
            "constellation proc_macros for `{}` must be enabled or disabled",
            package.name
        ));
    }
    if !is_hex_digest(&entry.public_contract_fingerprint, 64) {
        report.error(format!(
            "constellation public-contract fingerprint for `{}` must be a 64-hex digest",
            package.name
        ));
    }
    if entry.target_support == "unknown" || entry.target_support == "missing" {
        report.error(format!(
            "constellation target-support evidence is missing for `{}`",
            package.name
        ));
    }
    if entry.license == "unknown" || entry.license == "missing" {
        report.error(format!(
            "constellation license evidence is missing for `{}`",
            package.name
        ));
    }
    if !is_hex_digest(&entry.transitive_unsafe_digest, 64) {
        report.error(format!(
            "constellation transitive-unsafe evidence for `{}` must be a 64-hex inventory digest",
            package.name
        ));
    }
    if !matches!(entry.evidence_class.as_str(), "reviewed" | "admitted") {
        report.error(format!(
            "constellation evidence_class for `{}` must be reviewed or admitted",
            package.name
        ));
    }
    if entry.removal_update_path == "missing" || entry.removal_update_path == "unknown" {
        report.error(format!(
            "constellation removal/update path is missing for `{}`",
            package.name
        ));
    }
}

fn is_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn load_allowed_dependency_patterns(root: &Path, report: &mut Report) -> Vec<String> {
    let path = root.join("registries/dependency_policy.tsv");
    let Ok(text) = fs::read_to_string(&path) else {
        report.error("cannot read dependency policy registry");
        return Vec::new();
    };
    let mut patterns = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() < DEPENDENCY_POLICY_COLUMNS {
            continue;
        }
        let decision = fields[3];
        let status = fields[9];
        if status == "active" && decision.starts_with("allow") {
            patterns.push(fields[1].to_owned());
        }
    }
    patterns
}

fn dependency_pattern_matches(pattern: &str, dependency: &str) -> bool {
    pattern.strip_suffix('*').map_or_else(
        || dependency == pattern,
        |prefix| dependency.starts_with(prefix),
    )
}

fn manifest_dependency_names(text: &str) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    let mut in_dependency_section = false;
    // A `[dependencies.NAME]` table registers NAME, but a `package = "real"`
    // key inside it renames the dependency; the real crate is what the
    // closed-world policy must see, not the local alias.
    let mut pending_table_alias: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(name) = pending_table_alias.take() {
                dependencies.insert(name);
            }
            let section = &line[1..line.len() - 1];
            in_dependency_section = section == "dependencies"
                || section == "dev-dependencies"
                || section == "build-dependencies"
                || section == "workspace.dependencies"
                || section.ends_with(".dependencies")
                || section.ends_with(".dev-dependencies")
                || section.ends_with(".build-dependencies");

            for marker in ["dependencies.", "dev-dependencies.", "build-dependencies."] {
                if let Some(index) = section.rfind(marker) {
                    let name = section[index + marker.len()..].trim_matches('"');
                    if !name.is_empty() {
                        pending_table_alias = Some(name.to_owned());
                    }
                }
            }
            continue;
        }
        if pending_table_alias.is_some() {
            if let Some((key, value)) = line.split_once('=')
                && key.trim().trim_matches('"') == "package"
                && let Some(package) = extract_string_value(value)
            {
                pending_table_alias = Some(package);
            }
            continue;
        }
        if !in_dependency_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let raw_alias = key.trim().trim_matches('"');
        let alias = raw_alias.strip_suffix(".workspace").unwrap_or(raw_alias);
        if let Some(package) = extract_inline_string_field(value, "package") {
            dependencies.insert(package);
        } else if !alias.is_empty() {
            dependencies.insert(alias.to_owned());
        }
    }
    if let Some(name) = pending_table_alias.take() {
        dependencies.insert(name);
    }

    dependencies
}

fn extract_inline_string_field(value: &str, field: &str) -> Option<String> {
    extract_string_value(inline_field_value(value, field)?)
}

fn inline_field_value<'a>(value: &'a str, field: &str) -> Option<&'a str> {
    let bytes = value.as_bytes();
    let mut search = 0;
    while let Some(pos) = value[search..].find(field) {
        let start = search + pos;
        search = start + field.len();
        let boundary_before = start == 0
            || !(bytes[start - 1].is_ascii_alphanumeric()
                || bytes[start - 1] == b'_'
                || bytes[start - 1] == b'-');
        if !boundary_before {
            continue;
        }
        let after = value[start + field.len()..].trim_start();
        if let Some(rest) = after.strip_prefix('=') {
            return Some(rest.trim_start());
        }
    }
    None
}

fn extract_string_value(value: &str) -> Option<String> {
    let quoted = value.trim_start().strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_owned())
}

fn check_toolchain(root: &Path, report: &mut Report) {
    let text = fs::read_to_string(root.join("rust-toolchain.toml")).unwrap_or_default();
    let mut channel_pinned = false;
    let mut components_line = String::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(value) = line.strip_prefix("channel")
            && let Some(value) = value.trim_start().strip_prefix('=')
            && value.trim().starts_with("\"nightly-")
        {
            channel_pinned = true;
        }
        if line.starts_with("components") {
            line.clone_into(&mut components_line);
        }
    }
    if !channel_pinned {
        report.error("rust-toolchain.toml must pin a dated nightly channel");
    }
    for component in ["rustfmt", "clippy"] {
        if !components_line.contains(component) {
            report.error(format!("rust-toolchain.toml lacks component `{component}`"));
        }
    }
}

fn check_forbidden_artifacts(root: &Path, report: &mut Report) {
    let mut files = Vec::new();
    collect_files(root, &mut files);
    for path in files {
        let display = relative(root, &path);
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if matches!(name, ".DS_Store" | "Thumbs.db" | "Desktop.ini") {
            report.error(format!("forbidden platform artifact: {display}"));
        }
        if display == "scripts/verify_docs.py" {
            report.error("superseded Python verifier must be removed; use fgit-registry-check");
        }
        if display == "bootstrap_github_repo.sh" {
            report.error("bootstrap_github_repo.sh is a transfer artifact, not repository source");
        }
        if name == "Cargo.lock" && display != "Cargo.lock" {
            report.error(format!(
                "nested lockfile {display}: the workspace has exactly one root Cargo.lock"
            ));
        }
    }
}

fn collect_files(root: &Path, output: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == OsStr::new(".git")
            || name == OsStr::new("target")
            // Generated compliance-audit scratch is gitignored by the
            // skill's own hard rule, but its reports carry relative links
            // into per-pass artifacts and broke this lane twice on
            // 2026-08-23. Scratch trees are not review surface.
            || name == OsStr::new("beads_compliance_audit")
            || is_registry_checker_fixture_dir(&path)
        {
            continue;
        }
        if entry
            .file_type()
            .map(|file_type| file_type.is_symlink())
            .unwrap_or(true)
        {
            continue;
        }
        if path.is_dir() {
            collect_files(&path, output);
        } else if path.is_file() {
            output.push(path);
        }
    }
}

/// Checker fixtures intentionally contain malformed Cargo manifests, locks,
/// and Rust snippets. They are executable test data, never production source,
/// so the live self-check must not interpret their planted violations as a
/// violation in the `FrankenGit` tree.
fn is_registry_checker_fixture_dir(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("fixtures"))
        && path.parent().and_then(Path::file_name) == Some(OsStr::new("tests"))
        && path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            == Some(OsStr::new("registry-check"))
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn print_human(report: &Report) {
    if report.errors.is_empty() {
        println!(
            "FrankenGit constitutional verification passed: {} Markdown files, {} registry rows, {} Rust files.",
            report.markdown_files, report.registry_rows, report.rust_files
        );
    } else {
        eprintln!("FrankenGit constitutional verification FAILED:");
        for error in &report.errors {
            eprintln!("  - {error}");
        }
    }
    for note in &report.notes {
        eprintln!("note: {note}");
    }
}

fn print_json(report: &Report) {
    let errors = report
        .errors
        .iter()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    let notes = report
        .notes
        .iter()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{{\"ok\":{},\"markdown_files\":{},\"registry_rows\":{},\"rust_files\":{},\"errors\":[{}],\"notes\":[{}]}}",
        report.errors.is_empty(),
        report.markdown_files,
        report.registry_rows,
        report.rust_files,
        errors,
        notes
    );
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                let _ = write!(output, "\\u{:04x}", u32::from(control));
            }
            other => output.push(other),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct FixtureWorkspace {
        root: PathBuf,
    }

    impl Drop for FixtureWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn fixture_workspace(name: &str) -> FixtureWorkspace {
        fixture_workspace_in("constellation", name)
    }

    fn fixture_workspace_in(group: &str, name: &str) -> FixtureWorkspace {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/constellation")
            .parent()
            .expect("fixture group parent")
            .join(group)
            .join(name);
        let nonce = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!("fgit-registry-check-{nanos}-{nonce}"));
        copy_tree(&source, &root);
        FixtureWorkspace { root }
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create fixture destination");
        for entry in fs::read_dir(source).expect("read fixture source").flatten() {
            let from = entry.path();
            let file_name = entry.file_name();
            let fixture_name = file_name.to_string_lossy();
            let target_name = fixture_name
                .strip_suffix(".fixture")
                .unwrap_or(&fixture_name);
            let to = destination.join(target_name);
            if from.is_dir() {
                copy_tree(&from, &to);
            } else {
                fs::copy(&from, &to).expect("copy fixture file");
            }
        }
    }

    fn matching_metadata() -> MetadataSnapshot {
        let mut snapshot = MetadataSnapshot::default();
        snapshot.feature_closures.insert(
            ("asupersync".to_owned(), "0.4.9".to_owned()),
            BTreeSet::new(),
        );
        snapshot
    }

    fn report_for_fixture(
        workspace: &FixtureWorkspace,
        metadata: Option<&MetadataSnapshot>,
    ) -> Report {
        let constellation = parse_constellation_lock(
            &fs::read_to_string(workspace.root.join("constellation.lock"))
                .expect("read fixture constellation"),
        )
        .expect("parse fixture constellation");
        let packages = parse_lock_packages(
            &fs::read_to_string(workspace.root.join("Cargo.lock")).expect("read fixture lock"),
        )
        .expect("parse fixture lock");
        let mut report = Report::new();
        let dependencies = workspace_dependencies(&workspace.root, &mut report);
        check_constellation_model(
            &constellation,
            &packages,
            &dependencies,
            metadata,
            &mut report,
        );
        report
    }

    fn assert_error(report: &Report, expected: &str) {
        assert!(
            report.errors.iter().any(|error| error.contains(expected)),
            "expected diagnostic containing `{expected}`, observed {:?}",
            report.errors
        );
    }

    fn evidence_pack_fixture(source: &str, allowed_classes: &str) -> FixtureWorkspace {
        let nonce = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!("fgit-evidence-pack-{nanos}-{nonce}"));
        let source_path = root.join("crates/fgit-evidence/src");
        fs::create_dir_all(&source_path).expect("create evidence pack fixture source");
        fs::create_dir_all(root.join("registries")).expect("create evidence pack fixture registry");
        fs::write(
            root.join("registries/evidence_packs.tsv"),
            [
                "# franken-registry-v1\n",
                "id\tbody_family\tsource_path\tcompleteness_field\tallowed_classes\tstatus\n",
                &format!(
                    "EVID-001\tevidence-record\tcrates/fgit-evidence/src/lib.rs\t\
                     replay_completeness\t{allowed_classes}\tactive\n"
                ),
            ]
            .concat(),
        )
        .expect("write evidence pack fixture registry");
        fs::write(source_path.join("lib.rs"), source).expect("write evidence pack fixture source");
        FixtureWorkspace { root }
    }

    #[test]
    fn evidence_pack_registry_refuses_a_pack_without_replay_completeness() {
        const COMPLETE_BODY: &str = r#"
pub enum ReplayCompleteness { Replayable, Structural, VerifiableIfSupplied, AuditOnly }
pub struct EvidenceContext { replay_completeness: ReplayCompleteness }
pub struct EvidenceRecordBody { context: EvidenceContext }
impl CanonicalBody for EvidenceRecordBody {
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("evidence-record");
    fn write_payload(&self, out: &mut Encoder) {
        out.write_raw_byte(self.context.replay_completeness.code());
    }
    fn read_payload(input: &mut Decoder<'_>) {
        ReplayCompleteness::from_code(input.read_raw_byte("replay_completeness"), 0);
    }
}
"#;
        const CLASSES: &str =
            "replayable,structural-replay,verifiable-with-named-artifacts,audit-only";

        let permitted = evidence_pack_fixture(COMPLETE_BODY, CLASSES);
        let mut permitted_report = Report::new();
        check_evidence_packs(&permitted.root, &mut permitted_report);
        assert!(
            permitted_report.errors.is_empty(),
            "a complete evidence pack must be admitted: {:?}",
            permitted_report.errors
        );

        let missing = COMPLETE_BODY.replace(
            "out.write_raw_byte(self.context.replay_completeness.code());",
            "out.write_raw_byte(0);",
        );
        let refused = evidence_pack_fixture(&missing, CLASSES);
        let mut refused_report = Report::new();
        check_evidence_packs(&refused.root, &mut refused_report);
        assert_error(
            &refused_report,
            "does not encode required replay completeness marker",
        );

        let unknown_class = evidence_pack_fixture(
            COMPLETE_BODY,
            "replayable,structural-replay,verifiable-with-named-artifacts,hashes-logged",
        );
        let mut unknown_class_report = Report::new();
        check_evidence_packs(&unknown_class.root, &mut unknown_class_report);
        assert_error(&unknown_class_report, "must declare exactly replay classes");
    }

    #[test]
    fn live_evidence_pack_registry_covers_every_emitted_body() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("registry checker lives under the workspace tools directory");
        let mut report = Report::new();
        check_evidence_packs(root, &mut report);
        assert!(
            report.errors.is_empty(),
            "the committed evidence-pack registry must cover the live fgit-evidence emitters: {:?}",
            report.errors
        );
    }

    #[test]
    fn crate_graph_fixture_with_a_real_vertical_slice_proceeds() {
        let workspace = fixture_workspace_in("crate_graph", "clean");
        let mut report = Report::new();
        check_workspace_crate_graph(&workspace.root, &mut report);
        assert!(
            report.errors.is_empty(),
            "unexpected crate-graph errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn planted_empty_and_reexport_only_crates_are_refused() {
        for (fixture, expected) in [
            ("empty", "contains no real production item"),
            (
                "reexport_only",
                "lib.rs only re-exports symbols and contains no implementation item",
            ),
        ] {
            let workspace = fixture_workspace_in("crate_graph", fixture);
            let mut report = Report::new();
            check_workspace_crate_graph(&workspace.root, &mut report);
            assert_error(&report, expected);
        }
    }

    #[test]
    fn planted_placeholder_cfg_test_only_and_lint_relaxation_are_refused() {
        for (fixture, expected) in [
            ("placeholders", concat!("placeholder `to", "do!`")),
            ("placeholders", concat!("placeholder `un", "implemented!`")),
            ("placeholders", "placeholder `panic!(\"TODO…\")`"),
            ("placeholders", "placeholder `unreachable!(\"TODO…\")`"),
            ("cfg_test_only", "contains only cfg(test)-gated behavior"),
            ("lint_relaxation", "clippy::too_many_arguments"),
        ] {
            let workspace = fixture_workspace_in("crate_graph", fixture);
            let mut report = Report::new();
            check_workspace_crate_graph(&workspace.root, &mut report);
            assert_error(&report, expected);
        }
    }

    #[test]
    fn cfg_test_items_with_spacing_attributes_and_lexical_braces_are_not_production() {
        for source in [
            concat!(
                "#[cfg(test)]\n",
                "\n",
                "#[allow(dead_code)]\n",
                "mod tests {\n",
                "    const BRACES: &str = \"} ignored {\";\n",
                "    /* } ignored { */\n",
                "    fn runs() {}\n",
                "}\n"
            ),
            concat!(
                "#[cfg(test)] mod tests {\n",
                "    const RAW: &str = r#\"} ignored {\"#;\n",
                "    // } ignored {\n",
                "    fn runs() {}\n",
                "}\n"
            ),
        ] {
            let assessment = assess_first_party_source(source);
            assert!(
                assessment.has_cfg_test_item(),
                "the fixture must exercise cfg(test) recognition"
            );
            assert!(
                !assessment.has_production_item(),
                "test-only item leaked into the production assessment: {source}"
            );
        }
    }

    #[test]
    fn layer_registry_fixture_with_downward_edges_emits_a_deterministic_report() {
        let workspace = fixture_workspace_in("layers", "clean");
        let mut report = Report::new();
        let layer_report = evaluate_crate_layers(&workspace.root, &mut report);
        assert!(
            report.errors.is_empty(),
            "unexpected layer errors: {:?}",
            report.errors
        );
        assert_eq!(
            layer_report.render(),
            concat!(
                "# franken-layer-report-v1\n",
                "record\tcrate\tlayer\towner\tstatus\tdependency\tdependency_layer\tallowed_dependency_layers\toutcome\n",
                "crate\tfgit-derived\tL3\tderived\tactive\t-\t-\tL0,L1,L2\tregistered\n",
                "crate\tfgit-engine\tL2\tengine\tactive\t-\t-\tL0,L1,L2\tregistered\n",
                "crate\tfgit-foundation\tL0\tfoundation\tactive\t-\t-\tnone\tregistered\n",
                "crate\tfgit-product\tL4\tproduct\tactive\t-\t-\tL0,L1,L2,L3,L4\tregistered\n",
                "crate\tfgit-protocol\tL1\tprotocol\tactive\t-\t-\tL0,L1\tregistered\n",
                "edge\tfgit-derived\tL3\tderived\tactive\tfgit-engine\tL2\tL0,L1,L2\tpermitted\n",
                "edge\tfgit-engine\tL2\tengine\tactive\tfgit-protocol\tL1\tL0,L1,L2\tpermitted\n",
                "edge\tfgit-product\tL4\tproduct\tactive\tfgit-derived\tL3\tL0,L1,L2,L3,L4\tpermitted\n",
                "edge\tfgit-protocol\tL1\tprotocol\tactive\tfgit-foundation\tL0\tL0,L1\tpermitted\n"
            )
        );
    }

    #[test]
    fn planted_upward_and_l3_sibling_edges_are_refused() {
        for (fixture, expected) in [
            ("upward", "`fgit-engine` (L2) -> `fgit-derived` (L3)"),
            ("l3_sibling", "`fgit-alpha` (L3) -> `fgit-beta` (L3)"),
        ] {
            let workspace = fixture_workspace_in("layers", fixture);
            let mut report = Report::new();
            let layer_report = evaluate_crate_layers(&workspace.root, &mut report);
            assert_error(&report, expected);
            assert!(
                layer_report.render().contains("violation"),
                "layer report must retain the failing edge: {}",
                layer_report.render()
            );
        }
    }

    #[test]
    fn layer_diagnostics_name_the_rule_that_refused_the_edge() {
        let upward = fixture_workspace_in("layers", "upward");
        let mut upward_report = Report::new();
        let _ = evaluate_crate_layers(&upward.root, &mut upward_report);
        let upward_error = upward_report
            .errors
            .iter()
            .find(|error| error.contains("`fgit-engine` (L2) -> `fgit-derived` (L3)"))
            .expect("upward edge must be refused");
        assert!(
            upward_error.contains("raise the source crate layer to at least L3"),
            "upward diagnostic must name the source-layer remedy: {upward_error}"
        );
        assert!(
            !upward_error.contains("declared allowed layers"),
            "upward diagnostic must not name an unconsulted field: {upward_error}"
        );

        let undeclared = fixture_workspace_in("layers", "clean");
        let registry_path = undeclared.root.join(CRATE_LAYERS_FILE);
        let registry = fs::read_to_string(&registry_path).expect("read clean layer registry");
        let narrowed = registry.replace(
            "fgit-engine\tL2\tL0,L1,L2\tengine\tactive",
            "fgit-engine\tL2\tL0\tengine\tactive",
        );
        assert_ne!(
            registry, narrowed,
            "fixture must narrow only fgit-engine's allowed layers"
        );
        fs::write(&registry_path, narrowed).expect("write narrowed layer registry");

        let mut undeclared_report = Report::new();
        let _ = evaluate_crate_layers(&undeclared.root, &mut undeclared_report);
        let undeclared_error = undeclared_report
            .errors
            .iter()
            .find(|error| error.contains("`fgit-engine` (L2) -> `fgit-protocol` (L1)"))
            .expect("same-or-lower edge outside allowed layers must be refused");
        assert!(
            undeclared_error.contains("target layer is absent from declared allowed layers `L0`"),
            "undeclared-layer diagnostic must name the consulted field: {undeclared_error}"
        );
        assert!(
            !undeclared_error.contains("raise the source crate layer"),
            "undeclared-layer diagnostic must not claim an upward-edge remedy: {undeclared_error}"
        );
    }

    #[test]
    fn layer_registry_requires_an_explicit_row_for_every_workspace_crate() {
        let workspace = fixture_workspace_in("layers", "clean");
        let path = workspace.root.join(CRATE_LAYERS_FILE);
        let registry = fs::read_to_string(&path).expect("read layer registry fixture");
        let without_product = registry
            .lines()
            .filter(|line| !line.starts_with("fgit-product\t"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, format!("{without_product}\n")).expect("write incomplete layer registry");

        let mut report = Report::new();
        let _ = evaluate_crate_layers(&workspace.root, &mut report);
        assert_error(
            &report,
            "crate-layer registry lacks workspace crate `fgit-product`",
        );
    }

    #[test]
    fn layer_registry_refuses_an_orphaned_first_party_row() {
        let workspace = fixture_workspace_in("layers", "clean");
        let path = workspace.root.join(CRATE_LAYERS_FILE);
        let registry = fs::read_to_string(&path).expect("read layer registry fixture");
        let with_orphan = registry.replace(
            "fgit-product\tL4\tL0,L1,L2,L3,L4\tproduct\tactive\n",
            concat!(
                "fgit-orphan\tL0\tnone\torphan\tactive\n",
                "fgit-product\tL4\tL0,L1,L2,L3,L4\tproduct\tactive\n"
            ),
        );
        fs::write(&path, with_orphan).expect("write over-complete layer registry");

        let mut report = Report::new();
        let _ = evaluate_crate_layers(&workspace.root, &mut report);
        assert_error(
            &report,
            "crate-layer registry declares non-workspace crate `fgit-orphan`",
        );
    }

    #[test]
    fn planted_unsafe_ffi_assembly_build_proc_and_nested_lock_are_refused() {
        let workspace = fixture_workspace_in("crate_graph", "forbidden_surfaces");
        let mut report = Report::new();
        check_rust_sources(&workspace.root, &mut report);
        check_forbidden_artifacts(&workspace.root, &mut report);
        let manifest = fs::read_to_string(workspace.root.join("crates/forbidden/Cargo.toml"))
            .expect("read planted manifest");
        check_first_party_manifest_declarations(
            "crates/forbidden/Cargo.toml",
            &manifest,
            &mut report,
        );
        for expected in [
            concat!("uns", "afe {"),
            concat!("extern ", "\"C\""),
            concat!("as", "m!"),
            "first-party build script",
            "nested lockfile",
            "first-party proc macro",
        ] {
            assert_error(&report, expected);
        }
        assert_eq!(
            find_inline_assembly_construct(concat!("global_as", "m!(\"nop\");")),
            Some(concat!("global_as", "m!").to_owned())
        );
    }

    /// The workspace root, derived from this crate's manifest directory.
    /// The needle this suite plants, assembled rather than written. This file
    /// lives under `tools/registry-check/src/`, so the check under test scans
    /// it: a fixture containing the literal token would make the constitution
    /// lane fail on its own test suite. Proving that is awkward is part of
    /// proving the check works.
    fn planted_float_type() -> String {
        concat!("f", "64").to_owned()
    }

    #[test]
    fn a_planted_float_type_in_production_source_is_refused() {
        let source = format!(
            "pub fn ratio(numerator: u64) -> {} {{ 0.0 }}",
            planted_float_type()
        );
        assert!(
            find_floating_point_construct(&source).is_some(),
            "a float type in production source must be refused"
        );
    }

    #[test]
    fn float_arithmetic_is_refused_even_when_the_type_is_never_named() {
        // The escape hatch worth closing: state can live in an integer newtype
        // and still accumulate through transcendental methods, which are
        // float-only. Naming no float type must not buy a pass.
        let source = format!("let bound = variance{};", concat!(".sq", "rt()"));
        assert!(
            find_floating_point_construct(&source).is_some(),
            "transcendental arithmetic must be refused on its own"
        );
    }

    #[test]
    fn a_doc_comment_forbidding_floats_is_permitted() {
        // THE PAIRED PERMITTED CASE, and the one that decides whether this
        // check survives contact. `fgit-types`, `fgit-witness` and
        // `fgit-statistics` all document the prohibition by NAMING the type.
        // A checker that flagged those would be reverted within the hour.
        let source = format!(
            "//! No floating point. `{}` and `{}` do not implement the trait.\npub fn width() -> u64 {{ 8 }}",
            planted_float_type(),
            concat!("f", "32")
        );
        assert!(
            find_floating_point_construct(&source).is_none(),
            "prose that forbids a float must not be read as a use of one"
        );
    }

    #[test]
    fn an_identifier_that_merely_contains_the_token_is_permitted() {
        // Word-boundary check. Without it, `parse_f64_from_text` or a field
        // named `f64_disabled` would be refused, and the first person to hit
        // that would weaken the check rather than rename the field.
        let source = format!(
            "struct Limits {{ {}_disabled: bool }} fn parse_{}_text() {{}}",
            planted_float_type(),
            planted_float_type()
        );
        assert!(
            find_floating_point_construct(&source).is_none(),
            "an identifier containing the token is not a float use"
        );
    }

    #[test]
    fn the_float_check_runs_over_a_non_empty_tree_and_the_tree_is_clean() {
        // Non-vacuity plus the live result. If the walker stopped finding Rust
        // files, every assertion above would still pass while the gate scanned
        // nothing -- the decorative-gate failure this whole lane exists to
        // prevent one layer down.
        let root = calm_repo_root();
        let mut report = Report::new();
        check_rust_sources(&root, &mut report);
        assert!(
            report.rust_files > 100,
            "expected a substantial Rust tree, saw {}",
            report.rust_files
        );
        let floats: Vec<&String> = report
            .errors
            .iter()
            .filter(|error| error.contains("floating point is excluded"))
            .collect();
        assert!(
            floats.is_empty(),
            "first-party production source must carry no floating point: {floats:?}"
        );
    }

    /// Builds a ledger fragment carrying the machine-read vocabulary block.
    fn vocabulary_block(values: &[&str]) -> String {
        let mut out = String::from("<!-- registry-status-vocabulary:begin -->\n");
        for value in values {
            out.push_str("- `");
            out.push_str(value);
            out.push_str("`\n");
        }
        out.push_str("<!-- registry-status-vocabulary:end -->\n");
        out
    }

    #[test]
    fn the_documented_vocabulary_parses_to_exactly_the_listed_values() {
        let parsed = ledger_status_vocabulary(&vocabulary_block(&["active", "rejected"]))
            .expect("a well-formed block parses");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("active") && parsed.contains("rejected"));
    }

    #[test]
    fn a_missing_or_empty_block_is_refused_rather_than_read_as_an_empty_set() {
        // The vacuity guard. If a deleted block parsed as an empty set, the
        // difference comparison would find no disagreement and the pin would
        // pass while enforcing nothing.
        assert!(ledger_status_vocabulary("no markers here at all").is_none());
        assert!(ledger_status_vocabulary(&vocabulary_block(&[])).is_none());
    }

    #[test]
    fn the_pin_detects_drift_in_both_directions() {
        // Presence case: the comparison must actually fire. Direction one --
        // the document naming a value the checker does not admit.
        let doc_only =
            ledger_status_vocabulary(&vocabulary_block(&["active", "superseded"])).expect("parses");
        let enforced: BTreeSet<String> = KNOWN_STATUSES.iter().map(|s| (*s).to_owned()).collect();
        assert!(
            doc_only.difference(&enforced).any(|v| v == "superseded"),
            "a documented value the checker rejects must be detected"
        );

        // Direction two -- the checker admitting a value the document omits.
        let short = ledger_status_vocabulary(&vocabulary_block(&["active"])).expect("parses");
        assert!(
            enforced.difference(&short).count() > 0,
            "an enforced value the document omits must be detected"
        );
    }

    #[test]
    fn the_pin_is_reached_by_both_the_registry_and_constitution_lanes() {
        // The lane-coverage regression guard. The pin was originally called
        // only from `check_registries`, so `verify.sh constitution` was blind
        // to a divergence -- measured at the time as constitution exit 0 while
        // docs exited 1. That matters because `KNOWN_STATUSES` is a RUST source
        // constant: whoever adds a seventh value is editing Rust and reaches
        // for the Rust lane, which is the one that stayed quiet.
        //
        // Asserting the predicates rather than the call site, because the call
        // site is what a future refactor moves and the predicates are what
        // decide whether it runs.
        assert!(
            CheckSet::Constitution.includes_constitution(),
            "the constitution lane must reach the pin"
        );
        assert!(
            CheckSet::Registries.includes_registries(),
            "the registry lane must reach the pin"
        );
        assert!(
            CheckSet::All.includes_registries() && CheckSet::All.includes_constitution(),
            "`all` satisfies both predicates, which is why the dispatch guards \
             them with `||` rather than calling the pin in each branch -- \
             otherwise `all` would report every divergence twice"
        );
        // And the paired negative, so this is not merely asserting that
        // everything is included: a lane genuinely outside both must stay out.
        assert!(
            !CheckSet::CrateGraph.includes_registries()
                && !CheckSet::CrateGraph.includes_constitution(),
            "a lane outside both predicates must not reach the pin"
        );
    }

    #[test]
    fn the_shipped_ledger_and_the_checker_agree_and_the_set_is_non_empty() {
        // The live assertion, plus non-vacuity: a vocabulary that had shrunk to
        // nothing would satisfy set equality trivially.
        let root = calm_repo_root();
        let mut report = Report::new();
        check_status_vocabulary_pin(&root, &mut report);
        assert!(
            report.errors.is_empty(),
            "ledger §6.2 and is_known_status must agree: {:?}",
            report.errors
        );
        assert_eq!(
            KNOWN_STATUSES.len(),
            6,
            "the vocabulary is six values; changing it requires changing the ledger in the same commit"
        );
    }

    #[test]
    fn is_known_status_still_admits_exactly_the_documented_set() {
        // The refactor from `matches!` to a slice must not have changed
        // behaviour: every listed value passes, and a near-miss does not.
        for value in KNOWN_STATUSES {
            assert!(is_known_status(value), "{value} must be admitted");
        }
        for planted in ["superseded", "Active", "act", "", "retired"] {
            assert!(
                !is_known_status(planted),
                "`{planted}` must not be admitted"
            );
        }
    }

    fn calm_repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("tools/registry-check sits two levels under the workspace root")
            .to_path_buf()
    }

    #[test]
    fn calm_classes_are_parsed_from_the_authoritative_document() {
        // The closed set must come from the document, not from this checker.
        let root = calm_repo_root();
        let mut report = Report::new();
        let classes = calm_coordination_classes(&root, &mut report);
        assert_eq!(
            classes.len(),
            CALM_CLASS_COUNT,
            "section 1 must declare exactly {CALM_CLASS_COUNT} classes; parsed {classes:?}"
        );
        for expected in [
            "monotone_with_authentication",
            "monotone_scoped",
            "commutative_but_bounded",
            "local_deterministic",
            "ordered_projection",
            "head_cas_required",
            "exclusive_external_effect",
        ] {
            assert!(
                classes.contains(expected),
                "`{expected}` missing from the parsed closed set: {classes:?}"
            );
        }
        assert!(
            report.errors.is_empty(),
            "parsing the authoritative document must not itself report errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn every_registry_coordination_class_is_declared() {
        // The PRESENCE half: the shipped registry satisfies the closed set.
        // Without this, the rejection test below could pass against a registry
        // that was already broken.
        let root = calm_repo_root();
        let mut report = Report::new();
        let classes = calm_coordination_classes(&root, &mut report);
        let text = fs::read_to_string(root.join("registries/calm_operations.tsv"))
            .expect("the calm operations registry must be readable");
        let mut checked = 0_usize;
        for line in text.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.first().copied() == Some("id") {
                continue;
            }
            let Some(value) = fields.get(2) else { continue };
            checked += 1;
            assert!(
                classes.contains(value.trim()),
                "registry row uses undeclared class `{}`",
                value.trim()
            );
        }
        assert!(
            checked > 0,
            "no registry rows were checked; this assertion would be vacuous"
        );
    }

    #[test]
    fn an_undeclared_coordination_class_is_rejected() {
        // The ABSENCE half. A closed-set check nobody has watched reject
        // something is not known to constrain anything.
        let root = calm_repo_root();
        let mut report = Report::new();
        let classes = calm_coordination_classes(&root, &mut report);
        for planted in [
            "monotone",                    // a plausible truncation
            "head_cas",                    // the near-homonym of the obligation type
            "monotone_with_authorisation", // one-letter spelling drift
            "totally_ordered_broadcast",   // an invented eighth class
        ] {
            assert!(
                !classes.contains(planted),
                "planted class `{planted}` must not be accepted as declared"
            );
        }
    }

    #[test]
    fn unsafe_ledger_policy_classes_are_specific_and_stable() {
        assert_eq!(
            expected_unsafe_policy("fgit-vertical", false),
            "must_forbid_first_party_unsafe"
        );
        assert_eq!(
            expected_unsafe_policy("franken-evidence", false),
            "must_match_sibling_contract"
        );
        assert_eq!(
            expected_unsafe_policy("pin-project-internal", true),
            "proc_macro_transitive"
        );
        assert_eq!(expected_unsafe_policy("rustix", false), "os_abi");
        assert!(unsafe_policy_matches(
            "ledgered_transitive",
            "ledgered_transitive"
        ));
        assert!(!unsafe_policy_matches(
            "ledgered_transitive",
            "ledgered_transitive_unaudited"
        ));
        assert!(!unsafe_policy_matches(
            "proc_macro_transitive",
            "ledgered_transitive_unaudited"
        ));
    }

    #[test]
    fn unsafe_ledger_rows_are_deterministic_and_count_lexical_constructs() {
        let workspace = fixture_workspace_in("crate_graph", "clean");
        let package = LockPackage {
            name: "fgit-vertical".to_owned(),
            version: "0.0.1".to_owned(),
            source: None,
            checksum: None,
            dependencies: Vec::new(),
        };
        let mut metadata = MetadataSnapshot::default();
        metadata.package_sources.insert(
            (package.name.clone(), package.version.clone()),
            PackageSource {
                manifest_path: workspace.root.join("crates/vertical/Cargo.toml"),
                license: "not_applicable".to_owned(),
                license_file: None,
            },
        );
        let policies = vec![ActiveDependencyPolicy {
            id: "DEP-013".to_owned(),
            crate_pattern: "fgit-*".to_owned(),
            unsafe_policy: "must_forbid_first_party_unsafe".to_owned(),
        }];
        let first = unsafe_ledger_rows(std::slice::from_ref(&package), &metadata, &policies)
            .expect("render first unsafe ledger row");
        let second = unsafe_ledger_rows(&[package], &metadata, &policies)
            .expect("render second unsafe ledger row");
        assert_eq!(first, second);
        assert_eq!(first[0].rust_files, 1);
        assert_eq!(first[0].unsafe_tokens, 0);
        assert_eq!(
            count_unsafe_constructs(concat!("uns", "afe { let value = 1_u8; let _ = value; }")),
            1
        );
    }

    #[test]
    fn planted_generated_wasm_policy_drift_is_refused() {
        let workspace = fixture_workspace_in("crate_graph", "clean");
        let package = LockPackage {
            name: "wasm-bindgen".to_owned(),
            version: "0.2.0".to_owned(),
            source: None,
            checksum: None,
            dependencies: Vec::new(),
        };
        let mut metadata = MetadataSnapshot::default();
        metadata.package_sources.insert(
            (package.name.clone(), package.version.clone()),
            PackageSource {
                manifest_path: workspace.root.join("crates/vertical/Cargo.toml"),
                license: "not_applicable".to_owned(),
                license_file: None,
            },
        );
        let policies = vec![ActiveDependencyPolicy {
            id: "DEP-WASM".to_owned(),
            crate_pattern: "wasm-bindgen".to_owned(),
            unsafe_policy: "ledgered_transitive".to_owned(),
        }];
        let rows = unsafe_ledger_rows(&[package], &metadata, &policies)
            .expect("render planted WASM ledger row");
        assert_eq!(rows[0].expected_policy, "proc_macro_transitive");
        let mut mismatch_report = Report::new();
        report_unsafe_ledger_policy_mismatches(&rows, &mut mismatch_report);
        assert_error(&mismatch_report, "unsafe ledger policy mismatch");

        let mut admitted_row = rows[0].clone();
        admitted_row.registry_policy = admitted_row.expected_policy.clone();
        let mut admitted_report = Report::new();
        report_unsafe_ledger_policy_mismatches(&[admitted_row], &mut admitted_report);
        assert!(
            admitted_report.errors.is_empty(),
            "near-identical admitted package must proceed: {:?}",
            admitted_report.errors
        );
    }

    fn replace_fixture_file(workspace: &FixtureWorkspace, relative: &str, from: &str, to: &str) {
        let path = workspace.root.join(relative);
        let text = fs::read_to_string(&path).expect("read fixture file");
        assert!(
            text.contains(from),
            "fixture did not contain replacement source"
        );
        fs::write(path, text.replacen(from, to, 1)).expect("write fixture file");
    }

    #[test]
    fn dormant_fixture_is_an_explicit_vacuous_pass() {
        let workspace = fixture_workspace("dormant");
        let report = report_for_fixture(&workspace, None);
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("explicitly dormant"))
        );
    }

    #[test]
    fn admitted_fixture_matches_exact_lock_metadata_and_evidence() {
        let workspace = fixture_workspace("admitted");
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn planted_second_asupersync_is_a_type_universe_failure() {
        let workspace = fixture_workspace("admitted");
        let addition = "\n[[package]]\nname = \"asupersync\"\nversion = \"0.3.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"\n";
        let path = workspace.root.join("Cargo.lock");
        let text = fs::read_to_string(&path).expect("read lock");
        fs::write(path, format!("{text}{addition}")).expect("write lock");
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "multiple Asupersync 0.x type universes",
        );
    }

    #[test]
    fn planted_tokio_is_a_typed_second_runtime_failure() {
        let workspace = fixture_workspace("admitted");
        let path = workspace.root.join("Cargo.lock");
        let text = fs::read_to_string(&path).expect("read lock");
        fs::write(
            path,
            format!("{text}\n[[package]]\nname = \"tokio\"\nversion = \"1.0.0\"\n"),
        )
        .expect("write lock");
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "alternate async runtime `tokio`",
        );
    }

    #[test]
    fn planted_source_version_and_checksum_drift_are_diagnosed() {
        let workspace = fixture_workspace("admitted");
        replace_fixture_file(
            &workspace,
            "constellation.lock",
            "registry+https://github.com/rust-lang/crates.io-index",
            "registry+https://example.invalid/index",
        );
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "constellation source drift",
        );

        let workspace = fixture_workspace("admitted");
        replace_fixture_file(&workspace, "constellation.lock", "\t0.4.9\t", "\t0.4.8\t");
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "constellation version drift",
        );

        let workspace = fixture_workspace("admitted");
        let expected_checksum = "a".repeat(64);
        let replacement_checksum = "d".repeat(64);
        let expected_field = format!("\t{expected_checksum}\tnone");
        let replacement_field = format!("\t{replacement_checksum}\tnone");
        replace_fixture_file(
            &workspace,
            "constellation.lock",
            &expected_field,
            &replacement_field,
        );
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "constellation checksum drift",
        );
    }

    #[test]
    fn planted_missing_row_and_default_feature_drift_are_diagnosed() {
        let workspace = fixture_workspace("admitted");
        let path = workspace.root.join("constellation.lock");
        let text = fs::read_to_string(&path).expect("read constellation");
        fs::write(&path, text.lines().take(3).collect::<Vec<_>>().join("\n"))
            .expect("write constellation");
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "lacks a row for resolved adopted package `asupersync`",
        );

        let workspace = fixture_workspace("admitted");
        replace_fixture_file(
            &workspace,
            "constellation.lock",
            "\tdisabled\t",
            "\tenabled\t",
        );
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "constellation default-feature drift",
        );
    }

    #[test]
    fn planted_path_and_patch_dependency_forms_are_refused() {
        let mut report = Report::new();
        check_manifest_dependency_sources(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            "fixtures/Cargo.toml",
            "[dependencies]\ndep = { version = \"1\", path = \"/absolute/unpublished\" }",
            &mut report,
        );
        assert_error(
            &report,
            "unpublished path dependency `/absolute/unpublished`",
        );

        let mut report = Report::new();
        check_manifest_dependency_sources(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            "fixtures/Cargo.toml",
            concat!(
                "[dependencies]\n",
                "compact-path={version=\"1\",path=\"/absolute/compact\"}\n",
                "compact-git={version=\"1\",git=\"https://example.invalid/compact.git\"}\n"
            ),
            &mut report,
        );
        assert_error(&report, "unpublished path dependency `/absolute/compact`");
        assert_error(
            &report,
            "unresolved Git dependency `https://example.invalid/compact.git`",
        );

        let workspace = fixture_workspace("admitted");
        let mut report = Report::new();
        check_manifest_dependency_sources(
            &workspace.root,
            &workspace.root.join("Cargo.toml"),
            "Cargo.toml",
            "[workspace.dependencies]\nfgit-runtime = { path = \"crates/fgit-runtime\" }",
            &mut report,
        );
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );

        let mut report = Report::new();
        check_manifest_overrides("fixtures/Cargo.toml", "[patch.crates-io]", &mut report);
        assert_error(&report, "[patch]/[replace]");

        let mut report = Report::new();
        check_manifest_dependency_sources(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            "fixtures/Cargo.toml",
            "[[test]]\npath = \"tests/suite/main.rs\"",
            &mut report,
        );
        assert!(
            report.errors.is_empty(),
            "test target path is not a dependency: {:?}",
            report.errors
        );
    }

    #[test]
    fn dependency_table_headers_cannot_hide_path_or_unpinned_git_sources() {
        let workspace = fixture_workspace_in("workspace_inheritance", "table_header");
        let root_manifest = workspace.root.join("Cargo.toml");
        let root_text = fs::read_to_string(&root_manifest).expect("read root fixture manifest");
        let mut report = Report::new();
        check_manifest_dependency_sources(
            &workspace.root,
            &root_manifest,
            "Cargo.toml",
            &root_text,
            &mut report,
        );
        assert!(
            report.errors.is_empty(),
            "first-party workspace table dependency should be admitted: {:?}",
            report.errors
        );
        assert!(
            manifest_dependency_names(&root_text).contains("fgit-table-header"),
            "table-form workspace dependency must remain visible to the policy parser"
        );

        let manifest = workspace.root.join("crates/table/Cargo.toml");
        let text = fs::read_to_string(&manifest).expect("read member fixture manifest");
        let mut report = Report::new();
        check_manifest_dependency_sources(
            &workspace.root,
            &manifest,
            "crates/table/Cargo.toml",
            &text,
            &mut report,
        );
        assert_error(
            &report,
            "unpublished path dependency `/absolute/unpublished`",
        );
        assert_error(
            &report,
            "unresolved Git dependency `https://example.invalid/unpinned.git`",
        );
        assert_eq!(
            report.errors.len(),
            2,
            "the table-form dependency with an exact HTTPS revision must be accepted: {:?}",
            report.errors
        );
        assert_eq!(
            manifest_dependency_names(&text),
            BTreeSet::from([
                "path-smuggle".to_owned(),
                "pinned-git".to_owned(),
                "unpinned-git".to_owned(),
            ])
        );

        let mut report = Report::new();
        check_manifest_dependency_sources(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            "fixtures/Cargo.toml",
            "[package.metadata.dependencies.provenance]\npath = \"/not/a/dependency\"",
            &mut report,
        );
        assert!(
            report.errors.is_empty(),
            "metadata containing the word dependencies is not a Cargo dependency table: {:?}",
            report.errors
        );
    }

    #[test]
    fn planted_sqlmodel_backend_and_ftui_demo_are_refused() {
        let workspace = fixture_workspace("admitted");
        let path = workspace.root.join("Cargo.lock");
        let text = fs::read_to_string(&path).expect("read lock");
        fs::write(
            path,
            format!("{text}\n[[package]]\nname = \"sqlmodel-postgres\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"ftui-showcase\"\nversion = \"0.1.0\"\n"),
        )
        .expect("write lock");
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert_error(&report, "forbidden sqlmodel backend `sqlmodel-postgres`");
        assert_error(
            &report,
            "forbidden ftui demo/showcase package `ftui-showcase`",
        );
    }

    #[test]
    fn sqlmodel_backend_predicate_admits_only_the_frankensqlite_backend() {
        let no_features = BTreeSet::new();
        assert!(!is_forbidden_sqlmodel_backend(
            "sqlmodel-frankensqlite",
            &no_features
        ));
        assert!(is_forbidden_sqlmodel_backend(
            "sqlmodel-sqlite",
            &no_features
        ));
        assert!(is_forbidden_sqlmodel_backend(
            "sqlmodel-postgres",
            &no_features
        ));
        assert!(is_forbidden_sqlmodel_backend(
            "sqlmodel-mysql",
            &no_features
        ));
        assert!(is_forbidden_sqlmodel_backend(
            "sqlmodel-core",
            &BTreeSet::from(["c-sqlite".to_owned()])
        ));
    }

    #[test]
    fn sqlmodel_substrate_with_default_feature_fsqlite_is_refused() {
        let packages = vec![
            lock_package("sqlmodel-frankensqlite"),
            lock_package("fsqlite"),
        ];
        let mut metadata = MetadataSnapshot::default();
        metadata.feature_closures.insert(
            ("fsqlite".to_owned(), "0.0.0".to_owned()),
            BTreeSet::from([
                "async-api".to_owned(),
                "native".to_owned(),
                "json".to_owned(),
                "linux-asupersync-uring".to_owned(),
            ]),
        );
        let mut report = Report::new();
        check_sqlmodel_substrate_feature_profile(&packages, &metadata, &mut report);
        assert_error(&report, "`fsqlite` resolved with excluded feature `json`");
        assert_error(
            &report,
            "`fsqlite` resolved with excluded feature `linux-asupersync-uring`",
        );
        assert_no_error(&report, "excluded feature `native`");
        assert_no_error(&report, "excluded feature `async-api`");
    }

    #[test]
    fn fsqlite_extension_features_without_substrate_stay_admitted() {
        // The rule targets the indirect widening vector only: a direct
        // consumer with its own admission decision must not start failing
        // because of the substrate gate.
        let packages = vec![lock_package("fsqlite")];
        let mut metadata = MetadataSnapshot::default();
        metadata.feature_closures.insert(
            ("fsqlite".to_owned(), "0.0.0".to_owned()),
            BTreeSet::from(["json".to_owned()]),
        );
        let mut report = Report::new();
        check_sqlmodel_substrate_feature_profile(&packages, &metadata, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
    }

    #[test]
    fn sqlmodel_substrate_with_minimal_profile_fsqlite_stays_silent() {
        // The shape upstream must publish: default-features = false with the
        // minimal native async set. The gate must not fire against it, so the
        // future admission attempt fails (if anywhere) on evidence rows, not
        // here.
        let packages = vec![
            lock_package("sqlmodel-frankensqlite"),
            lock_package("fsqlite"),
            lock_package("fsqlite-types"),
        ];
        let mut metadata = MetadataSnapshot::default();
        metadata.feature_closures.insert(
            ("fsqlite".to_owned(), "0.0.0".to_owned()),
            BTreeSet::from(["async-api".to_owned(), "native".to_owned()]),
        );
        metadata.feature_closures.insert(
            ("fsqlite-types".to_owned(), "0.0.0".to_owned()),
            BTreeSet::from(["native".to_owned()]),
        );
        let mut report = Report::new();
        check_sqlmodel_substrate_feature_profile(&packages, &metadata, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
    }

    fn assert_no_error(report: &Report, unexpected: &str) {
        assert!(
            !report.errors.iter().any(|error| error.contains(unexpected)),
            "diagnostic containing `{unexpected}` must not fire, observed {:?}",
            report.errors
        );
    }

    fn lock_with_extra_packages(workspace: &FixtureWorkspace, packages: &[(&str, &str)]) {
        let path = workspace.root.join("Cargo.lock");
        let mut text = fs::read_to_string(&path).expect("read lock");
        for (name, version) in packages {
            write!(
                text,
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"
            )
            .expect("write in-memory Cargo.lock fixture");
        }
        fs::write(path, text).expect("write lock");
    }

    fn lock_package(name: &str) -> LockPackage {
        LockPackage {
            name: name.to_owned(),
            version: "0.0.0".to_owned(),
            source: None,
            checksum: None,
            dependencies: Vec::new(),
        }
    }

    fn workspace_dependency(package: &str, features: &[&str]) -> WorkspaceDependency {
        WorkspaceDependency {
            package: package.to_owned(),
            manifest: "crates/fgit-fixture/Cargo.toml".to_owned(),
            version: None,
            default_features: "not_applicable".to_owned(),
            declared_features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        }
    }

    #[test]
    fn forbidden_constellation_classifiers_keep_explicit_permitted_boundaries() {
        assert!(is_forbidden_telemetry_exporter("opentelemetry-otlp"));
        assert!(is_forbidden_telemetry_exporter("tracing-opentelemetry"));
        assert!(!is_forbidden_telemetry_exporter("tracing"));
        assert!(!is_forbidden_telemetry_exporter("tracing-core"));
        assert!(!is_forbidden_telemetry_exporter("tracing-subscriber"));
        assert!(!is_forbidden_telemetry_exporter("log"));

        assert!(is_forbidden_native_media("wgpu"));
        assert!(is_forbidden_native_media("freetype-sys"));
        assert!(!is_forbidden_native_media("png"));
        assert!(!is_forbidden_native_media("image"));

        assert!(is_forbidden_native_transport("hyper"));
        assert!(is_forbidden_native_transport("actix"));
        assert!(!is_forbidden_native_transport("miniz_oxide"));

        assert!(is_forbidden_fastapi_surface(
            "fastapi-demo",
            &BTreeSet::new()
        ));
        assert!(is_forbidden_fastapi_surface(
            "fastapi-core",
            &BTreeSet::from(["tokio".to_owned()])
        ));
        assert!(!is_forbidden_fastapi_surface(
            "fastapi-core",
            &BTreeSet::from(["json".to_owned()])
        ));
        assert!(!is_forbidden_fastapi_surface(
            "fgit-api",
            &BTreeSet::from(["tokio".to_owned()])
        ));
    }

    #[test]
    fn forbidden_constellation_preflight_checks_the_lock_package_loop() {
        let packages = vec![
            lock_package("fastapi-demo"),
            lock_package("hyper"),
            lock_package("opentelemetry-otlp"),
            lock_package("wgpu"),
        ];
        let mut report = Report::new();

        check_forbidden_constellation_surfaces(&packages, &[], &mut report);

        assert_error(
            &report,
            "forbidden fastapi demo/example package `fastapi-demo`",
        );
        assert_error(
            &report,
            "forbidden native transport `hyper` resolved in Cargo.lock",
        );
        assert_error(
            &report,
            "forbidden telemetry exporter `opentelemetry-otlp` resolved in Cargo.lock",
        );
        assert_error(
            &report,
            "forbidden native media/GPU dependency `wgpu` resolved in Cargo.lock",
        );
    }

    #[test]
    fn forbidden_constellation_preflight_checks_the_workspace_feature_loop() {
        let dependencies = vec![
            workspace_dependency("fastapi-core", &["tokio"]),
            workspace_dependency("hyper", &[]),
            workspace_dependency("opentelemetry-sdk", &[]),
            workspace_dependency("glow", &[]),
        ];
        let mut report = Report::new();

        check_forbidden_constellation_surfaces(&[], &dependencies, &mut report);

        assert_error(
            &report,
            "forbidden fastapi feature closure for `fastapi-core` in crates/fgit-fixture/Cargo.toml",
        );
        assert_error(
            &report,
            "forbidden native transport dependency `hyper` declared in crates/fgit-fixture/Cargo.toml",
        );
        assert_error(
            &report,
            "forbidden telemetry exporter dependency `opentelemetry-sdk` declared in crates/fgit-fixture/Cargo.toml",
        );
        assert_error(
            &report,
            "forbidden native media/GPU dependency `glow` declared in crates/fgit-fixture/Cargo.toml",
        );
    }

    #[test]
    fn planted_gateway_transport_surfaces_are_refused() {
        let workspace = fixture_workspace("admitted");
        lock_with_extra_packages(
            &workspace,
            &[
                ("hyper", "1.4.0"),
                ("openssl-sys", "0.9.0"),
                ("actix-rt", "2.9.0"),
                ("libz-sys", "1.1.0"),
                ("fastapi-demo", "0.4.3"),
            ],
        );
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        for package in ["hyper", "openssl-sys", "actix-rt", "libz-sys"] {
            assert_error(
                &report,
                &format!("forbidden native transport `{package}` resolved in Cargo.lock"),
            );
        }
        assert_error(
            &report,
            "forbidden fastapi demo/example package `fastapi-demo`",
        );
    }

    /// The permitted twin for [`planted_gateway_transport_surfaces_are_refused`].
    ///
    /// Without this, a rule that refused every package would pass that test for
    /// entirely the wrong reason.
    #[test]
    fn the_admitted_closure_carries_no_forbidden_transport() {
        let workspace = fixture_workspace("admitted");
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert_no_error(&report, "forbidden native transport");
        assert_no_error(&report, "forbidden fastapi");
    }

    /// Pure-Rust compression is admissible; only the `-sys` shims that link a C
    /// library are refused. A rule matching on "compression" rather than on the
    /// exact backend names would fail here.
    #[test]
    fn pure_rust_compression_is_not_mistaken_for_a_native_backend() {
        let workspace = fixture_workspace("admitted");
        lock_with_extra_packages(
            &workspace,
            &[("flate2", "1.0.30"), ("miniz_oxide", "0.7.3")],
        );
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert_no_error(&report, "forbidden native transport `flate2`");
        assert_no_error(&report, "forbidden native transport `miniz_oxide`");
    }

    /// Records the reason FG-048c cannot admit `fastapi_rust` today.
    ///
    /// Every published fastapi-core 0.4.x (0.4.0 through 0.4.3, each checked
    /// separately) carries a non-optional `futures-executor` dependency, and
    /// `futures-executor` is an alternate runtime. This test encodes that
    /// upstream fact, and is expected to keep failing to admit until the
    /// upstream owner drops the dependency -- at which point the planted lock
    /// below stops resembling reality and this test should be revisited.
    #[test]
    fn planted_ftui_extras_telemetry_and_gpu_surfaces_are_refused() {
        let workspace = fixture_workspace("admitted");
        lock_with_extra_packages(
            &workspace,
            &[
                ("ftui-extras", "0.5.0"),
                ("opentelemetry-otlp", "0.27.0"),
                ("tracing-opentelemetry", "0.28.0"),
                ("wgpu", "22.1.0"),
                ("freetype-sys", "0.20.1"),
            ],
        );
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert_error(
            &report,
            "forbidden ftui demo/showcase package `ftui-extras`",
        );
        for exporter in ["opentelemetry-otlp", "tracing-opentelemetry"] {
            assert_error(
                &report,
                &format!("forbidden telemetry exporter `{exporter}` resolved in Cargo.lock"),
            );
        }
        for media in ["wgpu", "freetype-sys"] {
            assert_error(
                &report,
                &format!("forbidden native media/GPU dependency `{media}` resolved in Cargo.lock"),
            );
        }
    }

    /// The permitted twin. `tracing`, `tracing-core` and `log` are pure-Rust
    /// facades already resolved in this workspace: a telemetry rule that matched
    /// on the substring "tracing" rather than on the exporter family would break
    /// every pane, and this is the case that would have caught it.
    #[test]
    fn the_tracing_facade_is_not_a_telemetry_exporter() {
        let workspace = fixture_workspace("admitted");
        lock_with_extra_packages(
            &workspace,
            &[
                ("tracing", "0.1.41"),
                ("tracing-core", "0.1.33"),
                ("log", "0.4.22"),
                ("tracing-subscriber", "0.3.19"),
            ],
        );
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        for facade in ["tracing", "tracing-core", "log", "tracing-subscriber"] {
            assert_no_error(&report, &format!("forbidden telemetry exporter `{facade}`"));
        }
    }

    /// A plain ftui kernel crate carries no forbidden surface; only the
    /// demo/showcase/extras names and the extras/telemetry features do.
    #[test]
    fn the_ftui_kernel_names_are_not_themselves_forbidden() {
        assert!(!is_forbidden_ftui_surface("ftui-core", &BTreeSet::new()));
        assert!(!is_forbidden_ftui_surface("ftui-runtime", &BTreeSet::new()));
        assert!(!is_forbidden_ftui_surface("ftui-render", &BTreeSet::new()));
        assert!(is_forbidden_ftui_surface("ftui-extras", &BTreeSet::new()));
        let telemetry = BTreeSet::from(["telemetry".to_owned()]);
        assert!(is_forbidden_ftui_surface("ftui-runtime", &telemetry));
        let extras = BTreeSet::from(["extras".to_owned()]);
        assert!(is_forbidden_ftui_surface("ftui", &extras));
    }

    #[test]
    fn published_fastapi_zero_four_x_is_refused_for_its_bundled_executor() {
        let workspace = fixture_workspace("admitted");
        lock_with_extra_packages(
            &workspace,
            &[
                ("fastapi-rust", "0.4.3"),
                ("fastapi-core", "0.4.3"),
                ("futures-executor", "0.3.31"),
            ],
        );
        let metadata = matching_metadata();
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert_error(
            &report,
            "alternate async runtime `futures-executor` resolved in Cargo.lock",
        );
    }

    #[test]
    fn planted_feature_build_proc_unsafe_and_license_drift_are_refused() {
        let workspace = fixture_workspace("admitted");
        let mut metadata = matching_metadata();
        metadata
            .feature_closures
            .get_mut(&("asupersync".to_owned(), "0.4.9".to_owned()))
            .expect("fixture feature closure")
            .insert("unexpected".to_owned());
        metadata.build_scripts.insert("asupersync".to_owned());
        metadata.proc_macros.insert("asupersync".to_owned());
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert_error(&report, "constellation feature closure drift");
        assert_error(&report, "constellation build-script evidence drift");
        assert_error(&report, "constellation proc-macro evidence drift");

        replace_fixture_file(
            &workspace,
            "constellation.lock",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "missing",
        );
        replace_fixture_file(
            &workspace,
            "constellation.lock",
            "MIT OR Apache-2.0",
            "missing",
        );
        let report = report_for_fixture(&workspace, Some(&matching_metadata()));
        assert_error(&report, "transitive-unsafe evidence");
        assert_error(&report, "license evidence is missing");
    }

    #[test]
    fn candidate_state_and_malformed_schema_fail_closed() {
        let workspace = fixture_workspace("admitted");
        replace_fixture_file(
            &workspace,
            "constellation.lock",
            "state\tadmitted",
            "state\tcandidate",
        );
        let metadata = matching_metadata();
        assert_error(
            &report_for_fixture(&workspace, Some(&metadata)),
            "state=candidate is not a release admission",
        );
        assert!(parse_constellation_lock("# wrong\nstate\tdormant\n").is_err());
    }

    #[test]
    fn cargo_metadata_parser_extracts_feature_and_codegen_closures() {
        let metadata = parse_cargo_metadata(
            r#"{"packages":[{"name":"asupersync","version":"0.4.9","manifest_path":"/registry/asupersync/Cargo.toml","license":"MIT","targets":[{"kind":["lib"]},{"kind":["custom-build"]}]},{"name":"file-license","version":"1.0.0","manifest_path":"/registry/file-license/Cargo.toml","license":null,"license_file":"LICENSE","targets":[{"kind":["lib"]}]},{"name":"derive-risk","version":"1.0.0","manifest_path":"/registry/derive-risk/Cargo.toml","license":"Apache-2.0","targets":[{"kind":["proc-macro"]}]}],"resolve":{"nodes":[{"id":"registry+https://index#asupersync@0.4.9","features":["lab","net"]}]}}"#,
        )
        .expect("parse metadata");
        assert_eq!(
            metadata
                .feature_closures
                .get(&("asupersync".to_owned(), "0.4.9".to_owned())),
            Some(&BTreeSet::from(["lab".to_owned(), "net".to_owned()]))
        );
        assert!(metadata.build_scripts.contains("asupersync"));
        assert!(metadata.proc_macros.contains("derive-risk"));
        assert_eq!(
            metadata
                .package_sources
                .get(&("asupersync".to_owned(), "0.4.9".to_owned()))
                .map(|source| source.license.as_str()),
            Some("MIT")
        );
        assert_eq!(
            metadata
                .package_sources
                .get(&("file-license".to_owned(), "1.0.0".to_owned()))
                .and_then(|source| source.license_file.as_deref()),
            Some(Path::new("LICENSE"))
        );
    }

    #[test]
    fn exact_license_file_evidence_is_recognized_and_unknown_files_fail_closed() {
        let workspace = fixture_workspace_in("crate_graph", "clean");
        let known_license = workspace.root.join("LICENSE");
        fs::write(&known_license, include_str!("../../../LICENSE")).expect("write known license");
        let source = PackageSource {
            manifest_path: workspace.root.join("Cargo.toml"),
            license: "missing".to_owned(),
            license_file: Some(PathBuf::from("LICENSE")),
        };
        assert_eq!(
            package_license_evidence(&source),
            Ok(MIT_OPENAI_ANTHROPIC_RIDER.to_owned())
        );

        fs::write(&known_license, "unknown license evidence\n").expect("write unknown license");
        assert!(
            package_license_evidence(&source)
                .expect_err("unknown license must fail closed")
                .contains("unrecognized SHA-256")
        );
    }

    #[test]
    fn admission_inventory_hash_is_standard_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn generated_policy_classification_marks_os_and_wasm_surfaces() {
        assert_eq!(generated_unsafe_policy("libc", false), "os_abi");
        assert_eq!(generated_unsafe_policy("windows-sys", false), "os_abi");
        assert_eq!(
            generated_unsafe_policy("wasm-bindgen", false),
            "proc_macro_transitive"
        );
        assert_eq!(
            generated_ffi_policy("windows-sys", false),
            "os_abi_shim_no_foreign_engine"
        );
        assert_eq!(
            generated_unsafe_policy("tracing-attributes", true),
            "proc_macro_transitive"
        );
        assert_eq!(
            generated_unsafe_policy("fsqlite-vfs", false),
            "must_match_sibling_contract"
        );
    }

    #[test]
    fn fsqlite_admission_ledger_configuration_is_exact_and_distinct() {
        let config = admission_ledger_config(CheckSet::LedgerFsqlitePolicy)
            .expect("fsqlite policy generator must have a configuration");
        assert_eq!(config.root_package, "fsqlite");
        assert_eq!(config.root_version, "0.3.7");
        assert_eq!(config.decision, "allow_transitive_admitted_fsqlite");
        assert_eq!(config.owner, "storage");
        assert_ne!(
            config,
            admission_ledger_config(CheckSet::LedgerPolicy)
                .expect("runtime policy generator must have a configuration")
        );
    }

    #[test]
    fn dependency_policy_schema_marker_is_versioned_independently() {
        assert_eq!(
            registry_marker_for("dependency_policy.tsv"),
            DEPENDENCY_POLICY_MARKER_V2
        );
        assert_eq!(registry_marker_for("crate_layers.tsv"), REGISTRY_MARKER_V1);
        assert_eq!(
            registry_marker_for("verification_lanes.tsv"),
            REGISTRY_MARKER_V1
        );
    }

    #[test]
    fn constellation_default_features_follow_direct_workspace_edges() {
        let fsqlite = LockPackage {
            name: "fsqlite".to_owned(),
            version: "0.3.7".to_owned(),
            source: Some("registry+https://example.invalid/index".to_owned()),
            checksum: Some("a".repeat(64)),
            dependencies: Vec::new(),
        };
        let disabled = vec![WorkspaceDependency {
            package: "fsqlite".to_owned(),
            manifest: "crates/fgit-authority-fsqlite/Cargo.toml".to_owned(),
            version: Some("0.3.7".to_owned()),
            default_features: "disabled".to_owned(),
            declared_features: BTreeSet::new(),
        }];
        assert_eq!(
            constellation_default_features(&fsqlite, &disabled),
            Ok("disabled".to_owned())
        );
        assert_eq!(
            constellation_default_features(&fsqlite, &[]),
            Ok("not_applicable".to_owned())
        );
        let mut conflicting = disabled;
        conflicting.push(WorkspaceDependency {
            package: "fsqlite".to_owned(),
            manifest: "crates/another-adapter/Cargo.toml".to_owned(),
            version: Some("0.3.7".to_owned()),
            default_features: "enabled".to_owned(),
            declared_features: BTreeSet::new(),
        });
        assert!(
            constellation_default_features(&fsqlite, &conflicting)
                .expect_err("conflicting direct feature policy must fail closed")
                .contains("conflicting direct default-feature states")
        );
    }

    #[test]
    fn workspace_inherited_dependency_uses_root_version_features_and_default_state() {
        let workspace = fixture_workspace_in("workspace_inheritance", "inherited_disabled");
        let mut report = Report::new();
        let dependencies = workspace_dependencies(&workspace.root, &mut report);
        assert!(
            report.errors.is_empty(),
            "workspace inheritance fixture had parser errors: {:?}",
            report.errors
        );
        assert_eq!(dependencies.len(), 1);
        let dependency = &dependencies[0];
        assert_eq!(dependency.package, "asupersync");
        assert_eq!(dependency.version.as_deref(), Some("0.4.9"));
        assert_eq!(dependency.default_features, "disabled");
        assert_eq!(
            dependency.declared_features,
            BTreeSet::from(["root-feature".to_owned()])
        );

        let asupersync = LockPackage {
            name: "asupersync".to_owned(),
            version: "0.4.9".to_owned(),
            source: Some("registry+https://example.invalid/index".to_owned()),
            checksum: Some("a".repeat(64)),
            dependencies: Vec::new(),
        };
        assert_eq!(
            constellation_default_features(&asupersync, &dependencies),
            Ok("disabled".to_owned())
        );
    }

    #[test]
    fn direct_enabled_dependency_conflicts_with_inherited_disabled_root_policy() {
        let workspace = fixture_workspace_in("workspace_inheritance", "direct_conflict");
        let mut report = Report::new();
        let dependencies = workspace_dependencies(&workspace.root, &mut report);
        assert!(
            report.errors.is_empty(),
            "workspace inheritance fixture had parser errors: {:?}",
            report.errors
        );
        let asupersync = LockPackage {
            name: "asupersync".to_owned(),
            version: "0.4.9".to_owned(),
            source: Some("registry+https://example.invalid/index".to_owned()),
            checksum: Some("a".repeat(64)),
            dependencies: Vec::new(),
        };
        assert!(
            constellation_default_features(&asupersync, &dependencies)
                .expect_err(
                    "a direct enabled declaration must conflict with root-disabled inheritance"
                )
                .contains("conflicting direct default-feature states")
        );
    }

    #[test]
    fn generated_policy_block_keeps_its_first_id_after_later_admission() {
        let workspace = fixture_workspace("dormant");
        let registry = workspace.root.join("registries");
        fs::create_dir_all(&registry).expect("create registry fixture");
        fs::write(
            registry.join("dependency_policy.tsv"),
            concat!(
                "# franken-registry-v2\n",
                "id\tcrate_pattern\tscope\tdecision\towner\trationale\tfeature_policy\tunsafe_policy\tffi_policy\tstatus\tbuild_script\tproc_macro\n",
                "DEP-013\tfgit-*\tproduction\tallow_first_party\tarchitecture\tfirst-party\tworkspace_pinned\tsafe\tno_ffi\tactive\tabsent\tabsent\n",
                "DEP-014\taead\tproduction\tallow_transitive_admitted_runtime\tconcurrency\tasupersync_0.4.9_transitive_direct_parent_aes-gcm\tresolved_none\tledgered\tno_ffi\tactive\tabsent\tabsent\n",
                "DEP-175\tbubblewrap\ttooling\texternal_tool\trelease\toracle sandbox\tnot_linked\tnot_in_binary\texternal_process\tactive\tnot_applicable\tnot_applicable\n"
            ),
        )
        .expect("write registry fixture");
        assert_eq!(
            next_admission_policy_id(
                &workspace.root,
                admission_ledger_config(CheckSet::LedgerPolicy).expect("runtime config"),
                1,
            ),
            Ok(14)
        );
    }

    #[test]
    fn generated_policy_block_refuses_an_unrelated_occupied_successor_id() {
        let workspace = fixture_workspace("dormant");
        let registry = workspace.root.join("registries");
        fs::create_dir_all(&registry).expect("create registry fixture");
        fs::write(
            registry.join("dependency_policy.tsv"),
            concat!(
                "# franken-registry-v2\n",
                "id\tcrate_pattern\tscope\tdecision\towner\trationale\tfeature_policy\tunsafe_policy\tffi_policy\tstatus\tbuild_script\tproc_macro\n",
                "DEP-014\taead\tproduction\tallow_transitive_admitted_runtime\tconcurrency\tasupersync_0.4.9_transitive_direct_parent_aes-gcm\tresolved_none\tledgered\tno_ffi\tactive\tabsent\tabsent\n",
                "DEP-015\tunrelated\tproduction\tallow_transitive_admitted_other\tother\tunrelated\tresolved_none\tledgered\tno_ffi\tactive\tabsent\tabsent\n"
            ),
        )
        .expect("write registry fixture");
        let error = next_admission_policy_id(
            &workspace.root,
            admission_ledger_config(CheckSet::LedgerPolicy).expect("runtime config"),
            2,
        )
        .expect_err("an unrelated successor must not be reused by regeneration");
        assert!(
            error.contains("DEP-015 is occupied by an unrelated policy"),
            "unexpected occupied-ID refusal: {error}"
        );
    }

    #[test]
    fn workspace_member_parser_accepts_multiline_membership_lists() {
        let manifest = "[workspace]\nmembers = [\n  \"crates/fgit-types\",\n  \"tools/registry-check\",\n]\ndefault-members = [\n  \"crates/fgit-types\",\n]\n";
        assert_eq!(
            extract_workspace_string_list(manifest, "members"),
            vec!["crates/fgit-types", "tools/registry-check"]
        );
        assert_eq!(
            extract_workspace_string_list(manifest, "default-members"),
            vec!["crates/fgit-types"]
        );
    }

    #[test]
    fn direct_crate_glob_membership_permits_only_one_child_segment() {
        let members = vec!["crates/*".to_owned()];
        assert!(workspace_member_path_is_declared(
            &members,
            "crates/fgit-runtime"
        ));
        assert!(!workspace_member_path_is_declared(
            &members,
            "crates/fgit-runtime/nested"
        ));
        assert!(!workspace_member_path_is_declared(
            &members,
            "outside/fgit-runtime"
        ));
    }

    #[test]
    fn invocation_parser_accepts_a_single_fixture_root_override() {
        let invocation = parse_invocation(vec![
            "constitution".to_owned(),
            "--json".to_owned(),
            "--root".to_owned(),
            "/tmp/constellation-fixture".to_owned(),
        ])
        .expect("parse invocation");
        assert_eq!(invocation.check_set, CheckSet::Constitution);
        assert!(invocation.json);
        assert_eq!(
            invocation.root_override,
            Some(PathBuf::from("/tmp/constellation-fixture"))
        );
        assert_eq!(
            parse_invocation(vec!["--root".to_owned()]),
            Err("--root requires a directory path".to_owned())
        );
    }
}
