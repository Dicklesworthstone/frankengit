#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const REGISTRY_MARKER: &str = "# franken-registry-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckSet {
    All,
    Docs,
    Registries,
    Constitution,
}

impl CheckSet {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("all") {
            "all" => Ok(Self::All),
            "docs" => Ok(Self::Docs),
            "registries" => Ok(Self::Registries),
            "constitution" => Ok(Self::Constitution),
            other => Err(format!(
                "unknown check set `{other}`; expected all, docs, registries, or constitution"
            )),
        }
    }

    const fn includes_docs(self) -> bool {
        matches!(self, Self::All | Self::Docs | Self::Constitution)
    }

    const fn includes_registries(self) -> bool {
        matches!(self, Self::All | Self::Registries | Self::Constitution)
    }

    const fn includes_constitution(self) -> bool {
        matches!(self, Self::All | Self::Constitution)
    }
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
    let mut positional = Vec::new();
    let mut json = false;
    for arg in env::args().skip(1) {
        if arg == "--json" {
            json = true;
        } else {
            positional.push(arg);
        }
    }

    let check_set = match CheckSet::parse(positional.first().map(String::as_str)) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if positional.len() > 1 {
        eprintln!("unexpected positional arguments: {:?}", &positional[1..]);
        return ExitCode::from(2);
    }

    let root = workspace_root();
    let mut report = Report::new();
    check_required_files(&root, &mut report);
    if check_set.includes_registries() {
        check_registries(&root, &mut report);
    }
    if check_set.includes_docs() {
        check_markdown(&root, &mut report);
        check_workflows(&root, &mut report);
        check_contract_phrases(&root, &mut report);
    }
    if check_set.includes_constitution() {
        check_rust_sources(&root, &mut report);
        check_manifests(&root, &mut report);
        check_toolchain(&root, &mut report);
        check_forbidden_artifacts(&root, &mut report);
    }

    report.errors.sort();
    report.errors.dedup();
    if json {
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("registry-check must live at tools/registry-check")
        .to_path_buf()
}

fn check_required_files(root: &Path, report: &mut Report) {
    const REQUIRED: &[&str] = &[
        "Cargo.toml",
        "Cargo.lock",
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
        "docs/RAPTORQ_PERMEATION_MAP.md",
        "docs/RESEARCH_PROVENANCE.md",
        "registries/README.md",
        "registries/calm_operations.tsv",
        "registries/claim_classes.tsv",
        "registries/dependency_policy.tsv",
        "registries/durable_objects.tsv",
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
            ][..],
        ),
        (
            "durable_objects.tsv",
            &[
                "id",
                "object_class",
                "canonical_identity",
                "raptorq_profile",
                "post_decode_verification",
                "retention_owner",
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

fn check_registries(root: &Path, report: &mut Report) {
    let schemas = registry_schemas();
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
        if marker.trim() != REGISTRY_MARKER {
            report.error(format!(
                "registry marker mismatch at {display}:{}: expected `{REGISTRY_MARKER}`",
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
            let id = fields[id_index].to_owned();
            if !ids.insert(id.clone()) {
                report.error(format!("duplicate registry id `{id}` in {display}"));
            }
            if let Some(previous) = &previous_id
                && id <= *previous
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
}

fn is_known_status(value: &str) -> bool {
    matches!(
        value,
        "active" | "specified" | "implemented" | "verified" | "experimental" | "rejected"
    )
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
            if line.contains("TxId = H(") {
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
                .any(|guard| lowered.contains(guard))
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

fn check_fences(display: &str, text: &str, report: &mut Report) {
    let mut open: Option<(char, usize)> = None;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let family = if trimmed.starts_with("```") {
            Some('`')
        } else if trimmed.starts_with("~~~") {
            Some('~')
        } else {
            None
        };
        let Some(family) = family else {
            continue;
        };
        match open {
            None => open = Some((family, index + 1)),
            Some((current, _)) if current == family => open = None,
            Some(_) => {}
        }
    }
    if let Some((_, line)) = open {
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
    let bytes = text.as_bytes();
    let mut cursor = 0;
    while cursor + 2 < bytes.len() {
        let Some(close_offset) = text[cursor..].find("](") else {
            break;
        };
        let start = cursor + close_offset + 2;
        let Some(end_offset) = text[start..].find(')') else {
            break;
        };
        let end = start + end_offset;
        let raw = text[start..end].trim();
        cursor = end + 1;
        if raw.is_empty() || raw.starts_with('#') || raw.starts_with("mailto:") {
            continue;
        }
        let target = raw
            .trim_matches(|character| character == '<' || character == '>')
            .split_whitespace()
            .next()
            .unwrap_or("");
        if target.is_empty()
            || target.starts_with("http://")
            || target.starts_with("https://")
            || target.starts_with("data:")
            || target.starts_with("//")
        {
            continue;
        }
        let file_part = target.split('#').next().unwrap_or("");
        if file_part.is_empty() {
            continue;
        }
        let decoded = percent_decode(file_part);
        let candidate = path.parent().unwrap_or(root).join(decoded);
        if !candidate.exists() {
            report.error(format!("broken relative link: {display} -> {target}"));
            continue;
        }
        if let Ok(canonical) = fs::canonicalize(&candidate)
            && !canonical.starts_with(root_canonical)
        {
            report.error(format!(
                "relative link escapes repository: {display} -> {target}"
            ));
        }
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
        if !text.lines().any(|line| line.trim() == "workflow_dispatch:") {
            report.error(format!(
                "workflow {display} must expose workflow_dispatch for local DSR/act execution"
            ));
        }
        for (line_number, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed == "pull_request:" || trimmed == "push:" {
                report.error(format!(
                    "workflow {display}:{} enables hosted automatic execution; FrankenGit workflows are local/dispatch manifests",
                    line_number + 1
                ));
            }
            let Some(action) = trimmed.strip_prefix("uses:") else {
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
        if matches!(
            path.file_name().and_then(OsStr::to_str),
            Some("main.rs" | "lib.rs")
        ) && !text
            .lines()
            .take(20)
            .any(|line| line.contains("#![forbid(unsafe_code)]"))
        {
            report.error(format!(
                "crate root lacks #![forbid(unsafe_code)]: {display}"
            ));
        }
        // Quote-free patterns are split with concat! so this checker's own
        // source does not contain the forbidden byte sequences it scans for.
        for forbidden in [
            concat!("uns", "afe {"),
            concat!("uns", "afe fn "),
            concat!("uns", "afe impl "),
            concat!("#![allow(uns", "afe_code)]"),
            concat!("#[allow(uns", "afe_code)]"),
            "extern \"C\"",
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

fn check_manifests(root: &Path, report: &mut Report) {
    let allowed = load_allowed_dependency_patterns(root, report);
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

        if text.lines().any(|line| {
            let line = line.trim();
            line.starts_with("build =")
                || line.starts_with("links =")
                || line == "proc-macro = true"
        }) {
            report.error(format!(
                "manifest {display} declares a build script, native links, or first-party proc macro without a registered constitutional exception"
            ));
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
        if fields.len() < 10 {
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

    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
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
                        dependencies.insert(name.to_owned());
                    }
                }
            }
            continue;
        }
        if !in_dependency_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let alias = key.trim().trim_matches('"');
        if let Some(package) = extract_inline_string_field(value, "package") {
            dependencies.insert(package);
        } else if !alias.is_empty() {
            dependencies.insert(alias.to_owned());
        }
    }

    dependencies
}

fn extract_inline_string_field(value: &str, field: &str) -> Option<String> {
    let marker = format!("{field} =");
    let start = value.find(&marker)? + marker.len();
    let remainder = value[start..].trim_start();
    let quoted = remainder.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_owned())
}

fn check_toolchain(root: &Path, report: &mut Report) {
    let text = fs::read_to_string(root.join("rust-toolchain.toml")).unwrap_or_default();
    if !text.contains("channel = \"nightly-") {
        report.error("rust-toolchain.toml must pin a dated nightly channel");
    }
    for component in ["rustfmt", "clippy"] {
        if !text.contains(component) {
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
        if name == OsStr::new(".git") || name == OsStr::new("target") {
            continue;
        }
        if path.is_dir() {
            collect_files(&path, output);
        } else if path.is_file() {
            output.push(path);
        }
    }
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
