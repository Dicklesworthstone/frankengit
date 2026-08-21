#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const REGISTRY_MARKER: &str = "# franken-registry-v1";
const CONSTELLATION_MARKER: &str = "# franken-constellation-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckSet {
    All,
    Docs,
    Registries,
    Constitution,
    Constellation,
    LedgerPolicy,
    LedgerConstellation,
}

impl CheckSet {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("all") {
            "all" => Ok(Self::All),
            "docs" => Ok(Self::Docs),
            "registries" => Ok(Self::Registries),
            "constitution" => Ok(Self::Constitution),
            "constellation" => Ok(Self::Constellation),
            "ledger-policy" => Ok(Self::LedgerPolicy),
            "ledger-constellation" => Ok(Self::LedgerConstellation),
            other => Err(format!(
                "unknown command `{other}`; expected all, docs, registries, constitution, constellation, ledger-policy, or ledger-constellation"
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
        matches!(self, Self::LedgerPolicy | Self::LedgerConstellation)
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
    let mut report = Report::new();
    if invocation.check_set == CheckSet::Constellation {
        check_constellation_manifests(&root, &mut report);
        check_constellation(&root, &mut report);
    } else {
        check_required_files(&root, &mut report);
        if invocation.check_set.includes_registries() {
            check_registries(&root, &mut report);
        }
        if invocation.check_set.includes_docs() {
            check_markdown(&root, &mut report);
            check_workflows(&root, &mut report);
            check_contract_phrases(&root, &mut report);
        }
        if invocation.check_set.includes_constitution() {
            check_rust_sources(&root, &mut report);
            check_manifests(&root, &mut report);
            check_constellation(&root, &mut report);
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
                "encoding_class",
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
    const BANNED: [&str; 5] = [
        "push",
        "pull_request",
        "schedule",
        "workflow_run",
        "repository_dispatch",
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
        if let Some(token) = find_unsafe_construct(&text) {
            report.error(format!("forbidden Rust construct `{token}` in {display}"));
        }
        // Quote-free patterns are split with concat! so this checker's own
        // source does not contain the forbidden byte sequences it scans for.
        for forbidden in [
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
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = line.trim_matches(['[', ']']);
            in_workspace_dependencies = section == "workspace.dependencies";
            in_dependency_section = is_dependency_section(section);
            continue;
        }
        if !in_dependency_section || !looks_like_dependency_declaration(line) {
            continue;
        }
        if let Some(path) = extract_inline_string_field(line, "path") {
            let local_name = line
                .split_once('=')
                .map(|(name, _)| name.trim().trim_matches('"'))
                .unwrap_or("");
            if !is_first_party_workspace_path(
                root,
                manifest_path,
                in_workspace_dependencies,
                local_name,
                &path,
            ) {
                report.error(format!(
                    "unpublished path dependency `{path}` in {display}:{}; release-facing dependencies must resolve from a pinned release source",
                    line_number + 1
                ));
            }
        }
        if let Some(git) = extract_inline_string_field(line, "git")
            && (!git.starts_with("https://") || extract_inline_string_field(line, "rev").is_none())
        {
            report.error(format!(
                "unresolved Git dependency `{git}` in {display}:{}; require HTTPS plus an exact rev or use a registry release",
                line_number + 1
            ));
        }
    }
}

fn is_dependency_section(section: &str) -> bool {
    matches!(
        section,
        "dependencies" | "dev-dependencies" | "build-dependencies" | "workspace.dependencies"
    ) || section.ends_with(".dependencies")
        || section.ends_with(".dev-dependencies")
        || section.ends_with(".build-dependencies")
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
    let member_declared = workspace_member_path_is_declared(
        &extract_workspace_string_list(&root_manifest, "members"),
        path,
    );
    let default_member_declared = workspace_member_path_is_declared(
        &extract_workspace_string_list(&root_manifest, "default-members"),
        path,
    );
    member_declared && default_member_declared
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
    line.contains("path =") || line.contains("git =")
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

/// Emits deterministic, reviewable policy rows for the exact package closure
/// rooted at the one admitted runtime. It deliberately emits rows rather than
/// editing the registry: a reviewer can inspect every generated rationale and
/// policy before the rows are applied under the registry reservation.
fn generate_admission_ledger(root: &Path, command: CheckSet) -> Result<String, String> {
    let lock_text = fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|error| format!("cannot read Cargo.lock: {error}"))?;
    let packages = parse_lock_packages(&lock_text)?;
    let runtime = packages
        .iter()
        .filter(|package| package.name == "asupersync")
        .collect::<Vec<_>>();
    if runtime.len() != 1 {
        return Err(format!(
            "expected exactly one asupersync package before ledger generation, observed {}",
            runtime.len()
        ));
    }
    if command == CheckSet::LedgerConstellation {
        return generate_constellation_ledger(&packages, &cargo_metadata(root)?);
    }
    let closure = dependency_closure(&packages, "asupersync");
    let baseline_allowed = baseline_dependency_patterns(root)?;
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
    let mut output = String::new();
    for (next_id, name) in (next_admission_policy_id(root)?..).zip(&unresolved) {
        let packages_for_name = packages
            .iter()
            .filter(|package| package.name == *name)
            .collect::<Vec<_>>();
        let feature_policy = resolved_feature_policy(&packages_for_name, &metadata);
        let parent = parent_edges.get(name).map_or("asupersync", String::as_str);
        let unsafe_policy = generated_unsafe_policy(name);
        let ffi_policy = generated_ffi_policy(name);
        writeln!(
            output,
            "DEP-{next_id:03}\t{name}\tproduction\tallow_transitive_admitted_runtime\tconcurrency\tasupersync_0.4.9_transitive_direct_parent_{parent}\t{feature_policy}\t{unsafe_policy}\t{ffi_policy}\tactive"
        )
        .map_err(|error| format!("cannot render policy row: {error}"))?;
    }
    Ok(output)
}

/// Generated rows must remain reproducible after they have been admitted. The
/// baseline is therefore every active allow row except the generator's own
/// `allow_transitive_admitted_runtime` decision; using the full active registry
/// would make a second invocation emit nothing and hide drift.
fn baseline_dependency_patterns(root: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(root.join("registries/dependency_policy.tsv"))
        .map_err(|error| format!("cannot read dependency policy registry: {error}"))?;
    let mut patterns = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 10 {
            continue;
        }
        if fields[9] == "active"
            && fields[3].starts_with("allow")
            && fields[3] != "allow_transitive_admitted_runtime"
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

/// The generated runtime admission block retains its first assigned ID even if
/// a later, unrelated policy row is appended. On a fresh registry it starts at
/// the next free ID; once present it is identified by its exact decision,
/// owner, and runtime-rooted rationale rather than by the registry tail.
fn next_admission_policy_id(root: &Path) -> Result<usize, String> {
    let text = fs::read_to_string(root.join("registries/dependency_policy.tsv"))
        .map_err(|error| format!("cannot read dependency policy registry: {error}"))?;
    let generated_start = text
        .lines()
        .filter_map(dependency_policy_fields)
        .filter(|fields| {
            fields[3] == "allow_transitive_admitted_runtime"
                && fields[4] == "concurrency"
                && fields[5].starts_with("asupersync_0.4.9_transitive_direct_parent_")
        })
        .filter_map(|fields| fields[0].strip_prefix("DEP-"))
        .filter_map(|number| number.parse::<usize>().ok())
        .min();
    if let Some(start) = generated_start {
        return Ok(start);
    }
    let largest = text
        .lines()
        .filter_map(dependency_policy_fields)
        .filter_map(|fields| fields[0].strip_prefix("DEP-"))
        .filter_map(|number| number.parse::<usize>().ok())
        .max()
        .unwrap_or(0);
    Ok(largest + 1)
}

fn dependency_policy_fields(line: &str) -> Option<[&str; 10]> {
    let fields = line.split('\t').collect::<Vec<_>>();
    (fields.len() == 10).then(|| {
        [
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7],
            fields[8], fields[9],
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

fn generated_unsafe_policy(name: &str) -> &'static str {
    if name.contains("derive")
        || name.contains("macro")
        || name.starts_with("wasm")
        || matches!(
            name,
            "quote"
                | "syn"
                | "proc-macro2"
                | "pastey"
                | "rustversion"
                | "windows-implement"
                | "windows-interface"
        )
    {
        "proc_macro_transitive"
    } else if matches!(
        name,
        "libc" | "nix" | "ntapi" | "rustix" | "socket2" | "windows" | "windows-sys" | "winapi"
    ) || name.starts_with("windows-")
        || name.starts_with("winapi")
        || name.starts_with("objc2")
        || matches!(
            name,
            "dispatch2" | "wasi" | "r-efi" | "redox_syscall" | "hermit-abi"
        )
    {
        "os_abi"
    } else {
        "ledgered_transitive_unaudited"
    }
}

fn generated_ffi_policy(name: &str) -> &'static str {
    if generated_unsafe_policy(name) == "os_abi" {
        "os_abi_shim_no_foreign_engine"
    } else {
        "no_foreign_engine_declared"
    }
}

/// Renders the four currently resolved FrankenSuite rows from `Cargo`'s lock and
/// metadata rather than accepting human-invented evidence digests. The public
/// contract fingerprint is a canonical source-level inventory of public-item
/// candidates; it is deliberately not a claim that this lexical pass is a
/// semantic `Rust` API proof. The unsafe digest similarly records a canonical
/// lexical inventory over the package's resolved transitive closure.
fn generate_constellation_ledger(
    packages: &[LockPackage],
    metadata: &MetadataSnapshot,
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
        if package_source.license == "missing" {
            return Err(format!(
                "cargo metadata lacks license evidence for constellation package `{}` {}",
                package.name, package.version
            ));
        }
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
        let default_features = if package.name == "asupersync" {
            "disabled"
        } else {
            "not_applicable"
        };
        let features = canonical_feature_list(features);
        writeln!(
            output,
            "{}\t{source}\t{}\tnot_applicable\t{checksum}\t{features}\t{default_features}\t{public_contract_fingerprint}\tall-cargo-lock-targets\t{}\t{build_scripts}\t{proc_macros}\t{transitive_unsafe_digest}\tadmitted\tdocs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md#7-dependency-admission-procedure",
            package.name, package.version, package_source.license,
        )
        .map_err(|error| format!("cannot render constellation row: {error}"))?;
    }
    if output.is_empty() {
        return Err("Cargo.lock has no resolved constellation package".to_owned());
    }
    Ok(output)
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
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).take(16).enumerate() {
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
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (index, constant) in SHA256_ROUND_CONSTANTS.iter().enumerate() {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceDependency {
    package: String,
    manifest: String,
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
    let mut dependencies = Vec::new();
    for path in workspace_manifest_paths(root, report) {
        let display = relative(root, &path);
        let Ok(text) = fs::read_to_string(&path) else {
            report.error(format!("cannot read workspace manifest {display}"));
            continue;
        };
        dependencies.extend(parse_manifest_dependencies(&display, &text));
    }
    dependencies
}

fn parse_manifest_dependencies(display: &str, text: &str) -> Vec<WorkspaceDependency> {
    let mut dependencies = Vec::new();
    let mut in_dependencies = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            in_dependencies = section == "dependencies" || section == "workspace.dependencies";
            continue;
        }
        if !in_dependencies || line.is_empty() {
            continue;
        }
        let Some((raw_name, value)) = line.split_once('=') else {
            continue;
        };
        let name = raw_name.trim().trim_matches('"');
        if name.is_empty() {
            continue;
        }
        let package =
            extract_inline_string_field(value, "package").unwrap_or_else(|| name.to_owned());
        let default_features = if value.contains("default-features = false") {
            "disabled"
        } else {
            "enabled"
        };
        dependencies.push(WorkspaceDependency {
            package,
            manifest: display.to_owned(),
            default_features: default_features.to_owned(),
            declared_features: extract_inline_string_list(value, "features"),
        });
    }
    dependencies
}

fn extract_inline_string_list(value: &str, field: &str) -> BTreeSet<String> {
    let Some(position) = value.find(field) else {
        return BTreeSet::new();
    };
    let tail = &value[position + field.len()..];
    let Some(after_equals) = tail.trim_start().strip_prefix('=') else {
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
            || features
                .iter()
                .any(|feature| matches!(feature.as_str(), "demo" | "showcase")))
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
        snapshot.package_sources.insert(
            (name.clone(), version),
            PackageSource {
                manifest_path: PathBuf::from(manifest_path),
                license,
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
    check_constellation_exact(constellation, packages, dependencies, metadata, report);
    check_generated_constellation_evidence(constellation, packages, metadata, report);
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
    report: &mut Report,
) {
    if constellation.state != ConstellationState::Admitted || metadata.package_sources.is_empty() {
        return;
    }
    let rows = match generate_constellation_ledger(packages, metadata) {
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
        let alias = key.trim().trim_matches('"');
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
        if let Some(rest) = after.strip_prefix('=')
            && let Some(found) = extract_string_value(rest)
        {
            return Some(found);
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
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/constellation")
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
            let to = destination.join(entry.file_name());
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
        for (from, to, expected) in [
            (
                "registry+https://github.com/rust-lang/crates.io-index",
                "registry+https://example.invalid/index",
                "constellation source drift",
            ),
            ("\t0.4.9\t", "\t0.4.8\t", "constellation version drift"),
            (
                "\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tnone",
                "\tdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\tnone",
                "constellation checksum drift",
            ),
        ] {
            let workspace = fixture_workspace("admitted");
            replace_fixture_file(&workspace, "constellation.lock", from, to);
            let metadata = matching_metadata();
            assert_error(&report_for_fixture(&workspace, Some(&metadata)), expected);
        }
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
            r#"{"packages":[{"name":"asupersync","version":"0.4.9","manifest_path":"/registry/asupersync/Cargo.toml","license":"MIT","targets":[{"kind":["lib"]},{"kind":["custom-build"]}]},{"name":"derive-risk","version":"1.0.0","manifest_path":"/registry/derive-risk/Cargo.toml","license":"Apache-2.0","targets":[{"kind":["proc-macro"]}]}],"resolve":{"nodes":[{"id":"registry+https://index#asupersync@0.4.9","features":["lab","net"]}]}}"#,
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
        assert_eq!(generated_unsafe_policy("libc"), "os_abi");
        assert_eq!(generated_unsafe_policy("windows-sys"), "os_abi");
        assert_eq!(
            generated_unsafe_policy("wasm-bindgen"),
            "proc_macro_transitive"
        );
        assert_eq!(
            generated_ffi_policy("windows-sys"),
            "os_abi_shim_no_foreign_engine"
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
