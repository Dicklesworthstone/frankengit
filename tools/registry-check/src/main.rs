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
        matches!(self, Self::All | Self::Docs)
    }

    const fn includes_registries(self) -> bool {
        matches!(self, Self::All | Self::Docs | Self::Registries)
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
        check_constellation(&root, &mut report);
        check_toolchain(&root, &mut report);
    }
    check_forbidden_artifacts(&root, &mut report);

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
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_workspace_dependencies = line == "[workspace.dependencies]";
            continue;
        }
        if !looks_like_dependency_declaration(line) {
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
    let member_declared = extract_workspace_string_list(&root_manifest, "members")
        .iter()
        .any(|member| member == path);
    let default_member_declared = extract_workspace_string_list(&root_manifest, "default-members")
        .iter()
        .any(|member| member == path);
    member_declared && default_member_declared
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
}

/// Cargo.lock is TOML, but this deliberately handles only its package-array
/// shape. The checker fails closed if a package omits a name or version rather
/// than silently accepting a future lockfile grammar change.
fn parse_lock_packages(text: &str) -> Result<Vec<LockPackage>, String> {
    let mut packages = Vec::new();
    let mut current: Option<LockPackage> = None;

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
            });
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
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
    build_scripts: BTreeSet<String>,
    proc_macros: BTreeSet<String>,
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
            build_scripts: parse_canonical_list(fields[10], "build_scripts", line_number + 1)?,
            proc_macros: parse_canonical_list(fields[11], "proc_macros", line_number + 1)?,
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
    members
        .into_iter()
        .map(|member| root.join(member).join("Cargo.toml"))
        .filter(|path| {
            if path.is_file() {
                true
            } else {
                report.error(format!(
                    "workspace member lacks Cargo.toml: {}",
                    relative(root, path)
                ));
                false
            }
        })
        .collect()
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
    check_runtime_universe(&packages, report);
    check_forbidden_constellation_surfaces(&packages, &dependencies, report);

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
    check_constellation_exact(&constellation, &packages, &dependencies, metadata, report);
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
    check_global_codegen_inventory(constellation, metadata, report);
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

fn check_global_codegen_inventory(
    constellation: &ConstellationLock,
    metadata: &MetadataSnapshot,
    report: &mut Report,
) {
    for entry in constellation.entries.values() {
        if entry.build_scripts != metadata.build_scripts {
            report.error(format!(
                "constellation build-script inventory drift for `{}`: metadata {:?}, constellation {:?}",
                entry.package, metadata.build_scripts, entry.build_scripts
            ));
        }
        if entry.proc_macros != metadata.proc_macros {
            report.error(format!(
                "constellation proc-macro inventory drift for `{}`: metadata {:?}, constellation {:?}",
                entry.package, metadata.proc_macros, entry.proc_macros
            ));
        }
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
/// violation in the FrankenGit tree.
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
            "dep = { version = \"1\", path = \"/absolute/unpublished\" }",
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
        metadata.build_scripts.insert("build-risk".to_owned());
        metadata.proc_macros.insert("macro-risk".to_owned());
        let report = report_for_fixture(&workspace, Some(&metadata));
        assert_error(&report, "constellation feature closure drift");
        assert_error(&report, "constellation build-script inventory drift");
        assert_error(&report, "constellation proc-macro inventory drift");

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
            r#"{"packages":[{"name":"asupersync","targets":[{"kind":["lib"]},{"kind":["custom-build"]}]},{"name":"derive-risk","targets":[{"kind":["proc-macro"]}]}],"resolve":{"nodes":[{"id":"registry+https://index#asupersync@0.4.9","features":["lab","net"]}]}}"#,
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
}
