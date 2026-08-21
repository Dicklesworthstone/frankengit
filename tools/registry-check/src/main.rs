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

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("[patch") || line.starts_with("[replace") {
                report.error(format!(
                    "manifest {display} declares a [patch]/[replace] section, which bypasses the closed dependency universe"
                ));
            }
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
        if name == OsStr::new(".git") || name == OsStr::new("target") {
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
