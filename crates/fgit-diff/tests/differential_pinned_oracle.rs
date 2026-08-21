#![forbid(unsafe_code)]
//! E3 corpus consumer for `scripts/e2e/suites/diff/merge_differential.sh`.
//!
//! The shell suite is the only caller of the separately pinned upstream-Git
//! oracle. This ignored Rust test only consumes byte-preserved corpus files and
//! exercises the public pure-Rust `fgit-diff` surface.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fmt::{self, Display, Formatter},
    fs,
    path::{Component, Path, PathBuf},
};

use fgit_diff::{
    CommitGraph, ContentMergeOptions, ContentMergeOutcome, DiffError, DiffLimits, DiffOptions,
    DiffProfile, MergeBaseError, MergeBaseLimits, MergeBaseResult, ParentSet, SequenceGranularity,
    TreeDiffError, TreeDiffOptions, TreeEntry, TreeMode, VirtualBaseProfile, diff, diff_trees,
    merge_bases_all, merge_content, merge_content_many,
};

const CORPUS_ENV: &str = "FGIT_DIFF_DIFFERENTIAL_CORPUS";
const ARTIFACT_ENV: &str = "FGIT_DIFF_DIFFERENTIAL_ARTIFACT_DIR";
const CORPUS_SCHEMA: &str = "frankengit.diff-merge-differential-corpus.v1";
const DIFF_DENOMINATOR: usize = 6;
const MERGE_DENOMINATOR: usize = 6;
const MERGE_BASE_DENOMINATOR: usize = 2;
const DETERMINISM_REPETITIONS: usize = 2;

#[derive(Debug)]
struct DifferentialError {
    detail: String,
}

impl DifferentialError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl Display for DifferentialError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for DifferentialError {}

#[derive(Clone, Debug)]
struct DiffCase {
    label: String,
    old: PathBuf,
    new: PathBuf,
    git_minimal_patch: PathBuf,
    git_histogram_patch: PathBuf,
}

#[derive(Clone, Debug)]
struct MergeCase {
    label: String,
    expected_exit: u8,
    base: PathBuf,
    ours: PathBuf,
    theirs: PathBuf,
    git_output: PathBuf,
}

#[derive(Clone, Debug)]
struct MergeBaseQuery {
    label: String,
    left: String,
    right: String,
    git_output: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct CorpusGraph {
    parents: BTreeMap<String, ParentSet<String>>,
}

impl CommitGraph for CorpusGraph {
    type CommitId = String;
    type Error = String;

    fn parents_of(
        &self,
        commit: &Self::CommitId,
    ) -> Result<ParentSet<Self::CommitId>, Self::Error> {
        self.parents
            .get(commit)
            .cloned()
            .ok_or_else(|| format!("corpus graph lacks commit {commit}"))
    }
}

fn required_directory(variable: &str) -> Result<PathBuf, DifferentialError> {
    let value = env::var_os(variable).ok_or_else(|| {
        DifferentialError::new(format!("missing required environment {variable}"))
    })?;
    let path = PathBuf::from(value);
    if path.is_dir() {
        Ok(path)
    } else {
        Err(DifferentialError::new(format!(
            "{variable} is not a directory: {}",
            path.display()
        )))
    }
}

fn is_safe_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn corpus_file(corpus: &Path, relative: &str) -> Result<PathBuf, DifferentialError> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(DifferentialError::new(format!(
            "corpus path escapes its root: {relative}"
        )));
    }
    let path = corpus.join(relative_path);
    if path.is_file() {
        Ok(path)
    } else {
        Err(DifferentialError::new(format!(
            "corpus file is missing: {}",
            path.display()
        )))
    }
}

fn manifest_rows(
    path: &Path,
    expected_fields: usize,
) -> Result<Vec<Vec<String>>, DifferentialError> {
    let text = fs::read_to_string(path).map_err(|error| {
        DifferentialError::new(format!("cannot read manifest {}: {error}", path.display()))
    })?;
    let mut rows = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<String> = line.split('\t').map(ToOwned::to_owned).collect();
        if fields.len() != expected_fields || fields.iter().any(String::is_empty) {
            return Err(DifferentialError::new(format!(
                "{}:{} has {} fields; expected {expected_fields} nonempty fields",
                path.display(),
                line_number + 1,
                fields.len()
            )));
        }
        rows.push(fields);
    }
    if rows.is_empty() {
        Err(DifferentialError::new(format!(
            "manifest {} has no data rows",
            path.display()
        )))
    } else {
        Ok(rows)
    }
}

fn receipt_value(receipt: &str, key: &str) -> Result<String, DifferentialError> {
    receipt
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(ToOwned::to_owned)
        .ok_or_else(|| DifferentialError::new(format!("corpus receipt lacks {key}")))
}

fn parse_denominator(receipt: &str, key: &str, expected: usize) -> Result<(), DifferentialError> {
    let actual = receipt_value(receipt, key)?
        .parse::<usize>()
        .map_err(|error| {
            DifferentialError::new(format!("corpus receipt has invalid {key}: {error}"))
        })?;
    if actual == expected {
        Ok(())
    } else {
        Err(DifferentialError::new(format!(
            "corpus receipt {key}={actual}, expected {expected}"
        )))
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control.is_control() => {
                escaped.push_str("\\u");
                let code = u32::from(control);
                for shift in [12, 8, 4, 0] {
                    let nibble = (code >> shift) & 0x0f;
                    let digit = if nibble < 10 {
                        char::from_u32(u32::from(b'0') + nibble)
                    } else {
                        char::from_u32(u32::from(b'a') + (nibble - 10))
                    };
                    if let Some(digit) = digit {
                        escaped.push(digit);
                    }
                }
            }
            ordinary => escaped.push(ordinary),
        }
    }
    escaped
}

fn write_finding(
    artifact_directory: &Path,
    kind: &str,
    label: &str,
    files: &[(&str, &[u8])],
    detail: impl Into<String>,
) -> Result<DifferentialError, DifferentialError> {
    if !is_safe_token(kind) || !is_safe_token(label) {
        return Err(DifferentialError::new(
            "refusing to write a finding with an unsafe kind or label",
        ));
    }
    let finding_directory = artifact_directory.join(format!("finding-{label}"));
    fs::create_dir_all(&finding_directory).map_err(|error| {
        DifferentialError::new(format!(
            "cannot create finding directory {}: {error}",
            finding_directory.display()
        ))
    })?;
    for (name, bytes) in files {
        if !is_safe_token(name) {
            return Err(DifferentialError::new(
                "refusing an unsafe finding file name",
            ));
        }
        fs::write(finding_directory.join(name), bytes).map_err(|error| {
            DifferentialError::new(format!("cannot preserve finding bytes {name}: {error}"))
        })?;
    }
    let detail = detail.into();
    let finding = format!(
        "{{\"schema\":\"frankengit.diff-merge-finding.v1\",\"kind\":\"{kind}\",\"label\":\"{label}\",\"detail\":\"{}\"}}\n",
        json_escape(&detail)
    );
    fs::write(finding_directory.join("finding.ndjson"), finding)
        .map_err(|error| DifferentialError::new(format!("cannot write typed finding: {error}")))?;
    Ok(DifferentialError::new(format!(
        "FG-044C-DIFFERENTIAL-FINDING {kind} for {label}: {detail}"
    )))
}

const fn diff_limits() -> DiffLimits {
    DiffLimits {
        max_input_bytes: 64 * 1024 * 1024,
        max_units: 2_000_000,
        max_work: 100_000_000,
        max_trace_cells: 8_000_000,
    }
}

const fn diff_options(profile: DiffProfile) -> DiffOptions {
    DiffOptions {
        profile,
        granularity: SequenceGranularity::Lines,
        limits: diff_limits(),
    }
}

const fn profile_name(profile: DiffProfile) -> &'static str {
    match profile {
        DiffProfile::MyersMinimal => "myers",
        DiffProfile::Patience => "patience",
        DiffProfile::Histogram => "histogram",
    }
}

fn load_diff_cases(corpus: &Path) -> Result<Vec<DiffCase>, DifferentialError> {
    let rows = manifest_rows(&corpus.join("diff-manifest.tsv"), 5)?;
    rows.into_iter()
        .map(|row| {
            if !is_safe_token(&row[0]) {
                return Err(DifferentialError::new(
                    "diff manifest has unsafe case label",
                ));
            }
            Ok(DiffCase {
                label: row[0].clone(),
                old: corpus_file(corpus, &row[1])?,
                new: corpus_file(corpus, &row[2])?,
                git_minimal_patch: corpus_file(corpus, &row[3])?,
                git_histogram_patch: corpus_file(corpus, &row[4])?,
            })
        })
        .collect()
}

fn run_diff_cases(corpus: &Path, artifact_directory: &Path) -> Result<usize, DifferentialError> {
    let cases = load_diff_cases(corpus)?;
    if cases.len() != DIFF_DENOMINATOR {
        return Err(DifferentialError::new(format!(
            "diff manifest denominator is {}, expected {DIFF_DENOMINATOR}",
            cases.len()
        )));
    }
    for case in &cases {
        let old = fs::read(&case.old).map_err(|error| DifferentialError::new(error.to_string()))?;
        let new = fs::read(&case.new).map_err(|error| DifferentialError::new(error.to_string()))?;
        let minimal_patch = fs::read(&case.git_minimal_patch)
            .map_err(|error| DifferentialError::new(error.to_string()))?;
        let histogram_patch = fs::read(&case.git_histogram_patch)
            .map_err(|error| DifferentialError::new(error.to_string()))?;
        if minimal_patch.is_empty() || histogram_patch.is_empty() {
            return Err(write_finding(
                artifact_directory,
                "oracle_patch_missing",
                &case.label,
                &[("old.bin", &old), ("new.bin", &new)],
                "the declared changed pair lacks a retained upstream patch",
            )?);
        }
        for profile in [
            DiffProfile::MyersMinimal,
            DiffProfile::Patience,
            DiffProfile::Histogram,
        ] {
            let profile_label = profile_name(profile);
            let first = match diff(&old, &new, diff_options(profile)) {
                Ok(result) => result,
                Err(error) => {
                    return Err(write_finding(
                        artifact_directory,
                        "diff_refusal",
                        &format!("{}-{profile_label}", case.label),
                        &[("old.bin", &old), ("new.bin", &new)],
                        format!("owned diff refused declared corpus input: {error:?}"),
                    )?);
                }
            };
            let second = match diff(&old, &new, diff_options(profile)) {
                Ok(result) => result,
                Err(error) => {
                    return Err(write_finding(
                        artifact_directory,
                        "diff_second_refusal",
                        &format!("{}-{profile_label}", case.label),
                        &[("old.bin", &old), ("new.bin", &new)],
                        format!("second owned diff refused declared corpus input: {error:?}"),
                    )?);
                }
            };
            if first != second {
                return Err(write_finding(
                    artifact_directory,
                    "diff_nondeterministic",
                    &format!("{}-{profile_label}", case.label),
                    &[("old.bin", &old), ("new.bin", &new)],
                    "two identical profile calls produced different edit scripts",
                )?);
            }
            let applied = match first.apply_to(&old) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Err(write_finding(
                        artifact_directory,
                        "diff_malformed_script",
                        &format!("{}-{profile_label}", case.label),
                        &[("old.bin", &old), ("new.bin", &new)],
                        format!("owned edit script cannot replay: {error:?}"),
                    )?);
                }
            };
            if applied != new {
                return Err(write_finding(
                    artifact_directory,
                    "diff_target_mismatch",
                    &format!("{}-{profile_label}", case.label),
                    &[
                        ("old.bin", &old),
                        ("new.bin", &new),
                        ("fgit-output.bin", &applied),
                    ],
                    "applying the owned edit script did not reproduce the target bytes",
                )?);
            }
        }
    }
    Ok(cases.len())
}

fn load_merge_cases(corpus: &Path) -> Result<Vec<MergeCase>, DifferentialError> {
    let rows = manifest_rows(&corpus.join("merge-manifest.tsv"), 6)?;
    rows.into_iter()
        .map(|row| {
            let expected_exit = row[1].parse::<u8>().map_err(|error| {
                DifferentialError::new(format!("merge manifest has invalid expected exit: {error}"))
            })?;
            if !is_safe_token(&row[0]) || !matches!(expected_exit, 0 | 1) {
                return Err(DifferentialError::new(
                    "merge manifest has an unsafe label or unsupported expected exit",
                ));
            }
            Ok(MergeCase {
                label: row[0].clone(),
                expected_exit,
                base: corpus_file(corpus, &row[2])?,
                ours: corpus_file(corpus, &row[3])?,
                theirs: corpus_file(corpus, &row[4])?,
                git_output: corpus_file(corpus, &row[5])?,
            })
        })
        .collect()
}

fn run_merge_cases(corpus: &Path, artifact_directory: &Path) -> Result<usize, DifferentialError> {
    let cases = load_merge_cases(corpus)?;
    if cases.len() != MERGE_DENOMINATOR {
        return Err(DifferentialError::new(format!(
            "merge manifest denominator is {}, expected {MERGE_DENOMINATOR}",
            cases.len()
        )));
    }
    for case in &cases {
        let base =
            fs::read(&case.base).map_err(|error| DifferentialError::new(error.to_string()))?;
        let ours =
            fs::read(&case.ours).map_err(|error| DifferentialError::new(error.to_string()))?;
        let theirs =
            fs::read(&case.theirs).map_err(|error| DifferentialError::new(error.to_string()))?;
        let git_output = fs::read(&case.git_output)
            .map_err(|error| DifferentialError::new(error.to_string()))?;
        let first = match merge_content(&base, &ours, &theirs, ContentMergeOptions::default()) {
            Ok(result) => result,
            Err(error) => {
                return Err(write_finding(
                    artifact_directory,
                    "merge_refusal",
                    &case.label,
                    &[
                        ("base.bin", &base),
                        ("ours.bin", &ours),
                        ("theirs.bin", &theirs),
                    ],
                    format!("owned merge refused declared corpus input: {error:?}"),
                )?);
            }
        };
        let second = match merge_content(&base, &ours, &theirs, ContentMergeOptions::default()) {
            Ok(result) => result,
            Err(error) => {
                return Err(write_finding(
                    artifact_directory,
                    "merge_second_refusal",
                    &case.label,
                    &[
                        ("base.bin", &base),
                        ("ours.bin", &ours),
                        ("theirs.bin", &theirs),
                    ],
                    format!("second owned merge refused declared corpus input: {error:?}"),
                )?);
            }
        };
        if first != second {
            return Err(write_finding(
                artifact_directory,
                "merge_nondeterministic",
                &case.label,
                &[
                    ("base.bin", &base),
                    ("ours.bin", &ours),
                    ("theirs.bin", &theirs),
                ],
                "two identical merge calls produced different results",
            )?);
        }
        match (&first.outcome, case.expected_exit) {
            (ContentMergeOutcome::Clean { bytes }, 0) if bytes == &git_output => {}
            (ContentMergeOutcome::Clean { bytes }, 0) => {
                return Err(write_finding(
                    artifact_directory,
                    "clean_merge_mismatch",
                    &case.label,
                    &[
                        ("base.bin", &base),
                        ("ours.bin", &ours),
                        ("theirs.bin", &theirs),
                        ("git-output.bin", &git_output),
                        ("fgit-output.bin", bytes),
                    ],
                    "a clean owned merge differs byte-for-byte from pinned git merge-file",
                )?);
            }
            (ContentMergeOutcome::Conflicted { conflicts, .. }, 1) => {
                let has_all_sides = conflicts.iter().all(|conflict| {
                    !conflict.base.bytes.is_empty()
                        && !conflict.ours.bytes.is_empty()
                        && !conflict.theirs.bytes.is_empty()
                        && base
                            .windows(conflict.base.bytes.len())
                            .any(|span| span == conflict.base.bytes)
                        && ours
                            .windows(conflict.ours.bytes.len())
                            .any(|span| span == conflict.ours.bytes)
                        && theirs
                            .windows(conflict.theirs.bytes.len())
                            .any(|span| span == conflict.theirs.bytes)
                });
                if conflicts.is_empty()
                    || !has_all_sides
                    || !git_output.windows(7).any(|span| span == b"<<<<<<<")
                {
                    return Err(write_finding(
                        artifact_directory,
                        "conflict_evidence_lost",
                        &case.label,
                        &[
                            ("base.bin", &base),
                            ("ours.bin", &ours),
                            ("theirs.bin", &theirs),
                            ("git-output.bin", &git_output),
                            ("fgit-output.bin", first.outcome.proposed_bytes()),
                        ],
                        "conflict classification failed to preserve each original side",
                    )?);
                }
            }
            (ContentMergeOutcome::Clean { bytes }, 1) => {
                return Err(write_finding(
                    artifact_directory,
                    "missing_conflict",
                    &case.label,
                    &[
                        ("base.bin", &base),
                        ("ours.bin", &ours),
                        ("theirs.bin", &theirs),
                        ("fgit-output.bin", bytes),
                    ],
                    "pinned git reported a conflict but the owned merge returned clean bytes",
                )?);
            }
            (ContentMergeOutcome::Conflicted { .. }, 0) => {
                return Err(write_finding(
                    artifact_directory,
                    "unexpected_conflict",
                    &case.label,
                    &[
                        ("base.bin", &base),
                        ("ours.bin", &ours),
                        ("theirs.bin", &theirs),
                        ("git-output.bin", &git_output),
                    ],
                    "pinned git reported a clean merge but the owned merge conflicted",
                )?);
            }
            (_, unexpected_exit) => {
                return Err(DifferentialError::new(format!(
                    "unsupported merge expected exit {unexpected_exit}"
                )));
            }
        }
    }
    Ok(cases.len())
}

fn load_graph(corpus: &Path) -> Result<CorpusGraph, DifferentialError> {
    let rows = manifest_rows(&corpus.join("merge-base/graph.tsv"), 3)?;
    let mut graph = CorpusGraph::default();
    for row in rows {
        if !is_safe_token(&row[0]) || !is_sha1(&row[1]) || graph.parents.contains_key(&row[1]) {
            return Err(DifferentialError::new(
                "graph manifest has invalid or duplicate commit data",
            ));
        }
        let parents = if row[2] == "-" {
            Vec::new()
        } else {
            let parents: Vec<String> = row[2].split(',').map(ToOwned::to_owned).collect();
            if parents.iter().any(|parent| !is_sha1(parent)) {
                return Err(DifferentialError::new(
                    "graph manifest has an invalid parent OID",
                ));
            }
            parents
        };
        graph
            .parents
            .insert(row[1].clone(), ParentSet::Complete(parents));
    }
    for parents in graph.parents.values() {
        let ParentSet::Complete(parents) = parents else {
            return Err(DifferentialError::new(
                "corpus graph unexpectedly contains a shallow edge",
            ));
        };
        if parents
            .iter()
            .any(|parent| !graph.parents.contains_key(parent))
        {
            return Err(DifferentialError::new(
                "graph manifest parent is outside graph closure",
            ));
        }
    }
    Ok(graph)
}

fn load_merge_base_queries(corpus: &Path) -> Result<Vec<MergeBaseQuery>, DifferentialError> {
    let rows = manifest_rows(&corpus.join("merge-base/query-manifest.tsv"), 4)?;
    rows.into_iter()
        .map(|row| {
            if !is_safe_token(&row[0]) || !is_sha1(&row[1]) || !is_sha1(&row[2]) {
                return Err(DifferentialError::new(
                    "merge-base query manifest has invalid identifiers",
                ));
            }
            Ok(MergeBaseQuery {
                label: row[0].clone(),
                left: row[1].clone(),
                right: row[2].clone(),
                git_output: corpus_file(corpus, &row[3])?,
            })
        })
        .collect()
}

fn output_oid_set(path: &Path) -> Result<BTreeSet<String>, DifferentialError> {
    let output = fs::read_to_string(path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", path.display()))
    })?;
    let oids: BTreeSet<String> = output.lines().map(ToOwned::to_owned).collect();
    if oids.is_empty() || oids.iter().any(|oid| !is_sha1(oid)) {
        return Err(DifferentialError::new(format!(
            "pinned Git merge-base output is malformed: {}",
            path.display()
        )));
    }
    Ok(oids)
}

fn run_merge_base_cases(
    corpus: &Path,
    artifact_directory: &Path,
) -> Result<usize, DifferentialError> {
    let graph = load_graph(corpus)?;
    let queries = load_merge_base_queries(corpus)?;
    if queries.len() != MERGE_BASE_DENOMINATOR {
        return Err(DifferentialError::new(format!(
            "merge-base query denominator is {}, expected {MERGE_BASE_DENOMINATOR}",
            queries.len()
        )));
    }
    for query in &queries {
        let expected = output_oid_set(&query.git_output)?;
        let result = merge_bases_all(
            &graph,
            query.left.clone(),
            query.right.clone(),
            MergeBaseLimits::default(),
        )
        .map_err(|error| {
            DifferentialError::new(format!("owned merge-base refused corpus: {error:?}"))
        })?;
        let MergeBaseResult::Bases(actual) = result else {
            return Err(DifferentialError::new(
                "owned merge-base returned no common ancestor",
            ));
        };
        let actual_set: BTreeSet<String> = actual.iter().cloned().collect();
        if actual.len() != actual_set.len() || actual.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(DifferentialError::new(
                "owned merge-base violated its ascending deterministic ID order",
            ));
        }
        if actual_set != expected {
            let expected_bytes = expected.iter().cloned().collect::<Vec<_>>().join("\n");
            let actual_bytes = actual.join("\n");
            return Err(write_finding(
                artifact_directory,
                "merge_base_set_mismatch",
                &query.label,
                &[
                    ("git-output.txt", expected_bytes.as_bytes()),
                    ("fgit-output.txt", actual_bytes.as_bytes()),
                ],
                "owned merge-base set differs from the pinned Git --all set",
            )?);
        }
        if query.label == "criss-cross" {
            let wrong_base = graph
                .parents
                .iter()
                .find_map(|(oid, parents)| {
                    matches!(parents, ParentSet::Complete(values) if values.is_empty())
                        .then_some(oid.clone())
                })
                .ok_or_else(|| {
                    DifferentialError::new(
                        "criss-cross graph has no root for planted wrong-base detection",
                    )
                })?;
            if actual_set == BTreeSet::from([wrong_base]) {
                return Err(DifferentialError::new(
                    "planted wrong merge base was not detected by the criss-cross comparison",
                ));
            }
        }
    }
    Ok(queries.len())
}

fn validate_adversarial_refusals() -> Result<usize, DifferentialError> {
    let work_limited = diff(
        b"old\n",
        b"new\n",
        DiffOptions {
            limits: DiffLimits {
                max_work: 0,
                ..diff_limits()
            },
            ..diff_options(DiffProfile::MyersMinimal)
        },
    );
    if !matches!(work_limited, Err(DiffError::WorkExceeded { limit: 0 })) {
        return Err(DifferentialError::new(
            "planted unbounded diff scan did not produce WorkExceeded",
        ));
    }
    let unordered = diff_trees(
        vec![
            TreeEntry {
                path: b"z".to_vec(),
                mode: TreeMode(0o100_644),
                object: 1_u8,
            },
            TreeEntry {
                path: b"a".to_vec(),
                mode: TreeMode(0o100_644),
                object: 2_u8,
            },
        ],
        Vec::<TreeEntry<u8>>::new(),
        TreeDiffOptions::default(),
    );
    if !matches!(unordered, Err(TreeDiffError::UnsortedOrDuplicatePath)) {
        return Err(DifferentialError::new(
            "planted nondeterministic tree path order was not refused",
        ));
    }
    let mut shallow = CorpusGraph::default();
    shallow
        .parents
        .insert("base".to_owned(), ParentSet::ShallowBoundary);
    shallow.parents.insert(
        "tip".to_owned(),
        ParentSet::Complete(vec!["base".to_owned()]),
    );
    let shallow_result = merge_bases_all(
        &shallow,
        "tip".to_owned(),
        "base".to_owned(),
        MergeBaseLimits::default(),
    );
    if !matches!(shallow_result, Err(MergeBaseError::ShallowBoundary { .. })) {
        return Err(DifferentialError::new(
            "planted shallow boundary silently fell back to a merge base",
        ));
    }
    let conflict = merge_content(
        b"base\n",
        b"ours\n",
        b"theirs\n",
        ContentMergeOptions::default(),
    )
    .map_err(|error| DifferentialError::new(format!("conflict setup refused: {error:?}")))?;
    let ContentMergeOutcome::Conflicted { conflicts, .. } = conflict.outcome else {
        return Err(DifferentialError::new(
            "planted conflicting edits produced an unclassified clean merge",
        ));
    };
    if conflicts.len() != 1
        || conflicts[0].base.bytes != b"base\n"
        || conflicts[0].ours.bytes != b"ours\n"
        || conflicts[0].theirs.bytes != b"theirs\n"
    {
        return Err(DifferentialError::new(
            "planted conflict lost a source side or exact side bytes",
        ));
    }
    let recursive = merge_content_many(
        &[b"base-a\n", b"base-b\n"],
        b"ours\n",
        b"theirs\n",
        ContentMergeOptions {
            profile: fgit_diff::MergeProfile {
                virtual_base: VirtualBaseProfile::RecursiveConflictPreservingV1,
                ..fgit_diff::MergeProfile::default()
            },
            ..ContentMergeOptions::default()
        },
    )
    .map_err(|error| {
        DifferentialError::new(format!("recursive virtual base refused: {error:?}"))
    })?;
    if !matches!(recursive.outcome, ContentMergeOutcome::Conflicted { .. }) {
        return Err(DifferentialError::new(
            "multi-base recursive profile silently selected one divergent ancestor",
        ));
    }
    Ok(5)
}

fn write_success_receipt(
    artifact_directory: &Path,
    diff_cases: usize,
    merge_cases: usize,
    merge_base_cases: usize,
    refusal_cases: usize,
) -> Result<(), DifferentialError> {
    let receipt = format!(
        "{{\"schema\":\"frankengit.diff-merge-differential-verdict.v1\",\"oracle_pin\":\"git-2.54.0\",\"diff_case_denominator\":{diff_cases},\"merge_case_denominator\":{merge_cases},\"merge_base_case_denominator\":{merge_base_cases},\"determinism_repetitions\":{DETERMINISM_REPETITIONS},\"resource_refusal_cells\":{refusal_cases},\"semantically_equal_declared\":[\"FG-044C-HISTOGRAM-PROFILE-V1\",\"FG-044C-MERGEBASE-ORDER-V1\",\"FG-044C-CRISSCROSS-VIRTUALBASE-V1\"],\"non_claim\":\"finite E3 corpus evidence; not full Git diff, merge-base, or merge compatibility\"}}\n"
    );
    fs::write(artifact_directory.join("verdict.ndjson"), receipt).map_err(|error| {
        DifferentialError::new(format!(
            "cannot write differential verdict receipt: {error}"
        ))
    })
}

#[test]
#[ignore = "requires the pinned shell oracle corpus from merge_differential.sh"]
fn pinned_oracle_diff_merge_and_refusal_corpus() -> Result<(), DifferentialError> {
    let corpus = required_directory(CORPUS_ENV)?;
    let artifact_directory = required_directory(ARTIFACT_ENV)?;
    let receipt = fs::read_to_string(corpus.join("receipt.tsv"))
        .map_err(|error| DifferentialError::new(format!("cannot read corpus receipt: {error}")))?;
    if receipt_value(&receipt, "schema")? != CORPUS_SCHEMA {
        return Err(DifferentialError::new(
            "unsupported differential corpus schema",
        ));
    }
    if receipt_value(&receipt, "pin_id")? != "git-2.54.0" {
        return Err(DifferentialError::new(
            "corpus pin is not the declared Git 2.54.0 oracle",
        ));
    }
    parse_denominator(&receipt, "diff_case_denominator", DIFF_DENOMINATOR)?;
    parse_denominator(&receipt, "merge_case_denominator", MERGE_DENOMINATOR)?;
    parse_denominator(
        &receipt,
        "merge_base_case_denominator",
        MERGE_BASE_DENOMINATOR,
    )?;
    let diff_cases = run_diff_cases(&corpus, &artifact_directory)?;
    let merge_cases = run_merge_cases(&corpus, &artifact_directory)?;
    let merge_base_cases = run_merge_base_cases(&corpus, &artifact_directory)?;
    let refusal_cases = validate_adversarial_refusals()?;
    write_success_receipt(
        &artifact_directory,
        diff_cases,
        merge_cases,
        merge_base_cases,
        refusal_cases,
    )
}
