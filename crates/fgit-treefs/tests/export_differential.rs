//! Differential export evidence for FG-026d.
//!
//! The FG-026c tests in `export.rs` check the exporter against my own reading of
//! Git's tree format. That is exactly the class of assertion that can be wrong in
//! the code and in the test at the same time, because one person wrote both. This
//! test removes that shared assumption: `scripts/e2e/suites/treefs/export_crash.sh`
//! builds each case with the pinned sandboxed Git oracle, dumps every object Git
//! itself wrote, and hands the corpus here through the environment. FrankenGit is
//! then given the same base objects and the same edit list and must arrive at the
//! same root tree identity and the same tree bytes.
//!
//! Kept `#[ignore]` so ordinary `cargo test -p fgit-treefs` stays hermetic and
//! needs no oracle; the shell suite invokes it with `-- --ignored`.
//!
//! CLAIM CLASS. This is finite-corpus differential evidence, not a proof. A
//! passing corpus says these cases agree with the pinned Git on this platform. It
//! says nothing about inputs the corpus does not contain.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, parse_tree};
use fgit_treefs::base::{BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::export::{ExportLimits, ExportPlanner};
use fgit_treefs::overlay::{ContentRef, EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, GitOidSha1, RepositoryId};
use std::collections::BTreeMap;
use std::env;
use std::fmt::{self, Display, Formatter, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

type Oid = GitOid<Sha1>;

const CORPUS_ENV: &str = "FGIT_TREEFS_EXPORT_CORPUS";
const CORPUS_SCHEMA: &str = "frankengit.treefs-export-corpus.v1";

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

impl std::error::Error for DifferentialError {}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// corpus parsing
// ---------------------------------------------------------------------------

/// Git objects from the oracle, keyed by lowercase hex identity.
type GitObjects = BTreeMap<String, (GitObjectKind, Vec<u8>)>;

/// Parses Git's `cat-file --batch` framing: `<oid> SP <type> SP <size> LF <body> LF`.
///
/// Parsed here rather than in the shell generator on purpose. Tree bodies are
/// binary — every entry ends in a raw 20-byte object id that routinely contains
/// NUL and newline — so routing them through bash would have meant hex-laundering
/// each object and then trusting that round trip. Reading Git's own framing keeps
/// the oracle's bytes untouched all the way to the comparison.
fn parse_batch(bytes: &[u8]) -> Result<GitObjects, DifferentialError> {
    let mut objects = GitObjects::new();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let line_end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| DifferentialError::new("batch header without a terminating newline"))?
            + cursor;
        let header = &bytes[cursor..line_end];
        cursor = line_end + 1;

        if header.is_empty() {
            continue;
        }

        let text = std::str::from_utf8(header)
            .map_err(|_| DifferentialError::new("batch header is not UTF-8"))?;
        let mut fields = text.split(' ');
        let oid_hex = fields
            .next()
            .ok_or_else(|| DifferentialError::new("batch header has no object id"))?;
        let kind_text = fields
            .next()
            .ok_or_else(|| DifferentialError::new("batch header has no type"))?;

        // `missing` and `ambiguous` responses carry no body; treating them as
        // zero-length objects would silently insert an empty blob.
        if kind_text == "missing" || kind_text == "ambiguous" {
            continue;
        }

        let size_text = fields
            .next()
            .ok_or_else(|| DifferentialError::new("batch header has no size"))?;
        let size: usize = size_text
            .parse()
            .map_err(|_| DifferentialError::new(format!("unparsable batch size {size_text:?}")))?;
        if cursor + size > bytes.len() {
            return Err(DifferentialError::new(format!(
                "batch body for {oid_hex} claims {size} bytes but only {} remain",
                bytes.len() - cursor
            )));
        }
        let body = bytes[cursor..cursor + size].to_vec();
        cursor += size;
        if cursor < bytes.len() && bytes[cursor] == b'\n' {
            cursor += 1;
        }

        let kind = match kind_text {
            "blob" => GitObjectKind::Blob,
            "tree" => GitObjectKind::Tree,
            // Commits and tags may exist in the corpus repository. They are not
            // part of a tree export, so they are skipped, not refused.
            _ => continue,
        };

        objects.insert(oid_hex.to_ascii_lowercase(), (kind, body));
    }

    Ok(objects)
}

fn tsv_value(text: &str, key: &str) -> Result<String, DifferentialError> {
    for line in text.lines() {
        if let Some((found, value)) = line.split_once('\t')
            && found == key
        {
            return Ok(value.trim().to_owned());
        }
    }
    Err(DifferentialError::new(format!("missing corpus key {key}")))
}

// ---------------------------------------------------------------------------
// object source backed by the oracle's own bytes
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct OracleSource {
    objects: BTreeMap<String, Vec<u8>>,
}

impl ObjectSource<Sha1> for OracleSource {
    fn read_object(
        &self,
        oid: &Oid,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        let key = hex(oid.digest_bytes());
        self.objects
            .get(&key)
            .cloned()
            .ok_or(ObjectSourceError::NotFound { oid_hex: key })
    }
}

// ---------------------------------------------------------------------------
// capability derivation
// ---------------------------------------------------------------------------

/// Every path the base tree contains, files and directories alike.
///
/// The capability has to be derived rather than hard-coded. An empty read-prefix
/// list authorises nothing by design (capability.rs), so the `untouched` case —
/// which has no edits at all — would otherwise be handed a capability that
/// refuses the export, and the differential would "fail" for a reason that has
/// nothing to do with Git agreement.
fn collect_base_paths(
    objects: &GitObjects,
    root_hex: &str,
    prefix: &[u8],
    limits: &ParseLimits,
    out: &mut Vec<TreePath>,
) -> Result<(), DifferentialError> {
    let Some((kind, body)) = objects.get(root_hex) else {
        return Err(DifferentialError::new(format!(
            "base tree {root_hex} is absent from the oracle object dump"
        )));
    };
    if *kind != GitObjectKind::Tree {
        return Err(DifferentialError::new(format!("{root_hex} is not a tree")));
    }

    let entries = parse_tree(body, AcceptanceProfile::GitCompatibleImport, limits)
        .map_err(|refusal| DifferentialError::new(format!("base tree {root_hex}: {refusal:?}")))?;

    for entry in entries {
        let mut path_bytes = prefix.to_vec();
        if !path_bytes.is_empty() {
            path_bytes.push(b'/');
        }
        path_bytes.extend_from_slice(&entry.name);

        if let Ok(path) = TreePath::parse_default(&path_bytes) {
            out.push(path);
        }

        if entry.mode == b"40000" || entry.mode == b"040000" {
            let child = hex(&entry.object_id);
            collect_base_paths(objects, &child, &path_bytes, limits, out)?;
        }
    }
    Ok(())
}

/// Adds a path and every ancestor of it, so a nested add is not refused before
/// it reaches the exporter.
fn push_with_ancestors(out: &mut Vec<TreePath>, rel: &str) {
    let mut prefix: Vec<u8> = Vec::new();
    for component in rel.split('/').filter(|part| !part.is_empty()) {
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(component.as_bytes());
        if let Ok(path) = TreePath::parse_default(&prefix) {
            out.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// case execution
// ---------------------------------------------------------------------------

fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([7; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[9_u8; 32]).expect("fixture digest is a legal width"),
    )
}

/// Applies the case's edit list to the overlay.
///
/// Format mirrors the shell generator: `path:mode:content`, and `path:DELETE:`
/// for a removal.
fn apply_edits(
    overlay: &mut Overlay,
    paths: &mut Vec<TreePath>,
    edits: &str,
) -> Result<(), DifferentialError> {
    for raw in edits.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let (rel, rest) = line
            .split_once(':')
            .ok_or_else(|| DifferentialError::new(format!("unparsable edit {line:?}")))?;
        let (mode, content) = rest
            .split_once(':')
            .ok_or_else(|| DifferentialError::new(format!("unparsable edit {line:?}")))?;

        let path = TreePath::parse_default(rel.as_bytes())
            .map_err(|refusal| DifferentialError::new(format!("edit path {rel:?}: {refusal:?}")))?;
        push_with_ancestors(paths, rel);

        if mode == "DELETE" {
            // An absent overlay entry means "consult the base"; a delete has to
            // be the explicit marker or the base entry survives the export.
            overlay.put(path, OverlayEntry::Whiteout);
            continue;
        }

        // The shell generator writes each file with `printf '%s\n'`, so the blob
        // Git hashed ends in a newline. Reproduce that exactly or every content
        // identity differs by one byte and the whole corpus fails for a reason
        // that has nothing to do with tree encoding.
        let mut body = content.as_bytes().to_vec();
        body.push(b'\n');
        let interned = overlay.intern(body);
        let file_mode = match mode {
            "100644" => FileMode::Regular,
            "100755" => FileMode::Executable,
            other => {
                return Err(DifferentialError::new(format!(
                    "edit mode {other:?} is not covered by this corpus"
                )));
            }
        };
        overlay.put(
            path,
            OverlayEntry::File {
                content: ContentRef::Overlay(interned),
                mode: file_mode,
                class: EntryClass::Content,
            },
        );
    }
    Ok(())
}

struct CaseOutcome {
    expected_root: String,
    actual_root: String,
    byte_divergences: Vec<String>,
    trees_compared: usize,
}

fn run_case(case_dir: &Path, name: &str) -> Result<CaseOutcome, DifferentialError> {
    let meta = fs::read_to_string(case_dir.join("meta.tsv"))
        .map_err(|error| DifferentialError::new(format!("{name}: meta.tsv: {error}")))?;
    let base_root_hex = tsv_value(&meta, "base_root")?.to_ascii_lowercase();
    let expected_root_hex = tsv_value(&meta, "expected_root")?.to_ascii_lowercase();

    let batch = fs::read(case_dir.join("objects.batch"))
        .map_err(|error| DifferentialError::new(format!("{name}: objects.batch: {error}")))?;
    let git_objects = parse_batch(&batch)?;

    let mut source = OracleSource::default();
    for (oid_hex, (_kind, body)) in &git_objects {
        source.objects.insert(oid_hex.clone(), body.clone());
    }

    let limits = ParseLimits::default();
    let base_root = GitOidSha1::from_hex(&base_root_hex).map_err(|refusal| {
        DifferentialError::new(format!("{name}: base root {base_root_hex}: {refusal:?}"))
    })?;

    let mut paths = Vec::new();
    collect_base_paths(&git_objects, &base_root_hex, b"", &limits, &mut paths)
        .map_err(|error| DifferentialError::new(format!("{name}: {}", error.detail)))?;

    let edits = fs::read_to_string(case_dir.join("edits.txt")).unwrap_or_default();
    let mut overlay = Overlay::new();
    apply_edits(&mut overlay, &mut paths, &edits)
        .map_err(|error| DifferentialError::new(format!("{name}: {}", error.detail)))?;

    if paths.is_empty() {
        return Err(DifferentialError::new(format!(
            "{name}: derived an empty capability, which authorises nothing"
        )));
    }

    let view = BaseView::new(
        repository_id(),
        rcr_id(),
        base_root,
        base_root,
        limits.clone(),
        PathPolicy::default(),
    );
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        paths.clone(),
        paths,
    );

    let planner = ExportPlanner::new(ExportLimits::default(), limits);
    let plan = planner
        .plan(&view, &source, &mut capability, &overlay, 0, &|| false)
        .map_err(|refusal| {
            DifferentialError::new(format!("{name}: export refused: {refusal:?}"))
        })?;

    // Byte comparison of every tree the plan emitted that Git also wrote.
    // Root-identity equality alone could be satisfied by two encoders that merely
    // agree on this input's final hash; comparing bodies makes the framing itself
    // the subject of the test.
    let mut byte_divergences = Vec::new();
    let mut trees_compared = 0usize;
    for object in plan.objects() {
        if object.kind() != GitObjectKind::Tree {
            continue;
        }
        let oid_hex = hex(object.oid().digest_bytes());
        if let Some((_kind, git_body)) = git_objects.get(&oid_hex) {
            trees_compared += 1;
            if git_body != object.body() {
                byte_divergences.push(format!(
                    "{name}: tree {oid_hex} shares Git's identity but not its bytes"
                ));
            }
        }
    }

    Ok(CaseOutcome {
        expected_root: expected_root_hex,
        actual_root: hex(plan.root_tree().digest_bytes()),
        byte_divergences,
        trees_compared,
    })
}

fn required_directory(variable: &str) -> Result<PathBuf, DifferentialError> {
    let value = env::var_os(variable).ok_or_else(|| {
        DifferentialError::new(format!("missing required environment {variable}"))
    })?;
    let path = PathBuf::from(value);
    if !path.is_dir() {
        return Err(DifferentialError::new(format!(
            "{variable} does not name a directory: {}",
            path.display()
        )));
    }
    Ok(path)
}

#[test]
#[ignore = "requires the pinned oracle corpus from scripts/e2e/suites/treefs/export_crash.sh"]
fn export_agrees_with_the_pinned_git_oracle() -> Result<(), DifferentialError> {
    let corpus = required_directory(CORPUS_ENV)?;

    let receipt = fs::read_to_string(corpus.join("receipt.tsv"))
        .map_err(|error| DifferentialError::new(format!("corpus receipt: {error}")))?;
    if tsv_value(&receipt, "schema")? != CORPUS_SCHEMA {
        return Err(DifferentialError::new(format!(
            "corpus schema is not {CORPUS_SCHEMA}"
        )));
    }
    let declared: usize = tsv_value(&receipt, "case_count")?
        .parse()
        .map_err(|_| DifferentialError::new("case_count is not a number"))?;

    let mut case_dirs: Vec<PathBuf> = fs::read_dir(corpus.join("cases"))
        .map_err(|error| DifferentialError::new(format!("corpus cases: {error}")))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    case_dirs.sort();

    // A corpus that lost cases between generation and consumption would
    // otherwise shrink the differential silently and still report success.
    if case_dirs.len() != declared {
        return Err(DifferentialError::new(format!(
            "corpus declares {declared} cases but {} are present",
            case_dirs.len()
        )));
    }
    if case_dirs.is_empty() {
        return Err(DifferentialError::new(
            "corpus is empty; a differential over zero cases proves nothing",
        ));
    }

    let mut failures = Vec::new();
    let mut total_trees = 0usize;
    for case_dir in &case_dirs {
        let name = case_dir
            .file_name()
            .and_then(|raw| raw.to_str())
            .unwrap_or("<unnamed>")
            .to_owned();
        match run_case(case_dir, &name) {
            Ok(outcome) => {
                total_trees += outcome.trees_compared;
                if outcome.expected_root != outcome.actual_root {
                    failures.push(format!(
                        "{name}: root tree mismatch — oracle {} vs frankengit {}",
                        outcome.expected_root, outcome.actual_root
                    ));
                }
                failures.extend(outcome.byte_divergences);
            }
            Err(error) => failures.push(error.detail),
        }
    }

    // A run where no tree body was ever compared would report success having
    // checked only root hashes. Say so rather than counting it as agreement.
    if total_trees == 0 {
        failures.push(
            "no exported tree shared an identity with the oracle, so no body was compared"
                .to_owned(),
        );
    }

    if failures.is_empty() {
        println!(
            "differential ok: {} cases, {total_trees} tree bodies byte-compared against the oracle",
            case_dirs.len()
        );
        Ok(())
    } else {
        Err(DifferentialError::new(failures.join("\n")))
    }
}
