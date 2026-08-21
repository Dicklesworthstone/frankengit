#![forbid(unsafe_code)]
//! E3 object differential test driven by the shell-only pinned-Git oracle.
//!
//! `scripts/e2e/suites/git-object/object_differential.sh` generates the
//! source-derived corpus, supplies its directory through the environment, and
//! invokes this ignored test. Keeping it ignored in ordinary crate tests is
//! intentional: an absent pinned oracle is an unavailable E3 run, never a
//! false local pass against ambient Git.

use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, Sha1, Sha256, emit_loose_framed,
    emit_object_body, native_object_oid, parse_loose_framed, parse_object_body,
};

const CORPUS_ENV: &str = "FGIT_OBJECT_DIFFERENTIAL_CORPUS";
const ARTIFACT_ENV: &str = "FGIT_OBJECT_DIFFERENTIAL_ARTIFACT_DIR";
const CORPUS_SCHEMA: &str = "frankengit.object-differential-corpus.v1";

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
struct CorpusEntry {
    label: String,
    object_type: ObjectType,
    native_oid: String,
    body_path: PathBuf,
}

#[derive(Clone, Copy, Debug)]
enum FindingKind {
    FramedParseRefusal,
    FramedReemitMismatch,
    BodyParseRefusal,
    BodyReemitMismatch,
    NativeOidMismatch,
    CorpusShapeMismatch,
}

impl FindingKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FramedParseRefusal => "framed_parse_refusal",
            Self::FramedReemitMismatch => "framed_reemit_mismatch",
            Self::BodyParseRefusal => "body_parse_refusal",
            Self::BodyReemitMismatch => "body_reemit_mismatch",
            Self::NativeOidMismatch => "native_oid_mismatch",
            Self::CorpusShapeMismatch => "corpus_shape_mismatch",
        }
    }
}

#[derive(Debug)]
struct VerificationFailure {
    kind: FindingKind,
    actual_bytes: Option<Vec<u8>>,
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

fn receipt_value(receipt: &str, key: &str) -> Result<String, DifferentialError> {
    receipt
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(ToOwned::to_owned)
        .ok_or_else(|| DifferentialError::new(format!("receipt lacks {key}")))
}

fn parse_object_type(label: &str) -> Result<ObjectType, DifferentialError> {
    ObjectType::from_label(label)
        .ok_or_else(|| DifferentialError::new(format!("unknown corpus object type {label}")))
}

fn parse_manifest(corpus: &Path) -> Result<Vec<CorpusEntry>, DifferentialError> {
    let manifest_path = corpus.join("manifest.tsv");
    let manifest = fs::read_to_string(&manifest_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", manifest_path.display()))
    })?;
    let mut entries = Vec::new();

    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let mut fields = line.split('\t');
        let label = fields
            .next()
            .ok_or_else(|| DifferentialError::new("manifest line lacks label"))?;
        let object_type = fields
            .next()
            .ok_or_else(|| DifferentialError::new("manifest line lacks object type"))?;
        let native_oid = fields
            .next()
            .ok_or_else(|| DifferentialError::new("manifest line lacks native OID"))?;
        let body_path = fields
            .next()
            .ok_or_else(|| DifferentialError::new("manifest line lacks body path"))?;
        if fields.next().is_some() {
            return Err(DifferentialError::new("manifest line has surplus fields"));
        }
        if label.is_empty() || native_oid.is_empty() || body_path.is_empty() {
            return Err(DifferentialError::new(
                "manifest line has an empty required field",
            ));
        }
        entries.push(CorpusEntry {
            label: label.to_owned(),
            object_type: parse_object_type(object_type)?,
            native_oid: native_oid.to_owned(),
            body_path: corpus.join(body_path),
        });
    }
    if entries.is_empty() {
        return Err(DifferentialError::new("manifest has no object entries"));
    }
    Ok(entries)
}

fn parse_denominator(corpus: &Path) -> Result<usize, DifferentialError> {
    let receipt_path = corpus.join("receipt.tsv");
    let receipt = fs::read_to_string(&receipt_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", receipt_path.display()))
    })?;
    if receipt_value(&receipt, "schema")? != CORPUS_SCHEMA {
        return Err(DifferentialError::new(
            "receipt has an unsupported corpus schema",
        ));
    }
    receipt_value(&receipt, "corpus_denominator")?
        .parse::<usize>()
        .map_err(|error| DifferentialError::new(format!("invalid corpus denominator: {error}")))
}

fn algorithm_limits(corpus: &Path) -> Result<(&'static str, ParseLimits), DifferentialError> {
    let receipt_path = corpus.join("receipt.tsv");
    let receipt = fs::read_to_string(&receipt_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", receipt_path.display()))
    })?;
    let algorithm = receipt_value(&receipt, "algorithm")?;
    let mut limits = ParseLimits::default();
    let label = match algorithm.as_str() {
        "sha1" => "sha1",
        "sha256" => {
            limits.tree_reference_bytes = 32;
            "sha256"
        }
        _ => {
            return Err(DifferentialError::new(format!(
                "unsupported corpus algorithm {algorithm}"
            )));
        }
    };
    Ok((label, limits))
}

fn verify_special_headers(
    entry: &CorpusEntry,
    parsed: &ParsedObject,
) -> Result<(), VerificationFailure> {
    if entry.label.ends_with("commit-headers") {
        let ParsedObject::Commit(commit) = parsed else {
            return Err(VerificationFailure {
                kind: FindingKind::CorpusShapeMismatch,
                actual_bytes: None,
            });
        };
        let parents = commit.parent_references().count();
        let header_names: Vec<&[u8]> = commit
            .headers()
            .iter()
            .map(|header| header.name.as_slice())
            .collect();
        if parents != 2
            || !header_names.contains(&b"mergetag".as_slice())
            || !header_names.contains(&b"gpgsig".as_slice())
            || !header_names.contains(&b"encoding".as_slice())
        {
            return Err(VerificationFailure {
                kind: FindingKind::CorpusShapeMismatch,
                actual_bytes: None,
            });
        }
    }
    if entry.label.ends_with("tag-signed") {
        let ParsedObject::Tag(tag) = parsed else {
            return Err(VerificationFailure {
                kind: FindingKind::CorpusShapeMismatch,
                actual_bytes: None,
            });
        };
        if !tag.headers().iter().any(|header| header.name == b"gpgsig") {
            return Err(VerificationFailure {
                kind: FindingKind::CorpusShapeMismatch,
                actual_bytes: None,
            });
        }
    }
    Ok(())
}

fn verify_entry(
    entry: &CorpusEntry,
    algorithm: &str,
    limits: &ParseLimits,
) -> Result<(), VerificationFailure> {
    let source_bytes = fs::read(&entry.body_path).map_err(|_| VerificationFailure {
        kind: FindingKind::CorpusShapeMismatch,
        actual_bytes: None,
    })?;
    let framed = emit_loose_framed(entry.object_type, &source_bytes, limits).map_err(|_| {
        VerificationFailure {
            kind: FindingKind::FramedParseRefusal,
            actual_bytes: None,
        }
    })?;
    let parsed_loose =
        parse_loose_framed(&framed, limits.clone()).map_err(|_| VerificationFailure {
            kind: FindingKind::FramedParseRefusal,
            actual_bytes: None,
        })?;
    let reemitted_framed =
        parsed_loose
            .emit_framed_bytes(limits)
            .map_err(|_| VerificationFailure {
                kind: FindingKind::FramedParseRefusal,
                actual_bytes: None,
            })?;
    if framed != reemitted_framed {
        return Err(VerificationFailure {
            kind: FindingKind::FramedReemitMismatch,
            actual_bytes: Some(reemitted_framed),
        });
    }
    let parsed_body = parse_object_body(
        entry.object_type,
        &source_bytes,
        AcceptanceProfile::GitCompatibleImport,
        limits,
    )
    .map_err(|_| VerificationFailure {
        kind: FindingKind::BodyParseRefusal,
        actual_bytes: None,
    })?;
    verify_special_headers(entry, &parsed_body)?;
    let reemitted_body =
        emit_object_body(&parsed_body, AcceptanceProfile::GitCompatibleImport, limits).map_err(
            |_| VerificationFailure {
                kind: FindingKind::BodyParseRefusal,
                actual_bytes: None,
            },
        )?;
    if source_bytes != reemitted_body {
        return Err(VerificationFailure {
            kind: FindingKind::BodyReemitMismatch,
            actual_bytes: Some(reemitted_body),
        });
    }
    let computed_oid = match algorithm {
        "sha1" => native_object_oid::<Sha1>(entry.object_type, &source_bytes).to_string(),
        "sha256" => native_object_oid::<Sha256>(entry.object_type, &source_bytes).to_string(),
        _ => unreachable!("algorithm_limits admits only SHA-1 and SHA-256"),
    };
    if computed_oid != entry.native_oid {
        return Err(VerificationFailure {
            kind: FindingKind::NativeOidMismatch,
            actual_bytes: None,
        });
    }
    Ok(())
}

fn write_finding(
    artifact_directory: &Path,
    entry: &CorpusEntry,
    failure: &VerificationFailure,
) -> Result<DifferentialError, DifferentialError> {
    let finding_directory = artifact_directory.join(format!("finding-{}", entry.label));
    fs::create_dir_all(&finding_directory).map_err(|error| {
        DifferentialError::new(format!(
            "cannot create {}: {error}",
            finding_directory.display()
        ))
    })?;
    let source = fs::read(&entry.body_path).map_err(|error| {
        DifferentialError::new(format!(
            "cannot preserve {}: {error}",
            entry.body_path.display()
        ))
    })?;
    fs::write(finding_directory.join("oracle.body"), source).map_err(|error| {
        DifferentialError::new(format!("cannot preserve oracle object bytes: {error}"))
    })?;
    if let Some(actual_bytes) = &failure.actual_bytes {
        fs::write(finding_directory.join("frankengit.body"), actual_bytes).map_err(|error| {
            DifferentialError::new(format!("cannot preserve FrankenGit object bytes: {error}"))
        })?;
    }
    let finding = format!(
        "{{\"schema\":\"frankengit.object-differential-finding.v1\",\"kind\":\"{}\",\"label\":\"{}\",\"object_type\":\"{}\",\"expected_oid\":\"{}\"}}\n",
        failure.kind.as_str(),
        entry.label,
        entry.object_type,
        entry.native_oid,
    );
    fs::write(finding_directory.join("finding.ndjson"), finding)
        .map_err(|error| DifferentialError::new(format!("cannot write typed finding: {error}")))?;
    Ok(DifferentialError::new(format!(
        "FG-015B-DIFFERENTIAL-FINDING {} for {} ({})",
        failure.kind.as_str(),
        entry.label,
        entry.native_oid
    )))
}

fn write_success_receipt(
    artifact_directory: &Path,
    algorithm: &str,
    denominator: usize,
) -> Result<(), DifferentialError> {
    let receipt = format!(
        "{{\"schema\":\"frankengit.object-differential-verdict.v1\",\"algorithm\":\"{algorithm}\",\"corpus_denominator\":{denominator},\"passed\":{denominator},\"non_claim\":\"E3 corpus evidence only; no full Git compatibility claim\"}}\n"
    );
    fs::write(artifact_directory.join("verdict.ndjson"), receipt).map_err(|error| {
        DifferentialError::new(format!("cannot write differential verdict: {error}"))
    })
}

#[test]
#[ignore = "requires the pinned shell oracle corpus from object_differential.sh"]
fn pinned_oracle_corpus_is_byte_exact_for_the_declared_algorithm() -> Result<(), DifferentialError>
{
    let corpus = required_directory(CORPUS_ENV)?;
    let artifact_directory = required_directory(ARTIFACT_ENV)?;
    let denominator = parse_denominator(&corpus)?;
    let (algorithm, limits) = algorithm_limits(&corpus)?;
    let entries = parse_manifest(&corpus)?;
    if entries.len() != denominator {
        return Err(DifferentialError::new(format!(
            "FG-015B-DIFFERENTIAL-FINDING {}: receipt denominator {denominator} differs from manifest {}",
            FindingKind::CorpusShapeMismatch.as_str(),
            entries.len()
        )));
    }
    for entry in &entries {
        if let Err(failure) = verify_entry(entry, algorithm, &limits) {
            return Err(write_finding(&artifact_directory, entry, &failure)?);
        }
    }
    write_success_receipt(&artifact_directory, algorithm, denominator)
}
