#![forbid(unsafe_code)]
//! E3 pack differential consumer for the separately pinned Git oracle.
//!
//! The ignored test never invokes Git. Its E2E caller creates a corpus through
//! `scripts/e2e/oracle/oracle.sh`, supplies the attested directory, and keeps
//! the oracle process boundary outside the Rust production and test APIs.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use fgit_git_object::ObjectType;
use fgit_pack::{
    EntryKind, ExternalBaseLookup, IdxV2, NativeChecksumVerifier, ObjectFormat, ObjectId,
    PackLimits, ParsedDeltaBase, QuarantinedEntry, ScalarResolver, read_verified_pack,
    validate_idx_entry_crc, validate_idx_pack_count,
};

const CORPUS_ENV: &str = "FGIT_PACK_DIFFERENTIAL_CORPUS";
const ARTIFACT_ENV: &str = "FGIT_PACK_DIFFERENTIAL_ARTIFACT_DIR";
const CORPUS_SCHEMA: &str = "frankengit.pack-differential-corpus.v1";

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

#[derive(Debug)]
struct ManifestEntry {
    object_type: ObjectType,
    body_path: PathBuf,
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

fn receipt_values(corpus: &Path) -> Result<BTreeMap<String, String>, DifferentialError> {
    let path = corpus.join("receipt.tsv");
    let text = fs::read_to_string(&path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", path.display()))
    })?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| DifferentialError::new("receipt line lacks '='"))?;
        if key.is_empty()
            || value.is_empty()
            || values.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(DifferentialError::new(
                "receipt has an empty or duplicate field",
            ));
        }
    }
    if values.get("schema").map(String::as_str) != Some(CORPUS_SCHEMA) {
        return Err(DifferentialError::new(
            "unsupported pack differential corpus schema",
        ));
    }
    Ok(values)
}

fn receipt<'values>(
    values: &'values BTreeMap<String, String>,
    key: &str,
) -> Result<&'values str, DifferentialError> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| DifferentialError::new(format!("receipt lacks {key}")))
}

fn object_format(value: &str) -> Result<ObjectFormat, DifferentialError> {
    match value {
        "sha1" => Ok(ObjectFormat::Sha1),
        "sha256" => Ok(ObjectFormat::Sha256),
        _ => Err(DifferentialError::new(format!(
            "unsupported corpus object format {value}"
        ))),
    }
}

fn object_type(value: &str) -> Result<ObjectType, DifferentialError> {
    ObjectType::from_label(value)
        .ok_or_else(|| DifferentialError::new(format!("unsupported manifest object type {value}")))
}

fn parse_manifest(corpus: &Path) -> Result<BTreeMap<String, ManifestEntry>, DifferentialError> {
    let path = corpus.join("manifest.tsv");
    let text = fs::read_to_string(&path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", path.display()))
    })?;
    let mut entries = BTreeMap::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let mut fields = line.split('\t');
        let oid = fields
            .next()
            .ok_or_else(|| DifferentialError::new("manifest lacks native OID"))?;
        let kind = fields
            .next()
            .ok_or_else(|| DifferentialError::new("manifest lacks object type"))?;
        let body = fields
            .next()
            .ok_or_else(|| DifferentialError::new("manifest lacks object body path"))?;
        if oid.is_empty() || body.is_empty() || fields.next().is_some() {
            return Err(DifferentialError::new(
                "manifest has an empty or surplus field",
            ));
        }
        let inserted = entries.insert(
            oid.to_owned(),
            ManifestEntry {
                object_type: object_type(kind)?,
                body_path: corpus.join(body),
            },
        );
        if inserted.is_some() {
            return Err(DifferentialError::new("manifest repeats a native OID"));
        }
    }
    if entries.is_empty() {
        return Err(DifferentialError::new("manifest has no objects"));
    }
    Ok(entries)
}

fn oid_text(oid: &ObjectId) -> String {
    oid.to_string()
}

fn entry_type(
    offset: u64,
    entries: &[QuarantinedEntry],
    offsets_at_id: &BTreeMap<String, u64>,
    stack: &mut BTreeSet<u64>,
) -> Result<ObjectType, DifferentialError> {
    if !stack.insert(offset) {
        return Err(DifferentialError::new(
            "differential corpus has a delta cycle",
        ));
    }
    let entry = entries
        .iter()
        .find(|entry| entry.offset == offset)
        .ok_or_else(|| DifferentialError::new("idx references no quarantined entry"))?;
    let result = match entry.header.kind {
        EntryKind::Commit => Ok(ObjectType::Commit),
        EntryKind::Tree => Ok(ObjectType::Tree),
        EntryKind::Blob => Ok(ObjectType::Blob),
        EntryKind::Tag => Ok(ObjectType::Tag),
        EntryKind::OfsDelta => match entry.delta_base.as_ref() {
            Some(ParsedDeltaBase::Ofs { base_offset, .. }) => {
                entry_type(*base_offset, entries, offsets_at_id, stack)
            }
            Some(ParsedDeltaBase::Ref { .. }) | None => {
                Err(DifferentialError::new("OFS_DELTA lacks an OFS base"))
            }
        },
        EntryKind::RefDelta => match entry.delta_base.as_ref() {
            Some(ParsedDeltaBase::Ref { base, .. }) => {
                let base_offset = offsets_at_id.get(&oid_text(base)).ok_or_else(|| {
                    DifferentialError::new("full-pack REF_DELTA base is absent from its idx")
                })?;
                entry_type(*base_offset, entries, offsets_at_id, stack)
            }
            Some(ParsedDeltaBase::Ofs { .. }) | None => {
                Err(DifferentialError::new("REF_DELTA lacks a REF base"))
            }
        },
    };
    let removed = stack.remove(&offset);
    debug_assert!(removed);
    result
}

fn raw_entry_span<'pack>(
    pack: &'pack [u8],
    entries: &[QuarantinedEntry],
    offset: u64,
    format: ObjectFormat,
) -> Result<&'pack [u8], DifferentialError> {
    let start = usize::try_from(offset)
        .map_err(|_| DifferentialError::new("pack offset does not fit usize"))?;
    let trailer_start = pack
        .len()
        .checked_sub(format.digest_len())
        .ok_or_else(|| DifferentialError::new("pack has no native trailer"))?;
    let end = entries
        .iter()
        .map(|entry| entry.offset)
        .filter(|candidate| *candidate > offset)
        .min()
        .map(usize::try_from)
        .transpose()
        .map_err(|_| DifferentialError::new("next pack offset does not fit usize"))?
        .unwrap_or(trailer_start);
    pack.get(start..end)
        .ok_or_else(|| DifferentialError::new("idx entry span lies outside pack bytes"))
}

fn write_verdict(
    artifact_directory: &Path,
    format: ObjectFormat,
    denominator: usize,
    delta_kind: &str,
) -> Result<(), DifferentialError> {
    fs::create_dir_all(artifact_directory).map_err(|error| {
        DifferentialError::new(format!(
            "cannot create artifact directory {}: {error}",
            artifact_directory.display()
        ))
    })?;
    let algorithm = match format {
        ObjectFormat::Sha1 => "sha1",
        ObjectFormat::Sha256 => "sha256",
    };
    let verdict = format!(
        "{{\"schema\":\"frankengit.pack-differential-verdict.v1\",\"algorithm\":\"{algorithm}\",\"corpus_denominator\":{denominator},\"delta_kind\":\"{delta_kind}\",\"non_claim\":\"E3 corpus evidence only; no full Git compatibility claim\"}}\n"
    );
    let path = artifact_directory.join("verdict.ndjson");
    fs::write(&path, verdict).map_err(|error| {
        DifferentialError::new(format!("cannot write {}: {error}", path.display()))
    })
}

struct ThinBase {
    id: ObjectId,
    bytes: Vec<u8>,
}

impl ExternalBaseLookup for ThinBase {
    fn lookup(&self, id: &ObjectId) -> Option<&[u8]> {
        (id == &self.id).then_some(&self.bytes)
    }
}

fn three_field_manifest(
    corpus: &Path,
    name: &str,
) -> Result<(String, ObjectType, Vec<u8>), DifferentialError> {
    let path = corpus.join(name);
    let text = fs::read_to_string(&path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", path.display()))
    })?;
    let line = text
        .lines()
        .find(|line| !line.starts_with('#'))
        .ok_or_else(|| DifferentialError::new("thin manifest has no entry"))?;
    let mut fields = line.split('\t');
    let oid = fields
        .next()
        .ok_or_else(|| DifferentialError::new("thin manifest lacks OID"))?;
    let kind = fields
        .next()
        .ok_or_else(|| DifferentialError::new("thin manifest lacks type"))?;
    let body = fields
        .next()
        .ok_or_else(|| DifferentialError::new("thin manifest lacks body"))?;
    if oid.is_empty() || body.is_empty() || fields.next().is_some() {
        return Err(DifferentialError::new(
            "thin manifest has an empty or surplus field",
        ));
    }
    let bytes = fs::read(corpus.join(body))
        .map_err(|error| DifferentialError::new(format!("cannot read thin body: {error}")))?;
    Ok((oid.to_owned(), object_type(kind)?, bytes))
}

fn parse_external_oid(format: ObjectFormat, text: &str) -> Result<ObjectId, DifferentialError> {
    match format {
        ObjectFormat::Sha1 => {
            fgit_crypto::parse_git_oid::<fgit_crypto::Sha1>(text).map(ObjectId::from)
        }
        ObjectFormat::Sha256 => {
            fgit_crypto::parse_git_oid::<fgit_crypto::Sha256>(text).map(ObjectId::from)
        }
    }
    .map_err(|error| DifferentialError::new(format!("invalid thin external OID: {error}")))
}

fn synthetic_large_offset_idx(entry: &fgit_pack::IdxEntry, format: ObjectFormat) -> Vec<u8> {
    let mut bytes = vec![0xff, b't', b'O', b'c'];
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    let first = usize::from(entry.oid.as_bytes()[0]);
    for bucket in 0..256 {
        let count = u32::from(bucket >= first);
        bytes.extend_from_slice(&count.to_be_bytes());
    }
    bytes.extend_from_slice(entry.oid.as_bytes());
    bytes.extend_from_slice(&entry.crc32.to_be_bytes());
    bytes.extend_from_slice(&0x8000_0000_u32.to_be_bytes());
    bytes.extend_from_slice(&entry.pack_offset.to_be_bytes());
    bytes.resize(bytes.len() + format.digest_len() * 2, 0);
    bytes
}

#[test]
#[ignore = "requires a corpus generated by the pinned oracle E2E lane"]
fn pinned_oracle_pack_matches_all_manifest_bytes_oids_and_idx_entries()
-> Result<(), DifferentialError> {
    let corpus = required_directory(CORPUS_ENV)?;
    let artifact_directory = required_directory(ARTIFACT_ENV)?;
    let values = receipt_values(&corpus)?;
    let format = object_format(receipt(&values, "algorithm")?)?;
    let expected_delta_kind = receipt(&values, "delta_kind")?;
    if !matches!(expected_delta_kind, "ofs" | "ref") {
        return Err(DifferentialError::new(
            "receipt has an unsupported delta kind",
        ));
    }
    let denominator = receipt(&values, "corpus_denominator")?
        .parse::<usize>()
        .map_err(|error| DifferentialError::new(format!("invalid corpus denominator: {error}")))?;
    let manifest = parse_manifest(&corpus)?;
    if receipt(&values, "oracle_pin")? != "git-2.54.0"
        || !corpus.join("oracle-receipt.tsv").is_file()
    {
        return Err(DifferentialError::new(
            "corpus lacks the pinned Git 2.54.0 oracle attestation",
        ));
    }
    if manifest.len() != denominator {
        return Err(DifferentialError::new(
            "manifest count disagrees with corpus denominator",
        ));
    }

    let pack_path = corpus.join("pack.pack");
    let pack_bytes = fs::read(&pack_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", pack_path.display()))
    })?;
    let idx_path = corpus.join("pack.idx");
    let idx_bytes = fs::read(&idx_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", idx_path.display()))
    })?;
    let limits = PackLimits::default();
    let quarantined = read_verified_pack(
        &pack_bytes,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .map_err(|error| DifferentialError::new(format!("pack refusal: {error}")))?;
    let index = IdxV2::parse_verified(
        &idx_bytes,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .map_err(|error| DifferentialError::new(format!("idx refusal: {error}")))?;
    validate_idx_pack_count(&index, quarantined.header)
        .map_err(|error| DifferentialError::new(format!("idx count refusal: {error}")))?;

    let mut ids_at_offset = BTreeMap::new();
    let mut offsets_at_id = BTreeMap::new();
    for entry in index.entries() {
        validate_idx_entry_crc(
            entry,
            raw_entry_span(
                &pack_bytes,
                quarantined.entries(),
                entry.pack_offset,
                format,
            )?,
            &limits,
            &mut || true,
        )
        .map_err(|error| DifferentialError::new(format!("idx CRC refusal: {error}")))?;
        let previous_offset = ids_at_offset.insert(entry.pack_offset, entry.oid);
        let previous_id = offsets_at_id.insert(oid_text(&entry.oid), entry.pack_offset);
        if previous_offset.is_some() || previous_id.is_some() {
            return Err(DifferentialError::new(
                "idx duplicates an offset or native OID",
            ));
        }
    }
    if ids_at_offset.len() != quarantined.entries().len() {
        return Err(DifferentialError::new(
            "idx and quarantined entry counts disagree",
        ));
    }
    let actual_ids = offsets_at_id.keys().cloned().collect::<BTreeSet<_>>();
    let expected_ids = manifest.keys().cloned().collect::<BTreeSet<_>>();
    if actual_ids != expected_ids {
        return Err(DifferentialError::new(
            "idx native OID set disagrees with oracle manifest",
        ));
    }

    let entries = quarantined.entries().to_vec();
    let objects = quarantined
        .into_scalar_objects(|offset| ids_at_offset.get(&offset).copied())
        .map_err(|error| DifferentialError::new(format!("scalar conversion refusal: {error}")))?;
    let scalar = ScalarResolver::new(&objects, &(), &limits, &mut || true).map_err(|error| {
        DifferentialError::new(format!("resolver construction refusal: {error}"))
    })?;
    let mut observed_delta = false;
    for index_entry in index.entries() {
        let reconstructed = scalar
            .resolve_offset(index_entry.pack_offset, &mut || true)
            .map_err(|error| {
                DifferentialError::new(format!("delta resolution refusal: {error}"))
            })?;
        let expected = manifest
            .get(&oid_text(&index_entry.oid))
            .ok_or_else(|| DifferentialError::new("idx object is missing from manifest"))?;
        let expected_body = fs::read(&expected.body_path).map_err(|error| {
            DifferentialError::new(format!(
                "cannot read {}: {error}",
                expected.body_path.display()
            ))
        })?;
        if reconstructed != expected_body {
            return Err(DifferentialError::new(
                "resolved object bytes disagree with oracle body",
            ));
        }
        let mut stack = BTreeSet::new();
        let inherited_type = entry_type(
            index_entry.pack_offset,
            &entries,
            &offsets_at_id,
            &mut stack,
        )?;
        if inherited_type != expected.object_type {
            return Err(DifferentialError::new(
                "resolved object type disagrees with oracle manifest",
            ));
        }
        if fgit_crypto::git_object_id(format, inherited_type, &reconstructed) != index_entry.oid {
            return Err(DifferentialError::new(
                "resolved object native OID disagrees with idx",
            ));
        }
        let entry = entries
            .iter()
            .find(|entry| entry.offset == index_entry.pack_offset)
            .ok_or_else(|| DifferentialError::new("idx references no quarantined entry"))?;
        observed_delta |= matches!(entry.header.kind, EntryKind::OfsDelta | EntryKind::RefDelta);
    }
    if !observed_delta {
        return Err(DifferentialError::new(
            "oracle corpus did not contain a delta entry",
        ));
    }
    write_verdict(
        &artifact_directory,
        format,
        denominator,
        expected_delta_kind,
    )
}

#[test]
#[ignore = "requires a thin pack generated by the pinned oracle E2E lane"]
fn pinned_oracle_thin_pack_requires_its_caller_supplied_base() -> Result<(), DifferentialError> {
    let corpus = required_directory(CORPUS_ENV)?;
    let artifact_directory = required_directory(ARTIFACT_ENV)?;
    let values = receipt_values(&corpus)?;
    let format = object_format(receipt(&values, "algorithm")?)?;
    if receipt(&values, "case_kind")? != "thin_ref_delta"
        || receipt(&values, "oracle_pin")? != "git-2.54.0"
    {
        return Err(DifferentialError::new(
            "thin corpus receipt lacks its pinned oracle identity",
        ));
    }
    let denominator = receipt(&values, "corpus_denominator")?
        .parse::<usize>()
        .map_err(|error| DifferentialError::new(format!("invalid thin denominator: {error}")))?;
    let (expected_oid, expected_type, expected_bytes) =
        three_field_manifest(&corpus, "thin-manifest.tsv")?;
    let (external_oid, external_type, external_bytes) =
        three_field_manifest(&corpus, "external-base.tsv")?;
    if external_type != ObjectType::Blob {
        return Err(DifferentialError::new("thin external base is not a blob"));
    }
    let external = ThinBase {
        id: parse_external_oid(format, &external_oid)?,
        bytes: external_bytes,
    };
    let pack_path = corpus.join("thin.pack");
    let pack = fs::read(&pack_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", pack_path.display()))
    })?;
    let limits = PackLimits::default();
    let quarantined = read_verified_pack(
        &pack,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .map_err(|error| DifferentialError::new(format!("thin pack refusal: {error}")))?;
    if quarantined.entries().len() != denominator {
        return Err(DifferentialError::new(
            "thin pack count disagrees with denominator",
        ));
    }
    if !quarantined
        .entries()
        .iter()
        .any(|entry| entry.header.kind == EntryKind::RefDelta)
    {
        return Err(DifferentialError::new(
            "oracle thin corpus did not contain REF_DELTA",
        ));
    }
    if !quarantined.entries().iter().any(|entry| {
        matches!(
            entry.delta_base.as_ref(),
            Some(ParsedDeltaBase::Ref { base, .. }) if base == &external.id
        )
    }) {
        return Err(DifferentialError::new(
            "oracle thin corpus did not reference the recorded external base",
        ));
    }
    let offsets = quarantined
        .entries()
        .iter()
        .map(|entry| entry.offset)
        .collect::<Vec<_>>();
    let objects = quarantined
        .into_scalar_objects(|_| None)
        .map_err(|error| DifferentialError::new(format!("thin scalar refusal: {error}")))?;
    let resolver = ScalarResolver::new(&objects, &external, &limits, &mut || true)
        .map_err(|error| DifferentialError::new(format!("thin resolver refusal: {error}")))?;
    let mut matched_target = false;
    for offset in offsets {
        let bytes = resolver
            .resolve_offset(offset, &mut || true)
            .map_err(|error| DifferentialError::new(format!("thin resolution refusal: {error}")))?;
        let actual_oid = fgit_crypto::git_object_id(format, expected_type, &bytes);
        if oid_text(&actual_oid) == expected_oid {
            if bytes != expected_bytes {
                return Err(DifferentialError::new(
                    "thin target body disagrees with oracle",
                ));
            }
            matched_target = true;
        }
    }
    if !matched_target {
        return Err(DifferentialError::new(
            "thin target OID was not reconstructed",
        ));
    }
    write_verdict(&artifact_directory, format, denominator, "thin_ref_delta")
}

#[test]
#[ignore = "requires an attested full pack corpus from the pinned oracle E2E lane"]
fn attested_oracle_entry_exercises_idx_v2_large_offset_indirection() -> Result<(), DifferentialError>
{
    let corpus = required_directory(CORPUS_ENV)?;
    let artifact_directory = required_directory(ARTIFACT_ENV)?;
    let values = receipt_values(&corpus)?;
    let format = object_format(receipt(&values, "algorithm")?)?;
    if receipt(&values, "oracle_pin")? != "git-2.54.0" {
        return Err(DifferentialError::new(
            "large-offset corpus lacks pinned oracle identity",
        ));
    }
    let pack_path = corpus.join("pack.pack");
    let pack = fs::read(&pack_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", pack_path.display()))
    })?;
    let idx_path = corpus.join("pack.idx");
    let idx = fs::read(&idx_path).map_err(|error| {
        DifferentialError::new(format!("cannot read {}: {error}", idx_path.display()))
    })?;
    let limits = PackLimits::default();
    let quarantined = read_verified_pack(
        &pack,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .map_err(|error| DifferentialError::new(format!("pack refusal: {error}")))?;
    let parsed =
        IdxV2::parse_verified(&idx, format, &limits, &mut || true, &NativeChecksumVerifier)
            .map_err(|error| DifferentialError::new(format!("idx refusal: {error}")))?;
    let entry = parsed
        .entries()
        .first()
        .ok_or_else(|| DifferentialError::new("oracle idx has no entries"))?;
    let synthetic = synthetic_large_offset_idx(entry, format);
    let indirect = IdxV2::parse(&synthetic, format, &limits, &mut || true)
        .map_err(|error| DifferentialError::new(format!("large-offset parse refusal: {error}")))?;
    let indirect_entry = indirect
        .entries()
        .first()
        .ok_or_else(|| DifferentialError::new("synthetic idx has no entries"))?;
    if indirect_entry.oid != entry.oid || indirect_entry.pack_offset != entry.pack_offset {
        return Err(DifferentialError::new(
            "large-offset table changed an attested OID or pack offset",
        ));
    }
    validate_idx_entry_crc(
        indirect_entry,
        raw_entry_span(
            &pack,
            quarantined.entries(),
            indirect_entry.pack_offset,
            format,
        )?,
        &limits,
        &mut || true,
    )
    .map_err(|error| DifferentialError::new(format!("large-offset CRC refusal: {error}")))?;
    write_verdict(
        &artifact_directory,
        format,
        1,
        "synthetic_idx_v2_large_offset_indirection",
    )
}
