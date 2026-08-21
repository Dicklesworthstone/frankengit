#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;
use std::path::{Path, PathBuf};

/// Bytes the frame format begins with.
const FRAME_MAGIC: [u8; 4] = *b"FGC1";

/// Largest frame this verifier will read, so a corrupt length cannot make it
/// allocate. Deliberately generous: the corpus is small.
const MAX_FRAME: usize = 1 << 20;

/// Why the verifier rejected something.
///
/// Deliberately coarse. This tool exists to disagree with `fgit-codec` when
/// one of them is wrong, so it does not attempt to mirror that crate's refusal
/// taxonomy — matching taxonomies would be a way of sharing a bug.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// A golden file could not be read or parsed.
    Corpus(String),
    /// A frame did not conform to the format specification.
    Frame(String),
    /// A frame conformed but disagreed with what the golden records.
    Mismatch(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(detail) => write!(formatter, "corpus: {detail}"),
            Self::Frame(detail) => write!(formatter, "frame: {detail}"),
            Self::Mismatch(detail) => write!(formatter, "mismatch: {detail}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// One record parsed out of the golden corpus.
#[derive(Clone, Debug)]
pub struct GoldenRecord {
    /// File stem.
    pub name: String,
    /// Schema the golden belongs to.
    pub schema: String,
    /// `valid` or `invalid`.
    pub kind: String,
    /// Planted defect, for invalid records.
    pub mutation: Option<String>,
    /// Refusal the encoder crate is expected to produce, for invalid records.
    pub expect: Option<String>,
    /// Identity the corpus records, for valid records.
    pub body_id: Option<String>,
    /// Whole-frame length the corpus records.
    pub frame_len: Option<usize>,
    /// Payload length the corpus records.
    pub canonical_body_len: Option<usize>,
    /// The bytes themselves.
    pub bytes: Vec<u8>,
}

impl GoldenRecord {
    /// True when the record is a canonical vector rather than a planted defect.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.kind == "valid"
    }
}

/// A frame, as this verifier reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Codec major version.
    pub codec_major: u16,
    /// Codec minor version.
    pub codec_minor: u16,
    /// Domain separation tag.
    pub domain: String,
    /// Schema family.
    pub family: String,
    /// Schema major version.
    pub schema_major: u16,
    /// Schema minor version.
    pub schema_minor: u16,
    /// Canonical body bytes: the payload, which is what identity covers.
    pub payload: Vec<u8>,
}

/// Reads a big-endian `u16` and advances the cursor.
fn take_u16(bytes: &[u8], at: &mut usize) -> Result<u16, VerifyError> {
    let end = at.checked_add(2).ok_or_else(|| overflow("u16"))?;
    let slice = bytes
        .get(*at..end)
        .ok_or_else(|| VerifyError::Frame(format!("truncated u16 at {at}")))?;
    *at = end;
    Ok(u16::from(slice[0]) << 8 | u16::from(slice[1]))
}

/// Reads a big-endian `u32` and advances the cursor.
fn take_u32(bytes: &[u8], at: &mut usize) -> Result<u32, VerifyError> {
    let end = at.checked_add(4).ok_or_else(|| overflow("u32"))?;
    let slice = bytes
        .get(*at..end)
        .ok_or_else(|| VerifyError::Frame(format!("truncated u32 at {at}")))?;
    *at = end;
    Ok(u32::from(slice[0]) << 24
        | u32::from(slice[1]) << 16
        | u32::from(slice[2]) << 8
        | u32::from(slice[3]))
}

fn overflow(what: &str) -> VerifyError {
    VerifyError::Frame(format!("offset overflow reading {what}"))
}

/// Reads a `u32`-length-prefixed byte string and advances the cursor.
fn take_bytes<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], VerifyError> {
    let declared = take_u32(bytes, at)?;
    let length = usize::try_from(declared)
        .map_err(|_| VerifyError::Frame(format!("length {declared} exceeds this platform")))?;
    if length > MAX_FRAME {
        return Err(VerifyError::Frame(format!(
            "length {length} over the bound"
        )));
    }
    let end = at.checked_add(length).ok_or_else(|| overflow("bytes"))?;
    let slice = bytes.get(*at..end).ok_or_else(|| {
        VerifyError::Frame(format!(
            "declared {length} bytes at {at} but only {} remain",
            bytes.len().saturating_sub(*at)
        ))
    })?;
    *at = end;
    Ok(slice)
}

/// Reads a length-prefixed label as text.
fn take_label(bytes: &[u8], at: &mut usize) -> Result<String, VerifyError> {
    let raw = take_bytes(bytes, at)?;
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| VerifyError::Frame("label is not text".to_owned()))
}

/// Parses a frame straight from the written format specification.
///
/// Written to be obvious rather than shared: a bug present in both this and
/// `fgit-codec` would be invisible, which is the whole reason this exists.
pub fn parse_frame(bytes: &[u8]) -> Result<Frame, VerifyError> {
    if bytes.len() > MAX_FRAME {
        return Err(VerifyError::Frame(format!(
            "frame of {} bytes",
            bytes.len()
        )));
    }
    let mut at = 0_usize;
    let magic = bytes
        .get(0..4)
        .ok_or_else(|| VerifyError::Frame("shorter than the magic".to_owned()))?;
    if magic != FRAME_MAGIC {
        return Err(VerifyError::Frame(format!("bad magic {magic:02x?}")));
    }
    at += 4;

    let codec_major = take_u16(bytes, &mut at)?;
    let codec_minor = take_u16(bytes, &mut at)?;
    if codec_major != 1 {
        return Err(VerifyError::Frame(format!(
            "codec major {codec_major} is not 1"
        )));
    }
    let domain = take_label(bytes, &mut at)?;
    let family = take_label(bytes, &mut at)?;
    let schema_major = take_u16(bytes, &mut at)?;
    let schema_minor = take_u16(bytes, &mut at)?;
    let payload = take_bytes(bytes, &mut at)?.to_vec();

    if at != bytes.len() {
        return Err(VerifyError::Frame(format!(
            "{} trailing bytes after the payload",
            bytes.len() - at
        )));
    }
    Ok(Frame {
        codec_major,
        codec_minor,
        domain,
        family,
        schema_major,
        schema_minor,
        payload,
    })
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// `FNV-1a`, 64-bit.
#[must_use]
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in data {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The corpus digest: `FNV-1a` forward, then over the reversed input.
///
/// Not a cryptographic digest, and the corpus says so. Reproduced here because
/// the point is to re-derive the recorded identities without borrowing the
/// implementation that produced them.
#[must_use]
pub fn corpus_digest(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&fnv1a64(bytes).to_be_bytes());
    let reversed: Vec<u8> = bytes.iter().copied().rev().collect();
    out[8..].copy_from_slice(&fnv1a64(&reversed).to_be_bytes());
    out
}

/// The identity preimage, framed as the digest registry specifies.
#[must_use]
pub fn identity_preimage(
    domain: &str,
    family: &str,
    schema_major: u16,
    schema_minor: u16,
    canonical_body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    let domain = domain.as_bytes();
    let family = family.as_bytes();
    out.push(u8::try_from(domain.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(domain);
    out.push(u8::try_from(family.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(family);
    out.extend_from_slice(&schema_major.to_be_bytes());
    out.extend_from_slice(&schema_minor.to_be_bytes());
    let body_len = u64::try_from(canonical_body.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(canonical_body);
    out
}

/// Renders lowercase hexadecimal.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('?'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('?'));
    }
    out
}

/// The identity string a golden records, re-derived from the frame alone.
///
/// Format: `domain/vMAJOR.MINOR/alg:CODEPOINT/HEX`.
#[must_use]
pub fn derive_body_id(frame: &Frame, algorithm_code_point: u16) -> String {
    let preimage = identity_preimage(
        &frame.domain,
        &frame.family,
        frame.schema_major,
        frame.schema_minor,
        &frame.payload,
    );
    format!(
        "{}/v{}.{}/alg:{}/{}",
        frame.domain,
        frame.codec_major,
        frame.codec_minor,
        algorithm_code_point,
        hex(&corpus_digest(&preimage))
    )
}

/// Code point the corpus reserves for its non-cryptographic digest.
pub const CORPUS_ALGORITHM_CODE_POINT: u16 = 0xfff1;

/// Outcome of verifying the corpus.
#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    /// Valid vectors that re-derived correctly.
    pub valid_confirmed: usize,
    /// Planted defects this verifier also rejected.
    pub invalid_rejected: usize,
    /// Planted defects this verifier could still parse. Not a failure on its
    /// own: a payload-interior defect is invisible to a frame parser.
    pub invalid_parsed: Vec<String>,
    /// Everything that disagreed with the corpus.
    pub failures: Vec<String>,
}

impl VerifyReport {
    /// True when nothing disagreed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

fn parse_golden(path: &Path) -> Result<GoldenRecord, VerifyError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| VerifyError::Corpus(format!("{}: {error}", path.display())))?;
    let name = path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    let mut record = GoldenRecord {
        name: name.clone(),
        schema: String::new(),
        kind: String::new(),
        mutation: None,
        expect: None,
        body_id: None,
        frame_len: None,
        canonical_body_len: None,
        bytes: Vec::new(),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| VerifyError::Corpus(format!("{name}: malformed line {line:?}")))?;
        let value = value.trim();
        match key.trim() {
            "schema" => record.schema = value.to_owned(),
            "kind" => record.kind = value.to_owned(),
            "mutation" => record.mutation = Some(value.to_owned()),
            "expect" => record.expect = Some(value.to_owned()),
            "body_id" => record.body_id = Some(value.to_owned()),
            "frame_len" => {
                record.frame_len = Some(
                    value
                        .parse()
                        .map_err(|_| VerifyError::Corpus(format!("{name}: bad frame_len")))?,
                );
            }
            "canonical_body_len" => {
                record.canonical_body_len =
                    Some(value.parse().map_err(|_| {
                        VerifyError::Corpus(format!("{name}: bad canonical_body_len"))
                    })?);
            }
            "bytes" => record.bytes = unhex(&name, value)?,
            other => {
                return Err(VerifyError::Corpus(format!(
                    "{name}: unknown key {other:?}"
                )));
            }
        }
    }
    if record.bytes.is_empty() {
        return Err(VerifyError::Corpus(format!("{name}: no bytes")));
    }
    Ok(record)
}

fn unhex(name: &str, text: &str) -> Result<Vec<u8>, VerifyError> {
    if !text.len().is_multiple_of(2) {
        return Err(VerifyError::Corpus(format!("{name}: odd hex length")));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().as_chunks::<2>().0 {
        let high = char::from(pair[0])
            .to_digit(16)
            .ok_or_else(|| VerifyError::Corpus(format!("{name}: bad hex digit")))?;
        let low = char::from(pair[1])
            .to_digit(16)
            .ok_or_else(|| VerifyError::Corpus(format!("{name}: bad hex digit")))?;
        out.push(u8::try_from(high << 4 | low).unwrap_or(0));
    }
    Ok(out)
}

/// Reads every golden in a directory, sorted by file name.
pub fn load_corpus(directory: &Path) -> Result<Vec<GoldenRecord>, VerifyError> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| VerifyError::Corpus(format!("{}: {error}", directory.display())))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| VerifyError::Corpus(format!("bad directory entry: {error}")))?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "golden")
        {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(VerifyError::Corpus("no golden files".to_owned()));
    }
    paths.iter().map(|path| parse_golden(path)).collect()
}

/// Re-derives every canonical vector in the corpus and reports disagreements.
pub fn verify_corpus(directory: &Path) -> Result<VerifyReport, VerifyError> {
    let records = load_corpus(directory)?;
    let mut report = VerifyReport::default();
    for record in &records {
        match parse_frame(&record.bytes) {
            Ok(frame) => {
                if record.is_valid() {
                    verify_valid(record, &frame, &mut report);
                } else {
                    report.invalid_parsed.push(record.name.clone());
                }
            }
            Err(error) => {
                if record.is_valid() {
                    report.failures.push(format!(
                        "{}: canonical vector rejected: {error}",
                        record.name
                    ));
                } else {
                    report.invalid_rejected += 1;
                }
            }
        }
    }
    Ok(report)
}

fn verify_valid(record: &GoldenRecord, frame: &Frame, report: &mut VerifyReport) {
    let mut ok = true;
    if let Some(expected) = record.frame_len
        && expected != record.bytes.len()
    {
        report.failures.push(format!(
            "{}: frame_len records {expected}, bytes are {}",
            record.name,
            record.bytes.len()
        ));
        ok = false;
    }
    if let Some(expected) = record.canonical_body_len
        && expected != frame.payload.len()
    {
        report.failures.push(format!(
            "{}: canonical_body_len records {expected}, payload is {}",
            record.name,
            frame.payload.len()
        ));
        ok = false;
    }
    if let Some(expected) = record.body_id.as_ref() {
        let derived = derive_body_id(frame, CORPUS_ALGORITHM_CODE_POINT);
        if &derived != expected {
            report.failures.push(format!(
                "{}: identity records {expected}, re-derives to {derived}",
                record.name
            ));
            ok = false;
        }
    }
    if record.schema != frame.family {
        report.failures.push(format!(
            "{}: schema {} does not match the frame's family {}",
            record.name, record.schema, frame.family
        ));
        ok = false;
    }
    if ok {
        report.valid_confirmed += 1;
    }
}

/// Locates the golden corpus relative to this crate.
#[must_use]
pub fn default_corpus_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fgit-codec")
        .join("tests")
        .join("goldens")
}
