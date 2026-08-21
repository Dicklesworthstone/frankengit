#![forbid(unsafe_code)]
//! Bounded parsers and byte-preserving emitters for canonical Git object bytes.
//!
//! This crate deliberately handles *decompressed* loose-object bytes. Bounded
//! zlib framing belongs to `fgit-deflate`, and native object identity belongs to
//! `fgit-crypto`; neither is reimplemented here. Tree references remain opaque
//! native-width byte sequences until they are converted at that typed boundary.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub use fgit_crypto::{
    GitHashAlgorithm, GitObjectHasher, GitObjectKind as ObjectType, GitOid, NativeObjectIdentity,
    Sha1, Sha256,
};
pub use fgit_deflate::{CancellationProbe, InflateLimits, InflateRefusal, StreamProgress};

/// Parser policy for an object that is being imported or newly created.
///
/// `StrictCreate` accepts only object shapes `FrankenGit` will create: canonical
/// Git modes/tree order, safe tree names, a header separator, and required
/// commit/tag headers with bounded dates. The import profile preserves bounded
/// unusual headers, missing commit/tag separators, unordered tree entries,
/// non-canonical octal modes, and unsafe names as raw bytes for
/// quarantine/conformance handling. Loose framing itself is canonical and is
/// validated independently of this profile. Both profiles refuse ambiguous
/// framing, unterminated entries, invalid reference widths, and budget excess.
/// Differential coverage of every pinned upstream-version edge is FG-015b.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AcceptanceProfile {
    /// Reject malformed or non-canonical structures before `FrankenGit` creates them.
    #[default]
    StrictCreate,
    /// Preserve historically tolerated structures that have a bounded, unambiguous parse.
    GitCompatibleImport,
}

/// Bounds checked before input bytes are accumulated or structured.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Largest decompressed object accepted by this parser.
    pub max_object_bytes: usize,
    /// Largest loose header accepted before the NUL delimiter.
    pub max_loose_header_bytes: usize,
    /// Largest number of tree entries.
    pub max_tree_entries: usize,
    /// Largest number of commit/tag headers, including continuations.
    pub max_header_lines: usize,
    /// Largest single commit/tag header line.
    pub max_header_line_bytes: usize,
    /// Native byte width of tree object references (20 for SHA-1, 32 for SHA-256).
    pub tree_reference_bytes: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: 64 * 1024 * 1024,
            max_loose_header_bytes: 128,
            max_tree_entries: 1_000_000,
            max_header_lines: 16_384,
            max_header_line_bytes: 64 * 1024,
            tree_reference_bytes: 20,
        }
    }
}

/// Typed refusal from object framing or structure validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectError {
    /// The bounded object limit would be exceeded.
    ObjectTooLarge { limit: usize },
    /// The bounded loose-header limit would be exceeded.
    LooseHeaderTooLarge { limit: usize },
    /// The loose header did not contain its required NUL terminator.
    MissingLooseHeaderTerminator,
    /// The loose header was not `<type> <decimal-size>`.
    MalformedLooseHeader,
    /// The loose size field was not canonical decimal.
    NonCanonicalLooseLength,
    /// The payload byte count did not equal the declared loose size.
    LooseLengthMismatch { declared: usize, actual: usize },
    /// Data followed a complete framed object.
    TrailingLooseBytes,
    /// The object type has no supported Git spelling.
    UnsupportedObjectType,
    /// Only native SHA-1 and SHA-256 tree-reference widths are supported.
    UnsupportedTreeReferenceWidth { width: usize },
    /// A tree entry omitted the separating ASCII space.
    MissingTreeModeSeparator,
    /// A tree entry omitted the NUL after its filename.
    MissingTreeNameTerminator,
    /// A tree mode contained non-octal or empty bytes.
    MalformedTreeMode,
    /// A strict tree entry used a non-canonical mode.
    NonCanonicalTreeMode,
    /// A strict tree filename cannot be created safely.
    InvalidStrictTreeName,
    /// A tree ended before the native-width reference was complete.
    TruncatedTreeReference,
    /// A tree exceeded its configured entry count.
    TooManyTreeEntries { limit: usize },
    /// Strict creation requires Git tree order.
    TreeEntriesOutOfOrder,
    /// Strict creation rejects duplicate tree names even when modes differ.
    DuplicateTreeEntry,
    /// A commit or tag header section had no message separator.
    MissingHeaderMessageSeparator,
    /// A header line could not be split into a name and value.
    MalformedHeader,
    /// A continuation appeared before a header.
    OrphanHeaderContinuation,
    /// A strict header name included unsupported bytes.
    InvalidStrictHeaderName,
    /// A header budget was exceeded.
    HeaderLimitExceeded { limit: usize },
    /// Strict commit creation requires exactly one tree header.
    MissingOrDuplicateCommitTree,
    /// Strict commit creation requires exactly one author and committer header.
    MissingOrDuplicateCommitIdentity,
    /// Strict commit creation requires Git's tree/parent/author/committer prefix order.
    StrictCommitHeaderOrder,
    /// Strict commit creation rejects a NUL anywhere in the commit body.
    NulInStrictCommit,
    /// A native object-reference field was not 40 or 64 lowercase-or-uppercase hex bytes.
    MalformedObjectReference,
    /// A strict author, committer, or tagger date was malformed.
    MalformedSignatureDate,
    /// A strict annotated tag did not carry all mandatory headers.
    MissingOrDuplicateTagHeader,
    /// A strict annotated-tag type was not one of Git's four native object types.
    InvalidTagTargetType,
    /// A strict tag name was empty or contained a control byte.
    InvalidTagName,
    /// The streaming decoder reached an impossible partial internal state.
    DecoderStateInconsistent,
    /// A bounded allocation could not be reserved without risking a process abort.
    AllocationFailure,
}

impl Display for ObjectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectTooLarge { limit } => {
                write!(formatter, "object exceeds {limit}-byte limit")
            }
            Self::LooseHeaderTooLarge { limit } => {
                write!(formatter, "loose header exceeds {limit}-byte limit")
            }
            Self::MissingLooseHeaderTerminator => {
                formatter.write_str("loose header has no NUL terminator")
            }
            Self::MalformedLooseHeader => formatter.write_str("malformed loose-object header"),
            Self::NonCanonicalLooseLength => {
                formatter.write_str("non-canonical loose-object length")
            }
            Self::LooseLengthMismatch { declared, actual } => write!(
                formatter,
                "loose length mismatch: declared {declared}, received {actual}"
            ),
            Self::TrailingLooseBytes => formatter.write_str("trailing bytes after loose object"),
            Self::UnsupportedObjectType => formatter.write_str("unsupported Git object type"),
            Self::UnsupportedTreeReferenceWidth { width } => {
                write!(formatter, "unsupported tree-reference width {width}")
            }
            Self::MissingTreeModeSeparator => {
                formatter.write_str("tree entry has no mode separator")
            }
            Self::MissingTreeNameTerminator => {
                formatter.write_str("tree entry has no filename terminator")
            }
            Self::MalformedTreeMode => formatter.write_str("malformed tree mode"),
            Self::NonCanonicalTreeMode => formatter.write_str("non-canonical tree mode"),
            Self::InvalidStrictTreeName => formatter.write_str("invalid strict tree filename"),
            Self::TruncatedTreeReference => formatter.write_str("truncated tree object reference"),
            Self::TooManyTreeEntries { limit } => {
                write!(formatter, "tree has more than {limit} entries")
            }
            Self::TreeEntriesOutOfOrder => formatter.write_str("tree entries are not in Git order"),
            Self::DuplicateTreeEntry => formatter.write_str("tree contains duplicate filename"),
            Self::MissingHeaderMessageSeparator => {
                formatter.write_str("commit/tag lacks header-message separator")
            }
            Self::MalformedHeader => formatter.write_str("malformed commit/tag header"),
            Self::OrphanHeaderContinuation => {
                formatter.write_str("header continuation without prior header")
            }
            Self::InvalidStrictHeaderName => formatter.write_str("invalid strict header name"),
            Self::HeaderLimitExceeded { limit } => {
                write!(formatter, "header limit {limit} exceeded")
            }
            Self::MissingOrDuplicateCommitTree => {
                formatter.write_str("strict commit requires one tree header")
            }
            Self::MissingOrDuplicateCommitIdentity => {
                formatter.write_str("strict commit requires one author and committer")
            }
            Self::StrictCommitHeaderOrder => {
                formatter.write_str("strict commit headers are not in Git fsck order")
            }
            Self::NulInStrictCommit => formatter.write_str("strict commit contains a NUL byte"),
            Self::MalformedObjectReference => {
                formatter.write_str("malformed native object reference")
            }
            Self::MalformedSignatureDate => formatter.write_str("malformed strict signature date"),
            Self::MissingOrDuplicateTagHeader => {
                formatter.write_str("strict annotated tag has mandatory-header mismatch")
            }
            Self::InvalidTagTargetType => formatter.write_str("invalid annotated-tag target type"),
            Self::InvalidTagName => formatter.write_str("invalid strict tag name"),
            Self::DecoderStateInconsistent => {
                formatter.write_str("loose decoder state is inconsistent")
            }
            Self::AllocationFailure => {
                formatter.write_str("object parser could not reserve memory")
            }
        }
    }
}

impl Error for ObjectError {}

/// Typed failure while decoding a zlib-wrapped loose object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LooseObjectDecodeError {
    /// The independently bounded zlib decoder refused the compressed member.
    Inflate(InflateRefusal),
    /// The decompressed native loose-object framing or body was invalid.
    Object(ObjectError),
}

impl Display for LooseObjectDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inflate(error) => write!(formatter, "zlib loose-object refusal: {error}"),
            Self::Object(error) => write!(formatter, "loose-object refusal: {error}"),
        }
    }
}

impl Error for LooseObjectDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inflate(error) => Some(error),
            Self::Object(error) => Some(error),
        }
    }
}

impl From<InflateRefusal> for LooseObjectDecodeError {
    fn from(value: InflateRefusal) -> Self {
        Self::Inflate(value)
    }
}

impl From<ObjectError> for LooseObjectDecodeError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

/// A complete decompressed loose Git object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LooseObject {
    /// Native object type from the header.
    pub object_type: ObjectType,
    /// Exact body size declared by the header.
    pub declared_size: usize,
    /// Uncompressed body bytes.
    pub body: Vec<u8>,
}

impl LooseObject {
    /// Emits the native loose-object framing without zlib compression.
    pub fn emit_framed_bytes(&self, limits: &ParseLimits) -> Result<Vec<u8>, ObjectError> {
        if self.declared_size != self.body.len() {
            return Err(ObjectError::LooseLengthMismatch {
                declared: self.declared_size,
                actual: self.body.len(),
            });
        }
        emit_loose_framed(self.object_type, &self.body, limits)
    }
}

/// Incremental parser for a decompressed loose-object stream.
#[derive(Clone, Debug)]
pub struct LooseObjectDecoder {
    limits: ParseLimits,
    header: Vec<u8>,
    object_type: Option<ObjectType>,
    declared_size: Option<usize>,
    body: Vec<u8>,
}

/// Streaming zlib wrapper for a loose object. Decompressed bytes remain
/// tentative until both the RFC 1950 trailer and native loose frame finish.
#[derive(Clone, Debug)]
pub struct ZlibLooseObjectDecoder {
    inflater: fgit_deflate::Inflater,
    loose: LooseObjectDecoder,
}

impl ZlibLooseObjectDecoder {
    /// Starts a bounded zlib decoder and a bounded native loose-object decoder.
    pub fn new(
        inflate_limits: InflateLimits,
        object_limits: ParseLimits,
    ) -> Result<Self, LooseObjectDecodeError> {
        Ok(Self {
            inflater: fgit_deflate::Inflater::new(inflate_limits)?,
            loose: LooseObjectDecoder::new(object_limits),
        })
    }

    /// Supplies compressed bytes using a control that never cancels.
    pub fn push(&mut self, input: &[u8]) -> Result<StreamProgress, LooseObjectDecodeError> {
        let progress = self.inflater.push(input)?;
        self.drain_tentative_output()?;
        Ok(progress)
    }

    /// Supplies compressed bytes with caller-owned cancellation checks.
    pub fn push_with_control(
        &mut self,
        input: &[u8],
        control: &mut impl CancellationProbe,
    ) -> Result<StreamProgress, LooseObjectDecodeError> {
        let progress = self.inflater.push_with_control(input, control)?;
        self.drain_tentative_output()?;
        Ok(progress)
    }

    /// Verifies the zlib trailer and native loose length before releasing bytes.
    pub fn finish(mut self) -> Result<LooseObject, LooseObjectDecodeError> {
        self.inflater.finish()?;
        self.drain_tentative_output()?;
        self.loose.finish().map_err(Into::into)
    }

    fn drain_tentative_output(&mut self) -> Result<(), LooseObjectDecodeError> {
        let output = self.inflater.take_output();
        self.loose.push(&output).map_err(Into::into)
    }
}

impl LooseObjectDecoder {
    /// Starts a decoder with the specified hard limits.
    #[must_use]
    pub const fn new(limits: ParseLimits) -> Self {
        Self {
            limits,
            header: Vec::new(),
            object_type: None,
            declared_size: None,
            body: Vec::new(),
        }
    }

    /// Incorporates one decompressed input chunk without allocating from its declared length.
    pub fn push(&mut self, mut chunk: &[u8]) -> Result<(), ObjectError> {
        if self.object_type.is_none() {
            let terminator = chunk.iter().position(|byte| *byte == 0);
            let header_part = terminator.map_or(chunk, |index| &chunk[..index]);
            let new_header_len = self.header.len().checked_add(header_part.len()).ok_or(
                ObjectError::LooseHeaderTooLarge {
                    limit: self.limits.max_loose_header_bytes,
                },
            )?;
            if new_header_len > self.limits.max_loose_header_bytes {
                return Err(ObjectError::LooseHeaderTooLarge {
                    limit: self.limits.max_loose_header_bytes,
                });
            }
            self.header
                .try_reserve(header_part.len())
                .map_err(|_| ObjectError::AllocationFailure)?;
            self.header.extend_from_slice(header_part);
            let Some(index) = terminator else {
                return Ok(());
            };
            let (object_type, declared_size) = parse_loose_header(&self.header, &self.limits)?;
            self.object_type = Some(object_type);
            self.declared_size = Some(declared_size);
            chunk = &chunk[index + 1..];
        }
        let declared_size = self
            .declared_size
            .ok_or(ObjectError::DecoderStateInconsistent)?;
        let new_body_len =
            self.body
                .len()
                .checked_add(chunk.len())
                .ok_or(ObjectError::ObjectTooLarge {
                    limit: self.limits.max_object_bytes,
                })?;
        if new_body_len > declared_size {
            return Err(ObjectError::TrailingLooseBytes);
        }
        self.body
            .try_reserve(chunk.len())
            .map_err(|_| ObjectError::AllocationFailure)?;
        self.body.extend_from_slice(chunk);
        Ok(())
    }

    /// Finishes one exact loose object or returns a typed incomplete-frame refusal.
    pub fn finish(self) -> Result<LooseObject, ObjectError> {
        let object_type = self
            .object_type
            .ok_or(ObjectError::MissingLooseHeaderTerminator)?;
        let declared_size = self
            .declared_size
            .ok_or(ObjectError::DecoderStateInconsistent)?;
        if self.body.len() != declared_size {
            return Err(ObjectError::LooseLengthMismatch {
                declared: declared_size,
                actual: self.body.len(),
            });
        }
        Ok(LooseObject {
            object_type,
            declared_size,
            body: self.body,
        })
    }
}

/// Parses one complete decompressed loose-object byte sequence.
pub fn parse_loose_framed(bytes: &[u8], limits: ParseLimits) -> Result<LooseObject, ObjectError> {
    let mut decoder = LooseObjectDecoder::new(limits);
    decoder.push(bytes)?;
    decoder.finish()
}

/// Parses one complete zlib-wrapped loose object with independent compressed
/// and decompressed resource ceilings.
pub fn parse_zlib_loose(
    compressed: &[u8],
    inflate_limits: InflateLimits,
    object_limits: ParseLimits,
) -> Result<LooseObject, LooseObjectDecodeError> {
    let mut decoder = ZlibLooseObjectDecoder::new(inflate_limits, object_limits)?;
    decoder.push(compressed)?;
    decoder.finish()
}

/// Emits canonical loose-object framing before the separate zlib codec wraps it.
pub fn emit_loose_framed(
    object_type: ObjectType,
    body: &[u8],
    limits: &ParseLimits,
) -> Result<Vec<u8>, ObjectError> {
    if body.len() > limits.max_object_bytes {
        return Err(ObjectError::ObjectTooLarge {
            limit: limits.max_object_bytes,
        });
    }
    let header = format!("{} {}\0", object_type.label(), body.len());
    let required = header
        .len()
        .checked_add(body.len())
        .ok_or(ObjectError::ObjectTooLarge {
            limit: limits.max_object_bytes,
        })?;
    let mut output = Vec::new();
    output
        .try_reserve(required)
        .map_err(|_| ObjectError::AllocationFailure)?;
    output.extend_from_slice(header.as_bytes());
    output.extend_from_slice(body);
    Ok(output)
}

/// Computes the native Git object identity over exactly `<type> <size>\0<body>`.
///
/// The generic algorithm marker makes SHA-1 and SHA-256 identities impossible
/// to compare or substitute accidentally at the call site.
#[must_use]
pub fn native_object_oid<A: GitHashAlgorithm>(object_type: ObjectType, body: &[u8]) -> GitOid<A> {
    GitOid::<A>::of_object(object_type, body)
}

/// Starts typed incremental native-object hashing with the already validated size.
pub fn native_object_hasher<A: GitHashAlgorithm>(
    object_type: ObjectType,
    declared_size: usize,
) -> Result<GitObjectHasher<A>, ObjectError> {
    let declared_size = u64::try_from(declared_size)
        .map_err(|_| ObjectError::ObjectTooLarge { limit: usize::MAX })?;
    Ok(GitOid::<A>::object_hasher(object_type, declared_size))
}

/// One parsed tree entry. `object_id` is an opaque native-width byte sequence,
/// not a `FrankenGit` OID type; conversion is owned by `fgit-crypto`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    /// Original ASCII-octal mode bytes.
    pub mode: Vec<u8>,
    /// Raw filename bytes without its NUL terminator.
    pub name: Vec<u8>,
    /// Raw native object-reference bytes of the configured width.
    pub object_id: Vec<u8>,
}

impl TreeEntry {
    /// Returns whether this entry is a directory for Git's special tree ordering.
    #[must_use]
    pub fn is_tree(&self) -> bool {
        self.mode == b"40000" || self.mode == b"040000"
    }
}

/// Parses a raw tree body and preserves every accepted entry byte exactly.
pub fn parse_tree(
    body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<Vec<TreeEntry>, ObjectError> {
    validate_tree_reference_width(limits.tree_reference_bytes)?;
    if body.len() > limits.max_object_bytes {
        return Err(ObjectError::ObjectTooLarge {
            limit: limits.max_object_bytes,
        });
    }
    let mut cursor = 0;
    let mut entries = Vec::new();
    while cursor < body.len() {
        if entries.len() == limits.max_tree_entries {
            return Err(ObjectError::TooManyTreeEntries {
                limit: limits.max_tree_entries,
            });
        }
        let mode_end = body[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| cursor + offset)
            .ok_or(ObjectError::MissingTreeModeSeparator)?;
        let mode = copy_bytes(&body[cursor..mode_end])?;
        validate_tree_mode(&mode, profile)?;
        let name_start = mode_end
            .checked_add(1)
            .ok_or(ObjectError::MissingTreeNameTerminator)?;
        let name_end = body[name_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| name_start + offset)
            .ok_or(ObjectError::MissingTreeNameTerminator)?;
        let name = copy_bytes(&body[name_start..name_end])?;
        if profile == AcceptanceProfile::StrictCreate && !is_strict_tree_name(&name) {
            return Err(ObjectError::InvalidStrictTreeName);
        }
        let reference_start = name_end
            .checked_add(1)
            .ok_or(ObjectError::TruncatedTreeReference)?;
        let reference_end = reference_start
            .checked_add(limits.tree_reference_bytes)
            .ok_or(ObjectError::TruncatedTreeReference)?;
        if reference_end > body.len() {
            return Err(ObjectError::TruncatedTreeReference);
        }
        entries
            .try_reserve(1)
            .map_err(|_| ObjectError::AllocationFailure)?;
        entries.push(TreeEntry {
            mode,
            name,
            object_id: copy_bytes(&body[reference_start..reference_end])?,
        });
        cursor = reference_end;
    }
    if profile == AcceptanceProfile::StrictCreate {
        validate_strict_tree(&entries)?;
    }
    Ok(entries)
}

/// Emits the exact tree body implied by ordered, raw entry fields.
pub fn emit_tree(
    entries: &[TreeEntry],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<Vec<u8>, ObjectError> {
    validate_tree_reference_width(limits.tree_reference_bytes)?;
    if entries.len() > limits.max_tree_entries {
        return Err(ObjectError::TooManyTreeEntries {
            limit: limits.max_tree_entries,
        });
    }
    if profile == AcceptanceProfile::StrictCreate {
        validate_strict_tree(entries)?;
    }
    let mut output = Vec::new();
    for entry in entries {
        validate_tree_mode(&entry.mode, profile)?;
        if profile == AcceptanceProfile::StrictCreate && !is_strict_tree_name(&entry.name) {
            return Err(ObjectError::InvalidStrictTreeName);
        }
        if entry.object_id.len() != limits.tree_reference_bytes {
            return Err(ObjectError::TruncatedTreeReference);
        }
        let entry_len = entry
            .mode
            .len()
            .checked_add(entry.name.len())
            .and_then(|value| value.checked_add(entry.object_id.len()))
            .and_then(|value| value.checked_add(2))
            .ok_or(ObjectError::ObjectTooLarge {
                limit: limits.max_object_bytes,
            })?;
        let total = output
            .len()
            .checked_add(entry_len)
            .ok_or(ObjectError::ObjectTooLarge {
                limit: limits.max_object_bytes,
            })?;
        if total > limits.max_object_bytes {
            return Err(ObjectError::ObjectTooLarge {
                limit: limits.max_object_bytes,
            });
        }
        output
            .try_reserve(entry_len)
            .map_err(|_| ObjectError::AllocationFailure)?;
        output.extend_from_slice(&entry.mode);
        output.push(b' ');
        output.extend_from_slice(&entry.name);
        output.push(0);
        output.extend_from_slice(&entry.object_id);
    }
    Ok(output)
}

/// Compares entries using Git's directory-name-as-name-plus-slash ordering.
#[must_use]
pub fn compare_tree_entries(left: &TreeEntry, right: &TreeEntry) -> Ordering {
    let mut index = 0;
    loop {
        let left_byte = tree_sort_byte(left, index);
        let right_byte = tree_sort_byte(right, index);
        match (left_byte, right_byte) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left_value), Some(right_value)) => match left_value.cmp(&right_value) {
                Ordering::Equal => index += 1,
                ordering => return ordering,
            },
        }
    }
}

/// Generic parsed object body. Commit/tag values retain their exact original bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedObject {
    /// Arbitrary blob bytes.
    Blob(Vec<u8>),
    /// Parsed tree entries.
    Tree(Vec<TreeEntry>),
    /// Parsed commit headers with the original full body retained.
    Commit(Commit),
    /// Parsed annotated-tag headers with the original full body retained.
    Tag(Tag),
}

/// Parses an object body according to its native type.
pub fn parse_object_body(
    object_type: ObjectType,
    body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<ParsedObject, ObjectError> {
    if body.len() > limits.max_object_bytes {
        return Err(ObjectError::ObjectTooLarge {
            limit: limits.max_object_bytes,
        });
    }
    match object_type {
        ObjectType::Blob => copy_bytes(body).map(ParsedObject::Blob),
        ObjectType::Tree => parse_tree(body, profile, limits).map(ParsedObject::Tree),
        ObjectType::Commit => parse_commit(body, profile, limits).map(ParsedObject::Commit),
        ObjectType::Tag => parse_tag(body, profile, limits).map(ParsedObject::Tag),
    }
}

/// Emits a parsed object body. Imported commit/tag bytes are never normalized.
pub fn emit_object_body(
    object: &ParsedObject,
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<Vec<u8>, ObjectError> {
    match object {
        ParsedObject::Blob(body) => checked_body_copy(body, limits),
        ParsedObject::Tree(entries) => emit_tree(entries, profile, limits),
        ParsedObject::Commit(commit) => {
            if profile == AcceptanceProfile::StrictCreate {
                validate_strict_commit(commit.headers(), commit.as_bytes(), limits)?;
            }
            emit_header_object_body(
                commit.headers(),
                commit.message(),
                commit.has_message_separator,
                limits,
            )
        }
        ParsedObject::Tag(tag) => {
            if profile == AcceptanceProfile::StrictCreate {
                validate_strict_tag(tag.headers(), limits)?;
            }
            emit_header_object_body(
                tag.headers(),
                tag.message(),
                tag.has_message_separator,
                limits,
            )
        }
    }
}

/// One ordered commit/tag header, including its continuation lines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderField {
    /// Raw header name bytes.
    pub name: Vec<u8>,
    /// Raw first-line value bytes.
    pub value: Vec<u8>,
    /// Continuation bytes after each leading continuation space.
    pub continuations: Vec<Vec<u8>>,
}

/// A byte-preserving parsed commit object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commit {
    raw: Vec<u8>,
    headers: Vec<HeaderField>,
    message_start: usize,
    has_message_separator: bool,
}

impl Commit {
    /// Returns the exact original body bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Returns ordered headers without sorting or normalization.
    #[must_use]
    pub fn headers(&self) -> &[HeaderField] {
        &self.headers
    }

    /// Returns the exact message suffix, including any trailing bytes.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.raw[self.message_start..]
    }

    /// Returns all raw parent-reference values in original header order.
    pub fn parent_references(&self) -> impl Iterator<Item = &[u8]> {
        self.headers
            .iter()
            .filter(|header| header.name == b"parent")
            .map(|header| header.value.as_slice())
    }

    /// Returns the raw tree-reference value when present.
    #[must_use]
    pub fn tree_reference(&self) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|header| header.name == b"tree")
            .map(|header| header.value.as_slice())
    }
}

/// A byte-preserving parsed annotated-tag object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tag {
    raw: Vec<u8>,
    headers: Vec<HeaderField>,
    message_start: usize,
    has_message_separator: bool,
}

impl Tag {
    /// Returns the exact original body bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Returns ordered headers without sorting or normalization.
    #[must_use]
    pub fn headers(&self) -> &[HeaderField] {
        &self.headers
    }

    /// Returns the exact message suffix, including any trailing bytes.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.raw[self.message_start..]
    }
}

/// Parses a commit while retaining every accepted body byte for exact re-emission.
pub fn parse_commit(
    body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<Commit, ObjectError> {
    let (headers, message_start, has_message_separator) = parse_headers(body, profile, limits)?;
    if profile == AcceptanceProfile::StrictCreate {
        validate_strict_commit(&headers, body, limits)?;
    }
    Ok(Commit {
        raw: copy_bytes(body)?,
        headers,
        message_start,
        has_message_separator,
    })
}

/// Parses an annotated tag while retaining every accepted body byte for exact re-emission.
pub fn parse_tag(
    body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<Tag, ObjectError> {
    let (headers, message_start, has_message_separator) = parse_headers(body, profile, limits)?;
    if profile == AcceptanceProfile::StrictCreate {
        validate_strict_tag(&headers, limits)?;
    }
    Ok(Tag {
        raw: copy_bytes(body)?,
        headers,
        message_start,
        has_message_separator,
    })
}

fn parse_loose_header(
    header: &[u8],
    limits: &ParseLimits,
) -> Result<(ObjectType, usize), ObjectError> {
    let space = header
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(ObjectError::MalformedLooseHeader)?;
    if header[space + 1..].contains(&b' ') {
        return Err(ObjectError::MalformedLooseHeader);
    }
    let type_label =
        std::str::from_utf8(&header[..space]).map_err(|_| ObjectError::UnsupportedObjectType)?;
    let object_type =
        ObjectType::from_label(type_label).ok_or(ObjectError::UnsupportedObjectType)?;
    let length_bytes = &header[space + 1..];
    if length_bytes.is_empty() || !length_bytes.iter().all(u8::is_ascii_digit) {
        return Err(ObjectError::MalformedLooseHeader);
    }
    if length_bytes.len() > 1 && length_bytes[0] == b'0' {
        return Err(ObjectError::NonCanonicalLooseLength);
    }
    let mut value = 0_usize;
    for byte in length_bytes {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(usize::from(*byte - b'0')))
            .ok_or(ObjectError::ObjectTooLarge {
                limit: limits.max_object_bytes,
            })?;
    }
    if value > limits.max_object_bytes {
        return Err(ObjectError::ObjectTooLarge {
            limit: limits.max_object_bytes,
        });
    }
    Ok((object_type, value))
}

const fn validate_tree_reference_width(width: usize) -> Result<(), ObjectError> {
    if matches!(width, 20 | 32) {
        Ok(())
    } else {
        Err(ObjectError::UnsupportedTreeReferenceWidth { width })
    }
}

fn validate_tree_mode(mode: &[u8], profile: AcceptanceProfile) -> Result<(), ObjectError> {
    if mode.is_empty() || !mode.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(ObjectError::MalformedTreeMode);
    }
    if profile == AcceptanceProfile::StrictCreate
        && !matches!(
            mode,
            b"40000" | b"100644" | b"100755" | b"120000" | b"160000"
        )
    {
        return Err(ObjectError::NonCanonicalTreeMode);
    }
    Ok(())
}

fn is_strict_tree_name(name: &[u8]) -> bool {
    !name.is_empty()
        && !name.contains(&b'/')
        && name != b"."
        && name != b".."
        && name.iter().all(|byte| *byte >= b' ' && *byte != 0x7f)
}

fn validate_strict_tree(entries: &[TreeEntry]) -> Result<(), ObjectError> {
    let mut names = BTreeSet::new();
    for entry in entries {
        if !names.insert(entry.name.as_slice()) {
            return Err(ObjectError::DuplicateTreeEntry);
        }
    }
    for pair in entries.windows(2) {
        if compare_tree_entries(&pair[0], &pair[1]) != Ordering::Less {
            return Err(ObjectError::TreeEntriesOutOfOrder);
        }
    }
    Ok(())
}

fn tree_sort_byte(entry: &TreeEntry, index: usize) -> Option<u8> {
    entry
        .name
        .get(index)
        .copied()
        .or_else(|| (index == entry.name.len() && entry.is_tree()).then_some(b'/'))
}

fn parse_headers(
    body: &[u8],
    profile: AcceptanceProfile,
    limits: &ParseLimits,
) -> Result<(Vec<HeaderField>, usize, bool), ObjectError> {
    let boundary = body.windows(2).position(|window| window == b"\n\n");
    let (header_bytes, message_start, has_message_separator) = match boundary {
        Some(index) => (&body[..index], index + 2, true),
        None if profile == AcceptanceProfile::GitCompatibleImport => (body, body.len(), false),
        None => return Err(ObjectError::MissingHeaderMessageSeparator),
    };
    // A Git-compatible object with no header/message separator still has its
    // final header newline.  `split` would otherwise manufacture an empty
    // header after that newline, despite there being no empty separator line
    // in the original body.  Preserve the raw body and its `message_start`,
    // but parse only the actual header lines.
    let header_bytes =
        if !has_message_separator && profile == AcceptanceProfile::GitCompatibleImport {
            header_bytes.strip_suffix(b"\n").unwrap_or(header_bytes)
        } else {
            header_bytes
        };
    let mut headers: Vec<HeaderField> = Vec::new();
    if header_bytes.is_empty() {
        return Ok((headers, message_start, has_message_separator));
    }
    let mut line_count = 0_usize;
    for line in header_bytes.split(|byte| *byte == b'\n') {
        line_count = line_count
            .checked_add(1)
            .ok_or(ObjectError::HeaderLimitExceeded {
                limit: limits.max_header_lines,
            })?;
        if line_count > limits.max_header_lines || line.len() > limits.max_header_line_bytes {
            return Err(ObjectError::HeaderLimitExceeded {
                limit: limits.max_header_lines,
            });
        }
        if line.first() == Some(&b' ') {
            let header = headers
                .last_mut()
                .ok_or(ObjectError::OrphanHeaderContinuation)?;
            header
                .continuations
                .try_reserve(1)
                .map_err(|_| ObjectError::AllocationFailure)?;
            header.continuations.push(copy_bytes(&line[1..])?);
            continue;
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(ObjectError::MalformedHeader)?;
        let name = &line[..separator];
        if name.is_empty() {
            return Err(ObjectError::MalformedHeader);
        }
        if profile == AcceptanceProfile::StrictCreate && !is_strict_header_name(name) {
            return Err(ObjectError::InvalidStrictHeaderName);
        }
        headers
            .try_reserve(1)
            .map_err(|_| ObjectError::AllocationFailure)?;
        headers.push(HeaderField {
            name: copy_bytes(name)?,
            value: copy_bytes(&line[separator + 1..])?,
            continuations: Vec::new(),
        });
    }
    Ok((headers, message_start, has_message_separator))
}

fn is_strict_header_name(name: &[u8]) -> bool {
    name.iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn validate_strict_commit(
    headers: &[HeaderField],
    body: &[u8],
    limits: &ParseLimits,
) -> Result<(), ObjectError> {
    if body.contains(&0) {
        return Err(ObjectError::NulInStrictCommit);
    }
    let Some((tree, remaining)) = headers.split_first() else {
        return Err(ObjectError::MissingOrDuplicateCommitTree);
    };
    if tree.name != b"tree" || !tree.continuations.is_empty() {
        return Err(ObjectError::StrictCommitHeaderOrder);
    }
    validate_native_reference(&tree.value, limits.tree_reference_bytes)?;

    let mut position = 0_usize;
    while let Some(parent) = remaining.get(position) {
        if parent.name != b"parent" {
            break;
        }
        if !parent.continuations.is_empty() {
            return Err(ObjectError::StrictCommitHeaderOrder);
        }
        validate_native_reference(&parent.value, limits.tree_reference_bytes)?;
        position += 1;
    }

    let author_start = position;
    while let Some(author) = remaining.get(position) {
        if author.name != b"author" {
            break;
        }
        if !author.continuations.is_empty() {
            return Err(ObjectError::StrictCommitHeaderOrder);
        }
        validate_signature_date(&author.value)?;
        position += 1;
    }
    let author_count = position - author_start;
    if author_count > 1 {
        return Err(ObjectError::MissingOrDuplicateCommitIdentity);
    }
    if author_count == 0 {
        if remaining[position..]
            .iter()
            .any(|header| matches!(header.name.as_slice(), b"author" | b"committer"))
        {
            return Err(ObjectError::StrictCommitHeaderOrder);
        }
        return Err(ObjectError::MissingOrDuplicateCommitIdentity);
    }

    let Some(committer) = remaining.get(position) else {
        return Err(ObjectError::MissingOrDuplicateCommitIdentity);
    };
    if committer.name != b"committer" || !committer.continuations.is_empty() {
        if remaining[position..]
            .iter()
            .any(|header| header.name == b"committer")
        {
            return Err(ObjectError::StrictCommitHeaderOrder);
        }
        return Err(ObjectError::MissingOrDuplicateCommitIdentity);
    }
    validate_signature_date(&committer.value)?;

    for header in &remaining[position + 1..] {
        if header.name == b"encoding"
            && (header.value.is_empty() || header.value.iter().any(u8::is_ascii_whitespace))
        {
            return Err(ObjectError::MalformedHeader);
        }
    }
    Ok(())
}

fn validate_strict_tag(headers: &[HeaderField], limits: &ParseLimits) -> Result<(), ObjectError> {
    let mut object_count = 0;
    let mut type_count = 0;
    let mut tag_count = 0;
    let mut tagger_count = 0;
    for header in headers {
        match header.name.as_slice() {
            b"object" => {
                object_count += 1;
                validate_native_reference(&header.value, limits.tree_reference_bytes)?;
            }
            b"type" => {
                type_count += 1;
                if !matches!(
                    header.value.as_slice(),
                    b"blob" | b"tree" | b"commit" | b"tag"
                ) {
                    return Err(ObjectError::InvalidTagTargetType);
                }
            }
            b"tag" => {
                tag_count += 1;
                if header.value.is_empty()
                    || header
                        .value
                        .iter()
                        .any(|byte| *byte < b' ' || *byte == 0x7f)
                {
                    return Err(ObjectError::InvalidTagName);
                }
            }
            b"tagger" => {
                tagger_count += 1;
                validate_signature_date(&header.value)?;
            }
            _ => {}
        }
    }
    if object_count != 1 || type_count != 1 || tag_count != 1 || tagger_count != 1 {
        return Err(ObjectError::MissingOrDuplicateTagHeader);
    }
    Ok(())
}

fn validate_native_reference(value: &[u8], object_id_bytes: usize) -> Result<(), ObjectError> {
    validate_tree_reference_width(object_id_bytes)?;
    let expected_hex_bytes =
        object_id_bytes
            .checked_mul(2)
            .ok_or(ObjectError::UnsupportedTreeReferenceWidth {
                width: object_id_bytes,
            })?;
    if value.len() == expected_hex_bytes && value.iter().all(u8::is_ascii_hexdigit) {
        Ok(())
    } else {
        Err(ObjectError::MalformedObjectReference)
    }
}

fn validate_signature_date(value: &[u8]) -> Result<(), ObjectError> {
    let email_start = value
        .iter()
        .position(|byte| *byte == b'<')
        .ok_or(ObjectError::MalformedSignatureDate)?;
    if email_start == 0 || value[email_start - 1] != b' ' {
        return Err(ObjectError::MalformedSignatureDate);
    }
    let after_email = &value[email_start + 1..];
    let email_end = after_email
        .iter()
        .position(|byte| *byte == b'>')
        .ok_or(ObjectError::MalformedSignatureDate)?;
    if email_end == 0 || after_email[..email_end].contains(&b'<') {
        return Err(ObjectError::MalformedSignatureDate);
    }
    let after_identity = &after_email[email_end + 1..];
    let Some(mut timestamp_and_timezone) = after_identity.strip_prefix(b" ") else {
        return Err(ObjectError::MalformedSignatureDate);
    };
    while matches!(timestamp_and_timezone.first(), Some(b' ' | b'\t')) {
        timestamp_and_timezone = &timestamp_and_timezone[1..];
    }
    let timestamp_length = timestamp_and_timezone
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let (timestamp, after_timestamp) = timestamp_and_timezone.split_at(timestamp_length);
    if timestamp.is_empty()
        || (timestamp[0] == b'0' && timestamp.get(1) != Some(&b' '))
        || !after_timestamp.starts_with(b" ")
    {
        return Err(ObjectError::MalformedSignatureDate);
    }
    let timezone = &after_timestamp[1..];
    if timezone.len() != 5
        || !matches!(timezone[0], b'+' | b'-')
        || !timezone[1..].iter().all(u8::is_ascii_digit)
    {
        return Err(ObjectError::MalformedSignatureDate);
    }
    let _timestamp = parse_decimal_u64(timestamp)?;
    Ok(())
}

fn emit_header_object_body(
    headers: &[HeaderField],
    message: &[u8],
    has_message_separator: bool,
    limits: &ParseLimits,
) -> Result<Vec<u8>, ObjectError> {
    let mut output_len = message.len();
    if has_message_separator {
        output_len = output_len
            .checked_add(2)
            .ok_or(ObjectError::ObjectTooLarge {
                limit: limits.max_object_bytes,
            })?;
    }
    for (index, header) in headers.iter().enumerate() {
        let line_prefix = usize::from(index != 0);
        output_len = output_len
            .checked_add(line_prefix)
            .and_then(|length| length.checked_add(header.name.len()))
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(header.value.len()))
            .ok_or(ObjectError::ObjectTooLarge {
                limit: limits.max_object_bytes,
            })?;
        for continuation in &header.continuations {
            output_len = output_len
                .checked_add(2)
                .and_then(|length| length.checked_add(continuation.len()))
                .ok_or(ObjectError::ObjectTooLarge {
                    limit: limits.max_object_bytes,
                })?;
        }
    }
    if output_len > limits.max_object_bytes {
        return Err(ObjectError::ObjectTooLarge {
            limit: limits.max_object_bytes,
        });
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| ObjectError::AllocationFailure)?;
    for (index, header) in headers.iter().enumerate() {
        if index != 0 {
            output.push(b'\n');
        }
        output.extend_from_slice(&header.name);
        output.push(b' ');
        output.extend_from_slice(&header.value);
        for continuation in &header.continuations {
            output.push(b'\n');
            output.push(b' ');
            output.extend_from_slice(continuation);
        }
    }
    if has_message_separator {
        output.extend_from_slice(b"\n\n");
    }
    output.extend_from_slice(message);
    Ok(output)
}

fn parse_decimal_u64(bytes: &[u8]) -> Result<u64, ObjectError> {
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(*byte - b'0')))
            .ok_or(ObjectError::MalformedSignatureDate)
    })
}

fn checked_body_copy(body: &[u8], limits: &ParseLimits) -> Result<Vec<u8>, ObjectError> {
    if body.len() > limits.max_object_bytes {
        return Err(ObjectError::ObjectTooLarge {
            limit: limits.max_object_bytes,
        });
    }
    copy_bytes(body)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, ObjectError> {
    let mut output = Vec::new();
    output
        .try_reserve(bytes.len())
        .map_err(|_| ObjectError::AllocationFailure)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ParseLimits {
        ParseLimits {
            max_object_bytes: 4096,
            max_tree_entries: 16,
            max_header_lines: 32,
            max_header_line_bytes: 512,
            ..ParseLimits::default()
        }
    }

    fn oid(byte: u8, width: usize) -> Vec<u8> {
        vec![byte; width]
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        let text = text.trim();
        assert_eq!(text.len() % 2, 0, "fixture contains whole bytes");
        let bytes = text.as_bytes();
        (0..bytes.len())
            .step_by(2)
            .map(|index| (hex_nibble(bytes[index]) << 4) | hex_nibble(bytes[index + 1]))
            .collect()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("checked-in fixture contains only lowercase hexadecimal"),
        }
    }

    #[test]
    fn fragmented_loose_header_and_payload_round_trip_exactly() {
        let framed = b"blob 5\0hello";
        let mut decoder = LooseObjectDecoder::new(limits());
        decoder.push(&framed[..3]).expect("first fragment accepted");
        decoder
            .push(&framed[3..8])
            .expect("header fragment accepted");
        decoder
            .push(&framed[8..])
            .expect("payload fragment accepted");
        let object = decoder.finish().expect("complete object accepted");
        assert_eq!(object.object_type, ObjectType::Blob);
        assert_eq!(object.body, b"hello");
        assert_eq!(
            object
                .emit_framed_bytes(&limits())
                .expect("bounded frame emit succeeds"),
            framed
        );
    }

    #[test]
    fn loose_frame_refuses_length_mismatch_and_trailing_bytes() {
        assert_eq!(
            parse_loose_framed(b"blob 5\0hell", limits()),
            Err(ObjectError::LooseLengthMismatch {
                declared: 5,
                actual: 4
            })
        );
        assert_eq!(
            parse_loose_framed(b"blob 1\0xy", limits()),
            Err(ObjectError::TrailingLooseBytes)
        );
    }

    #[test]
    fn configured_byte_and_structure_budgets_refuse_before_unbounded_work() {
        let mut object_limited = limits();
        object_limited.max_object_bytes = 0;
        assert_eq!(
            parse_loose_framed(b"blob 1\0x", object_limited),
            Err(ObjectError::ObjectTooLarge { limit: 0 })
        );

        let mut header_limited = limits();
        header_limited.max_loose_header_bytes = 5;
        assert_eq!(
            parse_loose_framed(b"blob 1\0x", header_limited),
            Err(ObjectError::LooseHeaderTooLarge { limit: 5 })
        );

        let entry = TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a".to_vec(),
            object_id: oid(1, 20),
        };
        let mut tree_limited = limits();
        tree_limited.max_tree_entries = 0;
        assert_eq!(
            emit_tree(&[entry], AcceptanceProfile::StrictCreate, &tree_limited),
            Err(ObjectError::TooManyTreeEntries { limit: 0 })
        );

        let commit = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> 1 +0000\ncommitter C <c@x> 1 +0000\n\nmessage";
        let mut commit_headers_limited = limits();
        commit_headers_limited.max_header_lines = 2;
        assert_eq!(
            parse_commit(
                commit,
                AcceptanceProfile::StrictCreate,
                &commit_headers_limited
            ),
            Err(ObjectError::HeaderLimitExceeded { limit: 2 })
        );
    }

    #[test]
    fn checked_in_zlib_loose_blob_decodes_after_trailer_verification() {
        let compressed = decode_hex(include_str!("../tests/corpus/blob-hello.zlib.hex"));
        let object = parse_zlib_loose(&compressed, InflateLimits::GIT_OBJECT, limits())
            .expect("checked-in zlib member and its trailer are valid");
        assert_eq!(object.object_type, ObjectType::Blob);
        assert_eq!(object.body, b"hello");
        assert_eq!(
            object
                .emit_framed_bytes(&limits())
                .expect("parsed loose object remains internally consistent"),
            b"blob 5\0hello"
        );
    }

    #[test]
    fn pinned_git_level9_high_ratio_loose_blob_is_admitted_with_a_bounded_twin_refusal() {
        let compressed = decode_hex(include_str!(
            "../tests/corpus/loose-blob-zeros-1mib-git.zlib.hex"
        ));
        let object = parse_zlib_loose(
            &compressed,
            InflateLimits::GIT_OBJECT,
            ParseLimits::default(),
        )
        .expect("pinned Git 2.54.0 level-9 loose blob remains within Git-object admission limits");
        assert_eq!(object.object_type, ObjectType::Blob);
        assert_eq!(object.body.len(), 1024 * 1024);
        assert!(object.body[..1024 * 1024 - 1].iter().all(|byte| *byte == 0));
        assert_eq!(object.body.last(), Some(&b'x'));

        let limited = InflateLimits {
            max_expansion_ratio: Some(512),
            ..InflateLimits::GIT_OBJECT
        };
        assert!(matches!(
            parse_zlib_loose(&compressed, limited, ParseLimits::default()),
            Err(LooseObjectDecodeError::Inflate(
                InflateRefusal::ResourceLimit {
                    resource: fgit_deflate::Resource::ExpansionRatio,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn planted_malformed_corpus_maps_to_typed_refusals() {
        let loose = decode_hex(include_str!("../tests/corpus/malformed/loose-trailing.hex"));
        assert_eq!(
            parse_loose_framed(&loose, limits()),
            Err(ObjectError::TrailingLooseBytes)
        );
        assert!(parse_loose_framed(b"blob 1\0x", limits()).is_ok());

        let tree = decode_hex(include_str!(
            "../tests/corpus/malformed/tree-truncated-reference.hex"
        ));
        assert_eq!(
            parse_tree(&tree, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::TruncatedTreeReference)
        );
        let valid_tree = vec![TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a".to_vec(),
            object_id: oid(1, 20),
        }];
        assert!(emit_tree(&valid_tree, AcceptanceProfile::StrictCreate, &limits()).is_ok());

        let bad_date = include_bytes!("../tests/corpus/malformed/commit-malformed-date.body");
        assert_eq!(
            parse_commit(bad_date, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::MalformedSignatureDate)
        );
        let permitted_date = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> 1 +0000\ncommitter C <c@x> 1 +0000\n\nmessage";
        assert!(parse_commit(permitted_date, AcceptanceProfile::StrictCreate, &limits()).is_ok());
    }

    #[test]
    fn strict_tree_order_uses_directory_name_plus_slash() {
        let file_a = TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a".to_vec(),
            object_id: oid(1, 20),
        };
        let directory_a = TreeEntry {
            mode: b"40000".to_vec(),
            name: b"a".to_vec(),
            object_id: oid(3, 20),
        };
        let entries = vec![
            TreeEntry {
                mode: b"100644".to_vec(),
                name: b"a-".to_vec(),
                object_id: oid(2, 20),
            },
            directory_a,
            TreeEntry {
                mode: b"100644".to_vec(),
                name: b"a0".to_vec(),
                object_id: oid(4, 20),
            },
        ];
        assert_eq!(compare_tree_entries(&file_a, &entries[0]), Ordering::Less);
        assert_eq!(
            compare_tree_entries(&entries[0], &entries[1]),
            Ordering::Less
        );
        assert_eq!(
            compare_tree_entries(&entries[1], &entries[2]),
            Ordering::Less
        );
        let body = emit_tree(&entries, AcceptanceProfile::StrictCreate, &limits())
            .expect("Git order accepted");
        assert_eq!(
            parse_tree(&body, AcceptanceProfile::StrictCreate, &limits()).expect("tree parses"),
            entries
        );
    }

    #[test]
    fn import_preserves_unordered_legacy_tree_but_strict_refuses_it() {
        let entries = vec![
            TreeEntry {
                mode: b"100755".to_vec(),
                name: b"z".to_vec(),
                object_id: oid(9, 20),
            },
            TreeEntry {
                mode: b"100644".to_vec(),
                name: b"a".to_vec(),
                object_id: oid(8, 20),
            },
        ];
        let body = emit_tree(&entries, AcceptanceProfile::GitCompatibleImport, &limits())
            .expect("import emitter preserves bytes");
        assert_eq!(
            parse_tree(&body, AcceptanceProfile::GitCompatibleImport, &limits())
                .expect("import accepts"),
            entries
        );
        assert_eq!(
            parse_tree(&body, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::TreeEntriesOutOfOrder)
        );
    }

    #[test]
    fn profile_matrix_import_preserves_legacy_mode_and_name() {
        let legacy = vec![TreeEntry {
            mode: b"100600".to_vec(),
            name: b"legacy/name".to_vec(),
            object_id: oid(4, 20),
        }];
        let body = emit_tree(&legacy, AcceptanceProfile::GitCompatibleImport, &limits())
            .expect("import profile preserves bounded legacy entry bytes");
        assert_eq!(
            parse_tree(&body, AcceptanceProfile::GitCompatibleImport, &limits())
                .expect("import profile parses the same entry"),
            legacy
        );
        assert_eq!(
            parse_tree(&body, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::NonCanonicalTreeMode)
        );
    }

    #[test]
    fn strict_tree_rejects_bad_mode_duplicate_and_unsafe_name() {
        let duplicate = vec![
            TreeEntry {
                mode: b"100644".to_vec(),
                name: b"same".to_vec(),
                object_id: oid(1, 20),
            },
            TreeEntry {
                mode: b"40000".to_vec(),
                name: b"same".to_vec(),
                object_id: oid(2, 20),
            },
        ];
        assert_eq!(
            emit_tree(&duplicate, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::DuplicateTreeEntry)
        );
        let invalid_mode = vec![TreeEntry {
            mode: b"100600".to_vec(),
            name: b"ok".to_vec(),
            object_id: oid(1, 20),
        }];
        assert_eq!(
            emit_tree(&invalid_mode, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::NonCanonicalTreeMode)
        );
        let invalid_name = vec![TreeEntry {
            mode: b"100644".to_vec(),
            name: b"a/b".to_vec(),
            object_id: oid(1, 20),
        }];
        assert_eq!(
            emit_tree(&invalid_name, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::InvalidStrictTreeName)
        );
    }

    #[test]
    fn sha_widths_are_separate_parser_configurations() {
        let entries = vec![TreeEntry {
            mode: b"100644".to_vec(),
            name: b"file".to_vec(),
            object_id: oid(1, 32),
        }];
        let mut sha256_limits = limits();
        sha256_limits.tree_reference_bytes = 32;
        let body = emit_tree(&entries, AcceptanceProfile::StrictCreate, &sha256_limits)
            .expect("32-byte references accepted");
        assert!(parse_tree(&body, AcceptanceProfile::StrictCreate, &limits()).is_err());
        assert_eq!(
            parse_tree(&body, AcceptanceProfile::StrictCreate, &sha256_limits)
                .expect("32-byte parser accepts"),
            entries
        );

        let sha256_reference = "a".repeat(64);
        let sha256_commit = format!(
            "tree {sha256_reference}\nauthor A <a@x> 1 +0000\ncommitter C <c@x> 1 +0000\n\nmessage"
        );
        assert!(
            parse_commit(
                sha256_commit.as_bytes(),
                AcceptanceProfile::StrictCreate,
                &sha256_limits
            )
            .is_ok()
        );
        assert_eq!(
            parse_commit(
                sha256_commit.as_bytes(),
                AcceptanceProfile::StrictCreate,
                &limits()
            ),
            Err(ObjectError::MalformedObjectReference)
        );

        let mut unsupported_width = limits();
        unsupported_width.tree_reference_bytes = 24;
        assert_eq!(
            parse_commit(
                b"tree 111111111111111111111111111111111111111111111111\nauthor A <a@x> 1 +0000\ncommitter C <c@x> 1 +0000\n\nmessage",
                AcceptanceProfile::StrictCreate,
                &unsupported_width
            ),
            Err(ObjectError::UnsupportedTreeReferenceWidth { width: 24 })
        );
    }

    #[test]
    fn native_oid_algorithm_markers_cannot_alias() {
        let sha1: GitOid<Sha1> = native_object_oid::<Sha1>(ObjectType::Blob, b"same body");
        let sha256: GitOid<Sha256> = native_object_oid::<Sha256>(ObjectType::Blob, b"same body");
        assert_eq!(sha1.as_bytes().len(), 20);
        assert_eq!(sha256.as_bytes().len(), 32);
    }

    #[test]
    fn incremental_hasher_commits_the_same_framed_native_object() {
        let expected: GitOid<Sha1> = native_object_oid::<Sha1>(ObjectType::Blob, b"hello");
        let mut hasher = native_object_hasher::<Sha1>(ObjectType::Blob, 5)
            .expect("a bounded usize fits the native length field");
        hasher.update(b"he").expect("first chunk fits declaration");
        hasher
            .update(b"llo")
            .expect("second chunk completes declaration");
        assert_eq!(
            hasher.finish().expect("exact length completes hashing"),
            expected
        );

        let mut overrun = native_object_hasher::<Sha256>(ObjectType::Blob, 1)
            .expect("small declaration is representable");
        assert_eq!(
            overrun.update(b"xy"),
            Err(fgit_crypto::GitHashError::DeclaredLengthOverrun {
                declared: 1,
                received: 2,
            })
        );
    }

    #[test]
    fn checked_in_corpus_reconstructs_exact_object_bodies() {
        let limits = limits();
        let blob = b"checked-in blob\n";
        let tree_entries = vec![TreeEntry {
            mode: b"100644".to_vec(),
            name: b"corpus-file".to_vec(),
            object_id: oid(7, 20),
        }];
        let tree = emit_tree(&tree_entries, AcceptanceProfile::StrictCreate, &limits)
            .expect("strict tree corpus constructs");
        let corpus = [
            (
                ObjectType::Blob,
                blob.as_slice(),
                AcceptanceProfile::StrictCreate,
            ),
            (
                ObjectType::Tree,
                tree.as_slice(),
                AcceptanceProfile::StrictCreate,
            ),
            (
                ObjectType::Commit,
                include_bytes!("../tests/corpus/commit.body").as_slice(),
                AcceptanceProfile::GitCompatibleImport,
            ),
            (
                ObjectType::Tag,
                include_bytes!("../tests/corpus/tag.body").as_slice(),
                AcceptanceProfile::StrictCreate,
            ),
        ];
        for (object_type, body, profile) in corpus {
            let framed = emit_loose_framed(object_type, body, &limits)
                .expect("bounded loose corpus frame constructs");
            let parsed_loose =
                parse_loose_framed(&framed, limits.clone()).expect("loose corpus parses");
            let parsed = parse_object_body(
                parsed_loose.object_type,
                &parsed_loose.body,
                profile,
                &limits,
            )
            .expect("structured corpus parses");
            let emitted_body =
                emit_object_body(&parsed, profile, &limits).expect("structured corpus emits");
            assert_eq!(
                emit_loose_framed(object_type, &emitted_body, &limits)
                    .expect("loose corpus re-emits"),
                framed
            );
        }
    }

    #[test]
    fn commit_preserves_multiple_parents_signatures_and_extra_header_order() {
        let tree = "1".repeat(40);
        let parent_a = "2".repeat(40);
        let parent_b = "3".repeat(40);
        let body = format!(
            "tree {tree}\nparent {parent_a}\nparent {parent_b}\nauthor A U Thor <a@example.com> 1700000000 +0000\ncommitter C Ommitter <c@example.com> 1700000001 -0530\nmergetag object {tree}\n extra signed body\ngpgsig -----BEGIN SIGNATURE-----\n continued signature\nencoding ISO-8859-1\nx-custom opaque\n\nmessage"
        );
        let commit = parse_commit(body.as_bytes(), AcceptanceProfile::StrictCreate, &limits())
            .expect("strict commit accepted");
        assert_eq!(commit.parent_references().count(), 2);
        assert_eq!(commit.headers()[6].name, b"gpgsig");
        assert_eq!(commit.as_bytes(), body.as_bytes());
        assert_eq!(commit.message(), b"message");
        assert_eq!(
            emit_object_body(
                &ParsedObject::Commit(commit),
                AcceptanceProfile::StrictCreate,
                &limits()
            )
            .expect("strict commit fields reconstruct"),
            body.as_bytes()
        );
    }

    #[test]
    fn import_preserves_out_of_order_commit_headers_but_strict_refuses_them() {
        let tree = "1".repeat(40);
        let parent = "2".repeat(40);
        let body = format!(
            "tree {tree}\nparent {parent}\nmergetag object {tree}\n extra signed body\ngpgsig -----BEGIN SIGNATURE-----\n continued signature\nencoding ISO-8859-1\nx-custom opaque\nauthor A U Thor <a@example.com> 1700000000 +0000\ncommitter C Ommitter <c@example.com> 1700000001 -0530\n\nmessage"
        );
        let imported = parse_commit(
            body.as_bytes(),
            AcceptanceProfile::GitCompatibleImport,
            &limits(),
        )
        .expect("import profile preserves bounded unusual header order");
        assert_eq!(
            emit_object_body(
                &ParsedObject::Commit(imported),
                AcceptanceProfile::GitCompatibleImport,
                &limits()
            )
            .expect("imported fields reconstruct"),
            body.as_bytes()
        );
        assert_eq!(
            parse_commit(body.as_bytes(), AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::StrictCommitHeaderOrder)
        );
    }

    #[test]
    fn strict_commit_refuses_nul_while_import_preserves_it() {
        let body = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> 1 +0000\ncommitter C <c@x> 1 +0000\n\nmessage\0tail";
        assert!(parse_commit(body, AcceptanceProfile::GitCompatibleImport, &limits()).is_ok());
        assert_eq!(
            parse_commit(body, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::NulInStrictCommit)
        );
    }

    #[test]
    fn import_accepts_missing_separator_but_strict_refuses() {
        let body = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> 1 +0000\ncommitter C <c@x> 1 +0000\n";
        assert!(parse_commit(body, AcceptanceProfile::GitCompatibleImport, &limits()).is_ok());
        assert_eq!(
            parse_commit(body, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::MissingHeaderMessageSeparator)
        );
    }

    #[test]
    fn strict_commit_date_syntax_matches_git_fsck_edges() {
        let malformed = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> bad +0000\ncommitter C <c@x> 1 +0000\n\nmessage";
        assert_eq!(
            parse_commit(malformed, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::MalformedSignatureDate)
        );
        let zero_padded = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> 01 +0000\ncommitter C <c@x> 1 +0000\n\nmessage";
        assert_eq!(
            parse_commit(zero_padded, AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::MalformedSignatureDate)
        );
        assert!(
            parse_commit(
                zero_padded,
                AcceptanceProfile::GitCompatibleImport,
                &limits()
            )
            .is_ok()
        );
        let git_permitted = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> 1 +9900\ncommitter C <c@x> 1 +9900\n\nmessage";
        assert!(parse_commit(git_permitted, AcceptanceProfile::StrictCreate, &limits()).is_ok());
        let malformed_timezone = b"tree 1111111111111111111111111111111111111111\nauthor A <a@x> 1 +9x00\ncommitter C <c@x> 1 +0000\n\nmessage";
        assert_eq!(
            parse_commit(
                malformed_timezone,
                AcceptanceProfile::StrictCreate,
                &limits()
            ),
            Err(ObjectError::MalformedSignatureDate)
        );
    }

    #[test]
    fn annotated_tag_round_trips_and_refuses_bad_target_type() {
        let object = "f".repeat(40);
        let body = format!(
            "object {object}\ntype commit\ntag v1.0\ntagger T Agger <t@example.com> 1700000000 +0000\n\nrelease\n"
        );
        let tag = parse_tag(body.as_bytes(), AcceptanceProfile::StrictCreate, &limits())
            .expect("tag accepted");
        assert_eq!(tag.as_bytes(), body.as_bytes());
        let bad = format!("object {object}\ntype future\ntag v1\ntagger T <t@x> 1 +0000\n\n");
        assert_eq!(
            parse_tag(bad.as_bytes(), AcceptanceProfile::StrictCreate, &limits()),
            Err(ObjectError::InvalidTagTargetType)
        );
    }
}
