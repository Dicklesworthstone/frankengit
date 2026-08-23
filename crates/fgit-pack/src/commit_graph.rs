//! Deterministic, derived commit-graph V1 materialization.
//!
//! A commit graph accelerates graph traversal over already admitted native Git
//! commits.  It is never an authority source: this module requires callers to
//! name the authority snapshot that selected its input, verifies every supplied
//! commit body against its native object identity, and refuses a parent closure
//! that is not complete.  A graph reader must still authenticate repository
//! state before using this derived output to answer a request.

use crate::{Deadline, ObjectFormat, ObjectId, PackError, checkpoint};
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_git_object::{AcceptanceProfile, HeaderField, ParseLimits, parse_commit};
use fgit_types::{RepositoryCommitId, RepositoryId};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const COMMIT_GRAPH_SIGNATURE: &[u8; 4] = b"CGPH";
const COMMIT_GRAPH_VERSION_V1: u8 = 1;
const COMMIT_GRAPH_HEADER_BYTES: usize = 8;
const COMMIT_GRAPH_TOC_ENTRY_BYTES: usize = 12;
const COMMIT_GRAPH_FANOUT_BYTES: usize = 256 * 4;
const COMMIT_GRAPH_DATA_SUFFIX_BYTES: usize = 16;
const NO_PARENT: u32 = 0x7000_0000;
const EDGE_LAST_BIT: u32 = 0x8000_0000;
const MAX_GRAPH_POSITION: usize = NO_PARENT as usize;
const MAX_GENERATION: u32 = (1 << 30) - 1;
const MAX_COMMIT_TIME: u64 = (1_u64 << 34) - 1;

const CHUNK_OID_FANOUT: [u8; 4] = *b"OIDF";
const CHUNK_OID_LOOKUP: [u8; 4] = *b"OIDL";
const CHUNK_COMMIT_DATA: [u8; 4] = *b"CDAT";
const CHUNK_EXTRA_EDGES: [u8; 4] = *b"EDGE";

/// Bounds selected before the commit-graph materializer parses, retains, or
/// emits native commit metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitGraphLimits {
    /// Most commit bodies retained in a single graph file.
    pub max_commits: usize,
    /// Most parents accepted from one commit body.
    pub max_parents_per_commit: usize,
    /// Most parent edges retained across the complete graph.
    pub max_edges: usize,
    /// Most input bytes retained across all supplied commit bodies.
    pub max_total_input_bytes: usize,
    /// Most bytes in the complete graph, including its native checksum.
    pub max_output_bytes: usize,
    /// Object-parser limits used for every supplied commit body.
    pub object_parse: ParseLimits,
}

impl Default for CommitGraphLimits {
    fn default() -> Self {
        Self {
            max_commits: 10_000_000,
            max_parents_per_commit: 64,
            max_edges: 64_000_000,
            max_total_input_bytes: 512 * 1024 * 1024,
            max_output_bytes: 1024 * 1024 * 1024,
            object_parse: ParseLimits::default(),
        }
    }
}

/// Frozen profile for the first supported standard commit-graph layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitGraphProfile {
    /// Standard V1 chunks with generation-number-v1 and no corrected-date or
    /// changed-path Bloom-filter chunks.
    V1GenerationNumber,
}

/// Exact input coverage represented by one derived commit graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitGraphCompleteness {
    /// The graph contains every supplied commit and requires every named
    /// parent to be supplied in the same materialization input.
    ClosedSuppliedCommitSetV1,
}

/// Verification performed before a commit record enters this graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitGraphVerification {
    /// Every body matched its native Git commit identity and passed the strict
    /// commit parser with the selected bounds.  This does not publish or
    /// authenticate the authority coordinate named in the receipt.
    NativeCommitIdentityAndStrictHeadersV1,
}

/// Exact authority-selected source coordinates for a derived commit graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitGraphSource {
    repository_id: RepositoryId,
    source_rcr_id: RepositoryCommitId,
    source_commit_oid: ObjectId,
}

impl CommitGraphSource {
    /// Constructs source coordinates and refuses Git's all-zero non-object
    /// sentinel as the selected source commit.
    pub fn new(
        repository_id: RepositoryId,
        source_rcr_id: RepositoryCommitId,
        source_commit_oid: ObjectId,
    ) -> Result<Self, CommitGraphRefusal> {
        if source_commit_oid.is_zero() {
            return Err(CommitGraphRefusal::ZeroObjectId {
                subject: "source commit",
            });
        }
        Ok(Self {
            repository_id,
            source_rcr_id,
            source_commit_oid,
        })
    }

    /// Repository whose authority read selected this derived input.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Canonical RCR used to select the commit closure.
    #[must_use]
    pub const fn source_rcr_id(&self) -> RepositoryCommitId {
        self.source_rcr_id
    }

    /// Source commit which must occur in the closed graph input.
    #[must_use]
    pub const fn source_commit_oid(&self) -> &ObjectId {
        &self.source_commit_oid
    }
}

/// One commit body selected for materialization, named by its native Git OID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitGraphInput {
    commit_oid: ObjectId,
    body: Vec<u8>,
}

impl CommitGraphInput {
    /// Creates one named commit input.  Native identity is verified by
    /// [`CommitGraphV1::write`] once the repository object format is known.
    pub fn new(commit_oid: ObjectId, body: Vec<u8>) -> Result<Self, CommitGraphRefusal> {
        if commit_oid.is_zero() {
            return Err(CommitGraphRefusal::ZeroObjectId { subject: "commit" });
        }
        Ok(Self { commit_oid, body })
    }

    /// Claimed native Git commit object identity.
    #[must_use]
    pub const fn commit_oid(&self) -> &ObjectId {
        &self.commit_oid
    }

    /// Exact decompressed commit body, excluding loose-object framing.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Immutable evidence for one derived commit-graph output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitGraphV1Receipt {
    source: CommitGraphSource,
    profile: CommitGraphProfile,
    completeness: CommitGraphCompleteness,
    verification: CommitGraphVerification,
    commit_count: usize,
    edge_count: usize,
    checksum: ObjectId,
    output_bytes: usize,
}

impl CommitGraphV1Receipt {
    /// Authority-selected source coordinate recorded before materialization.
    #[must_use]
    pub const fn source(&self) -> &CommitGraphSource {
        &self.source
    }

    /// Frozen binary/profile shape of this graph.
    #[must_use]
    pub const fn profile(&self) -> CommitGraphProfile {
        self.profile
    }

    /// Exact scope of the closed input set.
    #[must_use]
    pub const fn completeness(&self) -> CommitGraphCompleteness {
        self.completeness
    }

    /// Verification boundary crossed before graph data was retained.
    #[must_use]
    pub const fn verification(&self) -> CommitGraphVerification {
        self.verification
    }

    /// Number of commit records emitted in OID order.
    #[must_use]
    pub const fn commit_count(&self) -> usize {
        self.commit_count
    }

    /// Number of values emitted in the optional `EDGE` chunk.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edge_count
    }

    /// Native graph checksum over every preceding output byte.
    #[must_use]
    pub const fn checksum(&self) -> &ObjectId {
        &self.checksum
    }

    /// Complete output length including the native trailing checksum.
    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }
}

/// Complete standard commit-graph V1 bytes and their derived receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitGraphV1 {
    bytes: Vec<u8>,
    receipt: CommitGraphV1Receipt,
}

impl CommitGraphV1 {
    /// Materializes standard commit-graph V1 bytes from a complete, verified
    /// commit closure.  The output is a derived accelerator only: it cannot
    /// authorize reads, advance a ref, or substitute for an authority read.
    pub fn write(
        source: CommitGraphSource,
        inputs: &[CommitGraphInput],
        limits: &CommitGraphLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, CommitGraphRefusal> {
        if inputs.is_empty() {
            return Err(CommitGraphRefusal::EmptyCommitSet);
        }
        if inputs.len() > limits.max_commits {
            return Err(CommitGraphRefusal::CommitLimitExceeded {
                observed: inputs.len(),
                limit: limits.max_commits,
            });
        }
        if inputs.len() >= MAX_GRAPH_POSITION {
            return Err(CommitGraphRefusal::FormatCommitLimitExceeded {
                observed: inputs.len(),
            });
        }

        let format = source.source_commit_oid().algorithm();
        let parse_limits = parse_limits_for(format, &limits.object_parse);
        let mut total_input_bytes = 0_usize;
        let mut commits = Vec::new();
        commits.try_reserve_exact(inputs.len()).map_err(|_| {
            CommitGraphRefusal::AllocationFailed {
                requested: inputs.len(),
            }
        })?;
        let mut known = BTreeSet::new();
        for input in inputs {
            checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
            if input.commit_oid.algorithm() != format {
                return Err(CommitGraphRefusal::ObjectFormatMismatch {
                    subject: "commit",
                    expected: format,
                    observed: input.commit_oid.algorithm(),
                });
            }
            total_input_bytes = total_input_bytes
                .checked_add(input.body.len())
                .ok_or(CommitGraphRefusal::SizeOverflow)?;
            if total_input_bytes > limits.max_total_input_bytes {
                return Err(CommitGraphRefusal::InputBytesExceeded {
                    observed: total_input_bytes,
                    limit: limits.max_total_input_bytes,
                });
            }
            if input.body.len() > parse_limits.max_object_bytes {
                return Err(CommitGraphRefusal::CommitBodyTooLarge {
                    object: input.commit_oid,
                    observed: input.body.len(),
                    limit: parse_limits.max_object_bytes,
                });
            }
            if !known.insert(input.commit_oid) {
                return Err(CommitGraphRefusal::DuplicateCommit {
                    object: input.commit_oid,
                });
            }
            let actual = git_object_id(format, GitObjectKind::Commit, &input.body);
            if actual != input.commit_oid {
                return Err(CommitGraphRefusal::CommitIdentityMismatch {
                    expected: input.commit_oid,
                    actual,
                });
            }
            let parsed = parse_commit(&input.body, AcceptanceProfile::StrictCreate, &parse_limits)
                .map_err(CommitGraphRefusal::Object)?;
            let tree = parse_reference(
                parsed
                    .tree_reference()
                    .ok_or(CommitGraphRefusal::MissingTree {
                        object: input.commit_oid,
                    })?,
                format,
                input.commit_oid,
                "tree",
            )?;
            if tree.is_zero() {
                return Err(CommitGraphRefusal::ZeroObjectId { subject: "tree" });
            }
            let mut parents = Vec::new();
            parents
                .try_reserve_exact(parsed.parent_references().size_hint().0)
                .map_err(|_| CommitGraphRefusal::AllocationFailed {
                    requested: parsed.parent_references().size_hint().0,
                })?;
            let mut parent_set = BTreeSet::new();
            for reference in parsed.parent_references() {
                checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
                if parents.len() >= limits.max_parents_per_commit {
                    return Err(CommitGraphRefusal::ParentLimitExceeded {
                        commit: input.commit_oid,
                        observed: parents.len().saturating_add(1),
                        limit: limits.max_parents_per_commit,
                    });
                }
                let parent = parse_reference(reference, format, input.commit_oid, "parent")?;
                if parent.is_zero() {
                    return Err(CommitGraphRefusal::ZeroObjectId { subject: "parent" });
                }
                if !parent_set.insert(parent) {
                    return Err(CommitGraphRefusal::DuplicateParent {
                        commit: input.commit_oid,
                        parent,
                    });
                }
                parents.push(parent);
            }
            commits.push(ParsedCommit {
                oid: input.commit_oid,
                tree,
                parents,
                commit_time: committer_time(parsed.headers(), input.commit_oid)?,
            });
        }
        if !known.contains(source.source_commit_oid()) {
            return Err(CommitGraphRefusal::SourceCommitMissing {
                object: *source.source_commit_oid(),
            });
        }

        commits.sort_unstable_by_key(|commit| commit.oid);
        let mut positions = BTreeMap::new();
        for (position, commit) in commits.iter().enumerate() {
            positions.insert(
                commit.oid,
                u32::try_from(position).map_err(|_| {
                    CommitGraphRefusal::FormatCommitLimitExceeded {
                        observed: commits.len(),
                    }
                })?,
            );
        }

        let mut parent_positions = Vec::new();
        parent_positions
            .try_reserve_exact(commits.len())
            .map_err(|_| CommitGraphRefusal::AllocationFailed {
                requested: commits.len(),
            })?;
        let mut child_counts = zeroed_usize(commits.len())?;
        let mut edge_count = 0_usize;
        for commit in &commits {
            checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
            let mut positions_for_commit = Vec::new();
            positions_for_commit
                .try_reserve_exact(commit.parents.len())
                .map_err(|_| CommitGraphRefusal::AllocationFailed {
                    requested: commit.parents.len(),
                })?;
            for parent in &commit.parents {
                edge_count = edge_count
                    .checked_add(1)
                    .ok_or(CommitGraphRefusal::SizeOverflow)?;
                if edge_count > limits.max_edges {
                    return Err(CommitGraphRefusal::EdgeLimitExceeded {
                        observed: edge_count,
                        limit: limits.max_edges,
                    });
                }
                let position = positions.get(parent).copied().ok_or(
                    CommitGraphRefusal::ParentOutsideInput {
                        commit: commit.oid,
                        parent: *parent,
                    },
                )?;
                let child_count = child_counts
                    .get_mut(position as usize)
                    .ok_or(CommitGraphRefusal::SizeOverflow)?;
                *child_count = child_count
                    .checked_add(1)
                    .ok_or(CommitGraphRefusal::SizeOverflow)?;
                positions_for_commit.push(position);
            }
            parent_positions.push(positions_for_commit);
        }

        let mut children = Vec::new();
        children.try_reserve_exact(commits.len()).map_err(|_| {
            CommitGraphRefusal::AllocationFailed {
                requested: commits.len(),
            }
        })?;
        for count in child_counts {
            let mut descendants = Vec::new();
            descendants
                .try_reserve_exact(count)
                .map_err(|_| CommitGraphRefusal::AllocationFailed { requested: count })?;
            children.push(descendants);
        }
        for (child, parents) in parent_positions.iter().enumerate() {
            for parent in parents {
                children[*parent as usize].push(child);
            }
        }

        let generations = generation_numbers(&parent_positions, &children, deadline)?;
        let edge_count = extra_edge_count(&parent_positions)?;
        let output_bytes = output_bytes(format, commits.len(), edge_count)?;
        if output_bytes > limits.max_output_bytes {
            return Err(CommitGraphRefusal::OutputBytesExceeded {
                observed: output_bytes,
                limit: limits.max_output_bytes,
            });
        }
        let edge_values = encode_edge_values(&parent_positions, edge_count, deadline)?;
        let bytes = encode(
            format,
            &commits,
            &parent_positions,
            &generations,
            &edge_values,
            output_bytes,
            deadline,
        )?;
        if bytes.len() != output_bytes {
            return Err(CommitGraphRefusal::OutputMismatch {
                expected: output_bytes,
                actual: bytes.len(),
            });
        }
        let checksum = checksum(format, &bytes[..bytes.len() - format.digest_len()]);
        Ok(Self {
            bytes,
            receipt: CommitGraphV1Receipt {
                source,
                profile: CommitGraphProfile::V1GenerationNumber,
                completeness: CommitGraphCompleteness::ClosedSuppliedCommitSetV1,
                verification: CommitGraphVerification::NativeCommitIdentityAndStrictHeadersV1,
                commit_count: commits.len(),
                edge_count,
                checksum,
                output_bytes,
            },
        })
    }

    /// Exact commit-graph bytes, including the native trailing checksum.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derived receipt describing this immutable output.
    #[must_use]
    pub const fn receipt(&self) -> &CommitGraphV1Receipt {
        &self.receipt
    }
}

/// Why a commit-graph V1 materialization was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitGraphRefusal {
    /// A graph requires at least one selected commit.
    EmptyCommitSet,
    /// The selected commit count exceeded the caller's bound.
    CommitLimitExceeded { observed: usize, limit: usize },
    /// The standard V1 parent-position domain cannot represent this many commits.
    FormatCommitLimitExceeded { observed: usize },
    /// A supplied identity belongs to a different native Git object format.
    ObjectFormatMismatch {
        subject: &'static str,
        expected: ObjectFormat,
        observed: ObjectFormat,
    },
    /// A source, commit, tree, or parent used Git's all-zero non-object sentinel.
    ZeroObjectId { subject: &'static str },
    /// The same commit identity appeared more than once in the input.
    DuplicateCommit { object: ObjectId },
    /// The exact input bytes did not hash to their claimed native commit OID.
    CommitIdentityMismatch {
        expected: ObjectId,
        actual: ObjectId,
    },
    /// The strict commit parser rejected the supplied body.
    Object(fgit_git_object::ObjectError),
    /// A strict commit unexpectedly exposed no tree reference.
    MissingTree { object: ObjectId },
    /// A tree or parent reference could not become the selected native OID type.
    MalformedReference {
        commit: ObjectId,
        field: &'static str,
    },
    /// A parent occurred more than once in one commit's ordered parent list.
    DuplicateParent { commit: ObjectId, parent: ObjectId },
    /// A commit exceeded its configured parent bound before another parent was retained.
    ParentLimitExceeded {
        commit: ObjectId,
        observed: usize,
        limit: usize,
    },
    /// Aggregate selected parent edges exceeded their configured bound.
    EdgeLimitExceeded { observed: usize, limit: usize },
    /// A required parent was missing from the selected closure.
    ParentOutsideInput { commit: ObjectId, parent: ObjectId },
    /// A strict commit lacked a usable committer timestamp.
    MissingCommitterTime { commit: ObjectId },
    /// A committer timestamp could not fit standard V1's 34-bit field.
    CommitterTimeOutOfRange { commit: ObjectId, time: u64 },
    /// The selected parent closure contains a cycle, so generation numbers are undefined.
    ParentCycle,
    /// The authority-selected source commit was absent from the selected graph.
    SourceCommitMissing { object: ObjectId },
    /// Total supplied body bytes exceeded the configured bound.
    InputBytesExceeded { observed: usize, limit: usize },
    /// An individual body exceeded the selected strict parser bound.
    CommitBodyTooLarge {
        object: ObjectId,
        observed: usize,
        limit: usize,
    },
    /// The complete graph output would exceed the selected bound.
    OutputBytesExceeded { observed: usize, limit: usize },
    /// Checked arithmetic overflowed while planning graph metadata or bytes.
    SizeOverflow,
    /// Bounded graph metadata or output could not be reserved.
    AllocationFailed { requested: usize },
    /// A deadline/cancellation checkpoint refused work before output publication.
    Pack(PackError),
    /// Precomputed and emitted graph output lengths disagreed.
    OutputMismatch { expected: usize, actual: usize },
}

impl Display for CommitGraphRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommitSet => formatter.write_str("commit graph needs one commit"),
            Self::CommitLimitExceeded { observed, limit } => {
                write!(formatter, "{observed} commits exceeds limit {limit}")
            }
            Self::FormatCommitLimitExceeded { observed } => write!(
                formatter,
                "{observed} commits exceeds the V1 parent-position domain"
            ),
            Self::ObjectFormatMismatch {
                subject,
                expected,
                observed,
            } => write!(
                formatter,
                "commit graph {subject} has format {observed:?}, expected {expected:?}"
            ),
            Self::ZeroObjectId { subject } => {
                write!(
                    formatter,
                    "commit graph {subject} uses the zero non-object ID"
                )
            }
            Self::DuplicateCommit { object } => write!(formatter, "duplicate commit {object}"),
            Self::CommitIdentityMismatch { expected, actual } => write!(
                formatter,
                "commit body hashes to {actual}, not claimed identity {expected}"
            ),
            Self::Object(error) => write!(formatter, "strict commit parse refused: {error}"),
            Self::MissingTree { object } => write!(formatter, "commit {object} has no tree"),
            Self::MalformedReference { commit, field } => {
                write!(formatter, "commit {commit} has malformed {field} reference")
            }
            Self::DuplicateParent { commit, parent } => {
                write!(formatter, "commit {commit} repeats parent {parent}")
            }
            Self::ParentLimitExceeded {
                commit,
                observed,
                limit,
            } => write!(
                formatter,
                "commit {commit} has {observed} parents, limit is {limit}"
            ),
            Self::EdgeLimitExceeded { observed, limit } => {
                write!(formatter, "{observed} graph edges exceeds limit {limit}")
            }
            Self::ParentOutsideInput { commit, parent } => write!(
                formatter,
                "commit {commit} names parent {parent} outside the selected closure"
            ),
            Self::MissingCommitterTime { commit } => {
                write!(
                    formatter,
                    "commit {commit} has no usable committer timestamp"
                )
            }
            Self::CommitterTimeOutOfRange { commit, time } => write!(
                formatter,
                "commit {commit} timestamp {time} exceeds V1's 34-bit domain"
            ),
            Self::ParentCycle => formatter.write_str("commit parent closure contains a cycle"),
            Self::SourceCommitMissing { object } => {
                write!(
                    formatter,
                    "source commit {object} is absent from selected graph"
                )
            }
            Self::InputBytesExceeded { observed, limit } => {
                write!(
                    formatter,
                    "commit input has {observed} bytes, limit is {limit}"
                )
            }
            Self::CommitBodyTooLarge {
                object,
                observed,
                limit,
            } => write!(
                formatter,
                "commit {object} has {observed} bytes, parser limit is {limit}"
            ),
            Self::OutputBytesExceeded { observed, limit } => {
                write!(
                    formatter,
                    "commit graph has {observed} bytes, limit is {limit}"
                )
            }
            Self::SizeOverflow => formatter.write_str("commit graph V1 size overflowed"),
            Self::AllocationFailed { requested } => {
                write!(
                    formatter,
                    "commit graph could not reserve {requested} elements or bytes"
                )
            }
            Self::Pack(error) => write!(formatter, "commit graph checkpoint refused: {error}"),
            Self::OutputMismatch { expected, actual } => write!(
                formatter,
                "commit graph emitted {actual} bytes after planning {expected}"
            ),
        }
    }
}

impl core::error::Error for CommitGraphRefusal {}

struct ParsedCommit {
    oid: ObjectId,
    tree: ObjectId,
    parents: Vec<ObjectId>,
    commit_time: u64,
}

fn parse_limits_for(format: ObjectFormat, selected: &ParseLimits) -> ParseLimits {
    let mut limits = selected.clone();
    limits.tree_reference_bytes = format.digest_len();
    limits
}

fn parse_reference(
    reference: &[u8],
    format: ObjectFormat,
    commit: ObjectId,
    field: &'static str,
) -> Result<ObjectId, CommitGraphRefusal> {
    let reference = core::str::from_utf8(reference)
        .map_err(|_| CommitGraphRefusal::MalformedReference { commit, field })?;
    ObjectId::from_hex(format, reference)
        .map_err(|_| CommitGraphRefusal::MalformedReference { commit, field })
}

fn committer_time(headers: &[HeaderField], commit: ObjectId) -> Result<u64, CommitGraphRefusal> {
    let value = headers
        .iter()
        .find(|header| header.name == b"committer")
        .map(|header| header.value.as_slice())
        .ok_or(CommitGraphRefusal::MissingCommitterTime { commit })?;
    let close = value
        .iter()
        .rposition(|byte| *byte == b'>')
        .ok_or(CommitGraphRefusal::MissingCommitterTime { commit })?;
    let mut remainder = &value[close.saturating_add(1)..];
    while matches!(remainder.first(), Some(b' ' | b'\t')) {
        remainder = &remainder[1..];
    }
    let digits = remainder
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .copied();
    let mut timestamp = 0_u64;
    let mut saw_digit = false;
    for digit in digits {
        saw_digit = true;
        timestamp = timestamp
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(CommitGraphRefusal::MissingCommitterTime { commit })?;
    }
    if !saw_digit {
        return Err(CommitGraphRefusal::MissingCommitterTime { commit });
    }
    if timestamp > MAX_COMMIT_TIME {
        return Err(CommitGraphRefusal::CommitterTimeOutOfRange {
            commit,
            time: timestamp,
        });
    }
    Ok(timestamp)
}

fn generation_numbers(
    parents: &[Vec<u32>],
    children: &[Vec<usize>],
    deadline: &mut impl Deadline,
) -> Result<Vec<u32>, CommitGraphRefusal> {
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(parents.len())
        .map_err(|_| CommitGraphRefusal::AllocationFailed {
            requested: parents.len(),
        })?;
    let mut highest_parent = zeroed_u32(parents.len())?;
    let mut ready = VecDeque::new();
    for parent_set in parents {
        pending.push(parent_set.len());
    }
    for (position, count) in pending.iter().enumerate() {
        if *count == 0 {
            ready.push_back(position);
        }
    }
    let mut generations = zeroed_u32(parents.len())?;
    let mut processed = 0_usize;
    while let Some(parent) = ready.pop_front() {
        checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
        let generation = if parents[parent].is_empty() {
            1
        } else {
            highest_parent[parent]
                .checked_add(1)
                .ok_or(CommitGraphRefusal::SizeOverflow)?
        };
        if generation > MAX_GENERATION {
            return Err(CommitGraphRefusal::SizeOverflow);
        }
        generations[parent] = generation;
        processed = processed
            .checked_add(1)
            .ok_or(CommitGraphRefusal::SizeOverflow)?;
        for child in &children[parent] {
            highest_parent[*child] = highest_parent[*child].max(generation);
            let remaining = pending
                .get_mut(*child)
                .ok_or(CommitGraphRefusal::SizeOverflow)?;
            *remaining = remaining
                .checked_sub(1)
                .ok_or(CommitGraphRefusal::SizeOverflow)?;
            if *remaining == 0 {
                ready.push_back(*child);
            }
        }
    }
    if processed != parents.len() {
        return Err(CommitGraphRefusal::ParentCycle);
    }
    Ok(generations)
}

fn extra_edge_count(parents: &[Vec<u32>]) -> Result<usize, CommitGraphRefusal> {
    parents.iter().try_fold(0_usize, |total, parent_set| {
        if parent_set.len() > 2 {
            total
                .checked_add(parent_set.len() - 1)
                .ok_or(CommitGraphRefusal::SizeOverflow)
        } else {
            Ok(total)
        }
    })
}

fn encode_edge_values(
    parents: &[Vec<u32>],
    required: usize,
    deadline: &mut impl Deadline,
) -> Result<Vec<u32>, CommitGraphRefusal> {
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(required)
        .map_err(|_| CommitGraphRefusal::AllocationFailed {
            requested: required,
        })?;
    for parent_set in parents {
        checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
        if parent_set.len() > 2 {
            for (index, parent) in parent_set.iter().enumerate().skip(1) {
                let final_parent = index + 1 == parent_set.len();
                edges.push(if final_parent {
                    EDGE_LAST_BIT | *parent
                } else {
                    *parent
                });
            }
        }
    }
    Ok(edges)
}

fn zeroed_usize(length: usize) -> Result<Vec<usize>, CommitGraphRefusal> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| CommitGraphRefusal::AllocationFailed { requested: length })?;
    values.resize(length, 0);
    Ok(values)
}

fn zeroed_u32(length: usize) -> Result<Vec<u32>, CommitGraphRefusal> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| CommitGraphRefusal::AllocationFailed { requested: length })?;
    values.resize(length, 0);
    Ok(values)
}

fn output_bytes(
    format: ObjectFormat,
    commit_count: usize,
    edge_count: usize,
) -> Result<usize, CommitGraphRefusal> {
    let chunks = if edge_count == 0 { 3_usize } else { 4 };
    let toc = chunks
        .checked_add(1)
        .and_then(|count| count.checked_mul(COMMIT_GRAPH_TOC_ENTRY_BYTES))
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let oid_lookup = commit_count
        .checked_mul(format.digest_len())
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let commit_data = commit_count
        .checked_mul(
            format
                .digest_len()
                .checked_add(COMMIT_GRAPH_DATA_SUFFIX_BYTES)
                .ok_or(CommitGraphRefusal::SizeOverflow)?,
        )
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let edges = edge_count
        .checked_mul(4)
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    COMMIT_GRAPH_HEADER_BYTES
        .checked_add(toc)
        .and_then(|value| value.checked_add(COMMIT_GRAPH_FANOUT_BYTES))
        .and_then(|value| value.checked_add(oid_lookup))
        .and_then(|value| value.checked_add(commit_data))
        .and_then(|value| value.checked_add(edges))
        .and_then(|value| value.checked_add(format.digest_len()))
        .ok_or(CommitGraphRefusal::SizeOverflow)
}

fn encode(
    format: ObjectFormat,
    commits: &[ParsedCommit],
    parents: &[Vec<u32>],
    generations: &[u32],
    edges: &[u32],
    output_bytes: usize,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, CommitGraphRefusal> {
    let chunk_count = if edges.is_empty() { 3_usize } else { 4 };
    let toc_bytes = chunk_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(COMMIT_GRAPH_TOC_ENTRY_BYTES))
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let fanout_offset = COMMIT_GRAPH_HEADER_BYTES
        .checked_add(toc_bytes)
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let oid_lookup_offset = fanout_offset
        .checked_add(COMMIT_GRAPH_FANOUT_BYTES)
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let oid_lookup_bytes = commits
        .len()
        .checked_mul(format.digest_len())
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let commit_data_offset = oid_lookup_offset
        .checked_add(oid_lookup_bytes)
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let commit_data_bytes = commits
        .len()
        .checked_mul(
            format
                .digest_len()
                .checked_add(COMMIT_GRAPH_DATA_SUFFIX_BYTES)
                .ok_or(CommitGraphRefusal::SizeOverflow)?,
        )
        .ok_or(CommitGraphRefusal::SizeOverflow)?;
    let edge_offset = commit_data_offset
        .checked_add(commit_data_bytes)
        .ok_or(CommitGraphRefusal::SizeOverflow)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(output_bytes)
        .map_err(|_| CommitGraphRefusal::AllocationFailed {
            requested: output_bytes,
        })?;
    output.extend_from_slice(COMMIT_GRAPH_SIGNATURE);
    output.push(COMMIT_GRAPH_VERSION_V1);
    output.push(format_code(format));
    output.push(u8::try_from(chunk_count).map_err(|_| CommitGraphRefusal::SizeOverflow)?);
    output.push(0);
    append_chunk_toc(&mut output, CHUNK_OID_FANOUT, fanout_offset)?;
    append_chunk_toc(&mut output, CHUNK_OID_LOOKUP, oid_lookup_offset)?;
    append_chunk_toc(&mut output, CHUNK_COMMIT_DATA, commit_data_offset)?;
    if !edges.is_empty() {
        append_chunk_toc(&mut output, CHUNK_EXTRA_EDGES, edge_offset)?;
    }
    append_chunk_toc(
        &mut output,
        [0; 4],
        output_bytes
            .checked_sub(format.digest_len())
            .ok_or(CommitGraphRefusal::SizeOverflow)?,
    )?;

    let mut next = 0_usize;
    for bucket in 0_u16..=255 {
        while next < commits.len() && u16::from(commits[next].oid.as_bytes()[0]) <= bucket {
            next += 1;
        }
        append_u32(
            &mut output,
            u32::try_from(next).map_err(|_| CommitGraphRefusal::FormatCommitLimitExceeded {
                observed: commits.len(),
            })?,
        );
    }
    for commit in commits {
        checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
        output.extend_from_slice(commit.oid.as_bytes());
    }
    let mut next_edge_index = 0_usize;
    for ((commit, parent_positions), generation) in commits.iter().zip(parents).zip(generations) {
        checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
        output.extend_from_slice(commit.tree.as_bytes());
        let first_parent = parent_positions.first().copied().unwrap_or(NO_PARENT);
        let second_parent = match parent_positions.len() {
            0 | 1 => NO_PARENT,
            2 => parent_positions[1],
            _ => {
                let index =
                    u32::try_from(next_edge_index).map_err(|_| CommitGraphRefusal::SizeOverflow)?;
                next_edge_index = next_edge_index
                    .checked_add(parent_positions.len() - 1)
                    .ok_or(CommitGraphRefusal::SizeOverflow)?;
                EDGE_LAST_BIT | index
            }
        };
        append_u32(&mut output, first_parent);
        append_u32(&mut output, second_parent);
        append_u32(
            &mut output,
            generation
                .checked_shl(2)
                .ok_or(CommitGraphRefusal::SizeOverflow)?
                | u32::try_from(commit.commit_time >> 32)
                    .map_err(|_| CommitGraphRefusal::SizeOverflow)?,
        );
        append_u32(&mut output, commit.commit_time as u32);
    }
    for edge in edges {
        checkpoint(deadline).map_err(CommitGraphRefusal::Pack)?;
        append_u32(&mut output, *edge);
    }
    if next_edge_index != edges.len() {
        return Err(CommitGraphRefusal::OutputMismatch {
            expected: edges.len(),
            actual: next_edge_index,
        });
    }
    let digest = checksum(format, &output);
    output.extend_from_slice(digest.as_bytes());
    Ok(output)
}

fn append_chunk_toc(
    output: &mut Vec<u8>,
    id: [u8; 4],
    offset: usize,
) -> Result<(), CommitGraphRefusal> {
    output.extend_from_slice(&id);
    output.extend_from_slice(
        &u64::try_from(offset)
            .map_err(|_| CommitGraphRefusal::SizeOverflow)?
            .to_be_bytes(),
    );
    Ok(())
}

fn append_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn format_code(format: ObjectFormat) -> u8 {
    match format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    }
}

fn checksum(format: ObjectFormat, body: &[u8]) -> ObjectId {
    match format {
        ObjectFormat::Sha1 => ObjectId::from(fgit_types::GitOidSha1::from_bytes(sha1_digest(body))),
        ObjectFormat::Sha256 => {
            ObjectId::from(fgit_types::GitOidSha256::from_bytes(sha256_digest(body)))
        }
    }
}
