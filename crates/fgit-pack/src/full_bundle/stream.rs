//! Native full and incremental bundle export with one source body in custody at a time.
//!
//! Every output byte is tentative. The caller owns a private staged artifact
//! and publishes it only after this function returns its complete receipt and
//! the caller's source/runtime obligations close. Neither a successful write
//! nor a pack trailer by itself publishes an artifact.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::ops::Range;

use fgit_crypto::{
    DigestHasher, GitHashAlgorithm, GitObjectHasher, NativeObjectIdentity, Sha1, Sha1Hasher,
    Sha256, Sha256Hasher,
};
use fgit_deflate::{CancellationProbe, DeflateLimits, Deflater};
use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, TagTargetType, parse_annotated_tag,
    parse_object_body, required_ref_target_kind,
};

use super::{FullBundleError, FullBundleLimits, MAX_BUNDLE_PREREQUISITES, append_ref};
use crate::writer::{encode_entry_header, pack_header};
use crate::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, Deadline, ObjectFormat, ObjectId,
    PackError, PackLimits, PackWriteError, PackWriteProfile, checkpoint, object_id_from_bytes,
};

const CHUNK_BYTES: usize = 16 * 1024;

/// OID ordering is separate from the materializing planner's type/recency/path
/// ordering. Only its frozen no-delta compression policy is shared.
pub const STREAM_FULL_BUNDLE_PROFILE: &str = "git-pack-compressed-oid-no-delta-v1";

/// The same frozen OID-ordered compression policy with an explicit prerequisite
/// envelope. This profile is transfer data, not a self-contained backup.
pub const STREAM_INCREMENTAL_BUNDLE_PROFILE: &str =
    "git-bundle-incremental-compressed-oid-no-delta-v1";

/// Hard ceiling on caller-verified omitted-object metadata for one transfer.
pub const MAX_INCREMENTAL_EXTERNAL_OBJECTS: usize = 1_000_000;

/// One operation's independent byte, object, graph and compression bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFullBundleLimits {
    /// `max_input_bytes` bounds emitted pack bytes, including its trailer.
    /// Source bodies share `max_total_expanded_bytes`; each also obeys
    /// `max_object_bytes`. Both entry and index counts bound retained metadata.
    pub pack: PackLimits,
    pub envelope: FullBundleLimits,
    /// Counts every parsed graph edge, including repeated edges and gitlinks.
    pub max_graph_edges: usize,
    /// One exact deterministic encoder-work allowance across all zlib members.
    pub max_compression_work: u64,
}

impl Default for StreamFullBundleLimits {
    fn default() -> Self {
        Self {
            pack: PackLimits::default(),
            envelope: FullBundleLimits::default(),
            max_graph_edges: 1_000_000,
            max_compression_work: 1_000_000_000,
        }
    }
}

/// Source/codec refusals remain distinct from an output I/O failure. Either
/// can follow partial output and neither produces a complete-artifact receipt.
#[derive(Debug)]
pub enum StreamFullBundleError {
    Io(io::Error),
    Bundle(FullBundleError),
}

impl std::fmt::Display for StreamFullBundleError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(out, "streamed bundle output: {error}"),
            Self::Bundle(error) => error.fmt(out),
        }
    }
}
impl std::error::Error for StreamFullBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Bundle(error) => Some(error),
        }
    }
}
impl From<io::Error> for StreamFullBundleError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<FullBundleError> for StreamFullBundleError {
    fn from(error: FullBundleError) -> Self {
        Self::Bundle(error)
    }
}
impl From<PackError> for StreamFullBundleError {
    fn from(error: PackError) -> Self {
        Self::Bundle(FullBundleError::Pack(error))
    }
}
impl From<PackWriteError> for StreamFullBundleError {
    fn from(error: PackWriteError) -> Self {
        Self::Bundle(FullBundleError::Write(error))
    }
}

/// Complete native output and selected-graph verification, without object
/// bodies or per-object receipts. A nonzero prerequisite count identifies an
/// incremental transfer using caller-validated omitted closure/type facts.
/// This receipt authenticates the emitted bytes, not omitted payload bytes.
/// Construction does not establish file durability or authorize disclosure;
/// those remain the selecting caller's responsibilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFullBundleReceipt {
    format: ObjectFormat,
    profile_id: &'static str,
    pack_checksum: ObjectId,
    object_count: u32,
    prerequisite_count: usize,
    external_object_count: usize,
    total_object_bytes: usize,
    pack_bytes: usize,
    header_bytes: usize,
    bundle_bytes: usize,
    bundle_sha256: [u8; 32],
    compression_work: u64,
}

impl StreamFullBundleReceipt {
    #[must_use]
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }
    #[must_use]
    pub const fn profile_id(&self) -> &'static str {
        self.profile_id
    }
    #[must_use]
    pub const fn pack_checksum(&self) -> ObjectId {
        self.pack_checksum
    }
    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }
    /// Number of explicitly declared native commit prerequisites; zero for a
    /// self-contained full bundle.
    #[must_use]
    pub const fn prerequisite_count(&self) -> usize {
        self.prerequisite_count
    }
    /// Number of omitted objects in the caller-validated prerequisite closure;
    /// their payload bytes are neither loaded nor authenticated by this codec.
    #[must_use]
    pub const fn external_object_count(&self) -> usize {
        self.external_object_count
    }
    #[must_use]
    pub const fn total_object_bytes(&self) -> usize {
        self.total_object_bytes
    }
    #[must_use]
    pub const fn pack_bytes(&self) -> usize {
        self.pack_bytes
    }
    #[must_use]
    pub const fn header_bytes(&self) -> usize {
        self.header_bytes
    }
    #[must_use]
    pub const fn bundle_bytes(&self) -> usize {
        self.bundle_bytes
    }
    #[must_use]
    pub const fn bundle_sha256(&self) -> [u8; 32] {
        self.bundle_sha256
    }
    #[must_use]
    pub const fn compression_work(&self) -> u64 {
        self.compression_work
    }
}

/// Stream deterministic V2/SHA-1 or V3/SHA-256 full-bundle bytes into a
/// caller-owned tentative output. This function never flushes or promotes it.
///
/// The selected set and advertisements are checked before the first source
/// load or output write. Objects are loaded once in increasing native OID
/// order, authenticated, parsed and compressed independently. Source-provided
/// edge metadata cannot substitute for the edges in those exact native bytes.
/// Before emitting the pack trailer, every local edge must resolve to its
/// required kind and every selected object must be reachable from an advertised
/// ref. Gitlinks remain foreign references and are never loaded.
///
/// Memory is bounded by one body plus its bounded parsed view, one encoder's
/// buffers, the bounded header and O(objects + graph edges) metadata. There is
/// no whole-pack buffer, delta window or retained body plan. Cancellation is
/// latched and checked between source reads, parsing, hashing chunks, encoder
/// work and output writes. The caller must bound blocking source and writer
/// I/O; cooperative checkpoints cannot interrupt an in-progress OS call.
pub fn write_full_bundle_stream<W: Write + ?Sized>(
    format: ObjectFormat,
    references: &[BundleReference],
    head: Option<ObjectId>,
    selected: &[ObjectId],
    source: &impl CanonicalObjectSource,
    limits: &StreamFullBundleLimits,
    deadline: &mut impl Deadline,
    output: &mut W,
) -> Result<StreamFullBundleReceipt, StreamFullBundleError> {
    write_bundle_stream(
        format,
        references,
        head,
        &[],
        selected,
        &BTreeMap::new(),
        STREAM_FULL_BUNDLE_PROFILE,
        source,
        limits,
        deadline,
        output,
    )
}

/// Stream a native incremental bundle into caller-owned tentative output.
///
/// The caller must independently validate prerequisite reachability and complete
/// closure/type facts in the selected repository snapshot. This map is a
/// transfer boundary, never a caller-supplied authorization or retention root.
/// The codec validates its shape, but does not load or authenticate omitted
/// payload bytes; the receiver is assumed to hold the declared history.
/// Every prerequisite must be a commit in that map, and the selected and omitted
/// inventories must be disjoint. Advertisements may target either inventory,
/// including an entirely external advertisement with an empty emitted pack.
///
/// Selected bodies retain the full writer's identity, parsing, typed-edge and
/// reachability checks. Each parsed local edge must resolve to a selected object
/// of the required kind or an external entry of that exact kind. All selected
/// objects must be reachable from an advertisement without walking beyond the
/// validated external boundary. Gitlinks remain foreign and consume edge budget.
///
/// Ref, header and frontier validation precedes source reads and output. The
/// same independent pack, body, graph, compression and cancellation budgets
/// apply; omitted bodies consume no new read allowance here. All output remains
/// tentative until this receipt and the caller's lifecycle obligations complete.
pub fn write_incremental_bundle_stream<W: Write + ?Sized>(
    format: ObjectFormat,
    references: &[BundleReference],
    prerequisites: &[ObjectId],
    selected: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    source: &impl CanonicalObjectSource,
    limits: &StreamFullBundleLimits,
    deadline: &mut impl Deadline,
    output: &mut W,
) -> Result<StreamFullBundleReceipt, StreamFullBundleError> {
    if prerequisites.is_empty() {
        checkpoint(deadline)?;
        return Err(FullBundleError::Invalid("empty prerequisite frontier").into());
    }
    write_bundle_stream(
        format,
        references,
        None,
        prerequisites,
        selected,
        external,
        STREAM_INCREMENTAL_BUNDLE_PROFILE,
        source,
        limits,
        deadline,
        output,
    )
}

fn write_bundle_stream<W: Write + ?Sized>(
    format: ObjectFormat,
    references: &[BundleReference],
    head: Option<ObjectId>,
    prerequisites: &[ObjectId],
    selected: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    profile_id: &'static str,
    source: &impl CanonicalObjectSource,
    limits: &StreamFullBundleLimits,
    deadline: &mut impl Deadline,
    output: &mut W,
) -> Result<StreamFullBundleReceipt, StreamFullBundleError> {
    let mut control = Control {
        deadline,
        cancelled: false,
    };
    checkpoint(&mut control)?;
    if limits.max_compression_work == 0 {
        return Err(FullBundleError::Limit("compression work").into());
    }
    let ids = selected_ids(format, selected, limits, &mut control)?;
    let boundary = prerequisite_ids(format, prerequisites, &ids, external, &mut control)?;
    let header = header(
        format,
        references,
        head,
        &boundary,
        &ids,
        external,
        limits.envelope,
        &mut control,
    )?;
    let count = u32::try_from(ids.len()).map_err(|_| FullBundleError::Limit("objects"))?;
    let header_bytes = header.len();
    let mut graph = Graph::new(ids.len(), limits.max_graph_edges)?;
    let mut emitter = Output {
        writer: output,
        native: NativeHash::new(format),
        sha256: Sha256Hasher::new(),
        bytes: 0,
        header_bytes,
        pack_limit: limits.pack.max_input_bytes,
        bundle_limit: limits.envelope.max_bundle_bytes,
    };
    emitter.emit(&header, false, &mut control)?;
    drop(header);
    emitter.emit(&pack_header(count), true, &mut control)?;
    let mut total_object_bytes = 0_usize;
    let mut compression_work = 0_u64;
    for id in &ids {
        checkpoint(&mut control)?;
        let loaded = source.load(id);
        checkpoint(&mut control)?;
        let object = loaded?;
        if object.id() != *id {
            return Err(PackWriteError::SourceIdentityMismatch {
                requested: *id,
                returned: object.id(),
            }
            .into());
        }
        limits.pack.object_size(object.body().len())?;
        total_object_bytes = total_object_bytes
            .checked_add(object.body().len())
            .ok_or(FullBundleError::Limit("source bytes"))?;
        if total_object_bytes > limits.pack.max_total_expanded_bytes {
            return Err(PackError::TotalExpandedLimit {
                actual: total_object_bytes,
                limit: limits.pack.max_total_expanded_bytes,
            }
            .into());
        }
        verify_identity(&object, &mut control)?;
        graph.object(format, &object, &ids, external, &limits.pack, &mut control)?;
        emitter.emit(
            &encode_entry_header(object.object_type().type_code(), object.body().len())?,
            true,
            &mut control,
        )?;
        let remaining_work = limits
            .max_compression_work
            .checked_sub(compression_work)
            .filter(|left| *left > 0)
            .ok_or(FullBundleError::Limit("compression work"))?;
        let compression_limits = DeflateLimits {
            max_input_bytes: limits.pack.max_object_bytes.max(1),
            max_output_bytes: emitter.remaining_pack_bytes().min(
                limits
                    .envelope
                    .max_bundle_bytes
                    .saturating_sub(emitter.bytes),
            ),
            max_work_units: remaining_work,
            ..DeflateLimits::GIT_OBJECT
        };
        let mut encoder = Deflater::new(
            compression_limits,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1.compression,
        )
        .map_err(PackWriteError::from)?;
        emitter.emit(&encoder.take_output(), true, &mut control)?;
        for chunk in object.body().chunks(CHUNK_BYTES) {
            checkpoint(&mut control)?;
            encoder
                .push_with_control(chunk, &mut control)
                .map_err(PackWriteError::from)?;
            emitter.emit(&encoder.take_output(), true, &mut control)?;
        }
        encoder
            .finish_with_control(&mut control)
            .map_err(PackWriteError::from)?;
        emitter.emit(&encoder.take_output(), true, &mut control)?;
        encoder
            .receipt()
            .ok_or(PackWriteError::MissingCompressionReceipt)?;
        compression_work = compression_work
            .checked_add(encoder.work_units())
            .ok_or(FullBundleError::Limit("compression work"))?;
        // The source object, parser view and compressor never survive to the
        // next load. Only exact native kinds and index-valued edges are retained.
    }
    graph.verify(&ids, references, external, &mut control)?;
    checkpoint(&mut control)?;
    let pack_checksum = emitter.native.clone().finish();
    emitter.emit(pack_checksum.as_bytes(), false, &mut control)?;
    checkpoint(&mut control)?;
    let bundle_bytes = emitter.bytes;
    Ok(StreamFullBundleReceipt {
        format,
        profile_id,
        pack_checksum,
        object_count: count,
        prerequisite_count: boundary.len(),
        external_object_count: external.len(),
        total_object_bytes,
        pack_bytes: bundle_bytes - header_bytes,
        header_bytes,
        bundle_bytes,
        bundle_sha256: emitter.sha256.finish(),
        compression_work,
    })
}

fn selected_ids(
    format: ObjectFormat,
    selected: &[ObjectId],
    limits: &StreamFullBundleLimits,
    control: &mut impl Deadline,
) -> Result<Vec<ObjectId>, FullBundleError> {
    if selected.len() > limits.pack.max_entries as usize
        || selected.len() > limits.pack.max_index_entries
    {
        return Err(FullBundleError::Limit("objects"));
    }
    let mut ids = Vec::new();
    ids.try_reserve_exact(selected.len())
        .map_err(|_| FullBundleError::Limit("object metadata"))?;
    for &id in selected {
        checkpoint(control)?;
        if id.algorithm() != format {
            return Err(FullBundleError::FormatMismatch);
        }
        if id.is_zero() {
            return Err(FullBundleError::Invalid("zero selected object"));
        }
        ids.push(id);
    }
    ids.sort_unstable();
    checkpoint(control)?;
    for pair in ids.windows(2) {
        checkpoint(control)?;
        if pair[0] == pair[1] {
            return Err(PackWriteError::DuplicateSelectedObject(pair[0]).into());
        }
    }
    Ok(ids)
}

fn prerequisite_ids(
    format: ObjectFormat,
    prerequisites: &[ObjectId],
    ids: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    control: &mut impl Deadline,
) -> Result<Vec<ObjectId>, FullBundleError> {
    if prerequisites.len() > MAX_BUNDLE_PREREQUISITES {
        return Err(FullBundleError::Limit("prerequisites"));
    }
    if external.len() > MAX_INCREMENTAL_EXTERNAL_OBJECTS {
        return Err(FullBundleError::Limit("external closure"));
    }
    if prerequisites.is_empty() && !external.is_empty() {
        return Err(FullBundleError::Invalid("external closure"));
    }
    for id in external.keys() {
        checkpoint(control)?;
        if id.is_zero() || id.algorithm() != format {
            return Err(FullBundleError::Invalid("external closure"));
        }
        if ids.binary_search(id).is_ok() {
            return Err(FullBundleError::Invalid(
                "selected object in prerequisite closure",
            ));
        }
    }
    let mut boundary = Vec::new();
    boundary
        .try_reserve_exact(prerequisites.len())
        .map_err(|_| FullBundleError::Limit("prerequisite metadata"))?;
    for &id in prerequisites {
        checkpoint(control)?;
        if id.is_zero() || id.algorithm() != format {
            return Err(FullBundleError::Invalid("prerequisite identity"));
        }
        match external.get(&id) {
            None => return Err(FullBundleError::Invalid("prerequisite closure")),
            Some(ObjectType::Commit) => {}
            Some(_) => return Err(FullBundleError::Invalid("prerequisite target kind")),
        }
        boundary.push(id);
    }
    boundary.sort_unstable();
    for pair in boundary.windows(2) {
        checkpoint(control)?;
        if pair[0] == pair[1] {
            return Err(FullBundleError::Invalid("duplicate prerequisite"));
        }
    }
    Ok(boundary)
}

fn header(
    format: ObjectFormat,
    references: &[BundleReference],
    head: Option<ObjectId>,
    prerequisites: &[ObjectId],
    ids: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    limits: FullBundleLimits,
    control: &mut impl Deadline,
) -> Result<Vec<u8>, FullBundleError> {
    let count = references
        .len()
        .checked_add(usize::from(head.is_some()))
        .ok_or(FullBundleError::Limit("references"))?;
    if references.is_empty() || count > limits.max_references {
        return Err(FullBundleError::Limit("references"));
    }
    let mut refs = Vec::new();
    refs.try_reserve_exact(references.len())
        .map_err(|_| FullBundleError::Limit("reference metadata"))?;
    for reference in references {
        checkpoint(control)?;
        let id = reference.target();
        if id.algorithm() != format || id.is_zero() {
            return Err(FullBundleError::FormatMismatch);
        }
        if !reference.name().as_bytes().starts_with(b"refs/") {
            return Err(FullBundleError::Invalid("full reference name required"));
        }
        if ids.binary_search(id).is_err() {
            let kind = external
                .get(id)
                .ok_or(FullBundleError::MissingObject(*id))?;
            if required_ref_target_kind(reference.name().as_bytes())
                .is_some_and(|required| *kind != required)
            {
                return Err(FullBundleError::Invalid("branch target kind"));
            }
        }
        refs.push(reference);
    }
    refs.sort_unstable_by(|left, right| left.name().cmp(right.name()));
    for pair in refs.windows(2) {
        checkpoint(control)?;
        if pair[0].name() == pair[1].name() {
            return Err(FullBundleError::Invalid("duplicate reference"));
        }
    }
    if let Some(id) = head
        && (id.algorithm() != format
            || !refs.iter().any(|reference| {
                reference.name().as_bytes().starts_with(b"refs/heads/") && *reference.target() == id
            }))
    {
        return Err(FullBundleError::Invalid(
            "HEAD must name an advertised branch tip",
        ));
    }
    let mut header = match format {
        ObjectFormat::Sha1 => b"# v2 git bundle\n".to_vec(),
        ObjectFormat::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    let maximum = limits.max_header_bytes.min(limits.max_bundle_bytes);
    if header.len() >= maximum {
        return Err(FullBundleError::Limit("header bytes"));
    }
    for id in prerequisites {
        checkpoint(control)?;
        if header.len().checked_add(1).is_none_or(|n| n >= maximum) {
            return Err(FullBundleError::Limit("header bytes"));
        }
        header
            .try_reserve(1)
            .map_err(|_| FullBundleError::Limit("header bytes"))?;
        header.push(b'-');
        append_ref(&mut header, *id, b"required history", maximum)?;
    }
    if let Some(id) = head {
        append_ref(&mut header, id, b"HEAD", maximum)?;
    }
    for reference in refs {
        checkpoint(control)?;
        append_ref(
            &mut header,
            *reference.target(),
            reference.name().as_bytes(),
            maximum,
        )?;
    }
    if header.len() >= maximum {
        return Err(FullBundleError::Limit("header bytes"));
    }
    header.push(b'\n');
    Ok(header)
}

fn verify_identity(
    object: &CanonicalPackObject,
    control: &mut impl Deadline,
) -> Result<(), FullBundleError> {
    match object.id().algorithm() {
        ObjectFormat::Sha1 => verify_identity_format::<Sha1>(object, control),
        ObjectFormat::Sha256 => verify_identity_format::<Sha256>(object, control),
    }
}

fn verify_identity_format<A: GitHashAlgorithm>(
    object: &CanonicalPackObject,
    control: &mut impl Deadline,
) -> Result<(), FullBundleError> {
    // The native object hasher owns Git's type/length/NUL identity framing.
    let length = u64::try_from(object.body().len())
        .map_err(|_| FullBundleError::Limit("source object length"))?;
    let mut hash = GitObjectHasher::<A>::new(object.object_type(), length);
    for chunk in object.body().chunks(CHUNK_BYTES) {
        checkpoint(control)?;
        hash.update(chunk)
            .map_err(|_| FullBundleError::Invalid("native identity length"))?;
    }
    checkpoint(control)?;
    let actual = hash
        .finish()
        .map_err(|_| FullBundleError::Invalid("native identity length"))?;
    if actual.erase() != object.id() {
        return Err(PackError::NativeObjectIdMismatch.into());
    }
    Ok(())
}

struct Node {
    kind: ObjectType,
    edges: Range<usize>,
}
struct Edge {
    target: usize,
    required: ObjectType,
}
struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    edges_left: usize,
}

impl Graph {
    fn new(objects: usize, edges: usize) -> Result<Self, FullBundleError> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(objects)
            .map_err(|_| FullBundleError::Limit("object metadata"))?;
        Ok(Self {
            nodes,
            edges: Vec::new(),
            edges_left: edges,
        })
    }

    fn charge_edge(&mut self) -> Result<(), FullBundleError> {
        self.edges_left = self
            .edges_left
            .checked_sub(1)
            .ok_or(FullBundleError::Limit("graph edges"))?;
        Ok(())
    }

    fn edge(
        &mut self,
        id: ObjectId,
        required: ObjectType,
        ids: &[ObjectId],
        external: &BTreeMap<ObjectId, ObjectType>,
    ) -> Result<(), FullBundleError> {
        if id.is_zero() {
            return Err(FullBundleError::Invalid("zero graph edge"));
        }
        let target = match ids.binary_search(&id) {
            Ok(index) => index,
            Err(_) => {
                return match external.get(&id) {
                    Some(kind) if *kind == required => Ok(()),
                    Some(_) => Err(FullBundleError::Invalid("graph edge target kind")),
                    None => Err(FullBundleError::MissingObject(id)),
                };
            }
        };
        self.edges
            .try_reserve(1)
            .map_err(|_| FullBundleError::Limit("graph metadata"))?;
        self.edges.push(Edge { target, required });
        Ok(())
    }

    fn object(
        &mut self,
        format: ObjectFormat,
        object: &CanonicalPackObject,
        ids: &[ObjectId],
        external: &BTreeMap<ObjectId, ObjectType>,
        limits: &PackLimits,
        control: &mut impl Deadline,
    ) -> Result<(), FullBundleError> {
        let start = self.edges.len();
        let parse_limits = ParseLimits {
            max_object_bytes: limits.max_object_bytes,
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        };
        // Blob content is arbitrary bytes. Avoid the generic parser's owned
        // duplicate of an already size-bounded and identity-verified blob.
        if object.object_type() != ObjectType::Blob {
            checkpoint(control)?;
            let parsed = parse_object_body(
                object.object_type(),
                object.body(),
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits,
            );
            checkpoint(control)?;
            match parsed.map_err(PackError::ObjectParse)? {
                ParsedObject::Blob(_) => {}
                ParsedObject::Tree(entries) => {
                    for entry in entries {
                        checkpoint(control)?;
                        self.charge_edge()?;
                        let mode = std::str::from_utf8(&entry.mode)
                            .ok()
                            .and_then(|text| u32::from_str_radix(text, 8).ok())
                            .ok_or(FullBundleError::Invalid("tree mode"))?;
                        let required = match mode & 0o170_000 {
                            0o040_000 => ObjectType::Tree,
                            0o100_000 | 0o120_000 => ObjectType::Blob,
                            0o160_000 => continue,
                            _ => return Err(FullBundleError::Invalid("tree mode")),
                        };
                        self.edge(
                            object_id_from_bytes(format, &entry.object_id)?,
                            required,
                            ids,
                            external,
                        )?;
                    }
                }
                ParsedObject::Commit(commit) => {
                    let mut trees = 0_usize;
                    for field in commit.headers() {
                        checkpoint(control)?;
                        let required = match field.name.as_slice() {
                            b"tree" => {
                                trees += 1;
                                ObjectType::Tree
                            }
                            b"parent" => ObjectType::Commit,
                            _ => continue,
                        };
                        if trees > 1 || !field.continuations.is_empty() {
                            return Err(FullBundleError::Invalid("commit graph headers"));
                        }
                        self.charge_edge()?;
                        self.edge(
                            hex_reference(format, &field.value)?,
                            required,
                            ids,
                            external,
                        )?;
                    }
                    if trees != 1 {
                        return Err(FullBundleError::Invalid("commit tree"));
                    }
                }
                ParsedObject::Tag(tag) => {
                    // The typed annotated-tag parser is the shared native
                    // contract for unique object/type headers and hash domain.
                    drop(tag);
                    let tag = parse_annotated_tag(
                        object.body(),
                        format,
                        AcceptanceProfile::GitCompatibleImport,
                        &parse_limits,
                    );
                    checkpoint(control)?;
                    let target = tag.map_err(PackError::ObjectParse)?.target();
                    let required = match target.object_type {
                        TagTargetType::Blob => ObjectType::Blob,
                        TagTargetType::Tree => ObjectType::Tree,
                        TagTargetType::Commit => ObjectType::Commit,
                        TagTargetType::Tag => ObjectType::Tag,
                    };
                    self.charge_edge()?;
                    self.edge(target.oid, required, ids, external)?;
                }
            }
        }
        checkpoint(control)?;
        self.nodes.push(Node {
            kind: object.object_type(),
            edges: start..self.edges.len(),
        });
        Ok(())
    }

    fn verify(
        &self,
        ids: &[ObjectId],
        refs: &[BundleReference],
        external: &BTreeMap<ObjectId, ObjectType>,
        control: &mut impl Deadline,
    ) -> Result<(), FullBundleError> {
        let mut seen = Vec::new();
        let mut pending = Vec::new();
        seen.try_reserve_exact(ids.len())
            .map_err(|_| FullBundleError::Limit("reachability metadata"))?;
        pending
            .try_reserve_exact(ids.len())
            .map_err(|_| FullBundleError::Limit("reachability metadata"))?;
        seen.resize(ids.len(), false);
        for edge in &self.edges {
            checkpoint(control)?;
            if self.nodes[edge.target].kind != edge.required {
                return Err(FullBundleError::Invalid("graph edge target kind"));
            }
        }
        for reference in refs {
            checkpoint(control)?;
            let index = match ids.binary_search(reference.target()) {
                Ok(index) => index,
                Err(_) => {
                    let kind = external
                        .get(reference.target())
                        .ok_or(FullBundleError::MissingObject(*reference.target()))?;
                    if required_ref_target_kind(reference.name().as_bytes())
                        .is_some_and(|required| *kind != required)
                    {
                        return Err(FullBundleError::Invalid("branch target kind"));
                    }
                    continue;
                }
            };
            if required_ref_target_kind(reference.name().as_bytes())
                .is_some_and(|required| self.nodes[index].kind != required)
            {
                return Err(FullBundleError::Invalid("branch target kind"));
            }
            if !seen[index] {
                seen[index] = true;
                pending.push(index);
            }
        }
        while let Some(index) = pending.pop() {
            checkpoint(control)?;
            for edge in &self.edges[self.nodes[index].edges.clone()] {
                checkpoint(control)?;
                if !seen[edge.target] {
                    seen[edge.target] = true;
                    pending.push(edge.target);
                }
            }
        }
        for (index, reached) in seen.into_iter().enumerate() {
            checkpoint(control)?;
            if !reached {
                return Err(FullBundleError::UnreachableObject(ids[index]));
            }
        }
        Ok(())
    }
}

fn hex_reference(format: ObjectFormat, bytes: &[u8]) -> Result<ObjectId, FullBundleError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| ObjectId::from_hex(format, text).ok())
        .ok_or(FullBundleError::Invalid("native graph reference"))
}

struct Control<'a, D> {
    deadline: &'a mut D,
    cancelled: bool,
}
impl<D: Deadline> Deadline for Control<'_, D> {
    fn checkpoint(&mut self) -> bool {
        if !self.cancelled && !self.deadline.checkpoint() {
            self.cancelled = true;
        }
        !self.cancelled
    }
}
impl<D: Deadline> CancellationProbe for Control<'_, D> {
    fn is_cancelled(&mut self) -> bool {
        !self.checkpoint()
    }
}

#[derive(Clone)]
enum NativeHash {
    Sha1(Sha1Hasher),
    Sha256(Sha256Hasher),
}
impl NativeHash {
    const fn new(format: ObjectFormat) -> Self {
        match format {
            ObjectFormat::Sha1 => Self::Sha1(Sha1Hasher::new()),
            ObjectFormat::Sha256 => Self::Sha256(Sha256Hasher::new()),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
    }
    fn finish(self) -> ObjectId {
        match self {
            Self::Sha1(hash) => fgit_types::native::GitOidSha1::from_bytes(hash.finish()).into(),
            Self::Sha256(hash) => {
                fgit_types::native::GitOidSha256::from_bytes(hash.finish()).into()
            }
        }
    }
}

struct Output<'a, W: Write + ?Sized> {
    writer: &'a mut W,
    native: NativeHash,
    sha256: Sha256Hasher,
    bytes: usize,
    header_bytes: usize,
    pack_limit: usize,
    bundle_limit: usize,
}
impl<W: Write + ?Sized> Output<'_, W> {
    const fn remaining_pack_bytes(&self) -> usize {
        self.pack_limit
            .saturating_sub(self.bytes.saturating_sub(self.header_bytes))
    }
    fn emit(
        &mut self,
        bytes: &[u8],
        native: bool,
        control: &mut impl Deadline,
    ) -> Result<(), StreamFullBundleError> {
        let end = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(FullBundleError::Limit("bundle bytes"))?;
        if end > self.bundle_limit {
            return Err(FullBundleError::Limit("bundle bytes").into());
        }
        let pack_end = end.saturating_sub(self.header_bytes);
        if pack_end > self.pack_limit {
            return Err(PackWriteError::OutputLimit {
                attempted: pack_end,
                limit: self.pack_limit,
            }
            .into());
        }
        for mut chunk in bytes.chunks(CHUNK_BYTES) {
            while !chunk.is_empty() {
                checkpoint(control)?;
                let result = self.writer.write(chunk);
                checkpoint(control)?;
                let written = match result {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    other => other?,
                };
                if written == 0 || written > chunk.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "streamed bundle writer made no valid progress",
                    )
                    .into());
                }
                let accepted = &chunk[..written];
                if native {
                    self.native.update(accepted);
                }
                self.sha256.update(accepted);
                self.bytes += written;
                chunk = &chunk[written..];
            }
        }
        Ok(())
    }
}
