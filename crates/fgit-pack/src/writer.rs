//! Deterministic, bounded construction of standard Git pack v2 materializations.
//!
//! A pack is a derived view over an already canonical object closure.  This
//! module never treats its output as canonical storage: callers supply a
//! [`CanonicalObjectSource`] for verified objects, and an output becomes
//! consumable only when a [`PackArtifactSink`] promotes the completed temporary
//! artifact.  A cancelled or refused write drops through the sink's abort path.
//!
//! The ordering policy is intentionally part of [`PackWriteProfile`]: object
//! type code ascending, recency descending, path hash ascending, then native
//! object ID ascending.  The final ID comparison makes the order total across
//! platforms and independent of source enumeration order.  Delta selection is
//! likewise fixed: only the preceding `delta_window` planned entries of the
//! same native type are considered; the smallest delta wins, then the nearest
//! preceding entry, then its native object ID.

use std::collections::BTreeSet;
use std::fmt;

use fgit_crypto::{DigestHasher, Sha1Hasher, Sha256Hasher};
use fgit_deflate::{
    CancellationProbe, DeflateLimits, DeflateProfile, DeflateReceipt, DeflateRefusal, Deflater,
};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits};

use crate::{
    Deadline, ObjectFormat, ObjectId, PackError, PackLimits, checkpoint, object_id_from_bytes,
    verify_native_object,
};

const PACK_HEADER_BYTES: usize = 12;
const ENCODER_INPUT_CHUNK_BYTES: usize = 16 * 1024;

/// One immutable canonical Git object and its canonical closure metadata.
///
/// `recency` and `path_hash` are canonical, caller-supplied ordering metadata;
/// the writer never reads a clock or filesystem path while materializing a
/// pack.  `references` must be the object fabric's verified outgoing closure
/// edges for this exact object, not a caller guess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalPackObject {
    id: ObjectId,
    object_type: ObjectType,
    body: Vec<u8>,
    references: Vec<ObjectId>,
    recency: u64,
    path_hash: u64,
}

impl CanonicalPackObject {
    /// Creates a canonical-object record for deterministic pack planning.
    #[must_use]
    pub fn new(
        id: ObjectId,
        object_type: ObjectType,
        body: Vec<u8>,
        references: Vec<ObjectId>,
        recency: u64,
        path_hash: u64,
    ) -> Self {
        Self {
            id,
            object_type,
            body,
            references,
            recency,
            path_hash,
        }
    }

    /// Native object identity in the plan's explicit object-format domain.
    #[must_use]
    pub const fn id(&self) -> ObjectId {
        self.id
    }

    /// Native Git object type carried by the base pack entry.
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        self.object_type
    }

    /// Exact native object content, without loose-object framing.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Verified outgoing canonical-closure references.
    #[must_use]
    pub fn references(&self) -> &[ObjectId] {
        &self.references
    }

    /// Canonical monotone recency coordinate used only by the frozen profile.
    #[must_use]
    pub const fn recency(&self) -> u64 {
        self.recency
    }

    /// Canonical path-cluster hash used only by the frozen profile.
    #[must_use]
    pub const fn path_hash(&self) -> u64 {
        self.path_hash
    }
}

/// Read-only canonical object/closure boundary for pack materialization.
///
/// Implementations normally bridge the verified immutable object fabric.  It
/// is deliberately a lookup interface rather than an in-memory storage model;
/// the writer keeps only its bounded planning state.
pub trait CanonicalObjectSource {
    /// Loads exactly the object named by `id`, including verified closure edges.
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError>;
}

/// Frozen deterministic pack-construction policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackWriteProfile {
    /// Stable profile identity recorded in every receipt.
    pub id: &'static str,
    /// Maximum preceding same-type entries considered as delta bases.
    pub delta_window: usize,
    /// Maximum emitted OFS-delta chain depth, counted from base entries at 0.
    pub max_delta_depth: usize,
    /// Exact deterministic zlib profile used for every emitted member.
    pub compression: DeflateProfile,
}

impl PackWriteProfile {
    /// First deterministic, byte-identical materialization profile.
    ///
    /// Stored DEFLATE blocks trade pack size for an especially auditable first
    /// slice.  It still uses real zlib framing, bounded OFS deltas, streaming
    /// trailer hashing, and the final encoder interface; later profiles can
    /// select fixed or dynamic coding without changing planner semantics.
    pub const STORED_V1: Self = Self {
        id: "git-pack-stored-v1",
        delta_window: 32,
        max_delta_depth: 8,
        compression: DeflateProfile::FAST_STORED,
    };
}

/// A selected OFS-delta relation in a deterministic plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedDelta {
    base_index: usize,
    depth: usize,
    program: Vec<u8>,
}

impl PlannedDelta {
    /// Index of the earlier planned base entry.
    #[must_use]
    pub const fn base_index(&self) -> usize {
        self.base_index
    }

    /// Delta-chain depth recorded by the profile.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Exact inflated Git delta instruction program.
    #[must_use]
    pub fn program(&self) -> &[u8] {
        &self.program
    }
}

/// One plan entry: a native base object or an OFS delta inheriting its type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackPlanEntry {
    object: CanonicalPackObject,
    delta: Option<PlannedDelta>,
}

impl PackPlanEntry {
    /// The verified canonical object represented by this entry.
    #[must_use]
    pub fn object(&self) -> &CanonicalPackObject {
        &self.object
    }

    /// The selected OFS-delta program, if this entry is not a base object.
    #[must_use]
    pub fn delta(&self) -> Option<&PlannedDelta> {
        self.delta.as_ref()
    }
}

/// A complete bounded, deterministic pack-emission plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackPlan {
    format: ObjectFormat,
    profile: PackWriteProfile,
    entries: Vec<PackPlanEntry>,
    total_object_bytes: usize,
}

impl PackPlan {
    /// Native object-format identity domain for the complete pack.
    #[must_use]
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }

    /// Frozen construction profile selected before planning began.
    #[must_use]
    pub const fn profile(&self) -> PackWriteProfile {
        self.profile
    }

    /// Deterministically ordered base/delta entries.
    #[must_use]
    pub fn entries(&self) -> &[PackPlanEntry] {
        &self.entries
    }

    /// Sum of canonical source-body bytes represented by the plan.
    #[must_use]
    pub const fn total_object_bytes(&self) -> usize {
        self.total_object_bytes
    }
}

/// Builds one closure-complete deterministic pack plan from canonical roots.
#[derive(Clone, Debug)]
pub struct PackPlanner {
    format: ObjectFormat,
    profile: PackWriteProfile,
    limits: PackLimits,
}

impl PackPlanner {
    /// Creates a planner with explicit native format, profile, and bounds.
    #[must_use]
    pub fn new(format: ObjectFormat, profile: PackWriteProfile, limits: PackLimits) -> Self {
        Self {
            format,
            profile,
            limits,
        }
    }

    /// Walks canonical closure edges, verifies every supplied object identity,
    /// then applies the profile's total ordering and deterministic delta window.
    pub fn plan(
        &self,
        source: &impl CanonicalObjectSource,
        roots: &[ObjectId],
        deadline: &mut impl Deadline,
    ) -> Result<PackPlan, PackWriteError> {
        let mut pending = roots.to_vec();
        pending.sort_unstable();
        pending.dedup();
        let mut seen = BTreeSet::new();
        let mut objects = Vec::new();
        let mut total_object_bytes = 0_usize;

        while let Some(id) = pending.pop() {
            checkpoint(deadline)?;
            ensure_format(self.format, id)?;
            if !seen.insert(id) {
                continue;
            }
            if seen.len() > usize::try_from(self.limits.max_entries).unwrap_or(usize::MAX) {
                return Err(PackError::EntryCountLimit {
                    actual: u32::try_from(seen.len()).unwrap_or(u32::MAX),
                    limit: self.limits.max_entries,
                }
                .into());
            }
            let object = source.load(&id)?;
            if object.id != id {
                return Err(PackWriteError::SourceIdentityMismatch {
                    requested: id,
                    returned: object.id,
                });
            }
            self.limits.object_size(object.body.len())?;
            total_object_bytes = total_object_bytes.checked_add(object.body.len()).ok_or(
                PackError::IntegerOverflow {
                    context: "pack plan total object bytes",
                },
            )?;
            if total_object_bytes > self.limits.max_total_expanded_bytes {
                return Err(PackError::TotalExpandedLimit {
                    actual: total_object_bytes,
                    limit: self.limits.max_total_expanded_bytes,
                }
                .into());
            }
            verify_native_object(
                self.format,
                object.object_type,
                &object.body,
                &object.id,
                AcceptanceProfile::GitCompatibleImport,
                &object_parse_limits(self.format, &self.limits),
            )?;

            let mut references = object.references.clone();
            references.sort_unstable();
            references.dedup();
            for reference in references.into_iter().rev() {
                checkpoint(deadline)?;
                ensure_format(self.format, reference)?;
                if !seen.contains(&reference) {
                    pending.push(reference);
                }
            }
            objects.push(object);
        }

        objects.sort_unstable_by(compare_pack_objects);
        let entries = select_deltas(&objects, self.profile, deadline)?;
        Ok(PackPlan {
            format: self.format,
            profile: self.profile,
            entries,
            total_object_bytes,
        })
    }
}

/// Result type for pack planning, streaming materialization, and promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackWriteError {
    /// A shared pack parser/identity/resource refusal.
    Pack(PackError),
    /// The selected dependency-owned deterministic encoder refused the member.
    Deflate(DeflateRefusal),
    /// The canonical source returned an object different from the requested ID.
    SourceIdentityMismatch {
        /// Requested canonical identity.
        requested: ObjectId,
        /// Identity carried by the object source result.
        returned: ObjectId,
    },
    /// A generated pack would exceed the caller's declared output budget.
    OutputLimit {
        /// Bytes that would have been emitted.
        attempted: usize,
        /// Maximum permitted bytes.
        limit: usize,
    },
    /// The sink could not create the temporary artifact.
    TemporaryArtifactRefused,
    /// The sink refused a bounded write to its temporary artifact.
    TemporaryWriteRefused,
    /// The sink could not atomically promote the completed temporary artifact.
    PromotionRefused,
    /// A completed dependency encoder omitted its required immutable receipt.
    MissingCompressionReceipt,
}

impl From<PackError> for PackWriteError {
    fn from(value: PackError) -> Self {
        Self::Pack(value)
    }
}

impl From<DeflateRefusal> for PackWriteError {
    fn from(value: DeflateRefusal) -> Self {
        Self::Deflate(value)
    }
}

impl fmt::Display for PackWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PackWriteError {}

/// A temporary-artifact sink with an explicit promotion boundary.
///
/// `promote_temporary` must be all-or-nothing: on an error the temporary
/// remains abortable, and on success the resulting artifact is consumable.
/// The writer invokes `abort_temporary` on every non-success path after a
/// temporary artifact exists, including deadline cancellation.
pub trait PackArtifactSink {
    /// Sink-specific temporary artifact state.
    type Temporary;

    /// Creates a non-consumable temporary artifact.
    fn create_temporary(&mut self) -> Result<Self::Temporary, PackWriteError>;

    /// Appends bytes to a still non-consumable temporary artifact.
    fn write_temporary(
        &mut self,
        temporary: &mut Self::Temporary,
        bytes: &[u8],
    ) -> Result<(), PackWriteError>;

    /// Atomically makes the finished temporary artifact consumable.
    fn promote_temporary(&mut self, temporary: &mut Self::Temporary) -> Result<(), PackWriteError>;

    /// Discards an unpromoted temporary artifact.
    fn abort_temporary(&mut self, temporary: Self::Temporary);
}

/// Encoder boundary used by the writer for one zlib-wrapped pack entry.
///
/// Implementations must send bytes to `emit` only as tentative member output.
/// A caller promotes the outer pack only after this method returns a final
/// receipt.  This interface is intentionally owned by `fgit-pack` so it does
/// not create a reverse dependency from `fgit-deflate`.
pub trait PackEntryEncoder {
    /// Encodes one complete zlib member, returning its final deterministic receipt.
    fn encode_entry(
        &mut self,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError>;
}

/// Adapter from the dependency-owned deterministic DEFLATE encoder to the
/// writer's streaming, cancellation-safe entry-encoder boundary.
#[derive(Clone, Copy, Debug)]
pub struct DeterministicPackEncoder {
    limits: DeflateLimits,
    profile: DeflateProfile,
}

impl DeterministicPackEncoder {
    /// Selects one frozen `fgit-deflate` profile and its independent bounds.
    #[must_use]
    pub const fn new(limits: DeflateLimits, profile: DeflateProfile) -> Self {
        Self { limits, profile }
    }
}

impl PackEntryEncoder for DeterministicPackEncoder {
    fn encode_entry(
        &mut self,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        let mut encoder = Deflater::new(self.limits, self.profile)?;
        emit(&encoder.take_output())?;
        for chunk in input.chunks(ENCODER_INPUT_CHUNK_BYTES) {
            checkpoint(deadline)?;
            let mut control = DeflateDeadline { deadline };
            let _ = encoder.push_with_control(chunk, &mut control)?;
            emit(&encoder.take_output())?;
        }
        let mut control = DeflateDeadline { deadline };
        encoder.finish_with_control(&mut control)?;
        emit(&encoder.take_output())?;
        encoder
            .receipt()
            .ok_or(PackWriteError::MissingCompressionReceipt)
    }
}

/// Final immutable receipt returned only after a sink has promoted the pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackWriteReceipt {
    /// Frozen planner and compressor constants that selected these bytes.
    pub profile: PackWriteProfile,
    /// Native pack checksum in the named object-format domain.
    pub checksum: ObjectId,
    /// Number of emitted pack entries.
    pub object_count: u32,
    /// Number of entries represented as OFS deltas.
    pub delta_count: usize,
    /// Sum of exact uncompressed canonical source bytes.
    pub total_object_bytes: usize,
    /// Total pack bytes including native trailer.
    pub output_bytes: usize,
    /// Immutable receipts for every successfully finalized zlib member.
    pub compression: Vec<DeflateReceipt>,
}

/// Deterministic stream writer over one already validated [`PackPlan`].
#[derive(Clone, Debug)]
pub struct PackWriter {
    limits: PackLimits,
}

impl PackWriter {
    /// Creates a writer whose output budget is `limits.max_input_bytes`.
    #[must_use]
    pub fn new(limits: PackLimits) -> Self {
        Self { limits }
    }

    /// Materializes a complete pack into a temporary in-memory artifact and
    /// returns bytes only after final checksum and promotion succeed.
    pub fn write(
        &self,
        plan: &PackPlan,
        deadline: &mut impl Deadline,
    ) -> Result<(Vec<u8>, PackWriteReceipt), PackWriteError> {
        let mut sink = MemoryPackSink::default();
        let mut encoder =
            DeterministicPackEncoder::new(DeflateLimits::GIT_OBJECT, plan.profile.compression);
        let receipt = self.write_into(plan, deadline, &mut encoder, &mut sink)?;
        let bytes = sink.promoted.ok_or(PackWriteError::PromotionRefused)?;
        Ok((bytes, receipt))
    }

    /// Streams a pack through a caller-supplied encoder and temporary-artifact
    /// sink.  The sink is promoted only after every member and the pack trailer
    /// have finalized successfully.
    pub fn write_into(
        &self,
        plan: &PackPlan,
        deadline: &mut impl Deadline,
        encoder: &mut impl PackEntryEncoder,
        sink: &mut impl PackArtifactSink,
    ) -> Result<PackWriteReceipt, PackWriteError> {
        let count = u32::try_from(plan.entries.len()).map_err(|_| PackError::EntryCountLimit {
            actual: u32::MAX,
            limit: self.limits.max_entries,
        })?;
        if count > self.limits.max_entries {
            return Err(PackError::EntryCountLimit {
                actual: count,
                limit: self.limits.max_entries,
            }
            .into());
        }
        let temporary = sink.create_temporary()?;
        let mut staged = StagedArtifact::new(sink, temporary);
        let mut emitter =
            StreamingEmitter::new(&mut staged, plan.format, self.limits.max_input_bytes);
        emitter.emit_hashed(&pack_header(count), deadline)?;

        let mut offsets = Vec::new();
        offsets
            .try_reserve(plan.entries.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: plan.entries.len(),
            })?;
        let mut compression = Vec::new();
        compression
            .try_reserve(plan.entries.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: plan.entries.len(),
            })?;
        let mut delta_count = 0_usize;

        for entry in &plan.entries {
            checkpoint(deadline)?;
            let offset =
                u64::try_from(emitter.bytes_written()).map_err(|_| PackError::IntegerOverflow {
                    context: "pack entry offset",
                })?;
            offsets.push(offset);
            let payload = match entry.delta.as_ref() {
                Some(delta) => {
                    let base_offset = *offsets
                        .get(delta.base_index)
                        .ok_or(PackError::MissingDeltaBase)?;
                    let distance = offset
                        .checked_sub(base_offset)
                        .ok_or(PackError::InvalidOfsDelta)?;
                    emitter.emit_hashed(&encode_entry_header(6, delta.program.len())?, deadline)?;
                    emitter.emit_hashed(&encode_ofs_delta_distance(distance)?, deadline)?;
                    delta_count = delta_count
                        .checked_add(1)
                        .ok_or(PackError::IntegerOverflow {
                            context: "pack delta count",
                        })?;
                    delta.program.as_slice()
                }
                None => {
                    emitter.emit_hashed(
                        &encode_entry_header(
                            entry.object.object_type.type_code(),
                            entry.object.body.len(),
                        )?,
                        deadline,
                    )?;
                    entry.object.body.as_slice()
                }
            };
            let receipt = encoder.encode_entry(payload, deadline, &mut |bytes| {
                emitter.emit_hashed(bytes, deadline)
            })?;
            compression.push(receipt);
        }
        let checksum = emitter.finish_and_emit_trailer(deadline)?;
        staged.promote()?;
        Ok(PackWriteReceipt {
            profile: plan.profile,
            checksum,
            object_count: count,
            delta_count,
            total_object_bytes: plan.total_object_bytes,
            output_bytes: emitter.bytes_written(),
            compression,
        })
    }
}

fn ensure_format(format: ObjectFormat, id: ObjectId) -> Result<(), PackWriteError> {
    if id.algorithm() == format {
        Ok(())
    } else {
        Err(PackError::ObjectFormatMismatch {
            expected: format,
            actual: id.algorithm(),
        }
        .into())
    }
}

fn object_parse_limits(format: ObjectFormat, pack_limits: &PackLimits) -> ParseLimits {
    ParseLimits {
        max_object_bytes: pack_limits.max_object_bytes,
        tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    }
}

fn compare_pack_objects(
    left: &CanonicalPackObject,
    right: &CanonicalPackObject,
) -> std::cmp::Ordering {
    left.object_type
        .type_code()
        .cmp(&right.object_type.type_code())
        .then_with(|| right.recency.cmp(&left.recency))
        .then_with(|| left.path_hash.cmp(&right.path_hash))
        .then_with(|| left.id.cmp(&right.id))
}

fn select_deltas(
    objects: &[CanonicalPackObject],
    profile: PackWriteProfile,
    deadline: &mut impl Deadline,
) -> Result<Vec<PackPlanEntry>, PackWriteError> {
    let mut entries = Vec::new();
    entries
        .try_reserve(objects.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: objects.len(),
        })?;
    for object in objects {
        checkpoint(deadline)?;
        let window_start = entries.len().saturating_sub(profile.delta_window);
        let mut selected: Option<PlannedDelta> = None;
        for base_index in (window_start..entries.len()).rev() {
            checkpoint(deadline)?;
            let base = &entries[base_index];
            if base.object.object_type != object.object_type {
                continue;
            }
            let base_depth = base.delta.as_ref().map_or(0, PlannedDelta::depth);
            let depth = base_depth
                .checked_add(1)
                .ok_or(PackError::IntegerOverflow {
                    context: "planned delta depth",
                })?;
            if depth > profile.max_delta_depth {
                continue;
            }
            let Some(program) = make_delta_program(&base.object.body, &object.body)? else {
                continue;
            };
            let candidate = PlannedDelta {
                base_index,
                depth,
                program,
            };
            if selected.as_ref().is_none_or(|current| {
                candidate.program.len() < current.program.len()
                    || (candidate.program.len() == current.program.len()
                        && (candidate.base_index > current.base_index
                            || (candidate.base_index == current.base_index
                                && base.object.id < entries[current.base_index].object.id)))
            }) {
                selected = Some(candidate);
            }
        }
        entries.push(PackPlanEntry {
            object: object.clone(),
            delta: selected,
        });
    }
    Ok(entries)
}

fn make_delta_program(base: &[u8], target: &[u8]) -> Result<Option<Vec<u8>>, PackWriteError> {
    let prefix = common_prefix(base, target);
    let suffix = common_suffix(base, target, prefix);
    let target_middle_start = prefix;
    let target_middle_end = target
        .len()
        .checked_sub(suffix)
        .ok_or(PackError::IntegerOverflow {
            context: "delta target middle boundary",
        })?;
    let base_suffix_start = base
        .len()
        .checked_sub(suffix)
        .ok_or(PackError::IntegerOverflow {
            context: "delta base suffix boundary",
        })?;
    let mut program = Vec::new();
    program
        .try_reserve(target.len().saturating_add(16))
        .map_err(|_| PackError::AllocationFailed {
            requested: target.len().saturating_add(16),
        })?;
    encode_delta_varint(base.len(), &mut program)?;
    encode_delta_varint(target.len(), &mut program)?;
    emit_copy_run(0, prefix, &mut program)?;
    emit_insert_run(
        &target[target_middle_start..target_middle_end],
        &mut program,
    )?;
    emit_copy_run(base_suffix_start, suffix, &mut program)?;
    if program.len() < target.len() {
        Ok(Some(program))
    } else {
        Ok(None)
    }
}

fn common_prefix(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left_byte, right_byte)| left_byte == right_byte)
        .count()
}

fn common_suffix(base: &[u8], target: &[u8], prefix: usize) -> usize {
    base[prefix..]
        .iter()
        .rev()
        .zip(target[prefix..].iter().rev())
        .take_while(|(base_byte, target_byte)| base_byte == target_byte)
        .count()
}

fn encode_delta_varint(value: usize, output: &mut Vec<u8>) -> Result<(), PackWriteError> {
    let mut value = u64::try_from(value).map_err(|_| PackError::IntegerOverflow {
        context: "delta size varint",
    })?;
    loop {
        let mut byte = u8::try_from(value & 0x7f).map_err(|_| PackError::InvalidVarint {
            context: "delta size varint",
        })?;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return Ok(());
        }
    }
}

fn emit_copy_run(offset: usize, length: usize, output: &mut Vec<u8>) -> Result<(), PackWriteError> {
    let mut offset = u32::try_from(offset).map_err(|_| PackError::IntegerOverflow {
        context: "delta copy offset",
    })?;
    let mut remaining = length;
    while remaining != 0 {
        let chunk = remaining.min(0x1_0000);
        emit_copy_instruction(offset, chunk, output)?;
        offset = offset
            .checked_add(
                u32::try_from(chunk).map_err(|_| PackError::IntegerOverflow {
                    context: "delta copy chunk",
                })?,
            )
            .ok_or(PackError::IntegerOverflow {
                context: "delta copy next offset",
            })?;
        remaining = remaining
            .checked_sub(chunk)
            .ok_or(PackError::IntegerOverflow {
                context: "delta copy remaining",
            })?;
    }
    Ok(())
}

fn emit_copy_instruction(
    offset: u32,
    length: usize,
    output: &mut Vec<u8>,
) -> Result<(), PackWriteError> {
    if length == 0 || length > 0x1_0000 {
        return Err(PackError::InvalidDeltaInstruction.into());
    }
    let mut opcode = 0x80_u8;
    let mut extra = [0_u8; 7];
    let mut used = 0_usize;
    for index in 0..4 {
        let byte = u8::try_from((offset >> (index * 8)) & 0xff).map_err(|_| {
            PackError::IntegerOverflow {
                context: "delta copy offset byte",
            }
        })?;
        if byte != 0 {
            opcode |= 1_u8 << index;
            extra[used] = byte;
            used += 1;
        }
    }
    if length != 0x1_0000 {
        let length = u32::try_from(length).map_err(|_| PackError::IntegerOverflow {
            context: "delta copy length",
        })?;
        for index in 0..3 {
            let byte = u8::try_from((length >> (index * 8)) & 0xff).map_err(|_| {
                PackError::IntegerOverflow {
                    context: "delta copy length byte",
                }
            })?;
            if byte != 0 {
                opcode |= 1_u8 << (index + 4);
                extra[used] = byte;
                used += 1;
            }
        }
    }
    output.push(opcode);
    output.extend_from_slice(&extra[..used]);
    Ok(())
}

fn emit_insert_run(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), PackWriteError> {
    for chunk in bytes.chunks(127) {
        if chunk.is_empty() {
            continue;
        }
        output.push(u8::try_from(chunk.len()).map_err(|_| PackError::InvalidDeltaInstruction)?);
        output.extend_from_slice(chunk);
    }
    Ok(())
}

fn pack_header(count: u32) -> [u8; PACK_HEADER_BYTES] {
    let mut header = [0_u8; PACK_HEADER_BYTES];
    header[..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2_u32.to_be_bytes());
    header[8..].copy_from_slice(&count.to_be_bytes());
    header
}

fn encode_entry_header(type_code: u8, size: usize) -> Result<Vec<u8>, PackWriteError> {
    if !(1..=7).contains(&type_code) || type_code == 5 {
        return Err(PackError::InvalidEntryType(type_code).into());
    }
    let mut size = u64::try_from(size).map_err(|_| PackError::IntegerOverflow {
        context: "pack entry size",
    })?;
    let mut first = u8::try_from(size & 0x0f).map_err(|_| PackError::InvalidVarint {
        context: "pack entry size",
    })? | (type_code << 4);
    size >>= 4;
    let mut output = Vec::new();
    output
        .try_reserve(10)
        .map_err(|_| PackError::AllocationFailed { requested: 10 })?;
    if size != 0 {
        first |= 0x80;
    }
    output.push(first);
    while size != 0 {
        let mut byte = u8::try_from(size & 0x7f).map_err(|_| PackError::InvalidVarint {
            context: "pack entry size",
        })?;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        output.push(byte);
    }
    Ok(output)
}

fn encode_ofs_delta_distance(distance: u64) -> Result<Vec<u8>, PackWriteError> {
    if distance == 0 {
        return Err(PackError::InvalidOfsDelta.into());
    }
    let mut bytes = vec![u8::try_from(distance & 0x7f).map_err(|_| PackError::InvalidOfsDelta)?];
    let mut value = distance >> 7;
    while value != 0 {
        value = value.checked_sub(1).ok_or(PackError::InvalidOfsDelta)?;
        bytes.push(u8::try_from(value & 0x7f).map_err(|_| PackError::InvalidOfsDelta)? | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    Ok(bytes)
}

struct DeflateDeadline<'a> {
    deadline: &'a mut dyn Deadline,
}

impl CancellationProbe for DeflateDeadline<'_> {
    fn is_cancelled(&mut self) -> bool {
        !self.deadline.checkpoint()
    }
}

struct StagedArtifact<'a, S>
where
    S: PackArtifactSink,
{
    sink: &'a mut S,
    temporary: Option<S::Temporary>,
}

impl<'a, S> StagedArtifact<'a, S>
where
    S: PackArtifactSink,
{
    fn new(sink: &'a mut S, temporary: S::Temporary) -> Self {
        Self {
            sink,
            temporary: Some(temporary),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), PackWriteError> {
        let temporary = self
            .temporary
            .as_mut()
            .ok_or(PackWriteError::TemporaryWriteRefused)?;
        self.sink.write_temporary(temporary, bytes)
    }

    fn promote(&mut self) -> Result<(), PackWriteError> {
        let temporary = self
            .temporary
            .as_mut()
            .ok_or(PackWriteError::PromotionRefused)?;
        self.sink.promote_temporary(temporary)?;
        let _ = self.temporary.take();
        Ok(())
    }
}

impl<S> Drop for StagedArtifact<'_, S>
where
    S: PackArtifactSink,
{
    fn drop(&mut self) {
        if let Some(temporary) = self.temporary.take() {
            self.sink.abort_temporary(temporary);
        }
    }
}

enum PackStreamHasher {
    Sha1(Sha1Hasher),
    Sha256(Sha256Hasher),
}

impl PackStreamHasher {
    fn new(format: ObjectFormat) -> Self {
        match format {
            ObjectFormat::Sha1 => Self::Sha1(Sha1Hasher::new()),
            ObjectFormat::Sha256 => Self::Sha256(Sha256Hasher::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hasher) => hasher.update(bytes),
            Self::Sha256(hasher) => hasher.update(bytes),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha1(hasher) => hasher.finish().to_vec(),
            Self::Sha256(hasher) => hasher.finish().to_vec(),
        }
    }
}

struct StreamingEmitter<'a, S>
where
    S: PackArtifactSink,
{
    staged: &'a mut StagedArtifact<'a, S>,
    hasher: Option<PackStreamHasher>,
    output_limit: usize,
    bytes_written: usize,
}

impl<'a, S> StreamingEmitter<'a, S>
where
    S: PackArtifactSink,
{
    fn new(
        staged: &'a mut StagedArtifact<'a, S>,
        format: ObjectFormat,
        output_limit: usize,
    ) -> Self {
        Self {
            staged,
            hasher: Some(PackStreamHasher::new(format)),
            output_limit,
            bytes_written: 0,
        }
    }

    fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    fn emit_hashed(
        &mut self,
        bytes: &[u8],
        deadline: &mut impl Deadline,
    ) -> Result<(), PackWriteError> {
        checkpoint(deadline)?;
        self.emit(bytes)?;
        self.hasher
            .as_mut()
            .ok_or(PackWriteError::PromotionRefused)?
            .update(bytes);
        Ok(())
    }

    fn finish_and_emit_trailer(
        &mut self,
        deadline: &mut impl Deadline,
    ) -> Result<ObjectId, PackWriteError> {
        checkpoint(deadline)?;
        let hasher = self.hasher.take().ok_or(PackWriteError::PromotionRefused)?;
        let checksum = hasher.finish();
        let format = match checksum.len() {
            20 => ObjectFormat::Sha1,
            32 => ObjectFormat::Sha256,
            _ => return Err(PackWriteError::PromotionRefused),
        };
        self.emit(&checksum)?;
        object_id_from_bytes(format, &checksum).map_err(Into::into)
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), PackWriteError> {
        let attempted =
            self.bytes_written
                .checked_add(bytes.len())
                .ok_or(PackError::IntegerOverflow {
                    context: "pack output length",
                })?;
        if attempted > self.output_limit {
            return Err(PackWriteError::OutputLimit {
                attempted,
                limit: self.output_limit,
            });
        }
        self.staged.write(bytes)?;
        self.bytes_written = attempted;
        Ok(())
    }
}

#[derive(Default)]
struct MemoryPackSink {
    promoted: Option<Vec<u8>>,
}

impl PackArtifactSink for MemoryPackSink {
    type Temporary = Vec<u8>;

    fn create_temporary(&mut self) -> Result<Self::Temporary, PackWriteError> {
        Ok(Vec::new())
    }

    fn write_temporary(
        &mut self,
        temporary: &mut Self::Temporary,
        bytes: &[u8],
    ) -> Result<(), PackWriteError> {
        temporary
            .try_reserve(bytes.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: bytes.len(),
            })?;
        temporary.extend_from_slice(bytes);
        Ok(())
    }

    fn promote_temporary(&mut self, temporary: &mut Self::Temporary) -> Result<(), PackWriteError> {
        self.promoted = Some(std::mem::take(temporary));
        Ok(())
    }

    fn abort_temporary(&mut self, _temporary: Self::Temporary) {}
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{NativeChecksumVerifier, read_verified_pack};

    fn limits() -> PackLimits {
        PackLimits {
            max_input_bytes: 100_000,
            max_entries: 32,
            max_object_bytes: 10_000,
            max_delta_depth: 16,
            max_delta_fanout: 16,
            max_total_expanded_bytes: 20_000,
            max_expansion_ratio: 128,
            max_delta_work: 20_000,
            max_inflate_work: 100_000,
            max_cached_bytes: 20_000,
            max_index_entries: 32,
        }
    }

    fn always() -> bool {
        true
    }

    fn object(kind: ObjectType, body: &[u8], recency: u64, path_hash: u64) -> CanonicalPackObject {
        let id = fgit_crypto::git_object_id(ObjectFormat::Sha1, kind, body);
        CanonicalPackObject::new(id, kind, body.to_vec(), Vec::new(), recency, path_hash)
    }

    #[derive(Default)]
    struct FixtureSource {
        objects: BTreeMap<ObjectId, CanonicalPackObject>,
    }

    impl FixtureSource {
        fn with(objects: Vec<CanonicalPackObject>) -> Self {
            Self {
                objects: objects
                    .into_iter()
                    .map(|object| (object.id, object))
                    .collect(),
            }
        }
    }

    impl CanonicalObjectSource for FixtureSource {
        fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
            self.objects
                .get(id)
                .cloned()
                .ok_or(PackWriteError::TemporaryArtifactRefused)
        }
    }

    fn planned(objects: Vec<CanonicalPackObject>) -> PackPlan {
        let roots = objects
            .iter()
            .map(CanonicalPackObject::id)
            .collect::<Vec<_>>();
        PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits())
            .plan(&FixtureSource::with(objects), &roots, &mut always)
            .expect("fixture plan")
    }

    #[test]
    fn fixed_empty_blob_pack_has_stable_golden_digest_and_round_trips_reader() {
        let plan = planned(vec![object(ObjectType::Blob, b"", 1, 7)]);
        let (bytes, receipt) = PackWriter::new(limits())
            .write(&plan, &mut always)
            .expect("stored deterministic pack");
        assert_eq!(
            receipt.checksum.as_bytes(),
            &[
                0x84, 0x10, 0x33, 0xee, 0xed, 0x45, 0x04, 0x1e, 0x80, 0x00, 0xff, 0xa9, 0x62, 0x90,
                0xb9, 0x33, 0x05, 0x28, 0x03, 0xec,
            ]
        );
        assert_eq!(
            fgit_crypto::sha1_digest(&bytes),
            [
                0x53, 0xca, 0x3e, 0xb1, 0x51, 0xa3, 0xfa, 0x75, 0x28, 0x87, 0x8e, 0x8e, 0x51, 0x84,
                0x5b, 0x8e, 0x8b, 0x83, 0x8a, 0x37,
            ]
        );
        let parsed = read_verified_pack(
            &bytes,
            ObjectFormat::Sha1,
            &limits(),
            &mut always,
            &NativeChecksumVerifier,
        )
        .expect("writer output accepted by reader");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].inflated, b"");
        assert_eq!(receipt.profile.delta_window, 32);
        assert_eq!(receipt.profile.max_delta_depth, 8);
    }

    #[test]
    fn ordering_is_total_and_independent_of_root_order() {
        let first = object(ObjectType::Blob, b"first", 5, 2);
        let second = object(ObjectType::Blob, b"second", 5, 2);
        let commit = object(
            ObjectType::Commit,
            b"tree 0000000000000000000000000000000000000000\n\na",
            2,
            9,
        );
        let left = planned(vec![first.clone(), second.clone(), commit.clone()]);
        let right = planned(vec![commit, second, first]);
        assert_eq!(left, right);
        assert_eq!(left.entries()[0].object().object_type(), ObjectType::Commit);
    }

    #[test]
    fn deterministic_window_selects_economical_ofs_delta_and_records_depth() {
        let base = object(ObjectType::Blob, b"aaaaaaaaaaaaaaaaaaaa--same-suffix", 3, 1);
        let target = object(ObjectType::Blob, b"aaaaaaaaaaaaaaaaaaaaXXsame-suffix", 2, 1);
        let plan = planned(vec![base, target]);
        let delta = plan.entries()[1].delta().expect("selected compact delta");
        assert_eq!(delta.base_index(), 0);
        assert_eq!(delta.depth(), 1);
        let (bytes, receipt) = PackWriter::new(limits())
            .write(&plan, &mut always)
            .expect("delta pack write");
        assert_eq!(receipt.delta_count, 1);
        let parsed = read_verified_pack(
            &bytes,
            ObjectFormat::Sha1,
            &limits(),
            &mut always,
            &NativeChecksumVerifier,
        )
        .expect("delta pack reader round trip");
        assert!(matches!(
            parsed.entries[1].header.kind,
            crate::EntryKind::OfsDelta
        ));
    }

    #[derive(Default)]
    struct RecordingSink {
        temporary: Option<Vec<u8>>,
        promoted: Option<Vec<u8>>,
        aborts: usize,
    }

    impl PackArtifactSink for RecordingSink {
        type Temporary = Vec<u8>;

        fn create_temporary(&mut self) -> Result<Self::Temporary, PackWriteError> {
            Ok(Vec::new())
        }

        fn write_temporary(
            &mut self,
            temporary: &mut Self::Temporary,
            bytes: &[u8],
        ) -> Result<(), PackWriteError> {
            temporary.extend_from_slice(bytes);
            Ok(())
        }

        fn promote_temporary(
            &mut self,
            temporary: &mut Self::Temporary,
        ) -> Result<(), PackWriteError> {
            self.promoted = Some(std::mem::take(temporary));
            Ok(())
        }

        fn abort_temporary(&mut self, temporary: Self::Temporary) {
            self.temporary = Some(temporary);
            self.aborts += 1;
        }
    }

    struct CancelAfter {
        remaining_successes: usize,
    }

    impl Deadline for CancelAfter {
        fn checkpoint(&mut self) -> bool {
            if self.remaining_successes == 0 {
                false
            } else {
                self.remaining_successes -= 1;
                true
            }
        }
    }

    #[test]
    fn cancellation_at_header_and_member_boundaries_never_promotes_an_artifact() {
        let plan = planned(vec![object(ObjectType::Blob, b"member bytes", 1, 1)]);
        for successes in [0, 2, 5, 10] {
            let mut sink = RecordingSink::default();
            let mut encoder = DeterministicPackEncoder::new(
                DeflateLimits::GIT_OBJECT,
                PackWriteProfile::STORED_V1.compression,
            );
            let mut cancelled = CancelAfter {
                remaining_successes: successes,
            };
            let result = PackWriter::new(limits()).write_into(
                &plan,
                &mut cancelled,
                &mut encoder,
                &mut sink,
            );
            assert!(matches!(
                result,
                Err(PackWriteError::Pack(PackError::DeadlineExceeded))
                    | Err(PackWriteError::Deflate(DeflateRefusal::Cancelled))
            ));
            assert!(sink.promoted.is_none());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn malformed_source_identity_and_output_limit_are_typed_refusals() {
        let valid = object(ObjectType::Blob, b"body", 1, 1);
        let wrong_id = fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Blob, b"other");
        let malformed = CanonicalPackObject::new(
            wrong_id,
            ObjectType::Blob,
            b"body".to_vec(),
            Vec::new(),
            1,
            1,
        );
        let source = FixtureSource::with(vec![malformed]);
        assert!(matches!(
            PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits()).plan(
                &source,
                &[valid.id()],
                &mut always,
            ),
            Err(PackWriteError::TemporaryArtifactRefused)
        ));

        let plan = planned(vec![valid]);
        let mut tiny_limits = limits();
        tiny_limits.max_input_bytes = PACK_HEADER_BYTES;
        assert!(matches!(
            PackWriter::new(tiny_limits).write(&plan, &mut always),
            Err(PackWriteError::OutputLimit { .. })
        ));
    }

    #[test]
    fn copy_instruction_zero_size_encodes_native_64k_semantics() {
        let mut program = Vec::new();
        emit_copy_instruction(0, 0x1_0000, &mut program).expect("64k special copy");
        assert_eq!(program, vec![0x80]);
    }
}
