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

use std::collections::{BTreeSet, VecDeque};
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

/// Bytes hashed per indexed base block under [`DeltaSearch::IndexedBlocks`].
///
/// A copy run shorter than this is not worth an instruction against an insert
/// run, so the index granularity is also the shortest match the search emits.
const DELTA_INDEX_BLOCK_BYTES: usize = 16;

/// Maximum candidate base offsets inspected at one target position.
///
/// A bucket is walked from its highest indexed offset downwards and the walk
/// stops after this many candidates, so the bound is on work per position.
/// Among candidates of equal match length the lowest base offset wins, which
/// makes the emitted program independent of how the bucket happened to fill.
const DELTA_MAX_MATCH_CHAIN: usize = 64;

/// Target positions scanned between deadline checkpoints.
///
/// The scan visits at worst one position per target byte, which is far finer
/// than a useful cancellation granularity; batching keeps the probe rate
/// bounded without letting a large object outrun its budget unobserved.
const DELTA_SCAN_CHECKPOINT_STRIDE: usize = 4096;

/// Odd multiplier for the rolling base-block fingerprint.
///
/// The fingerprint is deliberately modular: it selects buckets and never
/// decides equality, which is always settled by comparing the bytes.
const DELTA_HASH_MULTIPLIER: u32 = 0x0100_0193;

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
    pub const fn new(
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

/// How a profile searches a candidate base for reusable byte runs.
///
/// This is the shape of the emitted delta program, not the choice of which
/// entries are offered as bases: base candidacy stays the frozen window policy
/// documented on [`PackWriteProfile`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeltaSearch {
    /// Longest common prefix and longest common suffix only.
    ///
    /// The first auditable slice.  It expresses exactly one shape -- copy a
    /// prefix, insert a middle, copy a suffix -- so a target that is its base
    /// shifted by even one byte has no common prefix and is inexpressible.
    PrefixSuffix,
    /// Bounded hashed interior-block matching over the whole base.
    ///
    /// Reaches the copy runs [`Self::PrefixSuffix`] cannot see, at the cost of
    /// one bounded index per candidate base.  The emitted program is whichever
    /// of the two encodings is shorter, so this never emits more bytes than
    /// [`Self::PrefixSuffix`] would for the same pair.
    IndexedBlocks,
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
    /// Exact deterministic delta-program search policy.
    pub delta_search: DeltaSearch,
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
        delta_search: DeltaSearch::PrefixSuffix,
    };

    /// Deterministic fixed-Huffman pack emission with bounded match search.
    ///
    /// This is a separate profile rather than a silent revision of
    /// [`Self::STORED_V1`]: pack receipts retain the exact compressor policy,
    /// and the stored profile remains the auditable baseline for callers that
    /// deliberately select it.  The fixed-Huffman profile is not a claim of
    /// byte-for-byte equivalence with upstream Git's adaptive pack heuristics.
    pub const COMPRESSED_V1: Self = Self {
        id: "git-pack-compressed-v1",
        delta_window: 32,
        max_delta_depth: 8,
        compression: DeflateProfile::DEFAULT,
        delta_search: DeltaSearch::PrefixSuffix,
    };

    /// [`Self::COMPRESSED_V1`] with interior-match delta search.
    ///
    /// A separate profile for the same reason [`Self::COMPRESSED_V1`] was one:
    /// a receipt names the exact policy that produced its bytes, so a profile
    /// that has been measured is never silently redefined underneath the
    /// measurement.  Only the delta-program search differs; ordering, window,
    /// depth, and compression are [`Self::COMPRESSED_V1`]'s.
    ///
    /// The motivating measurement, on the FG-028c anchor corpus (8 commits x 4
    /// files x 300000 lines): under [`DeltaSearch::PrefixSuffix`] not one of
    /// the 380 ordered blob pairs yields a program shorter than its target, so
    /// every object ships as a full base.  The versions of a line-oriented file
    /// differ by a shift, which leaves no common prefix and a one-byte common
    /// suffix -- the one shape prefix/suffix search cannot encode.
    pub const COMPRESSED_V2: Self = Self {
        id: "git-pack-compressed-v2",
        delta_window: 32,
        max_delta_depth: 8,
        compression: DeflateProfile::DEFAULT,
        delta_search: DeltaSearch::IndexedBlocks,
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
    pub const fn object(&self) -> &CanonicalPackObject {
        &self.object
    }

    /// The selected OFS-delta program, if this entry is not a base object.
    #[must_use]
    pub const fn delta(&self) -> Option<&PlannedDelta> {
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
    pub const fn new(format: ObjectFormat, profile: PackWriteProfile, limits: PackLimits) -> Self {
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
        self.validate_profile_depth()?;
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

        self.finish_plan(objects, total_object_bytes, deadline)
    }

    /// Plans exactly an authenticated caller-selected object set.
    ///
    /// This method deliberately does not traverse
    /// [`CanonicalPackObject::references`]. The caller owns authorization and
    /// closure/filter validation; this planner only verifies that every named
    /// object is canonical, bounded, unique, and in the selected format before
    /// applying the frozen deterministic ordering and delta policy.
    pub fn plan_selected(
        &self,
        source: &impl CanonicalObjectSource,
        selected: &[ObjectId],
        deadline: &mut impl Deadline,
    ) -> Result<PackPlan, PackWriteError> {
        self.validate_profile_depth()?;
        let selected_count =
            u32::try_from(selected.len()).map_err(|_| PackError::EntryCountLimit {
                actual: u32::MAX,
                limit: self.limits.max_entries,
            })?;
        if selected_count > self.limits.max_entries {
            return Err(PackError::EntryCountLimit {
                actual: selected_count,
                limit: self.limits.max_entries,
            }
            .into());
        }

        let mut ids = Vec::new();
        ids.try_reserve_exact(selected.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: selected.len(),
            })?;
        for &id in selected {
            checkpoint(deadline)?;
            ensure_format(self.format, id)?;
            ids.push(id);
        }
        ids.sort_unstable();
        for pair in ids.windows(2) {
            if pair[0] == pair[1] {
                return Err(PackWriteError::DuplicateSelectedObject(pair[0]));
            }
        }

        let mut objects = Vec::new();
        objects
            .try_reserve_exact(ids.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: ids.len(),
            })?;
        let mut total_object_bytes = 0_usize;
        for id in ids {
            checkpoint(deadline)?;
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
                    context: "selected pack plan total object bytes",
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
            objects.push(object);
        }
        self.finish_plan(objects, total_object_bytes, deadline)
    }

    const fn validate_profile_depth(&self) -> Result<(), PackWriteError> {
        if self.profile.max_delta_depth > self.limits.max_delta_depth {
            return Err(PackWriteError::Pack(PackError::DeltaDepthLimit {
                depth: self.profile.max_delta_depth,
                limit: self.limits.max_delta_depth,
            }));
        }
        Ok(())
    }

    fn finish_plan(
        &self,
        mut objects: Vec<CanonicalPackObject>,
        total_object_bytes: usize,
        deadline: &mut impl Deadline,
    ) -> Result<PackPlan, PackWriteError> {
        objects.sort_unstable_by(compare_pack_objects);
        let entries = select_deltas(&objects, self.profile, &self.limits, deadline)?;
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
    /// A requested edge in the canonical closure had no immutable object body.
    MissingCanonicalObject(ObjectId),
    /// The caller-selected object list named one native object more than once.
    DuplicateSelectedObject(ObjectId),
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
        checkpoint(deadline)?;
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

/// One promoted pack artifact bound to the exact plan and receipt that wrote it.
///
/// Its fields are intentionally private: a downstream caller cannot pair an
/// arbitrary plan with an unrelated checksum and present the combination as a
/// writer-produced artifact. Derived materializers that depend on pack order,
/// such as a bitmap, consume this value rather than loose coordinates.
#[derive(Debug)]
pub struct MaterializedPack {
    plan: PackPlan,
    bytes: Vec<u8>,
    receipt: PackWriteReceipt,
}

impl MaterializedPack {
    /// Exact complete pack bytes after promotion, including native trailer.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact ordered plan whose entries produced [`Self::bytes`].
    #[must_use]
    pub const fn plan(&self) -> &PackPlan {
        &self.plan
    }

    /// Final writer receipt for this exact promoted pack.
    #[must_use]
    pub const fn receipt(&self) -> &PackWriteReceipt {
        &self.receipt
    }
}

/// Deterministic stream writer over one already validated [`PackPlan`].
#[derive(Clone, Debug)]
pub struct PackWriter {
    limits: PackLimits,
}

impl PackWriter {
    /// Creates a writer whose output budget is `limits.max_input_bytes`.
    #[must_use]
    pub const fn new(limits: PackLimits) -> Self {
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

    /// Materializes a promoted pack and retains the exact plan/receipt binding
    /// for a downstream derived accelerator.  This is the final seam for
    /// products whose bit positions depend on pack order; it is not a second
    /// storage or publication authority.
    pub fn materialize(
        &self,
        plan: &PackPlan,
        deadline: &mut impl Deadline,
    ) -> Result<MaterializedPack, PackWriteError> {
        let (bytes, receipt) = self.write(plan, deadline)?;
        Ok(MaterializedPack {
            plan: plan.clone(),
            bytes,
            receipt,
        })
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
        validate_plan_for_writer(plan, &self.limits)?;
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
        checkpoint(deadline)?;
        emitter.emit_hashed(&pack_header(count))?;

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
                    emitter.emit_hashed(&encode_entry_header(6, delta.program.len())?)?;
                    emitter.emit_hashed(&encode_ofs_delta_distance(distance)?)?;
                    delta_count = delta_count
                        .checked_add(1)
                        .ok_or(PackError::IntegerOverflow {
                            context: "pack delta count",
                        })?;
                    delta.program.as_slice()
                }
                None => {
                    emitter.emit_hashed(&encode_entry_header(
                        entry.object.object_type.type_code(),
                        entry.object.body.len(),
                    )?)?;
                    entry.object.body.as_slice()
                }
            };
            let receipt =
                encoder.encode_entry(payload, deadline, &mut |bytes| emitter.emit_hashed(bytes))?;
            compression.push(receipt);
        }
        let checksum = emitter.finish_and_emit_trailer(deadline)?;
        let output_bytes = emitter.bytes_written();
        staged.promote()?;
        Ok(PackWriteReceipt {
            profile: plan.profile,
            checksum,
            object_count: count,
            delta_count,
            total_object_bytes: plan.total_object_bytes,
            output_bytes,
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

fn validate_plan_for_writer(plan: &PackPlan, limits: &PackLimits) -> Result<(), PackWriteError> {
    let count = u32::try_from(plan.entries.len()).map_err(|_| PackError::EntryCountLimit {
        actual: u32::MAX,
        limit: limits.max_entries,
    })?;
    if count > limits.max_entries {
        return Err(PackError::EntryCountLimit {
            actual: count,
            limit: limits.max_entries,
        }
        .into());
    }
    if plan.total_object_bytes > limits.max_total_expanded_bytes {
        return Err(PackError::TotalExpandedLimit {
            actual: plan.total_object_bytes,
            limit: limits.max_total_expanded_bytes,
        }
        .into());
    }
    let mut fanout = Vec::new();
    fanout
        .try_reserve(plan.entries.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: plan.entries.len(),
        })?;
    for (index, entry) in plan.entries.iter().enumerate() {
        limits.object_size(entry.object.body.len())?;
        fanout.push(0_usize);
        let Some(delta) = entry.delta.as_ref() else {
            continue;
        };
        limits.object_size(delta.program.len())?;
        if delta.base_index >= index {
            return Err(PackError::MissingDeltaBase.into());
        }
        if delta.depth > limits.max_delta_depth {
            return Err(PackError::DeltaDepthLimit {
                depth: delta.depth,
                limit: limits.max_delta_depth,
            }
            .into());
        }
        fanout[delta.base_index] =
            fanout[delta.base_index]
                .checked_add(1)
                .ok_or(PackError::IntegerOverflow {
                    context: "pack plan delta fanout",
                })?;
        if fanout[delta.base_index] > limits.max_delta_fanout {
            return Err(PackError::DeltaFanoutLimit {
                fanout: fanout[delta.base_index],
                limit: limits.max_delta_fanout,
            }
            .into());
        }
    }
    Ok(())
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
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<PackPlanEntry>, PackWriteError> {
    let max_delta_fanout = limits.max_delta_fanout;
    // One index per candidate base, built on first use and retained only while
    // that base is still inside the window. Every target in the window would
    // otherwise rebuild the same index, which is the whole cost of the search.
    let mut indexes: VecDeque<(usize, Option<BaseDeltaIndex>)> = VecDeque::new();
    let mut entries: Vec<PackPlanEntry> = Vec::new();
    entries
        .try_reserve(objects.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: objects.len(),
        })?;
    let mut fanout = Vec::new();
    fanout
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
            if fanout[base_index] >= max_delta_fanout {
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
            let index = match profile.delta_search {
                DeltaSearch::PrefixSuffix => None,
                DeltaSearch::IndexedBlocks => {
                    if !indexes.iter().any(|(cached, _)| *cached == base_index) {
                        let built = BaseDeltaIndex::build(&base.object.body, limits, deadline)?;
                        while indexes.len() >= profile.delta_window.max(1) {
                            indexes.pop_front();
                        }
                        indexes.push_back((base_index, built));
                    }
                    indexes
                        .iter()
                        .find(|(cached, _)| *cached == base_index)
                        .and_then(|(_, built)| built.as_ref())
                }
            };
            let Some(program) = make_delta_program(
                &base.object.body,
                &object.body,
                profile.delta_search,
                index,
                deadline,
            )?
            else {
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
        fanout.push(0);
        if let Some(delta) = entries.last().and_then(PackPlanEntry::delta) {
            fanout[delta.base_index] =
                fanout[delta.base_index]
                    .checked_add(1)
                    .ok_or(PackError::IntegerOverflow {
                        context: "planned delta fanout",
                    })?;
        }
    }
    Ok(entries)
}

/// Builds the profile's delta program for one base/target pair.
///
/// Under [`DeltaSearch::IndexedBlocks`] both encodings are built and the
/// shorter one is emitted; an exact tie keeps the prefix/suffix encoding, so a
/// pair that prefix/suffix search already encoded well emits the same bytes it
/// emitted before.  The pair is rejected -- the target is written as a full
/// base entry -- when even the shorter program is no smaller than the target.
fn make_delta_program(
    base: &[u8],
    target: &[u8],
    search: DeltaSearch,
    index: Option<&BaseDeltaIndex>,
    deadline: &mut impl Deadline,
) -> Result<Option<Vec<u8>>, PackWriteError> {
    let prefix_suffix = make_prefix_suffix_delta_program(base, target)?;
    let chosen = match (search, index) {
        (DeltaSearch::IndexedBlocks, Some(index)) => {
            let indexed = make_indexed_delta_program(index, base, target, deadline)?;
            if indexed.len() < prefix_suffix.len() {
                indexed
            } else {
                prefix_suffix
            }
        }
        _ => prefix_suffix,
    };
    if chosen.len() < target.len() {
        Ok(Some(chosen))
    } else {
        Ok(None)
    }
}

/// Encodes the target as copy-prefix, insert-middle, copy-suffix.
fn make_prefix_suffix_delta_program(base: &[u8], target: &[u8]) -> Result<Vec<u8>, PackWriteError> {
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
    Ok(program)
}

/// Bounded hashed index over one candidate delta base.
///
/// Encoder-local planning state, never storage.  Blocks are indexed at a
/// uniform stride so a base larger than the entry ceiling stays wholly
/// reachable instead of having its tail silently dropped.
#[derive(Clone, Debug)]
struct BaseDeltaIndex {
    /// Bucket heads, indexed by fingerprint; [`Self::NONE`] when empty.
    heads: Vec<u32>,
    /// Next candidate in the same bucket, parallel to `offsets`.
    chain: Vec<u32>,
    /// Indexed base offsets, ascending.
    offsets: Vec<u32>,
    /// `heads.len() - 1`; `heads.len()` is always a power of two.
    mask: u32,
}

impl BaseDeltaIndex {
    const NONE: u32 = u32::MAX;

    /// Indexes `base`, or returns `None` when it is too short to match against.
    fn build(
        base: &[u8],
        limits: &PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Option<Self>, PackWriteError> {
        if base.len() < DELTA_INDEX_BLOCK_BYTES || u32::try_from(base.len()).is_err() {
            return Ok(None);
        }
        let blocks = base.len() / DELTA_INDEX_BLOCK_BYTES;
        let ceiling = limits.max_index_entries.max(1);
        let stride = DELTA_INDEX_BLOCK_BYTES
            .checked_mul(blocks.div_ceil(ceiling).max(1))
            .ok_or(PackError::IntegerOverflow {
                context: "delta base index stride",
            })?;
        let span =
            base.len()
                .checked_sub(DELTA_INDEX_BLOCK_BYTES)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta base index span",
                })?;
        let entries = span / stride + 1;
        let buckets = entries
            .checked_next_power_of_two()
            .ok_or(PackError::IntegerOverflow {
                context: "delta base index buckets",
            })?;
        let mask = u32::try_from(buckets - 1).map_err(|_| PackError::IntegerOverflow {
            context: "delta base index mask",
        })?;

        let mut heads = Vec::new();
        heads
            .try_reserve_exact(buckets)
            .map_err(|_| PackError::AllocationFailed { requested: buckets })?;
        heads.resize(buckets, Self::NONE);
        let mut chain = Vec::new();
        chain
            .try_reserve_exact(entries)
            .map_err(|_| PackError::AllocationFailed { requested: entries })?;
        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(entries)
            .map_err(|_| PackError::AllocationFailed { requested: entries })?;

        let mut offset = 0_usize;
        while offset <= span {
            checkpoint(deadline)?;
            let slot = u32::try_from(offsets.len()).map_err(|_| PackError::IntegerOverflow {
                context: "delta base index slot",
            })?;
            let bucket = (block_fingerprint(&base[offset..offset + DELTA_INDEX_BLOCK_BYTES]) & mask)
                as usize;
            chain.push(heads[bucket]);
            heads[bucket] = slot;
            offsets.push(
                u32::try_from(offset).map_err(|_| PackError::IntegerOverflow {
                    context: "delta base index offset",
                })?,
            );
            offset = offset
                .checked_add(stride)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta base index position",
                })?;
        }

        Ok(Some(Self {
            heads,
            chain,
            offsets,
            mask,
        }))
    }

    /// Longest indexed run of `base` matching `target` at `position`.
    ///
    /// Returns the base offset and length, or `None` when no candidate reaches
    /// [`DELTA_INDEX_BLOCK_BYTES`].  Ties on length resolve to the lowest base
    /// offset examined.
    fn best_match(
        &self,
        base: &[u8],
        target: &[u8],
        position: usize,
        fingerprint: u32,
    ) -> Option<(usize, usize)> {
        let mut candidate = self.heads[(fingerprint & self.mask) as usize];
        let mut examined = 0_usize;
        let mut best: Option<(usize, usize)> = None;
        while candidate != Self::NONE && examined < DELTA_MAX_MATCH_CHAIN {
            examined += 1;
            let slot = candidate as usize;
            let offset = self.offsets[slot] as usize;
            let length = common_prefix(&base[offset..], &target[position..]);
            if length >= DELTA_INDEX_BLOCK_BYTES
                && best.is_none_or(|(best_offset, best_length)| {
                    length > best_length || (length == best_length && offset < best_offset)
                })
            {
                best = Some((offset, length));
            }
            candidate = self.chain[slot];
        }
        best
    }
}

/// Fingerprint of exactly one [`DELTA_INDEX_BLOCK_BYTES`] window.
///
/// Deliberately modular: it selects a bucket and never decides equality, which
/// [`BaseDeltaIndex::best_match`] always settles by comparing the bytes.
fn block_fingerprint(window: &[u8]) -> u32 {
    window.iter().fold(0_u32, |accumulator, &byte| {
        accumulator
            .wrapping_mul(DELTA_HASH_MULTIPLIER)
            .wrapping_add(u32::from(byte))
    })
}

/// Encodes the target as interior copy runs against an indexed base.
///
/// The scan is greedy and forward-only: at each position it takes the longest
/// indexed match and continues past it, accumulating unmatched bytes into one
/// insert run.  This is the shape that reaches a shifted base, which the
/// prefix/suffix encoding cannot express at all.
fn make_indexed_delta_program(
    index: &BaseDeltaIndex,
    base: &[u8],
    target: &[u8],
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackWriteError> {
    let mut program = Vec::new();
    program
        .try_reserve(target.len().saturating_add(16))
        .map_err(|_| PackError::AllocationFailed {
            requested: target.len().saturating_add(16),
        })?;
    encode_delta_varint(base.len(), &mut program)?;
    encode_delta_varint(target.len(), &mut program)?;

    let high_power = (1..DELTA_INDEX_BLOCK_BYTES)
        .fold(1_u32, |power, _| power.wrapping_mul(DELTA_HASH_MULTIPLIER));
    let mut literal_start = 0_usize;
    let mut position = 0_usize;
    let mut fingerprint = 0_u32;
    let mut rolling = false;
    let mut since_checkpoint = 0_usize;

    while let Some(window_end) = position
        .checked_add(DELTA_INDEX_BLOCK_BYTES)
        .filter(|end| *end <= target.len())
    {
        if since_checkpoint == 0 {
            checkpoint(deadline)?;
        }
        since_checkpoint = (since_checkpoint + 1) % DELTA_SCAN_CHECKPOINT_STRIDE;

        fingerprint = if rolling {
            fingerprint
                .wrapping_sub(u32::from(target[position - 1]).wrapping_mul(high_power))
                .wrapping_mul(DELTA_HASH_MULTIPLIER)
                .wrapping_add(u32::from(target[window_end - 1]))
        } else {
            block_fingerprint(&target[position..window_end])
        };
        rolling = true;

        if let Some((offset, length)) = index.best_match(base, target, position, fingerprint) {
            emit_insert_run(&target[literal_start..position], &mut program)?;
            emit_copy_run(offset, length, &mut program)?;
            position = position
                .checked_add(length)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta scan match advance",
                })?;
            literal_start = position;
            rolling = false;
        } else {
            position += 1;
        }
    }

    emit_insert_run(&target[literal_start..], &mut program)?;
    Ok(program)
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
    const fn new(sink: &'a mut S, temporary: S::Temporary) -> Self {
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
    const fn new(format: ObjectFormat) -> Self {
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

struct StreamingEmitter<'artifact, 'sink, S>
where
    S: PackArtifactSink,
{
    staged: &'artifact mut StagedArtifact<'sink, S>,
    hasher: Option<PackStreamHasher>,
    format: ObjectFormat,
    output_limit: usize,
    bytes_written: usize,
}

impl<'artifact, 'sink, S> StreamingEmitter<'artifact, 'sink, S>
where
    S: PackArtifactSink,
{
    const fn new(
        staged: &'artifact mut StagedArtifact<'sink, S>,
        format: ObjectFormat,
        output_limit: usize,
    ) -> Self {
        Self {
            staged,
            hasher: Some(PackStreamHasher::new(format)),
            format,
            output_limit,
            bytes_written: 0,
        }
    }

    const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    fn emit_hashed(&mut self, bytes: &[u8]) -> Result<(), PackWriteError> {
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
        self.emit(&checksum)?;
        object_id_from_bytes(self.format, &checksum).map_err(Into::into)
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
    use crate::{NativeChecksumVerifier, apply_delta, read_verified_pack};

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
                .ok_or(PackWriteError::MissingCanonicalObject(*id))
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
        let (second_bytes, second_receipt) = PackWriter::new(limits())
            .write(&plan, &mut always)
            .expect("second deterministic pack");
        assert_eq!(bytes, second_bytes);
        assert_eq!(receipt, second_receipt);
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
        assert_eq!(parsed.entries().len(), 1);
        assert_eq!(parsed.entries()[0].inflated, b"");
        assert_eq!(receipt.profile.delta_window, 32);
        assert_eq!(receipt.profile.max_delta_depth, 8);
    }

    #[test]
    fn compressed_profile_reduces_a_repetitive_pack_without_changing_objects() {
        let mut state = 0x7d41_a9c3_u32;
        let mut seed = Vec::new();
        seed.try_reserve_exact(2 * 1024)
            .expect("fixed test seed allocation fits");
        for _ in 0..2 * 1024 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            seed.push((state >> 24) as u8);
        }
        let mut body = Vec::new();
        body.try_reserve_exact(8 * 1024)
            .expect("fixed test body allocation fits");
        for _ in 0..4 {
            body.extend_from_slice(&seed);
        }
        let blob = object(ObjectType::Blob, &body, 1, 7);
        let source = FixtureSource::with(vec![blob.clone()]);
        let roots = [blob.id()];
        let stored = PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits())
            .plan_selected(&source, &roots, &mut always)
            .expect("stored profile plans the canonical blob");
        let compressed = PackPlanner::new(
            ObjectFormat::Sha1,
            PackWriteProfile::COMPRESSED_V1,
            limits(),
        )
        .plan_selected(&source, &roots, &mut always)
        .expect("compressed profile plans the same canonical blob");

        let (stored_bytes, stored_receipt) = PackWriter::new(limits())
            .write(&stored, &mut always)
            .expect("stored profile writes");
        let (compressed_bytes, compressed_receipt) = PackWriter::new(limits())
            .write(&compressed, &mut always)
            .expect("compressed profile writes");

        assert_eq!(stored_receipt.object_count, compressed_receipt.object_count);
        assert_eq!(compressed_receipt.profile, PackWriteProfile::COMPRESSED_V1);
        assert!(
            compressed_bytes.len() < stored_bytes.len(),
            "the compressing profile must improve the repetitive corpus"
        );
        let parsed = read_verified_pack(
            &compressed_bytes,
            ObjectFormat::Sha1,
            &limits(),
            &mut always,
            &NativeChecksumVerifier,
        )
        .expect("compressed pack remains a valid native pack");
        assert_eq!(parsed.entries().len(), 1);
        assert_eq!(parsed.entries()[0].inflated, body);
    }

    /// A line-oriented body, the FG-028c corpus shape in miniature.
    ///
    /// `shifted_lines(1, n)` is `shifted_lines(0, n)` with its first line
    /// dropped and one line appended, so the two share no prefix and a
    /// one-byte suffix -- the exact pair prefix/suffix search cannot encode.
    fn shifted_lines(start: u32, count: u32) -> Vec<u8> {
        (start..start + count).fold(Vec::new(), |mut body, line| {
            body.extend_from_slice(line.to_string().as_bytes());
            body.push(b'\n');
            body
        })
    }

    #[test]
    fn interior_match_delta_encodes_a_shifted_base_that_prefix_suffix_cannot() {
        let base_body = shifted_lines(0, 400);
        let target_body = shifted_lines(1, 400);
        assert_eq!(
            common_prefix(&base_body, &target_body),
            0,
            "the fixture must share no prefix, or it would not discriminate"
        );

        // The refusal: prefix/suffix search cannot express this pair at all.
        let prefix_suffix = make_prefix_suffix_delta_program(&base_body, &target_body)
            .expect("prefix/suffix program builds");
        assert!(
            prefix_suffix.len() >= target_body.len(),
            "prefix/suffix must not beat a full object here; got {} against {}",
            prefix_suffix.len(),
            target_body.len()
        );
        assert_eq!(
            make_delta_program(
                &base_body,
                &target_body,
                DeltaSearch::PrefixSuffix,
                None,
                &mut always,
            )
            .expect("prefix/suffix search completes"),
            None,
            "prefix/suffix search must reject the shifted pair"
        );

        // The permitted twin: interior matching finds the shifted copy run.
        let index = BaseDeltaIndex::build(&base_body, &limits(), &mut always)
            .expect("index build completes")
            .expect("a 400-line base is long enough to index");
        let indexed = make_delta_program(
            &base_body,
            &target_body,
            DeltaSearch::IndexedBlocks,
            Some(&index),
            &mut always,
        )
        .expect("interior search completes")
        .expect("interior matching encodes the shifted base");
        assert!(
            indexed.len() * 8 < target_body.len(),
            "a one-line shift must cost far less than the object; got {} against {}",
            indexed.len(),
            target_body.len()
        );

        // Output equivalence, checked against our own applier rather than by
        // inspecting the instruction stream.
        let rebuilt = apply_delta(&base_body, &indexed, &limits(), &mut always)
            .expect("the emitted program is a valid native delta");
        assert_eq!(
            rebuilt, target_body,
            "the delta must reconstruct the target byte for byte"
        );
    }

    #[test]
    fn interior_match_delta_is_never_worse_than_prefix_suffix_and_always_round_trips() {
        let long_run = vec![b'q'; 600];
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = vec![
            // shifted: prefix/suffix is blind, interior matching wins
            (shifted_lines(0, 300), shifted_lines(1, 300)),
            // middle edit: the shape prefix/suffix already encodes well
            (
                [&long_run[..], b"middle", &long_run[..]].concat(),
                [&long_run[..], b"CHANGED", &long_run[..]].concat(),
            ),
            // pure append
            (long_run.clone(), [&long_run[..], b"tail"].concat()),
            // pure truncation
            ([&long_run[..], b"tail"].concat(), long_run.clone()),
            // unrelated bodies: neither search should invent a win
            (shifted_lines(0, 200), vec![b'z'; 700]),
            // identical bodies
            (long_run.clone(), long_run.clone()),
        ];

        for (base_body, target_body) in pairs {
            let prefix_suffix = make_prefix_suffix_delta_program(&base_body, &target_body)
                .expect("prefix/suffix program builds");
            let index = BaseDeltaIndex::build(&base_body, &limits(), &mut always)
                .expect("index build completes");
            let indexed = make_indexed_delta_program(
                index.as_ref().expect("fixtures are long enough to index"),
                &base_body,
                &target_body,
                &mut always,
            )
            .expect("interior program builds");

            let emitted = make_delta_program(
                &base_body,
                &target_body,
                DeltaSearch::IndexedBlocks,
                index.as_ref(),
                &mut always,
            )
            .expect("interior search completes");

            assert!(
                indexed.len().min(prefix_suffix.len()) <= prefix_suffix.len(),
                "the emitted encoding must never exceed the prefix/suffix encoding"
            );
            if let Some(program) = emitted {
                assert!(
                    program.len() <= prefix_suffix.len(),
                    "an accepted program must be no larger than prefix/suffix would emit"
                );
                assert!(
                    program.len() < target_body.len(),
                    "an accepted program must beat a full object"
                );
                let rebuilt = apply_delta(&base_body, &program, &limits(), &mut always)
                    .expect("every accepted program is a valid native delta");
                assert_eq!(
                    rebuilt, target_body,
                    "every accepted program must reconstruct its target exactly"
                );
            }
        }
    }

    #[test]
    fn a_base_too_short_to_index_keeps_the_prefix_suffix_bytes_exactly() {
        // Shorter than DELTA_INDEX_BLOCK_BYTES, so no index exists at all.
        let base_body = b"0123456789";
        let target_body = b"0123456789abc";
        assert!(base_body.len() < DELTA_INDEX_BLOCK_BYTES);
        assert!(
            BaseDeltaIndex::build(base_body, &limits(), &mut always)
                .expect("index build completes")
                .is_none(),
            "a base below one block must produce no index"
        );

        let fallback = make_delta_program(
            base_body,
            target_body,
            DeltaSearch::IndexedBlocks,
            None,
            &mut always,
        )
        .expect("interior search completes with no index");
        let baseline = make_delta_program(
            base_body,
            target_body,
            DeltaSearch::PrefixSuffix,
            None,
            &mut always,
        )
        .expect("prefix/suffix search completes");
        assert_eq!(
            fallback, baseline,
            "with no index the emitted bytes must be exactly the prefix/suffix bytes"
        );
        let program = fallback.expect("an appended tail is expressible as prefix/suffix");
        assert_eq!(
            apply_delta(base_body, &program, &limits(), &mut always)
                .expect("the fallback program is a valid native delta"),
            target_body,
            "the fallback program must reconstruct the target exactly"
        );
    }

    #[test]
    fn compressed_v2_deltifies_a_shifted_corpus_that_compressed_v1_leaves_whole() {
        let first_body = shifted_lines(0, 400);
        let second_body = shifted_lines(1, 400);
        // Equal recency and path hash keep the two versions adjacent under the
        // frozen ordering, so the only variable between the arms is the search.
        let first = object(ObjectType::Blob, &first_body, 5, 3);
        let second = object(ObjectType::Blob, &second_body, 5, 3);
        let source = FixtureSource::with(vec![first.clone(), second.clone()]);
        let roots = [first.id(), second.id()];

        let plan_with = |profile| {
            PackPlanner::new(ObjectFormat::Sha1, profile, limits())
                .plan_selected(&source, &roots, &mut always)
                .expect("both profiles plan the same canonical objects")
        };
        let v1 = plan_with(PackWriteProfile::COMPRESSED_V1);
        let v2 = plan_with(PackWriteProfile::COMPRESSED_V2);

        let deltas = |plan: &PackPlan| {
            plan.entries()
                .iter()
                .filter(|entry| entry.delta().is_some())
                .count()
        };
        assert_eq!(
            deltas(&v1),
            0,
            "prefix/suffix search selects no delta on a shifted corpus"
        );
        assert_eq!(
            deltas(&v2),
            1,
            "interior matching must deltify the second version against the first"
        );
        assert_eq!(
            v1.entries().len(),
            v2.entries().len(),
            "the delta search must not change which objects are planned"
        );

        let (v1_bytes, v1_receipt) = PackWriter::new(limits())
            .write(&v1, &mut always)
            .expect("compressed v1 writes");
        let (v2_bytes, v2_receipt) = PackWriter::new(limits())
            .write(&v2, &mut always)
            .expect("compressed v2 writes");
        assert_eq!(v2_receipt.profile, PackWriteProfile::COMPRESSED_V2);
        assert_eq!(
            v1_receipt.object_count, v2_receipt.object_count,
            "both profiles must emit the same object count"
        );
        assert!(
            v2_bytes.len() < v1_bytes.len(),
            "interior matching must shrink the pack; got {} against {}",
            v2_bytes.len(),
            v1_bytes.len()
        );

        // Output equivalence at the pack level: v2 still parses as a native
        // pack, and its delta entry reconstructs the exact canonical body.
        let parsed = read_verified_pack(
            &v2_bytes,
            ObjectFormat::Sha1,
            &limits(),
            &mut always,
            &NativeChecksumVerifier,
        )
        .expect("the deltified pack remains a valid native pack");
        assert_eq!(parsed.entries().len(), 2);
        let base_entry = parsed
            .entries()
            .iter()
            .find(|entry| entry.delta_base.is_none())
            .expect("one entry is a full base");
        let delta_entry = parsed
            .entries()
            .iter()
            .find(|entry| entry.delta_base.is_some())
            .expect("one entry is an OFS delta");
        let reconstructed = apply_delta(
            &base_entry.inflated,
            &delta_entry.inflated,
            &limits(),
            &mut always,
        )
        .expect("the packed delta applies to the packed base");
        let mut recovered = vec![base_entry.inflated.clone(), reconstructed];
        recovered.sort();
        let mut expected = vec![first_body, second_body];
        expected.sort();
        assert_eq!(
            recovered, expected,
            "the deltified pack must carry exactly the canonical bodies"
        );
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
    fn closure_walker_loads_canonical_references_once() {
        let child = object(ObjectType::Blob, b"closure child", 1, 3);
        let mut tree_body = b"100644 child\0".to_vec();
        tree_body.extend_from_slice(child.id().as_bytes());
        let tree_id = fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Tree, &tree_body);
        let tree =
            CanonicalPackObject::new(tree_id, ObjectType::Tree, tree_body, vec![child.id()], 2, 1);
        let source = FixtureSource::with(vec![tree.clone(), child.clone()]);
        let plan = PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits())
            .plan(&source, &[tree.id()], &mut always)
            .expect("canonical tree closure");
        assert_eq!(plan.entries().len(), 2);
        assert!(
            plan.entries()
                .iter()
                .any(|entry| entry.object().id() == child.id())
        );
    }

    #[test]
    fn selected_plan_preserves_an_authorized_filter_omission() {
        let omitted = object(ObjectType::Blob, b"intentionally omitted", 1, 3);
        let mut tree_body = b"100644 omitted\0".to_vec();
        tree_body.extend_from_slice(omitted.id().as_bytes());
        let tree_id = fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Tree, &tree_body);
        let tree = CanonicalPackObject::new(
            tree_id,
            ObjectType::Tree,
            tree_body,
            vec![omitted.id()],
            2,
            1,
        );
        let source = FixtureSource::with(vec![tree.clone()]);
        let planner = PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits());

        let selected = planner
            .plan_selected(&source, &[tree.id()], &mut always)
            .expect("caller-authorized selected tree");
        assert_eq!(selected.entries().len(), 1);
        assert_eq!(selected.entries()[0].object().id(), tree.id());

        assert!(matches!(
            planner.plan(&source, &[tree.id()], &mut always),
            Err(PackWriteError::MissingCanonicalObject(id)) if id == omitted.id()
        ));
    }

    #[test]
    fn selected_plan_refuses_duplicates_and_accepts_distinct_objects() {
        let first = object(ObjectType::Blob, b"first selected", 2, 1);
        let second = object(ObjectType::Blob, b"second selected", 1, 2);
        let source = FixtureSource::with(vec![first.clone(), second.clone()]);
        let planner = PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits());

        assert!(matches!(
            planner.plan_selected(&source, &[first.id(), first.id()], &mut always),
            Err(PackWriteError::DuplicateSelectedObject(id)) if id == first.id()
        ));
        let permitted = planner
            .plan_selected(&source, &[second.id(), first.id()], &mut always)
            .expect("distinct selected objects");
        assert_eq!(permitted.entries().len(), 2);
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
            parsed.entries()[1].header.kind,
            crate::EntryKind::OfsDelta
        ));
        let resolved = crate::apply_delta(
            plan.entries()[0].object().body(),
            delta.program(),
            &limits(),
            &mut always,
        )
        .expect("writer delta program resolves through pack delta engine");
        assert_eq!(resolved, plan.entries()[1].object().body());
    }

    #[test]
    fn delta_window_excludes_older_candidates_with_a_stable_nearest_base() {
        let first = object(ObjectType::Blob, b"aaaaaaaaaaaaaaaaaaaa--same-suffix", 3, 1);
        let second = object(ObjectType::Blob, b"aaaaaaaaaaaaaaaaaaaaXXsame-suffix", 2, 1);
        let third = object(ObjectType::Blob, b"aaaaaaaaaaaaaaaaaaaaYYsame-suffix", 1, 1);
        let profile = PackWriteProfile {
            id: "window-one-test",
            delta_window: 1,
            ..PackWriteProfile::STORED_V1
        };
        let roots = vec![first.id(), second.id(), third.id()];
        let plan = PackPlanner::new(ObjectFormat::Sha1, profile, limits())
            .plan(
                &FixtureSource::with(vec![third, first, second]),
                &roots,
                &mut always,
            )
            .expect("window-bounded plan");
        assert_eq!(
            plan.entries()[2].delta().map(PlannedDelta::base_index),
            Some(1)
        );
        assert_eq!(plan.entries()[2].delta().map(PlannedDelta::depth), Some(2));
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
        for successes in [0, 1, 3] {
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
                Err(PackWriteError::Pack(PackError::DeadlineExceeded)
                    | PackWriteError::Deflate(DeflateRefusal::Cancelled))
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
        struct MisidentifiedSource(CanonicalPackObject);

        impl CanonicalObjectSource for MisidentifiedSource {
            fn load(&self, _id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
                Ok(self.0.clone())
            }
        }

        let source = MisidentifiedSource(malformed);
        assert!(matches!(
            PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits()).plan(
                &source,
                &[valid.id()],
                &mut always,
            ),
            Err(PackWriteError::SourceIdentityMismatch { .. })
        ));

        let plan = planned(vec![valid]);
        let mut tiny_limits = limits();
        tiny_limits.max_input_bytes = PACK_HEADER_BYTES;
        assert!(matches!(
            PackWriter::new(tiny_limits).write(&plan, &mut always),
            Err(PackWriteError::OutputLimit { .. })
        ));

        let mut shallower = limits();
        shallower.max_delta_depth = PackWriteProfile::STORED_V1.max_delta_depth - 1;
        assert!(matches!(
            PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, shallower,).plan(
                &FixtureSource::with(vec![]),
                &[],
                &mut always
            ),
            Err(PackWriteError::Pack(PackError::DeltaDepthLimit { .. }))
        ));
    }

    #[test]
    fn copy_instruction_zero_size_encodes_native_64k_semantics() {
        let mut program = Vec::new();
        emit_copy_instruction(0, 0x1_0000, &mut program).expect("64k special copy");
        assert_eq!(program, vec![0x80]);
    }
}
