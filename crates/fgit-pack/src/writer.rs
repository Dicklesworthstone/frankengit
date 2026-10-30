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
//! same native type are considered, fewer when the profile bounds their body
//! bytes (`delta_window_bytes`); the smallest delta wins, then the nearest
//! preceding entry, then its native object ID.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

mod cache;
pub use cache::{MemoizedPackEncoder, PackCacheStats, PackComputationCache};
mod blob_stream;
pub use blob_stream::{CanonicalBlobReader, CanonicalBlobStream};
mod ordering;
pub use ordering::{PackOrderingSource, basename_path_hash};
mod prefix_suffix;
use prefix_suffix::{PrefixSuffixDelta, common_prefix};

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

/// Indexed base blocks between deadline checks while an index is built:
/// 64 KiB of base at the finest stride.
const DELTA_INDEX_CHECKPOINT_STRIDE: usize = 4096;

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

    /// Optionally opens one blob without retaining its body. The stream's
    /// bytes remain tentative until the writer verifies its exact length and
    /// native identity and promotes the complete pack. Existing sources need
    /// only implement `load`; versioned streaming profiles use this seam.
    fn open_blob(&self, _id: &ObjectId) -> Result<Option<CanonicalBlobStream<'_>>, PackWriteError> {
        Ok(None)
    }
}

/// The ordering metadata a caller declares for one object of a streamed pack
/// ([`PackPlanner::stream_selected_thin`]): exactly what plan order compares,
/// so entries can be emitted in plan order before any body is loaded. The
/// loaded object must agree with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackOrderKey {
    /// Native object identity.
    pub id: ObjectId,
    /// Native object type, the first ordering key.
    pub object_type: ObjectType,
    /// [`CanonicalPackObject`] recency the source will report.
    pub recency: u64,
    /// [`CanonicalPackObject`] path hash the source will report.
    pub path_hash: u64,
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

/// Deterministic ceiling on the delta search spent on one target.
///
/// Every candidate base the search scans may visit every position of the
/// target, so a scan is charged the target's full length *before* it runs and
/// a candidate that would overrun the allowance is not scanned. Candidates are
/// offered nearest-first, so the allowance keeps the nearest bases and drops
/// the farther ones -- the same preference the window already encodes -- and
/// the plan depends only on the objects, never on time or machine speed.
///
/// The allowance is `max(floor_bytes, target_multiple x target length)`. A
/// target small enough that the whole window fits under `floor_bytes` is
/// searched exactly as without a budget; only large targets lose far
/// candidates. The measurement that motivated it: a served clone of 24
/// similar 13 MB blobs spent ~76% of 300+ s single-threaded CPU in 276
/// full-length pair scans under the unbudgeted window (frankengit-77qh).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeltaWorkBudget {
    /// Allowance every target gets regardless of its size.
    pub floor_bytes: usize,
    /// Allowance per target byte, in full target scans.
    pub target_multiple: usize,
}

impl DeltaWorkBudget {
    /// Scanned target bytes allowed for a target of `target_len` bytes.
    #[must_use]
    pub const fn allowance(self, target_len: usize) -> usize {
        let scaled = self.target_multiple.saturating_mul(target_len);
        if scaled > self.floor_bytes {
            scaled
        } else {
            self.floor_bytes
        }
    }
}

/// Frozen deterministic pack-construction policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackWriteProfile {
    /// Stable profile identity recorded in every receipt.
    pub id: &'static str,
    /// Maximum preceding same-type entries considered as delta bases.
    pub delta_window: usize,
    /// Maximum body bytes of the preceding entries a decision looks back
    /// over: the candidates are the nearest entries whose bodies together fit,
    /// so an entry larger than this is nobody's base. `None` bounds the window
    /// by count alone.
    pub delta_window_bytes: Option<usize>,
    /// Maximum emitted OFS-delta chain depth, counted from base entries at 0.
    pub max_delta_depth: usize,
    /// Exact deterministic zlib profile used for every emitted member.
    pub compression: DeflateProfile,
    /// Exact deterministic delta-program search policy.
    pub delta_search: DeltaSearch,
    /// Per-target ceiling on delta-search work; `None` searches the whole
    /// window for every target.
    pub delta_work: Option<DeltaWorkBudget>,
    /// Whether a plan may delta an entry against a client-held object the pack
    /// does not carry, emitted as REF_DELTA (a thin pack). Only a profile that
    /// says so accepts [`ThinBase`]s, so every other profile's packs stay
    /// self-contained (frankengit-pazc).
    pub thin: bool,
    /// Blobs larger than this threshold are emitted whole and clear the
    /// preceding delta window. A streaming source can then supply their bytes
    /// without retaining the body. `None` preserves the original policy.
    /// The caller's independent per-object limit still governs every blob.
    pub stream_blob_threshold: Option<usize>,
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
        delta_window_bytes: None,
        max_delta_depth: 8,
        compression: DeflateProfile::FAST_STORED,
        delta_search: DeltaSearch::PrefixSuffix,
        delta_work: None,
        thin: false,
        stream_blob_threshold: None,
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
        delta_window_bytes: None,
        max_delta_depth: 8,
        compression: DeflateProfile::DEFAULT,
        delta_search: DeltaSearch::PrefixSuffix,
        delta_work: None,
        thin: false,
        stream_blob_threshold: None,
    };

    /// [`Self::COMPRESSED_V1`]'s compression with delta emission disabled.
    ///
    /// The v0/v1 wire contract permits OFS_DELTA entries only when the client
    /// echoed the `ofs-delta` capability, so a serving path needs a profile
    /// that can never emit one. A zero window admits no delta bases, which
    /// removes the emission structurally rather than by a filter a later
    /// change could bypass. Also the honest fallback for the latent violation
    /// where a delta-capable profile served OFS entries to clients that never
    /// negotiated them.
    pub const COMPRESSED_NO_DELTA_V1: Self = Self {
        id: "git-pack-compressed-no-delta-v1",
        delta_window: 0,
        delta_window_bytes: None,
        max_delta_depth: 8,
        compression: DeflateProfile::DEFAULT,
        delta_search: DeltaSearch::PrefixSuffix,
        delta_work: None,
        thin: false,
        stream_blob_threshold: None,
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
        delta_window_bytes: None,
        max_delta_depth: 8,
        compression: DeflateProfile::DEFAULT,
        delta_search: DeltaSearch::IndexedBlocks,
        delta_work: None,
        thin: false,
        stream_blob_threshold: None,
    };

    /// [`Self::COMPRESSED_V2`] with a per-target delta-search work budget.
    ///
    /// A separate profile because it changes which base a large target may
    /// choose, so its packs are not [`Self::COMPRESSED_V2`]'s (a measured
    /// profile is never silently redefined). Every target keeps a 4 MiB
    /// allowance, which covers the whole 32-entry window for any target of at
    /// most 128 KiB, so ordinary source objects plan exactly as under
    /// [`Self::COMPRESSED_V2`]. A larger target may scan at most four times
    /// its own length, i.e. its four nearest same-type candidates.
    ///
    /// Why not a sampled probe that skips hopeless pairs (NEG-033's proposal):
    /// the served-clone cost it was measured against is similar blobs, where
    /// every candidate is a good base and a probe skips nothing. The budget
    /// bounds both shapes.
    pub const COMPRESSED_V3: Self = Self {
        id: "git-pack-compressed-v3",
        delta_window: 32,
        delta_window_bytes: None,
        max_delta_depth: 8,
        compression: DeflateProfile::DEFAULT,
        delta_search: DeltaSearch::IndexedBlocks,
        delta_work: Some(DeltaWorkBudget {
            floor_bytes: 4 << 20,
            target_multiple: 4,
        }),
        thin: false,
        stream_blob_threshold: None,
    };

    /// [`Self::COMPRESSED_V3`] that may also delta against client-held objects
    /// the pack does not carry, emitted as REF_DELTA: a thin pack.
    ///
    /// Only for a fetch whose client requested `thin-pack`. The caller supplies
    /// the bounded client-held candidates ([`ThinBase`]) and owns proving that
    /// the client holds each one. A separate profile because its packs are not
    /// self-contained, so a receipt must say so. With no thin bases its plan
    /// equals [`Self::COMPRESSED_V3`]'s entry for entry (frankengit-pazc).
    pub const COMPRESSED_V3_THIN: Self = Self {
        id: "git-pack-compressed-v3-thin",
        thin: true,
        ..Self::COMPRESSED_V3
    };

    /// [`Self::COMPRESSED_V3`]'s plan, compressed with
    /// [`DeflateProfile::FIXED_OR_STORED`] (frankengit-uf91). A member block
    /// whose fixed-Huffman encoding would not beat a stored block is stored;
    /// every other block is byte-identical to V3. Entries, bases and inflated
    /// payloads equal V3's. Random or already-compressed objects were
    /// bit-encoded at ~10 MB/s and grew ~5%; they are now copied. A separate
    /// profile because its bytes differ.
    pub const COMPRESSED_V4: Self = Self {
        id: "git-pack-compressed-v4",
        compression: DeflateProfile::FIXED_OR_STORED,
        ..Self::COMPRESSED_V3
    };

    /// [`Self::COMPRESSED_V4`] that may delta against client-held objects, as
    /// [`Self::COMPRESSED_V3_THIN`] does for V3.
    pub const COMPRESSED_V4_THIN: Self = Self {
        id: "git-pack-compressed-v4-thin",
        thin: true,
        ..Self::COMPRESSED_V4
    };

    /// [`Self::COMPRESSED_V4`] whose delta candidates are also bounded by
    /// body bytes: a decision looks back over at most 128 MiB of preceding
    /// bodies (frankengit-8xyq). A streamed pack holds only its candidates,
    /// so this is what bounds a served pack's memory: 32 candidates of 14 MB
    /// blobs would hold 448 MB, and their indexes about as much again. Where
    /// the 32 nearest bodies fit, which is every window of ordinary source,
    /// the plan is V4's entry for entry. A separate profile because a window
    /// that does not fit plans differently.
    pub const COMPRESSED_V5: Self = Self {
        id: "git-pack-compressed-v5",
        delta_window_bytes: Some(128 * 1024 * 1024),
        ..Self::COMPRESSED_V4
    };

    /// [`Self::COMPRESSED_V5`] that may delta against client-held objects, as
    /// [`Self::COMPRESSED_V3_THIN`] does for V3. Client-held bases are loaded
    /// per plan, bounded by [`MAX_THIN_BASES_PER_TARGET`], not by the window.
    pub const COMPRESSED_V5_THIN: Self = Self {
        id: "git-pack-compressed-v5-thin",
        thin: true,
        ..Self::COMPRESSED_V5
    };

    /// V5 for buffered objects, with blobs over 32 MiB emitted as full bases
    /// through a bounded stream. Such a blob clears the delta window and is
    /// never retained as a later base. Small-object bytes stay equal to V5;
    /// callers must explicitly select a larger object and encoder envelope.
    pub const COMPRESSED_V6: Self = Self {
        id: "git-pack-compressed-v6",
        stream_blob_threshold: Some(32 * 1024 * 1024),
        ..Self::COMPRESSED_V5
    };

    /// V6 with independently proven, buffered client-held thin bases.
    pub const COMPRESSED_V6_THIN: Self = Self {
        id: "git-pack-compressed-v6-thin",
        thin: true,
        ..Self::COMPRESSED_V6
    };

    /// The original no-delta compression policy with bounded blob streaming.
    /// This profile never emits OFS_DELTA, including for small objects.
    pub const COMPRESSED_NO_DELTA_V2: Self = Self {
        id: "git-pack-compressed-no-delta-v2",
        stream_blob_threshold: Some(32 * 1024 * 1024),
        ..Self::COMPRESSED_NO_DELTA_V1
    };

    const fn streams_blob(self, kind: ObjectType, length: usize) -> bool {
        matches!(kind, ObjectType::Blob)
            && match self.stream_blob_threshold {
                Some(threshold) => length > threshold,
                None => false,
            }
    }
}

/// Maximum client-held bases a plan considers for one target.
pub const MAX_THIN_BASES_PER_TARGET: usize = 2;

/// A client-held object offered as a delta base for one pack target.
///
/// The caller proves the client holds `base`. In a served fetch that means
/// `base` lies in the authenticated closure of the client's haves. The
/// planner verifies both identities, refuses a base the pack itself carries,
/// and never emits the base object.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ThinBase {
    target: ObjectId,
    base: ObjectId,
}

impl ThinBase {
    /// Offers `base` as a candidate delta base for `target`.
    #[must_use]
    pub const fn new(target: ObjectId, base: ObjectId) -> Self {
        Self { target, base }
    }

    /// The pack entry this base may serve.
    #[must_use]
    pub const fn target(&self) -> ObjectId {
        self.target
    }

    /// The client-held base object.
    #[must_use]
    pub const fn base(&self) -> ObjectId {
        self.base
    }
}

/// Where a planned delta's base lives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedDeltaBase {
    /// An earlier entry of the same pack, emitted as OFS_DELTA.
    Pack(usize),
    /// A client-held object the pack does not carry, emitted as REF_DELTA.
    Client(ObjectId),
}

/// A selected delta relation in a deterministic plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedDelta {
    base: PlannedDeltaBase,
    depth: usize,
    program: Vec<u8>,
}

impl PlannedDelta {
    /// Where the base of this delta lives.
    #[must_use]
    pub const fn base(&self) -> PlannedDeltaBase {
        self.base
    }

    /// Index of the earlier planned base entry, for an in-pack base.
    #[must_use]
    pub const fn base_index(&self) -> Option<usize> {
        match self.base {
            PlannedDeltaBase::Pack(index) => Some(index),
            PlannedDeltaBase::Client(_) => None,
        }
    }

    /// Program bytes plus the base ID a REF_DELTA entry also carries: the
    /// length a client-held base must beat. An in-pack base's OFS distance is
    /// a few bytes and is not counted, so in-pack comparisons are unchanged.
    const fn effective_len(&self) -> usize {
        match self.base {
            PlannedDeltaBase::Pack(_) => self.program.len(),
            PlannedDeltaBase::Client(base) => self.program.len() + base.as_bytes().len(),
        }
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
    cache: Option<Arc<PackComputationCache>>,
}

impl PackPlanner {
    /// Creates a planner with explicit native format, profile, and bounds.
    #[must_use]
    pub const fn new(format: ObjectFormat, profile: PackWriteProfile, limits: PackLimits) -> Self {
        Self {
            format,
            profile,
            limits,
            cache: None,
        }
    }

    /// Reuse pure delta computations after ordinary selection and validation.
    #[must_use]
    pub fn with_computation_cache(mut self, cache: Arc<PackComputationCache>) -> Self {
        self.cache = Some(cache);
        self
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

        self.finish_plan(
            objects,
            total_object_bytes,
            &ExternalBases::default(),
            deadline,
        )
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
        self.plan_selected_thin(source, selected, &[], deadline)
    }

    /// [`Self::plan_selected`] that may also delta an entry against a
    /// client-held object the pack does not carry (frankengit-pazc).
    ///
    /// Only a [`PackWriteProfile::thin`] profile accepts `thin_bases`. Each
    /// base is loaded and verified like a pack object but never emitted; the
    /// caller owns proving that the client holds it. A thin base competes with
    /// the in-pack window under the same work budget and is chosen only when
    /// its program is strictly shorter; an in-pack base wins an equal length.
    pub fn plan_selected_thin(
        &self,
        source: &impl CanonicalObjectSource,
        selected: &[ObjectId],
        thin_bases: &[ThinBase],
        deadline: &mut impl Deadline,
    ) -> Result<PackPlan, PackWriteError> {
        if !thin_bases.is_empty() && !self.profile.thin {
            return Err(PackWriteError::ThinBasesNotPermitted);
        }
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
        for &id in &ids {
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
        let external = self.load_thin_bases(source, &ids, thin_bases, deadline)?;
        self.finish_plan(objects, total_object_bytes, &external, deadline)
    }

    /// [`Self::plan_selected_thin`] followed by [`PackWriter::write_into`],
    /// byte for byte, without holding the plan (frankengit-8xyq).
    ///
    /// The caller declares each selected object's ordering key, so entries are
    /// emitted in plan order before any body is loaded; every loaded object
    /// must match its key. Each object is loaded, verified, decided against the
    /// window and emitted, then kept only while it can still be a delta base.
    /// A target's client-held bases are loaded for its decision alone. Held
    /// object bytes are therefore the candidates (bounded by the profile's
    /// `delta_window_bytes`, and refused typed past `max_cached_bytes` as
    /// [`PackWriteError::WindowCacheLimit`]) plus the current target and its
    /// at most [`MAX_THIN_BASES_PER_TARGET`] bases, not the pack. Decisions
    /// and emission share the planned path's code. The sink receives the
    /// complete pack and is promoted only after the trailer.
    pub fn stream_selected_thin(
        &self,
        source: &impl CanonicalObjectSource,
        selected: &[PackOrderKey],
        thin_bases: &[ThinBase],
        writer: &PackWriter,
        encoder: &mut impl PackEntryEncoder,
        sink: &mut impl PackArtifactSink,
        deadline: &mut impl Deadline,
    ) -> Result<PackWriteReceipt, PackWriteError> {
        if !thin_bases.is_empty() && !self.profile.thin {
            return Err(PackWriteError::ThinBasesNotPermitted);
        }
        self.validate_profile_depth()?;
        let count = u32::try_from(selected.len()).map_err(|_| PackError::EntryCountLimit {
            actual: u32::MAX,
            limit: self.limits.max_entries,
        })?;
        for limit in [self.limits.max_entries, writer.limits.max_entries] {
            if count > limit {
                return Err(PackError::EntryCountLimit {
                    actual: count,
                    limit,
                }
                .into());
            }
        }
        let mut ids = Vec::new();
        ids.try_reserve_exact(selected.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: selected.len(),
            })?;
        for key in selected {
            checkpoint(deadline)?;
            ensure_format(self.format, key.id)?;
            ids.push(key.id);
        }
        ids.sort_unstable();
        for pair in ids.windows(2) {
            if pair[0] == pair[1] {
                return Err(PackWriteError::DuplicateSelectedObject(pair[0]));
            }
        }
        let offers = self.validate_thin_offers(&ids, thin_bases, deadline)?;
        drop(ids);
        let mut counted_bases = BTreeSet::new();
        let mut total_base_bytes = 0_usize;
        let mut order = Vec::new();
        order
            .try_reserve_exact(selected.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: selected.len(),
            })?;
        order.extend_from_slice(selected);
        order.sort_unstable_by(compare_order_keys);

        let temporary = sink.create_temporary()?;
        let mut staged = StagedArtifact::new(sink, temporary);
        let mut emitter =
            StreamingEmitter::new(&mut staged, self.format, writer.limits.max_input_bytes);
        checkpoint(deadline)?;
        emitter.emit_hashed(&pack_header(count))?;
        let mut offsets = Vec::new();
        let mut compression = Vec::new();
        compression
            .try_reserve(order.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: order.len(),
            })?;
        let mut selector = DeltaSelector::new(self.profile, &self.limits, None)?;
        selector.cache.clone_from(&self.cache);
        let mut total_object_bytes = 0_usize;
        let mut delta_count = 0_usize;
        for key in order {
            checkpoint(deadline)?;
            let stream = if self.profile.stream_blob_threshold.is_some()
                && key.object_type == ObjectType::Blob
            {
                let opened = source.open_blob(&key.id);
                checkpoint(deadline)?;
                opened?
            } else {
                None
            };
            let object = if let Some(blob) = stream {
                blob.validate_key(key)?;
                let next_total = selected_object_total(
                    blob.length(),
                    total_object_bytes,
                    &self.limits,
                    &writer.limits,
                )?;
                if self.profile.streams_blob(ObjectType::Blob, blob.length()) {
                    total_object_bytes = next_total;
                    compression.push(blob_stream::emit_blob(
                        &mut emitter,
                        blob,
                        &mut offsets,
                        encoder,
                        self.profile,
                        deadline,
                    )?);
                    selector.advance_streamed_blob()?;
                    continue;
                }
                blob.into_buffered(deadline)?
            } else {
                let loaded = source.load(&key.id);
                checkpoint(deadline)?;
                loaded?
            };
            if object.id != key.id {
                return Err(PackWriteError::SourceIdentityMismatch {
                    requested: key.id,
                    returned: object.id,
                });
            }
            if object.object_type != key.object_type
                || object.recency != key.recency
                || object.path_hash != key.path_hash
            {
                return Err(PackWriteError::SourceOrderMismatch(key.id));
            }
            total_object_bytes = selected_object_total(
                object.body.len(),
                total_object_bytes,
                &self.limits,
                &writer.limits,
            )?;
            if self
                .profile
                .streams_blob(object.object_type, object.body.len())
            {
                compression.push(blob_stream::emit_blob(
                    &mut emitter,
                    CanonicalBlobStream::from_buffered(object),
                    &mut offsets,
                    encoder,
                    self.profile,
                    deadline,
                )?);
                selector.advance_streamed_blob()?;
                continue;
            }
            verify_native_object(
                self.format,
                object.object_type,
                &object.body,
                &object.id,
                AcceptanceProfile::GitCompatibleImport,
                &object_parse_limits(self.format, &self.limits),
            )?;
            let external = self.load_target_thin_bases(
                source,
                &offers,
                key.id,
                &mut counted_bases,
                &mut total_base_bytes,
                deadline,
            )?;
            let delta = selector.decide(&object, &external, deadline)?;
            drop(external);
            let entry = PackPlanEntry { object, delta };
            if let Some(delta) = entry.delta.as_ref() {
                writer.limits.object_size(delta.program.len())?;
                if delta.base_index().is_none() && !self.profile.thin {
                    return Err(PackWriteError::ThinBasesNotPermitted);
                }
            }
            checkpoint(deadline)?;
            let (receipt, delta) =
                emit_planned_entry(&mut emitter, &entry, &mut offsets, encoder, deadline)?;
            if delta {
                delta_count = delta_count
                    .checked_add(1)
                    .ok_or(PackError::IntegerOverflow {
                        context: "pack delta count",
                    })?;
            }
            compression.push(receipt);
            selector.push(entry)?;
            if selector.window.resident_bytes > self.limits.max_cached_bytes {
                return Err(PackWriteError::WindowCacheLimit {
                    resident: selector.window.resident_bytes,
                    limit: self.limits.max_cached_bytes,
                });
            }
        }
        let checksum = emitter.finish_and_emit_trailer(deadline)?;
        let output_bytes = emitter.bytes_written();
        staged.promote()?;
        Ok(PackWriteReceipt {
            profile: self.profile,
            checksum,
            object_count: count,
            delta_count,
            total_object_bytes,
            output_bytes,
            compression,
        })
    }

    /// Loads and verifies the offered client-held bases, grouped by target.
    fn load_thin_bases(
        &self,
        source: &impl CanonicalObjectSource,
        selected: &[ObjectId],
        thin_bases: &[ThinBase],
        deadline: &mut impl Deadline,
    ) -> Result<ExternalBases, PackWriteError> {
        let mut external = ExternalBases::default();
        let offers = self.validate_thin_offers(selected, thin_bases, deadline)?;
        if offers.is_empty() {
            return Ok(external);
        }
        let mut bases: Vec<ObjectId> = offers.iter().map(ThinBase::base).collect();
        bases.sort_unstable();
        bases.dedup();
        let mut total_base_bytes = 0_usize;
        external
            .objects
            .try_reserve_exact(bases.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: bases.len(),
            })?;
        for id in bases {
            if let Some(object) =
                self.load_thin_base(source, id, &mut total_base_bytes, deadline)?
            {
                external.objects.push(object);
            }
        }
        for offer in offers {
            let Ok(position) = external
                .objects
                .binary_search_by(|object| object.id.cmp(&offer.base))
            else {
                // A streamed large blob is deliberately not a delta base.
                continue;
            };
            external
                .by_target
                .entry(offer.target)
                .or_default()
                .push(position);
        }
        Ok(external)
    }

    /// The offers sorted by target then base, each target's at most
    /// [`MAX_THIN_BASES_PER_TARGET`], every target in `selected` (sorted) and
    /// no base in it. Identities only; nothing is loaded.
    fn validate_thin_offers(
        &self,
        selected: &[ObjectId],
        thin_bases: &[ThinBase],
        deadline: &mut impl Deadline,
    ) -> Result<Vec<ThinBase>, PackWriteError> {
        let mut offers = Vec::new();
        if thin_bases.is_empty() {
            return Ok(offers);
        }
        offers
            .try_reserve_exact(thin_bases.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: thin_bases.len(),
            })?;
        offers.extend_from_slice(thin_bases);
        offers.sort_unstable();
        let in_pack = |id: &ObjectId| selected.binary_search(id).is_ok();
        let mut per_target = 0_usize;
        for (index, offer) in offers.iter().enumerate() {
            checkpoint(deadline)?;
            ensure_format(self.format, offer.target)?;
            ensure_format(self.format, offer.base)?;
            let invalid = PackWriteError::InvalidThinBase {
                target: offer.target,
                base: offer.base,
            };
            let previous = index.checked_sub(1).map(|previous| offers[previous]);
            per_target = match previous {
                Some(previous) if previous == *offer => return Err(invalid),
                Some(previous) if previous.target == offer.target => per_target + 1,
                _ => 1,
            };
            if per_target > MAX_THIN_BASES_PER_TARGET
                || !in_pack(&offer.target)
                || in_pack(&offer.base)
            {
                return Err(invalid);
            }
        }
        Ok(offers)
    }

    /// One client-held base, loaded and verified, its bytes added to the
    /// distinct-base total that `max_total_expanded_bytes` bounds.
    fn load_thin_base(
        &self,
        source: &impl CanonicalObjectSource,
        id: ObjectId,
        total_base_bytes: &mut usize,
        deadline: &mut impl Deadline,
    ) -> Result<Option<CanonicalPackObject>, PackWriteError> {
        checkpoint(deadline)?;
        if self.profile.stream_blob_threshold.is_some() {
            let opened = source.open_blob(&id);
            checkpoint(deadline)?;
            if let Some(blob) = opened? {
                blob.validate_key(PackOrderKey {
                    id,
                    object_type: ObjectType::Blob,
                    recency: blob.order_key().recency,
                    path_hash: blob.order_key().path_hash,
                })?;
                if self.profile.streams_blob(ObjectType::Blob, blob.length()) {
                    return Ok(None);
                }
            }
        }
        let object = source.load(&id)?;
        if object.id != id {
            return Err(PackWriteError::SourceIdentityMismatch {
                requested: id,
                returned: object.id,
            });
        }
        if self
            .profile
            .streams_blob(object.object_type, object.body.len())
        {
            return Ok(None);
        }
        self.limits.object_size(object.body.len())?;
        *total_base_bytes =
            total_base_bytes
                .checked_add(object.body.len())
                .ok_or(PackError::IntegerOverflow {
                    context: "thin base total object bytes",
                })?;
        if *total_base_bytes > self.limits.max_total_expanded_bytes {
            return Err(PackError::TotalExpandedLimit {
                actual: *total_base_bytes,
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
        Ok(Some(object))
    }

    /// The client-held bases offered for `target` alone, loaded for its one
    /// decision. A decision reads only its own target's bases, so this is
    /// [`Self::load_thin_bases`]'s view of that target. `counted` keeps each
    /// distinct base in the total once, as the planned path counts it.
    fn load_target_thin_bases(
        &self,
        source: &impl CanonicalObjectSource,
        offers: &[ThinBase],
        target: ObjectId,
        counted: &mut BTreeSet<ObjectId>,
        total_base_bytes: &mut usize,
        deadline: &mut impl Deadline,
    ) -> Result<ExternalBases, PackWriteError> {
        let mut external = ExternalBases::default();
        let first = offers.partition_point(|offer| offer.target < target);
        let mine = offers[first..]
            .iter()
            .take_while(|offer| offer.target == target);
        for offer in mine {
            let mut uncounted = 0_usize;
            let total = if counted.insert(offer.base) {
                &mut *total_base_bytes
            } else {
                &mut uncounted
            };
            let Some(object) = self.load_thin_base(source, offer.base, total, deadline)? else {
                continue;
            };
            external
                .objects
                .try_reserve(1)
                .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
            external.objects.push(object);
        }
        if !external.objects.is_empty() {
            let positions: Vec<usize> = (0..external.objects.len()).collect();
            external.by_target.insert(target, positions);
        }
        Ok(external)
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
        external: &ExternalBases,
        deadline: &mut impl Deadline,
    ) -> Result<PackPlan, PackWriteError> {
        objects.sort_unstable_by(compare_pack_objects);
        let entries = select_deltas_cached(
            &objects,
            external,
            self.profile,
            &self.limits,
            self.cache.clone(),
            deadline,
        )?;
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
    /// A promoted artifact could not be read back from its custody.
    TemporaryReadRefused,
    /// A completed dependency encoder omitted its required immutable receipt.
    MissingCompressionReceipt,
    /// A custom encoder's receipt did not bind the actual streamed member.
    CompressionReceiptMismatch,
    /// This encoder has no bounded streaming input implementation.
    StreamingEncoderUnsupported,
    /// A source's observed EOF did not match its declared blob length.
    SourceLengthMismatch {
        id: ObjectId,
        declared: usize,
        observed: usize,
    },
    /// A source returned more bytes than the supplied destination could hold.
    SourceReadOverflow { count: usize, capacity: usize },
    /// Thin bases were offered to a profile that emits only self-contained
    /// packs, or a self-contained profile's plan carries a client-held base.
    ThinBasesNotPermitted,
    /// A streamed object did not match the type, recency or path hash its
    /// caller declared for ordering (frankengit-8xyq).
    SourceOrderMismatch(ObjectId),
    /// A streamed pack's delta window would hold more object bytes than
    /// `max_cached_bytes` (frankengit-8xyq).
    WindowCacheLimit {
        /// Object bytes the window would hold.
        resident: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// A thin-base offer the planner cannot honour: its target is not in the
    /// pack, its base is, the pair repeats, or the target already has
    /// [`MAX_THIN_BASES_PER_TARGET`] bases.
    InvalidThinBase {
        /// The pack entry the base was offered for.
        target: ObjectId,
        /// The offered client-held base.
        base: ObjectId,
    },
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

    /// Encodes a payload for an already verified native object. The default
    /// preserves custom encoders; memoizing encoders also bind this identity.
    fn encode_object_entry(
        &mut self,
        _id: ObjectId,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        self.encode_entry(input, deadline, emit)
    }

    /// Encodes a blob without retaining its entire body. The default fails
    /// closed for custom encoders that only implement buffered input. The
    /// writer verifies the source identity and exact length before promotion.
    fn encode_blob_stream(
        &mut self,
        _input: &mut dyn CanonicalBlobReader,
        _declared_length: usize,
        _deadline: &mut dyn Deadline,
        _emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        Err(PackWriteError::StreamingEncoderUnsupported)
    }
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

    /// The encoder [`PackWriter::write`] uses for `profile`: its compression
    /// profile under the Git-object DEFLATE bounds.
    #[must_use]
    pub const fn for_profile(profile: PackWriteProfile) -> Self {
        Self::new(DeflateLimits::GIT_OBJECT, profile.compression)
    }

    /// Bounded encoder for an explicitly widened pack-object envelope. Input
    /// and output inherit the caller's byte limits. Per-member codec work is
    /// at most eight units per permitted object byte, with the original Git
    /// codec work allowance as a floor. Pending input and history stay fixed.
    /// An unrepresentable work envelope is refused before source reads.
    pub fn for_pack_limits(
        profile: PackWriteProfile,
        limits: &PackLimits,
    ) -> Result<Self, PackWriteError> {
        let work = u64::try_from(limits.max_object_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or(PackError::IntegerOverflow {
                context: "streamed pack compression work",
            })?;
        Ok(Self::new(
            DeflateLimits {
                max_input_bytes: limits.max_object_bytes.max(1),
                max_output_bytes: limits.max_input_bytes,
                max_work_units: work.max(DeflateLimits::GIT_OBJECT.max_work_units),
                ..DeflateLimits::GIT_OBJECT
            },
            profile.compression,
        ))
    }
}

impl PackEntryEncoder for DeterministicPackEncoder {
    fn encode_entry(
        &mut self,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        self.encode_with_work(input, deadline, emit)
            .map(|(receipt, _)| receipt)
    }

    fn encode_blob_stream(
        &mut self,
        input: &mut dyn CanonicalBlobReader,
        declared_length: usize,
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<DeflateReceipt, PackWriteError> {
        self.encode_stream_with_work(input, declared_length, deadline, emit)
            .map(|(receipt, _)| receipt)
    }
}

impl DeterministicPackEncoder {
    fn encode_stream_with_work(
        &self,
        input: &mut dyn CanonicalBlobReader,
        declared_length: usize,
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<(DeflateReceipt, u64), PackWriteError> {
        checkpoint(deadline)?;
        if declared_length > self.limits.max_input_bytes {
            return Err(DeflateRefusal::ResourceLimit {
                resource: fgit_deflate::Resource::InputBytes,
                limit: self.limits.max_input_bytes as u64,
                observed: declared_length as u64,
            }
            .into());
        }
        let mut encoder = Deflater::new(self.limits, self.profile)?;
        emit(&encoder.take_output())?;
        let mut chunk = [0; ENCODER_INPUT_CHUNK_BYTES];
        loop {
            // Refill a complete fixed-size input chunk across short reads so
            // source fragmentation never changes the deterministic zlib bytes.
            let mut filled = 0;
            while filled < chunk.len() {
                checkpoint(deadline)?;
                let read = input.read(&mut chunk[filled..]);
                checkpoint(deadline)?;
                let count = read?;
                if count > chunk.len() - filled {
                    return Err(PackWriteError::SourceReadOverflow {
                        count,
                        capacity: chunk.len() - filled,
                    });
                }
                if count == 0 {
                    break;
                }
                filled += count;
            }
            if filled != 0 {
                let mut control = DeflateDeadline { deadline };
                let _ = encoder.push_with_control(&chunk[..filled], &mut control)?;
                emit(&encoder.take_output())?;
            }
            if filled < chunk.len() {
                break;
            }
        }
        let mut control = DeflateDeadline { deadline };
        encoder.finish_with_control(&mut control)?;
        emit(&encoder.take_output())?;
        let receipt = encoder
            .receipt()
            .ok_or(PackWriteError::MissingCompressionReceipt)?;
        Ok((receipt, encoder.work_units()))
    }

    fn encode_with_work(
        &self,
        input: &[u8],
        deadline: &mut dyn Deadline,
        emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
    ) -> Result<(DeflateReceipt, u64), PackWriteError> {
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
        let receipt = encoder
            .receipt()
            .ok_or(PackWriteError::MissingCompressionReceipt)?;
        Ok((receipt, encoder.work_units()))
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
        let mut encoder = DeterministicPackEncoder::for_profile(plan.profile);
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
            let (receipt, delta) =
                emit_planned_entry(&mut emitter, entry, &mut offsets, encoder, deadline)?;
            if delta {
                delta_count = delta_count
                    .checked_add(1)
                    .ok_or(PackError::IntegerOverflow {
                        context: "pack delta count",
                    })?;
            }
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

/// Emits one planned entry at the current offset and records that offset.
fn selected_object_total(
    length: usize,
    previous: usize,
    planner: &PackLimits,
    writer: &PackLimits,
) -> Result<usize, PackWriteError> {
    planner.object_size(length)?;
    writer.object_size(length)?;
    let total = previous
        .checked_add(length)
        .ok_or(PackError::IntegerOverflow {
            context: "selected pack plan total object bytes",
        })?;
    for limit in [
        planner.max_total_expanded_bytes,
        writer.max_total_expanded_bytes,
    ] {
        if total > limit {
            return Err(PackError::TotalExpandedLimit {
                actual: total,
                limit,
            }
            .into());
        }
    }
    Ok(total)
}

/// [`PackWriter::write_into`] and [`PackPlanner::stream_selected_thin`] both
/// emit through this, so equal decisions give equal bytes. Returns the
/// member's receipt and whether the entry is a delta.
fn emit_planned_entry<S: PackArtifactSink>(
    emitter: &mut StreamingEmitter<'_, '_, S>,
    entry: &PackPlanEntry,
    offsets: &mut Vec<u64>,
    encoder: &mut impl PackEntryEncoder,
    deadline: &mut impl Deadline,
) -> Result<(DeflateReceipt, bool), PackWriteError> {
    {
        {
            let offset =
                u64::try_from(emitter.bytes_written()).map_err(|_| PackError::IntegerOverflow {
                    context: "pack entry offset",
                })?;
            offsets
                .try_reserve(1)
                .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
            offsets.push(offset);
            let payload = match entry.delta.as_ref() {
                Some(delta) => {
                    match delta.base {
                        PlannedDeltaBase::Pack(base_index) => {
                            let base_offset =
                                *offsets.get(base_index).ok_or(PackError::MissingDeltaBase)?;
                            let distance = offset
                                .checked_sub(base_offset)
                                .ok_or(PackError::InvalidOfsDelta)?;
                            emitter.emit_hashed(&encode_entry_header(6, delta.program.len())?)?;
                            emitter.emit_hashed(&encode_ofs_delta_distance(distance)?)?;
                        }
                        // REF_DELTA names the client-held base by its native ID.
                        PlannedDeltaBase::Client(base) => {
                            emitter.emit_hashed(&encode_entry_header(7, delta.program.len())?)?;
                            emitter.emit_hashed(base.as_bytes())?;
                        }
                    }
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
                encoder.encode_object_entry(entry.object.id, payload, deadline, &mut |bytes| {
                    emitter.emit_hashed(bytes)
                })?;
            Ok((receipt, entry.delta.is_some()))
        }
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
    // Only a thin plan may name a client-held base, so only it pays for this set.
    let in_pack: BTreeSet<ObjectId> = if plan.profile.thin {
        plan.entries.iter().map(|entry| entry.object.id).collect()
    } else {
        BTreeSet::new()
    };
    for (index, entry) in plan.entries.iter().enumerate() {
        limits.object_size(entry.object.body.len())?;
        fanout.push(0_usize);
        let Some(delta) = entry.delta.as_ref() else {
            continue;
        };
        limits.object_size(delta.program.len())?;
        let base_index = match delta.base {
            PlannedDeltaBase::Pack(base_index) => base_index,
            PlannedDeltaBase::Client(base) => {
                // A client-held base is legal only in a thin profile, and only
                // for an object the pack itself does not carry.
                if !plan.profile.thin {
                    return Err(PackWriteError::ThinBasesNotPermitted);
                }
                ensure_format(plan.format, base)?;
                if in_pack.contains(&base) {
                    return Err(PackWriteError::InvalidThinBase {
                        target: entry.object.id,
                        base,
                    });
                }
                if delta.depth > limits.max_delta_depth {
                    return Err(PackError::DeltaDepthLimit {
                        depth: delta.depth,
                        limit: limits.max_delta_depth,
                    }
                    .into());
                }
                continue;
            }
        };
        if base_index >= index {
            return Err(PackError::MissingDeltaBase.into());
        }
        if delta.depth > limits.max_delta_depth {
            return Err(PackError::DeltaDepthLimit {
                depth: delta.depth,
                limit: limits.max_delta_depth,
            }
            .into());
        }
        fanout[base_index] =
            fanout[base_index]
                .checked_add(1)
                .ok_or(PackError::IntegerOverflow {
                    context: "pack plan delta fanout",
                })?;
        if fanout[base_index] > limits.max_delta_fanout {
            return Err(PackError::DeltaFanoutLimit {
                fanout: fanout[base_index],
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

/// Verified client-held bases and the targets each may serve.
#[derive(Default)]
struct ExternalBases {
    /// Distinct bases in object-ID order.
    objects: Vec<CanonicalPackObject>,
    /// Target ID to indices into `objects`, in base-ID order.
    by_target: BTreeMap<ObjectId, Vec<usize>>,
}

/// [`compare_pack_objects`] over declared keys: the same total order.
fn compare_order_keys(left: &PackOrderKey, right: &PackOrderKey) -> std::cmp::Ordering {
    left.object_type
        .type_code()
        .cmp(&right.object_type.type_code())
        .then_with(|| right.recency.cmp(&left.recency))
        .then_with(|| left.path_hash.cmp(&right.path_hash))
        .then_with(|| left.id.cmp(&right.id))
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

#[cfg(test)]
fn select_deltas(
    objects: &[CanonicalPackObject],
    external: &ExternalBases,
    profile: PackWriteProfile,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<PackPlanEntry>, PackWriteError> {
    select_deltas_cached(objects, external, profile, limits, None, deadline)
}

fn select_deltas_cached(
    objects: &[CanonicalPackObject],
    external: &ExternalBases,
    profile: PackWriteProfile,
    limits: &PackLimits,
    cache: Option<Arc<PackComputationCache>>,
    deadline: &mut impl Deadline,
) -> Result<Vec<PackPlanEntry>, PackWriteError> {
    let mut selector = DeltaSelector::new(profile, limits, Some(objects.len()))?;
    selector.cache = cache;
    for object in objects {
        let delta = selector.decide(object, external, deadline)?;
        selector.push(PackPlanEntry {
            object: object.clone(),
            delta,
        })?;
    }
    Ok(selector.window.entries.into())
}

/// The plan entries a delta decision may look back at, by absolute index.
///
/// The next decision's candidates are `start..len()`: the nearest entries, at
/// most the profile's `delta_window` of them and, under a byte bound, only as
/// many as fit in it. A plan retains every entry; a streamed pack evicts each
/// one as it leaves the candidates, since no later decision can name it
/// (frankengit-8xyq). Decisions read entries solely through [`Self::get`]
/// and [`Self::fanout`], so both keep the same decisions.
struct DeltaWindow {
    /// Absolute index of `entries[0]`.
    first: usize,
    entries: VecDeque<PackPlanEntry>,
    fanout: VecDeque<usize>,
    /// Whether entries leaving the candidates are dropped (a stream).
    evict: bool,
    /// The profile's candidate count bound.
    count: usize,
    /// The profile's candidate body-byte bound, if any.
    bytes: Option<usize>,
    /// Absolute index of the next decision's oldest candidate.
    start: usize,
    /// Body bytes of the candidates `start..len()`.
    candidate_bytes: usize,
    /// Object body bytes currently held.
    resident_bytes: usize,
}

impl DeltaWindow {
    fn len(&self) -> usize {
        self.first + self.entries.len()
    }

    fn get(&self, index: usize) -> &PackPlanEntry {
        &self.entries[index - self.first]
    }

    fn fanout(&self, index: usize) -> usize {
        self.fanout[index - self.first]
    }

    fn push(&mut self, entry: PackPlanEntry) -> Result<(), PackWriteError> {
        let base = entry.delta.as_ref().and_then(PlannedDelta::base_index);
        self.resident_bytes = self
            .resident_bytes
            .checked_add(entry.object.body.len())
            .ok_or(PackError::IntegerOverflow {
                context: "delta window resident bytes",
            })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
        self.fanout
            .try_reserve(1)
            .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
        self.candidate_bytes = self
            .candidate_bytes
            .checked_add(entry.object.body.len())
            .ok_or(PackError::IntegerOverflow {
                context: "delta window candidate bytes",
            })?;
        self.entries.push_back(entry);
        self.fanout.push_back(0);
        if let Some(base_index) = base {
            let count = &mut self.fanout[base_index - self.first];
            *count = count.checked_add(1).ok_or(PackError::IntegerOverflow {
                context: "planned delta fanout",
            })?;
        }
        while self.len() - self.start > self.count
            || self.bytes.is_some_and(|limit| self.candidate_bytes > limit)
        {
            let leaving = self.get(self.start).object.body.len();
            self.candidate_bytes -= leaving;
            self.start += 1;
        }
        if self.evict {
            while self.first < self.start {
                if let Some(evicted) = self.entries.pop_front() {
                    self.resident_bytes -= evicted.object.body.len();
                }
                self.fanout.pop_front();
                self.first += 1;
            }
        }
        Ok(())
    }
}

/// One plan's delta policy over a [`DeltaWindow`].
struct DeltaSelector<'limits> {
    profile: PackWriteProfile,
    limits: &'limits PackLimits,
    window: DeltaWindow,
    /// One index per candidate base, built on first use and retained only while
    /// that base is still inside the window. Every target in the window would
    /// otherwise rebuild the same index, which is the whole cost of the search.
    indexes: VecDeque<(usize, Option<BaseDeltaIndex>)>,
    cache: Option<Arc<PackComputationCache>>,
    cache_fingerprint: [u8; 32],
}

impl<'limits> DeltaSelector<'limits> {
    /// `retain` is the plan's entry count when every entry is kept, or `None`
    /// for a stream that keeps only the delta window.
    fn new(
        profile: PackWriteProfile,
        limits: &'limits PackLimits,
        retain: Option<usize>,
    ) -> Result<Self, PackWriteError> {
        let capacity = retain.unwrap_or(profile.delta_window.saturating_add(1));
        let mut entries = VecDeque::new();
        entries
            .try_reserve(capacity)
            .map_err(|_| PackError::AllocationFailed {
                requested: capacity,
            })?;
        let mut fanout = VecDeque::new();
        fanout
            .try_reserve(capacity)
            .map_err(|_| PackError::AllocationFailed {
                requested: capacity,
            })?;
        Ok(Self {
            profile,
            limits,
            window: DeltaWindow {
                first: 0,
                entries,
                fanout,
                evict: retain.is_none(),
                count: profile.delta_window,
                bytes: profile.delta_window_bytes,
                start: 0,
                candidate_bytes: 0,
                resident_bytes: 0,
            },
            indexes: VecDeque::new(),
            cache: None,
            cache_fingerprint: cache::delta_fingerprint(profile, limits),
        })
    }

    /// Appends a decided entry; an index whose base left the candidates goes
    /// with it. Indexes are a cache, so dropping one changes no decision.
    fn push(&mut self, entry: PackPlanEntry) -> Result<(), PackWriteError> {
        let barrier = self
            .profile
            .streams_blob(entry.object.object_type, entry.object.body.len());
        self.window.push(entry)?;
        if barrier {
            self.window.start = self.window.len();
            self.window.candidate_bytes = 0;
            if self.window.evict {
                self.window.entries.clear();
                self.window.fanout.clear();
                self.window.first = self.window.start;
                self.window.resident_bytes = 0;
            }
        }
        let start = self.window.start;
        self.indexes.retain(|(base_index, _)| *base_index >= start);
        Ok(())
    }

    /// A full streamed blob occupies one absolute pack offset, but retains no
    /// body and is a delta-window barrier under the selected frozen profile.
    fn advance_streamed_blob(&mut self) -> Result<(), PackWriteError> {
        let next = self
            .window
            .len()
            .checked_add(1)
            .ok_or(PackError::IntegerOverflow {
                context: "streamed blob pack index",
            })?;
        self.window.entries.clear();
        self.window.fanout.clear();
        self.window.first = next;
        self.window.start = next;
        self.window.candidate_bytes = 0;
        self.window.resident_bytes = 0;
        self.indexes.clear();
        Ok(())
    }

    /// The delta chosen for `object` after every entry already pushed.
    fn decide<D: Deadline>(
        &mut self,
        object: &CanonicalPackObject,
        external: &ExternalBases,
        deadline: &mut D,
    ) -> Result<Option<PlannedDelta>, PackWriteError> {
        if self
            .profile
            .streams_blob(object.object_type, object.body.len())
        {
            checkpoint(deadline)?;
            return Ok(None);
        }
        let profile = self.profile;
        let limits = self.limits;
        let max_delta_fanout = limits.max_delta_fanout;
        let window = &self.window;
        let indexes = &mut self.indexes;
        checkpoint(deadline)?;
        let window_start = window.start;
        // The candidates the window offers, nearest first, with the chain depth
        // a delta against each would have.
        let offered = window.len() - window_start;
        let mut candidates: Vec<(usize, usize)> = Vec::new();
        candidates
            .try_reserve(offered)
            .map_err(|_| PackError::AllocationFailed { requested: offered })?;
        for base_index in (window_start..window.len()).rev() {
            checkpoint(deadline)?;
            let base = window.get(base_index);
            if base.object.object_type != object.object_type {
                continue;
            }
            if window.fanout(base_index) >= max_delta_fanout {
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
            candidates.push((base_index, depth));
        }
        // Client-held bases for this target (frankengit-pazc), same type only.
        // Each is one link from a base the client already has.
        let mut thin: Vec<usize> = Vec::new();
        if profile.max_delta_depth >= 1 {
            for &position in external
                .by_target
                .get(&object.id)
                .map_or(&[][..], Vec::as_slice)
            {
                if external.objects[position].object_type == object.object_type {
                    thin.push(position);
                }
            }
        }
        // Every full scan may visit every target position, so the allowance
        // buys whole scans. Only when it cannot pay for every candidate does
        // the budget change anything: then the scans go to the candidates a
        // cheap probe ranks most promising. Client-held bases are scanned
        // first and are paid from the same allowance.
        if let Some(budget) = profile.delta_work {
            let allowance = budget
                .allowance(object.body.len())
                .checked_div(object.body.len())
                .unwrap_or(usize::MAX);
            thin.truncate(allowance);
            let scans = allowance - thin.len();
            if candidates.len() > scans {
                if profile.delta_search == DeltaSearch::IndexedBlocks {
                    candidates = rank_for_budget(
                        &candidates,
                        &object.body,
                        window,
                        indexes,
                        profile.delta_window,
                        limits,
                        deadline,
                    )?;
                }
                candidates.truncate(scans);
            }
        }
        // Every index this decision scans, then one live set over all of them
        // (frankengit-sctx). Indexes are a cache, so building them first
        // changes no decision.
        let mut thin_indexes: Vec<Option<BaseDeltaIndex>> = Vec::new();
        thin_indexes
            .try_reserve_exact(thin.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: thin.len(),
            })?;
        let mut live = None;
        if profile.delta_search == DeltaSearch::IndexedBlocks {
            for &position in &thin {
                thin_indexes.push(BaseDeltaIndex::build(
                    &external.objects[position].body,
                    limits,
                    deadline,
                )?);
            }
            for &(base_index, _) in &candidates {
                ensure_index(
                    indexes,
                    base_index,
                    &window.get(base_index).object.body,
                    profile.delta_window,
                    limits,
                    deadline,
                )?;
            }
            let mut scanned: Vec<&BaseDeltaIndex> = thin_indexes.iter().flatten().collect();
            scanned.extend(
                candidates
                    .iter()
                    .filter_map(|&(base_index, _)| cached_index(indexes, base_index)),
            );
            // One scan gains nothing from a pass that costs about as much.
            if scanned.len() >= 2 {
                live = LivePositions::build(&object.body, &scanned, deadline)?;
            }
        } else {
            thin_indexes.resize_with(thin.len(), || None);
        }
        let mut selected: Option<PlannedDelta> = None;
        for (position, index) in thin.into_iter().zip(&thin_indexes) {
            let base = &external.objects[position];
            // A REF_DELTA also carries the base ID, and every client-held base
            // it names is one more object stock git appends to the stored pack
            // (index-pack --fix-thin). So a client base must beat the best
            // choice so far, or the whole target, by more than that ID.
            let bound = selected
                .as_ref()
                .map_or(object.body.len(), |current| {
                    current.effective_len().min(object.body.len())
                })
                .saturating_sub(base.id.as_bytes().len());
            checkpoint(deadline)?;
            let compute = |deadline: &mut D| {
                make_delta_program_with(
                    &base.body,
                    &object.body,
                    profile.delta_search,
                    index.as_ref(),
                    live.as_ref(),
                    bound,
                    deadline,
                )
            };
            let program = match &self.cache {
                Some(cache) => cache.delta(
                    &self.cache_fingerprint,
                    base.id,
                    object.id,
                    bound,
                    deadline,
                    compute,
                )?,
                None => compute(deadline)?,
            };
            checkpoint(deadline)?;
            let Some(program) = program else {
                continue;
            };
            // `program` is below `bound`, so this is strictly shorter in
            // effective length; among equal client-held bases the smaller base
            // ID, visited first, keeps the choice.
            if selected.as_ref().is_none_or(|current| {
                program.len() + base.id.as_bytes().len() < current.effective_len()
            }) {
                selected = Some(PlannedDelta {
                    base: PlannedDeltaBase::Client(base.id),
                    depth: 1,
                    program,
                });
            }
        }
        for (base_index, depth) in candidates {
            let base = window.get(base_index);
            let index = match profile.delta_search {
                DeltaSearch::PrefixSuffix => None,
                DeltaSearch::IndexedBlocks => cached_index(indexes, base_index),
            };
            // A candidate replaces the current choice only when strictly
            // shorter (candidates are visited nearest-first -- best-probed
            // first under a binding budget -- so an equal length never wins
            // the tie-break below), and a program is only
            // ever emitted when shorter than its target. Anything at or over
            // this bound is irrelevant, so the search may stop proving it.
            let bound = selected.as_ref().map_or(object.body.len(), |current| {
                current.effective_len().min(object.body.len())
            });
            checkpoint(deadline)?;
            let compute = |deadline: &mut D| {
                make_delta_program_with(
                    &base.object.body,
                    &object.body,
                    profile.delta_search,
                    index,
                    live.as_ref(),
                    bound,
                    deadline,
                )
            };
            let program = match &self.cache {
                Some(cache) => cache.delta(
                    &self.cache_fingerprint,
                    base.object.id,
                    object.id,
                    bound,
                    deadline,
                    compute,
                )?,
                None => compute(deadline)?,
            };
            checkpoint(deadline)?;
            let Some(program) = program else {
                continue;
            };
            let candidate = PlannedDelta {
                base: PlannedDeltaBase::Pack(base_index),
                depth,
                program,
            };
            // Compared by effective length; an in-pack base also wins an equal
            // effective length against a client-held one.
            if selected.as_ref().is_none_or(|current| {
                candidate.program.len() < current.effective_len()
                    || (candidate.program.len() == current.effective_len()
                        && current.base_index().is_none_or(|current_index| {
                            base_index > current_index
                                || (base_index == current_index
                                    && base.object.id < window.get(current_index).object.id)
                        }))
            }) {
                selected = Some(candidate);
            }
        }
        Ok(selected)
    }
}

/// The window's index for `base_index`, built on first use.
///
/// One index per candidate base is retained only while that base is still
/// inside the window: every target in the window would otherwise rebuild the
/// same index, which is the whole cost of the search. An evicted index is
/// rebuilt identically, so eviction never changes a plan.
fn ensure_index<'a>(
    indexes: &'a mut VecDeque<(usize, Option<BaseDeltaIndex>)>,
    base_index: usize,
    base: &[u8],
    window: usize,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Option<&'a BaseDeltaIndex>, PackWriteError> {
    if !indexes.iter().any(|(cached, _)| *cached == base_index) {
        let built = BaseDeltaIndex::build(base, limits, deadline)?;
        while indexes.len() >= window.max(1) {
            indexes.pop_front();
        }
        indexes.push_back((base_index, built));
    }
    Ok(indexes
        .iter()
        .find(|(cached, _)| *cached == base_index)
        .and_then(|(_, built)| built.as_ref()))
}

/// The index [`ensure_index`] built for `base_index`, if the base has one.
fn cached_index(
    indexes: &VecDeque<(usize, Option<BaseDeltaIndex>)>,
    base_index: usize,
) -> Option<&BaseDeltaIndex> {
    indexes
        .iter()
        .find(|(cached, _)| *cached == base_index)
        .and_then(|(_, built)| built.as_ref())
}

/// Orders candidates for a budget that cannot scan them all.
///
/// Each candidate is scored by [`probe_score`]; a candidate the probe finds
/// nothing in is dropped, and the rest are ordered by score, the nearer
/// candidate first on a tie. The order is total and depends only on bytes.
fn rank_for_budget(
    candidates: &[(usize, usize)],
    target: &[u8],
    entries: &DeltaWindow,
    indexes: &mut VecDeque<(usize, Option<BaseDeltaIndex>)>,
    window: usize,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<(usize, usize)>, PackWriteError> {
    let mut scored: Vec<(usize, usize, usize, usize)> = Vec::new();
    scored
        .try_reserve(candidates.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: candidates.len(),
        })?;
    for (nearness, &(base_index, depth)) in candidates.iter().enumerate() {
        let base = &entries.get(base_index).object.body;
        let score = match ensure_index(indexes, base_index, base, window, limits, deadline)? {
            Some(index) => probe_score(index, base, target, deadline)?,
            None => 0,
        };
        if score > 0 {
            scored.push((score, nearness, base_index, depth));
        }
    }
    scored.sort_unstable_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    Ok(scored
        .into_iter()
        .map(|(_, _, base_index, depth)| (base_index, depth))
        .collect())
}

/// Target samples a binding budget probes per candidate.
const DELTA_PROBE_SAMPLES: usize = 32;

/// How many of [`DELTA_PROBE_SAMPLES`] evenly spaced target samples find an
/// indexed base block.
///
/// The base is indexed only at block-aligned offsets, so each sample tries
/// every alignment of one block: at most `32 x 16` bucket lookups, against one
/// per target byte for a full scan. A score of zero means no sampled region of
/// the target occurs in the base.
fn probe_score(
    index: &BaseDeltaIndex,
    base: &[u8],
    target: &[u8],
    deadline: &mut impl Deadline,
) -> Result<usize, PackWriteError> {
    let Some(span) = target.len().checked_sub(2 * DELTA_INDEX_BLOCK_BYTES) else {
        return Ok(0);
    };
    let stride = span / DELTA_PROBE_SAMPLES;
    let mut hits = 0;
    for sample in 0..DELTA_PROBE_SAMPLES {
        checkpoint(deadline)?;
        let start = stride * sample;
        for position in start..start + DELTA_INDEX_BLOCK_BYTES {
            let window = &target[position..position + DELTA_INDEX_BLOCK_BYTES];
            if index.has_block(base, window, block_fingerprint(window)) {
                hits += 1;
                break;
            }
        }
    }
    Ok(hits)
}

/// [`make_delta_program_with`] without a live set; for tests.
#[cfg(test)]
fn make_delta_program(
    base: &[u8],
    target: &[u8],
    search: DeltaSearch,
    index: Option<&BaseDeltaIndex>,
    bound: usize,
    deadline: &mut impl Deadline,
) -> Result<Option<Vec<u8>>, PackWriteError> {
    make_delta_program_with(base, target, search, index, None, bound, deadline)
}

/// Builds the profile's delta program for one base/target pair.
///
/// Under [`DeltaSearch::IndexedBlocks`] both encodings are considered and the
/// shorter one is emitted; an exact tie keeps the prefix/suffix encoding, so a
/// pair that prefix/suffix search already encoded well emits the same bytes it
/// emitted before.  The pair is rejected -- `None` -- unless the chosen
/// program is shorter than `bound`, which the caller sets to the target length
/// or the shorter program it already holds.  Rejecting at the bound is the
/// same decision the caller's strict comparison would make, so the indexed
/// scan may stop as soon as it can no longer come in under it.
///
/// Its indexed scan skips what `live` leaves unmarked; `live` must cover
/// `index`.
fn make_delta_program_with(
    base: &[u8],
    target: &[u8],
    search: DeltaSearch,
    index: Option<&BaseDeltaIndex>,
    live: Option<&LivePositions>,
    bound: usize,
    deadline: &mut impl Deadline,
) -> Result<Option<Vec<u8>>, PackWriteError> {
    let prefix_suffix = PrefixSuffixDelta::new(base, target)?;
    // The indexed program is emitted only when strictly shorter than the
    // prefix/suffix one, and only matters under `bound`.
    if let (DeltaSearch::IndexedBlocks, Some(index)) = (search, index)
        && let Some(program) = scan_indexed_delta_program(
            index,
            base,
            target,
            bound.min(prefix_suffix.len()),
            live,
            deadline,
        )?
    {
        return Ok(Some(program));
    }
    // Large losing candidates previously copied their unmatched target into
    // an eager fallback before checking the best length (frankengit-1tl9).
    // Sizing it is exact, so only a fallback that will be emitted is allocated.
    if prefix_suffix.len() < bound {
        prefix_suffix.encode().map(Some)
    } else {
        Ok(None)
    }
}

/// Encodes the target as copy-prefix, insert-middle, copy-suffix.
#[cfg(test)]
fn make_prefix_suffix_delta_program(base: &[u8], target: &[u8]) -> Result<Vec<u8>, PackWriteError> {
    PrefixSuffixDelta::new(base, target)?.encode()
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
    /// Each indexed block's full fingerprint, parallel to `offsets`.
    ///
    /// A match of [`DELTA_INDEX_BLOCK_BYTES`] or more means the two blocks are
    /// byte-identical, so their fingerprints are equal. A candidate whose
    /// fingerprint differs can therefore never qualify, and skipping its byte
    /// comparison changes no result while sparing a random read of the base.
    fingerprints: Vec<u32>,
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
        let mut fingerprints = Vec::new();
        fingerprints
            .try_reserve_exact(entries)
            .map_err(|_| PackError::AllocationFailed { requested: entries })?;

        let mut offset = 0_usize;
        while offset <= span {
            // A served deadline reads clocks; once per block was ~7.5% of a
            // clone's CPU (frankengit-t8cr).
            if offsets.len() % DELTA_INDEX_CHECKPOINT_STRIDE == 0 {
                checkpoint(deadline)?;
            }
            let slot = u32::try_from(offsets.len()).map_err(|_| PackError::IntegerOverflow {
                context: "delta base index slot",
            })?;
            let fingerprint = block_fingerprint(&base[offset..offset + DELTA_INDEX_BLOCK_BYTES]);
            let bucket = (fingerprint & mask) as usize;
            fingerprints.push(fingerprint);
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
            fingerprints,
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
            // Every walked candidate counts toward the chain bound, compared
            // or not, so the set examined is exactly the unfiltered walk's.
            examined += 1;
            let slot = candidate as usize;
            if self.fingerprints[slot] != fingerprint {
                candidate = self.chain[slot];
                continue;
            }
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

impl BaseDeltaIndex {
    /// Whether `window` (exactly one block) equals an indexed base block.
    ///
    /// Walks the same bounded chain as [`Self::best_match`], so it answers
    /// `true` exactly when `best_match` would return `Some` at this position,
    /// but compares one block instead of extending the match: on a target that
    /// is a shifted copy of its base a match runs to the end of the object, and
    /// measuring it made every probe cost a full scan.
    fn has_block(&self, base: &[u8], window: &[u8], fingerprint: u32) -> bool {
        let mut candidate = self.heads[(fingerprint & self.mask) as usize];
        let mut examined = 0_usize;
        while candidate != Self::NONE && examined < DELTA_MAX_MATCH_CHAIN {
            examined += 1;
            let slot = candidate as usize;
            if self.fingerprints[slot] == fingerprint {
                let offset = self.offsets[slot] as usize;
                if base[offset..offset + DELTA_INDEX_BLOCK_BYTES] == *window {
                    return true;
                }
            }
            candidate = self.chain[slot];
        }
        false
    }
}

/// Target positions at which some base of one decision may match
/// (frankengit-sctx).
///
/// [`BaseDeltaIndex::best_match`] accepts only a slot whose full fingerprint
/// equals the target window's, so a position whose fingerprint is in none of
/// a decision's indexes matches none of its bases. One pass over the target
/// marks the other positions against a union filter of every index's
/// fingerprints: a filter bit may stand for several fingerprints, never for
/// none of a present one. Each base's scan then jumps over unmarked runs
/// instead of probing every position for every base, which on targets no base
/// resembles (images, compressed or unrelated objects) is nearly all of them.
struct LivePositions {
    /// Bit `p` is set when the window at target position `p` may match.
    words: Vec<u64>,
}

/// Filter bits per indexed fingerprint, before rounding to a power of two:
/// about one false mark per sixteen unrelated positions.
const LIVE_FILTER_BITS_PER_ENTRY: usize = 16;
/// The union filter holds 4 KiB to 2 MiB.
const LIVE_FILTER_MIN_BITS: usize = 1 << 15;
const LIVE_FILTER_MAX_BITS: usize = 1 << 24;
/// Target positions marked between deadline checkpoints.
const LIVE_CHECKPOINT_STRIDE: usize = 1 << 16;

impl LivePositions {
    /// Marks the windows of `target` whose fingerprint any of `indexes` may
    /// hold, or `None` for a target shorter than one window.
    fn build(
        target: &[u8],
        indexes: &[&BaseDeltaIndex],
        deadline: &mut impl Deadline,
    ) -> Result<Option<Self>, PackWriteError> {
        let Some(last) = target.len().checked_sub(DELTA_INDEX_BLOCK_BYTES) else {
            return Ok(None);
        };
        let entries = indexes.iter().fold(0_usize, |total, index| {
            total.saturating_add(index.fingerprints.len())
        });
        let bits = entries
            .saturating_mul(LIVE_FILTER_BITS_PER_ENTRY)
            .clamp(LIVE_FILTER_MIN_BITS, LIVE_FILTER_MAX_BITS)
            .next_power_of_two();
        let filter_words = bits / 64;
        let mut filter = Vec::new();
        filter
            .try_reserve_exact(filter_words)
            .map_err(|_| PackError::AllocationFailed {
                requested: filter_words,
            })?;
        filter.resize(filter_words, 0_u64);
        let mask = bits - 1;
        for index in indexes {
            checkpoint(deadline)?;
            for &fingerprint in &index.fingerprints {
                let bit = fingerprint as usize & mask;
                filter[bit / 64] |= 1 << (bit % 64);
            }
        }
        let positions = last + 1;
        let words_needed = positions.div_ceil(64);
        let mut words = Vec::new();
        words
            .try_reserve_exact(words_needed)
            .map_err(|_| PackError::AllocationFailed {
                requested: words_needed,
            })?;
        words.resize(words_needed, 0_u64);
        let high_power = (1..DELTA_INDEX_BLOCK_BYTES)
            .fold(1_u32, |power, _| power.wrapping_mul(DELTA_HASH_MULTIPLIER));
        let mut fingerprint = block_fingerprint(&target[..DELTA_INDEX_BLOCK_BYTES]);
        for position in 0..positions {
            if position % LIVE_CHECKPOINT_STRIDE == 0 {
                checkpoint(deadline)?;
            }
            if position > 0 {
                fingerprint = fingerprint
                    .wrapping_sub(u32::from(target[position - 1]).wrapping_mul(high_power))
                    .wrapping_mul(DELTA_HASH_MULTIPLIER)
                    .wrapping_add(u32::from(target[position + DELTA_INDEX_BLOCK_BYTES - 1]));
            }
            let bit = fingerprint as usize & mask;
            if (filter[bit / 64] >> (bit % 64)) & 1 == 1 {
                words[position / 64] |= 1 << (position % 64);
            }
        }
        Ok(Some(Self { words }))
    }

    /// The first marked position at or after `from`.
    fn next(&self, from: usize) -> Option<usize> {
        let mut word_index = from / 64;
        let mut word = *self.words.get(word_index)? & (u64::MAX << (from % 64));
        loop {
            if word != 0 {
                return Some(word_index * 64 + word.trailing_zeros() as usize);
            }
            word_index += 1;
            word = *self.words.get(word_index)?;
        }
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

/// The byte-by-byte indexed scan: [`scan_indexed_delta_program`] without a
/// live set. Production scans pass one; tests use this as the plain scan.
#[cfg(test)]
fn make_indexed_delta_program(
    index: &BaseDeltaIndex,
    base: &[u8],
    target: &[u8],
    limit: usize,
    deadline: &mut impl Deadline,
) -> Result<Option<Vec<u8>>, PackWriteError> {
    scan_indexed_delta_program(index, base, target, limit, None, deadline)
}

/// Encodes the target as interior copy runs against an indexed base.
///
/// The scan is greedy and forward-only: at each position it takes the longest
/// indexed match and continues past it, accumulating unmatched bytes into one
/// insert run.  This is the shape that reaches a shifted base, which the
/// prefix/suffix encoding cannot express at all.
///
/// Returns `None` once the program provably reaches `limit` bytes: the program
/// only grows, and the pending unmatched bytes will be emitted as inserts
/// whatever follows, so `program + insert_cost(pending)` is a lower bound on
/// its final length.  A `Some` program is exactly the one the unbounded scan
/// would build.
///
/// With `live`, the scan jumps over the target positions it leaves unmarked
/// (frankengit-sctx); `live` must cover `index`.
fn scan_indexed_delta_program(
    index: &BaseDeltaIndex,
    base: &[u8],
    target: &[u8],
    limit: usize,
    live: Option<&LivePositions>,
    deadline: &mut impl Deadline,
) -> Result<Option<Vec<u8>>, PackWriteError> {
    let mut program = Vec::new();
    let reserve = limit.min(target.len()).saturating_add(16);
    program
        .try_reserve(reserve)
        .map_err(|_| PackError::AllocationFailed { requested: reserve })?;
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
        if let Some(live) = live {
            let after_last = target.len() - DELTA_INDEX_BLOCK_BYTES + 1;
            let next = live
                .next(position)
                .map_or(after_last, |next| next.min(after_last));
            if next > position {
                // At each unmarked position the byte-by-byte scan tests the
                // limit, finds no match and steps one byte. The pending insert
                // run only grows, so any of those tests fails only if the one
                // at `next` does, or, past the last window, the final length
                // check, which counts the whole run.
                position = next;
                rolling = false;
                continue;
            }
        }
        if program.len() + insert_run_cost(position - literal_start) >= limit {
            return Ok(None);
        }

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
    Ok((program.len() < limit).then_some(program))
}

/// Encoded bytes [`emit_insert_run`] spends on `length` literal bytes: one
/// opcode per chunk of at most 127, plus the bytes themselves.
const fn insert_run_cost(length: usize) -> usize {
    length + length.div_ceil(127)
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

pub fn pack_header(count: u32) -> [u8; PACK_HEADER_BYTES] {
    let mut header = [0_u8; PACK_HEADER_BYTES];
    header[..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2_u32.to_be_bytes());
    header[8..].copy_from_slice(&count.to_be_bytes());
    header
}

pub fn encode_entry_header(type_code: u8, size: usize) -> Result<Vec<u8>, PackWriteError> {
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

    /// The delta planner exactly as it was before the bounded scan and the
    /// fingerprint pre-check (76dd133f): the oracle both optimizations must
    /// match byte for byte.
    mod reference {
        use super::super::*;

        /// The indexed scan exactly as it was before dead positions were
        /// skipped (frankengit-sctx): the oracle the skipping scan must match.
        pub(super) fn bounded_indexed_scan(
            index: &BaseDeltaIndex,
            base: &[u8],
            target: &[u8],
            limit: usize,
            deadline: &mut impl Deadline,
        ) -> Result<Option<Vec<u8>>, PackWriteError> {
            let mut program = Vec::new();
            let reserve = limit.min(target.len()).saturating_add(16);
            program
                .try_reserve(reserve)
                .map_err(|_| PackError::AllocationFailed { requested: reserve })?;
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
                if program.len() + insert_run_cost(position - literal_start) >= limit {
                    return Ok(None);
                }

                fingerprint = if rolling {
                    fingerprint
                        .wrapping_sub(u32::from(target[position - 1]).wrapping_mul(high_power))
                        .wrapping_mul(DELTA_HASH_MULTIPLIER)
                        .wrapping_add(u32::from(target[window_end - 1]))
                } else {
                    block_fingerprint(&target[position..window_end])
                };
                rolling = true;

                if let Some((offset, length)) =
                    index.best_match(base, target, position, fingerprint)
                {
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
            Ok((program.len() < limit).then_some(program))
        }

        pub(super) fn select_deltas(
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
                                let built =
                                    BaseDeltaIndex::build(&base.object.body, limits, deadline)?;
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
                        base: PlannedDeltaBase::Pack(base_index),
                        depth,
                        program,
                    };
                    let reference_index =
                        |delta: &PlannedDelta| delta.base_index().unwrap_or(usize::MAX);
                    if selected.as_ref().is_none_or(|current| {
                        candidate.program.len() < current.program.len()
                            || (candidate.program.len() == current.program.len()
                                && (base_index > reference_index(current)
                                    || (base_index == reference_index(current)
                                        && base.object.id
                                            < entries[reference_index(current)].object.id)))
                    }) {
                        selected = Some(candidate);
                    }
                }
                entries.push(PackPlanEntry {
                    object: object.clone(),
                    delta: selected,
                });
                fanout.push(0);
                if let Some(base_index) = entries
                    .last()
                    .and_then(PackPlanEntry::delta)
                    .and_then(PlannedDelta::base_index)
                {
                    fanout[base_index] =
                        fanout[base_index]
                            .checked_add(1)
                            .ok_or(PackError::IntegerOverflow {
                                context: "planned delta fanout",
                            })?;
                }
            }
            Ok(entries)
        }

        fn make_delta_program(
            base: &[u8],
            target: &[u8],
            search: DeltaSearch,
            index: Option<&BaseDeltaIndex>,
            deadline: &mut impl Deadline,
        ) -> Result<Option<Vec<u8>>, PackWriteError> {
            let prefix_suffix = prefix_suffix::scalar_program(base, target)?;
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

        impl BaseDeltaIndex {
            fn reference_best_match(
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
                    let length = prefix_suffix::scalar_prefix(&base[offset..], &target[position..]);
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

                if let Some((offset, length)) =
                    index.reference_best_match(base, target, position, fingerprint)
                {
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
    }

    /// Deterministic pseudo-random bytes (xorshift), so corpora replay. The
    /// seed is mixed first: `seed | 1` alone made every even seed replay the
    /// next odd one.
    fn noise(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn delta_corpora() -> Vec<Vec<CanonicalPackObject>> {
        let mut corpora = Vec::new();
        for seed in 1..=12_u64 {
            let base = noise(seed, 3_000 + (seed as usize) * 97);
            let mut blobs = vec![base.clone()];
            // Versions: in-place edits, a shifted copy, an append, a truncation.
            let mut edited = base.clone();
            for (at, byte) in noise(seed + 100, 8).iter().enumerate() {
                let position = (usize::from(*byte) * 11 + at * 257) % edited.len();
                edited[position] ^= 0x5a;
            }
            blobs.push(edited.clone());
            let mut shifted = noise(seed + 200, (seed as usize) % 7 + 1);
            shifted.extend_from_slice(&base);
            blobs.push(shifted);
            let mut appended = edited.clone();
            appended.extend_from_slice(&noise(seed + 300, 211));
            blobs.push(appended);
            blobs.push(base[..base.len() / 2].to_vec());
            // Unrelated blobs of the same size (no useful delta at all),
            // repeated-block bodies, and tiny bodies below the index block.
            blobs.push(noise(seed + 400, base.len()));
            blobs.push(noise(seed + 500, base.len()));
            blobs.push(base.iter().copied().cycle().take(base.len() * 2).collect());
            blobs.push(noise(seed + 600, 9));
            blobs.push(b"0123456789abcdef0123456789abcdef".to_vec());
            blobs.push(b"0123456789abcdef0123456789abcdeX".to_vec());
            // Exact duplicates of an earlier body under a different path.
            blobs.push(format!("{seed}").into_bytes());
            corpora.push(
                blobs
                    .iter()
                    .enumerate()
                    .map(|(at, body)| {
                        object(
                            ObjectType::Blob,
                            body,
                            (at as u64) % 3,
                            seed + (at as u64) % 2,
                        )
                    })
                    .collect(),
            );
        }
        corpora
    }

    fn wide_limits() -> PackLimits {
        PackLimits {
            max_input_bytes: 1 << 24,
            max_entries: 1024,
            max_object_bytes: 1 << 22,
            max_delta_depth: 16,
            max_delta_fanout: 64,
            max_total_expanded_bytes: 1 << 24,
            max_expansion_ratio: 1024,
            max_delta_work: 1 << 26,
            max_inflate_work: 1 << 26,
            max_cached_bytes: 1 << 24,
            max_index_entries: 4096,
        }
    }

    #[test]
    fn bounded_fingerprinted_delta_search_matches_the_reference_planner_exactly() {
        let mut compared = 0;
        let mut deltas = 0;
        for objects in delta_corpora() {
            for profile in [
                PackWriteProfile::COMPRESSED_V2,
                PackWriteProfile::COMPRESSED_V1,
                PackWriteProfile {
                    id: "narrow-window-test",
                    delta_window: 3,
                    max_delta_depth: 2,
                    ..PackWriteProfile::COMPRESSED_V2
                },
            ] {
                for index_entries in [4096, 7] {
                    let limits = PackLimits {
                        max_index_entries: index_entries,
                        ..wide_limits()
                    };
                    let optimized = select_deltas(
                        &objects,
                        &ExternalBases::default(),
                        profile,
                        &limits,
                        &mut always,
                    )
                    .expect("optimized plan");
                    let reference =
                        reference::select_deltas(&objects, profile, &limits, &mut always)
                            .expect("reference plan");
                    assert_eq!(optimized, reference, "{} / {index_entries}", profile.id);
                    compared += 1;
                    deltas += optimized
                        .iter()
                        .filter(|entry| entry.delta.is_some())
                        .count();
                }
            }
        }
        // The corpora must actually exercise delta selection, or equality
        // would be vacuous.
        assert_eq!(compared, 72);
        assert!(deltas > 200, "only {deltas} deltas selected");
    }

    /// Planner throughput, reference versus bounded, on a corpus shaped like
    /// the x2mv.4.4 large-repository fixture: same-size unrelated random blobs
    /// plus in-place versions, all inside one delta window. Run explicitly:
    /// `cargo test --release -p fgit-pack --lib -- --ignored --nocapture
    /// delta_search_throughput`. The reference runs twice as an A-A control.
    /// Prints timings; asserts only plan equality, never a duration.
    #[test]
    #[ignore = "measurement; run explicitly in release"]
    fn delta_search_throughput_against_the_reference() {
        const BLOB: usize = 1 << 20;
        let mut bodies: Vec<Vec<u8>> = (0..24_u64).map(|seed| noise(1_000 + seed, BLOB)).collect();
        for version in 0..4_usize {
            let mut edited = bodies[version].clone();
            edited[4_096 * (version + 1)] ^= 1;
            bodies.push(edited);
        }
        let objects: Vec<_> = bodies
            .iter()
            .enumerate()
            .map(|(at, body)| object(ObjectType::Blob, body, 0, at as u64))
            .collect();
        let limits = PackLimits {
            max_object_bytes: 1 << 24,
            max_index_entries: 1_000_000,
            ..wide_limits()
        };
        let profile = PackWriteProfile::COMPRESSED_V2;
        for round in 1..=3 {
            let started = std::time::Instant::now();
            let reference_a =
                reference::select_deltas(&objects, profile, &limits, &mut always).expect("ref");
            let reference_a_time = started.elapsed();
            let started = std::time::Instant::now();
            let reference_b =
                reference::select_deltas(&objects, profile, &limits, &mut always).expect("ref");
            let reference_b_time = started.elapsed();
            let started = std::time::Instant::now();
            let bounded = select_deltas(
                &objects,
                &ExternalBases::default(),
                profile,
                &limits,
                &mut always,
            )
            .expect("bounded");
            let bounded_time = started.elapsed();
            assert_eq!(reference_a, reference_b);
            assert_eq!(reference_a, bounded);
            let deltas = bounded.iter().filter(|entry| entry.delta.is_some()).count();
            println!(
                "round={round} objects={} blob_bytes={BLOB} deltas={deltas} \
                 reference_a_ms={} reference_b_ms={} bounded_ms={}",
                objects.len(),
                reference_a_time.as_millis(),
                reference_b_time.as_millis(),
                bounded_time.as_millis()
            );
        }
    }

    /// Planner time and plan shape, COMPRESSED_V2 against the bounded-work
    /// COMPRESSED_V3, on two large-object shapes (frankengit-77qh):
    /// - "unrelated": NEG-033's 24 unrelated 1 MiB blobs plus 4 in-place
    ///   versions whose bases sit 24 entries back;
    /// - "similar": 12 line-oriented 2 MiB blobs that differ only by a
    ///   per-file digit on every line, like the XL clone-back corpus.
    ///
    /// Run explicitly: `cargo test --release -p fgit-pack --lib -- --ignored
    /// --nocapture bounded_work_profile_throughput`. Three interleaved rounds
    /// after a warm-up; each arm's repeat is its own A-A control. Prints
    /// timings, delta counts, and total program bytes; asserts only
    /// determinism, never a duration.
    #[test]
    #[ignore = "measurement; run explicitly in release"]
    fn bounded_work_profile_throughput() {
        let mut unrelated: Vec<Vec<u8>> = (0..24_u64)
            .map(|seed| noise(1_000 + seed, 1 << 20))
            .collect();
        for version in 0..4_usize {
            let mut edited = unrelated[version].clone();
            edited[4_096 * (version + 1)] ^= 1;
            unrelated.push(edited);
        }
        let similar: Vec<Vec<u8>> = (0..12_usize)
            .map(|file| {
                let mut body = Vec::new();
                let mut line = 0_usize;
                while body.len() < 2 << 20 {
                    body.extend_from_slice(format!("xl-file-{file} line {line}\n").as_bytes());
                    line += 1;
                }
                body
            })
            .collect();
        // The FG-028c anchor corpus: 8 commits x 4 files, each `seq a a+300000`
        // with a = commit x file, so every version is a shifted copy of the others.
        let mut shifted: Vec<Vec<u8>> = Vec::new();
        for commit in 1..=8_usize {
            for file in 1..=4_usize {
                let first = commit * file;
                let mut body = Vec::new();
                for value in first..=first + 300_000 {
                    body.extend_from_slice(format!("{value}\n").as_bytes());
                }
                shifted.push(body);
            }
        }
        let limits = PackLimits {
            max_object_bytes: 1 << 24,
            max_index_entries: 1_000_000,
            ..wide_limits()
        };
        for (shape, mut bodies) in [
            ("unrelated", unrelated),
            ("similar", similar),
            ("shifted", shifted),
        ] {
            // The served source orders a window by object ID, not by path.
            if shape == "shifted" {
                bodies.sort_by_key(|body| {
                    fgit_crypto::git_object_id(ObjectFormat::Sha1, ObjectType::Blob, body)
                });
            }
            let objects: Vec<_> = bodies
                .iter()
                .enumerate()
                .map(|(at, body)| object(ObjectType::Blob, body, 0, at as u64))
                .collect();
            let run = |profile: PackWriteProfile| {
                let started = std::time::Instant::now();
                let plan = select_deltas(
                    &objects,
                    &ExternalBases::default(),
                    profile,
                    &limits,
                    &mut always,
                )
                .expect("plan");
                (started.elapsed(), plan)
            };
            // Interleaved rounds, so host load drifts over both arms alike.
            let mut v2_ms = Vec::new();
            let mut v3_ms = Vec::new();
            let (_, v2_a) = run(PackWriteProfile::COMPRESSED_V2);
            let (_, v3) = run(PackWriteProfile::COMPRESSED_V3);
            for _ in 0..3 {
                let (v2_time, v2_again) = run(PackWriteProfile::COMPRESSED_V2);
                let (v3_time, v3_again) = run(PackWriteProfile::COMPRESSED_V3);
                assert_eq!(v2_a, v2_again);
                assert_eq!(v3, v3_again);
                v2_ms.push(v2_time.as_millis());
                v3_ms.push(v3_time.as_millis());
            }
            let shape_of = |plan: &[PackPlanEntry]| {
                let deltas: Vec<_> = plan
                    .iter()
                    .filter_map(|entry| entry.delta.as_ref())
                    .collect();
                let program_bytes: usize = deltas.iter().map(|delta| delta.program.len()).sum();
                let whole_bytes: usize = plan
                    .iter()
                    .filter(|entry| entry.delta.is_none())
                    .map(|entry| entry.object.body.len())
                    .sum();
                (deltas.len(), program_bytes, whole_bytes)
            };
            println!(
                "shape={shape} objects={} v2_ms={v2_ms:?} v3_ms={v3_ms:?} \
                 v2(deltas,program_bytes,whole_bytes)={:?} v3={:?}",
                objects.len(),
                shape_of(&v2_a),
                shape_of(&v3)
            );
        }
    }

    #[test]
    fn the_indexed_scan_stops_at_its_limit_and_is_exact_below_it() {
        let base = noise(7, 4_000);
        let mut target = base.clone();
        target[1_000] ^= 1;
        let index = BaseDeltaIndex::build(&base, &wide_limits(), &mut always)
            .expect("index")
            .expect("indexed");
        let full = make_indexed_delta_program(&index, &base, &target, usize::MAX, &mut always)
            .expect("scan")
            .expect("unbounded program");
        // At exactly its own length the program is not under the limit.
        assert_eq!(
            make_indexed_delta_program(&index, &base, &target, full.len(), &mut always)
                .expect("scan"),
            None
        );
        // One byte more and it is emitted unchanged.
        assert_eq!(
            make_indexed_delta_program(&index, &base, &target, full.len() + 1, &mut always)
                .expect("scan"),
            Some(full)
        );
        // An unrelated target under a tight limit stops early.
        let unrelated = noise(8, 4_000);
        assert_eq!(
            make_indexed_delta_program(&index, &base, &unrelated, 64, &mut always).expect("scan"),
            None
        );
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
                target_body.len(),
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
            target_body.len(),
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
                usize::MAX,
                &mut always,
            )
            .expect("interior program builds")
            .expect("an unbounded scan always emits its program");

            let emitted = make_delta_program(
                &base_body,
                &target_body,
                DeltaSearch::IndexedBlocks,
                index.as_ref(),
                target_body.len(),
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
            target_body.len(),
            &mut always,
        )
        .expect("interior search completes with no index");
        let baseline = make_delta_program(
            base_body,
            target_body,
            DeltaSearch::PrefixSuffix,
            None,
            target_body.len(),
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
        assert_eq!(delta.base_index(), Some(0));
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

    /// The probe's block test answers exactly what `best_match` would, at every
    /// target position, over corpora with shifted, edited, repeated and
    /// unrelated bodies (frankengit-77qh).
    #[test]
    fn the_probe_block_test_agrees_with_best_match_at_every_position() {
        let mut positions = 0;
        let mut hits = 0;
        for objects in delta_corpora() {
            for base in &objects {
                let Some(index) =
                    BaseDeltaIndex::build(&base.body, &wide_limits(), &mut always).expect("index")
                else {
                    continue;
                };
                for target in &objects {
                    let Some(last) = target.body.len().checked_sub(DELTA_INDEX_BLOCK_BYTES) else {
                        continue;
                    };
                    for position in 0..=last {
                        let window = &target.body[position..position + DELTA_INDEX_BLOCK_BYTES];
                        let fingerprint = block_fingerprint(window);
                        let expected = index
                            .best_match(&base.body, &target.body, position, fingerprint)
                            .is_some();
                        assert_eq!(index.has_block(&base.body, window, fingerprint), expected);
                        positions += 1;
                        hits += usize::from(expected);
                    }
                }
            }
        }
        assert!(hits > 10_000 && hits < positions, "{hits} of {positions}");
    }

    #[test]
    fn a_delta_work_allowance_is_the_larger_of_its_floor_and_its_multiple() {
        let budget = DeltaWorkBudget {
            floor_bytes: 4 << 20,
            target_multiple: 4,
        };
        assert_eq!(budget.allowance(0), 4 << 20);
        assert_eq!(budget.allowance(1 << 20), 4 << 20);
        assert_eq!(budget.allowance((1 << 20) + 1), (4 << 20) + 4);
        assert_eq!(budget.allowance(13 << 20), 52 << 20);
        assert_eq!(budget.allowance(usize::MAX), usize::MAX);
    }

    /// While a target's whole window fits the floor, the budget cannot bind,
    /// so the bounded-work profile must plan exactly like the one it bounds
    /// (frankengit-77qh). The corpora carry deltas, so equality is not vacuous.
    #[test]
    fn the_bounded_work_profile_plans_exactly_like_v2_while_the_window_fits_its_floor() {
        let profile = PackWriteProfile::COMPRESSED_V3;
        let floor = profile.delta_work.expect("v3 is budgeted").floor_bytes;
        let limits = wide_limits();
        let mut compared = 0;
        let mut deltas = 0;
        for objects in delta_corpora() {
            let largest = objects.iter().map(|object| object.body.len()).max();
            assert!(largest.expect("non-empty corpus") * profile.delta_window <= floor);
            let bounded = select_deltas(
                &objects,
                &ExternalBases::default(),
                profile,
                &limits,
                &mut always,
            )
            .expect("v3");
            let unbounded = select_deltas(
                &objects,
                &ExternalBases::default(),
                PackWriteProfile::COMPRESSED_V2,
                &limits,
                &mut always,
            )
            .expect("v2");
            assert_eq!(bounded, unbounded);
            compared += 1;
            deltas += bounded.iter().filter(|entry| entry.delta.is_some()).count();
        }
        assert_eq!(compared, 12);
        assert!(deltas > 20, "only {deltas} deltas selected");
    }

    /// A binding budget spends its scans on the candidates a cheap probe ranks
    /// most promising, not simply the nearest: one scan still finds a
    /// near-identical base behind three unrelated nearer candidates, which the
    /// probe finds nothing in and which are never scanned.
    #[test]
    fn a_binding_delta_work_budget_scans_the_best_probed_candidate_first() {
        let good = noise(71, 8_192);
        let mut target = good.clone();
        target[4_000] ^= 1;
        let mut bodies = vec![good];
        bodies.extend((0..3_u64).map(|seed| noise(80 + seed, 8_192)));
        bodies.push(target);
        let objects: Vec<_> = bodies
            .iter()
            .enumerate()
            .map(|(at, body)| object(ObjectType::Blob, body, 0, at as u64))
            .collect();
        let limits = wide_limits();
        let target_delta = |profile| {
            let plan = select_deltas(
                &objects,
                &ExternalBases::default(),
                profile,
                &limits,
                &mut always,
            )
            .expect("plan");
            plan[4].delta.clone()
        };

        let unbounded =
            target_delta(PackWriteProfile::COMPRESSED_V2).expect("v2 deltas the edited copy");
        assert_eq!(unbounded.base_index(), Some(0));
        assert_eq!(target_delta(scans(1)), Some(unbounded));
    }

    /// Among equally promising candidates a binding budget keeps the nearest,
    /// so it can miss a farther base that would have given a shorter program:
    /// the trade the profile makes, visible here and gone once the allowance
    /// covers both scans.
    #[test]
    fn a_binding_delta_work_budget_prefers_the_nearest_of_equally_probed_candidates() {
        let target = noise(90, 8_192);
        // Edits sit in blocks 1 and 2, which no probe sample aligns to (the
        // samples start every 255 bytes and use blocks 0, 16, 32, ...), so
        // both candidates probe perfectly and differ only in distance.
        let mut far = target.clone();
        far[20] ^= 1;
        let mut near = far.clone();
        near[40] ^= 1;
        let objects: Vec<_> = [far, near, target]
            .iter()
            .enumerate()
            .map(|(at, body)| object(ObjectType::Blob, body, 0, at as u64))
            .collect();
        let limits = wide_limits();
        let target_delta = |profile| {
            let plan = select_deltas(
                &objects,
                &ExternalBases::default(),
                profile,
                &limits,
                &mut always,
            )
            .expect("plan");
            plan[2].delta.clone().expect("the target is deltified")
        };

        let unbounded = target_delta(PackWriteProfile::COMPRESSED_V2);
        assert_eq!(
            unbounded.base_index(),
            Some(0),
            "the one-edit base is shorter"
        );
        let one_scan = target_delta(scans(1));
        assert_eq!(
            one_scan.base_index(),
            Some(1),
            "a tie in probe score keeps the nearer"
        );
        assert!(one_scan.program().len() > unbounded.program().len());
        assert_eq!(target_delta(scans(2)), unbounded);
    }

    fn scans(target_multiple: usize) -> PackWriteProfile {
        PackWriteProfile {
            id: "delta-work-budget-test",
            delta_work: Some(DeltaWorkBudget {
                floor_bytes: 0,
                target_multiple,
            }),
            ..PackWriteProfile::COMPRESSED_V3
        }
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
            plan.entries()[2].delta().and_then(PlannedDelta::base_index),
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
    // OFS_DELTA distance encoder: behavioural tests.
    //
    // Why this lives here: `encode_ofs_delta_distance` is private, but
    // `decode_ofs_delta_base` is re-exported at the crate root (lib.rs:53), so
    // any drift between the encoder and the decoder is visible the moment the
    // encoder is changed. The whole-pack round-trip in writer_roundtrip.rs
    // exercises the encoder only via whatever distances the planner
    // produces; the boundary cases (0x7f->0x80, 0x3fff->0x4000, 0x1ffff->0x20000)
    // and the d=0 refusal are pinned here. NO claim that the byte format
    // matches upstream git; that is a separate question answered by the
    // pinned-oracle lane (pack_writer_roundtrip.sh) once provisioned.
    #[test]
    fn ofs_delta_distance_zero_is_refused() {
        assert_eq!(
            encode_ofs_delta_distance(0),
            Err(PackWriteError::Pack(PackError::InvalidOfsDelta)),
        );
    }

    #[test]
    fn ofs_delta_distance_round_trips_across_varint_boundaries() {
        use crate::decode_ofs_delta_base;
        // Distances sampled to exercise each continuation-byte boundary.
        // current_offset must be large enough that distance <= current_offset
        // (decode_ofs_delta_base refuses otherwise) and that
        // current_offset - distance >= FIRST_ENTRY_OFFSET (12).
        let current_offset = u64::from(u32::MAX);
        let cases: &[u64] = &[
            1, 2, 0x7f, 0x80, 0x81, 0x100, 0x3fff, 0x4000, 0x4001, 0xffff, 0x1_0000, 0x1_ffff,
            0x2_0000, 0xff_ffff, 0x1_000000,
        ];
        for distance in cases {
            let encoded = encode_ofs_delta_distance(*distance).expect("encoder refuses only d=0");
            let (decoded, _consumed) = decode_ofs_delta_base(current_offset, &encoded, &mut always)
                .expect("encoder/decoder pair must round-trip");
            assert_eq!(
                decoded,
                current_offset - *distance,
                "encode->decode mismatch for distance {distance}: encoded={encoded:02x?}, \
                 decoder returned base_offset {decoded}, expected {}",
                current_offset - *distance,
            );
        }
    }

    #[test]
    fn ofs_delta_distance_encodes_full_u64_range() {
        // The encoder's loop uses `value >> 7` (7-bit continuation), so the
        // emitted length is O(log d) and d=u64::MAX must encode without
        // panicking.  Round-tripped against our own decoder for values small
        // enough that the decoder's `base_offset >= 12` constraint holds
        // (`current_offset - distance >= 12`); for d = u64::MAX and
        // d = u64::MAX - 1 the encoder must still not panic.
        use crate::decode_ofs_delta_base;
        for distance in [
            u64::MAX,
            u64::MAX - 1,
            u64::MAX - 12,
            u64::MAX / 2,
            0x100_0000_0000,
        ] {
            let encoded =
                encode_ofs_delta_distance(distance).expect("non-zero distance always encodes");
            if let Some(current_offset) = distance.checked_add(12) {
                let (decoded, _consumed) =
                    decode_ofs_delta_base(current_offset, &encoded, &mut always)
                        .expect("encoder/decoder round-trip for large distance");
                assert_eq!(decoded, 12, "u64-range distance {distance} must round-trip");
            }
        }
    }

    fn thin_planner(profile: PackWriteProfile) -> PackPlanner {
        PackPlanner::new(ObjectFormat::Sha1, profile, wide_limits())
    }

    fn order_keys(objects: &[CanonicalPackObject]) -> Vec<PackOrderKey> {
        objects
            .iter()
            .rev()
            .map(|object| PackOrderKey {
                id: object.id,
                object_type: object.object_type,
                recency: object.recency,
                path_hash: object.path_hash,
            })
            .collect()
    }

    fn stream(
        planner: &PackPlanner,
        source: &impl CanonicalObjectSource,
        keys: &[PackOrderKey],
        thin: &[ThinBase],
    ) -> Result<(Vec<u8>, PackWriteReceipt), PackWriteError> {
        let mut sink = MemoryPackSink::default();
        let mut encoder =
            DeterministicPackEncoder::new(DeflateLimits::GIT_OBJECT, planner.profile.compression);
        let receipt = planner.stream_selected_thin(
            source,
            keys,
            thin,
            &PackWriter::new(wide_limits()),
            &mut encoder,
            &mut sink,
            &mut always,
        )?;
        Ok((sink.promoted.expect("a streamed pack is promoted"), receipt))
    }

    /// frankengit-8xyq: a streamed pack is the planned pack, byte for byte and
    /// receipt for receipt, for every delta corpus and served profile. The
    /// declared keys arrive in reverse; plan order is recomputed.
    #[test]
    fn streamed_packs_equal_planned_packs_for_every_corpus_and_profile() {
        for profile in [
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            PackWriteProfile::COMPRESSED_V2,
            PackWriteProfile::COMPRESSED_V3,
            PackWriteProfile::COMPRESSED_V4,
        ] {
            for corpus in delta_corpora() {
                let ids: Vec<_> = corpus.iter().map(CanonicalPackObject::id).collect();
                let keys = order_keys(&corpus);
                let source = FixtureSource::with(corpus);
                let planner = thin_planner(profile);
                let plan = planner
                    .plan_selected(&source, &ids, &mut always)
                    .expect("plan");
                let planned = PackWriter::new(wide_limits())
                    .write(&plan, &mut always)
                    .expect("planned pack");
                let streamed = stream(&planner, &source, &keys, &[]).expect("streamed pack");
                assert_eq!(streamed, planned, "{}", profile.id);
            }
        }
    }

    /// The thin profile streams the same REF_DELTA against a client-held base.
    #[test]
    fn a_streamed_thin_pack_equals_the_planned_thin_pack() {
        let held = object(ObjectType::Blob, &shifted_lines(0, 4000), 1, 7);
        let target = object(ObjectType::Blob, &shifted_lines(3, 4000), 3, 7);
        let chained = object(ObjectType::Blob, &shifted_lines(5, 4000), 2, 7);
        let source = FixtureSource::with(vec![held.clone(), target.clone(), chained.clone()]);
        for profile in [
            PackWriteProfile::COMPRESSED_V3_THIN,
            PackWriteProfile::COMPRESSED_V4_THIN,
            PackWriteProfile::COMPRESSED_V5_THIN,
        ] {
            let planner = thin_planner(profile);
            let offer = ThinBase::new(target.id(), held.id());
            let plan = planner
                .plan_selected_thin(&source, &[target.id(), chained.id()], &[offer], &mut always)
                .expect("thin plan");
            let planned = PackWriter::new(wide_limits())
                .write(&plan, &mut always)
                .expect("planned thin pack");
            let keys = order_keys(&[target.clone(), chained.clone()]);
            let streamed = stream(&planner, &source, &keys, &[offer]).expect("streamed thin pack");
            assert_eq!(streamed, planned, "{}", profile.id);
            assert_eq!(streamed.1.delta_count, 2);
        }
    }

    /// The stream holds only the delta window: a corpus four times larger than
    /// `max_cached_bytes` streams (and equals the plan) while each window fits;
    /// a cap below one window refuses typed.
    #[test]
    fn a_streamed_pack_holds_only_the_delta_window() {
        let corpus: Vec<_> = (0..200_u64)
            .map(|seed| {
                object(
                    ObjectType::Blob,
                    &noise(seed + 1_000, 4_096),
                    seed % 5,
                    seed,
                )
            })
            .collect();
        let total: usize = corpus.iter().map(|object| object.body.len()).sum();
        let ids: Vec<_> = corpus.iter().map(CanonicalPackObject::id).collect();
        let keys = order_keys(&corpus);
        let source = FixtureSource::with(corpus);
        // After each entry the window keeps exactly `delta_window` bodies.
        let window_bytes = PackWriteProfile::COMPRESSED_V4.delta_window * 4_096;
        for (cap, admitted) in [(total / 4, true), (window_bytes - 1, false)] {
            assert!(cap >= window_bytes || !admitted);
            let limits = PackLimits {
                max_cached_bytes: cap,
                ..wide_limits()
            };
            let planner =
                PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::COMPRESSED_V4, limits);
            let result = stream(&planner, &source, &keys, &[]);
            if admitted {
                let plan = planner
                    .plan_selected(&source, &ids, &mut always)
                    .expect("plan");
                let planned = PackWriter::new(wide_limits())
                    .write(&plan, &mut always)
                    .expect("planned pack");
                assert_eq!(result.expect("window-bounded stream"), planned);
            } else {
                assert!(matches!(
                    result,
                    Err(PackWriteError::WindowCacheLimit { limit, .. }) if limit == cap
                ));
            }
        }
    }

    /// A loaded object that contradicts its declared ordering key is refused.
    #[test]
    fn a_streamed_object_must_match_its_declared_key() {
        let blob = object(ObjectType::Blob, b"declared as a tree", 0, 0);
        let source = FixtureSource::with(vec![blob.clone()]);
        let planner = thin_planner(PackWriteProfile::COMPRESSED_V4);
        let wrong = PackOrderKey {
            id: blob.id(),
            object_type: ObjectType::Tree,
            recency: 0,
            path_hash: 0,
        };
        assert_eq!(
            stream(&planner, &source, &[wrong], &[]),
            Err(PackWriteError::SourceOrderMismatch(blob.id()))
        );
        assert!(matches!(
            stream(&planner, &source, &[wrong, wrong], &[]),
            Err(PackWriteError::DuplicateSelectedObject(id)) if id == blob.id()
        ));
    }

    /// A source that records every load, in order.
    struct RecordingSource {
        inner: FixtureSource,
        loads: std::cell::RefCell<Vec<ObjectId>>,
    }

    impl CanonicalObjectSource for RecordingSource {
        fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
            self.loads.borrow_mut().push(*id);
            self.inner.load(id)
        }
    }

    fn byte_window(bytes: usize) -> PackWriteProfile {
        PackWriteProfile {
            id: "window-bytes-test",
            delta_window_bytes: Some(bytes),
            ..PackWriteProfile::COMPRESSED_V4
        }
    }

    /// frankengit-8xyq: where the nearest 32 bodies fit in 128 MiB, V5 is V4:
    /// the same bytes and per-entry receipts; only the profile differs.
    #[test]
    fn v5_writes_exactly_as_v4_where_every_window_fits() {
        assert_eq!(
            PackWriteProfile::COMPRESSED_V5.delta_window_bytes,
            Some(128 * 1024 * 1024)
        );
        assert_eq!(
            PackWriteProfile::COMPRESSED_V5_THIN.delta_window_bytes,
            PackWriteProfile::COMPRESSED_V5.delta_window_bytes
        );
        const { assert!(PackWriteProfile::COMPRESSED_V5_THIN.thin) };
        for corpus in delta_corpora() {
            let ids: Vec<_> = corpus.iter().map(CanonicalPackObject::id).collect();
            let source = FixtureSource::with(corpus);
            let write = |profile| {
                let plan = thin_planner(profile)
                    .plan_selected(&source, &ids, &mut always)
                    .expect("plan");
                PackWriter::new(wide_limits())
                    .write(&plan, &mut always)
                    .expect("pack")
            };
            let (v4, v4_receipt) = write(PackWriteProfile::COMPRESSED_V4);
            let (v5, v5_receipt) = write(PackWriteProfile::COMPRESSED_V5);
            assert_eq!(v5, v4);
            assert_eq!(v5_receipt.profile.id, "git-pack-compressed-v5");
            assert_eq!(v5_receipt.delta_count, v4_receipt.delta_count);
            assert_eq!(v5_receipt.compression, v4_receipt.compression);
        }
    }

    /// A byte bound offers only the nearest bodies that fit, inclusive: a
    /// similar base behind 16 KiB of unrelated bodies is a candidate at
    /// exactly their sum and not one byte below it. The stream holds no more
    /// than the bound and equals the plan either way.
    #[test]
    fn a_byte_bounded_window_offers_only_the_nearest_bodies_that_fit() {
        let base = object(ObjectType::Blob, &shifted_lines(0, 2_000), 9, 7);
        let target = object(ObjectType::Blob, &shifted_lines(1, 2_000), 1, 7);
        let mut corpus = vec![base.clone(), target.clone()];
        for (at, recency) in (5..=8_u64).enumerate() {
            corpus.push(object(
                ObjectType::Blob,
                &noise(at as u64 + 40, 4_096),
                recency,
                7,
            ));
        }
        let ids: Vec<_> = corpus.iter().map(CanonicalPackObject::id).collect();
        let keys = order_keys(&corpus);
        let source = FixtureSource::with(corpus);
        let reach = 4 * 4_096 + base.body.len();
        for (bytes, reaches) in [(reach, true), (reach - 1, false)] {
            let profile = byte_window(bytes);
            let limits = PackLimits {
                max_cached_bytes: bytes,
                ..wide_limits()
            };
            let planner = PackPlanner::new(ObjectFormat::Sha1, profile, limits);
            let plan = planner
                .plan_selected(&source, &ids, &mut always)
                .expect("plan");
            let last = plan.entries().last().expect("entries");
            assert_eq!(last.object().id(), target.id());
            let base_index = last.delta().and_then(PlannedDelta::base_index);
            assert_eq!(base_index, reaches.then_some(0), "bound {bytes}");
            let planned = PackWriter::new(wide_limits())
                .write(&plan, &mut always)
                .expect("planned pack");
            let streamed = stream(&planner, &source, &keys, &[]).expect("streamed pack");
            assert_eq!(streamed, planned, "bound {bytes}");
        }
        let unbounded = thin_planner(PackWriteProfile::COMPRESSED_V4)
            .plan_selected(&source, &ids, &mut always)
            .expect("unbounded plan");
        assert_eq!(
            unbounded.entries()[5]
                .delta()
                .and_then(PlannedDelta::base_index),
            Some(0)
        );
    }

    /// Over every corpus, no delta reaches back over more body bytes than the
    /// bound, the bound changes decisions, and the stream equals the plan.
    #[test]
    fn no_delta_reaches_past_the_byte_bound() {
        let bytes = 6_000;
        let (mut deltas, mut changed) = (0, 0);
        for corpus in delta_corpora() {
            let ids: Vec<_> = corpus.iter().map(CanonicalPackObject::id).collect();
            let keys = order_keys(&corpus);
            let source = FixtureSource::with(corpus);
            let limits = PackLimits {
                max_cached_bytes: bytes,
                ..wide_limits()
            };
            let planner = PackPlanner::new(ObjectFormat::Sha1, byte_window(bytes), limits);
            let plan = planner
                .plan_selected(&source, &ids, &mut always)
                .expect("plan");
            let unbounded = thin_planner(PackWriteProfile::COMPRESSED_V4)
                .plan_selected(&source, &ids, &mut always)
                .expect("unbounded plan");
            let entries = plan.entries();
            for (at, entry) in entries.iter().enumerate() {
                let reached = entry.delta().and_then(PlannedDelta::base_index);
                if let Some(base) = reached {
                    deltas += 1;
                    let behind: usize = entries[base..at]
                        .iter()
                        .map(|entry| entry.object().body.len())
                        .sum();
                    assert!(behind <= bytes, "{behind} bytes behind entry {at}");
                }
                let free = unbounded.entries()[at]
                    .delta()
                    .and_then(PlannedDelta::base_index);
                changed += usize::from(reached != free);
            }
            let planned = PackWriter::new(wide_limits())
                .write(&plan, &mut always)
                .expect("planned pack");
            assert_eq!(
                stream(&planner, &source, &keys, &[]).expect("streamed pack"),
                planned
            );
        }
        assert!(deltas > 0, "the bound leaves deltas to check");
        assert!(changed > 0, "the bound binds somewhere");
    }

    /// A streamed thin pack loads each client-held base for its own target's
    /// decision, right after that target, not all of them up front.
    #[test]
    fn a_streamed_thin_pack_loads_each_base_for_its_target() {
        let held = object(ObjectType::Blob, &shifted_lines(0, 4000), 1, 7);
        let target = object(ObjectType::Blob, &shifted_lines(3, 4000), 3, 7);
        let chained = object(ObjectType::Blob, &shifted_lines(5, 4000), 2, 7);
        let source = RecordingSource {
            inner: FixtureSource::with(vec![held.clone(), target.clone(), chained.clone()]),
            loads: std::cell::RefCell::new(Vec::new()),
        };
        let planner = thin_planner(PackWriteProfile::COMPRESSED_V5_THIN);
        let offer = ThinBase::new(target.id(), held.id());
        let keys = order_keys(&[target.clone(), chained.clone()]);
        let streamed = stream(&planner, &source, &keys, &[offer]).expect("streamed thin pack");
        assert_eq!(
            source.loads.borrow().as_slice(),
            &[target.id(), held.id(), chained.id()]
        );
        let plan = planner
            .plan_selected_thin(&source, &[target.id(), chained.id()], &[offer], &mut always)
            .expect("thin plan");
        let planned = PackWriter::new(wide_limits())
            .write(&plan, &mut always)
            .expect("planned thin pack");
        assert_eq!(streamed, planned);
        assert_eq!(streamed.1.delta_count, 2);
    }

    /// frankengit-sctx: skipping the positions no base can match at changes
    /// no program and no decision. Every ordered pair of every delta corpus,
    /// full and strided indexes, limits from zero to unbounded, and a live set
    /// over the base plus an unrelated index (so some marks are false) are
    /// compared with the byte-by-byte scan.
    #[test]
    fn skipping_dead_positions_scans_exactly_as_the_byte_by_byte_scan() {
        let unrelated = noise(9_999, 6_000);
        let (mut compared, mut found, mut refused, mut skipped) = (0, 0, 0, 0);
        let mut corpora = delta_corpora();
        corpora.push(vec![
            object(ObjectType::Blob, &shifted_lines(0, 3_000), 0, 0),
            object(ObjectType::Blob, &shifted_lines(7, 3_000), 0, 0),
            object(ObjectType::Blob, &noise(4, 40_000), 0, 0),
            object(
                ObjectType::Blob,
                &[noise(5, 900), shifted_lines(3, 400), noise(6, 900)].concat(),
                0,
                0,
            ),
        ]);
        for corpus in corpora {
            for index_entries in [4096, 7] {
                let limits = PackLimits {
                    max_index_entries: index_entries,
                    ..wide_limits()
                };
                let other = BaseDeltaIndex::build(&unrelated, &limits, &mut always)
                    .expect("index")
                    .expect("indexable");
                for base in &corpus {
                    let Some(index) =
                        BaseDeltaIndex::build(&base.body, &limits, &mut always).expect("index")
                    else {
                        continue;
                    };
                    for target in &corpus {
                        let Some(live) =
                            LivePositions::build(&target.body, &[&index, &other], &mut always)
                                .expect("live")
                        else {
                            continue;
                        };
                        let positions = target.body.len() - DELTA_INDEX_BLOCK_BYTES + 1;
                        let marked = (0..positions)
                            .filter(|&at| live.next(at) == Some(at))
                            .count();
                        skipped += positions - marked;
                        let full = reference::bounded_indexed_scan(
                            &index,
                            &base.body,
                            &target.body,
                            usize::MAX,
                            &mut always,
                        )
                        .expect("scan")
                        .expect("unbounded");
                        for limit in [
                            0,
                            1,
                            17,
                            full.len().saturating_sub(1),
                            full.len(),
                            full.len() + 1,
                            target.body.len() / 2,
                            target.body.len(),
                            usize::MAX,
                        ] {
                            let expected = reference::bounded_indexed_scan(
                                &index,
                                &base.body,
                                &target.body,
                                limit,
                                &mut always,
                            )
                            .expect("reference scan");
                            let actual = scan_indexed_delta_program(
                                &index,
                                &base.body,
                                &target.body,
                                limit,
                                Some(&live),
                                &mut always,
                            )
                            .expect("skipping scan");
                            assert_eq!(actual, expected, "limit {limit}");
                            compared += 1;
                            if expected.is_some() {
                                found += 1;
                            } else {
                                refused += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(compared > 1_000, "{compared}");
        assert!(found > 0 && refused > 0, "{found} found, {refused} refused");
        assert!(skipped > 0, "the live set skips positions");
    }

    /// A position marked by no index is skipped, and the next marked one is
    /// found across word boundaries; a target shorter than a window has none.
    #[test]
    fn live_positions_mark_exactly_the_windows_an_index_may_hold() {
        let base = noise(77, 4_000);
        let index = BaseDeltaIndex::build(&base, &wide_limits(), &mut always)
            .expect("index")
            .expect("indexable");
        // The base's block at 1_600 reappears at target position 130.
        let mut target = noise(78, 300);
        target[130..146].copy_from_slice(&base[1_600..1_616]);
        let live = LivePositions::build(&target, &[&index], &mut always)
            .expect("live")
            .expect("windows");
        assert_eq!(live.next(0).map(|at| at <= 130), Some(true));
        assert_eq!(live.next(130), Some(130));
        let fingerprint = block_fingerprint(&target[130..146]);
        assert!(matches!(
            index.best_match(&base, &target, 130, fingerprint),
            Some((1_600, length)) if length >= 16
        ));
        // Every unmarked position really has no match in the base.
        for at in 0..=target.len() - DELTA_INDEX_BLOCK_BYTES {
            if live.next(at) != Some(at) {
                let fingerprint = block_fingerprint(&target[at..at + DELTA_INDEX_BLOCK_BYTES]);
                assert_eq!(
                    index.best_match(&base, &target, at, fingerprint),
                    None,
                    "{at}"
                );
            }
        }
        assert!(
            LivePositions::build(&target[..15], &[&index], &mut always)
                .expect("live")
                .is_none()
        );
    }

    /// frankengit-t8cr: an index build checks its deadline once per stride of
    /// blocks, not per block, and a refused deadline still stops it partway.
    #[test]
    fn an_index_build_checks_its_deadline_per_stride_and_still_refuses() {
        let base = noise(321, 1 << 20);
        let limits = PackLimits {
            max_index_entries: 1 << 20,
            ..wide_limits()
        };
        let mut calls = 0_usize;
        let mut counting = || {
            calls += 1;
            true
        };
        BaseDeltaIndex::build(&base, &limits, &mut counting)
            .expect("index")
            .expect("indexable");
        let blocks = base.len() / DELTA_INDEX_BLOCK_BYTES;
        assert_eq!(calls, blocks.div_ceil(DELTA_INDEX_CHECKPOINT_STRIDE));
        let mut allowed = 5_usize;
        let mut expiring = || {
            allowed = allowed.saturating_sub(1);
            allowed > 0
        };
        assert!(matches!(
            BaseDeltaIndex::build(&base, &limits, &mut expiring),
            Err(PackWriteError::Pack(PackError::DeadlineExceeded))
        ));
    }

    /// frankengit-uf91: V4 plans exactly as V3 and its members inflate to
    /// exactly V3's, so only DEFLATE framing differs. It is never larger,
    /// and smaller wherever a corpus holds incompressible members.
    #[test]
    fn v4_plans_and_inflates_as_v3_and_is_never_larger() {
        let mut shrank = false;
        for corpus in delta_corpora() {
            let ids: Vec<_> = corpus.iter().map(CanonicalPackObject::id).collect();
            let source = FixtureSource::with(corpus);
            let write = |profile| {
                let plan = thin_planner(profile)
                    .plan_selected(&source, &ids, &mut always)
                    .expect("plan");
                let (bytes, receipt) = PackWriter::new(wide_limits())
                    .write(&plan, &mut always)
                    .expect("pack");
                let parsed = read_verified_pack(
                    &bytes,
                    ObjectFormat::Sha1,
                    &wide_limits(),
                    &mut always,
                    &NativeChecksumVerifier,
                )
                .expect("the reader accepts the pack");
                let members: Vec<Vec<u8>> = parsed
                    .entries()
                    .iter()
                    .map(|entry| entry.inflated.clone())
                    .collect();
                (plan, bytes, receipt, members)
            };
            let (v3, v3_bytes, _, v3_members) = write(PackWriteProfile::COMPRESSED_V3);
            let (v4, v4_bytes, v4_receipt, v4_members) = write(PackWriteProfile::COMPRESSED_V4);
            assert_eq!(v3.entries(), v4.entries());
            assert_eq!(v3_members, v4_members);
            assert!(v4_bytes.len() <= v3_bytes.len());
            shrank |= v4_bytes.len() < v3_bytes.len();
            assert_eq!(v4_receipt.profile.id, "git-pack-compressed-v4");
            let (_, thin_bytes, thin_receipt, _) = write(PackWriteProfile::COMPRESSED_V4_THIN);
            assert_eq!(thin_bytes, v4_bytes);
            assert_eq!(thin_receipt.profile.id, "git-pack-compressed-v4-thin");
        }
        assert!(shrank, "the corpora hold incompressible members");
    }

    /// frankengit-pazc: with no client-held bases the thin profile plans and
    /// writes exactly what COMPRESSED_V3 does; only the receipt's profile id
    /// differs.
    #[test]
    fn a_thin_profile_without_thin_bases_writes_the_v3_pack() {
        for corpus in delta_corpora() {
            let ids: Vec<_> = corpus.iter().map(CanonicalPackObject::id).collect();
            let source = FixtureSource::with(corpus);
            let write = |profile| {
                let plan = thin_planner(profile)
                    .plan_selected(&source, &ids, &mut always)
                    .expect("plan");
                let (bytes, receipt) = PackWriter::new(wide_limits())
                    .write(&plan, &mut always)
                    .expect("pack");
                (plan, bytes, receipt)
            };
            let (v3, v3_bytes, v3_receipt) = write(PackWriteProfile::COMPRESSED_V3);
            let (thin, thin_bytes, thin_receipt) = write(PackWriteProfile::COMPRESSED_V3_THIN);
            assert_eq!(v3.entries(), thin.entries());
            assert_eq!(v3_bytes, thin_bytes);
            assert_eq!(v3_receipt.profile.id, "git-pack-compressed-v3");
            assert_eq!(thin_receipt.profile.id, "git-pack-compressed-v3-thin");
        }
    }

    /// frankengit-pazc: a client-held base that the pack does not carry
    /// becomes a REF_DELTA base, and the pack round-trips against it. Another
    /// entry may chain on the thin target. The twin without the offer ships
    /// the target whole, so the thin pack is much smaller.
    #[test]
    fn a_client_held_base_is_emitted_as_ref_delta_and_round_trips() {
        let held = object(ObjectType::Blob, &shifted_lines(0, 4000), 1, 7);
        let target = object(ObjectType::Blob, &shifted_lines(3, 4000), 3, 7);
        let chained = object(ObjectType::Blob, &shifted_lines(5, 4000), 2, 7);
        let source = FixtureSource::with(vec![held.clone(), target.clone(), chained.clone()]);
        let planner = thin_planner(PackWriteProfile::COMPRESSED_V3_THIN);
        let selected = [target.id(), chained.id()];
        let offer = ThinBase::new(target.id(), held.id());
        let plan = planner
            .plan_selected_thin(&source, &selected, &[offer], &mut always)
            .expect("thin plan");
        let entries = plan.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].object().id(), target.id(), "newer first");
        let thin = entries[0]
            .delta()
            .expect("the target deltas against the held base");
        assert_eq!(thin.base(), PlannedDeltaBase::Client(held.id()));
        assert_eq!((thin.depth(), thin.base_index()), (1, None));
        let chain = entries[1]
            .delta()
            .expect("the older version chains on the target");
        assert_eq!(chain.base(), PlannedDeltaBase::Pack(0));
        assert_eq!(chain.depth(), 2);

        let (bytes, receipt) = PackWriter::new(wide_limits())
            .write(&plan, &mut always)
            .expect("thin pack");
        assert_eq!(receipt.delta_count, 2);
        let parsed = read_verified_pack(
            &bytes,
            ObjectFormat::Sha1,
            &wide_limits(),
            &mut always,
            &NativeChecksumVerifier,
        )
        .expect("the reader accepts the thin pack");
        let [first, second] = parsed.entries() else {
            panic!("two entries");
        };
        assert_eq!(first.header.kind, crate::EntryKind::RefDelta);
        assert!(matches!(
            first.delta_base,
            Some(crate::ParsedDeltaBase::Ref { base, .. }) if base == held.id()
        ));
        let rebuilt_target =
            apply_delta(held.body(), &first.inflated, &wide_limits(), &mut always).unwrap();
        assert_eq!(rebuilt_target, target.body());
        assert_eq!(second.header.kind, crate::EntryKind::OfsDelta);
        let rebuilt_chained = apply_delta(
            &rebuilt_target,
            &second.inflated,
            &wide_limits(),
            &mut always,
        )
        .unwrap();
        assert_eq!(rebuilt_chained, chained.body());

        let whole = planner
            .plan_selected(&source, &selected, &mut always)
            .expect("self-contained plan");
        assert!(
            whole.entries()[0].delta().is_none(),
            "no in-pack base for the newest"
        );
        let (whole_bytes, _) = PackWriter::new(wide_limits())
            .write(&whole, &mut always)
            .expect("self-contained pack");
        assert!(
            bytes.len() * 4 < whole_bytes.len(),
            "thin {} vs self-contained {}",
            bytes.len(),
            whole_bytes.len()
        );
    }

    /// frankengit-pazc: client-held bases are paid from the same per-target
    /// work budget, scanned first. When the budget buys one scan only the
    /// client-held base is tried, even though an in-pack base is better; one
    /// more scan lets the in-pack base win on length.
    #[test]
    fn client_held_bases_are_paid_from_the_per_target_work_budget() {
        let held = object(ObjectType::Blob, &shifted_lines(0, 4000), 1, 7);
        let near = object(ObjectType::Blob, &shifted_lines(2, 4000), 9, 7);
        let target = object(ObjectType::Blob, &shifted_lines(3, 4000), 5, 7);
        let source = FixtureSource::with(vec![held.clone(), near.clone(), target.clone()]);
        let offer = ThinBase::new(target.id(), held.id());
        let target_delta = |target_multiple| {
            let profile = PackWriteProfile {
                id: "thin-budget-test",
                delta_work: Some(DeltaWorkBudget {
                    floor_bytes: 0,
                    target_multiple,
                }),
                ..PackWriteProfile::COMPRESSED_V3_THIN
            };
            let plan = thin_planner(profile)
                .plan_selected_thin(&source, &[near.id(), target.id()], &[offer], &mut always)
                .expect("plan");
            let entry = plan
                .entries()
                .iter()
                .find(|entry| entry.object().id() == target.id())
                .expect("target entry");
            entry.delta().expect("deltified").base()
        };
        assert_eq!(target_delta(1), PlannedDeltaBase::Client(held.id()));
        assert!(matches!(target_delta(2), PlannedDeltaBase::Pack(_)));
    }

    /// frankengit-pazc: thin offers are typed refusals for a self-contained
    /// profile and for any pair the planner cannot honour, each beside a
    /// permitted twin; a thin plan cannot be written under a self-contained
    /// profile.
    #[test]
    fn thin_offers_are_refused_unless_the_profile_and_the_pair_are_valid() {
        let held = object(ObjectType::Blob, &shifted_lines(0, 400), 1, 7);
        let target = object(ObjectType::Blob, &shifted_lines(3, 400), 2, 7);
        let second = object(ObjectType::Blob, b"second held base", 1, 8);
        let third = object(ObjectType::Blob, b"third held base", 1, 9);
        let source = FixtureSource::with(vec![
            held.clone(),
            target.clone(),
            second.clone(),
            third.clone(),
        ]);
        let offer = ThinBase::new(target.id(), held.id());
        assert!(matches!(
            thin_planner(PackWriteProfile::COMPRESSED_V3).plan_selected_thin(
                &source,
                &[target.id()],
                &[offer],
                &mut always
            ),
            Err(PackWriteError::ThinBasesNotPermitted)
        ));
        let planner = thin_planner(PackWriteProfile::COMPRESSED_V3_THIN);
        let over_cap = [
            offer,
            ThinBase::new(target.id(), second.id()),
            ThinBase::new(target.id(), third.id()),
        ];
        for (selected, offers) in [
            (vec![held.id()], vec![offer]),
            (vec![target.id(), held.id()], vec![offer]),
            (vec![target.id()], vec![offer, offer]),
            (vec![target.id()], over_cap.to_vec()),
        ] {
            assert!(
                matches!(
                    planner.plan_selected_thin(&source, &selected, &offers, &mut always),
                    Err(PackWriteError::InvalidThinBase { .. })
                ),
                "{selected:?} {offers:?}"
            );
        }
        let permitted = planner
            .plan_selected_thin(&source, &[target.id()], &over_cap[..2], &mut always)
            .expect("two bases per target are permitted");
        assert_eq!(
            permitted.entries()[0].delta().map(PlannedDelta::base),
            Some(PlannedDeltaBase::Client(held.id()))
        );
        let relabelled = PackPlan {
            profile: PackWriteProfile::COMPRESSED_V3,
            ..permitted
        };
        assert!(matches!(
            PackWriter::new(wide_limits()).write(&relabelled, &mut always),
            Err(PackWriteError::ThinBasesNotPermitted)
        ));
    }
}
