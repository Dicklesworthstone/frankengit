use std::collections::HashMap;

use fgit_git_object::ObjectType;

use crate::{
    Deadline, EntryKind, ObjectId, PackError, PackLimits, checkpoint, object_type_from_base_entry,
};

mod stream;
pub use stream::{
    DeltaStreamIo, STREAM_DELTA_CHUNK_BYTES, StreamDeltaError,
    apply_delta_streamed_to_charged_base_with_budget, delta_declared_sizes,
};

/// A base reference carried by a delta entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaBase {
    /// Absolute offset of an earlier object in this pack.
    Ofs(u64),
    /// Native object ID, either in this pack or supplied by a thin-pack base
    /// lookup.
    Ref(ObjectId),
}

/// Quarantined, already-inflated delta bytes with their immutable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaObject {
    pub offset: u64,
    pub id: Option<ObjectId>,
    pub base: DeltaBase,
    pub program: Vec<u8>,
}

/// A scalar resolver input. The scalar resolver keeps no reconstruction cache,
/// providing the reference semantics that an optimized path must prove
/// equivalent to; its lookups are index probes whose answers equal a linear
/// scan's (see `indexed_lookups_answer_exactly_what_a_linear_scan_answers`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackObject {
    /// A legacy base input that carries bytes but no native object-type
    /// commitment. It remains available to preserve the byte-only resolver
    /// API, but cannot root a typed resolution.
    Base {
        offset: u64,
        id: Option<ObjectId>,
        data: Vec<u8>,
    },
    /// A base input whose pack entry kind commits to its native object type.
    ///
    /// [`crate::QuarantinedPack::into_scalar_objects`] emits this variant for
    /// every non-delta entry so typed resolution can carry the original pack
    /// type through an arbitrary delta chain without guessing from bytes.
    TypedBase {
        offset: u64,
        id: Option<ObjectId>,
        kind: EntryKind,
        data: Vec<u8>,
    },
    Delta(DeltaObject),
}

impl PackObject {
    const fn offset(&self) -> u64 {
        match self {
            Self::Base { offset, .. }
            | Self::TypedBase { offset, .. }
            | Self::Delta(DeltaObject { offset, .. }) => *offset,
        }
    }

    const fn id(&self) -> Option<&ObjectId> {
        match self {
            Self::Base { id, .. }
            | Self::TypedBase { id, .. }
            | Self::Delta(DeltaObject { id, .. }) => id.as_ref(),
        }
    }
}

/// Caller-owned thin-pack base source. The lookup returns borrowed data, so a
/// pack resolver never asks an untrusted lookup to allocate before its limits
/// are checked.
pub trait ExternalBaseLookup {
    fn lookup(&self, id: &ObjectId) -> Option<&[u8]>;

    /// Looks up a thin-pack base together with its already authenticated
    /// native object type.
    ///
    /// The default preserves every existing byte-only lookup implementation.
    /// A typed resolver treats that default as an explicit absence of type
    /// provenance and refuses rather than inferring a type from delta bytes.
    fn lookup_typed(&self, _id: &ObjectId) -> Option<(ObjectType, &[u8])> {
        None
    }
}

impl ExternalBaseLookup for () {
    fn lookup(&self, _id: &ObjectId) -> Option<&[u8]> {
        None
    }
}

/// Bounded scalar delta resolver for pack-local and thin-pack base chains.
///
/// Lookups by offset, by id and by shared delta base are binary searches over
/// indexes sorted once in [`Self::new`], each charged its probe depth against
/// `max_delta_work`. A linear scan per lookup charged one unit per object in
/// the pack, so resolving every object of an N-object pack charged N^2, and
/// any pack over about 16k objects was refused whatever it held
/// (frankengit-eq4h). The indexes answer exactly what the scan answered: the
/// same object, and a duplicate offset or id refused when -- and only when --
/// the duplicated key is looked up.
pub struct ScalarResolver<'objects, 'lookup, L> {
    external_bases: &'lookup L,
    limits: &'objects PackLimits,
    /// Every object, by offset (stable, so equal offsets keep slice order).
    by_offset: Vec<&'objects PackObject>,
    /// Every object that carries an id, by id.
    by_id: Vec<&'objects PackObject>,
    /// Every delta's base, offset bases before id bases, for fanout counts.
    by_base: Vec<&'objects DeltaBase>,
    /// Work charged per index probe: the bit length of the object count.
    probe_cost: usize,
}

/// Total order over delta bases for the fanout index. Only equality is
/// observable: it is exactly `DeltaBase`'s, which is what the fanout counts.
const fn base_key(base: &DeltaBase) -> (bool, u64, Option<&ObjectId>) {
    match base {
        DeltaBase::Ofs(offset) => (false, *offset, None),
        DeltaBase::Ref(id) => (true, 0, Some(id)),
    }
}

/// Reserves exactly `count` entries, refusing rather than aborting.
fn index_with_capacity<T>(count: usize) -> Result<Vec<T>, PackError> {
    let mut index = Vec::new();
    index
        .try_reserve_exact(count)
        .map_err(|_| PackError::AllocationFailed { requested: count })?;
    Ok(index)
}

impl<'objects, 'lookup, L> ScalarResolver<'objects, 'lookup, L>
where
    L: ExternalBaseLookup,
{
    /// Validates bounded input shape before it is used to surface any object,
    /// and sorts the lookup indexes once. Ambiguous base identities and fanout
    /// are still checked on the selected chain, where each index probe is
    /// charged to `max_delta_work`.
    pub fn new(
        objects: &'objects [PackObject],
        external_bases: &'lookup L,
        limits: &'objects PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, PackError> {
        let actual_count =
            u32::try_from(objects.len()).map_err(|_| PackError::EntryCountLimit {
                actual: u32::MAX,
                limit: limits.max_entries,
            })?;
        if actual_count > limits.max_entries {
            return Err(PackError::EntryCountLimit {
                actual: actual_count,
                limit: limits.max_entries,
            });
        }
        let mut by_offset = index_with_capacity(objects.len())?;
        let mut by_id = index_with_capacity(objects.len())?;
        let mut by_base = index_with_capacity(objects.len())?;
        for object in objects {
            checkpoint(deadline)?;
            match object {
                PackObject::Base { data, .. } | PackObject::TypedBase { data, .. } => {
                    limits.object_size(data.len())?;
                }
                PackObject::Delta(delta) => {
                    limits.input(delta.program.len())?;
                    by_base.push(&delta.base);
                }
            }
            by_offset.push(object);
            if object.id().is_some() {
                by_id.push(object);
            }
        }
        checkpoint(deadline)?;
        by_offset.sort_by_key(|object| object.offset());
        by_id.sort_by_key(|object| object.id());
        by_base.sort_by(|left, right| base_key(left).cmp(&base_key(right)));
        checkpoint(deadline)?;
        let probe_cost = usize::try_from(objects.len().bit_width())
            .map_err(|_| PackError::IntegerOverflow {
                context: "pack index probe cost",
            })?
            .max(1);
        Ok(Self {
            external_bases,
            limits,
            by_offset,
            by_id,
            by_base,
            probe_cost,
        })
    }

    /// Resolves one pack object by offset, enforcing chain-global budgets.
    pub fn resolve_offset(
        &self,
        offset: u64,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        let mut accounting = Accounting::default();
        let object = self
            .find_by_offset(offset, &mut accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let mut stack = Vec::new();
        self.resolve_object(object, 0, &mut stack, &mut accounting, deadline)
    }

    /// Resolves a known native ID. This supports a `REF_DELTA` root without
    /// forcing callers to expose their offset index.
    pub fn resolve_id(
        &self,
        id: &ObjectId,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        let mut accounting = Accounting::default();
        let object = self
            .find_by_id(id, &mut accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let mut stack = Vec::new();
        self.resolve_object(object, 0, &mut stack, &mut accounting, deadline)
    }

    /// Resolves one pack object by offset and returns the native object type
    /// inherited from its authenticated base root.
    pub fn resolve_offset_typed(
        &self,
        offset: u64,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Vec<u8>), PackError> {
        let mut accounting = Accounting::default();
        let object = self
            .find_by_offset(offset, &mut accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let mut stack = Vec::new();
        let resolved =
            self.resolve_object_typed(object, 0, &mut stack, &mut accounting, deadline)?;
        Ok((resolved.object_type, resolved.bytes))
    }

    /// Resolves one known native ID and returns the type inherited from its
    /// authenticated base root.
    pub fn resolve_id_typed(
        &self,
        id: &ObjectId,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Vec<u8>), PackError> {
        let mut accounting = Accounting::default();
        let object = self
            .find_by_id(id, &mut accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let mut stack = Vec::new();
        let resolved =
            self.resolve_object_typed(object, 0, &mut stack, &mut accounting, deadline)?;
        Ok((resolved.object_type, resolved.bytes))
    }

    fn resolve_object(
        &self,
        object: &PackObject,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        checkpoint(deadline)?;
        if stack.contains(&object.offset()) {
            return Err(PackError::DeltaCycle);
        }
        match object {
            PackObject::Base { data, .. } | PackObject::TypedBase { data, .. } => {
                self.limits.object_size(data.len())?;
                accounting.add_expanded(data.len(), self.limits)?;
                copy_bytes(data, deadline)
            }
            PackObject::Delta(delta) => {
                self.validate_fanout(&delta.base, accounting, deadline)?;
                let next_depth = depth.checked_add(1).ok_or(PackError::IntegerOverflow {
                    context: "delta depth",
                })?;
                if next_depth > self.limits.max_delta_depth {
                    return Err(PackError::DeltaDepthLimit {
                        depth: next_depth,
                        limit: self.limits.max_delta_depth,
                    });
                }
                stack
                    .try_reserve(1)
                    .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
                stack.push(delta.offset);
                let base_result =
                    self.resolve_base(&delta.base, next_depth, stack, accounting, deadline);
                let result = match base_result {
                    Ok(base) => apply_delta_with_accounting(
                        &base,
                        &delta.program,
                        self.limits,
                        accounting,
                        deadline,
                    ),
                    Err(error) => Err(error),
                };
                let popped = stack.pop();
                debug_assert_eq!(popped, Some(delta.offset));
                let result = result?;
                accounting.add_expanded(result.len(), self.limits)?;
                Ok(result)
            }
        }
    }

    fn resolve_object_typed(
        &self,
        object: &PackObject,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<TypedResolution, PackError> {
        checkpoint(deadline)?;
        if stack.contains(&object.offset()) {
            return Err(PackError::DeltaCycle);
        }
        match object {
            PackObject::Base { .. } => Err(PackError::UntypedInPackBase),
            PackObject::TypedBase { kind, data, .. } => {
                let object_type = object_type_from_base_entry(*kind)?;
                self.limits.object_size(data.len())?;
                accounting.add_expanded(data.len(), self.limits)?;
                Ok(TypedResolution {
                    object_type,
                    bytes: copy_bytes(data, deadline)?,
                })
            }
            PackObject::Delta(delta) => {
                self.validate_fanout(&delta.base, accounting, deadline)?;
                let next_depth = depth.checked_add(1).ok_or(PackError::IntegerOverflow {
                    context: "delta depth",
                })?;
                if next_depth > self.limits.max_delta_depth {
                    return Err(PackError::DeltaDepthLimit {
                        depth: next_depth,
                        limit: self.limits.max_delta_depth,
                    });
                }
                stack
                    .try_reserve(1)
                    .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
                stack.push(delta.offset);
                let base_result =
                    self.resolve_base_typed(&delta.base, next_depth, stack, accounting, deadline);
                // No `?` before the pop below, as in the cached resolver: an
                // early return left this offset on the stack, so a refusal
                // inside a typed chain panicked the caller's pop assertion.
                let result = match base_result {
                    Ok(base) => {
                        let object_type = base.object_type;
                        apply_delta_with_accounting(
                            &base.bytes,
                            &delta.program,
                            self.limits,
                            accounting,
                            deadline,
                        )
                        .and_then(|bytes| {
                            accounting.add_expanded(bytes.len(), self.limits)?;
                            Ok(TypedResolution { object_type, bytes })
                        })
                    }
                    Err(error) => Err(error),
                };
                let popped = stack.pop();
                debug_assert_eq!(popped, Some(delta.offset));
                result
            }
        }
    }

    fn resolve_base(
        &self,
        base: &DeltaBase,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        match base {
            DeltaBase::Ofs(offset) => {
                let object = self
                    .find_by_offset(*offset, accounting, deadline)?
                    .ok_or(PackError::MissingDeltaBase)?;
                self.resolve_object(object, depth, stack, accounting, deadline)
            }
            DeltaBase::Ref(id) => {
                if let Some(object) = self.find_by_id(id, accounting, deadline)? {
                    self.resolve_object(object, depth, stack, accounting, deadline)
                } else {
                    checkpoint(deadline)?;
                    let external = self
                        .external_bases
                        .lookup(id)
                        .ok_or(PackError::MissingDeltaBase)?;
                    self.limits.object_size(external.len())?;
                    accounting.add_expanded(external.len(), self.limits)?;
                    copy_bytes(external, deadline)
                }
            }
        }
    }

    fn resolve_base_typed(
        &self,
        base: &DeltaBase,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<TypedResolution, PackError> {
        match base {
            DeltaBase::Ofs(offset) => {
                let object = self
                    .find_by_offset(*offset, accounting, deadline)?
                    .ok_or(PackError::MissingDeltaBase)?;
                self.resolve_object_typed(object, depth, stack, accounting, deadline)
            }
            DeltaBase::Ref(id) => {
                if let Some(object) = self.find_by_id(id, accounting, deadline)? {
                    self.resolve_object_typed(object, depth, stack, accounting, deadline)
                } else if let Some((object_type, external)) = self.external_bases.lookup_typed(id) {
                    self.limits.object_size(external.len())?;
                    accounting.add_expanded(external.len(), self.limits)?;
                    Ok(TypedResolution {
                        object_type,
                        bytes: copy_bytes(external, deadline)?,
                    })
                } else if self.external_bases.lookup(id).is_some() {
                    Err(PackError::UntypedExternalDeltaBase)
                } else {
                    Err(PackError::MissingDeltaBase)
                }
            }
        }
    }

    fn find_by_offset(
        &self,
        offset: u64,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<Option<&'objects PackObject>, PackError> {
        checkpoint(deadline)?;
        accounting.add_work(self.probe_cost, self.limits)?;
        let first = self
            .by_offset
            .partition_point(|object| object.offset() < offset);
        let mut matching = self.by_offset[first..]
            .iter()
            .take_while(|object| object.offset() == offset);
        let found = matching.next().copied();
        if matching.next().is_some() {
            return Err(PackError::DuplicateObjectOffset(offset));
        }
        Ok(found)
    }

    fn find_by_id(
        &self,
        id: &ObjectId,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<Option<&'objects PackObject>, PackError> {
        checkpoint(deadline)?;
        accounting.add_work(self.probe_cost, self.limits)?;
        let first = self.by_id.partition_point(|object| object.id() < Some(id));
        let mut matching = self.by_id[first..]
            .iter()
            .take_while(|object| object.id() == Some(id));
        let found = matching.next().copied();
        if matching.next().is_some() {
            return Err(PackError::DuplicateObjectId);
        }
        Ok(found)
    }

    fn validate_fanout(
        &self,
        base: &DeltaBase,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<(), PackError> {
        checkpoint(deadline)?;
        accounting.add_work(self.probe_cost, self.limits)?;
        let key = base_key(base);
        let first = self
            .by_base
            .partition_point(|candidate| base_key(candidate) < key);
        let fanout = self.by_base[first..].partition_point(|candidate| base_key(candidate) == key);
        if fanout > self.limits.max_delta_fanout {
            // The value the scan reported: the count at which it first
            // exceeded the limit.
            return Err(PackError::DeltaFanoutLimit {
                fanout: self.limits.max_delta_fanout.checked_add(1).ok_or(
                    PackError::IntegerOverflow {
                        context: "delta fanout",
                    },
                )?,
                limit: self.limits.max_delta_fanout,
            });
        }
        Ok(())
    }
}

struct TypedResolution {
    object_type: ObjectType,
    bytes: Vec<u8>,
}

/// A bounded cache over the scalar resolver.
///
/// Each unique pack object's expanded bytes are charged to the aggregate
/// [`max_total_expanded_bytes`](crate::PackLimits::max_total_expanded_bytes)
/// budget exactly once, when that object is first resolved and cached. A later
/// cache hit re-uses those already-counted bytes and charges no further
/// expansion, so the bomb defence bounds the *unique* inflated size of the pack
/// rather than the number of times a shared delta base is reconstructed across
/// a receive (frankengit-rpqx).
///
/// [`max_delta_work`](crate::PackLimits::max_delta_work) is charged the work the
/// resolver actually performs: every byte a delta copies or inserts when an
/// object is reconstructed, and every byte copied out of the cache on a hit.
/// A hit does NOT re-charge the chain that originally built the entry -- that
/// reconstruction was charged once, when it ran. Re-charging it made the total
/// quadratic in chain length and refused an ordinary history (80 revisions of a
/// 120 KB file at Git's default depth 50) whose real work is a few MiB
/// (frankengit-z6rb). The charge stays a deterministic function of the pack and
/// the limits: entries are cached in resolution order until
/// [`max_cached_bytes`](crate::PackLimits::max_cached_bytes) is reached and never
/// evicted, and an object that did not fit is re-resolved -- and its chain
/// re-charged -- every time it is needed, which is exactly the work done.
/// Charging the copy also bounds a hot base: a base shared by many deltas is
/// copied once per delta, and each copy counts, where the old model charged a
/// base's hit nothing.
pub struct CachedResolver<'objects, 'lookup, L> {
    scalar: ScalarResolver<'objects, 'lookup, L>,
    /// By offset. Only ever probed by key, never iterated, so the hash order
    /// is unobservable. A sorted Vec shifted half its entries per insert when
    /// a walk resolves in idx (object id) order, as fg import does, which is
    /// quadratic in the pack (frankengit-eq4h).
    entries: HashMap<u64, CacheEntry>,
    cached_bytes: usize,
}

struct CacheEntry {
    bytes: Vec<u8>,
    object_type: Option<ObjectType>,
}

impl<'objects, 'lookup, L> CachedResolver<'objects, 'lookup, L>
where
    L: ExternalBaseLookup,
{
    /// Builds an optimized resolver from exactly the scalar resolver's input
    /// validation and immutable object graph.
    pub fn new(
        objects: &'objects [PackObject],
        external_bases: &'lookup L,
        limits: &'objects PackLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Self, PackError> {
        Ok(Self {
            scalar: ScalarResolver::new(objects, external_bases, limits, deadline)?,
            entries: HashMap::new(),
            cached_bytes: 0,
        })
    }

    /// Resolves one offset with base-result caching. The output is the scalar
    /// resolver's; the budget is charged the work this resolver performs (see
    /// the type documentation), not the scalar resolver's re-resolution.
    pub fn resolve_offset(
        &mut self,
        offset: u64,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        let mut accounting = Accounting::default();
        let object = self
            .scalar
            .find_by_offset(offset, &mut accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let object = clone_pack_object(object, deadline)?;
        let mut stack = Vec::new();
        self.resolve_object(&object, 0, &mut stack, &mut accounting, deadline)
    }

    /// Resolves one offset with the type inherited from its authenticated base
    /// root. Typed cache entries carry that root type alongside their bytes;
    /// byte-only cache entries are deliberately recomputed rather than being
    /// promoted into type authority.
    pub fn resolve_offset_typed(
        &mut self,
        offset: u64,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Vec<u8>), PackError> {
        let mut budget = ResolutionBudget::default();
        self.resolve_offset_typed_with_budget(offset, &mut budget, deadline)
    }

    /// Resolves one offset with a caller-owned budget shared across an entire
    /// bounded operation.
    ///
    /// A receive validator uses one [`ResolutionBudget`] for every retained
    /// pack entry, so a sequence of individually valid delta chains cannot
    /// evade aggregate expansion or work limits by resetting accounting at
    /// each object boundary.
    pub fn resolve_offset_typed_with_budget(
        &mut self,
        offset: u64,
        budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Vec<u8>), PackError> {
        let object = self
            .scalar
            .find_by_offset(offset, &mut budget.accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let object = clone_pack_object(object, deadline)?;
        let mut stack = Vec::new();
        let resolved =
            self.resolve_object_typed(&object, 0, &mut stack, &mut budget.accounting, deadline)?;
        Ok((resolved.object_type, resolved.bytes))
    }

    /// Resolves one native ID with the type inherited from its authenticated
    /// base root.
    pub fn resolve_id_typed(
        &mut self,
        id: &ObjectId,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Vec<u8>), PackError> {
        let mut budget = ResolutionBudget::default();
        self.resolve_id_typed_with_budget(id, &mut budget, deadline)
    }

    /// Resolves one identity with a caller-owned budget shared across an
    /// entire bounded operation.
    pub fn resolve_id_typed_with_budget(
        &mut self,
        id: &ObjectId,
        budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Vec<u8>), PackError> {
        let object = self
            .scalar
            .find_by_id(id, &mut budget.accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let object = clone_pack_object(object, deadline)?;
        let mut stack = Vec::new();
        let resolved =
            self.resolve_object_typed(&object, 0, &mut stack, &mut budget.accounting, deadline)?;
        Ok((resolved.object_type, resolved.bytes))
    }

    fn resolve_object(
        &mut self,
        object: &PackObject,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        checkpoint(deadline)?;
        if let Some(cached) = self.cached(object.offset()) {
            // Expanded bytes were charged when this offset was first resolved
            // (frankengit-rpqx); the hit charges only the copy it performs
            // (frankengit-z6rb).
            accounting.add_work(cached.bytes.len(), self.scalar.limits)?;
            return copy_bytes(&cached.bytes, deadline);
        }
        if stack.contains(&object.offset()) {
            return Err(PackError::DeltaCycle);
        }
        let result = match object {
            PackObject::Base { data, .. } | PackObject::TypedBase { data, .. } => {
                self.scalar.limits.object_size(data.len())?;
                accounting.add_expanded(data.len(), self.scalar.limits)?;
                copy_bytes(data, deadline)
            }
            PackObject::Delta(delta) => {
                self.scalar
                    .validate_fanout(&delta.base, accounting, deadline)?;
                let next_depth = depth.checked_add(1).ok_or(PackError::IntegerOverflow {
                    context: "delta depth",
                })?;
                if next_depth > self.scalar.limits.max_delta_depth {
                    return Err(PackError::DeltaDepthLimit {
                        depth: next_depth,
                        limit: self.scalar.limits.max_delta_depth,
                    });
                }
                stack
                    .try_reserve(1)
                    .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
                stack.push(delta.offset);
                let base = self.resolve_base(&delta.base, next_depth, stack, accounting, deadline);
                let result = match base {
                    Ok(bytes) => apply_delta_with_accounting(
                        &bytes,
                        &delta.program,
                        self.scalar.limits,
                        accounting,
                        deadline,
                    ),
                    Err(error) => Err(error),
                };
                let popped = stack.pop();
                debug_assert_eq!(popped, Some(delta.offset));
                let result = result?;
                accounting.add_expanded(result.len(), self.scalar.limits)?;
                Ok(result)
            }
        }?;
        self.cache(object.offset(), &result, None, deadline)?;
        Ok(result)
    }

    fn resolve_object_typed(
        &mut self,
        object: &PackObject,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<TypedResolution, PackError> {
        checkpoint(deadline)?;
        if let Some(cached) = self.cached(object.offset())
            && let Some(object_type) = cached.object_type
        {
            // Expanded bytes are charged once, at first resolution
            // (frankengit-rpqx); the hit charges only its copy (frankengit-z6rb).
            accounting.add_work(cached.bytes.len(), self.scalar.limits)?;
            return Ok(TypedResolution {
                object_type,
                bytes: copy_bytes(&cached.bytes, deadline)?,
            });
        }
        if stack.contains(&object.offset()) {
            return Err(PackError::DeltaCycle);
        }
        let resolved = match object {
            PackObject::Base { .. } => return Err(PackError::UntypedInPackBase),
            PackObject::TypedBase { kind, data, .. } => {
                let object_type = object_type_from_base_entry(*kind)?;
                self.scalar.limits.object_size(data.len())?;
                accounting.add_expanded(data.len(), self.scalar.limits)?;
                TypedResolution {
                    object_type,
                    bytes: copy_bytes(data, deadline)?,
                }
            }
            PackObject::Delta(delta) => {
                self.scalar
                    .validate_fanout(&delta.base, accounting, deadline)?;
                let next_depth = depth.checked_add(1).ok_or(PackError::IntegerOverflow {
                    context: "delta depth",
                })?;
                if next_depth > self.scalar.limits.max_delta_depth {
                    return Err(PackError::DeltaDepthLimit {
                        depth: next_depth,
                        limit: self.scalar.limits.max_delta_depth,
                    });
                }
                stack
                    .try_reserve(1)
                    .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
                stack.push(delta.offset);
                let base =
                    self.resolve_base_typed(&delta.base, next_depth, stack, accounting, deadline);
                // No `?` before the pop below: an early return here left this
                // offset on the stack, so any refusal inside a typed chain
                // (a work limit, a bad copy) tripped the pop assertion and
                // panicked in debug builds instead of returning its typed error.
                let resolved = match base {
                    Ok(base) => {
                        let object_type = base.object_type;
                        apply_delta_with_accounting(
                            &base.bytes,
                            &delta.program,
                            self.scalar.limits,
                            accounting,
                            deadline,
                        )
                        .and_then(|bytes| {
                            accounting.add_expanded(bytes.len(), self.scalar.limits)?;
                            Ok(TypedResolution { object_type, bytes })
                        })
                    }
                    Err(error) => Err(error),
                };
                let popped = stack.pop();
                debug_assert_eq!(popped, Some(delta.offset));
                resolved?
            }
        };
        self.cache(
            object.offset(),
            &resolved.bytes,
            Some(resolved.object_type),
            deadline,
        )?;
        Ok(resolved)
    }

    fn resolve_base(
        &mut self,
        base: &DeltaBase,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<u8>, PackError> {
        match base {
            DeltaBase::Ofs(offset) => {
                let object = self
                    .scalar
                    .find_by_offset(*offset, accounting, deadline)?
                    .ok_or(PackError::MissingDeltaBase)?;
                let object = clone_pack_object(object, deadline)?;
                self.resolve_object(&object, depth, stack, accounting, deadline)
            }
            DeltaBase::Ref(id) => {
                if let Some(object) = self.scalar.find_by_id(id, accounting, deadline)? {
                    let object = clone_pack_object(object, deadline)?;
                    self.resolve_object(&object, depth, stack, accounting, deadline)
                } else {
                    checkpoint(deadline)?;
                    let external = self
                        .scalar
                        .external_bases
                        .lookup(id)
                        .ok_or(PackError::MissingDeltaBase)?;
                    self.scalar.limits.object_size(external.len())?;
                    accounting.add_expanded(external.len(), self.scalar.limits)?;
                    copy_bytes(external, deadline)
                }
            }
        }
    }

    fn resolve_base_typed(
        &mut self,
        base: &DeltaBase,
        depth: usize,
        stack: &mut Vec<u64>,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<TypedResolution, PackError> {
        match base {
            DeltaBase::Ofs(offset) => {
                let object = self
                    .scalar
                    .find_by_offset(*offset, accounting, deadline)?
                    .ok_or(PackError::MissingDeltaBase)?;
                let object = clone_pack_object(object, deadline)?;
                self.resolve_object_typed(&object, depth, stack, accounting, deadline)
            }
            DeltaBase::Ref(id) => {
                if let Some(object) = self.scalar.find_by_id(id, accounting, deadline)? {
                    let object = clone_pack_object(object, deadline)?;
                    self.resolve_object_typed(&object, depth, stack, accounting, deadline)
                } else if let Some((object_type, external)) =
                    self.scalar.external_bases.lookup_typed(id)
                {
                    self.scalar.limits.object_size(external.len())?;
                    accounting.add_expanded(external.len(), self.scalar.limits)?;
                    Ok(TypedResolution {
                        object_type,
                        bytes: copy_bytes(external, deadline)?,
                    })
                } else if self.scalar.external_bases.lookup(id).is_some() {
                    Err(PackError::UntypedExternalDeltaBase)
                } else {
                    Err(PackError::MissingDeltaBase)
                }
            }
        }
    }

    fn cached(&self, offset: u64) -> Option<&CacheEntry> {
        self.entries.get(&offset)
    }

    fn cache(
        &mut self,
        offset: u64,
        bytes: &[u8],
        object_type: Option<ObjectType>,
        deadline: &mut impl Deadline,
    ) -> Result<(), PackError> {
        let required =
            self.cached_bytes
                .checked_add(bytes.len())
                .ok_or(PackError::IntegerOverflow {
                    context: "delta cache bytes",
                })?;
        if required > self.scalar.limits.max_cached_bytes {
            return Ok(());
        }
        checkpoint(deadline)?;
        if let Some(entry) = self.entries.get_mut(&offset) {
            if entry.object_type.is_none() {
                entry.object_type = object_type;
            }
            return Ok(());
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
        let copy = copy_bytes(bytes, deadline)?;
        self.entries.insert(
            offset,
            CacheEntry {
                bytes: copy,
                object_type,
            },
        );
        self.cached_bytes = required;
        Ok(())
    }
}

fn clone_pack_object(
    object: &PackObject,
    deadline: &mut impl Deadline,
) -> Result<PackObject, PackError> {
    match object {
        PackObject::Base { offset, id, data } => Ok(PackObject::Base {
            offset: *offset,
            id: *id,
            data: copy_bytes(data, deadline)?,
        }),
        PackObject::TypedBase {
            offset,
            id,
            kind,
            data,
        } => Ok(PackObject::TypedBase {
            offset: *offset,
            id: *id,
            kind: *kind,
            data: copy_bytes(data, deadline)?,
        }),
        PackObject::Delta(delta) => Ok(PackObject::Delta(DeltaObject {
            offset: delta.offset,
            id: delta.id,
            base: delta.base.clone(),
            program: copy_bytes(&delta.program, deadline)?,
        })),
    }
}

#[derive(Default)]
struct Accounting {
    expanded: usize,
    work: usize,
}

/// Caller-owned accounting for a bounded sequence of delta resolutions.
///
/// The ordinary resolver methods construct a fresh value for backwards
/// compatible one-object semantics.  A boundary that retains more than one
/// reconstructed object must retain one of these witnesses for its complete
/// operation and pass it to the `*_with_budget` methods.
#[derive(Default)]
pub struct ResolutionBudget {
    accounting: Accounting,
}

impl ResolutionBudget {
    /// Starts an empty aggregate resolution budget.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Charges caller-owned resolution lookup or scheduling work to the same
    /// operation-wide budget used by delta instructions. A refusal does not
    /// reset the previously consumed budget.
    pub fn charge_work(&mut self, amount: usize, limits: &PackLimits) -> Result<(), PackError> {
        self.accounting.add_work(amount, limits)
    }

    /// Charges bytes retained or reconstructed outside the resolver, such as a
    /// verified base spilled to caller-owned quarantine storage.
    pub fn charge_expanded(&mut self, amount: usize, limits: &PackLimits) -> Result<(), PackError> {
        self.accounting.add_expanded(amount, limits)
    }
}

impl Accounting {
    fn ensure_expanded(&self, bytes: usize, limits: &PackLimits) -> Result<(), PackError> {
        let attempted = self
            .expanded
            .checked_add(bytes)
            .ok_or(PackError::IntegerOverflow {
                context: "delta expanded bytes",
            })?;
        if attempted > limits.max_total_expanded_bytes {
            return Err(PackError::TotalExpandedLimit {
                actual: attempted,
                limit: limits.max_total_expanded_bytes,
            });
        }
        Ok(())
    }

    fn add_expanded(&mut self, bytes: usize, limits: &PackLimits) -> Result<(), PackError> {
        self.ensure_expanded(bytes, limits)?;
        let attempted = self
            .expanded
            .checked_add(bytes)
            .ok_or(PackError::IntegerOverflow {
                context: "delta expanded bytes",
            })?;
        self.expanded = attempted;
        Ok(())
    }

    fn add_work(&mut self, bytes: usize, limits: &PackLimits) -> Result<(), PackError> {
        let attempted = self
            .work
            .checked_add(bytes)
            .ok_or(PackError::IntegerOverflow {
                context: "delta chain work",
            })?;
        if attempted > limits.max_delta_work {
            return Err(PackError::DeltaWorkLimit {
                attempted,
                limit: limits.max_delta_work,
            });
        }
        self.work = attempted;
        Ok(())
    }
}

/// Applies a raw, inflated Git delta instruction stream with no hidden
/// allocation or unbounded work.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackError> {
    apply_delta_with_budget(base, delta, limits, &mut ResolutionBudget::new(), deadline)
}

/// Applies one delta under caller-owned aggregate accounting, reusing the same
/// instruction decoder as [`apply_delta`]. The base read and reconstructed
/// result are both charged; failed work never resets this operation's budget.
pub fn apply_delta_with_budget(
    base: &[u8],
    delta: &[u8],
    limits: &PackLimits,
    budget: &mut ResolutionBudget,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackError> {
    budget.accounting.add_expanded(base.len(), limits)?;
    let result =
        apply_delta_with_accounting(base, delta, limits, &mut budget.accounting, deadline)?;
    budget.accounting.add_expanded(result.len(), limits)?;
    Ok(result)
}

/// Applies one delta whose authenticated base is already charged to this
/// operation's expanded-byte budget. Only the new result is charged as expanded
/// payload; reading the reused base and executing the delta remain work charged
/// to [`PackLimits::max_delta_work`] on every call.
///
/// The caller must obtain `base` from its private, native-verified inventory and
/// have charged that object's full size to this same [`ResolutionBudget`],
/// either with [`ResolutionBudget::charge_expanded`] or by an earlier successful
/// resolution. It must verify scratch bytes against that inventory before
/// reuse. This function does not authenticate bytes, establish a base identity
/// or type, or make an uncharged external base eligible for count-once
/// accounting. Use [`apply_delta_with_budget`] when that precondition is absent.
pub fn apply_delta_to_charged_base_with_budget(
    base: &[u8],
    delta: &[u8],
    limits: &PackLimits,
    budget: &mut ResolutionBudget,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackError> {
    checkpoint(deadline)?;
    budget.accounting.add_work(base.len(), limits)?;
    let result =
        apply_delta_with_accounting(base, delta, limits, &mut budget.accounting, deadline)?;
    budget.accounting.add_expanded(result.len(), limits)?;
    Ok(result)
}

fn apply_delta_with_accounting(
    base: &[u8],
    delta: &[u8],
    limits: &PackLimits,
    accounting: &mut Accounting,
    deadline: &mut impl Deadline,
) -> Result<Vec<u8>, PackError> {
    limits.input(delta.len())?;
    limits.object_size(base.len())?;
    let mut cursor = 0;
    let declared_base = read_delta_size(delta, &mut cursor, "delta base size", deadline)?;
    if declared_base != base.len() {
        return Err(PackError::DeltaBaseSizeMismatch {
            declared: declared_base,
            actual: base.len(),
        });
    }
    let declared_result = read_delta_size(delta, &mut cursor, "delta result size", deadline)?;
    if declared_result > limits.max_object_bytes {
        return Err(PackError::DeltaResultSizeLimit {
            declared: declared_result,
            limit: limits.max_object_bytes,
        });
    }
    accounting.ensure_expanded(declared_result, limits)?;
    checkpoint(deadline)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(declared_result)
        .map_err(|_| PackError::AllocationFailed {
            requested: declared_result,
        })?;

    while cursor < delta.len() {
        checkpoint(deadline)?;
        let instruction = read_byte(delta, &mut cursor, "delta instruction", deadline)?;
        if instruction == 0 {
            return Err(PackError::InvalidDeltaInstruction);
        }
        if instruction & 0x80 == 0 {
            let length = usize::from(instruction);
            append_insert(
                &mut result,
                declared_result,
                delta,
                &mut cursor,
                length,
                accounting,
                limits,
                deadline,
            )?;
        } else {
            let (offset, length) =
                decode_copy_instruction(instruction, delta, &mut cursor, deadline)?;
            let end = offset
                .checked_add(length)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta copy range",
                })?;
            if end > base.len() {
                return Err(PackError::DeltaCopyOutOfRange {
                    offset,
                    length,
                    base_len: base.len(),
                });
            }
            append_copy(
                &mut result,
                declared_result,
                &base[offset..end],
                accounting,
                limits,
                deadline,
            )?;
        }
    }
    if result.len() != declared_result {
        return Err(PackError::DeltaResultSizeMismatch {
            declared: declared_result,
            actual: result.len(),
        });
    }
    Ok(result)
}

fn read_delta_size(
    input: &[u8],
    cursor: &mut usize,
    context: &'static str,
    deadline: &mut impl Deadline,
) -> Result<usize, PackError> {
    let mut value = 0_usize;
    let mut shift = 0_u32;
    loop {
        let byte = read_byte(input, cursor, context, deadline)?;
        let payload = usize::from(byte & 0x7f);
        let component = payload
            .checked_shl(shift)
            .filter(|component| (*component >> shift) == payload)
            .ok_or(PackError::InvalidVarint { context })?;
        value = value
            .checked_add(component)
            .ok_or(PackError::IntegerOverflow { context })?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift = shift
            .checked_add(7)
            .ok_or(PackError::InvalidVarint { context })?;
        if shift >= usize::BITS {
            return Err(PackError::InvalidVarint { context });
        }
    }
}

fn read_byte(
    input: &[u8],
    cursor: &mut usize,
    context: &'static str,
    deadline: &mut impl Deadline,
) -> Result<u8, PackError> {
    checkpoint(deadline)?;
    let byte = *input.get(*cursor).ok_or(PackError::Truncated { context })?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(PackError::IntegerOverflow { context })?;
    Ok(byte)
}

fn decode_copy_instruction(
    instruction: u8,
    input: &[u8],
    cursor: &mut usize,
    deadline: &mut impl Deadline,
) -> Result<(usize, usize), PackError> {
    let mut offset = 0_usize;
    for (mask, shift) in [(0x01_u8, 0_u32), (0x02, 8), (0x04, 16), (0x08, 24)] {
        if instruction & mask != 0 {
            offset |= usize::from(read_byte(input, cursor, "delta copy offset", deadline)?)
                .checked_shl(shift)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta copy offset",
                })?;
        }
    }
    let mut length = 0_usize;
    for (mask, shift) in [(0x10_u8, 0_u32), (0x20, 8), (0x40, 16)] {
        if instruction & mask != 0 {
            length |= usize::from(read_byte(input, cursor, "delta copy length", deadline)?)
                .checked_shl(shift)
                .ok_or(PackError::IntegerOverflow {
                    context: "delta copy length",
                })?;
        }
    }
    if length == 0 {
        length = 0x1_0000;
    }
    Ok((offset, length))
}

fn append_insert(
    result: &mut Vec<u8>,
    declared_result: usize,
    input: &[u8],
    cursor: &mut usize,
    length: usize,
    accounting: &mut Accounting,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<(), PackError> {
    let end = cursor
        .checked_add(length)
        .ok_or(PackError::IntegerOverflow {
            context: "delta insert range",
        })?;
    let bytes = input.get(*cursor..end).ok_or(PackError::Truncated {
        context: "delta insert data",
    })?;
    append_copy(result, declared_result, bytes, accounting, limits, deadline)?;
    *cursor = end;
    Ok(())
}

fn append_copy(
    result: &mut Vec<u8>,
    declared_result: usize,
    bytes: &[u8],
    accounting: &mut Accounting,
    limits: &PackLimits,
    deadline: &mut impl Deadline,
) -> Result<(), PackError> {
    checkpoint(deadline)?;
    let resulting_len =
        result
            .len()
            .checked_add(bytes.len())
            .ok_or(PackError::IntegerOverflow {
                context: "delta result length",
            })?;
    if resulting_len > declared_result {
        return Err(PackError::DeltaResultSizeMismatch {
            declared: declared_result,
            actual: resulting_len,
        });
    }
    accounting.add_work(bytes.len(), limits)?;
    result.extend_from_slice(bytes);
    Ok(())
}

fn copy_bytes(input: &[u8], deadline: &mut impl Deadline) -> Result<Vec<u8>, PackError> {
    checkpoint(deadline)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: input.len(),
        })?;
    output.extend_from_slice(input);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryKind, ObjectFormat, PackLimits, object_id_from_bytes};

    fn unlimited() -> PackLimits {
        PackLimits {
            max_input_bytes: 200_000,
            max_entries: 100,
            max_object_bytes: 100_000,
            max_delta_depth: 8,
            max_delta_fanout: 8,
            max_total_expanded_bytes: 200_000,
            max_expansion_ratio: 100_000,
            max_delta_work: 200_000,
            max_inflate_work: 200_000,
            max_cached_bytes: 200_000,
            max_index_entries: 100,
        }
    }

    fn always() -> bool {
        true
    }

    #[test]
    fn applies_copy_and_insert_instructions() {
        let mut delta = vec![6, 7, 0x91, 0, 3, 4];
        delta.extend_from_slice(b"xyz!");
        assert_eq!(
            apply_delta(b"abcdef", &delta, &unlimited(), &mut always),
            Ok(b"abcxyz!".to_vec())
        );
    }

    #[test]
    fn applies_insert_of_127_bytes() {
        let inserted = vec![0x5a; 127];
        let mut delta = vec![0, 127, 127];
        delta.extend_from_slice(&inserted);
        assert_eq!(
            apply_delta(&[], &delta, &unlimited(), &mut always),
            Ok(inserted)
        );
    }

    #[test]
    fn copy_size_zero_means_65536() {
        let base = vec![0x34; 0x1_0000];
        let delta = [0x80, 0x80, 0x04, 0x80, 0x80, 0x04, 0x80];
        assert_eq!(
            apply_delta(&base, &delta, &unlimited(), &mut always),
            Ok(base)
        );
    }

    #[test]
    fn copy_and_insert_bounds_are_typed_refusals() {
        let out_of_range = [3, 1, 0x91, 3, 1];
        let invalid = [0, 0, 0];
        assert!(matches!(
            apply_delta(b"abc", &out_of_range, &unlimited(), &mut always),
            Err(PackError::DeltaCopyOutOfRange { .. })
        ));
        assert_eq!(
            apply_delta(&[], &invalid, &unlimited(), &mut always),
            Err(PackError::InvalidDeltaInstruction)
        );
    }

    #[test]
    fn expired_deadline_refuses_before_delta_allocation() {
        fn expired() -> bool {
            false
        }

        assert_eq!(
            apply_delta(b"a", &[1, 1, 0x91, 0, 1], &unlimited(), &mut expired),
            Err(PackError::DeadlineExceeded)
        );
    }

    #[test]
    fn scalar_resolves_ofs_and_thin_ref_deltas() {
        let external_id = object_id_from_bytes(ObjectFormat::Sha1, &[9; 20]).expect("test ID");
        let in_pack_id = object_id_from_bytes(ObjectFormat::Sha1, &[4; 20]).expect("test ID");
        let objects = [
            PackObject::Base {
                offset: 12,
                id: Some(in_pack_id),
                data: b"abc".to_vec(),
            },
            PackObject::Delta(DeltaObject {
                offset: 24,
                id: None,
                base: DeltaBase::Ofs(12),
                program: vec![3, 3, 0x91, 0, 3],
            }),
            PackObject::Delta(DeltaObject {
                offset: 36,
                id: None,
                base: DeltaBase::Ref(external_id),
                program: vec![3, 3, 0x91, 0, 3],
            }),
        ];
        let bases = SingleBase {
            id: external_id,
            bytes: b"xyz".to_vec(),
        };
        let limits = unlimited();
        let resolver =
            ScalarResolver::new(&objects, &bases, &limits, &mut always).expect("valid graph");
        assert_eq!(
            resolver.resolve_offset(24, &mut always),
            Ok(b"abc".to_vec())
        );
        assert_eq!(
            resolver.resolve_offset(36, &mut always),
            Ok(b"xyz".to_vec())
        );
    }

    #[test]
    fn depth_and_work_bombs_refuse_before_completion() {
        let objects = [
            PackObject::Base {
                offset: 1,
                id: None,
                data: b"a".to_vec(),
            },
            PackObject::Delta(DeltaObject {
                offset: 2,
                id: None,
                base: DeltaBase::Ofs(1),
                program: vec![1, 1, 0x91, 0, 1],
            }),
            PackObject::Delta(DeltaObject {
                offset: 3,
                id: None,
                base: DeltaBase::Ofs(2),
                program: vec![1, 1, 0x91, 0, 1],
            }),
        ];
        let mut shallow = unlimited();
        shallow.max_delta_depth = 1;
        let resolver =
            ScalarResolver::new(&objects, &(), &shallow, &mut always).expect("valid graph");
        assert!(matches!(
            resolver.resolve_offset(3, &mut always),
            Err(PackError::DeltaDepthLimit { .. })
        ));

        let mut tiny_work = unlimited();
        tiny_work.max_delta_work = 2;
        assert!(matches!(
            apply_delta(b"abc", &[3, 3, 0x91, 0, 3], &tiny_work, &mut always),
            Err(PackError::DeltaWorkLimit { .. })
        ));
    }

    #[test]
    fn size_and_fanout_bombs_refuse() {
        let delta = [10, 10, 0x91, 0, 10];
        let mut size_limited = unlimited();
        size_limited.max_object_bytes = 9;
        assert!(matches!(
            apply_delta(&[1; 10], &delta, &size_limited, &mut always),
            Err(PackError::ObjectSizeLimit { .. } | PackError::DeltaResultSizeLimit { .. })
        ));
        let fanout_objects = [
            PackObject::Base {
                offset: 1,
                id: None,
                data: b"a".to_vec(),
            },
            PackObject::Delta(DeltaObject {
                offset: 2,
                id: None,
                base: DeltaBase::Ofs(1),
                program: vec![1, 1, 0x91, 0, 1],
            }),
            PackObject::Delta(DeltaObject {
                offset: 3,
                id: None,
                base: DeltaBase::Ofs(1),
                program: vec![1, 1, 0x91, 0, 1],
            }),
        ];
        let mut fanout_limited = unlimited();
        fanout_limited.max_delta_fanout = 1;
        let resolver = ScalarResolver::new(&fanout_objects, &(), &fanout_limited, &mut always)
            .expect("input shape is valid");
        assert!(matches!(
            resolver.resolve_offset(2, &mut always),
            Err(PackError::DeltaFanoutLimit { .. })
        ));
    }

    #[test]
    fn cached_and_scalar_resolvers_agree_over_generated_delta_packs() {
        for seed in 1_u8..=64 {
            let length = usize::from(seed % 63 + 1);
            let base_a = (0..length)
                .map(|index| seed.wrapping_add(u8::try_from(index).expect("small fixture")))
                .collect::<Vec<_>>();
            let base_b = (0..=(length / 2))
                .map(|index| {
                    seed.wrapping_mul(3)
                        .wrapping_add(u8::try_from(index).expect("small fixture"))
                })
                .collect::<Vec<_>>();
            let mut a1 = base_a.clone();
            a1.push(seed ^ 0x55);
            let mut a2 = a1.clone();
            a2.push(seed ^ 0xaa);
            let mut b1 = base_b.clone();
            b1.push(seed.wrapping_add(1));
            let objects = [
                PackObject::Base {
                    offset: 12,
                    id: None,
                    data: base_a.clone(),
                },
                PackObject::Base {
                    offset: 24,
                    id: None,
                    data: base_b.clone(),
                },
                PackObject::Delta(DeltaObject {
                    offset: 36,
                    id: None,
                    base: DeltaBase::Ofs(12),
                    program: copy_then_insert(&base_a, seed ^ 0x55),
                }),
                PackObject::Delta(DeltaObject {
                    offset: 48,
                    id: None,
                    base: DeltaBase::Ofs(36),
                    program: copy_then_insert(&a1, seed ^ 0xaa),
                }),
                PackObject::Delta(DeltaObject {
                    offset: 60,
                    id: None,
                    base: DeltaBase::Ofs(24),
                    program: copy_then_insert(&base_b, seed.wrapping_add(1)),
                }),
            ];
            let limits = unlimited();
            let scalar = ScalarResolver::new(&objects, &(), &limits, &mut always)
                .expect("generated scalar graph");
            let mut cached = CachedResolver::new(&objects, &(), &limits, &mut always)
                .expect("generated cached graph");
            for (offset, expected) in [(12, base_a), (24, base_b), (36, a1), (48, a2), (60, b1)] {
                let scalar_result = scalar
                    .resolve_offset(offset, &mut always)
                    .expect("generated scalar graph resolves");
                assert_eq!(scalar_result, expected);
                assert_eq!(
                    cached.resolve_offset(offset, &mut always),
                    Ok(scalar_result),
                    "cached resolver diverged for seed {seed} offset {offset}"
                );
            }
        }
    }

    /// Two typed deltas share one base. Their unique inflated content is the
    /// base (three bytes) plus each delta's result (three bytes each) = nine
    /// bytes. Before frankengit-rpqx the shared base was re-charged on the
    /// second resolution's cache hit, so the same receive was accounted as
    /// twelve bytes and refused under an eleven-byte budget; counting each
    /// unique object once, both deltas now resolve.
    fn shared_base_typed_graph() -> [PackObject; 3] {
        [
            PackObject::TypedBase {
                offset: 12,
                id: None,
                kind: EntryKind::Blob,
                data: b"abc".to_vec(),
            },
            PackObject::Delta(DeltaObject {
                offset: 24,
                id: None,
                base: DeltaBase::Ofs(12),
                program: vec![3, 3, 0x91, 0, 3],
            }),
            PackObject::Delta(DeltaObject {
                offset: 36,
                id: None,
                base: DeltaBase::Ofs(12),
                program: vec![3, 3, 0x91, 0, 3],
            }),
        ]
    }

    #[test]
    fn caller_owned_budget_charges_a_shared_base_once_across_a_receive() {
        let objects = shared_base_typed_graph();
        let mut limits = unlimited();
        // Eleven bytes refused the second delta before rpqx (accounted 12 > 11).
        // With the shared base counted once the receive expands nine bytes.
        limits.max_total_expanded_bytes = 11;
        let mut resolver = CachedResolver::new(&objects, &(), &limits, &mut always)
            .expect("the compact typed delta graph is structurally valid");
        let mut budget = ResolutionBudget::new();

        assert_eq!(
            resolver.resolve_offset_typed_with_budget(24, &mut budget, &mut always),
            Ok((ObjectType::Blob, b"abc".to_vec()))
        );
        assert_eq!(
            resolver.resolve_offset_typed_with_budget(36, &mut budget, &mut always),
            Ok((ObjectType::Blob, b"abc".to_vec())),
            "the shared base is charged once, so nine unique bytes fit an eleven-byte budget"
        );
    }

    #[test]
    fn caller_owned_budget_still_refuses_when_unique_bytes_exceed_the_ceiling() {
        let objects = shared_base_typed_graph();
        let mut limits = unlimited();
        // The aggregate bomb defence survives count-once: a budget below the
        // pack's unique inflated size still refuses, and the reported total is
        // the unique size (nine), not the pre-rpqx double-counted twelve.
        limits.max_total_expanded_bytes = 8;
        let mut resolver = CachedResolver::new(&objects, &(), &limits, &mut always)
            .expect("the compact typed delta graph is structurally valid");
        let mut budget = ResolutionBudget::new();

        assert_eq!(
            resolver.resolve_offset_typed_with_budget(24, &mut budget, &mut always),
            Ok((ObjectType::Blob, b"abc".to_vec()))
        );
        assert!(matches!(
            resolver.resolve_offset_typed_with_budget(36, &mut budget, &mut always),
            Err(PackError::TotalExpandedLimit {
                actual: 9,
                limit: 8,
            })
        ));
    }

    #[test]
    fn caller_owned_budget_counts_a_delta_chain_once() {
        // A three-deep chain B <- d1 <- d2 is the shape Git produces for a file
        // edited across commits. Resolving d1 then d2 across one shared receive
        // budget charges each object's expansion once: B (3) + d1 (4) + d2 (5)
        // = twelve bytes. Before frankengit-rpqx, resolving d2 re-charged d1's
        // whole subtree (B + d1 = 7) on the cache hit, overflowing the same
        // twelve-byte budget -- the exact over-count that refused an ~85 MB
        // first push accounted as ~150 MB.
        let base = b"abc".to_vec();
        let d1_program = copy_then_insert(&base, 0x11);
        let mut d1_bytes = base.clone();
        d1_bytes.push(0x11);
        let d2_program = copy_then_insert(&d1_bytes, 0x22);
        let mut d2_bytes = d1_bytes.clone();
        d2_bytes.push(0x22);

        let objects = [
            PackObject::TypedBase {
                offset: 12,
                id: None,
                kind: EntryKind::Blob,
                data: base,
            },
            PackObject::Delta(DeltaObject {
                offset: 24,
                id: None,
                base: DeltaBase::Ofs(12),
                program: d1_program,
            }),
            PackObject::Delta(DeltaObject {
                offset: 36,
                id: None,
                base: DeltaBase::Ofs(24),
                program: d2_program,
            }),
        ];
        let mut limits = unlimited();
        limits.max_total_expanded_bytes = 12;
        let mut resolver = CachedResolver::new(&objects, &(), &limits, &mut always)
            .expect("the compact typed delta chain is structurally valid");
        let mut budget = ResolutionBudget::new();

        assert_eq!(
            resolver.resolve_offset_typed_with_budget(24, &mut budget, &mut always),
            Ok((ObjectType::Blob, d1_bytes))
        );
        assert_eq!(
            resolver.resolve_offset_typed_with_budget(36, &mut budget, &mut always),
            Ok((ObjectType::Blob, d2_bytes)),
            "the chain's shared prefix is charged once, so twelve unique bytes fit a twelve-byte budget"
        );
    }

    /// A Git delta program that copies all of a `base_len`-byte base and then
    /// inserts one byte: the shape of a file edited once per commit.
    fn copy_all_then_insert(base_len: usize, byte: u8) -> Vec<u8> {
        fn varint(mut value: usize, out: &mut Vec<u8>) {
            loop {
                let mut part = u8::try_from(value & 0x7f).expect("seven bits fit a byte");
                value >>= 7;
                if value != 0 {
                    part |= 0x80;
                }
                out.push(part);
                if value == 0 {
                    break;
                }
            }
        }
        let mut program = Vec::new();
        varint(base_len, &mut program);
        varint(base_len + 1, &mut program);
        let mut instruction = 0x80_u8;
        let mut sizes = Vec::new();
        for (flag, shift) in [(0x10_u8, 0), (0x20, 8), (0x40, 16)] {
            let part = u8::try_from((base_len >> shift) & 0xff).expect("masked byte fits");
            if part != 0 {
                instruction |= flag;
                sizes.push(part);
            }
        }
        program.push(instruction);
        program.extend(sizes);
        program.extend([1, byte]);
        program
    }

    /// A base and a `depth`-deep chain of deltas over it, each appending one
    /// byte: what `git repack --depth=50` produces for a long-lived file.
    fn edit_chain(base_len: usize, depth: usize) -> Vec<PackObject> {
        let mut objects = vec![PackObject::TypedBase {
            offset: 100,
            id: None,
            kind: EntryKind::Blob,
            data: (0..base_len).map(|n| b"abcdefgh"[n % 8]).collect(),
        }];
        for step in 1..=depth {
            objects.push(PackObject::Delta(DeltaObject {
                offset: 100 + 100 * u64::try_from(step).expect("small depth"),
                id: None,
                base: DeltaBase::Ofs(100 * u64::try_from(step).expect("small depth")),
                program: copy_all_then_insert(
                    base_len + step - 1,
                    u8::try_from(step % 250).expect("fits"),
                ),
            }));
        }
        objects
    }

    /// Resolves every chain member, deepest first (as an idx-ordered walk may),
    /// through ONE operation-wide budget, and returns the work it charged.
    fn resolve_chain(objects: &[PackObject], limits: &PackLimits) -> Result<usize, PackError> {
        let mut resolver = CachedResolver::new(objects, &(), limits, &mut always)?;
        let mut budget = ResolutionBudget::new();
        for object in objects.iter().rev() {
            resolver.resolve_offset_typed_with_budget(object.offset(), &mut budget, &mut always)?;
        }
        Ok(budget.accounting.work)
    }

    #[test]
    fn an_ordinary_edit_chain_fits_the_default_work_budget_and_a_cacheless_replay_does_not() {
        // 50 revisions of a 240 KB file at Git's default depth (frankengit-z6rb).
        let (base_len, depth) = (240_000, 50);
        let objects = edit_chain(base_len, depth);
        let defaults = PackLimits::default();
        // The regime the old model refused: re-charging each cached base's whole
        // chain on every hit summed depth x size over the chain.
        let cumulative: usize = (1..=depth).map(|d| d * (base_len + d)).sum();
        assert!(cumulative > defaults.max_delta_work, "{cumulative}");

        let charged = resolve_chain(&objects, &defaults)
            .expect("the ordinary history resolves under the default limits");
        // Real work: every reconstructed byte plus every byte copied from the
        // cache, a small multiple of the unique expanded bytes.
        let unique: usize = (0..=depth).map(|d| base_len + d).sum();
        assert!(
            charged <= 4 * unique,
            "charged {charged} for {unique} unique bytes"
        );
        assert!(charged < defaults.max_delta_work);
        assert_eq!(
            resolve_chain(&objects, &defaults),
            Ok(charged),
            "the same pack and limits always charge the same work"
        );

        // Planted twin: no cache, so every object really re-runs its chain. That
        // work IS quadratic, and it is refused: under the defaults the
        // re-expanded bytes trip the expansion bound first ...
        let mut cacheless = defaults;
        cacheless.max_cached_bytes = 0;
        let replay = resolve_chain(&objects, &cacheless);
        assert!(
            matches!(
                replay,
                Err(PackError::TotalExpandedLimit { .. } | PackError::DeltaWorkLimit { .. })
            ),
            "{replay:?}"
        );
        // ... and with that bound lifted, the work bound refuses it by itself.
        cacheless.max_total_expanded_bytes = 1 << 30;
        let replay = resolve_chain(&objects, &cacheless);
        assert!(
            matches!(replay, Err(PackError::DeltaWorkLimit { .. })),
            "{replay:?}"
        );
    }

    /// One 64 KiB base and `fanout` deltas that each keep a single byte of it.
    fn hot_base(fanout: usize) -> Vec<PackObject> {
        let base_len = 64 * 1024;
        let mut objects = vec![PackObject::TypedBase {
            offset: 100,
            id: None,
            kind: EntryKind::Blob,
            data: vec![b'z'; base_len],
        }];
        for step in 1..=fanout {
            let mut program = Vec::new();
            let mut size = base_len;
            while size >= 0x80 {
                program.push(u8::try_from(size & 0x7f).expect("seven bits") | 0x80);
                size >>= 7;
            }
            program.push(u8::try_from(size).expect("final seven bits"));
            program.extend([1, 1, u8::try_from(step).expect("small fanout")]);
            objects.push(PackObject::Delta(DeltaObject {
                offset: 100 + 100 * u64::try_from(step).expect("small fanout"),
                id: None,
                base: DeltaBase::Ofs(100),
                program,
            }));
        }
        objects
    }

    #[test]
    fn every_copy_of_a_cached_base_is_charged_so_a_hot_base_cannot_amplify_work() {
        // Each delta keeps one byte, but resolving it copies the whole cached
        // base. Before frankengit-z6rb a hit on a base charged that base's
        // reconstruction work, which is zero, so this amplification was free.
        let mut limits = unlimited();
        limits.max_delta_fanout = 64;
        limits.max_delta_work = 1 << 20;
        let resolve_all = |objects: &[PackObject]| {
            let mut resolver = CachedResolver::new(objects, &(), &limits, &mut always)?;
            let mut budget = ResolutionBudget::new();
            for object in objects {
                resolver.resolve_offset_typed_with_budget(
                    object.offset(),
                    &mut budget,
                    &mut always,
                )?;
            }
            Ok::<_, PackError>(budget.accounting.work)
        };
        // Eight deltas: eight 64 KiB copies fit the 1 MiB work budget, and
        // every one of them is charged.
        let charged = resolve_all(&hot_base(8)).expect("eight copies fit");
        assert!(charged >= 8 * 64 * 1024, "charged {charged}");
        // Thirty-two would copy 2 MiB for 32 bytes of output: refused.
        let amplified = resolve_all(&hot_base(32));
        assert!(
            matches!(amplified, Err(PackError::DeltaWorkLimit { .. })),
            "{amplified:?}"
        );
    }

    /// The pre-index lookups, kept as the reference: a full scan that refuses
    /// a second match (frankengit-eq4h).
    fn scan_by_offset(
        objects: &[PackObject],
        offset: u64,
    ) -> Result<Option<&PackObject>, PackError> {
        let mut found = None;
        for object in objects {
            if object.offset() == offset {
                if found.is_some() {
                    return Err(PackError::DuplicateObjectOffset(offset));
                }
                found = Some(object);
            }
        }
        Ok(found)
    }

    fn scan_by_id<'a>(
        objects: &'a [PackObject],
        id: &ObjectId,
    ) -> Result<Option<&'a PackObject>, PackError> {
        let mut found = None;
        for object in objects {
            if object.id() == Some(id) {
                if found.is_some() {
                    return Err(PackError::DuplicateObjectId);
                }
                found = Some(object);
            }
        }
        Ok(found)
    }

    fn scan_fanout(
        objects: &[PackObject],
        base: &DeltaBase,
        limit: usize,
    ) -> Result<(), PackError> {
        let mut fanout = 0;
        for object in objects {
            if matches!(object, PackObject::Delta(delta) if &delta.base == base) {
                fanout += 1;
                if fanout > limit {
                    return Err(PackError::DeltaFanoutLimit { fanout, limit });
                }
            }
        }
        Ok(())
    }

    fn same_object(
        left: Result<Option<&PackObject>, PackError>,
        right: Result<Option<&PackObject>, PackError>,
    ) -> bool {
        match (left, right) {
            (Ok(Some(left)), Ok(Some(right))) => std::ptr::eq(left, right),
            (left, right) => left == right,
        }
    }

    #[test]
    fn indexed_lookups_answer_exactly_what_a_linear_scan_answers() {
        // Generated slices over few offsets and ids, so duplicate offsets,
        // duplicate ids, absent keys and fanout collisions all occur.
        let ids: Vec<ObjectId> = (1..=6_u8)
            .map(|byte| object_id_from_bytes(ObjectFormat::Sha1, &[byte; 20]).expect("20-byte id"))
            .collect();
        let mut state = 0x9e37_79b9_u64;
        let mut next = |bound: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % bound
        };
        let mut limits = unlimited();
        limits.max_delta_fanout = 2;
        for _ in 0..200 {
            let count = 1 + next(24);
            let objects: Vec<PackObject> = (0..count)
                .map(|_| {
                    let offset = next(16);
                    let id = (next(3) != 0).then(|| ids[usize::try_from(next(6)).expect("small")]);
                    if next(2) == 0 {
                        PackObject::Base {
                            offset,
                            id,
                            data: b"x".to_vec(),
                        }
                    } else {
                        let base = if next(2) == 0 {
                            DeltaBase::Ofs(next(16))
                        } else {
                            DeltaBase::Ref(ids[usize::try_from(next(6)).expect("small")])
                        };
                        PackObject::Delta(DeltaObject {
                            offset,
                            id,
                            base,
                            program: vec![1, 1, 0x91, 0, 1],
                        })
                    }
                })
                .collect();
            let resolver =
                ScalarResolver::new(&objects, &(), &limits, &mut always).expect("bounded slice");
            let mut accounting = Accounting::default();
            for offset in 0..17 {
                assert!(
                    same_object(
                        resolver.find_by_offset(offset, &mut accounting, &mut always),
                        scan_by_offset(&objects, offset),
                    ),
                    "offset {offset} in {objects:?}"
                );
                let base = DeltaBase::Ofs(offset);
                assert_eq!(
                    resolver.validate_fanout(&base, &mut accounting, &mut always),
                    scan_fanout(&objects, &base, limits.max_delta_fanout),
                    "{base:?} in {objects:?}"
                );
            }
            for id in &ids {
                assert!(
                    same_object(
                        resolver.find_by_id(id, &mut accounting, &mut always),
                        scan_by_id(&objects, id),
                    ),
                    "{id:?} in {objects:?}"
                );
                let base = DeltaBase::Ref(*id);
                assert_eq!(
                    resolver.validate_fanout(&base, &mut accounting, &mut always),
                    scan_fanout(&objects, &base, limits.max_delta_fanout),
                    "{base:?} in {objects:?}"
                );
            }
        }
    }

    #[test]
    fn resolving_every_object_of_a_large_pack_charges_n_log_n_not_n_squared() {
        // 25,000 typed bases and a one-byte-edit delta over each, resolved in
        // pack order through ONE budget, as fg import and the receive
        // validator do. A scan per lookup charged 50,000 per probe: about
        // 3.75e9 for this pack against the 256 MiB default, and fg import
        // refused an ordinary 18,092-object pack (frankengit-eq4h).
        let half = 25_000_u64;
        let mut objects = Vec::new();
        for n in 0..half {
            objects.push(PackObject::TypedBase {
                offset: 100 + 2 * n,
                id: None,
                kind: EntryKind::Blob,
                data: n.to_le_bytes().to_vec(),
            });
            objects.push(PackObject::Delta(DeltaObject {
                offset: 101 + 2 * n,
                id: None,
                base: DeltaBase::Ofs(100 + 2 * n),
                program: copy_all_then_insert(8, 0x2a),
            }));
        }
        let limits = PackLimits::default();
        let mut resolver =
            CachedResolver::new(&objects, &(), &limits, &mut always).expect("bounded pack");
        let mut budget = ResolutionBudget::new();
        for object in &objects {
            resolver
                .resolve_offset_typed_with_budget(object.offset(), &mut budget, &mut always)
                .expect("every object of an ordinary large pack resolves under the defaults");
        }
        let n = objects.len();
        let log_n = usize::try_from(n.bit_width()).expect("bit count fits");
        assert!(
            budget.accounting.work < 10 * n * log_n,
            "charged {} for {n} objects",
            budget.accounting.work
        );
        assert_eq!(
            resolver.resolve_offset_typed(101, &mut always),
            Ok((ObjectType::Blob, [0_u8, 0, 0, 0, 0, 0, 0, 0, 0x2a].to_vec()))
        );
        // fg import walks in idx (object id) order, which scatters offsets:
        // the same pack in a scrambled order resolves within the same bound.
        let mut resolver =
            CachedResolver::new(&objects, &(), &limits, &mut always).expect("bounded pack");
        let mut budget = ResolutionBudget::new();
        for step in 0..n {
            let object = &objects[(step * 7_919) % n];
            resolver
                .resolve_offset_typed_with_budget(object.offset(), &mut budget, &mut always)
                .expect("a scrambled walk resolves under the defaults");
        }
        assert!(
            budget.accounting.work < 10 * n * log_n,
            "charged {} for {n} objects in scrambled order",
            budget.accounting.work
        );
    }

    #[test]
    fn a_refusal_inside_a_typed_chain_is_returned_not_a_stack_panic() {
        // base <- middle <- top. A bad middle delta must surface its typed
        // error from both resolvers; before the fix an early `?` left the
        // middle offset on the stack and the top frame's pop assertion fired.
        let chain = |middle: Vec<u8>| {
            vec![
                PackObject::TypedBase {
                    offset: 12,
                    id: None,
                    kind: EntryKind::Blob,
                    data: b"abc".to_vec(),
                },
                PackObject::Delta(DeltaObject {
                    offset: 24,
                    id: None,
                    base: DeltaBase::Ofs(12),
                    program: middle,
                }),
                PackObject::Delta(DeltaObject {
                    offset: 36,
                    id: None,
                    base: DeltaBase::Ofs(24),
                    program: vec![3, 3, 0x91, 0, 3],
                }),
            ]
        };
        let limits = unlimited();
        // The middle delta declares a four-byte base for a three-byte one.
        let bad = chain(vec![4, 3, 0x91, 0, 3]);
        let expected = Err(PackError::DeltaBaseSizeMismatch {
            declared: 4,
            actual: 3,
        });
        let scalar = ScalarResolver::new(&bad, &(), &limits, &mut always).expect("valid graph");
        assert_eq!(scalar.resolve_offset_typed(36, &mut always), expected);
        let mut cached = CachedResolver::new(&bad, &(), &limits, &mut always).expect("valid graph");
        assert_eq!(cached.resolve_offset_typed(36, &mut always), expected);
        // Twin: the well-formed middle delta resolves through both.
        let good = chain(vec![3, 3, 0x91, 0, 3]);
        let expected = Ok((ObjectType::Blob, b"abc".to_vec()));
        let scalar = ScalarResolver::new(&good, &(), &limits, &mut always).expect("valid graph");
        assert_eq!(scalar.resolve_offset_typed(36, &mut always), expected);
        let mut cached =
            CachedResolver::new(&good, &(), &limits, &mut always).expect("valid graph");
        assert_eq!(cached.resolve_offset_typed(36, &mut always), expected);
    }

    fn copy_then_insert(base: &[u8], byte: u8) -> Vec<u8> {
        let base_length = u8::try_from(base.len()).expect("generated base stays compact");
        let result_length = base_length
            .checked_add(1)
            .expect("generated result stays compact");
        vec![base_length, result_length, 0x91, 0, base_length, 1, byte]
    }

    struct SingleBase {
        id: ObjectId,
        bytes: Vec<u8>,
    }

    impl ExternalBaseLookup for SingleBase {
        fn lookup(&self, id: &ObjectId) -> Option<&[u8]> {
            (id == &self.id).then_some(&self.bytes)
        }
    }
}
