use fgit_git_object::ObjectType;

use crate::{
    Deadline, EntryKind, ObjectId, PackError, PackLimits, checkpoint, object_type_from_base_entry,
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

/// A scalar resolver input. It deliberately uses a linear scan rather than an
/// unbounded cache, providing the reference semantics that an optimized path
/// must later prove equivalent to.
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
pub struct ScalarResolver<'objects, 'lookup, L> {
    objects: &'objects [PackObject],
    external_bases: &'lookup L,
    limits: &'objects PackLimits,
}

impl<'objects, 'lookup, L> ScalarResolver<'objects, 'lookup, L>
where
    L: ExternalBaseLookup,
{
    /// Validates bounded input shape before it is used to surface any object.
    /// Ambiguous base identities and fanout are checked on the selected chain,
    /// where their scan work is charged to `max_delta_work`.
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
        for object in objects {
            checkpoint(deadline)?;
            match object {
                PackObject::Base { data, .. } | PackObject::TypedBase { data, .. } => {
                    limits.object_size(data.len())?;
                }
                PackObject::Delta(delta) => limits.input(delta.program.len())?,
            }
        }
        Ok(Self {
            objects,
            external_bases,
            limits,
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
                let result = match base_result {
                    Ok(base) => {
                        let object_type = base.object_type;
                        let bytes = apply_delta_with_accounting(
                            &base.bytes,
                            &delta.program,
                            self.limits,
                            accounting,
                            deadline,
                        )?;
                        accounting.add_expanded(bytes.len(), self.limits)?;
                        Ok(TypedResolution { object_type, bytes })
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
    ) -> Result<Option<&PackObject>, PackError> {
        let mut found = None;
        for object in self.objects {
            checkpoint(deadline)?;
            accounting.add_work(1, self.limits)?;
            if object.offset() == offset {
                if found.is_some() {
                    return Err(PackError::DuplicateObjectOffset(offset));
                }
                found = Some(object);
            }
        }
        Ok(found)
    }

    fn find_by_id(
        &self,
        id: &ObjectId,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<Option<&PackObject>, PackError> {
        let mut found = None;
        for object in self.objects {
            checkpoint(deadline)?;
            accounting.add_work(1, self.limits)?;
            if object.id().is_some_and(|candidate| candidate == id) {
                if found.is_some() {
                    return Err(PackError::DuplicateObjectId);
                }
                found = Some(object);
            }
        }
        Ok(found)
    }

    fn validate_fanout(
        &self,
        base: &DeltaBase,
        accounting: &mut Accounting,
        deadline: &mut impl Deadline,
    ) -> Result<(), PackError> {
        let mut fanout = 0_usize;
        for candidate in self.objects {
            checkpoint(deadline)?;
            accounting.add_work(1, self.limits)?;
            if has_same_delta_base(candidate, base) {
                fanout = fanout.checked_add(1).ok_or(PackError::IntegerOverflow {
                    context: "delta fanout",
                })?;
                if fanout > self.limits.max_delta_fanout {
                    return Err(PackError::DeltaFanoutLimit {
                        fanout,
                        limit: self.limits.max_delta_fanout,
                    });
                }
            }
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
/// It preserves the scalar resolver's logical expansion/work charging, so a
/// cache hit cannot turn a resource refusal into success; it only avoids
/// recomputing already-proven delta bytes.
pub struct CachedResolver<'objects, 'lookup, L> {
    scalar: ScalarResolver<'objects, 'lookup, L>,
    entries: Vec<CacheEntry>,
    cached_bytes: usize,
}

struct CacheEntry {
    offset: u64,
    bytes: Vec<u8>,
    object_type: Option<ObjectType>,
    logical_expanded: usize,
    logical_work: usize,
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
            entries: Vec::new(),
            cached_bytes: 0,
        })
    }

    /// Resolves one offset with base-result caching while preserving scalar
    /// output and budget semantics.
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
        let mut accounting = Accounting::default();
        let object = self
            .scalar
            .find_by_offset(offset, &mut accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let object = clone_pack_object(object, deadline)?;
        let mut stack = Vec::new();
        let resolved =
            self.resolve_object_typed(&object, 0, &mut stack, &mut accounting, deadline)?;
        Ok((resolved.object_type, resolved.bytes))
    }

    /// Resolves one native ID with the type inherited from its authenticated
    /// base root.
    pub fn resolve_id_typed(
        &mut self,
        id: &ObjectId,
        deadline: &mut impl Deadline,
    ) -> Result<(ObjectType, Vec<u8>), PackError> {
        let mut accounting = Accounting::default();
        let object = self
            .scalar
            .find_by_id(id, &mut accounting, deadline)?
            .ok_or(PackError::MissingDeltaBase)?;
        let object = clone_pack_object(object, deadline)?;
        let mut stack = Vec::new();
        let resolved =
            self.resolve_object_typed(&object, 0, &mut stack, &mut accounting, deadline)?;
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
            accounting.add_expanded(cached.logical_expanded, self.scalar.limits)?;
            accounting.add_work(cached.logical_work, self.scalar.limits)?;
            return copy_bytes(&cached.bytes, deadline);
        }
        let expanded_before = accounting.expanded;
        let work_before = accounting.work;
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
        let logical_expanded =
            accounting
                .expanded
                .checked_sub(expanded_before)
                .ok_or(PackError::IntegerOverflow {
                    context: "cached delta expanded accounting",
                })?;
        let logical_work =
            accounting
                .work
                .checked_sub(work_before)
                .ok_or(PackError::IntegerOverflow {
                    context: "cached delta work accounting",
                })?;
        self.cache(
            object.offset(),
            &result,
            None,
            logical_expanded,
            logical_work,
            deadline,
        )?;
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
            accounting.add_expanded(cached.logical_expanded, self.scalar.limits)?;
            accounting.add_work(cached.logical_work, self.scalar.limits)?;
            return Ok(TypedResolution {
                object_type,
                bytes: copy_bytes(&cached.bytes, deadline)?,
            });
        }
        let expanded_before = accounting.expanded;
        let work_before = accounting.work;
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
                let resolved = match base {
                    Ok(base) => {
                        let object_type = base.object_type;
                        let bytes = apply_delta_with_accounting(
                            &base.bytes,
                            &delta.program,
                            self.scalar.limits,
                            accounting,
                            deadline,
                        )?;
                        accounting.add_expanded(bytes.len(), self.scalar.limits)?;
                        Ok(TypedResolution { object_type, bytes })
                    }
                    Err(error) => Err(error),
                };
                let popped = stack.pop();
                debug_assert_eq!(popped, Some(delta.offset));
                resolved?
            }
        };
        let logical_expanded =
            accounting
                .expanded
                .checked_sub(expanded_before)
                .ok_or(PackError::IntegerOverflow {
                    context: "cached typed delta expanded accounting",
                })?;
        let logical_work =
            accounting
                .work
                .checked_sub(work_before)
                .ok_or(PackError::IntegerOverflow {
                    context: "cached typed delta work accounting",
                })?;
        self.cache(
            object.offset(),
            &resolved.bytes,
            Some(resolved.object_type),
            logical_expanded,
            logical_work,
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
        self.entries
            .binary_search_by_key(&offset, |entry| entry.offset)
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    fn cache(
        &mut self,
        offset: u64,
        bytes: &[u8],
        object_type: Option<ObjectType>,
        logical_expanded: usize,
        logical_work: usize,
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
        let insertion = match self
            .entries
            .binary_search_by_key(&offset, |entry| entry.offset)
        {
            Ok(index) => {
                if self.entries[index].object_type.is_none() {
                    self.entries[index].object_type = object_type;
                }
                return Ok(());
            }
            Err(index) => index,
        };
        self.entries
            .try_reserve(1)
            .map_err(|_| PackError::AllocationFailed { requested: 1 })?;
        let copy = copy_bytes(bytes, deadline)?;
        self.entries.insert(
            insertion,
            CacheEntry {
                offset,
                bytes: copy,
                object_type,
                logical_expanded,
                logical_work,
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

fn has_same_delta_base(candidate: &PackObject, base: &DeltaBase) -> bool {
    let PackObject::Delta(delta) = candidate else {
        return false;
    };
    &delta.base == base
}

#[derive(Default)]
struct Accounting {
    expanded: usize,
    work: usize,
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
    let mut accounting = Accounting::default();
    accounting.add_expanded(base.len(), limits)?;
    let result = apply_delta_with_accounting(base, delta, limits, &mut accounting, deadline)?;
    accounting.add_expanded(result.len(), limits)?;
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
        let component = usize::from(byte & 0x7f)
            .checked_shl(shift)
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
    use crate::{ObjectFormat, PackLimits, object_id_from_bytes};

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
