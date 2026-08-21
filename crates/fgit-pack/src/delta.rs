use crate::{Deadline, ObjectId, PackError, PackLimits, checkpoint};

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
    Base {
        offset: u64,
        id: Option<ObjectId>,
        data: Vec<u8>,
    },
    Delta(DeltaObject),
}

impl PackObject {
    fn offset(&self) -> u64 {
        match self {
            Self::Base { offset, .. } | Self::Delta(DeltaObject { offset, .. }) => *offset,
        }
    }

    fn id(&self) -> Option<&ObjectId> {
        match self {
            Self::Base { id, .. } | Self::Delta(DeltaObject { id, .. }) => id.as_ref(),
        }
    }
}

/// Caller-owned thin-pack base source. The lookup returns borrowed data, so a
/// pack resolver never asks an untrusted lookup to allocate before its limits
/// are checked.
pub trait ExternalBaseLookup {
    fn lookup(&self, id: &ObjectId) -> Option<&[u8]>;
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
                PackObject::Base { data, .. } => limits.object_size(data.len())?,
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

    /// Resolves a known native ID. This supports a REF_DELTA root without
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
            PackObject::Base { data, .. } => {
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
    limits.checked_ratio(declared_result, delta.len())?;
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
        let delta = [0x80, 0x80, 0x04, 0x80];
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
                base: DeltaBase::Ref(external_id.clone()),
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
    fn size_ratio_and_fanout_bombs_refuse() {
        let delta = [10, 10, 0x91, 0, 10];
        let mut size_limited = unlimited();
        size_limited.max_object_bytes = 9;
        assert!(matches!(
            apply_delta(&[1; 10], &delta, &size_limited, &mut always),
            Err(PackError::ObjectSizeLimit { .. } | PackError::DeltaResultSizeLimit { .. })
        ));
        let mut ratio_limited = unlimited();
        ratio_limited.max_expansion_ratio = 1;
        assert!(matches!(
            apply_delta(&[1; 10], &delta, &ratio_limited, &mut always),
            Err(PackError::ExpansionRatioLimit { .. })
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
