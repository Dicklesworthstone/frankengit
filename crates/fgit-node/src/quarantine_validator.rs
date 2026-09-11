//! Production validation from a receive quarantine into immutable object fabric.
//!
//! A [`ProductionQuarantineValidator`] does not treat the local object fabric
//! as authority.  Its only external delta bases are members of an
//! [`AuthoritySelectedClosure`], which was reconstructed from one authenticated
//! authority basis.  Newly verified objects are staged first, then returned as
//! the exact closure witness for admission; staging itself never publishes a
//! ref.

mod typed_closure;
mod reused_targets;

use std::collections::{BTreeMap, BTreeSet};

use fgit_admission::{
    AdmissionError, BasisBoundValidatedReceive, PermittedObjectClosure, QuarantineValidator,
    ValidatedClosure, permitted_object_closure_root, validate_receive_at_basis,
};
use fgit_chronicle::PublicationBasis;
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject};
use fgit_pack::{
    CachedResolver, Deadline, ExternalBaseLookup, ObjectId, PackError, PackLimits, PackObject,
    ParsedDeltaBase, QuarantinedPack, ResolutionBudget, verify_native_object,
};
use fgit_types::{GitOid, RefusalCode};
#[cfg(test)]
use fgit_types::GitHashAlgorithm;
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveError, ReceiveQuarantineHandoff, ReceiveRequest,
};

use crate::{
    AuthoritySelectedClosure, MaterializedAdmission, NodeReceiveTransportRefusal, NodeRefusal,
    OneNode, crypto_object_kind,
};

/// Preserves the receive core's single refusal vocabulary when an asynchronous
/// node transport reports a failed handoff.
///
/// The conversion contains the complete [`ReceiveError`] rather than selecting
/// a lossy node-local category.  Consequently new receive refusal arms remain
/// exact until the transport chooses to expose a distinct additional surface.
impl From<ReceiveError> for NodeReceiveTransportRefusal {
    fn from(error: ReceiveError) -> Self {
        Self::Admission(Box::new(AdmissionError::from(error)))
    }
}

/// Synchronous production handoff from structural pack quarantine to one
/// validated receive.
///
/// This object owns only the deterministic verification half of receive-pack.
/// It runs while the quarantine and its transport deadline are still live,
/// stores no raw pack bytes, and retains the private `ValidatedReceive` proof
/// for the node's asynchronous durable-admission surface to consume later.
#[derive(Debug)]
pub struct ProductionReceiveQuarantineHandoff<'node> {
    validator: ProductionQuarantineValidator<'node>,
    validation_basis: PublicationBasis,
    validated: Option<BasisBoundValidatedReceive>,
}

impl<'node> ProductionReceiveQuarantineHandoff<'node> {
    /// Binds this one handoff to the validator reconstructed from one
    /// authenticated materialization.
    #[must_use]
    pub(crate) const fn new(
        validator: ProductionQuarantineValidator<'node>,
        validation_basis: PublicationBasis,
    ) -> Self {
        Self {
            validator,
            validation_basis,
            validated: None,
        }
    }

    /// Transfers the one validated proof to the asynchronous durable-admission
    /// phase after the synchronous handoff completed.
    ///
    /// A successful implementation of [`ReceiveQuarantineHandoff`] must have
    /// retained this proof.  Preserve a typed core refusal instead of exposing
    /// an unchecked optional value at the sync-to-async boundary.
    pub(crate) fn into_validated_receive(self) -> Result<BasisBoundValidatedReceive, ReceiveError> {
        self.validated.ok_or(ReceiveError::HandoffProofMissing)
    }

    fn validate(
        &mut self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut impl Deadline,
    ) -> Result<(), ReceiveError> {
        if self.validated.is_some() {
            return Err(ReceiveError::TerminalState {
                state: fgit_wire::receive::ReceivePhase::Complete,
            });
        }
        let validated = validate_receive_at_basis(
            request,
            pack,
            receipt,
            &self.validation_basis,
            &self.validator,
            deadline,
        )
        .map_err(ReceiveError::AuthoritativeRefusal)?;
        self.validated = Some(validated);
        Ok(())
    }
}

impl ReceiveQuarantineHandoff for ProductionReceiveQuarantineHandoff<'_> {
    fn handoff(
        &mut self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        // This legacy structural method has no cancellation owner. The raw
        // receive path uses handoff_with_deadline below; direct deterministic
        // verification remains bounded by the validator's resource limits.
        let mut continuing = || true;
        self.validate(request, pack, receipt, &mut continuing)
    }

    fn handoff_with_deadline(
        &mut self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut dyn Deadline,
    ) -> Result<(), ReceiveError> {
        let mut forwarded = ForwardedDeadline { deadline };
        self.validate(request, pack, receipt, &mut forwarded)
    }
}

/// Sized adapter for the generic admission and pack APIs while preserving the
/// transport-owned dynamic deadline identity.
struct ForwardedDeadline<'deadline> {
    deadline: &'deadline mut dyn Deadline,
}

impl Deadline for ForwardedDeadline<'_> {
    fn checkpoint(&mut self) -> bool {
        self.deadline.checkpoint()
    }
}

/// Pack/object-fabric validator bound to an authenticated object closure.
///
/// The caller obtains `selected_closure` from
/// [`crate::MaterializedAdmission::selected_closure`], rather than constructing
/// a mutable local reachability hint.  This prevents a thin delta from using a
/// merely-present (and potentially unauthorized) fabric object as its base.
#[derive(Debug)]
pub struct ProductionQuarantineValidator<'node> {
    node: &'node OneNode,
    selected_closure: AuthoritySelectedClosure,
    // Only canonical visible refs seed reuse of roots omitted from the pack.
    visible_roots: BTreeSet<GitOid>,
    pack_limits: PackLimits,
    parse_limits: ParseLimits,
}

/// One native object verified from the transaction-local pack before the
/// reachability walk decides whether it belongs in the admitted closure.
#[derive(Debug)]
struct VerifiedObject {
    object_type: ObjectType,
    body: Vec<u8>,
    parsed: ParsedObject,
}

type VerifiedPackObjects = (BTreeMap<GitOid, VerifiedObject>, BTreeMap<u64, GitOid>);

impl<'node> ProductionQuarantineValidator<'node> {
    /// Binds pack validation to one exact authority-selected object closure.
    #[must_use]
    pub(crate) const fn new(
        node: &'node OneNode,
        selected_closure: AuthoritySelectedClosure,
        pack_limits: PackLimits,
        parse_limits: ParseLimits,
    ) -> Self {
        Self {
            node,
            selected_closure,
            visible_roots: BTreeSet::new(),
            pack_limits,
            parse_limits,
        }
    }

    fn empty_closure() -> Result<ValidatedClosure, RefusalCode> {
        let objects = BTreeSet::new();
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))?,
            objects,
        })
    }

    /// Loads an authority-selected external base when one is actually named by
    /// the selected closure.
    ///
    /// A `REF_DELTA` name is not, by itself, evidence that its base is external:
    /// a later bounded pack-local identity pass may prove that the same name
    /// belongs to an uploaded entry.  Returning `None` for an unselected name
    /// lets that pass establish the pack-local edge without consulting merely
    /// present fabric state.  A name that remains unresolved after the bounded
    /// pass is refused as a thin base.
    fn load_selected_external_base(
        &self,
        id: ObjectId,
        remaining_bytes: usize,
        deadline: &mut impl Deadline,
    ) -> Result<Option<ExternalBase>, RefusalCode> {
        checkpoint(deadline)?;
        if !self.selected_closure.closure().objects().contains(&id) {
            return Ok(None);
        }

        let read = self.node.read_git_object(id);
        checkpoint(deadline)?;
        let verified = read.map_err(|error| match error {
            NodeRefusal::Fabric(failure)
                if matches!(
                    failure.as_ref(),
                    fgit_object_fabric::fabric::StoreRefusal::ObjectAbsent
                ) =>
            {
                // The authenticated basis selected this object, so a missing
                // placement is evidence loss, not permission to fall back to
                // another local source.
                RefusalCode::EvidenceMissing
            }
            _ => RefusalCode::EvidenceInvalid,
        })?;
        // The fabric owns its bounded read allocation. Refuse before making
        // an additional quarantine copy or accumulating another base body.
        if verified.payload().len() > remaining_bytes
            || verified.payload().len() > self.pack_limits.max_object_bytes
            || verified.payload().len() > self.parse_limits.max_object_bytes
        {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        let object_type = match verified.envelope().object_kind() {
            fgit_object_fabric::ObjectKind::Commit => ObjectType::Commit,
            fgit_object_fabric::ObjectKind::Tree => ObjectType::Tree,
            fgit_object_fabric::ObjectKind::Blob => ObjectType::Blob,
            fgit_object_fabric::ObjectKind::Tag => ObjectType::Tag,
            fgit_object_fabric::ObjectKind::Internal => return Err(RefusalCode::EvidenceInvalid),
        };
        let body = copy_bytes(verified.payload(), deadline)?;
        verify_native_object(
            self.node.object_format,
            object_type,
            &body,
            &id,
            AcceptanceProfile::GitCompatibleImport,
            &self.parse_limits,
        )
        .map_err(map_pack_error)?;
        Ok(Some(ExternalBase { object_type, body }))
    }

    fn external_bases(
        &self,
        pack: &QuarantinedPack,
        deadline: &mut impl Deadline,
    ) -> Result<ExternalBases, RefusalCode> {
        let mut bases = BTreeMap::new();
        let mut read_bytes = 0usize;
        let limit = self.external_read_limit();
        for entry in pack.entries() {
            checkpoint(deadline)?;
            let Some(ParsedDeltaBase::Ref { base, .. }) = &entry.delta_base else {
                continue;
            };
            if bases.contains_key(base) {
                continue;
            }
            let remaining = limit.checked_sub(read_bytes)
                .ok_or(RefusalCode::ResourceBudgetExceeded)?;
            if let Some(loaded) = self.load_selected_external_base(*base, remaining, deadline)? {
                read_bytes = read_bytes.checked_add(loaded.body.len())
                    .filter(|bytes| *bytes <= limit)
                    .ok_or(RefusalCode::ResourceBudgetExceeded)?;
                bases.insert(*base, loaded);
            }
        }
        Ok(ExternalBases { bases, read_bytes })
    }

    /// Original bodies are an independent, finite input to reconstruction.
    /// A tiny thin pack cannot allocate an unbounded set of selected bases
    /// before the delta resolver gets a chance to enforce its own budgets.
    fn external_read_limit(&self) -> usize {
        self.pack_limits.max_cached_bytes.min(self.pack_limits.max_total_expanded_bytes)
    }

    fn verify_resolved_object(
        &self,
        object_type: ObjectType,
        body: Vec<u8>,
    ) -> Result<(GitOid, VerifiedObject), RefusalCode> {
        let id = fgit_crypto::git_object_id(
            self.node.object_format,
            crypto_object_kind(object_type),
            &body,
        );
        let parsed = verify_native_object(
            self.node.object_format,
            object_type,
            &body,
            &id,
            AcceptanceProfile::GitCompatibleImport,
            &self.parse_limits,
        )
        .map_err(map_pack_error)?;
        Ok((
            id,
            VerifiedObject {
                object_type,
                body,
                parsed,
            },
        ))
    }

    /// Reconstructs and verifies every pack-local object identity before a
    /// `REF_DELTA` is classified as external.
    ///
    /// The pack format carries a REF base identity but no trusted offset index.
    /// Direct and OFS-rooted entries establish identities first; each bounded
    /// pass adds only identities reconstructed through the typed resolver. A
    /// subsequent pass may therefore resolve a `REF_DELTA` whose base was just
    /// proven pack-local. The number of passes is capped by the existing delta
    /// depth bound plus the direct-entry pass, and one `ResolutionBudget`
    /// charges the entire discovery operation.
    fn verified_pack_objects(
        &self,
        pack: &QuarantinedPack,
        bases: &ExternalBases,
        deadline: &mut impl Deadline,
    ) -> Result<VerifiedPackObjects, RefusalCode> {
        checkpoint(deadline)?;
        // An empty, checksum-verified pack is real wire evidence. It is not a
        // missing pack or an unresolved thin delta. Root reuse is established
        // separately from the exact authenticated visible-ref graph below.
        if pack.entries().is_empty() {
            return Ok((BTreeMap::new(), BTreeMap::new()));
        }
        let mut objects = pack
            .clone()
            .into_scalar_objects(|_| None)
            .map_err(map_pack_error)?;
        let mut verified = BTreeMap::new();
        let mut ids_at_offset = BTreeMap::new();
        let mut budget = ResolutionBudget::new();

        for _ in 0..=self.pack_limits.max_delta_depth {
            checkpoint(deadline)?;
            let mut newly_resolved = Vec::new();
            {
                let mut pack_resolver =
                    CachedResolver::new(&objects, bases, &self.pack_limits, deadline)
                        .map_err(map_pack_error)?;
                for entry in pack.entries() {
                    checkpoint(deadline)?;
                    if ids_at_offset.contains_key(&entry.offset) {
                        continue;
                    }
                    match pack_resolver.resolve_offset_typed_with_budget(
                        entry.offset,
                        &mut budget,
                        deadline,
                    ) {
                        Ok((object_type, body)) => {
                            newly_resolved.push((entry.offset, object_type, body));
                        }
                        // The base may be a pack-local entry whose native ID
                        // is established in this or a later bounded pass.
                        Err(PackError::MissingDeltaBase) => {}
                        Err(error) => return Err(map_pack_error(error)),
                    }
                }
            }

            if newly_resolved.is_empty() {
                break;
            }
            for (offset, object_type, body) in newly_resolved {
                let (id, object) = self.verify_resolved_object(object_type, body)?;
                if verified.insert(id, object).is_some()
                    || ids_at_offset.insert(offset, id).is_some()
                {
                    return Err(RefusalCode::PackFramingInvalid);
                }
                let pack_object = objects
                    .iter_mut()
                    .find(|object| pack_object_offset(object) == offset)
                    .ok_or(RefusalCode::PackFramingInvalid)?;
                set_pack_object_id(pack_object, id);
            }
            if verified.len() == pack.entries().len() {
                return Ok((verified, ids_at_offset));
            }
        }

        // Every pack-local identity must be reconstructable before staging.
        // The only deferred resolver error is a missing REF base, which is a
        // true thin-base refusal after the bounded local discovery exhausted.
        Err(RefusalCode::ThinPackBaseMissing)
    }

    fn stage(
        &self,
        id: GitOid,
        object_type: ObjectType,
        body: Vec<u8>,
        deadline: &mut impl Deadline,
    ) -> Result<(), RefusalCode> {
        checkpoint(deadline)?;
        let stored = self
            .node
            .put_git_object(object_type, body)
            .map_err(|error| match error {
                NodeRefusal::ObjectTooLarge { .. }
                | NodeRefusal::ObjectLengthOverflow
                | NodeRefusal::Resource(_) => RefusalCode::ResourceBudgetExceeded,
                _ => RefusalCode::EvidenceInvalid,
            })?;
        if stored.identity() != id {
            return Err(RefusalCode::NativeObjectIdMismatch);
        }
        Ok(())
    }

    /// Maps each reconstructed in-pack object to the verified pack-local
    /// bases required to reconstruct it.
    ///
    /// A `REF_DELTA` begins with an untrusted native identity rather than an
    /// offset. After [`Self::verified_pack_objects`] has reconstructed native
    /// IDs under bounded resolution, matching that identity to an uploaded
    /// entry proves an exact pack-local edge. An `OFS_DELTA` already commits
    /// directly to a prior offset and follows the same closure rule after
    /// native verification maps that offset to its actual OID.
    fn in_pack_delta_bases(
        pack: &QuarantinedPack,
        ids_at_offset: &BTreeMap<u64, GitOid>,
        deadline: &mut impl Deadline,
    ) -> Result<BTreeMap<GitOid, BTreeSet<GitOid>>, RefusalCode> {
        let mut offsets_by_id = BTreeMap::new();
        for (offset, id) in ids_at_offset {
            if offsets_by_id.insert(*id, *offset).is_some() {
                return Err(RefusalCode::PackFramingInvalid);
            }
        }
        let mut dependencies = BTreeMap::new();
        for entry in pack.entries() {
            checkpoint(deadline)?;
            let Some(delta_base) = &entry.delta_base else {
                continue;
            };
            let id = ids_at_offset
                .get(&entry.offset)
                .copied()
                .ok_or(RefusalCode::PackFramingInvalid)?;
            let base = match delta_base {
                ParsedDeltaBase::Ofs { base_offset, .. } => ids_at_offset
                    .get(base_offset)
                    .copied()
                    .ok_or(RefusalCode::PackFramingInvalid)?,
                ParsedDeltaBase::Ref { base, .. } => {
                    if !offsets_by_id.contains_key(base) {
                        continue;
                    }
                    *base
                }
            };
            dependencies
                .entry(id)
                .or_insert_with(BTreeSet::new)
                .insert(base);
        }
        Ok(dependencies)
    }

}

impl OneNode {
    /// Creates a receive validator from the same authenticated materialization
    /// that selected the external-base closure.
    ///
    /// This rejects a materialization from another repository before it can
    /// read object-fabric bytes.  The returned validator still only stages
    /// immutable objects; callers must pass its closure through admission for
    /// a ref transition to become authoritative.
    pub fn production_quarantine_validator(
        &self,
        materialized: &MaterializedAdmission,
        pack_limits: PackLimits,
        parse_limits: ParseLimits,
    ) -> Result<ProductionQuarantineValidator<'_>, RefusalCode> {
        let head = materialized
            .authenticated()
            .body()
            .map_err(|_| RefusalCode::AuthorityReceiptInvalid)?;
        if head.repository_id != self.repository_id || materialized.basis().body() != &head {
            return Err(RefusalCode::AuthorityReceiptStale);
        }
        let selected_closure = materialized.selected_closure().clone();
        if permitted_object_closure_root(selected_closure.closure())? != selected_closure.root() {
            return Err(RefusalCode::EvidenceInvalid);
        }
        if selected_closure
            .closure()
            .objects()
            .iter()
            .any(|id| id.algorithm() != self.object_format)
        {
            return Err(RefusalCode::HashAlgorithmDomainMismatch);
        }
        let mut validator = ProductionQuarantineValidator::new(
            self,
            selected_closure,
            pack_limits,
            parse_limits,
        );
        // Cumulative admitted membership alone is not disclosure authority:
        // hidden-only and no-longer-reachable objects cannot seed a new ref.
        validator.visible_roots = materialized.snapshot().refs.iter()
            .filter(|(name, _)| !materialized.snapshot().hidden_refs.hides(name.as_bytes()))
            .map(|(_, id)| *id)
            .collect();
        Ok(validator)
    }
}

const fn pack_object_offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. }
        | PackObject::TypedBase { offset, .. }
        | PackObject::Delta(fgit_pack::DeltaObject { offset, .. }) => *offset,
    }
}

const fn set_pack_object_id(object: &mut PackObject, id: GitOid) {
    match object {
        PackObject::Base { id: slot, .. } | PackObject::TypedBase { id: slot, .. } => {
            *slot = Some(id);
        }
        PackObject::Delta(delta) => delta.id = Some(id),
    }
}

impl QuarantineValidator for ProductionQuarantineValidator<'_> {
    fn validate(
        &self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        checkpoint(deadline)?;
        if receipt.delete_only != request.deletes_only() {
            return Err(RefusalCode::PackFramingInvalid);
        }
        let Some(pack) = pack else {
            if receipt.object_count != 0 || receipt.pack_bytes != 0 {
                return Err(RefusalCode::PackFramingInvalid);
            }
            return if request.requires_pack() {
                Err(RefusalCode::ObjectClosureIncomplete)
            } else {
                Self::empty_closure()
            };
        };
        if pack.format != receipt.object_format || pack.format != self.node.object_format {
            return Err(RefusalCode::HashAlgorithmDomainMismatch);
        }
        if u32::try_from(pack.entries().len()).ok() != Some(receipt.object_count) {
            return Err(RefusalCode::PackFramingInvalid);
        }

        let bases = self.external_bases(pack, deadline)?;
        if bases.read_bytes > self.external_read_limit() {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        let (mut verified, ids_at_offset) = self.verified_pack_objects(pack, &bases, deadline)?;
        let in_pack_delta_bases = Self::in_pack_delta_bases(pack, &ids_at_offset, deadline)?;
        let closure =
            self.reachable_uploaded_closure(request, &verified, &in_pack_delta_bases, &bases, deadline)?;
        // This second phase keeps a later malformed delta from leaving earlier
        // reachable objects in fabric.  Immutable placement remains
        // non-authority, but only the fully validated exact closure may
        // acquire that responsibility.
        for id in &closure {
            checkpoint(deadline)?;
            if let Some(object) = verified.remove(id) {
                self.stage(*id, object.object_type, object.body, deadline)?;
            } else if !self.selected_closure.closure().objects().contains(id) {
                return Err(RefusalCode::ObjectClosureIncomplete);
            }
            // Reused roots were independently verified by the closure walk.
            // They remain in the admission witness but are never restaged.
        }
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                closure.clone(),
            ))?,
            objects: closure,
        })
    }
}

#[derive(Debug)]
struct ExternalBase {
    object_type: ObjectType,
    body: Vec<u8>,
}

#[derive(Debug)]
struct ExternalBases {
    bases: BTreeMap<ObjectId, ExternalBase>,
    read_bytes: usize,
}

impl ExternalBaseLookup for ExternalBases {
    fn lookup(&self, id: &ObjectId) -> Option<&[u8]> {
        self.bases.get(id).map(|base| base.body.as_slice())
    }

    fn lookup_typed(&self, id: &ObjectId) -> Option<(ObjectType, &[u8])> {
        self.bases
            .get(id)
            .map(|base| (base.object_type, base.body.as_slice()))
    }
}

fn checkpoint(deadline: &mut impl Deadline) -> Result<(), RefusalCode> {
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(RefusalCode::CancellationInProgress)
    }
}

fn copy_bytes(bytes: &[u8], deadline: &mut impl Deadline) -> Result<Vec<u8>, RefusalCode> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
    for byte in bytes {
        checkpoint(deadline)?;
        copied.push(*byte);
    }
    Ok(copied)
}

const fn map_pack_error(error: PackError) -> RefusalCode {
    match error {
        PackError::DeadlineExceeded => RefusalCode::CancellationInProgress,
        PackError::InputLimit { .. }
        | PackError::EntryCountLimit { .. }
        | PackError::ObjectSizeLimit { .. }
        | PackError::TotalExpandedLimit { .. }
        | PackError::DeltaResultSizeLimit { .. }
        | PackError::AllocationFailed { .. } => RefusalCode::ResourceBudgetExceeded,
        PackError::Inflate(_) | PackError::InflatedEntrySizeMismatch { .. } => {
            RefusalCode::DecompressionBudgetExceeded
        }
        PackError::InvalidDeltaInstruction
        | PackError::InvalidOfsDelta
        | PackError::DeltaBaseSizeMismatch { .. }
        | PackError::DeltaResultSizeMismatch { .. }
        | PackError::DeltaCopyOutOfRange { .. }
        | PackError::DeltaDepthLimit { .. }
        | PackError::DeltaFanoutLimit { .. }
        | PackError::DeltaCycle
        | PackError::DeltaWorkLimit { .. }
        | PackError::DuplicateObjectOffset(_)
        | PackError::DuplicateObjectId => RefusalCode::DeltaBudgetExceeded,
        PackError::MissingDeltaBase => RefusalCode::ThinPackBaseMissing,
        PackError::NativeObjectIdMismatch => RefusalCode::NativeObjectIdMismatch,
        PackError::ObjectFormatMismatch { .. } => RefusalCode::HashAlgorithmDomainMismatch,
        PackError::ObjectParse(_) | PackError::InvalidEntryType(_) => {
            RefusalCode::ObjectHeaderInvalid
        }
        PackError::DeltaObjectTypeUnavailable
        | PackError::UntypedInPackBase
        | PackError::UntypedExternalDeltaBase => RefusalCode::ObjectClosureIncomplete,
        PackError::ObjectIdLength { .. }
        | PackError::Truncated { .. }
        | PackError::InvalidPackSignature
        | PackError::UnsupportedPackVersion(_)
        | PackError::InvalidVarint { .. }
        | PackError::IntegerOverflow { .. }
        | PackError::TrailerChecksumMismatch
        | PackError::IndexChecksumMismatch
        | PackError::IndexEntryCrcMismatch { .. }
        | PackError::ObjectCountMismatch { .. }
        | PackError::TrailingPackData
        | PackError::InvalidIndexSignature
        | PackError::UnsupportedIndexVersion(_)
        | PackError::InvalidIndexFanout
        | PackError::InvalidIndexOrdering
        | PackError::InvalidLargeOffset { .. }
        | PackError::TrailingIndexBytes => RefusalCode::PackFramingInvalid,
    }
}

#[cfg(test)]
mod tests;
