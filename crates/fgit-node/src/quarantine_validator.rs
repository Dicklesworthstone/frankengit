//! Production validation from a receive quarantine into immutable object fabric.
//!
//! A [`ProductionQuarantineValidator`] does not treat the local object fabric
//! as authority.  Its only external delta bases are members of an
//! [`AuthoritySelectedClosure`], which was reconstructed from one authenticated
//! authority basis.  Newly verified objects are staged first, then returned as
//! the exact closure witness for admission; staging itself never publishes a
//! ref.

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
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, RefusalCode};
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
        deadline: &mut impl Deadline,
    ) -> Result<Option<ExternalBase>, RefusalCode> {
        checkpoint(deadline)?;
        if !self.selected_closure.closure().objects().contains(&id) {
            return Ok(None);
        }

        let verified = self.node.read_git_object(id).map_err(|error| match error {
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
        for entry in pack.entries() {
            checkpoint(deadline)?;
            let Some(ParsedDeltaBase::Ref { base, .. }) = &entry.delta_base else {
                continue;
            };
            if bases.contains_key(base) {
                continue;
            }
            if let Some(loaded) = self.load_selected_external_base(*base, deadline)? {
                bases.insert(*base, loaded);
            }
        }
        Ok(ExternalBases { bases })
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

    /// Computes the uploaded portion of the exact object closure required by
    /// the requested ref tips.
    ///
    /// Every object in `verified` has already passed native identity and
    /// parser checks.  Traversal nevertheless begins only at non-delete
    /// command tips: a valid but unrelated uploaded object is not an admitted
    /// object.  Edges may terminate in the authenticated prior closure, but
    /// never in merely-present fabric state.
    fn reachable_uploaded_closure(
        &self,
        request: &ReceiveRequest,
        verified: &BTreeMap<GitOid, VerifiedObject>,
        in_pack_delta_bases: &BTreeMap<GitOid, BTreeSet<GitOid>>,
        deadline: &mut impl Deadline,
    ) -> Result<BTreeSet<GitOid>, RefusalCode> {
        let mut pending = BTreeSet::new();
        for command in &request.commands {
            checkpoint(deadline)?;
            if command.new.is_zero() {
                continue;
            }
            if !verified.contains_key(&command.new) {
                return Err(RefusalCode::ObjectClosureIncomplete);
            }
            pending.insert(command.new);
        }

        let mut closure = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            checkpoint(deadline)?;
            if !closure.insert(id) {
                continue;
            }
            let object = verified
                .get(&id)
                .ok_or(RefusalCode::ObjectClosureIncomplete)?;
            // A delta target is not reconstructable from its Git-object
            // graph edges alone. Its verified in-pack OFS or REF_DELTA base
            // is an additional exact closure edge: retain it even for blobs,
            // which otherwise have no object references. External REF bases
            // remain selected by the authenticated prior closure and are not
            // restaged.
            if let Some(bases) = in_pack_delta_bases.get(&id) {
                pending.extend(bases.iter().copied());
            }
            for child in self.object_references(&object.parsed, deadline)? {
                checkpoint(deadline)?;
                if verified.contains_key(&child) {
                    pending.insert(child);
                } else if !self.selected_closure.closure().objects().contains(&child) {
                    return Err(RefusalCode::ObjectClosureIncomplete);
                }
            }
        }
        Ok(closure)
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

    /// Extracts the direct native-object edges from one parser-verified object.
    fn object_references(
        &self,
        parsed: &ParsedObject,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<GitOid>, RefusalCode> {
        match parsed {
            ParsedObject::Blob(_) => Ok(Vec::new()),
            ParsedObject::Tree(entries) => {
                let mut references = Vec::new();
                references
                    .try_reserve_exact(entries.len())
                    .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
                for entry in entries {
                    checkpoint(deadline)?;
                    // A gitlink names a commit in another repository; it is
                    // data in this tree, not a required local object edge.
                    if entry.mode == b"160000" {
                        continue;
                    }
                    references.push(self.native_reference_from_bytes(&entry.object_id)?);
                }
                Ok(references)
            }
            ParsedObject::Commit(commit) => {
                let mut references = Vec::new();
                let tree = commit
                    .tree_reference()
                    .ok_or(RefusalCode::ObjectHeaderInvalid)?;
                references.push(self.native_reference_from_hex(tree)?);
                for parent in commit.parent_references() {
                    checkpoint(deadline)?;
                    references.push(self.native_reference_from_hex(parent)?);
                }
                Ok(references)
            }
            ParsedObject::Tag(tag) => {
                let mut targets = tag
                    .headers()
                    .iter()
                    .filter(|header| header.name == b"object")
                    .map(|header| header.value.as_slice());
                let target = targets.next().ok_or(RefusalCode::ObjectHeaderInvalid)?;
                if targets.next().is_some() {
                    return Err(RefusalCode::ObjectHeaderInvalid);
                }
                Ok(vec![self.native_reference_from_hex(target)?])
            }
        }
    }

    fn native_reference_from_hex(&self, value: &[u8]) -> Result<GitOid, RefusalCode> {
        let value = std::str::from_utf8(value).map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
        GitOid::from_hex(self.node.object_format, value)
            .map_err(|_| RefusalCode::ObjectHeaderInvalid)
    }

    fn native_reference_from_bytes(&self, value: &[u8]) -> Result<GitOid, RefusalCode> {
        match self.node.object_format {
            GitHashAlgorithm::Sha1 => {
                let bytes: [u8; GitOidSha1::LEN] = value
                    .try_into()
                    .map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                Ok(GitOid::from(GitOidSha1::from_bytes(bytes)))
            }
            GitHashAlgorithm::Sha256 => {
                let bytes: [u8; GitOidSha256::LEN] = value
                    .try_into()
                    .map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                Ok(GitOid::from(GitOidSha256::from_bytes(bytes)))
            }
        }
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
        Ok(ProductionQuarantineValidator::new(
            self,
            selected_closure,
            pack_limits,
            parse_limits,
        ))
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
        let (mut verified, ids_at_offset) = self.verified_pack_objects(pack, &bases, deadline)?;
        let in_pack_delta_bases = Self::in_pack_delta_bases(pack, &ids_at_offset, deadline)?;
        let closure =
            self.reachable_uploaded_closure(request, &verified, &in_pack_delta_bases, deadline)?;
        // This second phase keeps a later malformed delta from leaving earlier
        // reachable objects in fabric.  Immutable placement remains
        // non-authority, but only the fully validated exact closure may
        // acquire that responsibility.
        for id in &closure {
            let object = verified
                .remove(id)
                .ok_or(RefusalCode::ObjectClosureIncomplete)?;
            self.stage(*id, object.object_type, object.body, deadline)?;
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
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use fgit_admission::validate_receive;
    use fgit_crypto::{GitObjectKind, IdentityDomain};
    use fgit_pack::{
        CanonicalObjectSource, CanonicalPackObject, NativeChecksumVerifier, PackPlanner,
        PackWriteError, PackWriteProfile, PackWriter, read_verified_pack,
    };
    use fgit_types::{
        CANONICAL_CODEC_VERSION, DigestBytes, GitHashAlgorithm, GitOidSha1, RepositoryCommitId,
        RepositoryId, TenantId,
    };
    use fgit_wire::receive::{ReceiveCommand, ReceivePhase, ReceiveRequest};
    use fgit_wire::{AnyGitOid, GitObjectFormat};

    use super::*;
    use crate::{ClosureSelectionSource, NodeConfig};

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory {
        root: PathBuf,
    }

    impl ScratchDirectory {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            Self {
                root: std::env::temp_dir().join(format!(
                    "frankengit-production-quarantine-validator-{}-{sequence}",
                    std::process::id()
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct OneObjectSource {
        object: CanonicalPackObject,
    }

    impl CanonicalObjectSource for OneObjectSource {
        fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
            if *id == self.object.id() {
                Ok(self.object.clone())
            } else {
                Err(PackWriteError::MissingCanonicalObject(*id))
            }
        }
    }

    struct SelectedObjectsSource {
        objects: BTreeMap<ObjectId, CanonicalPackObject>,
    }

    impl CanonicalObjectSource for SelectedObjectsSource {
        fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
            self.objects
                .get(id)
                .cloned()
                .ok_or(PackWriteError::MissingCanonicalObject(*id))
        }
    }

    fn test_node(root: PathBuf) -> OneNode {
        OneNode::init(NodeConfig::new(
            root,
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([0x72; 16]),
        ))
        .expect("node initializes")
        .0
    }

    fn empty_selected_closure() -> AuthoritySelectedClosure {
        let closure = PermittedObjectClosure::default();
        AuthoritySelectedClosure {
            root: permitted_object_closure_root(&closure).expect("empty closure has a root"),
            closure,
            source: ClosureSelectionSource::EmptyGenesis,
        }
    }

    fn create_request(id: GitOid) -> ReceiveRequest {
        ReceiveRequest {
            commands: vec![ReceiveCommand {
                old: AnyGitOid::from_hex(
                    GitObjectFormat::Sha1,
                    "0000000000000000000000000000000000000000",
                )
                .expect("fixed zero SHA-1 identity parses"),
                new: AnyGitOid::from_hex(GitObjectFormat::Sha1, &id.to_string())
                    .expect("computed SHA-1 identity parses"),
                ref_name: b"refs/heads/main".to_vec(),
            }],
            capabilities: Vec::new(),
            push_options: Vec::new(),
            certificate: None,
        }
    }

    #[test]
    fn every_receive_refusal_arm_maps_losslessly_to_the_async_transport_surface() {
        // The synchronous core owns the vocabulary.  One representative of
        // every current ReceiveError arm must survive the node's async
        // transport wrapper without a category collapse or a catch-all.
        let synchronous_refusals = vec![
            ReceiveError::Wire(fgit_wire::WireError::InvalidLimit { field: "wire" }),
            ReceiveError::Pack(PackError::MissingDeltaBase),
            ReceiveError::AuthoritativeRefusal(RefusalCode::ObjectClosureIncomplete),
            ReceiveError::HandoffProofMissing,
            ReceiveError::InvalidLimit { field: "receive" },
            ReceiveError::UnsupportedCapability {
                capability: b"atomic".to_vec(),
            },
            ReceiveError::CapabilityNotAdvertised {
                capability: b"delete-refs".to_vec(),
            },
            ReceiveError::CapabilityValueRequired {
                capability: b"object-format".to_vec(),
            },
            ReceiveError::CapabilityValueForbidden {
                capability: b"report-status".to_vec(),
            },
            ReceiveError::ObjectFormatMismatch {
                expected: GitObjectFormat::Sha1,
                observed: Some(b"sha256".to_vec()),
            },
            ReceiveError::CapabilitiesNotFirstCommand,
            ReceiveError::MissingCommands,
            ReceiveError::TooManyCommands { limit: 1 },
            ReceiveError::DuplicateRefCommand {
                ref_name: b"refs/heads/main".to_vec(),
            },
            ReceiveError::BothObjectIdsZero,
            ReceiveError::MalformedCommand {
                line: b"bad command".to_vec(),
            },
            ReceiveError::DeleteRefsNotNegotiated,
            ReceiveError::UnexpectedPacket {
                state: ReceivePhase::Commands,
                packet: "flush",
            },
            ReceiveError::UnexpectedPackBytes {
                state: ReceivePhase::Ready,
            },
            ReceiveError::TerminalState {
                state: ReceivePhase::Complete,
            },
            ReceiveError::IncompleteRequest {
                state: ReceivePhase::Pack,
            },
            ReceiveError::PackRequired,
            ReceiveError::QuarantineBytesExceeded { limit: 1 },
            ReceiveError::TooManyPushOptions { limit: 1 },
            ReceiveError::InvalidPushOption,
            ReceiveError::SignedPushUnsupported,
            ReceiveError::SignedPushCapabilityMissing,
            ReceiveError::MalformedCertificate,
            ReceiveError::CertificateTruncated,
            ReceiveError::CertificateNonceMismatch,
            ReceiveError::CertificateTooLarge { limit: 1 },
            ReceiveError::Cancelled,
            ReceiveError::StatusCountMismatch {
                expected: 1,
                actual: 2,
            },
            ReceiveError::InvalidStatusMessage,
            ReceiveError::AllocationFailure,
        ];

        for synchronous in synchronous_refusals {
            let expected = synchronous.clone();
            let asynchronous = NodeReceiveTransportRefusal::from(synchronous);
            match asynchronous {
                NodeReceiveTransportRefusal::Admission(admission) => match admission.as_ref() {
                    AdmissionError::Receive(mapped) => assert_eq!(
                        mapped, &expected,
                        "the asynchronous transport must retain {expected:?} exactly"
                    ),
                    other => panic!(
                        "the asynchronous transport must preserve ReceiveError, got {other:?}"
                    ),
                },
                NodeReceiveTransportRefusal::Unauthenticated => panic!(
                    "a receive-core refusal must not be confused with missing authentication"
                ),
                // The cell-state arms exist because this match is deliberately
                // wildcard-free: a new refusal variant must be given a decision
                // here rather than silently joining whatever a catch-all did.
                // Both are unreachable from THIS conversion by construction --
                // it is driven by a ReceiveError, and cell state is consulted
                // elsewhere in the receive composition -- so the honest arm is a
                // panic, not a tolerant one that would make the loop vacuous.
                NodeReceiveTransportRefusal::CellState(refusal) => panic!(
                    "a receive-core refusal must not be reported as a cell-state refusal, got {refusal:?}"
                ),
                NodeReceiveTransportRefusal::StagedWithoutPublication { state } => panic!(
                    "a receive-core refusal must not be reported as a withheld publication, got {state:?}"
                ),
                // Quota containment happens at TRANSPORT intake, before any
                // ReceiveError exists, so it cannot arise from this
                // conversion; the honest arm stays a panic like its peers.
                NodeReceiveTransportRefusal::QuotaContained { code, expires_secs } => panic!(
                    "a receive-core refusal must not be reported as quota containment ({code}, {expires_secs}s)"
                ),
            }
        }
    }

    fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
        let length = u16::try_from(bytes.len()).expect("small bounded fixture");
        let mut output = vec![0x78, 0x01, 0x01];
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(&(!length).to_le_bytes());
        output.extend_from_slice(bytes);
        let (adler_a, adler_b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
            let next_a = (a + u32::from(*byte)) % 65_521;
            (next_a, (b + next_a) % 65_521)
        });
        output.extend_from_slice(&((adler_b << 16) | adler_a).to_be_bytes());
        output
    }

    fn thin_ref_delta_pack(base: GitOid, base_body: &[u8], target_body: &[u8]) -> Vec<u8> {
        let suffix = target_body
            .strip_prefix(base_body)
            .expect("fixture target extends its external base");
        assert_eq!(suffix.len(), 1, "fixture has one literal delta suffix");
        let base_length = u8::try_from(base_body.len()).expect("small bounded fixture");
        let target_length = u8::try_from(target_body.len()).expect("small bounded fixture");
        let mut program = vec![base_length, target_length, 0x91, 0, base_length];
        program.push(u8::try_from(suffix.len()).expect("one-byte literal fixture"));
        program.extend_from_slice(suffix);
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        pack.push(0x70 | u8::try_from(program.len()).expect("small delta program"));
        pack.extend_from_slice(base.as_bytes());
        pack.extend_from_slice(&zlib_stored(&program));
        let trailer = fgit_crypto::sha1_digest(&pack);
        pack.extend_from_slice(&trailer);
        pack
    }

    fn in_pack_ref_delta_pack(base: GitOid, base_body: &[u8], target_body: &[u8]) -> Vec<u8> {
        let suffix = target_body
            .strip_prefix(base_body)
            .expect("fixture target extends its uploaded base");
        assert_eq!(suffix.len(), 1, "fixture has one literal delta suffix");
        let base_length = u8::try_from(base_body.len()).expect("small bounded fixture");
        let target_length = u8::try_from(target_body.len()).expect("small bounded fixture");
        assert!(base_length < 16, "fixture base has a one-byte pack header");
        let mut program = vec![base_length, target_length, 0x91, 0, base_length];
        program.push(u8::try_from(suffix.len()).expect("one-byte literal fixture"));
        program.extend_from_slice(suffix);

        let mut pack = b"PACK\0\0\0\x02\0\0\0\x02".to_vec();
        // A blob base entry with its native body. The following REF_DELTA
        // names this entry's native ID, rather than a prior selected closure.
        pack.push(0x30 | base_length);
        pack.extend_from_slice(&zlib_stored(base_body));
        pack.push(0x70 | u8::try_from(program.len()).expect("small delta program"));
        pack.extend_from_slice(base.as_bytes());
        pack.extend_from_slice(&zlib_stored(&program));
        let trailer = fgit_crypto::sha1_digest(&pack);
        pack.extend_from_slice(&trailer);
        pack
    }

    fn selected_closure(objects: BTreeSet<GitOid>) -> AuthoritySelectedClosure {
        let closure = PermittedObjectClosure::new(objects);
        AuthoritySelectedClosure {
            root: permitted_object_closure_root(&closure)
                .expect("selected fixture objects have a canonical root"),
            closure,
            source: ClosureSelectionSource::RepositoryCommit(RepositoryCommitId::from_digest(
                IdentityDomain::RepositoryCommitRecord.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[0x61; 32])
                    .expect("fixture repository commit identity has one digest"),
            )),
        }
    }

    #[test]
    fn object_bearing_pack_is_verified_staged_and_reported_as_its_exact_closure() {
        let scratch = ScratchDirectory::new();
        let node = test_node(scratch.path().to_path_buf());
        let body = b"production quarantine validator".to_vec();
        let id = fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &body);
        let source = OneObjectSource {
            object: CanonicalPackObject::new(id, ObjectType::Blob, body, Vec::new(), 0, 0),
        };
        let limits = PackLimits::default();
        let mut live = || true;
        let plan = PackPlanner::new(
            GitHashAlgorithm::Sha1,
            PackWriteProfile::STORED_V1,
            limits.clone(),
        )
        .plan_selected(&source, &[id], &mut live)
        .expect("fixed object plans into a native pack");
        let (pack_bytes, receipt) = PackWriter::new(limits.clone())
            .write(&plan, &mut live)
            .expect("fixed pack writes");
        let pack = read_verified_pack(
            &pack_bytes,
            GitHashAlgorithm::Sha1,
            &limits,
            &mut live,
            &NativeChecksumVerifier,
        )
        .expect("writer output returns through the verified quarantine reader");
        let request = create_request(id);
        let quarantine = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: receipt.object_count,
            pack_bytes: pack_bytes.len(),
            delete_only: false,
        };
        let authority_request = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&authority_request))
            .expect("the initialized head materializes before receive validation");
        let validator = node
            .production_quarantine_validator(&materialized, limits, ParseLimits::default())
            .expect("the exact authenticated materialization supplies a validator");

        let mut admission_live = || true;
        let admitted = validate_receive(
            &request,
            Some(&pack),
            &quarantine,
            &validator,
            &mut admission_live,
        )
        .expect("the object-bearing receive is admitted from its exact closure");
        assert_eq!(admitted.request(), &request);

        let closure = validator
            .validate(&request, Some(&pack), &quarantine, &mut live)
            .expect("a bounded object-bearing pack reaches fabric before admission");

        assert_eq!(closure.objects, BTreeSet::from([id]));
        assert_eq!(
            closure.object_closure_root,
            permitted_object_closure_root(&PermittedObjectClosure::new(BTreeSet::from([id])))
                .expect("exact closure has one root")
        );
        assert!(
            node.read_git_object(id).is_ok(),
            "the validated native object is already immutable fabric state"
        );
        let wrong_target = GitOid::from(GitOidSha1::from_bytes([0xa1; 20]));
        let mut live = || true;
        assert_eq!(
            validate_receive(
                &create_request(wrong_target),
                Some(&pack),
                &quarantine,
                &validator,
                &mut live,
            ),
            Err(RefusalCode::ObjectClosureIncomplete),
            "a command cannot name an OID other than the validator's exact closure"
        );

        let handoff_validator = node
            .production_quarantine_validator(
                &materialized,
                PackLimits::default(),
                ParseLimits::default(),
            )
            .expect("the same authenticated materialization supplies a handoff validator");
        let mut handoff = ProductionReceiveQuarantineHandoff::new(
            handoff_validator,
            materialized.basis().clone(),
        );
        let mut transport_live = || true;
        handoff
            .handoff_with_deadline(&request, Some(&pack), &quarantine, &mut transport_live)
            .expect("the synchronous production handoff retains a validated receive");
        assert_eq!(
            handoff
                .into_validated_receive()
                .expect("successful handoff retains only its validated receive")
                .request(),
            &request
        );
        node.shutdown().expect("node shuts down after test");
    }

    #[test]
    fn graph_rooted_closure_stages_only_reachable_uploaded_objects() {
        let scratch = ScratchDirectory::new();
        let node = test_node(scratch.path().to_path_buf());
        let blob_body = b"reachable blob".to_vec();
        let blob_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &blob_body);

        let mut tree_body = b"100644 file\0".to_vec();
        tree_body.extend_from_slice(blob_id.as_bytes());
        let tree_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, &tree_body);
        let commit_body = format!(
            "tree {tree_id}\nauthor A <a@example.com> 1 +0000\ncommitter C <c@example.com> 1 +0000\n\nmessage"
        )
        .into_bytes();
        let commit_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, &commit_body);
        let tag_body = format!(
            "object {commit_id}\ntype commit\ntag release\ntagger T <t@example.com> 1 +0000\n\nmessage"
        )
        .into_bytes();
        let tag_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tag, &tag_body);
        let junk_body = b"unreachable upload".to_vec();
        let junk_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &junk_body);

        let source = SelectedObjectsSource {
            objects: BTreeMap::from([
                (
                    blob_id,
                    CanonicalPackObject::new(
                        blob_id,
                        ObjectType::Blob,
                        blob_body,
                        Vec::new(),
                        0,
                        0,
                    ),
                ),
                (
                    tree_id,
                    CanonicalPackObject::new(
                        tree_id,
                        ObjectType::Tree,
                        tree_body,
                        Vec::new(),
                        0,
                        0,
                    ),
                ),
                (
                    commit_id,
                    CanonicalPackObject::new(
                        commit_id,
                        ObjectType::Commit,
                        commit_body,
                        Vec::new(),
                        0,
                        0,
                    ),
                ),
                (
                    tag_id,
                    CanonicalPackObject::new(tag_id, ObjectType::Tag, tag_body, Vec::new(), 0, 0),
                ),
                (
                    junk_id,
                    CanonicalPackObject::new(
                        junk_id,
                        ObjectType::Blob,
                        junk_body,
                        Vec::new(),
                        0,
                        0,
                    ),
                ),
            ]),
        };
        let limits = PackLimits::default();
        let mut live = || true;
        let plan = PackPlanner::new(
            GitHashAlgorithm::Sha1,
            PackWriteProfile::STORED_V1,
            limits.clone(),
        )
        .plan_selected(
            &source,
            &[tag_id, commit_id, tree_id, blob_id, junk_id],
            &mut live,
        )
        .expect("the object graph and unrelated upload plan into one native pack");
        let (pack_bytes, receipt) = PackWriter::new(limits.clone())
            .write(&plan, &mut live)
            .expect("the graph fixture pack writes");
        let pack = read_verified_pack(
            &pack_bytes,
            GitHashAlgorithm::Sha1,
            &limits,
            &mut live,
            &NativeChecksumVerifier,
        )
        .expect("the graph fixture remains in receive quarantine");
        let quarantine = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: receipt.object_count,
            pack_bytes: pack_bytes.len(),
            delete_only: false,
        };
        let validator = ProductionQuarantineValidator::new(
            &node,
            empty_selected_closure(),
            limits,
            ParseLimits::default(),
        );

        let closure = validator
            .validate(&create_request(tag_id), Some(&pack), &quarantine, &mut live)
            .expect("the requested tag carries its commit, tree, and blob closure");
        assert_eq!(
            closure.objects,
            BTreeSet::from([tag_id, commit_id, tree_id, blob_id]),
            "the receipt closure follows native graph edges rather than every uploaded entry"
        );
        assert!(
            node.read_git_object(junk_id).is_err(),
            "a verified but unreachable upload is not staged into immutable fabric"
        );
        node.shutdown().expect("node shuts down after test");
    }

    #[test]
    fn graph_child_must_be_uploaded_or_in_the_authority_selected_closure() {
        let external_tree_body = Vec::new();
        let external_tree_id = fgit_crypto::git_object_id(
            GitHashAlgorithm::Sha1,
            GitObjectKind::Tree,
            &external_tree_body,
        );
        let commit_body = format!(
            "tree {external_tree_id}\nauthor A <a@example.com> 1 +0000\ncommitter C <c@example.com> 1 +0000\n\nmessage"
        )
        .into_bytes();
        let commit_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, &commit_body);
        let source = OneObjectSource {
            object: CanonicalPackObject::new(
                commit_id,
                ObjectType::Commit,
                commit_body,
                Vec::new(),
                0,
                0,
            ),
        };
        let limits = PackLimits::default();
        let mut live = || true;
        let plan = PackPlanner::new(
            GitHashAlgorithm::Sha1,
            PackWriteProfile::STORED_V1,
            limits.clone(),
        )
        .plan_selected(&source, &[commit_id], &mut live)
        .expect("the commit-only fixture plans into a native pack");
        let (pack_bytes, receipt) = PackWriter::new(limits.clone())
            .write(&plan, &mut live)
            .expect("the commit-only fixture pack writes");
        let pack = read_verified_pack(
            &pack_bytes,
            GitHashAlgorithm::Sha1,
            &limits,
            &mut live,
            &NativeChecksumVerifier,
        )
        .expect("the commit-only fixture remains quarantined");
        let quarantine = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: receipt.object_count,
            pack_bytes: pack_bytes.len(),
            delete_only: false,
        };

        let missing_scratch = ScratchDirectory::new();
        let missing_node = test_node(missing_scratch.path().to_path_buf());
        let missing = ProductionQuarantineValidator::new(
            &missing_node,
            empty_selected_closure(),
            limits.clone(),
            ParseLimits::default(),
        );
        assert_eq!(
            missing.validate(
                &create_request(commit_id),
                Some(&pack),
                &quarantine,
                &mut live
            ),
            Err(RefusalCode::ObjectClosureIncomplete),
            "an omitted graph child cannot be inferred from a local cache or fabric hint"
        );
        missing_node
            .shutdown()
            .expect("missing-child node shuts down after test");

        let permitted_scratch = ScratchDirectory::new();
        let permitted_node = test_node(permitted_scratch.path().to_path_buf());
        permitted_node
            .put_git_object(ObjectType::Tree, external_tree_body)
            .expect("the authenticated tree is available in immutable fabric");
        let permitted = ProductionQuarantineValidator::new(
            &permitted_node,
            selected_closure(BTreeSet::from([external_tree_id])),
            limits,
            ParseLimits::default(),
        );
        assert_eq!(
            permitted
                .validate(
                    &create_request(commit_id),
                    Some(&pack),
                    &quarantine,
                    &mut live
                )
                .expect("an authority-selected child completes the requested graph")
                .objects,
            BTreeSet::from([commit_id])
        );
        permitted_node
            .shutdown()
            .expect("permitted-child node shuts down after test");
    }

    #[test]
    fn expired_deadline_refuses_before_object_or_fabric_work() {
        let scratch = ScratchDirectory::new();
        let node = test_node(scratch.path().to_path_buf());
        let request = ReceiveRequest {
            commands: vec![ReceiveCommand {
                old: AnyGitOid::from_hex(
                    GitObjectFormat::Sha1,
                    "1111111111111111111111111111111111111111",
                )
                .expect("fixed SHA-1 identity parses"),
                new: AnyGitOid::from_hex(
                    GitObjectFormat::Sha1,
                    "0000000000000000000000000000000000000000",
                )
                .expect("fixed SHA-1 zero identity parses"),
                ref_name: b"refs/heads/main".to_vec(),
            }],
            capabilities: Vec::new(),
            push_options: Vec::new(),
            certificate: None,
        };
        let receipt = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 0,
            pack_bytes: 0,
            delete_only: true,
        };
        let authority_request = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&authority_request))
            .expect("the initialized head materializes before receive validation");
        let validator = node
            .production_quarantine_validator(
                &materialized,
                PackLimits::default(),
                ParseLimits::default(),
            )
            .expect("the exact authenticated materialization supplies a validator");
        let mut expired = || false;
        assert_eq!(
            validator.validate(&request, None, &receipt, &mut expired),
            Err(RefusalCode::CancellationInProgress)
        );
        assert!(receipt.delete_only);
        node.shutdown().expect("node shuts down after test");
    }

    #[test]
    fn live_delete_only_receive_returns_the_canonical_empty_closure() {
        let scratch = ScratchDirectory::new();
        let node = test_node(scratch.path().to_path_buf());
        let request = ReceiveRequest {
            commands: vec![ReceiveCommand {
                old: AnyGitOid::from_hex(
                    GitObjectFormat::Sha1,
                    "1111111111111111111111111111111111111111",
                )
                .expect("fixed SHA-1 identity parses"),
                new: AnyGitOid::from_hex(
                    GitObjectFormat::Sha1,
                    "0000000000000000000000000000000000000000",
                )
                .expect("fixed SHA-1 zero identity parses"),
                ref_name: b"refs/heads/main".to_vec(),
            }],
            capabilities: Vec::new(),
            push_options: Vec::new(),
            certificate: None,
        };
        let receipt = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 0,
            pack_bytes: 0,
            delete_only: true,
        };
        let validator = ProductionQuarantineValidator::new(
            &node,
            empty_selected_closure(),
            PackLimits::default(),
            ParseLimits::default(),
        );
        let mut live = || true;

        assert_eq!(
            validator
                .validate(&request, None, &receipt, &mut live)
                .expect("the live delete-only twin is permitted"),
            ProductionQuarantineValidator::empty_closure()
                .expect("empty closure has a canonical root")
        );
        node.shutdown().expect("node shuts down after test");
    }

    #[test]
    fn thin_ref_delta_requires_an_authority_selected_verified_fabric_base() {
        let base_body = b"thin-base".to_vec();
        let target_body = b"thin-base!".to_vec();
        let base_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &base_body);
        let target_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &target_body);
        let limits = PackLimits::default();
        let pack_bytes = thin_ref_delta_pack(base_id, &base_body, &target_body);
        let mut live = || true;
        let pack = read_verified_pack(
            &pack_bytes,
            GitHashAlgorithm::Sha1,
            &limits,
            &mut live,
            &NativeChecksumVerifier,
        )
        .expect("the thin fixture crosses the verified reader before validation");
        let receipt = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 1,
            pack_bytes: pack_bytes.len(),
            delete_only: false,
        };
        let request = create_request(target_id);

        let missing_scratch = ScratchDirectory::new();
        let missing_node = test_node(missing_scratch.path().to_path_buf());
        missing_node
            .put_git_object(ObjectType::Blob, base_body.clone())
            .expect("the unauthorized native base is present in local fabric");
        let missing = ProductionQuarantineValidator::new(
            &missing_node,
            empty_selected_closure(),
            limits.clone(),
            ParseLimits::default(),
        );
        let mut live = || true;
        assert_eq!(
            missing.validate(&request, Some(&pack), &receipt, &mut live),
            Err(RefusalCode::ThinPackBaseMissing),
            "fabric presence alone cannot authorize a REF_DELTA base"
        );
        missing_node
            .shutdown()
            .expect("missing-base node shuts down after test");

        let permitted_scratch = ScratchDirectory::new();
        let permitted_node = test_node(permitted_scratch.path().to_path_buf());
        permitted_node
            .put_git_object(ObjectType::Blob, base_body)
            .expect("the authority-selected native base enters immutable fabric");
        let permitted = ProductionQuarantineValidator::new(
            &permitted_node,
            selected_closure(BTreeSet::from([base_id])),
            limits,
            ParseLimits::default(),
        );
        let mut live = || true;
        assert_eq!(
            permitted
                .validate(&request, Some(&pack), &receipt, &mut live)
                .expect("selected and verified fabric data is a permitted REF_DELTA base")
                .objects,
            BTreeSet::from([target_id])
        );
        permitted_node
            .shutdown()
            .expect("permitted thin-base node shuts down after test");
    }

    #[test]
    fn in_pack_ref_delta_uses_its_verified_uploaded_base() {
        let base_body = b"in-pack-base".to_vec();
        let target_body = b"in-pack-base!".to_vec();
        let base_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &base_body);
        let target_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &target_body);
        let limits = PackLimits::default();
        let pack_bytes = in_pack_ref_delta_pack(base_id, &base_body, &target_body);
        let mut live = || true;
        let pack = read_verified_pack(
            &pack_bytes,
            GitHashAlgorithm::Sha1,
            &limits,
            &mut live,
            &NativeChecksumVerifier,
        )
        .expect("the complete REF_DELTA fixture crosses verified quarantine");
        let receipt = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 2,
            pack_bytes: pack_bytes.len(),
            delete_only: false,
        };
        let scratch = ScratchDirectory::new();
        let node = test_node(scratch.path().to_path_buf());
        let validator = ProductionQuarantineValidator::new(
            &node,
            empty_selected_closure(),
            limits,
            ParseLimits::default(),
        );

        let closure = validator
            .validate(&create_request(target_id), Some(&pack), &receipt, &mut live)
            .expect("a verified uploaded REF base is not classified as thin");
        assert_eq!(closure.objects, BTreeSet::from([base_id, target_id]));
        assert!(node.read_git_object(base_id).is_ok());
        assert!(node.read_git_object(target_id).is_ok());
        node.shutdown().expect("node shuts down after test");
    }

    #[test]
    fn delta_chain_over_the_selected_budget_is_refused_before_any_fabric_placement() {
        let scratch = ScratchDirectory::new();
        let node = test_node(scratch.path().to_path_buf());
        let base_body = b"aaaaaaaaaaaaaaaaaaaa--same-suffix".to_vec();
        let target_body = b"aaaaaaaaaaaaaaaaaaaaXXsame-suffix".to_vec();
        let base_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &base_body);
        let target_id =
            fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, &target_body);
        let source = SelectedObjectsSource {
            objects: BTreeMap::from([
                (
                    base_id,
                    CanonicalPackObject::new(
                        base_id,
                        ObjectType::Blob,
                        base_body,
                        Vec::new(),
                        3,
                        1,
                    ),
                ),
                (
                    target_id,
                    CanonicalPackObject::new(
                        target_id,
                        ObjectType::Blob,
                        target_body,
                        Vec::new(),
                        2,
                        1,
                    ),
                ),
            ]),
        };
        let writer_limits = PackLimits::default();
        let mut live = || true;
        let plan = PackPlanner::new(
            GitHashAlgorithm::Sha1,
            PackWriteProfile::STORED_V1,
            writer_limits.clone(),
        )
        .plan_selected(&source, &[base_id, target_id], &mut live)
        .expect("similar verified blobs plan into a delta pack");
        assert!(
            plan.entries().iter().any(|entry| entry.delta().is_some()),
            "the writer fixture must exercise the production delta resolver"
        );
        let (pack_bytes, receipt) = PackWriter::new(writer_limits.clone())
            .write(&plan, &mut live)
            .expect("delta plan writes a verified pack");
        let pack = read_verified_pack(
            &pack_bytes,
            GitHashAlgorithm::Sha1,
            &writer_limits,
            &mut live,
            &NativeChecksumVerifier,
        )
        .expect("writer delta pack remains structurally quarantined");
        let mut selected_limits = writer_limits;
        selected_limits.max_delta_depth = 0;
        let validator = ProductionQuarantineValidator::new(
            &node,
            empty_selected_closure(),
            selected_limits,
            ParseLimits::default(),
        );
        let quarantine = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: receipt.object_count,
            pack_bytes: pack_bytes.len(),
            delete_only: false,
        };

        assert_eq!(
            validator.validate(
                &create_request(target_id),
                Some(&pack),
                &quarantine,
                &mut live
            ),
            Err(RefusalCode::DeltaBudgetExceeded)
        );
        assert!(
            node.read_git_object(base_id).is_err() && node.read_git_object(target_id).is_err(),
            "the staging phase starts only after every pack entry has verified"
        );
        node.shutdown().expect("node shuts down after test");

        let permitted_scratch = ScratchDirectory::new();
        let permitted_node = test_node(permitted_scratch.path().to_path_buf());
        let permitted = ProductionQuarantineValidator::new(
            &permitted_node,
            empty_selected_closure(),
            PackLimits::default(),
            ParseLimits::default(),
        );
        let mut live = || true;
        assert_eq!(
            permitted
                .validate(
                    &create_request(target_id),
                    Some(&pack),
                    &quarantine,
                    &mut live
                )
                .expect("the same bounded delta pack is permitted under its selected budget")
                .objects,
            BTreeSet::from([base_id, target_id])
        );
        permitted_node
            .shutdown()
            .expect("permitted-twin node shuts down after test");
    }
}
