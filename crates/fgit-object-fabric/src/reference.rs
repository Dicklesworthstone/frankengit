//! Explicitly non-durable, faultable reference implementation of object fabric.
//!
//! This backend models the immutable fabric algebra with one mutex-protected
//! state transition per operation. It is for deterministic conformance and
//! fault tests only: it is neither a durable placement profile nor a source of
//! repository authority. Production profiles use [`crate::local::LocalFilesystemFabric`]
//! or a later durable backend.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use asupersync::{Cx, Outcome};
use fgit_resource::kinds::{
    AdmissionAbandoned, AdmissionAbortReason, AdmittedObject, ObjectAdmission,
    ObjectAdmissionPermit, ObjectClass, StructureVerdict,
};
use fgit_resource::{Grade, OpaqueHandle, ReservedObligation, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitOid, ObjectEnvelopeId, RepositoryAuthorityHeadId,
    SegmentManifestId,
};

use crate::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, FabricCapabilities, FabricCapability,
    ImmutableObjectFabric, ObjectRange, PlacementAdmission, PlacementBackend, PlacementReceipt,
    PublicationState, PutIfAbsent, ReferenceFaultPoint, RetentionRootProposal,
    RuntimeImmutableObjectFabric, SegmentManifest, StoreRefusal, VerifiedObject,
    VerifiedObjectStream, VerifiedRangeRead, VerifiedStreamBudget, WholeObjectRead,
    checkpoint_outcome,
};
use crate::{ENVELOPE_SCHEMA, ObjectKind};

/// Construction data for the explicit non-durable reference profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceMemoryConfig {
    namespace: Vec<u8>,
    failure_domain: OpaqueHandle,
    encryption_dependency: OpaqueHandle,
    max_object_bytes: u64,
    manifest_limits: crate::fabric::ManifestLimits,
    fault: Option<ReferenceFaultPoint>,
}

impl ReferenceMemoryConfig {
    /// Creates a namespace-scoped reference profile.
    pub fn new(
        namespace: Vec<u8>,
        failure_domain: OpaqueHandle,
        encryption_dependency: OpaqueHandle,
        max_object_bytes: u64,
        manifest_limits: crate::fabric::ManifestLimits,
    ) -> Result<Self, StoreRefusal> {
        if namespace.is_empty() {
            return Err(StoreRefusal::EmptyNamespace);
        }
        if namespace.len() > manifest_limits.max_namespace_bytes {
            return Err(StoreRefusal::NamespaceTooLarge);
        }
        Ok(Self {
            namespace,
            failure_domain,
            encryption_dependency,
            max_object_bytes,
            manifest_limits,
            fault: None,
        })
    }

    /// Adds one deterministic operation interruption for a fault drill.
    #[must_use]
    pub const fn with_fault_injection(mut self, point: ReferenceFaultPoint) -> Self {
        self.fault = Some(point);
        self
    }
}

/// A non-durable reference state used only for deterministic conformance work.
#[derive(Debug, Default)]
struct ReferenceState {
    objects: BTreeMap<GitOid, VerifiedObject>,
    manifests: BTreeMap<SegmentManifestId, SegmentManifest>,
    retention_bodies: BTreeMap<Digest, Vec<u8>>,
    retention_roots: BTreeMap<RepositoryAuthorityHeadId, Digest>,
}

/// In-memory, faultable conformance reference for the immutable-fabric traits.
///
/// Its staged epoch never claims authority visibility or durability. Callers
/// must never use this backend for canonical placement, recovery, or
/// retention evidence.
#[derive(Debug, Clone)]
pub struct ReferenceMemoryFabric {
    namespace: Vec<u8>,
    placement: PlacementReceipt,
    max_object_bytes: u64,
    manifest_limits: crate::fabric::ManifestLimits,
    fault: Option<ReferenceFaultPoint>,
    state: Arc<Mutex<ReferenceState>>,
}

impl ReferenceMemoryFabric {
    /// Opens a fresh non-durable reference profile.
    pub fn open(config: ReferenceMemoryConfig) -> Result<Self, StoreRefusal> {
        let locator = OpaqueHandle::new(b"reference-memory")?;
        Ok(Self {
            namespace: config.namespace,
            placement: PlacementReceipt::new(
                PlacementBackend::MemoryReference,
                locator,
                config.failure_domain,
                config.encryption_dependency,
            ),
            max_object_bytes: config.max_object_bytes,
            manifest_limits: config.manifest_limits,
            fault: config.fault,
            state: Arc::new(Mutex::new(ReferenceState::default())),
        })
    }

    fn state(&self) -> Result<MutexGuard<'_, ReferenceState>, StoreRefusal> {
        self.state
            .lock()
            .map_err(|_| StoreRefusal::ReferenceStatePoisoned)
    }

    fn fault_if(&self, point: ReferenceFaultPoint) -> Result<(), StoreRefusal> {
        if self.fault == Some(point) {
            return Err(StoreRefusal::ReferenceFaultInjected { point });
        }
        Ok(())
    }

    fn admitted_usage(object: &VerifiedObject) -> Result<ResourceVector, StoreRefusal> {
        let bytes =
            u64::try_from(object.payload().len()).map_err(|_| StoreRefusal::LengthOverflow)?;
        Ok(ResourceVector::from_grades(&[
            (Grade::Bytes, bytes),
            (Grade::Objects, 1),
        ]))
    }

    fn reservation(object: &VerifiedObject) -> Result<ObjectAdmission, StoreRefusal> {
        let declared_len =
            u64::try_from(object.payload().len()).map_err(|_| StoreRefusal::LengthOverflow)?;
        Ok(ObjectAdmission {
            class: ObjectClass::GitObject,
            declared_len,
            staging: object_envelope_id(object)?,
        })
    }

    fn staged_epochs() -> PublicationState {
        PublicationState::new(true, false, false)
    }
}

impl ImmutableObjectFabric for ReferenceMemoryFabric {
    fn capabilities(&self) -> FabricCapabilities {
        FabricCapabilities::new(&[
            FabricCapability::ConditionalPutIfAbsent,
            FabricCapability::VerifiedWholeReads,
            FabricCapability::ConditionalDeletion,
        ])
    }

    fn put_if_absent(
        &self,
        object: VerifiedObject,
        admission: PlacementAdmission<'_>,
    ) -> Result<PutIfAbsent, StoreRefusal> {
        let (ledger, budget) = admission.into_parts();
        if object.envelope().namespace() != self.namespace {
            let _released = budget.release();
            return Err(StoreRefusal::NamespaceMismatch);
        }
        let object_bytes =
            u64::try_from(object.payload().len()).map_err(|_| StoreRefusal::LengthOverflow)?;
        if object_bytes > self.max_object_bytes {
            let _released = budget.release();
            return Err(StoreRefusal::StoredObjectTooLarge {
                offered: object_bytes,
                maximum: self.max_object_bytes,
            });
        }
        let usage = match Self::admitted_usage(&object) {
            Ok(usage) => usage,
            Err(error) => {
                let _released = budget.release();
                return Err(error);
            }
        };
        if let Some(error) = budget.amount().first_deficit(&usage) {
            let _released = budget.release();
            return Err(StoreRefusal::Resource(error));
        }

        {
            let state = match self.state() {
                Ok(state) => state,
                Err(error) => {
                    let _released = budget.release();
                    return Err(error);
                }
            };
            if let Some(existing) = state.objects.get(&object.identity()) {
                let _released = budget.release();
                if existing != &object {
                    return Err(StoreRefusal::StoredObjectMismatch);
                }
                return Ok(PutIfAbsent::AlreadyPresent {
                    placement: self.placement.clone(),
                    epochs: Self::staged_epochs(),
                });
            }
        }

        let reservation = match Self::reservation(&object) {
            Ok(reservation) => reservation,
            Err(error) => {
                let _released = budget.release();
                return Err(error);
            }
        };
        let reserved = ledger.reserve::<ObjectAdmissionPermit>(reservation, budget)?;
        if let Err(error) = reserved.can_settle(&usage) {
            let _settled = reserved.abort_unused(AdmissionAbandoned {
                reason: AdmissionAbortReason::QuotaWithdrawn,
            });
            return Err(StoreRefusal::Settlement(error));
        }
        let mut state = match self.state() {
            Ok(state) => state,
            Err(error) => {
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &ResourceVector::ZERO,
                )?;
                return Err(error);
            }
        };
        if let Some(existing) = state.objects.get(&object.identity()) {
            settle_admission_abort(
                reserved,
                AdmissionAbortReason::Superseded,
                &ResourceVector::ZERO,
            )?;
            if existing != &object {
                return Err(StoreRefusal::StoredObjectMismatch);
            }
            return Ok(PutIfAbsent::AlreadyPresent {
                placement: self.placement.clone(),
                epochs: Self::staged_epochs(),
            });
        }
        if let Err(error) = self.fault_if(ReferenceFaultPoint::BeforeObjectInsert) {
            settle_admission_abort(
                reserved,
                AdmissionAbortReason::PlacementWriteFailed,
                &ResourceVector::ZERO,
            )?;
            return Err(error);
        }
        state.objects.insert(object.identity(), object.clone());
        drop(state);
        if let Err(error) = self.fault_if(ReferenceFaultPoint::AfterObjectInsert) {
            settle_admission_abort(reserved, AdmissionAbortReason::PlacementWriteFailed, &usage)?;
            return Err(error);
        }
        let strong_identity = payload_identity(object.envelope().object_kind(), object.payload())?;
        let receipt = match AdmittedObject::verified(
            &reservation,
            object.identity(),
            strong_identity,
            object_bytes,
            StructureVerdict::Verified,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &usage,
                )?;
                return Err(StoreRefusal::AdmissionEvidence(error));
            }
        };
        match reserved.commit_internal(receipt, &usage) {
            Ok(_settled) => Ok(PutIfAbsent::Created {
                placement: self.placement.clone(),
                epochs: Self::staged_epochs(),
            }),
            Err(refused) => {
                let error = refused.error();
                let reservation = refused.into_obligation();
                settle_admission_abort(
                    reservation,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &usage,
                )?;
                Err(StoreRefusal::Settlement(error))
            }
        }
    }

    fn read_whole(&self, identity: GitOid) -> Result<WholeObjectRead, StoreRefusal> {
        let object = self
            .state()?
            .objects
            .get(&identity)
            .cloned()
            .ok_or(StoreRefusal::ObjectAbsent)?;
        Ok(WholeObjectRead {
            object,
            placement: self.placement.clone(),
        })
    }

    fn read_range_verified(
        &self,
        identity: GitOid,
        range: ObjectRange,
    ) -> Result<VerifiedRangeRead, StoreRefusal> {
        let whole = self.read_whole(identity)?;
        let full_len = u64::try_from(whole.object.payload().len())
            .map_err(|_| StoreRefusal::LengthOverflow)?;
        if range.offset() != 0 || range.length() != full_len {
            return Err(StoreRefusal::PartialRangeUnverified);
        }
        Ok(VerifiedRangeRead {
            object_identity: identity,
            range,
            bytes: whole.object.payload().to_vec(),
            placement: whole.placement,
        })
    }

    fn write_manifest(
        &self,
        manifest: &SegmentManifest,
    ) -> Result<SegmentManifestId, StoreRefusal> {
        let identity = manifest.identity()?;
        self.fault_if(ReferenceFaultPoint::BeforeManifestInsert)?;
        self.state()?.manifests.insert(identity, manifest.clone());
        self.fault_if(ReferenceFaultPoint::AfterManifestInsert)?;
        Ok(identity)
    }

    fn read_manifest(&self, identity: SegmentManifestId) -> Result<SegmentManifest, StoreRefusal> {
        let manifest = self
            .state()?
            .manifests
            .get(&identity)
            .cloned()
            .ok_or(StoreRefusal::ObjectAbsent)?;
        let bytes = manifest.encode()?;
        SegmentManifest::decode_verified(&bytes, identity, &self.manifest_limits)
    }

    fn publish_retention_root<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        proposal: &RetentionRootProposal,
    ) -> Result<PublicationState, StoreRefusal> {
        registry.revalidate_root(proposal)?;
        let body = proposal.canonical_bytes()?;
        self.fault_if(ReferenceFaultPoint::BeforeRetentionBody)?;
        self.state()?
            .retention_bodies
            .insert(proposal.retention_root(), body);
        self.fault_if(ReferenceFaultPoint::AfterRetentionBody)?;
        self.fault_if(ReferenceFaultPoint::BeforeRetentionRoot)?;
        self.state()?
            .retention_roots
            .insert(proposal.authority_head(), proposal.retention_root());
        self.fault_if(ReferenceFaultPoint::AfterRetentionRoot)?;
        Ok(Self::staged_epochs())
    }

    fn delete_if_unretained<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        identity: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal> {
        registry.permits_placement_deletion(identity)?;
        if self.state()?.objects.remove(&identity).is_some() {
            Ok(DeletionReceipt::Deleted)
        } else {
            Ok(DeletionReceipt::AlreadyAbsent)
        }
    }
}

impl RuntimeImmutableObjectFabric for ReferenceMemoryFabric {
    fn open_verified_stream<'a>(
        &'a self,
        cx: &'a Cx,
        identity: GitOid,
        budget: VerifiedStreamBudget,
    ) -> impl std::future::Future<Output = Outcome<VerifiedObjectStream, StoreRefusal>> + 'a {
        async move {
            if let Some(outcome) = checkpoint_outcome(cx) {
                return outcome;
            }
            let whole = match self.read_whole(identity) {
                Ok(whole) => whole,
                Err(error) => return Outcome::Err(error),
            };
            if let Some(outcome) = checkpoint_outcome(cx) {
                return outcome;
            }
            match VerifiedObjectStream::new(whole, budget) {
                Ok(stream) => Outcome::Ok(stream),
                Err(error) => Outcome::Err(error),
            }
        }
    }
}

fn payload_identity(kind: ObjectKind, payload: &[u8]) -> Result<Digest, StoreRefusal> {
    let kind = match kind {
        ObjectKind::Commit => fgit_crypto::GitObjectKind::Commit,
        ObjectKind::Tree => fgit_crypto::GitObjectKind::Tree,
        ObjectKind::Blob => fgit_crypto::GitObjectKind::Blob,
        ObjectKind::Tag => fgit_crypto::GitObjectKind::Tag,
        ObjectKind::Internal => return Err(StoreRefusal::NativeObjectIdentityMismatch),
    };
    let identity = fgit_crypto::git_payload_commitment(kind, payload, CANONICAL_CODEC_VERSION);
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

fn object_envelope_id(object: &VerifiedObject) -> Result<ObjectEnvelopeId, StoreRefusal> {
    let body = object.envelope().encode()?;
    let identity = fgit_crypto::internal_object_id(
        fgit_crypto::IdentityDomain::ObjectEnvelope,
        ENVELOPE_SCHEMA,
        CANONICAL_CODEC_VERSION,
        &body,
    );
    ObjectEnvelopeId::from_internal_object_id(identity).map_err(StoreRefusal::from)
}

fn settle_admission_abort(
    reserved: ReservedObligation<ObjectAdmissionPermit>,
    reason: AdmissionAbortReason,
    spent: &ResourceVector,
) -> Result<(), StoreRefusal> {
    match reserved.abort(AdmissionAbandoned { reason }, spent) {
        Ok(_settled) => Ok(()),
        Err(refused) => {
            let error = refused.error();
            let reservation = refused.into_obligation();
            let _settled = reservation.abort_unused(AdmissionAbandoned { reason });
            Err(StoreRefusal::Settlement(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use asupersync::{CancelKind, Cx, Outcome};
    use fgit_resource::{LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId};
    use fgit_types::{
        DigestAlgorithmId, DigestBytes, GitHashAlgorithm, PublicationEpoch,
        RepositoryAuthorityHeadId,
    };

    use super::*;
    use crate::{
        CryptoDigest, MicrosegmentBuilder, ObjectEnvelope, SegmentLimits, SegmentRecordInput,
    };

    struct AllowRetention;

    impl AuthenticatedRetentionRegistry for AllowRetention {
        fn revalidate_root(&self, _proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
            Ok(())
        }

        fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
            Ok(())
        }
    }

    fn limits() -> SegmentLimits {
        SegmentLimits {
            max_segment_bytes: 4096,
            max_records: 16,
            max_namespace_bytes: 16,
            max_object_identity_bytes: 32,
            max_envelope_bytes: 256,
            max_record_bytes: 512,
        }
    }

    fn manifest_limits() -> crate::fabric::ManifestLimits {
        crate::fabric::ManifestLimits {
            max_namespace_bytes: 16,
            max_entries: 16,
            max_placements: 16,
        }
    }

    fn fabric(fault: Option<ReferenceFaultPoint>) -> ReferenceMemoryFabric {
        let config = ReferenceMemoryConfig::new(
            vec![b'n'],
            OpaqueHandle::new(b"reference-rack").expect("test failure domain must fit"),
            OpaqueHandle::new(b"reference-key").expect("test key dependency must fit"),
            4096,
            manifest_limits(),
        )
        .expect("test reference configuration must be valid");
        let config = match fault {
            Some(point) => config.with_fault_injection(point),
            None => config,
        };
        ReferenceMemoryFabric::open(config).expect("test reference fabric must open")
    }

    fn object(payload: &[u8]) -> VerifiedObject {
        let native = fgit_crypto::git_object_id(
            GitHashAlgorithm::Sha1,
            fgit_crypto::GitObjectKind::Blob,
            payload,
        );
        let commitment = fgit_crypto::git_payload_commitment(
            fgit_crypto::GitObjectKind::Blob,
            payload,
            CANONICAL_CODEC_VERSION,
        );
        let mut commitment_bytes = [0; 32];
        commitment_bytes.copy_from_slice(commitment.digest().as_bytes());
        let envelope = ObjectEnvelope::new(
            vec![b'n'],
            native,
            ObjectKind::Blob,
            u64::try_from(payload.len()).expect("test payload length must fit"),
            commitment_bytes,
            b"raw".to_vec(),
            [9; 32],
            None,
            &limits(),
        )
        .expect("test envelope must be valid");
        VerifiedObject::new(envelope, payload.to_vec()).expect("test object must verify")
    }

    fn ledger() -> ObligationLedger {
        ObligationLedger::root(
            RegionId::new(2),
            LeakDisposition::RecordAndContinue,
            ResourceVector::from_grades(&[(Grade::Bytes, 4096), (Grade::Objects, 16)]),
        )
    }

    fn admission<'a>(
        ledger: &'a ObligationLedger,
        object: &VerifiedObject,
    ) -> PlacementAdmission<'a> {
        let grant = ledger
            .grant(ResourceVector::from_grades(&[
                (
                    Grade::Bytes,
                    u64::try_from(object.payload().len()).expect("test length must fit"),
                ),
                (Grade::Objects, 1),
            ]))
            .expect("test grant must succeed");
        PlacementAdmission::new(ledger, grant)
    }

    fn assert_quiescent(ledger: ObligationLedger) {
        assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
    }

    #[test]
    fn reference_profile_is_non_durable_and_preserves_the_immutable_algebra() {
        let fabric = fabric(None);
        let object = object(b"payload");
        let ledger = ledger();
        let created = fabric
            .put_if_absent(object.clone(), admission(&ledger, &object))
            .expect("reference placement must create a verified object");
        assert!(matches!(
            created,
            PutIfAbsent::Created { placement, epochs }
                if placement.backend() == PlacementBackend::MemoryReference
                    && epochs.contains(PublicationEpoch::Staged)
                    && !epochs.contains(PublicationEpoch::Visible)
                    && !epochs.contains(PublicationEpoch::Durable)
        ));
        let second = fabric
            .put_if_absent(object.clone(), admission(&ledger, &object))
            .expect("identical reference placement must be idempotent");
        assert!(matches!(second, PutIfAbsent::AlreadyPresent { .. }));
        assert_eq!(
            fabric.read_whole(object.identity()),
            Ok(WholeObjectRead {
                object: object.clone(),
                placement: fabric.placement.clone(),
            })
        );
        let partial = ObjectRange::new(1, 1, 7).expect("partial range must be bounded");
        assert_eq!(
            fabric.read_range_verified(object.identity(), partial),
            Err(StoreRefusal::PartialRangeUnverified)
        );

        let digest = CryptoDigest;
        let mut builder = MicrosegmentBuilder::new(&digest, limits());
        builder
            .push(SegmentRecordInput {
                envelope: object.envelope().clone(),
                payload: object.payload().to_vec(),
            })
            .expect("segment record must be accepted");
        let segment = builder.build().expect("segment must build");
        let reader = crate::MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("segment must verify");
        let manifest =
            SegmentManifest::from_verified_segment(&reader, Vec::new(), &manifest_limits())
                .expect("verified segment must form a manifest");
        let manifest_id = fabric
            .write_manifest(&manifest)
            .expect("reference manifest write must succeed");
        assert_eq!(
            fabric
                .read_manifest(manifest_id)
                .expect("reference manifest identity must verify"),
            manifest
        );

        let algorithm = DigestAlgorithmId::try_new(2).expect("sha-256 code point is valid");
        let proposal = RetentionRootProposal::new(
            RepositoryAuthorityHeadId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[5; 32]).expect("test digest must fit"),
            ),
            Digest::new(
                algorithm,
                DigestBytes::try_new(&[6; 32]).expect("test digest must fit"),
            ),
            Vec::new(),
        )
        .expect("test retention proposal must be canonical");
        let epochs = fabric
            .publish_retention_root(&AllowRetention, &proposal)
            .expect("current retention evidence must publish to reference state");
        assert!(epochs.contains(PublicationEpoch::Staged));
        assert!(!epochs.contains(PublicationEpoch::Visible));
        assert!(!epochs.contains(PublicationEpoch::Durable));
        assert_eq!(
            fabric
                .delete_if_unretained(&AllowRetention, object.identity())
                .expect("unretained object must delete"),
            DeletionReceipt::Deleted
        );
        assert_eq!(
            fabric
                .delete_if_unretained(&AllowRetention, object.identity())
                .expect("double delete must be idempotent"),
            DeletionReceipt::AlreadyAbsent
        );
        assert_quiescent(ledger);
    }

    #[test]
    fn reference_fault_after_insert_exposes_only_a_complete_verified_object() {
        let fabric = fabric(Some(ReferenceFaultPoint::AfterObjectInsert));
        let object = object(b"payload");
        let ledger = ledger();
        assert_eq!(
            fabric.put_if_absent(object.clone(), admission(&ledger, &object)),
            Err(StoreRefusal::ReferenceFaultInjected {
                point: ReferenceFaultPoint::AfterObjectInsert,
            })
        );
        assert_eq!(
            fabric
                .read_whole(object.identity())
                .expect("fault cannot expose a partial reference object")
                .object,
            object
        );
        assert_quiescent(ledger);
    }

    #[test]
    fn reference_stream_preserves_cancellation_before_emission() {
        let fabric = fabric(None);
        let object = object(b"payload");
        let ledger = ledger();
        fabric
            .put_if_absent(object.clone(), admission(&ledger, &object))
            .expect("reference placement must succeed");
        let whole = fabric
            .read_whole(object.identity())
            .expect("whole object must verify");
        let mut stream = VerifiedObjectStream::new(
            whole,
            VerifiedStreamBudget::new(7, 3).expect("stream bounds must be finite"),
        )
        .expect("verified object must fit stream budget");
        let cancelled = Cx::detached_cancel_context();
        cancelled.cancel_with(CancelKind::User, Some("reference stream cancellation"));
        assert!(matches!(
            stream.next_chunk(&cancelled),
            Outcome::Cancelled(_)
        ));
        assert_quiescent(ledger);
    }
}
