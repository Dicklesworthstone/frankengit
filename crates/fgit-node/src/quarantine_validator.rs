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
    PermittedObjectClosure, QuarantineValidator, ValidatedClosure, permitted_object_closure_root,
};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits};
use fgit_pack::{
    CachedResolver, Deadline, ExternalBaseLookup, ObjectId, PackError, PackLimits, ParsedDeltaBase,
    QuarantinedPack, verify_native_object,
};
use fgit_types::{GitOid, RefusalCode};
use fgit_wire::receive::{QuarantineReceipt, ReceiveRequest};

use crate::{
    AuthoritySelectedClosure, MaterializedAdmission, NodeRefusal, OneNode, crypto_object_kind,
};

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

    fn load_external_base(
        &self,
        id: ObjectId,
        deadline: &mut impl Deadline,
    ) -> Result<ExternalBase, RefusalCode> {
        checkpoint(deadline)?;
        if !self.selected_closure.closure().objects().contains(&id) {
            return Err(RefusalCode::ThinPackBaseMissing);
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
        Ok(ExternalBase { object_type, body })
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
            let loaded = self.load_external_base(*base, deadline)?;
            bases.insert(*base, loaded);
        }
        Ok(ExternalBases { bases })
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
        // The receive quarantine has no trusted index association for pack
        // offsets.  Delta IDs are therefore resolved only through the
        // authority-selected external-base set; every returned object is
        // authenticated below before staging.
        let objects = pack
            .clone()
            .into_scalar_objects(|_| None)
            .map_err(map_pack_error)?;
        let mut resolver = CachedResolver::new(&objects, &bases, &self.pack_limits, deadline)
            .map_err(map_pack_error)?;
        let mut verified = Vec::new();
        verified
            .try_reserve_exact(pack.entries().len())
            .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
        let mut closure = BTreeSet::new();
        for entry in pack.entries() {
            checkpoint(deadline)?;
            let (object_type, body) = resolver
                .resolve_offset_typed(entry.offset, deadline)
                .map_err(map_pack_error)?;
            let id = fgit_crypto::git_object_id(
                self.node.object_format,
                crypto_object_kind(object_type),
                &body,
            );
            verify_native_object(
                self.node.object_format,
                object_type,
                &body,
                &id,
                AcceptanceProfile::GitCompatibleImport,
                &self.parse_limits,
            )
            .map_err(map_pack_error)?;
            closure.insert(id);
            verified.push((id, object_type, body));
        }
        // This second phase keeps a later malformed delta from leaving earlier
        // pack objects in fabric.  Immutable placement remains non-authority,
        // but only a fully validated pack may acquire that responsibility.
        for (id, object_type, body) in verified {
            self.stage(id, object_type, body, deadline)?;
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

fn map_pack_error(error: PackError) -> RefusalCode {
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
    use fgit_wire::receive::{ReceiveCommand, ReceiveRequest};
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
        program.extend_from_slice(suffix);
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
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
        node.shutdown().expect("node shuts down after test");
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
