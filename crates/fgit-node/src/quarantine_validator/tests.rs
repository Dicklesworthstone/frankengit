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
                // The processing-deadline wrapper is added only by the outer
                // git-daemon transport after this conversion has returned. A
                // direct ReceiveError conversion cannot synthesize it.
                NodeReceiveTransportRefusal::ReceiveProcessingDeadlineExceeded {
                    timeout,
                    source,
                } => panic!(
                    "a receive-core refusal must not be pre-wrapped as a processing timeout ({:?}): {source}",
                    timeout.duration()
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
        assert_eq!(suffix.len(), 1, "fixture has one literal suffix");
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

mod external_budget;
