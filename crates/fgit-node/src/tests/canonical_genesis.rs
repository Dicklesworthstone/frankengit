//! Canonical empty delivery maps are durable before a new node publishes genesis.
//! The native read counter isolates delivery from closure and outcome replay.

use super::*;
use fgit_admission::merge::native::delivery;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken, CasOutcome,
    HeadKey, HeadReadReceipt, ImmutableKey, PutOutcome, StoreInstanceId,
};
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, encode_body};
use fgit_types::HeadGeneration;
use fgit_types::layout::RootLayoutVersion;
use std::sync::Mutex;

struct Observe<'a> {
    node: &'a OneNode,
    reads: Mutex<Vec<ImmutableKey>>,
    puts: AtomicUsize,
    cancel_after_put: Option<usize>,
    replace_read: Option<(ImmutableKey, Option<Vec<u8>>)>,
}

impl<'a> Observe<'a> {
    fn new(node: &'a OneNode) -> Self {
        Self {
            node,
            reads: Mutex::new(Vec::new()),
            puts: AtomicUsize::new(0),
            cancel_after_put: None,
            replace_read: None,
        }
    }
}

impl AsyncAuthorityStore for Observe<'_> {
    type Context = FsqliteCx;

    fn instance_id(&self) -> StoreInstanceId {
        AsyncAuthorityStore::instance_id(&self.node.authority)
    }

    fn limits(&self) -> AuthorityLimits {
        AsyncAuthorityStore::limits(&self.node.authority)
    }

    async fn read_immutable(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.reads.lock().unwrap().push(key.clone());
        if let Some((target, replacement)) = &self.replace_read
            && target == key
        {
            return Ok(match replacement {
                Some(bytes) => ImmutableRead::Present(bytes.clone()),
                None => ImmutableRead::Absent,
            });
        }
        AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await
    }

    async fn put_if_absent(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        let result = AsyncAuthorityStore::put_if_absent(&self.node.authority, cx, key, body).await;
        let count = self.puts.fetch_add(1, Ordering::Relaxed) + 1;
        if self.cancel_after_put == Some(count) {
            cx.cancel();
        }
        result
    }

    async fn initialize_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        AsyncAuthorityStore::initialize_head(&self.node.authority, cx, key, generation, body).await
    }

    async fn read_head(&self, cx: &FsqliteCx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        AsyncAuthorityStore::read_head(&self.node.authority, cx, key).await
    }

    async fn compare_exchange_head(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        AsyncAuthorityStore::compare_exchange_head(
            &self.node.authority,
            cx,
            key,
            expected,
            generation,
            body,
        )
        .await
    }

    async fn authenticate_head_receipt(
        &self,
        cx: &FsqliteCx,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        AsyncAuthorityStore::authenticate_head_receipt(&self.node.authority, cx, receipt).await
    }
}

fn canonical_roots(repository: RepositoryId) -> (Digest, Digest) {
    (
        CanonicalForgePositionState::try_new(repository, Vec::new())
            .unwrap()
            .root()
            .unwrap(),
        CanonicalOutboxState::try_new(repository, Vec::new())
            .unwrap()
            .root()
            .unwrap(),
    )
}

fn selected(node: &OneNode) -> crate::MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
}

fn read_empty_delivery(node: &OneNode, basis: &PublicationBasis) -> Vec<ImmutableKey> {
    let observed = Observe::new(node);
    let request = node.request_context();
    let state = node
        .runtime()
        .block_on(delivery::read_in(
            &observed,
            request.authority(),
            basis,
            &|| request.authority().checkpoint().is_err(),
        ))
        .unwrap();
    assert!(state.forge.entries().is_empty());
    assert!(state.outbox.entries().is_empty());
    assert_eq!(
        state.forge.root().unwrap(),
        basis.body().forge_position_root
    );
    assert_eq!(state.outbox.root().unwrap(), basis.body().outbox_root);
    let reads = observed.reads.lock().unwrap().clone();
    assert_eq!(
        reads.len(),
        2,
        "canonical empty delivery resolves two bodies and never traverses the bounded legacy history"
    );
    assert!(
        reads[0]
            .as_bytes()
            .starts_with(b"frankengit/admission/forge-position-state/v1/")
    );
    assert!(reads[1].as_bytes().starts_with(delivery::OUTBOX_NAMESPACE));
    reads
}

fn publish_tag(node: &OneNode) -> GitOid {
    let oid = put_object(
        node,
        fgit_git_object::ObjectType::Blob,
        b"canonical genesis remains selected\n".to_vec(),
    );
    let old = GitOid::from_hex(
        node.object_format(),
        &"00".repeat(if node.object_format() == GitHashAlgorithm::Sha1 {
            20
        } else {
            32
        }),
    )
    .unwrap();
    let objects = BTreeSet::from([oid]);
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old,
            new: oid,
            ref_name: b"refs/tags/canonical-genesis".to_vec(),
        }],
        &SourceImportReceipt {
            object_format: node.object_format(),
            object_count: 1,
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        },
        ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))
            .unwrap(),
            objects,
        },
    )
    .unwrap();
    let (context, _, _) = evidence_request(node);
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    oid
}

#[test]
fn ref_only_genesis_and_cold_reopen_resolve_delivery_without_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV1,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        ] {
            let scratch = ScratchDirectory::new();
            let config = test_config(scratch.path().to_path_buf())
                .with_object_format(format)
                .with_root_layout(layout);
            let (node, initialized) = OneNode::init(config.clone()).unwrap();
            assert_eq!(initialized, NodeInitialization::Created);
            let before = selected(&node);
            let roots = canonical_roots(node.repository_id());
            assert_eq!(before.basis().body().forge_position_root, roots.0);
            assert_eq!(before.basis().body().outbox_root, roots.1);
            assert_ne!(
                roots.0,
                genesis_root(node.repository_id(), b"forge-position")
            );
            assert_ne!(roots.1, genesis_root(node.repository_id(), b"outbox"));
            read_empty_delivery(&node, before.basis());
            node.shutdown().unwrap();

            let (mut node, initialized) = OneNode::init(config.clone()).unwrap();
            assert_eq!(initialized, NodeInitialization::IdenticalRetry);
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let oid = publish_tag(&node);
            let after = selected(&node);
            assert_eq!(
                after.basis().generation().get(),
                before.basis().generation().get() + 1
            );
            assert_eq!(after.basis().body().forge_position_root, roots.0);
            assert_eq!(after.basis().body().outbox_root, roots.1);
            read_empty_delivery(&node, after.basis());
            node.shutdown().unwrap();

            let node = OneNode::open_existing(config).unwrap();
            let reopened = selected(&node);
            assert_eq!(reopened.basis(), after.basis());
            assert_eq!(reopened.snapshot().refs, after.snapshot().refs);
            assert_eq!(
                reopened
                    .snapshot()
                    .refs
                    .get(&RefName::try_new(b"refs/tags/canonical-genesis").unwrap()),
                Some(&oid)
            );
            assert_eq!(reopened.root_layout(), layout);
            read_empty_delivery(&node, reopened.basis());
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn missing_or_foreign_canonical_delivery_bodies_are_never_treated_as_empty() {
    let scratch = ScratchDirectory::new();
    let (mut node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    publish_tag(&node);
    let current = selected(&node);
    let keys = read_empty_delivery(&node, current.basis());
    let other = RepositoryId::from_bytes([0xee; 16]);

    for (index, key) in keys.into_iter().enumerate() {
        let foreign = if index == 0 {
            encode_body(&CanonicalForgePositionState::try_new(other, Vec::new()).unwrap()).unwrap()
        } else {
            encode_body(&CanonicalOutboxState::try_new(other, Vec::new()).unwrap()).unwrap()
        };
        for replacement in [
            None,
            Some(foreign),
            Some(b"invalid canonical frame".to_vec()),
        ] {
            let missing = replacement.is_none();
            let mut observed = Observe::new(&node);
            observed.replace_read = Some((key.clone(), replacement));
            let request = node.request_context();
            let result = node.runtime().block_on(delivery::read_in(
                &observed,
                request.authority(),
                current.basis(),
                &|| false,
            ));
            let expected = if missing && index == 1 {
                RefusalCode::EvidenceMissing
            } else {
                RefusalCode::EvidenceInvalid
            };
            assert!(matches!(
                result,
                Err(AdmissionError::AsyncProjectionUnavailable(code)) if code == expected
            ));
        }
    }

    assert_eq!(selected(&node).basis(), current.basis());
    read_empty_delivery(&node, current.basis());
    node.shutdown().unwrap();
}

#[test]
fn cancelled_empty_map_staging_publishes_no_head_and_retries_identically() {
    for boundary in 0..=2 {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let node = OneNode::open_components(config.clone()).unwrap();
        let cx = node.authority_context();
        let mut observed = Observe::new(&node);
        observed.cancel_after_put = Some(boundary);
        if boundary == 0 {
            cx.cancel();
        }
        let stopped = node.runtime().block_on(delivery::stage_empty_in(
            &observed,
            &cx,
            node.repository_id(),
            &|| cx.checkpoint().is_err(),
        ));
        assert!(matches!(
            stopped,
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::CancellationInProgress
            ))
        ));
        assert_eq!(observed.puts.load(Ordering::Relaxed), boundary);
        drop(observed);
        assert!(matches!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            HeadRead::Absent
        ));
        let retry_cx = node.authority_context();
        let roots = node
            .runtime()
            .block_on(delivery::stage_empty_in(
                &node.authority,
                &retry_cx,
                node.repository_id(),
                &|| retry_cx.checkpoint().is_err(),
            ))
            .unwrap();
        assert_eq!(roots, canonical_roots(node.repository_id()));
        assert!(matches!(
            node.runtime().block_on(node.read_authority_head()).unwrap(),
            HeadRead::Absent
        ));
        node.shutdown().unwrap();

        let (node, initialized) = OneNode::init(config).unwrap();
        assert_eq!(initialized, NodeInitialization::Created);
        read_empty_delivery(&node, selected(&node).basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn conflicting_outbox_staging_prevents_genesis_publication() {
    let scratch = ScratchDirectory::new();
    let config = test_config(scratch.path().to_path_buf());
    let node = OneNode::open_components(config.clone()).unwrap();
    let (_, root) = canonical_roots(node.repository_id());
    let key =
        admission_immutable_key(delivery::OUTBOX_NAMESPACE, node.repository_id(), root).unwrap();
    let cx = node.authority_context();
    assert_eq!(
        node.runtime()
            .block_on(
                node.authority
                    .put_if_absent(&cx, &key, b"conflicting immutable frame")
            )
            .unwrap(),
        PutOutcome::Created
    );
    node.shutdown().unwrap();

    let error = OneNode::init(config.clone()).unwrap_err();
    let NodeRefusal::AdmissionMaterialization(error) = error else {
        panic!("expected a canonical staging refusal: {error:?}");
    };
    let AdmissionMaterializationRefusal::Delivery(error) = *error else {
        panic!("expected a delivery staging refusal: {error:?}");
    };
    assert!(matches!(
        *error,
        AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceInvalid)
    ));

    let node = OneNode::open_components(config).unwrap();
    assert!(matches!(
        node.runtime().block_on(node.read_authority_head()).unwrap(),
        HeadRead::Absent
    ));
    node.shutdown().unwrap();
}

fn initialize_legacy(config: NodeConfig) -> OneNode {
    let node = OneNode::open_components(config).unwrap();
    let cx = node.authority_context();
    let configuration = fgit_codec::RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: node.service_config.root_layout,
        object_format: node.object_format(),
        repository_incarnation_id: node.repository_incarnation_id,
        policy_root: None,
    };
    let configuration_root = node
        .runtime()
        .block_on(
            fgit_authority::stage_latest_repository_incarnation_configuration_async(
                &node.authority,
                &cx,
                &configuration,
            ),
        )
        .unwrap();
    let refs = crate::genesis_ref_state_for(node.service_config.initial_branch.clone()).unwrap();
    let ref_root = node
        .runtime()
        .block_on(node.admission_materializer.stage_ref_state_for_layout_in(
            &node.authority,
            &cx,
            node.repository_id(),
            configuration.root_layout,
            refs,
        ))
        .unwrap();
    node.runtime()
        .block_on(
            node.admission_materializer
                .stage_permitted_object_closure_in(
                    &node.authority,
                    &cx,
                    node.repository_id(),
                    PermittedObjectClosure::default(),
                ),
        )
        .unwrap();
    let legacy = genesis_head(node.repository_id(), ref_root, configuration_root).unwrap();
    assert!(matches!(
        initialize_embedded_repository(
            node.runtime(),
            &node.authority,
            &cx,
            &node.head_key,
            &legacy,
        )
        .unwrap(),
        HeadInit::Created(_)
    ));
    node
}

#[test]
fn exact_legacy_genesis_retries_without_migration_or_custom_head_changes() {
    let scratch = ScratchDirectory::new();
    let initial_branch = RefName::try_new(b"refs/heads/trunk").unwrap();
    let config = test_config(scratch.path().to_path_buf())
        .with_object_format(GitHashAlgorithm::Sha256)
        .with_root_layout(RootLayoutVersion::RefStateMerkleV1)
        .with_initial_branch(initial_branch.clone());
    let node = initialize_legacy(config.clone());
    let before = selected(&node);
    assert_eq!(before.snapshot().head_target, Some(initial_branch.clone()));
    assert_eq!(
        before.basis().body().forge_position_root,
        genesis_root(node.repository_id(), b"forge-position")
    );
    node.shutdown().unwrap();

    let (node, initialized) = OneNode::init(config.clone()).unwrap();
    assert_eq!(initialized, NodeInitialization::IdenticalRetry);
    let retried = selected(&node);
    assert_eq!(retried.basis(), before.basis());
    assert_eq!(retried.snapshot().head_target, Some(initial_branch));
    assert_eq!(retried.root_layout(), RootLayoutVersion::RefStateMerkleV1);
    node.shutdown().unwrap();

    assert!(matches!(
        OneNode::init(
            config
                .clone()
                .with_initial_branch(RefName::try_new(b"refs/heads/different").unwrap())
        ),
        Err(NodeRefusal::HeadInitializationConflict)
    ));
    let node = OneNode::open_existing(config).unwrap();
    assert_eq!(selected(&node).basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn reinitializing_with_another_initial_branch_is_an_initialization_conflict_in_every_layout() {
    let trunk = RefName::try_new(b"refs/heads/trunk").unwrap();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV1,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        ] {
            for legacy in [false, true] {
                let case = format!("{format:?} {layout:?} legacy genesis {legacy}");
                let scratch = ScratchDirectory::new();
                let unnamed = test_config(scratch.path().to_path_buf())
                    .with_object_format(format)
                    .with_root_layout(layout);
                let config = unnamed.clone().with_initial_branch(trunk.clone());
                let node = if legacy {
                    initialize_legacy(config.clone())
                } else {
                    let (node, initialized) = OneNode::init(config.clone()).unwrap();
                    assert_eq!(initialized, NodeInitialization::Created, "{case}");
                    node
                };
                let before = selected(&node);
                node.shutdown().unwrap();

                let (node, initialized) = OneNode::init(config.clone()).unwrap();
                assert_eq!(initialized, NodeInitialization::IdenticalRetry, "{case}");
                assert_eq!(selected(&node).basis(), before.basis(), "{case}");
                node.shutdown().unwrap();

                for other in [
                    unnamed.clone(),
                    config
                        .clone()
                        .with_initial_branch(RefName::try_new(b"refs/heads/different").unwrap()),
                ] {
                    assert!(
                        matches!(
                            OneNode::init(other),
                            Err(NodeRefusal::HeadInitializationConflict)
                        ),
                        "{case}"
                    );
                }

                let node = OneNode::open_existing(config.clone()).unwrap();
                let after = selected(&node);
                assert_eq!(after.basis(), before.basis(), "{case}");
                assert_eq!(after.snapshot().head_target, Some(trunk.clone()), "{case}");
                node.shutdown().unwrap();
            }
        }
    }
}

#[test]
fn reinitializing_an_advanced_repository_is_an_initialization_conflict() {
    for layout in [
        RootLayoutVersion::LegacyWholeBody,
        RootLayoutVersion::RefStateMerkleV1,
    ] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf()).with_root_layout(layout);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let oid = publish_tag(&node);
        let advanced = selected(&node);
        node.shutdown().unwrap();

        assert!(
            matches!(
                OneNode::init(config.clone()),
                Err(NodeRefusal::HeadInitializationConflict)
            ),
            "{layout:?}"
        );
        let node = OneNode::open_existing(config).unwrap();
        let reopened = selected(&node);
        assert_eq!(reopened.basis(), advanced.basis(), "{layout:?}");
        assert_eq!(
            reopened
                .snapshot()
                .refs
                .get(&RefName::try_new(b"refs/tags/canonical-genesis").unwrap()),
            Some(&oid),
            "{layout:?}"
        );
        node.shutdown().unwrap();
    }
}
