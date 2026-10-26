//! Native read accounting and adversarial equivalence for the closure prefix.
//! Real node storage, publication and history verification are used throughout.

use super::*;
use crate::{
    ADMISSION_REF_STATE_KEY_PREFIX, AuthoritySelectedClosure, DurableAdmissionMaterializer,
    MaterializedAdmission, admission_cache_scope, select_authority_closure_in,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken, CasOutcome,
    HeadKey, HeadReadReceipt, ImmutableKey, PutOutcome, StoreInstanceId, body_key, body_key_for_id,
};
use fgit_chronicle::{
    BackupProfile, CapsuleClosure, activate_frozen_capsule_async, freeze_capsule_async,
};
use fgit_crypto::IdentityDomain;
use fgit_types::HeadGeneration;
use std::sync::{Arc, Mutex, mpsc};

fn cache() -> DurableAdmissionMaterializer {
    DurableAdmissionMaterializer::new(admission_cache_scope().unwrap())
}

fn zero(node: &OneNode) -> GitOid {
    GitOid::from_hex(
        node.object_format(),
        &"00".repeat(if node.object_format() == GitHashAlgorithm::Sha1 {
            20
        } else {
            32
        }),
    )
    .unwrap()
}

fn update(node: &OneNode, key: &str, name: &str, old: GitOid, new: GitOid) -> DecisionOutcome {
    let objects = if new.is_zero() {
        BTreeSet::new()
    } else {
        BTreeSet::from([new])
    };
    let receipt = SourceImportReceipt {
        object_format: node.object_format(),
        object_count: u32::try_from(objects.len()).unwrap(),
        delete_only: new.is_zero(),
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old,
            new,
            ref_name: name.as_bytes().to_vec(),
        }],
        &receipt,
        ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))
            .unwrap(),
            objects,
        },
    )
    .unwrap();
    let (mut context, _, _) = evidence_request(node);
    context.object_format = node.object_format();
    context.idempotency_key = fgit_authority::IdempotencyKey::new(key.as_bytes().to_vec()).unwrap();
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
    result.commands[0].terminal.outcome
}

fn add(node: &OneNode, index: usize) -> GitOid {
    let blob = put_object(
        node,
        fgit_git_object::ObjectType::Blob,
        format!("closure object {index}\n").into_bytes(),
    );
    assert!(matches!(
        update(
            node,
            &format!("closure-{index}"),
            &format!("refs/tags/closure-{index}"),
            zero(node),
            blob
        ),
        DecisionOutcome::Committed { .. }
    ));
    blob
}

fn selected<S: AsyncAuthorityStore<Context = FsqliteCx>>(
    materializer: &DurableAdmissionMaterializer,
    node: &OneNode,
    store: &S,
) -> Result<MaterializedAdmission, AdmissionMaterializationRefusal> {
    let request = node.request_context();
    node.runtime().block_on(materializer.materialize_current_in(
        store,
        request.authority(),
        &node.head_key,
        node.repository_id(),
        &|| request.authority().checkpoint().is_err(),
    ))
}

/// Account for this projection alone: native delivery also verifies legacy
/// empty forge/outbox roots against history and is deliberately not cached by
/// the closure selector.
fn project(
    materializer: &DurableAdmissionMaterializer,
    node: &OneNode,
    selected: &MaterializedAdmission,
    store: &Observe<'_>,
) -> AuthoritySelectedClosure {
    let request = node.request_context();
    let prefix = materializer
        .closure_prefix_for(
            store.instance_id(),
            selected.authenticated(),
            selected.basis(),
        )
        .unwrap();
    let refs = CanonicalRefState::new(selected.snapshot().refs.clone());
    node.runtime().block_on(async {
        let selection = crate::closure_selection::select_in(
            store,
            request.authority(),
            selected.basis(),
            &refs,
            prefix,
            &|| false,
        )
        .await
        .unwrap();
        selection
            .materialize_in(store, request.authority(), node.repository_id(), &|| false)
            .await
            .unwrap()
            .0
    })
}

/// Keep the old genesis walker as an independent selection oracle. This reads
/// and verifies every selected closure frame, without consulting either cache.
fn original_walk(node: &OneNode, selected: &MaterializedAdmission) -> AuthoritySelectedClosure {
    let request = node.request_context();
    let refs = CanonicalRefState::new(selected.snapshot().refs.clone());
    let (roots, source) = node
        .runtime()
        .block_on(select_authority_closure_in(
            &node.authority,
            request.authority(),
            selected.basis().body().clone(),
            &refs,
            &|| false,
        ))
        .unwrap();
    let mut objects = BTreeSet::new();
    if source != ClosureSelectionSource::EmptyGenesis {
        for root in roots {
            let key =
                admission_immutable_key(ADMISSION_CLOSURE_KEY_PREFIX, node.repository_id(), root)
                    .unwrap();
            let ImmutableRead::Present(bytes) = node
                .runtime()
                .block_on(AsyncAuthorityStore::read_immutable(
                    &node.authority,
                    request.authority(),
                    &key,
                ))
                .unwrap()
            else {
                panic!("every oracle-selected closure is staged");
            };
            let closure: PermittedObjectClosure =
                decode_body(&bytes, fgit_codec::DecodeLimits::DEFAULT).unwrap();
            assert_eq!(permitted_object_closure_root(&closure).unwrap(), root);
            objects.extend(closure.objects().iter().copied());
        }
    }
    let closure = PermittedObjectClosure::new(objects);
    AuthoritySelectedClosure {
        root: permitted_object_closure_root(&closure).unwrap(),
        closure,
        source,
    }
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Corrupt,
    Cancel,
}

struct Observe<'a> {
    node: &'a OneNode,
    reads: Mutex<Vec<ImmutableKey>>,
    target: Option<ImmutableKey>,
    fault: Fault,
    gate: Option<&'a ReadGate>,
}

struct ReadGate {
    reached: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl<'a> Observe<'a> {
    const fn new(node: &'a OneNode) -> Self {
        Self {
            node,
            reads: Mutex::new(Vec::new()),
            target: None,
            fault: Fault::None,
            gate: None,
        }
    }
    fn count_domain(&self, domain: &[u8]) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|key| {
                key.as_bytes()
                    .windows(domain.len())
                    .any(|window| window == domain)
            })
            .count()
    }
    fn history_reads(&self) -> usize {
        self.count_domain(b"frankengit/decision-batch/v1")
    }
    fn closure_reads(&self) -> usize {
        self.count_domain(ADMISSION_CLOSURE_KEY_PREFIX)
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
        let result = AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await;
        if self.target.as_ref() == Some(key) {
            if let Some(gate) = self.gate {
                gate.reached.send(()).unwrap();
                gate.release.lock().unwrap().recv().unwrap();
            }
            match self.fault {
                Fault::None => {}
                Fault::Corrupt => {
                    return Ok(ImmutableRead::Present(b"invalid history bytes".to_vec()));
                }
                Fault::Cancel => cx.cancel(),
            }
        }
        result
    }
    async fn put_if_absent(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        AsyncAuthorityStore::put_if_absent(&self.node.authority, cx, key, body).await
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

#[test]
fn genesis_warming_does_not_invent_a_committed_empty_closure() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let materializer = cache();
    let genesis_reads = Observe::new(&node);
    let genesis = selected(&materializer, &node, &genesis_reads).unwrap();
    assert_eq!(
        genesis.selected_closure().source(),
        ClosureSelectionSource::EmptyGenesis
    );
    assert_eq!(genesis.selected_closure(), &original_walk(&node, &genesis));
    assert!(genesis.selected_closure().closure().objects().is_empty());
    assert_eq!(genesis_reads.history_reads(), 0);
    assert_eq!(genesis_reads.closure_reads(), 0);
    assert!(
        materializer
            .materialized
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .closure_roots
            .is_empty()
    );
    let object = add(&node, 0);
    let current = selected(&cache(), &node, &node.authority).unwrap();
    let suffix_reads = Observe::new(&node);
    let projected = project(&materializer, &node, &current, &suffix_reads);
    assert_eq!(&projected, current.selected_closure());
    assert_eq!(projected.closure().objects(), &BTreeSet::from([object]));
    assert!(matches!(
        projected.source(),
        ClosureSelectionSource::RepositoryCommit(_)
    ));
    assert_eq!(suffix_reads.history_reads(), 1);
    assert_eq!(suffix_reads.closure_reads(), 1);
    node.shutdown().unwrap();
}

#[test]
fn warm_closure_reads_only_the_verified_suffix_and_matches_the_original_walk() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf()).with_object_format(format);
        let (node, _) = OneNode::init(config.clone()).unwrap();
        let materializer = cache();
        for index in 0..12 {
            add(&node, index);
        }
        selected(&materializer, &node, &node.authority).unwrap();
        for index in 12..15 {
            add(&node, index);
        }
        let cold = selected(&cache(), &node, &node.authority).unwrap();
        let warm_store = Observe::new(&node);
        let warm_projection = project(&materializer, &node, &cold, &warm_store);
        let cold_store = Observe::new(&node);
        let cold_projection = project(&cache(), &node, &cold, &cold_store);
        assert_eq!(warm_projection, cold_projection);
        assert_eq!(&warm_projection, cold.selected_closure());
        assert_eq!(warm_projection, original_walk(&node, &cold));
        assert_eq!(
            warm_store.history_reads(),
            3,
            "only the three new decision batches are read"
        );
        assert_eq!(
            warm_store.closure_reads(),
            3,
            "old verified closure frames are not reread"
        );
        assert_eq!(
            cold_store.history_reads(),
            15,
            "cold-cache negative control walks the complete history"
        );
        assert_eq!(cold_store.closure_reads(), 15);
        let warm = selected(&materializer, &node, &node.authority).unwrap();
        assert_eq!(warm.selected_closure(), cold.selected_closure());
        assert_eq!(warm.snapshot(), cold.snapshot());
        let repeated_store = Observe::new(&node);
        assert_eq!(
            project(&materializer, &node, &warm, &repeated_store),
            warm_projection
        );
        assert_eq!(repeated_store.history_reads(), 0);
        assert_eq!(repeated_store.closure_reads(), 0);
        let repeated_materialization = Observe::new(&node);
        let repeated = selected(&materializer, &node, &repeated_materialization).unwrap();
        assert_eq!(repeated.selected_closure(), warm.selected_closure());
        assert_eq!(repeated_materialization.closure_reads(), 0);
        assert!(
            repeated_materialization.count_domain(crate::ADMISSION_REF_STATE_KEY_PREFIX) > 0,
            "current ref state is still authenticated independently"
        );
        let expected = warm.selected_closure().clone();
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(config).unwrap();
        assert_eq!(
            selected(&cache(), &reopened, &reopened.authority)
                .unwrap()
                .selected_closure(),
            &expected
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn deletes_refusals_repeated_roots_and_checkpoints_preserve_the_cumulative_union() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let original = add(&node, 0);
    let materializer = cache();
    let basis = selected(&materializer, &node, &node.authority).unwrap();
    assert!(matches!(
        update(
            &node,
            "delete",
            "refs/tags/closure-0",
            original,
            zero(&node)
        ),
        DecisionOutcome::Committed { .. }
    ));
    assert!(matches!(
        update(&node, "reuse", "refs/tags/reused", zero(&node), original),
        DecisionOutcome::Committed { .. }
    ));
    let uncommitted = put_object(
        &node,
        fgit_git_object::ObjectType::Blob,
        b"never admitted".to_vec(),
    );
    assert!(matches!(
        update(
            &node,
            "refusal",
            "refs/tags/reused",
            zero(&node),
            uncommitted
        ),
        DecisionOutcome::Refused { .. }
    ));
    let request = node.request_context();
    let current = selected(&cache(), &node, &node.authority).unwrap();
    let frozen = node
        .runtime()
        .block_on(freeze_capsule_async(
            &node.authority,
            request.authority(),
            &CryptoBodyIdentity,
            current.authenticated().receipt(),
            None,
            CapsuleClosure {
                object_closure_root: current.selected_closure().root(),
                segment_manifest_root: digest_of(0xc4),
                backup_profile: BackupProfile::DecisionHistoryOnly,
            },
        ))
        .unwrap();
    node.runtime()
        .block_on(activate_frozen_capsule_async(
            &node.authority,
            request.authority(),
            current.authenticated().receipt(),
            &frozen,
        ))
        .unwrap();
    let observed = Observe::new(&node);
    let after = selected(&cache(), &node, &node.authority).unwrap();
    let projected = project(&materializer, &node, &after, &observed);
    assert_eq!(&projected, after.selected_closure());
    assert_eq!(after.selected_closure(), &original_walk(&node, &after));
    assert_eq!(
        after.selected_closure().closure().objects(),
        basis.selected_closure().closure().objects()
    );
    assert!(
        !after
            .selected_closure()
            .closure()
            .objects()
            .contains(&uncommitted)
    );
    assert_eq!(
        observed.history_reads(),
        3,
        "checkpoint edge invents no decision"
    );
    assert_eq!(
        observed.closure_reads(),
        1,
        "only the newly committed empty closure is read"
    );
    node.shutdown().unwrap();
}

#[test]
fn service_siblings_reuse_the_prefix_and_keep_exact_snapshots_private() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    for index in 0..3 {
        add(&node, index);
    }
    let before = selected(&node.admission_materializer, &node, &node.authority).unwrap();
    let first = OneNode::open_existing(node.service_config.clone()).unwrap();
    let second = OneNode::open_existing(node.service_config.clone()).unwrap();
    assert!(Arc::ptr_eq(
        &node.service_config.admission_closure_cache,
        &first.service_config.admission_closure_cache,
    ));
    assert!(
        first
            .admission_materializer
            .materialized
            .read()
            .unwrap()
            .is_none()
    );
    add(&node, 3);
    let current = selected(&cache(), &node, &node.authority).unwrap();
    let first_reads = Observe::new(&first);
    assert_eq!(
        &project(
            &first.admission_materializer,
            &first,
            &current,
            &first_reads
        ),
        current.selected_closure()
    );
    assert_eq!(first_reads.history_reads(), 1);
    assert_eq!(first_reads.closure_reads(), 1);
    let first_selected = selected(&first.admission_materializer, &first, &first.authority).unwrap();
    assert_eq!(
        node.admission_materializer
            .snapshot_for(before.basis(), before.authenticated())
            .unwrap(),
        *before.snapshot(),
        "advancing a sibling's prefix does not invalidate this node's exact snapshot"
    );
    let historical_reads = Observe::new(&node);
    assert_eq!(
        &project(
            &node.admission_materializer,
            &node,
            &before,
            &historical_reads
        ),
        before.selected_closure()
    );
    assert_eq!(historical_reads.history_reads(), 0);
    assert_eq!(historical_reads.closure_reads(), 0);
    let second_reads = Observe::new(&second);
    assert_eq!(
        &project(
            &second.admission_materializer,
            &second,
            &current,
            &second_reads
        ),
        current.selected_closure()
    );
    assert_eq!(second_reads.history_reads(), 0);
    assert_eq!(second_reads.closure_reads(), 0);
    let second_selected =
        selected(&second.admission_materializer, &second, &second.authority).unwrap();
    assert_eq!(
        first_selected.selected_closure(),
        second_selected.selected_closure()
    );
    assert_eq!(
        first
            .admission_materializer
            .snapshot_for(first_selected.basis(), first_selected.authenticated())
            .unwrap(),
        *first_selected.snapshot()
    );
    second.shutdown().unwrap();
    first.shutdown().unwrap();
    node.shutdown().unwrap();
}

#[test]
fn a_late_historical_materialization_cannot_evict_a_newer_sibling_prefix() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add(&node, 0);
    let old = selected(&node.admission_materializer, &node, &node.authority).unwrap();
    let earlier_config = node.service_config.clone();
    let later = OneNode::open_existing(node.service_config.clone()).unwrap();
    add(&node, 1);
    let target = admission_immutable_key(
        ADMISSION_REF_STATE_KEY_PREFIX,
        node.repository_id(),
        old.basis().body().ref_root,
    )
    .unwrap();
    let (reached_tx, reached_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let gate = ReadGate {
        reached: reached_tx,
        release: Mutex::new(release_rx),
    };
    let later_ref = &later;
    let (historical, newer) = std::thread::scope(move |scope| {
        let pending = scope.spawn(move || {
            let earlier = OneNode::open_existing(earlier_config).unwrap();
            let request = earlier.request_context();
            let store = Observe {
                target: Some(target),
                gate: Some(&gate),
                ..Observe::new(&earlier)
            };
            let historical = earlier
                .runtime()
                .block_on(earlier.admission_materializer.materialize_exact_in(
                    &store,
                    request.authority(),
                    earlier.repository_id(),
                    old.basis(),
                    old.authenticated(),
                    &|| false,
                ))
                .unwrap();
            drop(store);
            assert_eq!(
                earlier
                    .admission_materializer
                    .snapshot_for(historical.basis(), historical.authenticated())
                    .unwrap(),
                *historical.snapshot()
            );
            earlier.shutdown().unwrap();
            historical
        });
        reached_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let newer = selected(
            &later_ref.admission_materializer,
            later_ref,
            &later_ref.authority,
        );
        release_tx.send(()).unwrap();
        let historical = pending.join().unwrap();
        (historical, newer.unwrap())
    });
    let retained = node
        .service_config
        .admission_closure_cache
        .read()
        .unwrap()
        .unwrap();
    assert_eq!(retained.basis, *newer.basis());
    assert!(historical.basis().generation() < newer.basis().generation());
    assert_eq!(
        later
            .admission_materializer
            .snapshot_for(newer.basis(), newer.authenticated())
            .unwrap(),
        *newer.snapshot()
    );
    later.shutdown().unwrap();
    node.shutdown().unwrap();
}

#[test]
fn a_future_or_other_store_cache_cannot_expand_an_older_or_unrelated_closure() {
    let first = ScratchDirectory::new();
    let second = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(first.path().to_path_buf())).unwrap();
    let (other, _) = OneNode::init(
        test_config(second.path().to_path_buf()).with_store_instance(StoreInstanceId::from_raw(2)),
    )
    .unwrap();
    let original = add(&node, 0);
    let materializer = cache();
    let older = selected(&materializer, &node, &node.authority).unwrap();
    let future = add(&node, 1);
    selected(&materializer, &node, &node.authority).unwrap();
    let request = node.request_context();
    let historical = node
        .runtime()
        .block_on(materializer.materialize_exact_in(
            &node.authority,
            request.authority(),
            node.repository_id(),
            older.basis(),
            older.authenticated(),
            &|| false,
        ))
        .unwrap();
    assert_eq!(historical.selected_closure(), older.selected_closure());
    assert!(
        !historical
            .selected_closure()
            .closure()
            .objects()
            .contains(&future)
    );
    let independent = add(&other, 8);
    let unrelated = selected(&materializer, &other, &other.authority).unwrap();
    assert_eq!(
        unrelated.selected_closure(),
        &original_walk(&other, &unrelated)
    );
    assert_eq!(
        unrelated.selected_closure().closure().objects(),
        &BTreeSet::from([independent])
    );
    assert!(
        !unrelated
            .selected_closure()
            .closure()
            .objects()
            .contains(&original)
    );
    other.shutdown().unwrap();
    node.shutdown().unwrap();
}

#[test]
fn cancelled_or_corrupt_suffix_reads_never_install_a_partial_prefix() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add(&node, 0);
    let shared = Arc::new(crate::closure_selection::AdmissionClosureCache::default());
    let materializer = DurableAdmissionMaterializer::with_closure_cache(
        admission_cache_scope().unwrap(),
        Arc::clone(&shared),
    );
    let before = selected(&materializer, &node, &node.authority).unwrap();
    add(&node, 1);
    let request = node.request_context();
    let current = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .unwrap();
    let body = current.body().unwrap();
    let target = body_key_for_id(body.decision_tail_id.unwrap().as_internal_object_id()).unwrap();
    for fault in [Fault::Corrupt, Fault::Cancel] {
        let store = Observe {
            target: Some(target.clone()),
            fault,
            ..Observe::new(&node)
        };
        let error = selected(&materializer, &node, &store).unwrap_err();
        assert!(
            store.reads.lock().unwrap().contains(&target),
            "negative is planted inside a real suffix read"
        );
        match fault {
            Fault::Cancel => assert!(matches!(error, AdmissionMaterializationRefusal::Cancelled)),
            Fault::Corrupt => assert!(matches!(
                error,
                AdmissionMaterializationRefusal::DecisionHistory(_)
            )),
            Fault::None => unreachable!(),
        }
        assert_eq!(
            materializer
                .materialized
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .basis,
            *before.basis()
        );
        assert_eq!(shared.read().unwrap().unwrap().basis, *before.basis());
    }
    let recovered = selected(&materializer, &node, &node.authority).unwrap();
    assert_eq!(
        recovered.selected_closure(),
        &original_walk(&node, &recovered)
    );
    let cancelled = node.request_context();
    cancelled.cancel();
    assert!(matches!(
        node.runtime().block_on(materializer.materialize_exact_in(
            &node.authority,
            cancelled.authority(),
            node.repository_id(),
            recovered.basis(),
            recovered.authenticated(),
            &|| cancelled.authority().checkpoint().is_err(),
        )),
        Err(AdmissionMaterializationRefusal::Cancelled)
    ));
    node.shutdown().unwrap();
}

#[test]
fn claiming_the_cached_predecessor_cannot_skip_successor_verification() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    add(&node, 0);
    let materializer = cache();
    let before = selected(&materializer, &node, &node.authority).unwrap();
    add(&node, 1);
    let request = node.request_context();
    let current = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&request))
        .unwrap();
    let mut forged = current.body().unwrap();
    assert_eq!(forged.predecessor_head_id, Some(before.basis().id()));
    forged.generation = forged.generation.next().unwrap();
    let bytes = fgit_codec::encode_body(&forged).unwrap();
    let key = body_key(IdentityDomain::RepositoryAuthorityHead, &forged).unwrap();
    node.runtime()
        .block_on(AsyncAuthorityStore::put_if_absent(
            &node.authority,
            request.authority(),
            &key,
            &bytes,
        ))
        .unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(AsyncAuthorityStore::compare_exchange_head(
                &node.authority,
                request.authority(),
                &node.head_key,
                current.receipt().token(),
                forged.generation,
                &bytes,
            ))
            .unwrap(),
        CasOutcome::Committed(_)
    ));
    assert!(matches!(
        selected(&materializer, &node, &node.authority),
        Err(AdmissionMaterializationRefusal::DecisionHistoryVerification(_))
    ));
    assert_eq!(
        materializer
            .materialized
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .basis,
        *before.basis()
    );
    node.shutdown().unwrap();
}
