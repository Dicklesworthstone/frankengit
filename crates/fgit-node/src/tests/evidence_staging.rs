//! Exact-byte equivalence and fault coverage over real embedded authority puts.
//! The wrapper counts physical API calls and injects malformed/lost replies;
//! canonical data is still written and reread through FrankenSQLite.

use super::*;
use crate::evidence_staging::{EvidenceBatch, stage_commit_in, stage_decision_in};
use crate::{
    ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
    ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX, ADMISSION_RETENTION_DELTA_KEY_PREFIX,
    DecisionEvidenceBodies, async_projection_unavailable, stage_evidence_body_in,
    stage_policy_decision_in,
};
use fgit_admission::{
    PreparedCanonicalCommit, prepare_canonical_commit_for_layout_reusing_closure,
};
use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken,
    CasOutcome, HeadKey, HeadReadReceipt, ImmutableBatchFailure, ImmutableKey,
    MAX_IMMUTABLE_BATCH_BYTES, PutOutcome, StoreInstanceId,
};
use fgit_types::{HeadGeneration, RootLayoutVersion};
use std::sync::{Mutex, atomic::AtomicBool};

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Conflict(usize),
    ShortReply,
    LongReply,
    LostAfter(usize),
    CancelAfter,
}

struct Observe<'a> {
    node: &'a OneNode,
    singles: AtomicUsize,
    batches: Mutex<Vec<usize>>,
    frames: Mutex<Vec<(ImmutableKey, Vec<u8>)>>,
    cancelled: AtomicBool,
    fault: Fault,
}

impl<'a> Observe<'a> {
    fn new(node: &'a OneNode) -> Self {
        Self {
            node,
            singles: AtomicUsize::new(0),
            batches: Mutex::new(Vec::new()),
            frames: Mutex::new(Vec::new()),
            cancelled: AtomicBool::new(false),
            fault: Fault::None,
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
    async fn put_if_absent(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.singles.fetch_add(1, Ordering::Relaxed);
        self.frames
            .lock()
            .unwrap()
            .push((key.clone(), body.to_vec()));
        AsyncAuthorityStore::put_if_absent(&self.node.authority, cx, key, body).await
    }
    async fn put_if_absent_batch(
        &self,
        cx: &FsqliteCx,
        entries: &[(ImmutableKey, Vec<u8>)],
    ) -> Result<Vec<PutOutcome>, ImmutableBatchFailure> {
        self.batches.lock().unwrap().push(entries.len());
        self.frames.lock().unwrap().extend_from_slice(entries);
        fgit_authority::validate_immutable_batch(entries, self.limits())?;
        if let Fault::Conflict(index) = self.fault {
            assert_eq!(
                AsyncAuthorityStore::put_if_absent(
                    &self.node.authority,
                    cx,
                    &entries[index].0,
                    b"pre-existing conflicting bytes",
                )
                .await
                .unwrap(),
                PutOutcome::Created,
            );
        }
        if let Fault::LostAfter(completed) = self.fault {
            for (key, body) in entries.iter().take(completed) {
                AsyncAuthorityStore::put_if_absent(&self.node.authority, cx, key, body)
                    .await
                    .unwrap();
            }
            return Err(ImmutableBatchFailure::Interrupted {
                completed,
                source: AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
            });
        }
        let mut outcomes =
            AsyncAuthorityStore::put_if_absent_batch(&self.node.authority, cx, entries).await?;
        match self.fault {
            Fault::ShortReply => {
                outcomes.pop();
            }
            Fault::LongReply => outcomes.push(PutOutcome::Created),
            Fault::CancelAfter => self.cancelled.store(true, Ordering::SeqCst),
            _ => {}
        }
        Ok(outcomes)
    }
    async fn read_immutable(
        &self,
        cx: &FsqliteCx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await
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

fn bodies(node: &OneNode, authenticated: bool) -> DecisionEvidenceBodies {
    let selected = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    let (context, request, fold) = evidence_request(node);
    if authenticated {
        DecisionEvidenceBodies::derive_with_authentication(
            &context,
            selected.basis(),
            &request,
            &fold,
            AdmissionAuthentication::OperatorAssertion,
        )
        .unwrap()
    } else {
        DecisionEvidenceBodies::derive(&context, selected.basis(), &request, &fold).unwrap()
    }
}

fn prepared_ref_commit(node: &OneNode) -> (DecisionEvidenceBodies, PreparedCanonicalCommit) {
    let oid = node
        .put_git_object(ObjectType::Blob, b"grouped ref commit object\n".to_vec())
        .unwrap()
        .identity();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    let snapshot = selected.snapshot();
    let (context, mut request, _) = evidence_request(node);
    request.statements = vec![fgit_reference::intent::Statement {
        intents: vec![fgit_reference::intent::Intent::Ref(
            fgit_reference::intent::RefIntent::Update {
                name: RefName::try_new(b"refs/tags/grouped-staging").unwrap(),
                expected: fgit_reference::refs::ExpectedRefState::Absent,
                new: oid,
                force: false,
            },
        )],
        mismatch_policy: fgit_types::MismatchPolicy::TxnAbort,
    }];
    request.promised_closure.insert(oid);
    let fold = fgit_txn::IntentEvaluator::new().evaluate(
        fgit_reference::effect::FoldBasis {
            refs: &snapshot.refs,
            forge_positions: &snapshot.forge_positions,
            retention: &snapshot.retention,
            outbox: &snapshot.outbox,
        },
        &request,
    );
    assert!(fold.effects().is_some(), "the real tag update must fold");
    let bodies = DecisionEvidenceBodies::derive_with_authentication(
        &context,
        selected.basis(),
        &request,
        &fold,
        AdmissionAuthentication::OperatorAssertion,
    )
    .unwrap();
    let provider = crate::DurableAdmissionEvidence::from_bodies(
        context,
        selected.basis(),
        &request,
        bodies.clone(),
    )
    .unwrap();
    let evidence = provider
        .commit_evidence(selected.basis(), &request, &fold)
        .unwrap();
    let current = match &snapshot.head_target {
        Some(target) => {
            CanonicalRefState::new_with_head_target(snapshot.refs.clone(), target.clone()).unwrap()
        }
        None => CanonicalRefState::new(snapshot.refs.clone()),
    };
    let closure = PermittedObjectClosure::new(request.promised_closure.clone());
    let validated = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&closure).unwrap(),
        objects: request.promised_closure.clone(),
    };
    let prepared = prepare_canonical_commit_for_layout_reusing_closure(
        selected.basis(),
        &request,
        &fold,
        &validated,
        current,
        selected.root_layout(),
        Some(selected.selected_closure().closure()),
        evidence,
        None,
    )
    .unwrap();
    (bodies, prepared)
}

async fn sequential(store: &Observe<'_>, cx: &FsqliteCx, bodies: &DecisionEvidenceBodies) {
    let repository = bodies.principal_snapshot().repository_id();
    crate::admission_authentication::stage_principal_snapshot_in(
        store,
        cx,
        repository,
        bodies.principal_snapshot(),
        &|| false,
    )
    .await
    .unwrap();
    stage_policy_decision_in(store, cx, repository, bodies.policy_decision(), &|| false)
        .await
        .unwrap();
    stage_evidence_body_in(
        store,
        cx,
        repository,
        ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
        bodies.invariant_evidence(),
        &|| false,
    )
    .await
    .unwrap();
    stage_evidence_body_in(
        store,
        cx,
        repository,
        ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
        bodies.forge_event_batch(),
        &|| false,
    )
    .await
    .unwrap();
    stage_evidence_body_in(
        store,
        cx,
        repository,
        ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
        bodies.outbox_effect_batch(),
        &|| false,
    )
    .await
    .unwrap();
    stage_evidence_body_in(
        store,
        cx,
        repository,
        ADMISSION_RETENTION_DELTA_KEY_PREFIX,
        bodies.retention_delta(),
        &|| false,
    )
    .await
    .unwrap();
}

#[test]
fn native_evidence_batch_retains_all_six_sequential_keys_and_bytes_and_retries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for authenticated in [false, true] {
            let scratch = ScratchDirectory::new();
            let (node, _) =
                OneNode::init(test_config(scratch.path().to_path_buf()).with_object_format(format))
                    .unwrap();
            let request = node.request_context();
            let before = node
                .runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap();
            let evidence = bodies(&node, authenticated);
            let candidate = Observe::new(&node);
            node.runtime()
                .block_on(stage_decision_in(
                    &candidate,
                    request.authority(),
                    &evidence,
                    &|| false,
                ))
                .unwrap();
            assert_eq!(*candidate.batches.lock().unwrap(), [6]);
            assert_eq!(candidate.singles.load(Ordering::Relaxed), 0);
            let reference = Observe::new(&node);
            node.runtime()
                .block_on(sequential(&reference, request.authority(), &evidence));
            assert_eq!(reference.singles.load(Ordering::Relaxed), 6);
            assert_eq!(
                *candidate.frames.lock().unwrap(),
                *reference.frames.lock().unwrap()
            );
            for (key, bytes) in &*candidate.frames.lock().unwrap() {
                assert_eq!(
                    node.runtime()
                        .block_on(AsyncAuthorityStore::read_immutable(
                            &node.authority,
                            request.authority(),
                            key,
                        ))
                        .unwrap(),
                    ImmutableRead::Present(bytes.clone())
                );
            }
            node.runtime()
                .block_on(stage_decision_in(
                    &candidate,
                    request.authority(),
                    &evidence,
                    &|| false,
                ))
                .unwrap();
            assert_eq!(*candidate.batches.lock().unwrap(), [6, 6]);
            assert_eq!(
                node.runtime()
                    .block_on(node.authenticate_authority_head())
                    .unwrap(),
                before,
                "staging and identical retries cannot publish a head"
            );
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn prepared_commit_batches_eight_exact_bodies_under_every_live_layout() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV2,
            RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
            RootLayoutVersion::AuthorityBoundObjectClosureMerkleV2,
        ] {
            let scratch = ScratchDirectory::new();
            let (node, _) = OneNode::init(
                test_config(scratch.path().to_path_buf())
                    .with_object_format(format)
                    .with_root_layout(layout),
            )
            .unwrap();
            let request = node.request_context();
            let (evidence, mut prepared) = prepared_ref_commit(&node);
            let expected = prepared.clone().into_materialization();
            let before = node
                .runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap();
            let candidate = Observe::new(&node);
            node.runtime()
                .block_on(stage_commit_in(
                    &candidate,
                    request.authority(),
                    &evidence,
                    &mut prepared,
                    &|| false,
                ))
                .unwrap();
            assert_eq!(*candidate.batches.lock().unwrap(), [8]);
            assert_eq!(candidate.singles.load(Ordering::Relaxed), 0);

            // Independently rederive both roots through the former durable
            // path, retaining its six-evidence batch plus two individual puts.
            let reference = Observe::new(&node);
            node.runtime().block_on(async {
                stage_decision_in(&reference, request.authority(), &evidence, &|| false)
                    .await
                    .unwrap();
                assert_eq!(
                    node.admission_materializer
                        .stage_ref_state_for_layout_in(
                            &reference,
                            request.authority(),
                            node.repository_id(),
                            layout,
                            prepared.next_ref_state().clone(),
                        )
                        .await
                        .unwrap(),
                    prepared.ref_root(),
                );
                assert_eq!(
                    node.admission_materializer
                        .stage_permitted_object_closure_for_layout_in(
                            &reference,
                            request.authority(),
                            node.repository_id(),
                            layout,
                            prepared.object_closure().clone(),
                        )
                        .await
                        .unwrap(),
                    prepared.object_closure_root(),
                );
            });
            assert_eq!(*reference.batches.lock().unwrap(), [6]);
            assert_eq!(reference.singles.load(Ordering::Relaxed), 2);
            assert_eq!(
                *candidate.frames.lock().unwrap(),
                *reference.frames.lock().unwrap(),
                "layout {layout:?}, object format {format:?}",
            );
            for (key, bytes) in &*candidate.frames.lock().unwrap() {
                assert_eq!(
                    node.runtime()
                        .block_on(AsyncAuthorityStore::read_immutable(
                            &node.authority,
                            request.authority(),
                            key,
                        ))
                        .unwrap(),
                    ImmutableRead::Present(bytes.clone()),
                );
            }
            // The encoded closure can be reused, but placement is retried in
            // the selected store and cannot be inferred from that pure cache.
            node.runtime()
                .block_on(stage_commit_in(
                    &candidate,
                    request.authority(),
                    &evidence,
                    &mut prepared,
                    &|| false,
                ))
                .unwrap();
            assert_eq!(*candidate.batches.lock().unwrap(), [8, 8]);
            assert_eq!(candidate.singles.load(Ordering::Relaxed), 0);
            assert_eq!(prepared.into_materialization(), expected);
            assert_eq!(
                node.runtime()
                    .block_on(node.authenticate_authority_head())
                    .unwrap(),
                before,
                "immutable successor bodies do not publish repository state",
            );
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn grouped_successor_conflicts_and_interruption_never_complete_or_publish() {
    for fault in [
        Fault::Conflict(6),
        Fault::Conflict(7),
        Fault::ShortReply,
        Fault::LongReply,
        Fault::LostAfter(7),
        Fault::CancelAfter,
    ] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        let request = node.request_context();
        let (evidence, mut prepared) = prepared_ref_commit(&node);
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let mut observer = Observe::new(&node);
        observer.fault = fault;
        let error = node
            .runtime()
            .block_on(stage_commit_in(
                &observer,
                request.authority(),
                &evidence,
                &mut prepared,
                &|| observer.cancelled.load(Ordering::SeqCst),
            ))
            .unwrap_err();
        match fault {
            Fault::Conflict(index) => {
                assert!(matches!(
                    error,
                    AdmissionMaterializationRefusal::ImmutableConflict,
                ));
                let frames = observer.frames.lock().unwrap();
                assert_eq!(
                    node.runtime()
                        .block_on(AsyncAuthorityStore::read_immutable(
                            &node.authority,
                            request.authority(),
                            &frames[index].0,
                        ))
                        .unwrap(),
                    ImmutableRead::Present(b"pre-existing conflicting bytes".to_vec()),
                    "neither successor commitment may overwrite a collision",
                );
            }
            Fault::ShortReply | Fault::LongReply => assert!(matches!(
                error,
                AdmissionMaterializationRefusal::CanonicalRoot(
                    RefusalCode::InternalInvariantBreach,
                ),
            )),
            Fault::LostAfter(completed) => {
                assert!(matches!(
                    error,
                    AdmissionMaterializationRefusal::ImmutableBatch(
                        ImmutableBatchFailure::Interrupted {
                            completed: 7,
                            source: AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
                        },
                    ),
                ));
                for (index, (key, bytes)) in observer.frames.lock().unwrap().iter().enumerate() {
                    assert_eq!(
                        node.runtime()
                            .block_on(AsyncAuthorityStore::read_immutable(
                                &node.authority,
                                request.authority(),
                                key,
                            ))
                            .unwrap(),
                        if index < completed {
                            ImmutableRead::Present(bytes.clone())
                        } else {
                            ImmutableRead::Absent
                        },
                    );
                }
            }
            Fault::CancelAfter => {
                assert!(matches!(error, AdmissionMaterializationRefusal::Cancelled));
                // Cancellation is observed after the submitted write drains;
                // its immutable effects must not be described as absent.
                for (key, bytes) in &*observer.frames.lock().unwrap() {
                    assert_eq!(
                        node.runtime()
                            .block_on(AsyncAuthorityStore::read_immutable(
                                &node.authority,
                                request.authority(),
                                key,
                            ))
                            .unwrap(),
                        ImmutableRead::Present(bytes.clone()),
                    );
                }
            }
            Fault::None => unreachable!(),
        }
        assert_eq!(*observer.batches.lock().unwrap(), [8]);
        assert_eq!(observer.singles.load(Ordering::Relaxed), 0);
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap(),
            before,
        );
        if !matches!(fault, Fault::Conflict(_)) {
            let retry = Observe::new(&node);
            node.runtime()
                .block_on(stage_commit_in(
                    &retry,
                    request.authority(),
                    &evidence,
                    &mut prepared,
                    &|| false,
                ))
                .unwrap();
            assert_eq!(*retry.batches.lock().unwrap(), [8]);
            assert_eq!(
                *retry.frames.lock().unwrap(),
                *observer.frames.lock().unwrap(),
                "a failed attempt's pure preparation cannot skip any retry write",
            );
            assert_eq!(
                node.runtime()
                    .block_on(node.authenticate_authority_head())
                    .unwrap(),
                before,
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn conflicts_and_malformed_batch_replies_never_become_complete_evidence() {
    for fault in [
        Fault::Conflict(0),
        Fault::Conflict(5),
        Fault::ShortReply,
        Fault::LongReply,
    ] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        let request = node.request_context();
        let evidence = bodies(&node, false);
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let mut observer = Observe::new(&node);
        observer.fault = fault;
        let error = node
            .runtime()
            .block_on(stage_decision_in(
                &observer,
                request.authority(),
                &evidence,
                &|| false,
            ))
            .unwrap_err();
        match fault {
            Fault::Conflict(index) => {
                assert!(matches!(
                    error,
                    AdmissionMaterializationRefusal::ImmutableConflict
                ));
                let frames = observer.frames.lock().unwrap();
                assert_eq!(
                    node.runtime()
                        .block_on(AsyncAuthorityStore::read_immutable(
                            &node.authority,
                            request.authority(),
                            &frames[index].0,
                        ))
                        .unwrap(),
                    ImmutableRead::Present(b"pre-existing conflicting bytes".to_vec())
                );
            }
            _ => assert!(matches!(
                error,
                AdmissionMaterializationRefusal::CanonicalRoot(
                    RefusalCode::InternalInvariantBreach
                )
            )),
        }
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap(),
            before
        );
        assert_eq!(
            observer.batches.lock().unwrap().len(),
            1,
            "no automatic second mutation"
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn interrupted_prefix_and_cancellation_preserve_nonpublication_and_exact_retry() {
    for fault in [Fault::LostAfter(2), Fault::CancelAfter] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        let request = node.request_context();
        let evidence = bodies(&node, true);
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let mut observer = Observe::new(&node);
        observer.fault = fault;
        let error = node
            .runtime()
            .block_on(stage_decision_in(
                &observer,
                request.authority(),
                &evidence,
                &|| observer.cancelled.load(Ordering::SeqCst),
            ))
            .unwrap_err();
        match fault {
            Fault::LostAfter(completed) => {
                assert!(matches!(
                    &error,
                    AdmissionMaterializationRefusal::ImmutableBatch(
                        ImmutableBatchFailure::Interrupted {
                            completed: 2,
                            source: AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse)
                        }
                    )
                ));
                for (index, (key, bytes)) in observer.frames.lock().unwrap().iter().enumerate() {
                    let observed = node
                        .runtime()
                        .block_on(AsyncAuthorityStore::read_immutable(
                            &node.authority,
                            request.authority(),
                            key,
                        ))
                        .unwrap();
                    assert_eq!(
                        observed,
                        if index < completed {
                            ImmutableRead::Present(bytes.clone())
                        } else {
                            ImmutableRead::Absent
                        }
                    );
                }
                assert!(matches!(
                    async_projection_unavailable(error),
                    fgit_admission::AsyncProjectionFailure::Unavailable(
                        RefusalCode::ExternalEffectIndeterminate
                    )
                ));
            }
            _ => assert!(matches!(error, AdmissionMaterializationRefusal::Cancelled)),
        }
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap(),
            before
        );
        assert_eq!(observer.batches.lock().unwrap().len(), 1);
        let retry = Observe::new(&node);
        node.runtime()
            .block_on(stage_decision_in(
                &retry,
                request.authority(),
                &evidence,
                &|| false,
            ))
            .unwrap();
        assert_eq!(
            *retry.frames.lock().unwrap(),
            *observer.frames.lock().unwrap()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn pre_staging_cancellation_never_writes_and_large_frames_keep_the_single_body_envelope() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let request = node.request_context();
    let evidence = bodies(&node, true);
    let observer = Observe::new(&node);
    assert!(matches!(
        node.runtime().block_on(stage_decision_in(
            &observer,
            request.authority(),
            &evidence,
            &|| true,
        )),
        Err(AdmissionMaterializationRefusal::Cancelled)
    ));
    assert!(observer.frames.lock().unwrap().is_empty());
    let checks = AtomicUsize::new(0);
    assert!(matches!(
        node.runtime().block_on(stage_decision_in(
            &observer,
            request.authority(),
            &evidence,
            &|| checks.fetch_add(1, Ordering::SeqCst) >= 3,
        )),
        Err(AdmissionMaterializationRefusal::Cancelled)
    ));
    assert!(
        observer.frames.lock().unwrap().is_empty(),
        "cancelled encoding does not dispatch"
    );

    let lengths = [600_000, 600_000, MAX_IMMUTABLE_BATCH_BYTES + 1, 16];
    node.runtime().block_on(async {
        let mut batch = EvidenceBatch::new(&observer, request.authority(), &|| false);
        for (index, length) in lengths.into_iter().enumerate() {
            batch
                .push(
                    node.repository_id(),
                    b"test/evidence-batch/",
                    digest_of(index as u8 + 1),
                    vec![index as u8; length],
                )
                .await
                .unwrap();
        }
        batch.flush().await.unwrap();
    });
    assert_eq!(*observer.batches.lock().unwrap(), [1, 1, 1]);
    assert_eq!(
        observer.singles.load(Ordering::Relaxed),
        1,
        "an individually valid large body uses the original authority operation"
    );
    let frames = observer.frames.lock().unwrap();
    assert_eq!(frames.len(), lengths.len());
    for (index, (key, bytes)) in frames.iter().enumerate() {
        assert_eq!(bytes.len(), lengths[index]);
        assert_eq!(
            node.runtime()
                .block_on(AsyncAuthorityStore::read_immutable(
                    &node.authority,
                    request.authority(),
                    key,
                ))
                .unwrap(),
            ImmutableRead::Present(bytes.clone())
        );
    }
    drop(frames);
    node.shutdown().unwrap();
}

#[test]
fn prepared_commit_cancellation_before_dispatch_stages_nothing() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let request = node.request_context();
    let (evidence, mut prepared) = prepared_ref_commit(&node);
    let observer = Observe::new(&node);
    assert!(matches!(
        node.runtime().block_on(stage_commit_in(
            &observer,
            request.authority(),
            &evidence,
            &mut prepared,
            &|| true,
        )),
        Err(AdmissionMaterializationRefusal::Cancelled),
    ));
    assert!(observer.frames.lock().unwrap().is_empty());
    assert!(observer.batches.lock().unwrap().is_empty());
    assert_eq!(observer.singles.load(Ordering::Relaxed), 0);
    node.shutdown().unwrap();
}

#[test]
fn borrowed_final_body_keeps_the_single_put_fallback_without_a_larger_batch() {
    for (pending, final_length) in [
        (Some(600_000), 600_000),
        (Some(16), MAX_IMMUTABLE_BATCH_BYTES + 1),
        (None, 16),
    ] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        let request = node.request_context();
        let observer = Observe::new(&node);
        let final_body = vec![0x55; final_length];
        node.runtime().block_on(async {
            let mut batch = EvidenceBatch::new(&observer, request.authority(), &|| false);
            if let Some(length) = pending {
                batch
                    .push(
                        node.repository_id(),
                        b"test/borrowed-final/",
                        digest_of(0x11),
                        vec![0x11; length],
                    )
                    .await
                    .unwrap();
            }
            batch
                .finish_borrowed(
                    node.repository_id(),
                    b"test/borrowed-final/",
                    digest_of(0x55),
                    &final_body,
                )
                .await
                .unwrap();
        });
        let expected_batches = if pending.is_some() { vec![1] } else { vec![] };
        assert_eq!(*observer.batches.lock().unwrap(), expected_batches);
        assert_eq!(observer.singles.load(Ordering::Relaxed), 1);
        let frames = observer.frames.lock().unwrap();
        assert_eq!(frames.last().unwrap().1, final_body);
        for (key, bytes) in &*frames {
            assert_eq!(
                node.runtime()
                    .block_on(AsyncAuthorityStore::read_immutable(
                        &node.authority,
                        request.authority(),
                        key,
                    ))
                    .unwrap(),
                ImmutableRead::Present(bytes.clone()),
            );
        }
        drop(frames);
        node.shutdown().unwrap();
    }
}

#[test]
fn failed_pending_group_stops_borrowed_fallback_until_an_explicit_retry() {
    for fault in [Fault::LostAfter(1), Fault::CancelAfter] {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        let mut observer = Observe::new(&node);
        observer.fault = fault;
        let final_body = vec![0x55; MAX_IMMUTABLE_BATCH_BYTES + 1];
        let cancelled = || observer.cancelled.load(Ordering::SeqCst);
        let error = node.runtime().block_on(async {
            let mut batch = EvidenceBatch::new(&observer, request.authority(), &cancelled);
            batch
                .push(
                    node.repository_id(),
                    b"test/borrowed-retry/",
                    digest_of(0x11),
                    vec![0x11; 16],
                )
                .await
                .unwrap();
            batch
                .finish_borrowed(
                    node.repository_id(),
                    b"test/borrowed-retry/",
                    digest_of(0x55),
                    &final_body,
                )
                .await
                .unwrap_err()
        });
        match fault {
            Fault::LostAfter(_) => assert!(matches!(
                error,
                AdmissionMaterializationRefusal::ImmutableBatch(
                    ImmutableBatchFailure::Interrupted { completed: 1, .. },
                ),
            )),
            _ => assert!(matches!(error, AdmissionMaterializationRefusal::Cancelled)),
        }
        assert_eq!(*observer.batches.lock().unwrap(), [1]);
        assert_eq!(observer.singles.load(Ordering::Relaxed), 0);
        let final_key = admission_immutable_key(
            b"test/borrowed-retry/",
            node.repository_id(),
            digest_of(0x55),
        )
        .unwrap();
        assert_eq!(
            node.runtime()
                .block_on(AsyncAuthorityStore::read_immutable(
                    &node.authority,
                    request.authority(),
                    &final_key,
                ))
                .unwrap(),
            ImmutableRead::Absent,
            "a failed or cancelled prefix must not dispatch its fallback body",
        );
        let retry = Observe::new(&node);
        node.runtime().block_on(async {
            let mut batch = EvidenceBatch::new(&retry, request.authority(), &|| false);
            batch
                .push(
                    node.repository_id(),
                    b"test/borrowed-retry/",
                    digest_of(0x11),
                    vec![0x11; 16],
                )
                .await
                .unwrap();
            batch
                .finish_borrowed(
                    node.repository_id(),
                    b"test/borrowed-retry/",
                    digest_of(0x55),
                    &final_body,
                )
                .await
                .unwrap();
        });
        assert_eq!(*retry.batches.lock().unwrap(), [1]);
        assert_eq!(retry.singles.load(Ordering::Relaxed), 1);
        assert_eq!(
            node.runtime()
                .block_on(AsyncAuthorityStore::read_immutable(
                    &node.authority,
                    request.authority(),
                    &final_key,
                ))
                .unwrap(),
            ImmutableRead::Present(final_body),
        );
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap(),
            before,
        );
        node.shutdown().unwrap();
    }
}
