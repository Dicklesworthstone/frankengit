#![forbid(unsafe_code)]
//! Non-atomic batching against the retained sequential admission oracle.
//!
//! These are publication and ref-semantics tests over the reference authority
//! store. The validator declares an object catalog; it does not prove native
//! object ingestion, transport interoperability, durable restart or throughput.

#[path = "receive_microbatch/continuation.rs"]
mod continuation;
#[path = "receive_microbatch/index_race.rs"]
mod index_race;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fgit_admission::{
    AdmissionContext, AdmissionEvidence, AdmissionLimits, AdmissionProjection, AdmissionResult,
    AdmissionSnapshot, AdmissionSnapshotProjection, CanonicalAdmissionProjection,
    CanonicalAdmissionStore, CanonicalRefState, CommitEvidence, CommitMaterialization,
    PermittedObjectClosure, ProjectionFailure, QuarantineValidator, RefusalMaterialization,
    ValidatedClosure, ValidatedReceive, admit_validated_receive, admit_validated_receive_async,
    canonical_ref_state_root, permitted_object_closure_root, validate_receive,
    validate_receive_at_basis,
};
use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityStore, AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey,
    HeadRead, HeadReadReceipt, IdempotencyKey, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    OutcomeLookup, PutOutcome, StoreInstanceId, body_key_for_id, initialize_repository,
    read_authority_head_body, read_decision_batch_body, resolve_outcome,
};
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, RefusalRecordBody, RepositoryAuthorityHeadBody,
    RepositoryDecisionBatchBody, decode_body,
};
use fgit_reference::intent::{Intent, TransactionRequest};
use fgit_types::{
    DecisionOutcome, Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    HeadGeneration, PolicyEpoch, PrincipalId, PrincipalSnapshotId, RefName, RefusalCode,
    RegistryEpoch, RepositoryId, TenantId, TxId,
};
use fgit_wire::receive::{QuarantineReceipt, ReceiveCommand, ReceiveRequest};
use fgit_wire::visibility::RefVisibility;
use fgit_wire::{Capability, GitObjectFormat, WireLimits};

#[derive(Default)]
struct Bodies {
    refs: Mutex<BTreeMap<Digest, CanonicalRefState>>,
    closures: Mutex<BTreeMap<Digest, PermittedObjectClosure>>,
    ref_stages: AtomicUsize,
    fail_ref_stage_at: AtomicUsize,
}

#[derive(Clone, Default)]
struct StagingStore(Arc<Bodies>);

impl CanonicalAdmissionStore for StagingStore {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.0
            .refs
            .lock()
            .unwrap()
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        let stage = self.0.ref_stages.fetch_add(1, Ordering::SeqCst) + 1;
        if self.0.fail_ref_stage_at.load(Ordering::SeqCst) == stage {
            return Err(RefusalCode::EvidenceMissing);
        }
        self.0.refs.lock().unwrap().insert(root, state);
        Ok(())
    }

    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        self.0
            .closures
            .lock()
            .unwrap()
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        self.0.closures.lock().unwrap().insert(root, closure);
        Ok(())
    }

    fn resolve_hidden_ref_policy(
        &self,
        _configuration_root: Digest,
    ) -> Result<RefVisibility, RefusalCode> {
        let mut policy = RefVisibility::new();
        policy
            .push_rule(b"refs/heads/hidden", &WireLimits::default())
            .unwrap();
        Ok(policy)
    }
}

#[derive(Clone, Copy)]
struct Evidence;

impl AdmissionEvidence for Evidence {
    fn commit_evidence(
        &self,
        _basis: &PublicationBasis,
        request: &TransactionRequest,
        _fold: &fgit_txn::TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode> {
        // A deterministic materialization-stage policy refusal, distinct from
        // the snapshot's hidden-ref and expected-old failures.
        if request.addressed_intents().any(|(_, intent)| {
            matches!(intent, Intent::Ref(value) if value.target().as_bytes() == b"refs/heads/non-ff")
        }) {
            return Err(RefusalCode::NonFastForwardRefused);
        }
        Ok(CommitEvidence {
            principal_snapshot_id: PrincipalSnapshotId::from_digest(
                DigestAlgorithmId::try_new(0xfff1).unwrap(),
                fgit_types::CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[15; 32]).unwrap(),
            ),
            forge_event_batch_root: digest(8),
            policy_decision_root: digest(9),
            invariant_evidence_root: digest(10),
            outbox_effect_root: digest(11),
            retention_delta_root: digest(12),
        })
    }

    fn refusal_evidence(
        &self,
        basis: &PublicationBasis,
        _tx_id: TxId,
        _code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: "receive microbatch reference corpus".to_owned(),
            evidence_root: digest(13),
        })
    }
}

type Projection = CanonicalAdmissionProjection<StagingStore, Evidence>;

/// Intentionally inherits the default no-batching capability. This keeps the
/// original one-request/one-CAS driver as an executable independent oracle for
/// the new orchestration while sharing canonical ref/evidence construction.
struct Sequential<'a>(&'a Projection);

impl AdmissionSnapshotProjection for Sequential<'_> {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        self.0.snapshot(basis, authenticated)
    }
}

impl AdmissionProjection for Sequential<'_> {
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &fgit_txn::TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        self.0.materialize_commit(basis, request, fold, closure)
    }

    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        self.0.materialize_refusal(basis, tx_id, code)
    }
}

struct Rival {
    context: AdmissionContext,
    receive: ValidatedReceive,
    projection: Projection,
    staging: StagingStore,
    interrupt_after_first: bool,
}

/// Executes an actual competing admission exactly in the candidate's CAS
/// window. An optional dropped response occurs after the real atomic mutation.
struct Authority {
    inner: MemoryAuthorityStore,
    publications: AtomicUsize,
    drop_response: AtomicBool,
    rival: Mutex<Option<Rival>>,
    index_rival: Mutex<Option<(ImmutableKey, Rival)>>,
}

impl Authority {
    fn run_rival(&self, rival: Rival) {
        if rival.interrupt_after_first {
            rival.staging.0.fail_ref_stage_at.store(
                rival.staging.0.ref_stages.load(Ordering::SeqCst) + 2,
                Ordering::SeqCst,
            );
        }
        let result = admit_validated_receive(
            &self.inner,
            &rival.context,
            &rival.receive,
            AdmissionLimits::default(),
            &Sequential(&rival.projection),
        );
        assert_eq!(
            result.is_err(),
            rival.interrupt_after_first,
            "scheduled rival did not reach its intended boundary: {result:?}"
        );
        rival.staging.0.fail_ref_stage_at.store(0, Ordering::SeqCst);
    }
}

impl AsyncAuthorityStore for Authority {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }

    fn put_if_absent(
        &self,
        _cx: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.inner.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        _cx: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        let rival = {
            let mut scheduled = self.index_rival.lock().unwrap();
            if scheduled.as_ref().is_some_and(|(target, _)| target == key) {
                scheduled.take()
            } else {
                None
            }
        };
        if let Some((_, rival)) = rival {
            self.run_rival(rival);
        }
        std::future::ready(self.inner.read_immutable(key))
    }
    fn initialize_head(
        &self,
        _cx: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.inner.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _cx: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.inner.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        _cx: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(
            self.inner
                .compare_exchange_head(key, expected, generation, body),
        )
    }
    fn authenticate_head_receipt(
        &self,
        _cx: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.inner.authenticate_head_receipt(receipt))
    }
    fn publish_head_with_outcomes(
        &self,
        _cx: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        self.publications.fetch_add(1, Ordering::SeqCst);
        let rival = self.rival.lock().unwrap().take();
        if let Some(rival) = rival {
            self.run_rival(rival);
        }
        let result = self
            .inner
            .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness);
        if matches!(&result, Ok(CasOutcome::Committed(_)))
            && self.drop_response.swap(false, Ordering::SeqCst)
        {
            return std::future::ready(Err(AuthorityFailure::Ambiguous(
                AmbiguityReason::Cancelled,
            )));
        }
        std::future::ready(result)
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("reference authority operations are immediately ready"),
    }
}

fn digest(seed: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(0xfff1).unwrap(),
        DigestBytes::try_new(&[seed; 32]).unwrap(),
    )
}

fn oid(format: GitObjectFormat, seed: u8) -> GitOid {
    let (algorithm, bytes) = match format {
        GitObjectFormat::Sha1 => (GitHashAlgorithm::Sha1, 20),
        GitObjectFormat::Sha256 => (GitHashAlgorithm::Sha256, 32),
    };
    GitOid::from_hex(algorithm, &format!("{seed:02x}").repeat(bytes)).unwrap()
}

fn command(format: GitObjectFormat, name: &str, old: u8, new: u8) -> ReceiveCommand {
    ReceiveCommand {
        old: oid(format, old),
        new: oid(format, new),
        ref_name: name.as_bytes().to_vec(),
    }
}

fn context(format: GitObjectFormat, key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        head_key: HeadKey::new(b"fg/head/receive-microbatch".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        object_format: format,
    }
}

fn setup(
    context: &AdmissionContext,
    initial: &[(&str, u8)],
    head_target: Option<&str>,
) -> (Authority, StagingStore, Projection) {
    let refs = initial
        .iter()
        .map(|(name, seed)| {
            (
                RefName::try_new(name.as_bytes()).unwrap(),
                oid(context.object_format, *seed),
            )
        })
        .collect();
    let state = match head_target {
        Some(target) => CanonicalRefState::new_with_head_target(
            refs,
            RefName::try_new(target.as_bytes()).unwrap(),
        )
        .unwrap(),
        None => CanonicalRefState::new(refs),
    };
    let staging = StagingStore::default();
    let ref_root = canonical_ref_state_root(&state).unwrap();
    staging.stage_ref_state(ref_root, state).unwrap();
    let head = RepositoryAuthorityHeadBody {
        repository_id: context.repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root,
        forge_position_root: digest(16),
        outcome_index_root: digest(17),
        retention_root: digest(18),
        outbox_root: digest(19),
        configuration_root: digest(20),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let inner = MemoryAuthorityStore::new(StoreInstanceId::from_raw(290));
    initialize_repository(&inner, &context.head_key, &head).unwrap();
    let projection = Projection::new(staging.clone(), Evidence);
    (
        Authority {
            inner,
            publications: AtomicUsize::new(0),
            drop_response: AtomicBool::new(false),
            rival: Mutex::new(None),
            index_rival: Mutex::new(None),
        },
        staging,
        projection,
    )
}

struct DeclaredClosure;

impl QuarantineValidator for DeclaredClosure {
    fn validate(
        &self,
        request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
        _deadline: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        let objects = request
            .commands
            .iter()
            .filter(|value| !value.new.is_zero())
            .map(|value| value.new)
            .collect::<BTreeSet<_>>();
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))?,
            objects,
        })
    }
}

fn receive(
    format: GitObjectFormat,
    commands: Vec<ReceiveCommand>,
    atomic: bool,
) -> ValidatedReceive {
    let mut capabilities = vec![Capability {
        name: b"report-status".to_vec(),
        value: None,
    }];
    if atomic {
        capabilities.push(Capability {
            name: b"atomic".to_vec(),
            value: None,
        });
    }
    let request = ReceiveRequest {
        commands,
        capabilities,
        push_options: Vec::new(),
        certificate: None,
    };
    let mut bytes = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let pack_format = match format {
        GitObjectFormat::Sha1 => {
            let checksum = fgit_crypto::sha1_digest(&bytes);
            bytes.extend_from_slice(&checksum);
            fgit_pack::ObjectFormat::Sha1
        }
        GitObjectFormat::Sha256 => {
            let checksum = fgit_crypto::sha256_digest(&bytes);
            bytes.extend_from_slice(&checksum);
            fgit_pack::ObjectFormat::Sha256
        }
    };
    let pack = fgit_pack::read_verified_pack(
        &bytes,
        pack_format,
        &fgit_pack::PackLimits::default(),
        &mut || true,
        &fgit_pack::NativeChecksumVerifier,
    )
    .unwrap();
    let receipt = QuarantineReceipt {
        object_format: format,
        object_count: 0,
        pack_bytes: bytes.len(),
        delete_only: !request.requires_pack(),
    };
    validate_receive(
        &request,
        Some(&pack),
        &receipt,
        &DeclaredClosure,
        &mut || true,
    )
    .unwrap()
}

fn head(store: &MemoryAuthorityStore, context: &AdmissionContext) -> RepositoryAuthorityHeadBody {
    let HeadRead::Present(receipt) = store.read_head(&context.head_key).unwrap() else {
        panic!("initialized head absent")
    };
    store
        .authenticate_head_receipt(&receipt)
        .unwrap()
        .body()
        .unwrap()
}

fn refs(
    store: &MemoryAuthorityStore,
    staging: &StagingStore,
    context: &AdmissionContext,
) -> CanonicalRefState {
    staging
        .resolve_ref_state(head(store, context).ref_root)
        .unwrap()
}

fn codes(result: &AdmissionResult) -> Vec<Option<RefusalCode>> {
    result
        .commands
        .iter()
        .map(|value| match value.terminal.outcome {
            DecisionOutcome::Committed { .. } => None,
            DecisionOutcome::Refused { code, .. } => Some(code),
        })
        .collect()
}

fn batch(store: &MemoryAuthorityStore, context: &AdmissionContext) -> RepositoryDecisionBatchBody {
    let current = head(store, context);
    let batch = read_decision_batch_body(store, current.decision_tail_id.unwrap()).unwrap();
    let predecessor_id = current.predecessor_head_id.unwrap();
    let predecessor = read_authority_head_body(store, predecessor_id).unwrap();
    verify_pair(
        &CryptoBodyIdentity,
        &PublicationBasis::new(predecessor_id, predecessor),
        &batch,
        &current,
    )
    .unwrap();
    batch
}

fn verify_outcomes(
    store: &MemoryAuthorityStore,
    context: &AdmissionContext,
    result: &AdmissionResult,
) {
    for value in &result.commands {
        assert_eq!(
            resolve_outcome(
                store,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                value.tx_id
            )
            .unwrap(),
            OutcomeLookup::Decided(value.terminal)
        );
        if let DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } = value.terminal.outcome
        {
            let key = body_key_for_id(refusal_record_id.as_internal_object_id()).unwrap();
            let ImmutableRead::Present(bytes) = store.read_immutable(&key).unwrap() else {
                panic!("canonical refusal body absent")
            };
            let refusal = decode_body::<RefusalRecordBody>(&bytes, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(refusal.tx_id, value.tx_id);
            assert_eq!(
                refusal.decision_sequence, value.terminal.decision_sequence,
                "refusal body must be stamped at its actual batch position"
            );
            assert_eq!(refusal.code, code);
        }
    }
}

fn run(
    authority: &Authority,
    context: &AdmissionContext,
    receive: &ValidatedReceive,
    projection: &Projection,
) -> AdmissionResult {
    ready(admit_validated_receive_async(
        authority,
        &(),
        context,
        receive,
        AdmissionLimits::default(),
        projection,
    ))
    .unwrap()
}

#[test]
fn mixed_commands_match_sequential_oracle_and_share_one_authenticated_batch() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let context = context(format, b"mixed");
        let initial = [
            ("refs/heads/main", 1),
            ("refs/heads/stale", 6),
            ("refs/heads/remove", 4),
            ("refs/heads/hidden", 7),
            ("refs/heads/non-ff", 1),
        ];
        let input = receive(
            format,
            vec![
                command(format, "refs/heads/topic", 0, 2),
                command(format, "refs/heads/stale", 3, 4),
                command(format, "refs/heads/hidden", 7, 0),
                command(format, "refs/heads/remove", 4, 0),
                command(format, "refs/heads/absent", 0, 0),
                command(format, "refs/heads/main", 1, 0),
                command(format, "refs/heads/non-ff", 1, 2),
                command(format, "refs/heads/dir", 0, 2),
                command(format, "refs/heads/dir/child", 0, 2),
                command(format, "refs/heads/independent", 0, 3),
                command(format, "refs/heads/absent-stale", 9, 0),
            ],
            false,
        );
        let (reference, reference_bodies, reference_projection) =
            setup(&context, &initial, Some("refs/heads/main"));
        let expected = admit_validated_receive(
            &reference.inner,
            &context,
            &input,
            AdmissionLimits::default(),
            &Sequential(&reference_projection),
        )
        .unwrap();
        let (authority, staging, projection) = setup(&context, &initial, Some("refs/heads/main"));
        let actual = run(&authority, &context, &input, &projection);
        let (blocking, blocking_bodies, blocking_projection) =
            setup(&context, &initial, Some("refs/heads/main"));
        let blocking_result = admit_validated_receive(
            &blocking.inner,
            &context,
            &input,
            AdmissionLimits::default(),
            &blocking_projection,
        )
        .unwrap();
        assert_eq!(
            blocking_result, actual,
            "both batching drivers must produce identical canonical outcomes"
        );
        assert_eq!(
            refs(&blocking.inner, &blocking_bodies, &context),
            refs(&authority.inner, &staging, &context)
        );
        assert_eq!(
            batch(&blocking.inner, &context).decisions.len(),
            actual.commands.len()
        );
        assert_eq!(actual.session, expected.session);
        assert_eq!(actual.command_statuses(), expected.command_statuses());
        assert_eq!(codes(&actual), codes(&expected));
        assert_eq!(
            refs(&authority.inner, &staging, &context),
            refs(&reference.inner, &reference_bodies, &context)
        );
        let outcomes = codes(&actual);
        assert_eq!(outcomes[0], None);
        assert_eq!(outcomes[1], Some(RefusalCode::ExpectedOldRefMismatch));
        assert_eq!(outcomes[2], Some(RefusalCode::HiddenRefUnauthorized));
        assert_eq!(
            outcomes[4], None,
            "an already absent ref deletion commits as a no-op"
        );
        assert_eq!(outcomes[5], Some(RefusalCode::ProtectedRefTransitionDenied));
        assert_eq!(outcomes[6], Some(RefusalCode::NonFastForwardRefused));
        assert!(
            outcomes[8].is_some(),
            "a later namespace conflict must see the earlier successful create"
        );
        assert_eq!(
            outcomes[9], None,
            "refused siblings must not poison later commits"
        );
        assert_eq!(
            outcomes[10],
            Some(RefusalCode::ExpectedOldRefMismatch),
            "an exact nonzero old value still mismatches an absent ref"
        );
        assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
        assert_eq!(
            head(&authority.inner, &context).generation.get(),
            HeadGeneration::FIRST.get() + 1
        );
        let publication = batch(&authority.inner, &context);
        assert_eq!(publication.decisions.len(), actual.commands.len());
        assert_eq!(
            publication
                .decisions
                .iter()
                .map(|decision| decision.tx_id)
                .collect::<Vec<_>>(),
            actual.session.tx_ids
        );
        assert_eq!(
            publication.committed_rcrs.len(),
            outcomes.iter().filter(|code| code.is_none()).count()
        );
        verify_outcomes(&authority.inner, &context, &actual);
    }
}

#[test]
fn same_ref_create_update_delete_create_reads_prior_successful_decisions() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"read-your-own-prior-decisions");
    // The admission API accepts independent requests for one ref. The wire
    // parser's existing duplicate-ref refusal is deliberately not changed.
    let input = receive(
        format,
        vec![
            command(format, "refs/heads/chain", 0, 1),
            command(format, "refs/heads/chain", 1, 2),
            command(format, "refs/heads/chain", 2, 0),
            command(format, "refs/heads/chain", 0, 3),
        ],
        false,
    );
    let (reference, reference_bodies, reference_projection) = setup(&context, &[], None);
    let expected = admit_validated_receive(
        &reference.inner,
        &context,
        &input,
        AdmissionLimits::default(),
        &Sequential(&reference_projection),
    )
    .unwrap();
    let (authority, staging, projection) = setup(&context, &[], None);
    let actual = run(&authority, &context, &input, &projection);
    assert_eq!(
        codes(&actual),
        vec![None; 4],
        "dropping the intra-batch overlay turns the update/delete into stale refusals"
    );
    assert_eq!(actual.session, expected.session);
    assert_eq!(codes(&actual), codes(&expected));
    assert_eq!(
        refs(&authority.inner, &staging, &context),
        refs(&reference.inner, &reference_bodies, &context)
    );
    assert_eq!(
        refs(&authority.inner, &staging, &context).refs()
            [&RefName::try_new(b"refs/heads/chain").unwrap()],
        oid(format, 3)
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
    verify_outcomes(&authority.inner, &context, &actual);
}

#[test]
fn sixty_four_independent_commands_take_one_cas_and_retry_without_publication() {
    let format = GitObjectFormat::Sha256;
    let context = context(format, b"full-command-bound");
    let input = receive(
        format,
        (0..64)
            .map(|index| command(format, &format!("refs/tags/release-{index:02}"), 0, 1))
            .collect(),
        false,
    );
    let (authority, staging, projection) = setup(&context, &[], None);
    let first = run(&authority, &context, &input, &projection);
    assert_eq!(codes(&first), vec![None; 64]);
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
    assert_eq!(refs(&authority.inner, &staging, &context).refs().len(), 64);
    assert_eq!(batch(&authority.inner, &context).decisions.len(), 64);
    let before = authority.inner.read_head(&context.head_key).unwrap();
    let second = run(&authority, &context, &input, &projection);
    assert_eq!(
        second, first,
        "retry recovers original exact terminal records"
    );
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
    verify_outcomes(&authority.inner, &context, &second);
}

#[test]
fn an_unavailable_mid_chunk_stage_publishes_no_prefix_and_the_same_seals_retry() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"staging-failed");
    let input = receive(
        format,
        (0..3)
            .map(|index| command(format, &format!("refs/heads/branch-{index}"), 0, 1))
            .collect(),
        false,
    );
    let (reference, _, reference_projection) = setup(&context, &[], None);
    let expected = admit_validated_receive(
        &reference.inner,
        &context,
        &input,
        AdmissionLimits::default(),
        &Sequential(&reference_projection),
    )
    .unwrap();
    let (authority, staging, projection) = setup(&context, &[], None);
    staging.0.fail_ref_stage_at.store(3, Ordering::SeqCst); // genesis, first command, failure
    let before = authority.inner.read_head(&context.head_key).unwrap();
    assert!(
        ready(admit_validated_receive_async(
            &authority,
            &(),
            &context,
            &input,
            AdmissionLimits::default(),
            &projection
        ))
        .is_err()
    );
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 0);
    for tx_id in &expected.session.tx_ids {
        assert_eq!(
            resolve_outcome(
                &authority.inner,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                *tx_id
            )
            .unwrap(),
            OutcomeLookup::Undecided
        );
    }
    staging.0.fail_ref_stage_at.store(0, Ordering::SeqCst);
    let retried = run(&authority, &context, &input, &projection);
    assert_eq!(retried.session, expected.session);
    assert_eq!(codes(&retried), vec![None; 3]);
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
    verify_outcomes(&authority.inner, &context, &retried);
}

#[test]
fn a_foreign_cas_winner_replans_each_command_without_refusing_its_siblings() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"cas-loser");
    let input = receive(
        format,
        vec![
            command(format, "refs/heads/moving", 1, 2),
            command(format, "refs/heads/sibling", 0, 4),
        ],
        false,
    );
    let (authority, staging, projection) = setup(&context, &[("refs/heads/moving", 1)], None);
    let rival_context = AdmissionContext {
        idempotency_key: IdempotencyKey::new(b"foreign-winner".to_vec()).unwrap(),
        ..context.clone()
    };
    *authority.rival.lock().unwrap() = Some(Rival {
        context: rival_context,
        receive: receive(
            format,
            vec![command(format, "refs/heads/moving", 1, 3)],
            false,
        ),
        projection: projection.clone(),
        staging: staging.clone(),
        interrupt_after_first: false,
    });
    let result = run(&authority, &context, &input, &projection);
    assert_eq!(
        codes(&result),
        vec![Some(RefusalCode::ExpectedOldRefMismatch), None]
    );
    assert_eq!(
        authority.publications.load(Ordering::SeqCst),
        2,
        "one losing candidate and one replanned chunk"
    );
    let current = refs(&authority.inner, &staging, &context);
    assert_eq!(
        current.refs()[&RefName::try_new(b"refs/heads/moving").unwrap()],
        oid(format, 3)
    );
    assert_eq!(
        current.refs()[&RefName::try_new(b"refs/heads/sibling").unwrap()],
        oid(format, 4)
    );
    assert_eq!(batch(&authority.inner, &context).decisions.len(), 2);
    verify_outcomes(&authority.inner, &context, &result);
}

#[test]
fn a_partially_decided_same_session_replans_only_its_remaining_transactions() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"same-session-race");
    let input = receive(
        format,
        (0..3)
            .map(|index| command(format, &format!("refs/heads/race-{index}"), 0, 1))
            .collect(),
        false,
    );
    let (authority, staging, projection) = setup(&context, &[], None);
    *authority.rival.lock().unwrap() = Some(Rival {
        context: context.clone(),
        receive: input.clone(),
        projection: projection.clone(),
        staging: staging.clone(),
        interrupt_after_first: true,
    });
    let result = run(&authority, &context, &input, &projection);
    assert_eq!(codes(&result), vec![None; 3]);
    assert_eq!(
        head(&authority.inner, &context)
            .latest_decision_sequence
            .unwrap()
            .get(),
        3,
        "each original TxId has exactly one terminal decision"
    );
    let publication = batch(&authority.inner, &context);
    assert_eq!(
        publication.decisions.len(),
        2,
        "the already-decided prefix cannot be republished"
    );
    assert_eq!(
        publication
            .decisions
            .iter()
            .map(|decision| decision.tx_id)
            .collect::<Vec<_>>(),
        result.session.tx_ids[1..]
    );
    assert_eq!(refs(&authority.inner, &staging, &context).refs().len(), 3);
    verify_outcomes(&authority.inner, &context, &result);
    let before = authority.inner.read_head(&context.head_key).unwrap();
    assert_eq!(run(&authority, &context, &input, &projection), result);
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );
}

#[test]
fn a_lost_response_after_chunk_publication_recovers_every_original_outcome() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"lost-chunk-response");
    let input = receive(
        format,
        vec![
            command(format, "refs/heads/first", 0, 1),
            command(format, "refs/heads/second", 0, 2),
        ],
        false,
    );
    let (authority, _, projection) = setup(&context, &[], None);
    authority.drop_response.store(true, Ordering::SeqCst);
    let interrupted = ready(admit_validated_receive_async(
        &authority,
        &(),
        &context,
        &input,
        AdmissionLimits::default(),
        &projection,
    ));
    let published = authority.inner.read_head(&context.head_key).unwrap();
    assert_eq!(batch(&authority.inner, &context).decisions.len(), 2);
    let recovered = run(&authority, &context, &input, &projection);
    if let Ok(original) = interrupted {
        assert_eq!(original, recovered);
    }
    assert_eq!(codes(&recovered), vec![None; 2]);
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        published
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
    verify_outcomes(&authority.inner, &context, &recovered);
}

#[test]
fn production_session_coordinator_batches_and_retains_its_whole_request_binding() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"coordinator");
    // Delete-only input lets this test use the real public basis-bound
    // constructor without manufacturing a native-object validation receipt.
    let input = receive(
        format,
        vec![
            command(format, "refs/heads/first", 1, 0),
            command(format, "refs/heads/second", 2, 0),
        ],
        false,
    );
    let (authority, staging, projection) = setup(
        &context,
        &[("refs/heads/first", 1), ("refs/heads/second", 2)],
        None,
    );
    let initial = head(&authority.inner, &context);
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&initial).unwrap(),
        initial,
    );
    let bound = validate_receive_at_basis(
        input.request(),
        None,
        input.receipt(),
        &basis,
        &DeclaredClosure,
        &mut || true,
    )
    .unwrap();
    let result = ready(fgit_admission::policy_bridge::receive_session::admit(
        &authority,
        &(),
        &context,
        &bound,
        AdmissionLimits::default(),
        &projection,
    ))
    .unwrap();
    assert_eq!(codes(&result), vec![None; 2]);
    assert!(refs(&authority.inner, &staging, &context).refs().is_empty());
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
    let before = authority.inner.read_head(&context.head_key).unwrap();
    let repeated = ready(fgit_admission::policy_bridge::receive_session::admit(
        &authority,
        &(),
        &context,
        &bound,
        AdmissionLimits::default(),
        &projection,
    ))
    .unwrap();
    assert_eq!(result, repeated);
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );

    let changed = receive(
        format,
        vec![command(format, "refs/heads/first", 1, 0)],
        false,
    );
    let changed = validate_receive_at_basis(
        changed.request(),
        None,
        changed.receipt(),
        &basis,
        &DeclaredClosure,
        &mut || true,
    )
    .unwrap();
    assert!(
        ready(fgit_admission::policy_bridge::receive_session::admit(
            &authority,
            &(),
            &context,
            &changed,
            AdmissionLimits::default(),
            &projection
        ))
        .is_err(),
        "reusing the original key for a shorter session must refuse even when its prefix is already decided"
    );
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );
    verify_outcomes(&authority.inner, &context, &result);
}
