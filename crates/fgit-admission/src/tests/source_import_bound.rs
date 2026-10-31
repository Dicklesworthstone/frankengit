//! Basis-bound source imports through the real canonical admission driver.
//!
//! Native content verification belongs to the node import suites. This module
//! supplies explicit object-identity fixtures, then exercises real lowering,
//! sealing, canonical materialization, exact-head publication and recovery.

use super::*;
use std::future::ready;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AuthorityLimits, AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit,
    ImmutableKey, ImmutableRead, PutOutcome,
};

const BASE: u8 = 20;
const CANDIDATE: u8 = 42;
const CONCURRENT: u8 = 63;
const IMPORTED: &[u8] = b"refs/heads/imported";
const COPY: &[u8] = b"refs/heads/copied";
const OTHER: &[u8] = b"refs/heads/concurrent";

/// A synchronized version of the existing canonical backing fixture lets the
/// same source corpus run through both public admission surfaces.
#[derive(Clone, Default)]
struct Backing {
    refs: Arc<Mutex<BTreeMap<Digest, CanonicalRefState>>>,
    closures: Arc<Mutex<BTreeMap<Digest, PermittedObjectClosure>>>,
}

impl CanonicalAdmissionStore for Backing {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        self.refs
            .lock()
            .expect("fixture ref lock")
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_ref_state(&self, root: Digest, state: CanonicalRefState) -> Result<(), RefusalCode> {
        self.refs
            .lock()
            .expect("fixture ref lock")
            .insert(root, state);
        Ok(())
    }

    fn resolve_permitted_object_closure(
        &self,
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        self.closures
            .lock()
            .expect("fixture closure lock")
            .get(&root)
            .cloned()
            .ok_or(RefusalCode::EvidenceMissing)
    }

    fn stage_permitted_object_closure(
        &self,
        root: Digest,
        closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        self.closures
            .lock()
            .expect("fixture closure lock")
            .insert(root, closure);
        Ok(())
    }

    fn resolve_hidden_ref_policy(
        &self,
        _configuration_root: Digest,
    ) -> Result<RefVisibility, RefusalCode> {
        Ok(RefVisibility::new())
    }
}

type Projection = CanonicalAdmissionProjection<Backing, CanonicalFixtureEvidence>;

fn native_oid(format: GitObjectFormat, seed: u8) -> GitOid {
    match format {
        GitObjectFormat::Sha1 => GitOid::Sha1(fgit_types::GitOidSha1::from_bytes([seed; 20])),
        GitObjectFormat::Sha256 => GitOid::Sha256(fgit_types::GitOidSha256::from_bytes([seed; 32])),
    }
}

fn with_key(context: &AdmissionContext, key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        idempotency_key: IdempotencyKey::new(key.to_vec()).expect("bounded fixture key"),
        ..context.clone()
    }
}

fn closure(format: GitObjectFormat, seeds: &[u8]) -> ValidatedClosure {
    let objects = seeds.iter().map(|seed| native_oid(format, *seed)).collect();
    let permitted = PermittedObjectClosure::new(objects);
    ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&permitted)
            .expect("native closure root"),
        objects: permitted.objects().clone(),
    }
}

fn independent(format: GitObjectFormat, name: &[u8], seed: u8) -> ValidatedSourceImport {
    let updates = [SourceRefUpdate {
        old: native_oid(format, 0),
        new: native_oid(format, seed),
        ref_name: name.to_vec(),
    }];
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: 1,
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    validate_source_import(&updates, &receipt, closure(format, &[seed]))
        .expect("independent source covers its target")
}

fn committed(result: Result<AdmissionResult, AdmissionError>) -> AdmissionResult {
    let result = result.expect("admission reaches its canonical terminal decision");
    assert!(result.session.atomic);
    assert_eq!(result.session.tx_ids.len(), 1);
    assert!(!result.commands.is_empty());
    assert!(
        result.commands.iter().all(|command| {
            command == &result.commands[0]
                && matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })
        }),
        "{result:?}"
    );
    result
}

fn fixture(
    format: GitObjectFormat,
) -> (MemoryAuthorityStore, Backing, Projection, AdmissionContext) {
    let mut context = super::context();
    context.object_format = format;
    let backing = Backing::default();
    let projection = Projection::new(backing.clone(), CanonicalFixtureEvidence);
    let roots = projection
        .stage_initial_state(
            CanonicalRefState::default(),
            PermittedObjectClosure::new(BTreeSet::new()),
        )
        .expect("canonical genesis frames");
    let mut head = genesis(&context);
    head.ref_root = roots.ref_root;
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(79));
    initialize_repository(&store, &context.head_key, &head).expect("canonical genesis");

    // The prerequisite fixture is selected by actual canonical authority, not
    // merely claimed to exist in the incremental source receipt.
    committed(admit_validated_source_import(
        &store,
        &with_key(&context, b"seed-prerequisite"),
        &independent(format, b"refs/heads/base", BASE),
        AdmissionLimits::default(),
        &projection,
    ));
    (store, backing, projection, context)
}

fn source(
    format: GitObjectFormat,
) -> (Vec<SourceRefUpdate>, SourceImportReceipt, ValidatedClosure) {
    let updates = [IMPORTED, COPY]
        .into_iter()
        .map(|name| SourceRefUpdate {
            old: native_oid(format, 0),
            new: native_oid(format, CANDIDATE),
            ref_name: name.to_vec(),
        })
        .collect();
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: 2,
        delete_only: false,
        origin: SourceImportOrigin::IncrementalGitBundle {
            pack_checksum: native_oid(format, 91),
            pack_sha256: [92; 32],
            pack_bytes: 128,
            prerequisite_closure_root: closure(format, &[BASE]).object_closure_root,
        },
    };
    (updates, receipt, closure(format, &[BASE, CANDIDATE]))
}

fn bound(
    store: &MemoryAuthorityStore,
    context: &AdmissionContext,
) -> BasisBoundValidatedSourceImport {
    let (basis, _, _) = read_basis(store, &context.head_key).expect("authenticated source basis");
    let (updates, receipt, closure) = source(context.object_format);
    validate_source_import_at_basis(&updates, &receipt, closure, &basis)
        .expect("basis-bound source covers every proposed ref")
}

fn selected_refs(
    store: &MemoryAuthorityStore,
    context: &AdmissionContext,
    backing: &Backing,
) -> CanonicalRefState {
    let (basis, _, _) = read_basis(store, &context.head_key).expect("authenticated current basis");
    backing
        .resolve_ref_state(basis.body().ref_root)
        .expect("selected canonical refs")
}

fn advance(store: &MemoryAuthorityStore, context: &AdmissionContext, projection: &Projection) {
    committed(admit_validated_source_import(
        store,
        &with_key(context, b"concurrent-authority-change"),
        &independent(context.object_format, OTHER, CONCURRENT),
        AdmissionLimits::default(),
        projection,
    ));
}

#[test]
fn incremental_origin_cannot_enter_unbound_admission_and_independent_twins_still_commit() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (store, _, _, context) = fixture(format);
        let (basis, _, _) = read_basis(&store, &context.head_key).unwrap();
        let (updates, receipt, selected) = source(format);
        assert_eq!(
            validate_source_import(&updates, &receipt, selected.clone()),
            Err(RefusalCode::EvidenceInvalid),
        );
        assert_eq!(
            validate_source_import_at_basis(&updates, &receipt, closure(format, &[BASE]), &basis,),
            Err(RefusalCode::ObjectClosureIncomplete),
        );
        let proof =
            validate_source_import_at_basis(&updates, &receipt, selected.clone(), &basis).unwrap();
        assert_eq!(proof.updates(), updates);
        assert_eq!(proof.receipt(), &receipt);
        assert_eq!(proof.validation_basis(), basis.id());

        for origin in [
            SourceImportOrigin::LocalGitDirectory,
            SourceImportOrigin::FullGitBundle {
                pack_checksum: native_oid(format, 91),
                pack_sha256: [92; 32],
                pack_bytes: 128,
            },
        ] {
            let (store, backing, projection, context) = fixture(format);
            let independent_receipt = SourceImportReceipt {
                origin,
                ..receipt.clone()
            };
            let proof = validate_source_import(&updates, &independent_receipt, selected.clone())
                .expect("independent origin remains admitted");
            let result = committed(admit_validated_source_import(
                &store,
                &context,
                &proof,
                AdmissionLimits::default(),
                &projection,
            ));
            assert_eq!(result.commands.len(), 2);
            let refs = selected_refs(&store, &context, &backing);
            for name in [IMPORTED, COPY] {
                assert_eq!(
                    refs.refs().get(&RefName::try_new(name).unwrap()),
                    Some(&native_oid(format, CANDIDATE))
                );
            }
        }
    }
}

#[test]
fn a_bound_source_commits_atomically_then_replays_before_basis_freshness() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (store, backing, projection, context) = fixture(format);
        let proof = bound(&store, &context);
        let first = committed(admit_basis_bound_source_import(
            &store,
            &context,
            &proof,
            AdmissionLimits::default(),
            &projection,
        ));
        assert_eq!(first.commands.len(), 2);
        let refs = selected_refs(&store, &context, &backing);
        for name in [IMPORTED, COPY] {
            assert_eq!(
                refs.refs().get(&RefName::try_new(name).unwrap()),
                Some(&native_oid(format, CANDIDATE))
            );
        }

        advance(&store, &context, &projection);
        let (before_retry, _, _) = read_basis(&store, &context.head_key).unwrap();
        assert_ne!(before_retry.id(), proof.validation_basis());
        let replay = admit_basis_bound_source_import(
            &store,
            &context,
            &proof,
            AdmissionLimits::default(),
            &projection,
        )
        .unwrap();
        assert_eq!(replay, first);
        let async_replay = poll_ready(admit_basis_bound_source_import_async(
            &AsyncView(&store),
            &(),
            &context,
            &proof,
            AdmissionLimits::default(),
            &projection,
        ))
        .unwrap();
        assert_eq!(async_replay, first);
        assert_eq!(
            read_basis(&store, &context.head_key).unwrap().0,
            before_retry
        );
    }
}

#[test]
fn stale_initial_source_refuses_all_refs_and_revalidation_with_a_new_key_is_permitted() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (store, backing, projection, context) = fixture(format);
        let proof = bound(&store, &context);
        advance(&store, &context, &projection);
        let refs_before = selected_refs(&store, &context, &backing);
        let refused = admit_basis_bound_source_import(
            &store,
            &context,
            &proof,
            AdmissionLimits::default(),
            &projection,
        )
        .unwrap();
        assert_eq!(refused.commands.len(), 2);
        assert!(
            refused.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::AuthorityReceiptStale,
                    ..
                }
            )),
            "{refused:?}"
        );
        assert_eq!(selected_refs(&store, &context, &backing), refs_before);

        let (after_refusal, _, _) = read_basis(&store, &context.head_key).unwrap();
        // Even revalidated evidence cannot overwrite the original terminal
        // decision: the identical semantic request and key recover it.
        let refreshed = bound(&store, &context);
        assert_eq!(
            admit_basis_bound_source_import(
                &store,
                &context,
                &refreshed,
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap(),
            refused
        );
        assert_eq!(
            poll_ready(admit_basis_bound_source_import_async(
                &AsyncView(&store),
                &(),
                &context,
                &proof,
                AdmissionLimits::default(),
                &projection,
            ))
            .unwrap(),
            refused
        );
        assert_eq!(
            read_basis(&store, &context.head_key).unwrap().0,
            after_refusal
        );

        committed(admit_basis_bound_source_import(
            &store,
            &with_key(&context, b"revalidated-source"),
            &refreshed,
            AdmissionLimits::default(),
            &projection,
        ));
        let refs = selected_refs(&store, &context, &backing);
        assert_eq!(
            refs.refs().get(&RefName::try_new(OTHER).unwrap()),
            Some(&native_oid(format, CONCURRENT))
        );
        assert_eq!(
            refs.refs().get(&RefName::try_new(IMPORTED).unwrap()),
            Some(&native_oid(format, CANDIDATE))
        );
    }
}

/// Advances the actual authority after candidate materialization, immediately
/// before the outer CAS. No synthetic head or predetermined refusal is used.
struct RacingProjection<'a> {
    store: &'a MemoryAuthorityStore,
    context: &'a AdmissionContext,
    inner: &'a Projection,
    advanced: Cell<bool>,
}

impl AdmissionSnapshotProjection for RacingProjection<'_> {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        self.inner.snapshot(basis, authenticated)
    }
}

impl AdmissionProjection for RacingProjection<'_> {
    fn materialize_commit(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        let candidate = self
            .inner
            .materialize_commit(basis, request, fold, closure)?;
        if !self.advanced.replace(true) {
            advance(self.store, self.context, self.inner);
        }
        Ok(candidate)
    }

    fn materialize_refusal(
        &self,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        self.inner.materialize_refusal(basis, tx_id, code)
    }
}

#[test]
fn a_cas_loser_cannot_reuse_prerequisite_authority_from_the_displaced_head() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (store, backing, projection, context) = fixture(format);
        let proof = bound(&store, &context);
        let racing = RacingProjection {
            store: &store,
            context: &context,
            inner: &projection,
            advanced: Cell::new(false),
        };
        let refused = admit_basis_bound_source_import(
            &store,
            &context,
            &proof,
            AdmissionLimits::default(),
            &racing,
        )
        .unwrap();
        assert!(
            racing.advanced.get(),
            "the fixture must actually win a competing publication"
        );
        assert!(
            refused.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::AuthorityReceiptStale,
                    ..
                }
            )),
            "{refused:?}"
        );
        let refs = selected_refs(&store, &context, &backing);
        assert_eq!(
            refs.refs().get(&RefName::try_new(OTHER).unwrap()),
            Some(&native_oid(format, CONCURRENT))
        );
        for name in [IMPORTED, COPY] {
            assert!(!refs.refs().contains_key(&RefName::try_new(name).unwrap()));
        }
        let (after_refusal, _, _) = read_basis(&store, &context.head_key).unwrap();
        assert_eq!(
            admit_basis_bound_source_import(
                &store,
                &context,
                &proof,
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap(),
            refused
        );
        assert_eq!(
            read_basis(&store, &context.head_key).unwrap().0,
            after_refusal
        );

        let refreshed = bound(&store, &context);
        committed(admit_basis_bound_source_import(
            &store,
            &with_key(&context, b"after-cas-revalidation"),
            &refreshed,
            AdmissionLimits::default(),
            &projection,
        ));
    }
}

/// Resolved reference-store operations provide an async interface without a
/// second runtime or a blocking production adapter.
struct AsyncView<'a>(&'a MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncView<'_> {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        _cx: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        ready(self.0.put_if_absent(key, body))
    }

    fn read_immutable(
        &self,
        _cx: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        ready(self.0.read_immutable(key))
    }

    fn initialize_head(
        &self,
        _cx: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        ready(self.0.initialize_head(key, generation, body))
    }

    fn read_head(
        &self,
        _cx: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        ready(self.0.read_head(key))
    }

    fn compare_exchange_head(
        &self,
        _cx: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        ready(
            self.0
                .compare_exchange_head(key, expected, generation, body),
        )
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
        ready(
            self.0
                .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness),
        )
    }

    fn authenticate_head_receipt(
        &self,
        _cx: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        ready(self.0.authenticate_head_receipt(receipt))
    }
}

fn poll_ready<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("in-memory authority operations must resolve without suspension"),
    }
}

#[test]
fn sync_and_async_bound_source_admission_agree_on_commit_refusal_and_retry() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for stale in [false, true] {
            let (sync_store, sync_backing, sync_projection, sync_context) = fixture(format);
            let (async_store, async_backing, async_projection, async_context) = fixture(format);
            let sync_proof = bound(&sync_store, &sync_context);
            let async_proof = bound(&async_store, &async_context);
            assert_eq!(
                sync_proof.validation_basis(),
                async_proof.validation_basis()
            );
            if stale {
                advance(&sync_store, &sync_context, &sync_projection);
                advance(&async_store, &async_context, &async_projection);
            }
            let sync_result = admit_basis_bound_source_import(
                &sync_store,
                &sync_context,
                &sync_proof,
                AdmissionLimits::default(),
                &sync_projection,
            )
            .unwrap();
            let async_result = poll_ready(admit_basis_bound_source_import_async(
                &AsyncView(&async_store),
                &(),
                &async_context,
                &async_proof,
                AdmissionLimits::default(),
                &async_projection,
            ))
            .unwrap();
            assert_eq!(sync_result, async_result);
            if stale {
                assert!(matches!(
                    sync_result.commands[0].terminal.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::AuthorityReceiptStale,
                        ..
                    }
                ));
            } else {
                assert!(matches!(
                    sync_result.commands[0].terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
            }
            assert_eq!(
                selected_refs(&sync_store, &sync_context, &sync_backing),
                selected_refs(&async_store, &async_context, &async_backing)
            );
            let sync_head = read_basis(&sync_store, &sync_context.head_key).unwrap().0;
            let async_head = read_basis(&async_store, &async_context.head_key).unwrap().0;
            assert_eq!(sync_head, async_head);
            assert_eq!(
                admit_basis_bound_source_import(
                    &sync_store,
                    &sync_context,
                    &sync_proof,
                    AdmissionLimits::default(),
                    &sync_projection,
                )
                .unwrap(),
                sync_result
            );
            assert_eq!(
                poll_ready(admit_basis_bound_source_import_async(
                    &AsyncView(&async_store),
                    &(),
                    &async_context,
                    &async_proof,
                    AdmissionLimits::default(),
                    &async_projection,
                ))
                .unwrap(),
                async_result
            );
            assert_eq!(
                read_basis(&sync_store, &sync_context.head_key).unwrap().0,
                sync_head
            );
            assert_eq!(
                read_basis(&async_store, &async_context.head_key).unwrap().0,
                async_head
            );
        }
    }
}
