//! Fault injection at a real asynchronous authority read after projection entry.
//! The node, runtime, database, frames, materializer and protection evaluator are
//! production implementations. The adapter selects the one interrupted read;
//! this is deterministic native regression coverage, not a load campaign.

use super::*;
use crate::{ADMISSION_REF_STATE_KEY_PREFIX, async_projection_unavailable};
use fgit_admission::ProjectionFailure;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken, CasOutcome,
    DuplicateAbsenceWitness, HeadKey, HeadReadReceipt, ImmutableKey, PutOutcome, StoreInstanceId,
};
use fgit_reference::effect::RefEffect;
use fgit_types::HeadGeneration;
use std::sync::atomic::AtomicBool;

const POSITION_PREFIX: &[u8] = b"frankengit/admission/forge-position-state/v1/";
const CONFIG_PREFIX: &[u8] = fgit_authority::BODY_KEY_PREFIX;

#[derive(Clone, Copy)]
enum Fault {
    Cancel,
    Deadline,
    Absent,
    Corrupt,
    InvalidReceipt,
}

/// Only a matching immutable read is changed. Cancellation goes through the
/// actual request Cx and FrankenSQLite operation, not a fabricated final error.
struct ReadFault<'a> {
    node: &'a OneNode,
    prefix: &'static [u8],
    fault: Fault,
    fired: AtomicBool,
}

impl<'a> ReadFault<'a> {
    fn new(node: &'a OneNode, prefix: &'static [u8], fault: Fault) -> Self {
        Self {
            node,
            prefix,
            fault,
            fired: AtomicBool::new(false),
        }
    }
}

impl AsyncAuthorityStore for ReadFault<'_> {
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
        if key.as_bytes().starts_with(self.prefix) && !self.fired.swap(true, Ordering::SeqCst) {
            match self.fault {
                Fault::Cancel => cx.cancel(),
                Fault::Deadline => cx.set_native_cx(self.node.runtime.request_cx_with_budget(
                    ClassLimits::finite(Duration::ZERO, 1_000, 1_000).at(self.node.runtime.now()),
                )),
                Fault::Absent => return Ok(ImmutableRead::Absent),
                Fault::Corrupt => {
                    return Ok(ImmutableRead::Present(b"corrupt canonical frame".to_vec()));
                }
                Fault::InvalidReceipt => {
                    let HeadRead::Present(receipt) = AsyncAuthorityStore::read_head(
                        &self.node.authority,
                        cx,
                        &self.node.head_key,
                    )
                    .await?
                    else {
                        panic!("the initialized node retains its head");
                    };
                    let mut changed = receipt.body().to_vec();
                    changed[0] ^= 1;
                    let tampered = HeadReadReceipt::new(
                        receipt.key().clone(),
                        receipt.token(),
                        receipt.generation(),
                        changed,
                    );
                    return Err(AsyncAuthorityStore::authenticate_head_receipt(
                        &self.node.authority,
                        cx,
                        &tampered,
                    )
                    .await
                    .expect_err("the real authority must reject altered issued bytes"));
                }
            }
        }
        AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await
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

    async fn publish_head_with_outcomes(
        &self,
        cx: &FsqliteCx,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        AsyncAuthorityStore::publish_head_with_outcomes(
            &self.node.authority,
            cx,
            key,
            expected,
            generation,
            body,
            outcomes,
            witness,
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

fn ref_fold(node: &OneNode) -> TransactionFoldReport {
    let (_, _, mut fold) = evidence_request(node);
    let FoldOutcome::Folded(effects) = &mut fold.outcome else {
        unreachable!()
    };
    effects.refs.insert(
        RefName::try_new(b"refs/heads/cancellation-twin").unwrap(),
        RefEffect::Set(
            GitOid::from_hex(
                node.object_format,
                &"12".repeat(if node.object_format == GitHashAlgorithm::Sha1 {
                    20
                } else {
                    32
                }),
            )
            .unwrap(),
        ),
    );
    fold
}

#[test]
fn authority_read_interruption_survives_snapshot_history_and_delivery_adapters() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf()).with_object_format(format);
        let (node, _) = OneNode::init(config).unwrap();
        let live = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&live))
            .unwrap();
        for prefix in [
            ADMISSION_REF_STATE_KEY_PREFIX,
            CONFIG_PREFIX,
            POSITION_PREFIX,
        ] {
            for fault in [Fault::Cancel, Fault::Deadline] {
                let store = ReadFault::new(&node, prefix, fault);
                let interrupted = node.request_context();
                let error = node
                    .runtime()
                    .block_on(node.admission_materializer.materialize_exact_in(
                        &store,
                        interrupted.authority(),
                        node.repository_id(),
                        selected.basis(),
                        selected.authenticated(),
                        &|| false,
                    ))
                    .unwrap_err();
                assert!(
                    store.fired.load(Ordering::SeqCst),
                    "the chosen production read was reached"
                );
                assert_eq!(
                    async_projection_unavailable(error),
                    ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress),
                    "x2mv.4.51 acceptance 1: no corrupt/missing claim from an interrupted read"
                );
                let retry = node.request_context();
                let recovered = node
                    .runtime()
                    .block_on(node.materialize_admission_in(&retry))
                    .unwrap();
                assert_eq!(
                    recovered.basis(),
                    selected.basis(),
                    "permitted twin: healthy canonical state still materializes after interruption"
                );
            }
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn protection_read_interruption_remains_nonterminal_and_integrity_twins_stay_distinct() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf()).with_object_format(format);
        let (node, _) = OneNode::init(config).unwrap();
        let live = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&live))
            .unwrap();
        let fold = ref_fold(&node);
        for (fault, expected) in [
            (Fault::Cancel, RefusalCode::CancellationInProgress),
            (Fault::Deadline, RefusalCode::CancellationInProgress),
            (Fault::InvalidReceipt, RefusalCode::AuthorityReceiptInvalid),
            (Fault::Corrupt, RefusalCode::EvidenceInvalid),
        ] {
            let store = ReadFault::new(&node, POSITION_PREFIX, fault);
            let request = node.request_context();
            let result = node.runtime().block_on(
                fgit_admission::merge::native::protection::enforce_direct_at(
                    &store,
                    request.authority(),
                    selected.basis(),
                    &fold,
                    &|| false,
                ),
            );
            assert!(store.fired.load(Ordering::SeqCst));
            assert_eq!(
                result,
                Err(ProjectionFailure::Unavailable(expected)),
                "x2mv.4.51 acceptance 1/2: interruption and actual integrity remain distinct"
            );
            let retry = node.request_context();
            node.runtime()
                .block_on(
                    fgit_admission::merge::native::protection::enforce_direct_at(
                        &node.authority,
                        retry.authority(),
                        selected.basis(),
                        &fold,
                        &|| false,
                    ),
                )
                .expect("permitted twin: the same unprotected ref remains admissible");
        }
        let missing = ReadFault::new(&node, ADMISSION_REF_STATE_KEY_PREFIX, Fault::Absent);
        let request = node.request_context();
        let error = node
            .runtime()
            .block_on(node.admission_materializer.materialize_exact_in(
                &missing,
                request.authority(),
                node.repository_id(),
                selected.basis(),
                selected.authenticated(),
                &|| false,
            ))
            .unwrap_err();
        assert!(missing.fired.load(Ordering::SeqCst));
        assert_eq!(
            async_projection_unavailable(error),
            ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing),
            "x2mv.4.51 acceptance 2: actually absent selected evidence is still missing"
        );
        let retry = node.request_context();
        let recovered = node
            .runtime()
            .block_on(node.materialize_admission_in(&retry))
            .unwrap();
        assert_eq!(recovered.basis(), selected.basis());
        node.shutdown().unwrap();
    }
}
