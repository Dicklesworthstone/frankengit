#![forbid(unsafe_code)]
//! Fault only the retired historical event read on a real file-backed node.
//! Accepted publications, selected roots and delivery retirement stay intact.

use super::*;
use fgit_admission::{AdmissionError, merge::native::issues as native_issues};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId,
};
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Copy, Debug)]
enum Fault {
    Absent,
    Corrupt,
    Cancel,
}

struct HistoricalReadFault<'a> {
    node: &'a OneNode,
    key: ImmutableKey,
    fault: Fault,
    reads: AtomicUsize,
}

impl AsyncAuthorityStore for HistoricalReadFault<'_> {
    type Context = Cx;

    fn instance_id(&self) -> StoreInstanceId {
        AsyncAuthorityStore::instance_id(&self.node.authority)
    }

    fn limits(&self) -> AuthorityLimits {
        AsyncAuthorityStore::limits(&self.node.authority)
    }

    async fn read_immutable(
        &self,
        cx: &Cx,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        let original = AsyncAuthorityStore::read_immutable(&self.node.authority, cx, key).await?;
        if key != &self.key {
            return Ok(original);
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        let ImmutableRead::Present(mut frame) = original else {
            panic!("the real retired event remains durably stored");
        };
        Ok(match self.fault {
            Fault::Absent => ImmutableRead::Absent,
            Fault::Corrupt => {
                frame[0] ^= 1;
                ImmutableRead::Present(frame)
            }
            Fault::Cancel => {
                // Cancel at the await boundary after a successful native read.
                // The history walk must drain/refuse, not return partial state.
                cx.cancel();
                ImmutableRead::Present(frame)
            }
        })
    }

    async fn put_if_absent(
        &self,
        cx: &Cx,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        AsyncAuthorityStore::put_if_absent(&self.node.authority, cx, key, body).await
    }

    async fn initialize_head(
        &self,
        cx: &Cx,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        AsyncAuthorityStore::initialize_head(&self.node.authority, cx, key, generation, body).await
    }

    async fn read_head(&self, cx: &Cx, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        AsyncAuthorityStore::read_head(&self.node.authority, cx, key).await
    }

    async fn compare_exchange_head(
        &self,
        cx: &Cx,
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
        cx: &Cx,
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
        cx: &Cx,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        AsyncAuthorityStore::authenticate_head_receipt(&self.node.authority, cx, receipt).await
    }
}

#[test]
fn complete_active_issue_history_does_not_consult_an_unavailable_decision_ancestor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        publish_issue(&node, &open_issue(), "active-history-open");
        publish_issue(
            &node,
            &issue_command(
                1,
                IssueAction::Comment {
                    body: "Both accepted events are still in the active outbox".into(),
                },
            ),
            "active-history-comment",
        );
        let selected = snapshot(&node);
        assert_eq!(selected.snapshot().outbox.len(), 2);
        let expected = issue_history(&node, 0, 100, None);
        assert_eq!(expected.events.len(), 2);
        let store = HistoricalReadFault {
            node: &node,
            key: fgit_authority::body_key_for_id(
                selected
                    .basis()
                    .body()
                    .decision_tail_id
                    .unwrap()
                    .as_internal_object_id(),
            )
            .unwrap(),
            fault: Fault::Absent,
            reads: AtomicUsize::new(0),
        };
        let request = node.request_context();
        let actual = node
            .runtime()
            .block_on(native_issues::read_history_at(
                &store,
                request.authority(),
                selected.basis(),
                IssueNumber::FIRST,
                0,
                100,
                &|| !crate::treefs_workspace::workspace_request_live(&request),
            ))
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            store.reads.load(Ordering::SeqCst),
            0,
            "complete selected events must not acquire an unrelated history dependency"
        );
        assert_eq!(snapshot(&node).basis(), selected.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_corrupt_or_cancelled_retired_history_never_becomes_an_empty_or_partial_issue() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let initial = snapshot(&node);
        publish_issue(&node, &open_issue(), "fault-history-open");
        let opening_key = new_delivery(&initial, &snapshot(&node));
        publish_issue(
            &node,
            &issue_command(
                1,
                IssueAction::Edit(IssueEdit {
                    title: Some("Still requires its retired opening event".into()),
                    ..Default::default()
                }),
            ),
            "fault-history-edit",
        );
        let mut receiver = ReceiptDestination::new(scratch.0.join("fault-receiver"));
        let root = retire(&node, &mut receiver, opening_key);
        let selected = snapshot(&node);
        let key = crate::admission_immutable_key(
            crate::ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            node.repository_id(),
            root,
        )
        .unwrap();
        let expected = issue_history(&node, 0, 100, None);
        assert_eq!(expected.events.len(), 2);
        for (fault, expected_code) in [
            (Fault::Absent, RefusalCode::EvidenceMissing),
            (Fault::Corrupt, RefusalCode::EvidenceInvalid),
            (Fault::Cancel, RefusalCode::CancellationInProgress),
        ] {
            let store = HistoricalReadFault {
                node: &node,
                key: key.clone(),
                fault,
                reads: AtomicUsize::new(0),
            };
            let request = node.request_context();
            let result = node.runtime().block_on(native_issues::read_history_at(
                &store,
                request.authority(),
                selected.basis(),
                IssueNumber::FIRST,
                0,
                100,
                &|| !crate::treefs_workspace::workspace_request_live(&request),
            ));
            assert!(
                store.reads.load(Ordering::SeqCst) > 0,
                "fault must reach retired history"
            );
            assert!(
                matches!(result,
                    Err(AdmissionError::AsyncProjectionUnavailable(code)) if code == expected_code
                ),
                "{fault:?} must preserve its refusal, observed {result:?}"
            );
            assert_eq!(snapshot(&node).basis(), selected.basis());
            assert_eq!(
                issue_history(&node, 0, 100, None),
                expected,
                "permitted retry after {fault:?}"
            );
        }
        node.shutdown().unwrap();
    }
}
