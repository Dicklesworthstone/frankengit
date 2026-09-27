#![forbid(unsafe_code)]
//! The receipt-bearing API must be the original native method, not a new seal.
#[path = "fast_forward_command/fixture.rs"]
mod fixture;
use fixture::*;

use fgit_admission::merge::native::{NativeMergeIntent, objects::MergeObjectLimits};
use fgit_authority::TerminalOutcome;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::{AggregateVersion, ExpectedVersion, ForgeEventPayload, PullRequestNumber};
use fgit_node::{NodeReceiveTransportRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, RefusalCode, TxId};

fn call(node: &OneNode, source: GitOid, target: GitOid, version: AggregateVersion, key: &[u8], limits: MergeObjectLimits)
    -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>
{
    let request = node.request_context();
    node.runtime().block_on(node.fast_forward_pull_request_durable_in(
        &request, &session(key), PullRequestNumber::FIRST, version,
        &topic_ref(), source, &main_ref(), target, Default::default(), limits,
    ))
}
fn head(node: &OneNode) -> fgit_types::HeadGeneration {
    node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation()
}

#[test]
fn receipt_retries_share_the_native_seal_and_survive_reopen_before_service() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch.0, format, false);
        let (tx, outcome) = call(&f.node, f.source, f.target, AggregateVersion::FIRST, b"receipt", Default::default()).unwrap();
        committed(outcome);
        let request = f.node.request_context();
        let original = NativeMergeIntent::fast_forward_only(PullRequestNumber::FIRST, AggregateVersion::FIRST,
            topic_ref(), f.source, main_ref(), f.target).unwrap();
        assert_eq!(f.node.runtime().block_on(f.node.admit_native_merge_durable_in(
            &request, &session(b"receipt"), &original, Default::default(), Default::default()
        )).unwrap(), outcome);
        let selected = f.node.runtime().block_on(f.node.materialize_admission_in(&request)).unwrap();
        assert_eq!(selected.snapshot().refs[&main_ref()], f.source);
        assert_eq!(selected.snapshot().refs[&topic_ref()], f.source);
        let page = f.node.runtime().block_on(f.node.read_pull_requests_in(&request, &Default::default(), 0, 1, None)).unwrap();
        assert_eq!(page.pull_requests[0].event, *original.event());
        let after = head(&f.node);
        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        // Deliberately do not bring the cell into service. This is a historical
        // outcome read; no fresh policy, budget or intake gate may erase it.
        assert_eq!(call(&reopened, f.source, f.target, AggregateVersion::FIRST, b"receipt", Default::default()).unwrap(), (tx, outcome));
        assert_eq!(head(&reopened), after);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn divergent_and_stale_requests_are_terminal_without_ref_only_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch.0, format, true);
        let first = call(&f.node, f.source, f.target, AggregateVersion::FIRST, b"divergent", Default::default()).unwrap();
        assert!(matches!(first.1.outcome, DecisionOutcome::Refused { code: RefusalCode::NonFastForwardRefused, .. }));
        assert_eq!(call(&f.node, f.source, f.target, AggregateVersion::FIRST, b"divergent", Default::default()).unwrap(), first);
        let stale = call(&f.node, f.source, f.target, AggregateVersion::try_new(2).unwrap(), b"stale", Default::default()).unwrap();
        assert!(matches!(stale.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
        let request = f.node.request_context();
        let selected = f.node.runtime().block_on(f.node.materialize_admission_in(&request)).unwrap();
        assert_eq!(selected.snapshot().refs[&main_ref()], f.target);
        let page = f.node.runtime().block_on(f.node.read_pull_requests_in(&request, &Default::default(), 0, 1, None)).unwrap();
        assert!(matches!(page.pull_requests[0].event.payload, ForgeEventPayload::PullRequestChangedNative(_)));
        f.node.shutdown().unwrap();
    }
}

#[test]
fn construction_errors_do_not_publish_and_object_budgets_keep_the_seal_retryable() {
    let scratch = Scratch::new();
    let mut f = fixture(&scratch.0, GitHashAlgorithm::Sha256, false);
    let before = head(&f.node);
    assert!(call(&f.node, f.source, f.source, AggregateVersion::FIRST, b"equal", Default::default()).is_err());
    assert!(call(&f.node, f.source, f.target, AggregateVersion::try_new(u64::MAX).unwrap(), b"exhausted", Default::default()).is_err());
    assert_eq!(head(&f.node), before);
    assert!(call(&f.node, f.source, f.target, AggregateVersion::FIRST, b"budget",
        MergeObjectLimits { max_objects: 1, ..Default::default() }).is_err());
    let (_, terminal) = call(&f.node, f.source, f.target, AggregateVersion::FIRST, b"budget", Default::default()).unwrap();
    committed(terminal);
    f.node.shutdown().unwrap();
}

#[test]
fn a_returned_receipt_does_not_allow_changing_method_or_expected_coordinates() {
    let scratch = Scratch::new();
    let mut f = fixture(&scratch.0, GitHashAlgorithm::Sha1, false);
    committed(call(&f.node, f.source, f.target, AggregateVersion::FIRST, b"bound", Default::default()).unwrap().1);
    let published = head(&f.node);
    let request = f.node.request_context();
    let ff = NativeMergeIntent::fast_forward_only(PullRequestNumber::FIRST, AggregateVersion::FIRST,
        topic_ref(), f.source, main_ref(), f.target).unwrap();
    let ordinary = NativeMergeIntent::new(PullRequestNumber::FIRST, ExpectedVersion::Exactly(AggregateVersion::FIRST), ff.merge().unwrap().clone()).unwrap();
    assert!(f.node.runtime().block_on(f.node.admit_native_merge_durable_in(
        &request, &session(b"bound"), &ordinary, Default::default(), Default::default()
    )).is_err());
    assert!(call(&f.node, f.source, f.target, AggregateVersion::try_new(2).unwrap(), b"bound", Default::default()).is_err());
    assert_eq!(head(&f.node), published);
    f.node.shutdown().unwrap();
}

#[test]
fn receipt_api_keeps_mandatory_review_protection_on_the_real_publication_path() {
    let scratch = Scratch::new();
    let mut f = fixture(&scratch.0, GitHashAlgorithm::Sha1, false);
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            administrators: vec![actor(2)],
            branches: vec![ProtectedBranch { name: main_ref(), reviewers: vec![actor(3)] }],
        },
    };
    let request = f.node.request_context();
    committed(f.node.runtime().block_on(f.node.admit_review_protection_durable_in(
        &request, &session(b"protect"), &command, Default::default()
    )).unwrap().1);
    let (_, outcome) = call(&f.node, f.source, f.target, AggregateVersion::FIRST, b"protected", Default::default()).unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Refused { .. }));
    let request = f.node.request_context();
    let selected = f.node.runtime().block_on(f.node.materialize_admission_in(&request)).unwrap();
    assert_eq!(selected.snapshot().refs[&main_ref()], f.target);
    f.node.shutdown().unwrap();
}
