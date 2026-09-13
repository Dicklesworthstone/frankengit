//! End-to-end publication through the native rebase API, not a test publisher.
use super::*;
use fgit_admission::AdmissionResult;
use crate::{MaterializedAdmission, NodeWorkspaceRefusal};

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime().block_on(node.materialize_admission_in(&node.request_context())).unwrap()
}
fn prepared(node: &OneNode, f: &Fixture, empty: bool) -> (GitOid, Vec<u8>) {
    let mut inputs = rebase_inputs(f);
    if empty { inputs.upstream = f.source; }
    let artifact = node.runtime().block_on(node.prepare_rebase_bundle_in(
        &node.request_context(), &topic_ref(), &main_ref(), inputs, &Default::default(),
        None, &committer(), PreparationLimits::default(),
    )).unwrap();
    let RebasePreparation::Clean(plan) = artifact.outcome else { panic!("clean rebase expected"); };
    (plan.commit, artifact.bundle.unwrap())
}
fn apply(node: &OneNode, f: &Fixture, candidate: GitOid, bundle: &[u8], key: &[u8])
    -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    node.runtime().block_on(node.apply_rebase_bundle_durable_in(&node.request_context(),
        principal(), key, &topic_ref(), f.source, f.target, candidate, bundle))
}
fn committed(result: Result<AdmissionResult, NodeWorkspaceRefusal>) -> AdmissionResult {
    let result = result.unwrap();
    assert!(result.session.atomic);
    assert_eq!(result.commands.len(), 1);
    assert_eq!(result.session.tx_ids, vec![result.commands[0].tx_id]);
    assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }), "{result:?}");
    result
}
fn empty_pack_bundle(format: GitHashAlgorithm, onto: GitOid, candidate: GitOid) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let checksum = match format {
        GitHashAlgorithm::Sha1 => fgit_crypto::sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => fgit_crypto::sha256_digest(&pack).to_vec(),
    };
    pack.extend(checksum);
    let mut bundle = format!("# v3 git bundle\n@object-format={}\n-{onto} onto\n{candidate} refs/heads/topic\n\n", format.as_str()).into_bytes();
    bundle.extend(pack);
    bundle
}

#[test]
fn reviewed_series_publishes_atomically_and_recovers_after_reopen_without_serving_or_quota() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let before = snapshot(&node);
        let (candidate, bundle) = prepared(&node, &f, false);
        let result = committed(apply(&node, &f, candidate, &bundle, b"native-rebase"));
        let after = snapshot(&node);
        assert_eq!(after.snapshot().refs[&topic_ref()], candidate);
        assert_eq!(after.snapshot().refs[&main_ref()], f.target);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_eq!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_eq!(apply(&node, &f, candidate, &bundle, b"native-rebase").unwrap(), result);
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.push_quota.limit.max_events = 0;
        assert_eq!(apply(&reopened, &f, candidate, &bundle, b"native-rebase").unwrap(), result);
        // A historical terminal retry succeeds, while a new request cannot
        // use that path to bypass a stopped cell or exhausted intake quota.
        assert!(apply(&reopened, &f, candidate, &bundle, b"new-attempt").is_err());
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn zero_commit_rebase_uses_the_source_lease_and_preserves_the_workspace_contract() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let before = snapshot(&node);
        let (candidate, bundle) = prepared(&node, &f, true);
        assert_eq!(candidate, f.target);
        let request = node.request_context();
        assert!(node.runtime().block_on(node.apply_workspace_bundle_durable_in(
            &request, principal(), b"not-a-workspace", &topic_ref(), f.source, candidate, &bundle,
        )).is_err());
        assert_eq!(snapshot(&node).basis(), before.basis());
        let result = committed(apply(&node, &f, candidate, &bundle, b"empty-rebase"));
        assert_eq!(snapshot(&node).snapshot().refs[&topic_ref()], f.target);
        assert_eq!(apply(&node, &f, candidate, &bundle, b"empty-rebase").unwrap(), result);
        node.shutdown().unwrap();
    }
}

#[test]
fn changed_source_has_one_recoverable_refusal_and_cannot_overwrite_the_branch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let (candidate, bundle) = prepared(&node, &f, false);
        let command = fgit_authority::RefCommand { name: topic_ref(),
            expected_old: fgit_authority::ExpectedOld::Exactly(f.source),
            proposed_new: fgit_authority::ProposedNew::Update(f.picked), force: false };
        let session = crate::LoopbackReceiveSession::authenticated(principal(),
            fgit_authority::IdempotencyKey::new(b"move-source".to_vec()).unwrap());
        node.runtime().block_on(node.admit_branch_updates_durable_in(&node.request_context(),
            &session, &[command], Default::default())).unwrap();
        let before = snapshot(&node);
        assert_eq!(before.snapshot().refs[&topic_ref()], f.picked);
        let refused = apply(&node, &f, candidate, &bundle, b"stale-rebase").unwrap();
        assert!(matches!(refused.commands[0].terminal.outcome,
            DecisionOutcome::Refused { code: fgit_types::RefusalCode::ExpectedOldRefMismatch, .. }));
        assert_eq!(snapshot(&node).snapshot().refs, before.snapshot().refs);
        let terminal_head = snapshot(&node).basis().id();
        assert_eq!(apply(&node, &f, candidate, &bundle, b"stale-rebase").unwrap(), refused);
        assert_eq!(snapshot(&node).basis().id(), terminal_head);
        node.shutdown().unwrap();
    }
}

#[test]
fn corrupt_mismatched_non_linear_and_cancelled_artifacts_never_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let before = snapshot(&node);
        let (candidate, bundle) = prepared(&node, &f, false);
        let mut corrupt = bundle.clone(); *corrupt.last_mut().unwrap() ^= 1;
        assert!(apply(&node, &f, candidate, &corrupt, b"corrupt").is_err());
        assert!(apply(&node, &f, f.source, &bundle, b"wrong-candidate").is_err());
        let wrong_onto = String::from_utf8_lossy(&bundle[..bundle.len()-bundle_pack(&bundle).len()])
            .replace(&format!("-{} ", f.target), &format!("-{} ", f.base)).into_bytes();
        let wrong_onto = [wrong_onto, bundle_pack(&bundle).to_vec()].concat();
        assert!(apply(&node, &f, candidate, &wrong_onto, b"wrong-onto").is_err());
        let unrelated = empty_pack_bundle(format, f.target, f.source);
        assert!(apply(&node, &f, f.source, &unrelated, b"unrelated").is_err());
        let request = node.request_context(); request.authority().cancel();
        assert!(node.runtime().block_on(node.apply_rebase_bundle_durable_in(&request,
            principal(), b"cancel", &topic_ref(), f.source, f.target, candidate, &bundle)).is_err());
        assert_eq!(snapshot(&node).basis(), before.basis());
        // Refusal twins use the same real artifact and node as the permitted case.
        committed(apply(&node, &f, candidate, &bundle, b"permitted"));
        let committed_head = snapshot(&node).basis().id();
        let empty = empty_pack_bundle(format, f.target, f.target);
        assert!(apply(&node, &f, f.target, &empty, b"permitted").is_err());
        assert_eq!(snapshot(&node).basis().id(), committed_head);
        node.shutdown().unwrap();
    }
}
