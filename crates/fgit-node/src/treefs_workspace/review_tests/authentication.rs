//! Committed review provenance is read back through the original authority
//! decision, including actual HTTP ingress and recovery after restart.

#[path = "../../../tests/review_merge_http/support.rs"]
mod http;

use super::*;
use crate::{AuthenticatedReceiveSession, GitDaemonServerLimits};
use fgit_admission::evidence::{PolicyDecisionRecord, PrincipalSnapshotRecord};
use fgit_authority::key_recovery::RequestRecovery;
use std::net::TcpListener;
use std::time::Duration;

fn authenticated_session(
    reviewer: u8,
    key: &str,
    authentication: AdmissionAuthentication,
) -> LoopbackReceiveSession {
    LoopbackReceiveSession::Authenticated(
        AuthenticatedReceiveSession::new(
            actor(reviewer),
            IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
        )
        .with_authentication(authentication),
    )
}

fn authenticated_vote(
    node: &OneNode,
    reviewer: u8,
    key: &str,
    authentication: AdmissionAuthentication,
    command: &CandidateReviewCommand,
    bundle: Option<&[u8]>,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    node.runtime()
        .block_on(node.admit_candidate_review_durable_in(
            &node.request_context(),
            &authenticated_session(reviewer, key, authentication),
            command,
            bundle,
            AdmissionLimits::default(),
        ))
}

fn retained(
    node: &OneNode,
    reviewer: u8,
    key: &str,
    authentication: AdmissionAuthentication,
) -> ((TxId, TerminalOutcome), PrincipalSnapshotRecord) {
    // Recovery uses an operator session deliberately: present authentication
    // cannot replace the credential fact recorded by the original decision.
    let session = session(reviewer, key);
    let request = node.request_context();
    let report = node
        .runtime()
        .block_on(node.recover_transaction_in(&request, &session))
        .unwrap();
    let RequestRecovery::Recovered(recovered) = &report else {
        panic!("the review has a retained sealed request");
    };
    let terminal = report.terminal().unwrap();
    let principal = node
        .runtime()
        .block_on(node.recover_transaction_principal_in(&request, &session, &report))
        .unwrap()
        .unwrap();
    assert!(matches!(
        principal,
        PrincipalSnapshotRecord::Authenticated(_)
    ));
    assert_eq!(principal.principal_id(), actor(reviewer));
    assert_eq!(principal.authentication(), Some(authentication));

    if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) {
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&request))
            .unwrap();
        let records: Vec<_> = history
            .iter()
            .flat_map(|batch| &batch.batch.committed_rcrs)
            .filter(|record| record.tx_id == recovered.tx_id())
            .collect();
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert_eq!(record.principal_snapshot_id, principal.id().unwrap());
        let policy = node
            .runtime()
            .block_on(crate::read_policy_decision_in(
                &node.authority,
                request.authority(),
                node.repository_id,
                record.policy_decision_root,
                &|| false,
            ))
            .unwrap();
        // A review has no ref effect. Retaining authentication must not invent
        // a ref-policy evaluation or alter the original metadata request.
        assert!(matches!(policy, PolicyDecisionRecord::Legacy(_)));
    }
    ((recovered.tx_id(), terminal), principal)
}

#[test]
fn committed_review_methods_and_terminal_retries_retain_their_original_evidence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch, format);
        let before = snapshot(&f.node);
        let mut originals = Vec::new();
        for (reviewer, method, key) in [
            (
                3,
                AdmissionAuthentication::OperatorAssertion,
                "operator-review",
            ),
            (4, AdmissionAuthentication::HttpToken, "token-review"),
            (5, AdmissionAuthentication::SshDeployKey, "ssh-review"),
        ] {
            let accepted = committed(
                &authenticated_vote(&f.node, reviewer, key, method, &f.command, Some(&f.bundle))
                    .unwrap(),
            );
            let (recovered, principal) = retained(&f.node, reviewer, key, method);
            assert_eq!(recovered, accepted);
            let original_head = snapshot(&f.node).basis().clone();
            // Transport provenance is a decision receipt, not transaction
            // identity. The same key recovers without inspecting a bundle.
            assert_eq!(
                authenticated_vote(
                    &f.node,
                    reviewer,
                    key,
                    AdmissionAuthentication::HttpToken,
                    &f.command,
                    None,
                )
                .unwrap(),
                accepted
            );
            assert_eq!(snapshot(&f.node).basis(), &original_head);
            let mut different = f.command.clone();
            different.review.reason.push_str(" changed request");
            assert!(authenticated_vote(&f.node, reviewer, key, method, &different, None).is_err());
            assert_eq!(snapshot(&f.node).basis(), &original_head);
            originals.push((
                reviewer,
                key,
                method,
                f.command.clone(),
                accepted,
                principal,
            ));
        }

        for (reviewer, method, key, decision) in [
            (
                3,
                AdmissionAuthentication::SshDeployKey,
                "withdraw-review",
                ReviewDecision::Withdraw,
            ),
            (
                4,
                AdmissionAuthentication::OperatorAssertion,
                "change-review",
                ReviewDecision::RequestChanges,
            ),
        ] {
            let mut command = f.command.clone();
            command.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
            command.review.decision = decision;
            command.review.reason = "The exact candidate needs revision".into();
            let bundle = (decision != ReviewDecision::Withdraw).then_some(f.bundle.as_slice());
            let accepted = committed(
                &authenticated_vote(&f.node, reviewer, key, method, &command, bundle).unwrap(),
            );
            let (recovered, principal) = retained(&f.node, reviewer, key, method);
            assert_eq!(recovered, accepted);
            originals.push((reviewer, key, method, command, accepted, principal));
        }

        // A stale attempt has the same honest receipt as a successful one.
        let mut stale = f.command.clone();
        stale.review.subject.policy_epoch = stale.review.subject.policy_epoch.next().unwrap();
        let refused = authenticated_vote(
            &f.node,
            6,
            "stale-review",
            AdmissionAuthentication::HttpToken,
            &stale,
            Some(&f.bundle),
        )
        .unwrap();
        assert!(matches!(
            refused.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        let (recovered, principal) = retained(
            &f.node,
            6,
            "stale-review",
            AdmissionAuthentication::HttpToken,
        );
        assert_eq!(recovered, refused);
        originals.push((
            6,
            "stale-review",
            AdmissionAuthentication::HttpToken,
            stale,
            refused,
            principal,
        ));
        let after = snapshot(&f.node);
        code_unchanged(&before, &after);
        assert!(f.node.read_git_object(f.command.candidate.commit).is_err());
        f.node.shutdown().unwrap();

        // Terminal recovery works before re-entering mutation-ready service
        // and does not reinterpret historical approvals after a withdrawal.
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        for (reviewer, key, method, command, terminal, principal) in originals {
            assert_eq!(
                authenticated_vote(
                    &reopened,
                    reviewer,
                    key,
                    AdmissionAuthentication::SshDeployKey,
                    &command,
                    None
                )
                .unwrap(),
                terminal
            );
            assert_eq!(
                retained(&reopened, reviewer, key, method),
                (terminal, principal)
            );
        }
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

fn http_vote(
    node: &OneNode,
    credentials: &Path,
    action: &str,
    token: char,
    key: &str,
    form: &str,
    bundle: Option<&[u8]>,
) -> http::Reply {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = http::Endpoint {
        address: listener.local_addr().unwrap(),
        route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap(),
    };
    std::thread::scope(|scope| {
        let client =
            scope.spawn(move || http::send(&endpoint, action, token, key, form, bundle, false));
        let served = node
            .serve_repository_http_with_pull_requests_bounded(
                &listener,
                GitDaemonServerLimits::try_new(1, 1).unwrap(),
                credentials,
                false,
                false,
                true,
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(served.accepted_sessions(), 1);
        client.join().unwrap()
    })
}

#[test]
fn actual_http_review_decisions_retain_token_authentication_after_rotation_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch, format);
        let credentials = scratch.0.join("credentials");
        let header = http::header(&f.node);
        let scopes = "outcomes-read,reviews-read,reviews-write";
        http::replace(
            &credentials,
            &(header.clone() + &http::row('b', actor(3), scopes)),
        );
        let candidate = http::Candidate {
            data: f.data.clone(),
            binding: f.command.candidate,
            epoch: f.command.review.subject.policy_epoch,
            bundle: f.bundle.clone(),
        };
        let mut originals = Vec::new();
        for (version, action, key) in [
            (0, "reviews/approve", "http-approve"),
            (1, "reviews/request-changes", "http-request-changes"),
            (2, "reviews/withdraw", "http-withdraw"),
        ] {
            let form = http::review_form(&candidate, version);
            let bundle = (version != 2).then_some(f.bundle.as_slice());
            let reply = http_vote(&f.node, &credentials, action, 'b', key, &form, bundle);
            http::accepted(&reply);
            let original = retained(&f.node, 3, key, AdmissionAuthentication::HttpToken);
            assert!(
                reply
                    .body
                    .contains(&format!("\"tx_id\":\"{}\"", original.0.0))
            );
            originals.push((key, original));
        }
        let form = http::review_form(&candidate, 0);
        http::replace(&credentials, &(header + &http::row('c', actor(3), scopes)));
        let revoked = http_vote(
            &f.node,
            &credentials,
            "reviews/approve",
            'b',
            "http-approve",
            &form,
            None,
        );
        http::status(&revoked, 401);
        let retry = http_vote(
            &f.node,
            &credentials,
            "reviews/approve",
            'c',
            "http-approve",
            &form,
            None,
        );
        http::accepted(&retry);
        assert_eq!(
            retained(
                &f.node,
                3,
                "http-approve",
                AdmissionAuthentication::HttpToken
            ),
            originals[0].1
        );
        let after = snapshot(&f.node).basis().clone();
        f.node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        for (key, original) in originals {
            assert_eq!(
                retained(&reopened, 3, key, AdmissionAuthentication::HttpToken),
                original
            );
        }
        let mut original_command = f.command.clone();
        original_command.review.reason = "Reviewed exact candidate".into();
        assert_eq!(
            vote(&reopened, &original_command, None, 3, "http-approve").unwrap(),
            retained(
                &reopened,
                3,
                "http-approve",
                AdmissionAuthentication::HttpToken
            )
            .0
        );
        assert_eq!(snapshot(&reopened).basis(), &after);
        reopened.shutdown().unwrap();
    }
}
