#![forbid(unsafe_code)]
//! Public proof serving over native metadata decisions and retained checkpoints.

use fgit_authority::{AuthenticatedHead, IdempotencyKey, TerminalOutcome};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant, SOURCE_READ, SponsorKind,
    agent_credential_id,
};
use fgit_node::{
    ClosureSelectionSource, LoopbackReceiveSession, NodeConfig, OneNode, ServedVerifiedRead,
    VerifiedReadQuery, VerifiedReadServingRefusal,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, ReadLabel, RepositoryId,
    RootLayoutVersion, TenantId, TxId,
};
use fgit_verified_read::{
    PinnedAuthorityHead, ReadResponse, UnprovenReadAnswer, VerifiedMembership, VerifiedReadAnswer,
    VerifiedReadCapability, verify_envelope,
};
use fgit_wire::visibility::RefVisibility;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const OWNER: PrincipalId = PrincipalId::from_bytes([0x91; 16]);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(std::env::temp_dir().join(format!(
            "fg-verified-outcome-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.clone(),
            TenantId::from_bytes([0x92; 16]),
            RepositoryId::from_bytes([0x93; 16]),
        )
        .with_object_format(format)
        .with_root_layout(RootLayoutVersion::RefStateMerkleV1)
        .with_worker_threads(2)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn selected(node: &OneNode) -> AuthenticatedHead {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
}

fn command(node: &OneNode, tag: char) -> AgentCredentialCommand {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    AgentCredentialCommand {
        id: agent_credential_id(format!("fgagent_{}", tag.to_string().repeat(64)).as_bytes())
            .unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::Issue(AgentCredentialGrant {
            agent: PrincipalId::from_bytes([0x94; 16]),
            sponsor: OWNER,
            sponsor_kind: SponsorKind::Human,
            tenant: node.tenant_id(),
            repository: node.repository_id(),
            incarnation: node.repository_incarnation_id(),
            issued_at: now - 1,
            expires_at: now + 3_600,
            operations: SOURCE_READ,
        }),
    }
}

fn apply(node: &OneNode, retry: &str, command: &AgentCredentialCommand) -> (TxId, TerminalOutcome) {
    let request = node.request_context();
    let session = LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(retry.as_bytes().to_vec()).unwrap(),
    );
    node.runtime()
        .block_on(node.admit_agent_credential_durable_in(
            &request,
            &session,
            command,
            Default::default(),
        ))
        .unwrap()
}

fn checkpoint(node: &OneNode, expected_decisions: usize) -> AuthenticatedHead {
    let receipt = node
        .runtime()
        .block_on(node.checkpoint_outcomes_in(&node.request_context(), Default::default()))
        .unwrap();
    assert!(receipt.published);
    assert_eq!(receipt.decisions, expected_decisions);
    assert_eq!(
        receipt.backup_profile,
        fgit_chronicle::BackupProfile::DecisionHistoryWithAdmissionClosureV1.as_str()
    );
    selected(node)
}

fn assert_proof(
    served: &ServedVerifiedRead,
    pinned: &AuthenticatedHead,
    expected: (TxId, TerminalOutcome),
) {
    let body = pinned.body().unwrap();
    assert_eq!(served.authority_head(), &body);
    let ReadResponse::Verified(envelope) = served.response() else {
        panic!("an explicitly requested outcome proof must carry its envelope")
    };
    assert_eq!(
        verify_envelope(&PinnedAuthorityHead::new(body), envelope).unwrap(),
        VerifiedMembership::Outcome
    );
    assert!(matches!(
        envelope.answer(),
        VerifiedReadAnswer::OutcomeMembership { tx_id, outcome, .. }
            if *tx_id == expected.0 && **outcome == expected.1
    ));
}

#[test]
fn native_outcome_proofs_cover_retained_refusals_tail_and_exact_snapshot_after_cold_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let first_command = command(&node, 'a');
        let first = apply(&node, "proof-first-issue", &first_command);
        assert!(matches!(first.1.outcome, DecisionOutcome::Committed { .. }));
        let refused = apply(&node, "proof-conflicting-issue", &first_command);
        assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { .. }));
        let prefix = checkpoint(&node, 2);

        let AgentCredentialAction::Issue(grant) = first_command.action else {
            panic!("the fixture issues a credential")
        };
        let revoke = AgentCredentialCommand {
            id: first_command.id,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(grant),
        };
        let tail = apply(&node, "proof-revoke-after-checkpoint", &revoke);
        assert!(matches!(tail.1.outcome, DecisionOutcome::Committed { .. }));
        checkpoint(&node, 3);
        let newest = apply(&node, "proof-new-credential-tail", &command(&node, 'b'));
        assert!(matches!(
            newest.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let final_head = selected(&node);
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
        node.bring_into_service(final_head.receipt().generation())
            .unwrap();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert!(matches!(
            materialized.selected_closure().source(),
            ClosureSelectionSource::CapsuleCheckpoint { .. }
        ));
        assert_eq!(materialized.authenticated().receipt(), final_head.receipt());
        for expected in [first, refused, tail, newest] {
            let served = node
                .runtime()
                .block_on(node.serve_current_verified_read_in(
                    &node.request_context(),
                    &RefVisibility::new(),
                    ReadLabel::current(),
                    VerifiedReadCapability::EnvelopeV1,
                    VerifiedReadQuery::Outcome(expected.0),
                ))
                .unwrap();
            assert_proof(&served, &final_head, expected);
        }
        for expected in [first, refused] {
            let served = node
                .runtime()
                .block_on(node.serve_snapshot_verified_read_in(
                    &node.request_context(),
                    prefix.receipt(),
                    &RefVisibility::new(),
                    ReadLabel::snapshot(),
                    VerifiedReadCapability::EnvelopeV1,
                    VerifiedReadQuery::Outcome(expected.0),
                ))
                .unwrap();
            assert_proof(&served, &prefix, expected);
        }
        let future_at_prefix = node
            .runtime()
            .block_on(node.serve_snapshot_verified_read_in(
                &node.request_context(),
                prefix.receipt(),
                &RefVisibility::new(),
                ReadLabel::snapshot(),
                VerifiedReadCapability::EnvelopeV1,
                VerifiedReadQuery::Outcome(tail.0),
            ));
        assert!(matches!(
            future_at_prefix,
            Err(VerifiedReadServingRefusal::OutcomeProofUnavailable)
        ));
        let unproven = node
            .runtime()
            .block_on(node.serve_snapshot_verified_read_in(
                &node.request_context(),
                prefix.receipt(),
                &RefVisibility::new(),
                ReadLabel::snapshot(),
                VerifiedReadCapability::Unproven,
                VerifiedReadQuery::Outcome(tail.0),
            ))
            .unwrap();
        assert_eq!(unproven.authority_head(), &prefix.body().unwrap());
        assert!(matches!(
            unproven.response(),
            ReadResponse::Unproven(answer)
                if matches!(answer.as_ref(), UnprovenReadAnswer::Outcome { tx_id, outcome: None } if *tx_id == tail.0)
        ));

        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(
            node.runtime()
                .block_on(node.serve_snapshot_verified_read_in(
                    &cancelled,
                    prefix.receipt(),
                    &RefVisibility::new(),
                    ReadLabel::snapshot(),
                    VerifiedReadCapability::EnvelopeV1,
                    VerifiedReadQuery::Outcome(first.0),
                ))
                .is_err()
        );
        assert_eq!(selected(&node), final_head, "reads never move authority");
        node.shutdown().unwrap();
    }
}
