//! Real embedded authority, canonical grants, request runs and metadata writes.
//! No alternate credential store, projection, or authority implementation.
use super::*;
use crate::{AuthenticatedReceiveSession, NodeConfig};
use fgit_admission::evidence::PrincipalSnapshotRecord;
use fgit_authority::key_recovery::RequestRecovery;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::protection::{ProtectionCommand, ReviewProtection};
use fgit_forge::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_identity::agent::{
    AgentCredentialAction, AgentCredentialGrant, ISSUES_READ, ISSUES_WRITE, OUTCOMES_READ,
    PULLS_WRITE, SOURCE_CANDIDATES, SOURCE_HISTORY_READ, SOURCE_READ, SponsorKind,
    agent_credential_id,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId,
    RepositoryIncarnationId, TenantId,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "../tests/authority_read_fault.rs"]
mod read_fault;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-sponsored-credentials-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xa2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
    fn node(&self, format: GitHashAlgorithm) -> OneNode {
        let (mut node, _) = OneNode::init(self.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        node
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn actor(value: u8) -> PrincipalId {
    PrincipalId::from_bytes([value; 16])
}
fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value.as_bytes().to_vec()).unwrap()
}
fn operator(actor: PrincipalId, retry: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor, key(retry))
}
fn bearer(value: char) -> String {
    format!("fgagent_{}", value.to_string().repeat(64))
}
fn grant(node: &OneNode) -> AgentCredentialGrant {
    let now = epoch_seconds().unwrap();
    AgentCredentialGrant {
        agent: actor(2),
        sponsor: actor(1),
        sponsor_kind: SponsorKind::Human,
        tenant: node.tenant_id,
        repository: node.repository_id,
        incarnation: node.repository_incarnation_id,
        issued_at: now - 1,
        expires_at: now + 3600,
        operations: ISSUES_READ | ISSUES_WRITE | OUTCOMES_READ,
    }
}
fn issue_command(token: &str, grant: AgentCredentialGrant) -> AgentCredentialCommand {
    AgentCredentialCommand {
        id: agent_credential_id(token.as_bytes()).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::Issue(grant),
    }
}
fn credential(
    node: &OneNode,
    command: &AgentCredentialCommand,
    who: PrincipalId,
    retry: &str,
) -> (TxId, TerminalOutcome) {
    node.runtime()
        .block_on(node.admit_agent_credential_durable_in(
            &node.request_context(),
            &operator(who, retry),
            command,
            Default::default(),
        ))
        .unwrap()
}
fn committed(value: (TxId, TerminalOutcome)) -> (TxId, TerminalOutcome) {
    assert!(
        matches!(value.1.outcome, DecisionOutcome::Committed { .. }),
        "{value:?}"
    );
    value
}
fn denied(value: &(TxId, TerminalOutcome), expected: RefusalCode) {
    assert!(
        matches!(value.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "{value:?}"
    );
}
fn authentication(node: &OneNode, token: &str, retry: &str, operation: u16) -> AgentRequest {
    node.runtime()
        .block_on(node.authenticate_agent_request_in(
            &node.request_context(),
            token.as_bytes(),
            &key(retry),
            operation,
            sha256_digest(retry.as_bytes()),
            4096,
            8192,
        ))
        .unwrap()
}
fn session(witness: AgentAuthentication, retry: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::Authenticated(
        AuthenticatedReceiveSession::new(witness.agent(), key(retry))
            .with_authentication(AdmissionAuthentication::AgentCredential(witness)),
    )
}
fn issue(number: u64) -> IssueCommand {
    IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: format!("Sponsored issue {number}"),
            body: "Native bounded metadata request".into(),
            labels: Vec::new(),
        },
    }
}
fn publish(
    node: &OneNode,
    run: &AgentRequest,
    retry: &str,
    command: &IssueCommand,
) -> (TxId, TerminalOutcome) {
    node.runtime()
        .block_on(node.admit_issue_durable_in(
            &node.request_context(),
            &run.session(key(retry)),
            command,
            Default::default(),
        ))
        .unwrap()
}
fn provenance(node: &OneNode, who: PrincipalId, retry: &str) -> PrincipalSnapshotRecord {
    let request = node.request_context();
    // Trusted recovery authenticates the original principal; it deliberately
    // does not re-authorize old writes with a replacement credential.
    let session = operator(who, retry);
    let recovery = node
        .runtime()
        .block_on(node.recover_transaction_in(&request, &session))
        .unwrap();
    assert!(matches!(recovery, RequestRecovery::Recovered(_)));
    node.runtime()
        .block_on(node.recover_transaction_principal_in(&request, &session, &recovery))
        .unwrap()
        .unwrap()
}
fn install_administrators(node: &OneNode) {
    let request = node.request_context();
    let current = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: current.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![actor(1), actor(3)],
            branches: Vec::new(),
            ref_policy: None,
        },
    };
    committed(
        node.runtime()
            .block_on(node.admit_review_protection_durable_in(
                &request,
                &operator(actor(1), "install-administrators"),
                &command,
                Default::default(),
            ))
            .unwrap(),
    );
}

#[test]
fn agent_materialization_preserves_interruption_availability_and_integrity() {
    use read_fault::{Fault, ReadFault};

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let token = bearer('a');
        committed(credential(
            &node,
            &issue_command(&token, grant(&node)),
            actor(1),
            "materialization-fault-twin",
        ));
        let live = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&live))
            .unwrap();
        let key = crate::admission_immutable_key(
            crate::ADMISSION_REF_STATE_KEY_PREFIX,
            node.repository_id,
            selected.basis().body().ref_root,
        )
        .unwrap();
        for (fault, expected) in [
            (Fault::Cancel, RefusalCode::CancellationInProgress),
            (Fault::Deadline, RefusalCode::CancellationInProgress),
            (Fault::Capacity, RefusalCode::ResourceBudgetExceeded),
            (
                Fault::Unavailable,
                RefusalCode::DurabilityProfileUnavailable,
            ),
            (Fault::NoResponse, RefusalCode::ExternalEffectIndeterminate),
            (Fault::Absent, RefusalCode::EvidenceMissing),
            (Fault::Corrupt, RefusalCode::CanonicalFramingInvalid),
        ] {
            let store = ReadFault::new(&node, key.clone(), fault);
            let request = node.request_context();
            let error = node
                .runtime()
                .block_on(node.admission_materializer.materialize_exact_in(
                    &store,
                    request.authority(),
                    node.repository_id,
                    selected.basis(),
                    selected.authenticated(),
                    &|| false,
                ))
                .unwrap_err();
            assert!(
                store.fired(),
                "the selected canonical read was reached: {fault:?}"
            );
            let surfaced = materialization_refused(error);
            assert!(
                matches!(
                    &surfaced,
                    NodeReceiveTransportRefusal::Admission(error)
                        if matches!(error.as_ref(), AdmissionError::AsyncProjectionUnavailable(code) if *code == expected)
                ),
                "x2mv.4.51: {fault:?} must retain {expected:?}, got {surfaced:?}"
            );

            // The read fault cannot revoke a credential or alter canonical
            // authority. Both public callers succeed with a fresh live request.
            let listed = node
                .runtime()
                .block_on(node.read_agent_credentials_in(&node.request_context()))
                .unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].id, agent_credential_id(token.as_bytes()).unwrap());
            let run = authentication(&node, &token, "after-materialization-fault", ISSUES_READ);
            assert_eq!(run.authentication.agent(), actor(2));
            let retry = node
                .runtime()
                .block_on(node.materialize_admission_in(&node.request_context()))
                .unwrap();
            assert_eq!(retry.basis(), selected.basis());
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_issue_rotation_revocation_and_restart_keep_original_canonical_provenance() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let original_token = bearer('a');
        let original_grant = grant(&node);
        let original_command = issue_command(&original_token, original_grant);
        // Bootstrap is a trusted-local operator action before a policy exists.
        let issuance = committed(credential(
            &node,
            &original_command,
            actor(1),
            "issue-original",
        ));
        let run = authentication(&node, &original_token, "agent-opens-issue", ISSUES_WRITE);
        run.check(4096, 8192).unwrap();
        let witness = run.authentication;
        assert_eq!(witness.agent(), actor(2));
        assert_eq!(witness.sponsor(), actor(1));
        assert_eq!(witness.credential_id(), original_command.id);
        assert_ne!(*witness.run_commitment(), [0; 32]);
        let command = issue(1);
        let published = committed(publish(&node, &run, "agent-opens-issue", &command));
        let recorded = provenance(&node, actor(2), "agent-opens-issue");
        assert!(matches!(recorded, PrincipalSnapshotRecord::Agent(_)));
        assert_eq!(recorded.agent_provenance(), Some(&witness));
        let page = node
            .runtime()
            .block_on(node.read_issue_history_in(
                &node.request_context(),
                IssueNumber::FIRST,
                0,
                10,
                None,
            ))
            .unwrap();
        assert_eq!(page.issue.unwrap().opened_by, actor(2));

        // Authenticate a second request before revocation, then complete it
        // against the newer canonical basis. It must reach one stable refusal.
        let inflight = authentication(
            &node,
            &original_token,
            "pending-at-revocation",
            ISSUES_WRITE,
        );
        install_administrators(&node);
        let revocation = AgentCredentialCommand {
            id: original_command.id,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(original_grant),
        };
        let revoked = committed(credential(&node, &revocation, actor(3), "revoke-original"));
        let refused = publish(&node, &inflight, "pending-at-revocation", &issue(2));
        denied(&refused, RefusalCode::CapabilityScopeViolation);
        assert_eq!(
            publish(&node, &inflight, "pending-at-revocation", &issue(2)),
            refused
        );
        assert!(
            node.runtime()
                .block_on(node.authenticate_agent_request_in(
                    &node.request_context(),
                    original_token.as_bytes(),
                    &key("next-request"),
                    ISSUES_WRITE,
                    [1; 32],
                    4096,
                    8192
                ))
                .is_err()
        );
        assert_eq!(provenance(&node, actor(2), "agent-opens-issue"), recorded);
        assert_eq!(
            provenance(&node, actor(2), "pending-at-revocation").agent_provenance(),
            Some(&inflight.authentication)
        );

        let replacement_token = bearer('b');
        let replacement = issue_command(&replacement_token, original_grant);
        committed(credential(
            &node,
            &replacement,
            actor(1),
            "issue-replacement",
        ));
        let replacement_run =
            authentication(&node, &replacement_token, "agent-opens-issue", ISSUES_WRITE);
        assert_ne!(
            replacement_run.authentication.credential_id(),
            witness.credential_id()
        );
        assert_eq!(
            publish(&node, &replacement_run, "agent-opens-issue", &command),
            published
        );
        assert_eq!(provenance(&node, actor(2), "agent-opens-issue"), recorded);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // Original terminal outcomes survive restart and closed intake.
        assert_eq!(
            credential(&reopened, &original_command, actor(1), "issue-original"),
            issuance
        );
        assert_eq!(
            credential(&reopened, &revocation, actor(3), "revoke-original"),
            revoked
        );
        assert_eq!(
            provenance(&reopened, actor(2), "agent-opens-issue"),
            recorded
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let replacement_run = authentication(
            &reopened,
            &replacement_token,
            "agent-opens-issue",
            ISSUES_WRITE,
        );
        assert_eq!(
            publish(&reopened, &replacement_run, "agent-opens-issue", &command),
            published
        );
        let retained = reopened
            .runtime()
            .block_on(
                reopened.read_agent_credential_in(&reopened.request_context(), original_command.id),
            )
            .unwrap()
            .unwrap();
        assert!(retained.revoked);
        assert_eq!(retained.grant, original_grant);
        assert_eq!(retained.version.get(), 2);
        assert_eq!(
            provenance(&reopened, actor(2), "agent-opens-issue"),
            recorded
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn canonical_binding_current_administrators_and_identity_roles_refuse_forbidden_twins() {
    let scratch = Scratch::new();
    let node = scratch.node(GitHashAlgorithm::Sha256);
    let valid_grant = grant(&node);
    let command = issue_command(&bearer('a'), valid_grant);
    committed(credential(&node, &command, actor(1), "bootstrap"));
    for (index, changed) in [
        AgentCredentialGrant {
            tenant: TenantId::from_bytes([0xee; 16]),
            ..valid_grant
        },
        AgentCredentialGrant {
            repository: RepositoryId::from_bytes([0xee; 16]),
            ..valid_grant
        },
        AgentCredentialGrant {
            incarnation: RepositoryIncarnationId::from_bytes([0xee; 16]),
            ..valid_grant
        },
        AgentCredentialGrant {
            sponsor: actor(2),
            agent: actor(4),
            ..valid_grant
        },
        AgentCredentialGrant {
            sponsor_kind: SponsorKind::Service,
            ..valid_grant
        },
    ]
    .into_iter()
    .enumerate()
    {
        let proposal = issue_command(&bearer('b'), changed);
        denied(
            &credential(
                &node,
                &proposal,
                changed.sponsor,
                &format!("bad-binding-{index}"),
            ),
            RefusalCode::ProtectedRefTransitionDenied,
        );
    }
    install_administrators(&node);
    let untrusted_sponsor = AgentCredentialGrant {
        sponsor: actor(9),
        agent: actor(8),
        ..valid_grant
    };
    denied(
        &credential(
            &node,
            &issue_command(&bearer('c'), untrusted_sponsor),
            actor(9),
            "not-administrator",
        ),
        RefusalCode::ProtectedRefTransitionDenied,
    );
    let run = authentication(&node, &bearer('a'), "cannot-administer", ISSUES_WRITE);
    let revoke = AgentCredentialCommand {
        id: command.id,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: AgentCredentialAction::Revoke(valid_grant),
    };
    assert!(
        node.runtime()
            .block_on(node.admit_agent_credential_durable_in(
                &node.request_context(),
                &session(run.authentication, "cannot-administer"),
                &revoke,
                Default::default()
            ))
            .is_err()
    );
    let http = LoopbackReceiveSession::Authenticated(
        AuthenticatedReceiveSession::new(actor(1), key("http-cannot-administer"))
            .with_authentication(AdmissionAuthentication::HttpToken),
    );
    assert!(
        node.runtime()
            .block_on(node.admit_agent_credential_durable_in(
                &node.request_context(),
                &http,
                &revoke,
                Default::default()
            ))
            .is_err()
    );
    // Another current administrator may revoke, retaining the original sponsor.
    committed(credential(
        &node,
        &revoke,
        actor(3),
        "administrator-revokes",
    ));
    let state = node
        .runtime()
        .block_on(node.read_agent_credential_in(&node.request_context(), command.id))
        .unwrap()
        .unwrap();
    assert_eq!(state.grant.sponsor, actor(1));
    assert!(state.revoked);
    node.shutdown().unwrap();
}

#[test]
fn authentication_enforces_scope_expiry_binding_request_budgets_and_cancellation() {
    let scratch = Scratch::new();
    let node = scratch.node(GitHashAlgorithm::Sha1);
    let token = bearer('d');
    let live_grant = grant(&node);
    committed(credential(
        &node,
        &issue_command(&token, live_grant),
        actor(1),
        "live",
    ));
    let run = authentication(&node, &token, "permitted", ISSUES_WRITE);
    run.check(4096, 8192).unwrap();
    assert!(run.check(4097, 8192).is_err());
    assert!(run.check(4096, 8193).is_err());
    let transport_deadline = crate::GitDaemonSessionDeadline::new(
        crate::GitDaemonSessionTimeout::try_new(std::time::Duration::from_secs(60)).unwrap(),
        crate::GitDaemonSessionWorkScaling::FLAT,
    );
    assert!(
        node.authenticated_session_request_context(
            &transport_deadline,
            &operator(actor(1), "operator-context"),
        )
        .is_live()
    );
    assert!(
        node.authenticated_session_request_context(
            &transport_deadline,
            &run.session(key("live-agent-context")),
        )
        .is_live()
    );
    for (retry, deadline) in [
        ("missing-run-deadline", None),
        (
            "expired-run-deadline",
            Some(Instant::now() - std::time::Duration::from_secs(1)),
        ),
    ] {
        let unsupported = LoopbackReceiveSession::Authenticated(
            AuthenticatedReceiveSession::new(run.authentication.agent(), key(retry))
                .with_authentication(AdmissionAuthentication::AgentCredential(run.authentication))
                .with_agent_deadline(deadline),
        );
        assert!(
            !node
                .authenticated_session_request_context(&transport_deadline, &unsupported)
                .is_live(),
            "{retry} must cancel awaited authority work immediately"
        );
        let result = node.runtime().block_on(node.admit_issue_durable_in(
            &node.request_context(),
            &unsupported,
            &issue(90),
            Default::default(),
        ));
        assert!(
            matches!(
                result,
                Err(NodeReceiveTransportRefusal::Admission(ref cause))
                    if matches!(cause.as_ref(), AdmissionError::AsyncProjectionUnavailable(RefusalCode::CapabilityExpired))
            ),
            "{result:?}"
        );
    }
    let live_run = authentication(&node, &token, "live-run-deadline", ISSUES_WRITE);
    committed(publish(&node, &live_run, "live-run-deadline", &issue(90)));
    for (operation, input, output) in [
        (PULLS_WRITE, 4096, 8192),
        (0, 4096, 8192),
        (ISSUES_READ | ISSUES_WRITE, 4096, 8192),
        (ISSUES_WRITE, MAX_REQUEST_BYTES + 1, 8192),
        (ISSUES_WRITE, 4096, 0),
    ] {
        assert!(
            node.runtime()
                .block_on(node.authenticate_agent_request_in(
                    &node.request_context(),
                    token.as_bytes(),
                    &key("refused-profile"),
                    operation,
                    [1; 32],
                    input,
                    output
                ))
                .is_err()
        );
    }
    let cancelled = node.request_context();
    cancelled.cancel();
    assert!(
        node.runtime()
            .block_on(node.authenticate_agent_request_in(
                &cancelled,
                token.as_bytes(),
                &key("cancelled"),
                ISSUES_WRITE,
                [1; 32],
                4096,
                8192
            ))
            .is_err()
    );
    let now = epoch_seconds().unwrap();
    for (label, token, modified) in [
        (
            "expired",
            bearer('e'),
            AgentCredentialGrant {
                issued_at: now - 3,
                expires_at: now - 1,
                ..live_grant
            },
        ),
        (
            "future",
            bearer('f'),
            AgentCredentialGrant {
                issued_at: now + 3600,
                expires_at: now + 7200,
                ..live_grant
            },
        ),
    ] {
        committed(credential(
            &node,
            &issue_command(&token, modified),
            actor(1),
            label,
        ));
        assert!(
            node.runtime()
                .block_on(node.authenticate_agent_request_in(
                    &node.request_context(),
                    token.as_bytes(),
                    &key(label),
                    ISSUES_WRITE,
                    [1; 32],
                    4096,
                    8192
                ))
                .is_err()
        );
    }
    let other_root = Scratch::new();
    let other = other_root.node(GitHashAlgorithm::Sha1);
    assert_ne!(
        other.repository_incarnation_id,
        node.repository_incarnation_id
    );
    assert!(
        other
            .runtime()
            .block_on(other.authenticate_agent_request_in(
                &other.request_context(),
                token.as_bytes(),
                &key("other-incarnation"),
                ISSUES_WRITE,
                [1; 32],
                4096,
                8192
            ))
            .is_err()
    );
    other.shutdown().unwrap();
    node.shutdown().unwrap();
}

#[test]
fn adapter_api_keeps_the_original_key_and_only_shortens_request_authority() {
    let scratch = Scratch::new();
    let node = scratch.node(GitHashAlgorithm::Sha256);
    let token = bearer('c');
    committed(credential(
        &node,
        &issue_command(&token, grant(&node)),
        actor(1),
        "adapter-credential",
    ));
    let mut run = authentication(&node, &token, "original-adapter-key", ISSUES_WRITE);
    let session = run.authenticated_session();
    let authenticated = session.authenticated_session().unwrap();
    assert_eq!(
        authenticated.client_idempotency_key(),
        &key("original-adapter-key")
    );
    assert_eq!(authenticated.principal_id(), actor(2));
    assert_eq!(
        authenticated.authentication(),
        AdmissionAuthentication::AgentCredential(run.authentication)
    );
    assert!(run.context(&node).is_live());
    let original_deadline = run.deadline();
    run.constrain_deadline(original_deadline + std::time::Duration::from_secs(60));
    assert_eq!(run.deadline(), original_deadline);
    run.constrain_deadline(Instant::now() - std::time::Duration::from_secs(1));
    assert!(!run.context(&node).is_live());
    assert!(run.check(0, 0).is_err());
    node.shutdown().unwrap();
}

#[test]
fn history_requests_keep_independent_finite_authority_across_reopen_and_revocation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let token = bearer('e');
        let original = AgentCredentialGrant {
            operations: SOURCE_HISTORY_READ,
            ..grant(&node)
        };
        let command = issue_command(&token, original);
        committed(credential(&node, &command, actor(1), "issue-history"));
        let mut history = authentication(&node, &token, "read-history", SOURCE_HISTORY_READ);
        for class in OperationClass::ALL {
            assert_eq!(
                history.run.allowed_operation_classes().contains(class),
                class == OperationClass::ReadCanonicalObject,
                "history requests must not acquire {class:?}"
            );
        }
        assert!(history.mcp_source_read_context(&node).is_err());
        history.check(4096, 8192).unwrap();
        assert!(history.check(4097, 8192).is_err());
        assert!(history.check(4096, 8193).is_err());
        for operation in [SOURCE_READ, ISSUES_READ, ISSUES_WRITE, PULLS_WRITE] {
            let denied = node.runtime().block_on(node.authenticate_agent_request_in(
                &node.request_context(),
                token.as_bytes(),
                &key("wrong-history-operation"),
                operation,
                [1; 32],
                4096,
                8192,
            ));
            assert!(matches!(
                denied,
                Err(NodeReceiveTransportRefusal::Admission(error))
                    if matches!(*error, AdmissionError::AsyncProjectionUnavailable(RefusalCode::CapabilityScopeViolation))
            ));
        }
        history.constrain_deadline(Instant::now() - std::time::Duration::from_secs(1));
        assert!(!history.context(&node).is_live());
        assert!(history.check(0, 0).is_err());
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let stored = reopened
            .runtime()
            .block_on(reopened.read_agent_credential_in(&reopened.request_context(), command.id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.grant, original);
        assert!(!stored.revoked);
        authentication(&reopened, &token, "reopened-history", SOURCE_HISTORY_READ)
            .check(0, 0)
            .unwrap();
        committed(credential(
            &reopened,
            &AgentCredentialCommand {
                id: command.id,
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::Revoke(original),
            },
            actor(1),
            "revoke-history",
        ));
        assert!(matches!(
            reopened
                .runtime()
                .block_on(reopened.authenticate_agent_request_in(
                    &reopened.request_context(),
                    token.as_bytes(),
                    &key("revoked-history"),
                    SOURCE_HISTORY_READ,
                    [2; 32],
                    4096,
                    8192,
                )),
            Err(NodeReceiveTransportRefusal::Unauthenticated)
        ));
        reopened.shutdown().unwrap();
    }
}

#[test]
fn candidate_requests_bind_native_scope_namespace_budget_and_original_deadline() {
    let scratch = Scratch::new();
    let node = scratch.node(GitHashAlgorithm::Sha256);
    let token = bearer('f');
    let candidate = AgentCredentialGrant {
        operations: SOURCE_CANDIDATES,
        ..grant(&node)
    };
    committed(credential(
        &node,
        &issue_command(&token, candidate),
        actor(1),
        "issue-candidate",
    ));
    let mut run = authentication(&node, &token, "candidate-request", SOURCE_CANDIDATES);
    for class in OperationClass::ALL {
        assert_eq!(
            run.run.allowed_operation_classes().contains(class),
            matches!(
                class,
                OperationClass::ReadCanonicalObject
                    | OperationClass::TreeFsWorkspace
                    | OperationClass::CreateCandidateObject
            )
        );
    }
    assert!(run.mcp_source_read_context(&node).is_err());
    let bounded = run.source_candidates(&node).unwrap();
    assert!(bounded.context(&node).unwrap().is_live());
    assert_eq!(bounded.workspace_id(), *candidate.agent.as_bytes());
    run.check(4096, 8192).unwrap();
    assert!(run.check(4097, 8192).is_err());
    assert!(run.check(4096, 8193).is_err());
    let namespace = run.namespace;
    run.namespace.incarnation = RepositoryIncarnationId::from_bytes([0xff; 16]);
    assert!(run.source_candidates(&node).is_err());
    run.namespace = namespace;
    let operation = run.operation;
    for wrong in [SOURCE_READ, SOURCE_HISTORY_READ, ISSUES_READ, ISSUES_WRITE] {
        run.operation = wrong;
        assert!(run.source_candidates(&node).is_err());
    }
    run.operation = operation;
    run.constrain_deadline(Instant::now());
    assert!(run.source_candidates(&node).is_err());
    assert!(!run.context(&node).is_live());
    node.shutdown().unwrap();
}

#[test]
fn mcp_source_bridge_keeps_verified_scope_namespace_sponsorship_and_deadline() {
    fn scope_denied(result: Result<SourceReadContext, NodeReceiveTransportRefusal>) {
        assert!(matches!(
            result,
            Err(NodeReceiveTransportRefusal::Admission(error))
                if matches!(*error, AdmissionError::AsyncProjectionUnavailable(RefusalCode::CapabilityScopeViolation))
        ));
    }
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut node = scratch.node(format);
        let token = bearer('a');
        committed(credential(
            &node,
            &issue_command(
                &token,
                AgentCredentialGrant {
                    operations: SOURCE_READ | ISSUES_READ,
                    ..grant(&node)
                },
            ),
            actor(1),
            "mcp-source-credential",
        ));
        let metadata = authentication(&node, &token, "mcp-metadata", ISSUES_READ);
        scope_denied(metadata.mcp_source_read_context(&node));

        let mut source = authentication(&node, &token, "mcp-source", SOURCE_READ);
        source.constrain_deadline(Instant::now() + std::time::Duration::from_secs(60));
        let read = source.mcp_source_read_context(&node).unwrap();
        assert_eq!(read.host(), "mcp-sponsored-agent-source-read-credential");
        assert_eq!(read.principal(), Some(actor(2)));
        assert_eq!(read.sponsor(), Some(actor(1)));
        assert_eq!(read.agent_authentication(), Some(source.authentication));
        assert_eq!(read.agent_deadline(), Some(source.deadline()));
        assert!(read.is_live());
        read.check_node(&node).unwrap();

        // A real independent node shares the configured tenant/repository but
        // has its own incarnation. The reservation must not cross that bound.
        let other_root = Scratch::new();
        let other = other_root.node(format);
        assert_eq!(node.tenant_id, other.tenant_id);
        assert_eq!(node.repository_id, other.repository_id);
        assert_ne!(
            node.repository_incarnation_id,
            other.repository_incarnation_id
        );
        scope_denied(source.mcp_source_read_context(&other));
        assert!(read.check_node(&other).is_err());
        other.shutdown().unwrap();

        // Isolate each remaining namespace dimension at the adapter boundary.
        // No native work may start while any verified field is substituted.
        let original = source.namespace;
        node.tenant_id = TenantId::from_bytes([0xb1; 16]);
        scope_denied(source.mcp_source_read_context(&node));
        node.tenant_id = original.tenant;
        node.repository_id = RepositoryId::from_bytes([0xb2; 16]);
        scope_denied(source.mcp_source_read_context(&node));
        node.repository_id = original.repository;
        node.object_format = match format {
            GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
            GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
        };
        scope_denied(source.mcp_source_read_context(&node));
        node.object_format = original.object_format;
        source.mcp_source_read_context(&node).unwrap();

        source.constrain_deadline(Instant::now() - std::time::Duration::from_secs(1));
        assert!(matches!(
            source.mcp_source_read_context(&node),
            Err(NodeReceiveTransportRefusal::Admission(error))
                if matches!(*error, AdmissionError::AsyncProjectionUnavailable(RefusalCode::CapabilityExpired))
        ));
        node.shutdown().unwrap();
    }
}
