use super::*;
use fgit_identity::agent::PULLS_CHECK_EVIDENCE_READ;

#[test]
fn check_evidence_requests_keep_exact_identity_read_class_and_original_limits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let token = bearer('e');
        let original = AgentCredentialGrant {
            operations: PULLS_CHECK_EVIDENCE_READ,
            ..grant(&node)
        };
        let command = issue_command(&token, original);
        committed(credential(
            &node,
            &command,
            actor(1),
            "issue-check-evidence",
        ));

        // Every legacy operation except separately scoped publication includes
        // summary feedback but must still deny diagnostic evidence disclosure.
        let old_token = bearer('d');
        let retained = AgentCredentialGrant {
            operations: 0xefff,
            ..original
        };
        committed(credential(
            &node,
            &issue_command(&old_token, retained),
            actor(1),
            "issue-retained-feedback",
        ));
        assert!(matches!(
            node.runtime().block_on(node.authenticate_agent_request_in(
                &node.request_context(),
                old_token.as_bytes(),
                &key("retained-evidence-denied"),
                PULLS_CHECK_EVIDENCE_READ,
                [1; 32],
                4096,
                8192,
            )),
            Err(NodeReceiveTransportRefusal::Admission(error))
                if matches!(*error, AdmissionError::AsyncProjectionUnavailable(RefusalCode::CapabilityScopeViolation))
        ));
        authentication(&node, &old_token, "retained-summary", PULLS_FEEDBACK_READ)
            .check_operation(&node, PULLS_FEEDBACK_READ)
            .unwrap();

        let mut evidence = authentication(
            &node,
            &token,
            "read-check-evidence",
            PULLS_CHECK_EVIDENCE_READ,
        );
        assert_eq!(evidence.authentication.agent(), original.agent);
        assert_eq!(evidence.authentication.sponsor(), original.sponsor);
        assert_eq!(evidence.authentication.credential_id(), command.id);
        assert_ne!(*evidence.authentication.run_commitment(), [0; 32]);
        for class in OperationClass::ALL {
            assert_eq!(
                evidence.run.allowed_operation_classes().contains(class),
                class == OperationClass::ReadCanonicalObject,
                "check evidence requests must not acquire {class:?}"
            );
        }
        evidence
            .check_operation(&node, PULLS_CHECK_EVIDENCE_READ)
            .unwrap();
        for operation in (0..17).map(|bit| 1u32 << bit) {
            assert!(evidence.check_operation(&node, operation).is_err());
        }
        assert!(evidence.mcp_source_read_context(&node).is_err());
        assert!(evidence.source_candidates(&node).is_err());
        evidence.check(4096, 8192).unwrap();
        assert!(evidence.check(4097, 8192).is_err());
        assert!(evidence.check(4096, 8193).is_err());

        let namespace = evidence.namespace;
        for mismatch in [
            LexicalNamespace {
                tenant: TenantId::from_bytes([0xf1; 16]),
                ..namespace
            },
            LexicalNamespace {
                repository: RepositoryId::from_bytes([0xf2; 16]),
                ..namespace
            },
            LexicalNamespace {
                incarnation: RepositoryIncarnationId::from_bytes([0xf3; 16]),
                ..namespace
            },
            LexicalNamespace {
                object_format: match format {
                    GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256,
                    GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1,
                },
                ..namespace
            },
        ] {
            evidence.namespace = mismatch;
            assert!(
                evidence
                    .check_operation(&node, PULLS_CHECK_EVIDENCE_READ)
                    .is_err()
            );
        }
        evidence.namespace = namespace;
        for operation in [0, PULLS_CHECK_EVIDENCE_READ | PULLS_FEEDBACK_READ, 1 << 18] {
            assert!(matches!(
                node.runtime().block_on(node.authenticate_agent_request_in(
                    &node.request_context(),
                    token.as_bytes(),
                    &key("invalid-check-evidence-operation"),
                    operation,
                    [2; 32],
                    4096,
                    8192,
                )),
                Err(NodeReceiveTransportRefusal::Unauthenticated)
            ));
        }

        let original_deadline = evidence.deadline();
        evidence.constrain_deadline(original_deadline + std::time::Duration::from_secs(60));
        assert_eq!(evidence.deadline(), original_deadline);
        let LoopbackReceiveSession::Authenticated(session) = evidence.authenticated_session()
        else {
            panic!("the request must retain its authenticated agent")
        };
        assert_eq!(session.principal_id(), original.agent);
        assert_eq!(
            session.client_idempotency_key(),
            &key("read-check-evidence")
        );
        assert_eq!(
            session.authentication(),
            AdmissionAuthentication::AgentCredential(evidence.authentication)
        );
        assert_eq!(session.agent_deadline, Some(original_deadline));
        evidence.constrain_deadline(Instant::now() - std::time::Duration::from_secs(1));
        assert!(!evidence.context(&node).is_live());
        assert!(
            evidence
                .check_operation(&node, PULLS_CHECK_EVIDENCE_READ)
                .is_err()
        );
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let stored = reopened
            .runtime()
            .block_on(reopened.read_agent_credential_in(&reopened.request_context(), command.id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.grant, original);
        assert!(stored.source_scope.is_none());
        assert!(!stored.revoked);
        authentication(
            &reopened,
            &token,
            "reopened-check-evidence",
            PULLS_CHECK_EVIDENCE_READ,
        )
        .check_operation(&reopened, PULLS_CHECK_EVIDENCE_READ)
        .unwrap();
        committed(credential(
            &reopened,
            &AgentCredentialCommand {
                id: command.id,
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::Revoke(original),
            },
            actor(1),
            "revoke-check-evidence",
        ));
        assert!(matches!(
            reopened
                .runtime()
                .block_on(reopened.authenticate_agent_request_in(
                    &reopened.request_context(),
                    token.as_bytes(),
                    &key("revoked-check-evidence"),
                    PULLS_CHECK_EVIDENCE_READ,
                    [3; 32],
                    4096,
                    8192,
                )),
            Err(NodeReceiveTransportRefusal::Unauthenticated)
        ));
        let revoked = reopened
            .runtime()
            .block_on(reopened.read_agent_credential_in(&reopened.request_context(), command.id))
            .unwrap()
            .unwrap();
        assert_eq!(revoked.grant, original);
        assert!(revoked.revoked);
        assert!(revoked.source_scope.is_none());
        reopened.shutdown().unwrap();
    }
}
