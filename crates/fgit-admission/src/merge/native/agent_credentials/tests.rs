use super::*;
use crate::evidence::AgentAuthentication;
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::harness::{digest_of, head_id};
use fgit_forge::event::agent_credential::{SOURCE_READ, SponsorKind};
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

fn fixture() -> (AdmissionContext, AgentCredentialState, AgentAuthentication) {
    let grant = AgentCredentialGrant {
        agent: PrincipalId::from_bytes([1; 16]),
        sponsor: PrincipalId::from_bytes([2; 16]),
        sponsor_kind: SponsorKind::Human,
        tenant: TenantId::from_bytes([3; 16]),
        repository: RepositoryId::from_bytes([4; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([5; 16]),
        issued_at: 100,
        expires_at: 200,
        operations: SOURCE_PUBLISH,
    };
    let context = AdmissionContext {
        head_key: HeadKey::new(b"agent/source/head".to_vec()).unwrap(),
        tenant_id: grant.tenant,
        repository_id: grant.repository,
        principal_id: grant.agent,
        idempotency_key: IdempotencyKey::new(b"source-publication".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    };
    let id = AgentCredentialId::try_new([9; 32]).unwrap();
    let scope = SourcePublicationScope::new(
        "exact:726566732f68656164732f6167656e74",
        vec![b"src".to_vec()],
    )
    .unwrap();
    let root = scoped_grant_root(id, &grant, Some(&scope)).unwrap();
    let state = AgentCredentialState {
        source_head: head_id(),
        id,
        version: AggregateVersion::FIRST,
        grant,
        source_scope: Some(scope),
        grant_root: root,
        revoked: false,
    };
    let witness = AgentAuthentication::try_new(
        grant.agent,
        grant.sponsor,
        grant.sponsor_kind,
        id,
        root,
        [7; 32],
        110,
        200,
    )
    .unwrap();
    (context, state, witness)
}

#[test]
fn original_grant_root_commits_ref_and_path_ceiling_and_preserves_legacy_roots() {
    let (_, state, _) = fixture();
    let legacy = AgentCredentialGrant {
        operations: 0x0fff,
        ..state.grant
    };
    assert_eq!(
        grant_root(state.id, &legacy).unwrap(),
        scoped_grant_root(state.id, &legacy, None).unwrap()
    );
    assert!(grant_root(state.id, &state.grant).is_err());
    assert!(scoped_grant_root(state.id, &legacy, state.source_scope.as_ref()).is_err());
    for (reference, paths) in [
        (
            "exact:726566732f68656164732f6167656e74",
            vec![b"tests".to_vec()],
        ),
        ("exact:726566732f68656164732f6167656e74", vec![Vec::new()]),
        (
            "exact:726566732f68656164732f6d61696e",
            vec![b"src".to_vec()],
        ),
    ] {
        let substituted = SourcePublicationScope::new(reference, paths).unwrap();
        assert_ne!(
            state.grant_root,
            scoped_grant_root(state.id, &state.grant, Some(&substituted)).unwrap()
        );
    }
    let other_id = AgentCredentialId::try_new([8; 32]).unwrap();
    assert_ne!(
        state.grant_root,
        scoped_grant_root(other_id, &state.grant, state.source_scope.as_ref()).unwrap()
    );
}

#[test]
fn exact_basis_grant_validation_rejects_revocation_substitution_and_widening() {
    let (context, state, witness) = fixture();
    let check = |state: &AgentCredentialState| {
        validate_authenticated_grant(
            state,
            &context,
            &witness,
            state.grant.incarnation,
            SOURCE_PUBLISH,
            150,
        )
    };
    assert_eq!(check(&state), Ok(()));
    for change in 0..12 {
        let mut changed = state.clone();
        match change {
            0 => changed.revoked = true,
            1 => changed.id = AgentCredentialId::try_new([8; 32]).unwrap(),
            2 => changed.grant_root = digest_of(0x88),
            3 => changed.grant.agent = PrincipalId::from_bytes([8; 16]),
            4 => changed.grant.sponsor = PrincipalId::from_bytes([8; 16]),
            5 => changed.grant.sponsor_kind = SponsorKind::Service,
            6 => changed.grant.tenant = TenantId::from_bytes([8; 16]),
            7 => changed.grant.repository = RepositoryId::from_bytes([8; 16]),
            8 => changed.grant.issued_at = 111,
            9 => changed.grant.expires_at = 199,
            10 => changed.grant.operations = SOURCE_READ,
            11 => changed.source_scope = None,
            _ => unreachable!(),
        }
        assert_eq!(
            check(&changed),
            Err(RefusalCode::CapabilityScopeViolation),
            "change {change}"
        );
    }
    assert_eq!(
        validate_authenticated_grant(
            &state,
            &context,
            &witness,
            RepositoryIncarnationId::from_bytes([8; 16]),
            SOURCE_PUBLISH,
            150,
        ),
        Err(RefusalCode::CapabilityScopeViolation)
    );
    for now in [109, 200, u64::MAX] {
        assert_eq!(
            validate_authenticated_grant(
                &state,
                &context,
                &witness,
                state.grant.incarnation,
                SOURCE_PUBLISH,
                now,
            ),
            Err(RefusalCode::CapabilityExpired)
        );
    }
    for operation in [0, SOURCE_READ, SOURCE_PUBLISH | SOURCE_READ, 1 << 15] {
        assert_eq!(
            validate_authenticated_grant(
                &state,
                &context,
                &witness,
                state.grant.incarnation,
                operation,
                150,
            ),
            Err(RefusalCode::CapabilityScopeViolation)
        );
    }
}
