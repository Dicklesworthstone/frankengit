use super::*;

const BEARER: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn grant() -> AgentCredentialGrant {
    AgentCredentialGrant {
        agent: PrincipalId::from_bytes([1; 16]),
        sponsor: PrincipalId::from_bytes([2; 16]),
        sponsor_kind: SponsorKind::Service,
        tenant: TenantId::from_bytes([3; 16]),
        repository: RepositoryId::from_bytes([4; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([5; 16]),
        issued_at: 100,
        expires_at: 200,
        operations: ISSUES_WRITE | PULLS_READ,
    }
}

fn authenticate(
    grant: &AgentCredentialGrant,
    bearer: &[u8],
    now: u64,
    revocation: RevocationEvidence,
) -> Result<AuthenticatedAgentCredential, AgentCredentialRefusal> {
    authenticate_agent_credential(
        agent_credential_id(BEARER).unwrap(),
        grant,
        bearer,
        grant.tenant,
        grant.repository,
        grant.incarnation,
        now,
        revocation,
    )
}

#[test]
fn bearer_authentication_retains_agent_sponsor_and_exact_independent_ceiling() {
    let grant = grant();
    let authenticated = authenticate(&grant, BEARER, 100, RevocationEvidence::Live).unwrap();
    assert_eq!(authenticated.id(), agent_credential_id(BEARER).unwrap());
    assert_eq!(authenticated.grant(), &grant);
    assert_eq!(authenticated.principal(), grant.agent);
    assert_eq!(authenticated.sponsor(), grant.sponsor);
    assert_eq!(authenticated.authorize(ISSUES_WRITE), Ok(()));
    assert_eq!(authenticated.authorize(PULLS_READ), Ok(()));
    assert_eq!(authenticated.authorize(ISSUES_WRITE | PULLS_READ), Ok(()));
    for operation in [
        0,
        ISSUES_READ,
        PULLS_WRITE,
        DISCUSSIONS_READ,
        OUTCOMES_READ,
        1 << 15,
    ] {
        assert_eq!(
            authenticated.authorize(operation),
            Err(AgentCredentialRefusal::OperationNotGranted)
        );
    }
}

#[test]
fn every_binding_coordinate_lifetime_boundary_and_revocation_is_required() {
    let grant = grant();
    let id = agent_credential_id(BEARER).unwrap();
    for now in [grant.issued_at, grant.expires_at - 1] {
        assert!(authenticate(&grant, BEARER, now, RevocationEvidence::Live).is_ok());
    }
    assert_eq!(
        authenticate(&grant, BEARER, 99, RevocationEvidence::Live),
        Err(AgentCredentialRefusal::NotYetValid)
    );
    for now in [200, u64::MAX] {
        assert_eq!(
            authenticate(&grant, BEARER, now, RevocationEvidence::Live),
            Err(AgentCredentialRefusal::Expired)
        );
    }
    for (revocation, expected) in [
        (RevocationEvidence::Revoked, AgentCredentialRefusal::Revoked),
        (
            RevocationEvidence::NotChecked,
            AgentCredentialRefusal::RevocationEvidenceRequired,
        ),
    ] {
        assert_eq!(authenticate(&grant, BEARER, 100, revocation), Err(expected));
    }
    for (tenant, repository, incarnation) in [
        (
            TenantId::from_bytes([8; 16]),
            grant.repository,
            grant.incarnation,
        ),
        (
            grant.tenant,
            RepositoryId::from_bytes([8; 16]),
            grant.incarnation,
        ),
        (
            grant.tenant,
            grant.repository,
            RepositoryIncarnationId::from_bytes([8; 16]),
        ),
    ] {
        assert_eq!(
            authenticate_agent_credential(
                id,
                &grant,
                BEARER,
                tenant,
                repository,
                incarnation,
                100,
                RevocationEvidence::Live
            ),
            Err(AgentCredentialRefusal::BindingMismatch)
        );
    }
    let inflight = authenticate(&grant, BEARER, 100, RevocationEvidence::Live).unwrap();
    assert_eq!(
        authenticate(&grant, BEARER, 101, RevocationEvidence::Revoked),
        Err(AgentCredentialRefusal::Revoked)
    );
    assert_eq!(inflight.authorize(ISSUES_WRITE), Ok(()));
}

#[test]
fn wrong_secret_unbounded_input_and_malformed_grant_are_refused_without_secret_diagnostics() {
    let grant = grant();
    assert!(authenticate(&grant, BEARER, 100, RevocationEvidence::Live).is_ok());
    let mut changed = BEARER.to_vec();
    changed[0] ^= 1;
    assert_eq!(
        authenticate(&grant, &changed, 100, RevocationEvidence::Live),
        Err(AgentCredentialRefusal::InvalidBearer)
    );
    for length in [0, MIN_AGENT_BEARER_BYTES - 1, MAX_AGENT_BEARER_BYTES + 1] {
        let bearer = vec![b'x'; length];
        assert_eq!(
            agent_credential_id(&bearer),
            Err(AgentCredentialRefusal::InvalidBearer)
        );
        assert_eq!(
            authenticate(&grant, &bearer, 100, RevocationEvidence::Live),
            Err(AgentCredentialRefusal::InvalidBearer)
        );
    }
    for length in [MIN_AGENT_BEARER_BYTES, MAX_AGENT_BEARER_BYTES] {
        assert!(agent_credential_id(&vec![b'x'; length]).is_ok());
    }
    for invalid in [
        AgentCredentialGrant {
            operations: 0,
            ..grant
        },
        AgentCredentialGrant {
            operations: ALL_OPERATIONS | (1 << 15),
            ..grant
        },
        AgentCredentialGrant {
            sponsor: grant.agent,
            ..grant
        },
        AgentCredentialGrant {
            expires_at: grant.issued_at,
            ..grant
        },
    ] {
        assert_eq!(
            authenticate(&invalid, BEARER, 100, RevocationEvidence::Live),
            Err(AgentCredentialRefusal::InvalidGrant)
        );
    }
    for refusal in [
        AgentCredentialRefusal::InvalidGrant,
        AgentCredentialRefusal::InvalidBearer,
        AgentCredentialRefusal::BindingMismatch,
        AgentCredentialRefusal::NotYetValid,
        AgentCredentialRefusal::Expired,
        AgentCredentialRefusal::Revoked,
        AgentCredentialRefusal::RevocationEvidenceRequired,
        AgentCredentialRefusal::OperationNotGranted,
    ] {
        assert!(
            !refusal
                .to_string()
                .contains(std::str::from_utf8(BEARER).unwrap())
        );
    }
}
