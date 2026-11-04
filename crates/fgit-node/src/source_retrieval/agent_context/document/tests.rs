//! Clock and provenance contract checks. HTTP and MCP integration tests authenticate
//! real canonical credentials and retrieve real persisted source/index objects.
use super::*;
use crate::source_retrieval::authorization::{
    model_agent_context, model_context, model_mcp_agent_context,
};
use fgit_admission::evidence::AgentAuthentication;
use fgit_crypto::{IdentityDomain, internal_object_id};
use fgit_forge::event::agent_credential::{AgentCredentialId, SponsorKind};
use fgit_graph::lexical::LexicalNamespace;
use fgit_schema::json::Value;
use fgit_types::{
    CodecVersion, Digest, GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, SchemaFamily,
    SchemaId, TenantId,
};

fn namespace() -> LexicalNamespace {
    LexicalNamespace {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        object_format: GitHashAlgorithm::Sha256,
    }
}

fn authentication() -> AgentAuthentication {
    let root = internal_object_id(
        IdentityDomain::MerkleLeaf,
        SchemaId::new(SchemaFamily::from_static("test"), 1, 0),
        CodecVersion::new(1, 0),
        b"canonical-agent-grant",
    );
    AgentAuthentication::try_new(
        PrincipalId::from_bytes([4; 16]),
        PrincipalId::from_bytes([5; 16]),
        SponsorKind::Service,
        AgentCredentialId::try_new([6; 32]).unwrap(),
        Digest::new(root.algorithm(), *root.digest()),
        [7; 32],
        100,
        200,
    )
    .unwrap()
}

#[test]
fn sponsored_document_checks_the_authenticated_sponsor_instead_of_the_agent() {
    let authentication = authentication();
    let read = model_agent_context(namespace(), authentication, Instant::now());
    assert!(check_sponsor(&read, authentication.sponsor()).is_ok());
    assert!(matches!(
        check_sponsor(&read, authentication.agent()),
        Err(AgentContextDocumentError::SponsorAuthorization)
    ));
    assert!(matches!(
        check_sponsor(&read, PrincipalId::from_bytes([8; 16])),
        Err(AgentContextDocumentError::SponsorAuthorization)
    ));
    let local = model_context(namespace());
    assert!(check_sponsor(&local, authentication.sponsor()).is_ok());
}

#[test]
fn child_clock_uses_the_earliest_requested_credential_or_monotonic_expiry() {
    let origin = Instant::now();
    let authentication = authentication();
    let read = model_agent_context(namespace(), authentication, origin + Duration::from_secs(3));
    let wall = Duration::from_millis(150_500);
    let long = Clock::start_at(MAX_LIFETIME, &read, origin, wall).unwrap();
    assert_eq!(long.logical_origin, 150_500_000_000);
    assert_eq!(long.expiry.value(), 153_500_000_000);
    let narrow = Clock::start_at(Duration::from_secs(1), &read, origin, wall).unwrap();
    assert_eq!(narrow.expiry.value(), 151_500_000_000);

    let near_expiry = model_agent_context(namespace(), authentication, origin + MAX_LIFETIME);
    let bounded = Clock::start_at(
        MAX_LIFETIME,
        &near_expiry,
        origin,
        Duration::from_millis(199_750),
    )
    .unwrap();
    assert_eq!(
        bounded.expiry.value(),
        authentication.expires_at() * 1_000_000_000
    );
    for (start, wall) in [
        (origin + Duration::from_secs(3), wall),
        (origin, Duration::from_secs(authentication.expires_at())),
        (
            origin,
            Duration::from_secs(authentication.authenticated_at() - 1),
        ),
    ] {
        assert!(matches!(
            Clock::start_at(MAX_LIFETIME, &read, start, wall),
            Err(AgentContextDocumentError::Expired)
        ));
    }
    let local = model_context(namespace());
    let local_clock = Clock::start_at(MAX_LIFETIME, &local, origin, wall).unwrap();
    assert_eq!(local_clock.expiry.value(), 450_500_000_000);
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &value.object().unwrap()[name]
}

#[test]
fn context_intent_commits_agent_and_sponsor_as_distinct_verified_identities() {
    let authentication = authentication();
    let read = model_agent_context(namespace(), authentication, Instant::now());
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let query = InitialQuery::new(&[b"needle".to_vec()], &[]).unwrap();
    let checkpoints = Checkpoints::default();
    let input = AgentContextRequest {
        authorization: &read,
        reference: &reference,
        query: &query,
        checkpoints: &checkpoints,
        retrieval_limits: Default::default(),
        context_limits: Default::default(),
        sponsor: authentication.sponsor(),
        expected_head: None,
        expires_after: MAX_LIFETIME,
        max_output_bytes: 1024 * 1024,
    };
    let intent = render::intent(&input);
    assert_eq!(field(&intent, "profile").text(), Some(HTTP_AGENT_PROFILE));
    assert_eq!(
        field(&intent, "sponsor_id").text(),
        Some(authentication.sponsor().to_string().as_str())
    );
    assert_eq!(
        field(&intent, "sponsor_authentication").text(),
        Some("canonical-agent-credential")
    );
    let provenance = field(&intent, "agent_authentication");
    assert_eq!(
        field(provenance, "principal_id").text(),
        Some(authentication.agent().to_string().as_str())
    );
    assert_eq!(
        field(provenance, "sponsor_id").text(),
        Some(authentication.sponsor().to_string().as_str())
    );
    assert_eq!(field(provenance, "sponsor_kind").text(), Some("service"));
    assert_eq!(
        field(provenance, "credential_id").text(),
        Some(authentication.credential_id().to_string().as_str())
    );
    assert_eq!(
        field(provenance, "request_run_commitment").text(),
        Some(render::hex(authentication.run_commitment()).as_str())
    );
    assert_eq!(
        field(provenance, "authenticated_at_unix_seconds").unsigned(),
        Some(authentication.authenticated_at())
    );
    assert_eq!(
        field(provenance, "expires_at_unix_seconds").unsigned(),
        Some(authentication.expires_at())
    );
    let local = model_context(namespace());
    let local_intent = render::intent(&AgentContextRequest {
        authorization: &local,
        ..input
    });
    assert_eq!(field(&local_intent, "profile").text(), Some(PROFILE));
    assert!(
        !local_intent
            .object()
            .unwrap()
            .contains_key("agent_authentication")
    );
}

#[test]
fn mcp_document_binds_its_actual_host_without_extending_the_credential() {
    let authentication = authentication();
    let origin = Instant::now();
    let deadline = origin + Duration::from_secs(2);
    let http = model_agent_context(namespace(), authentication, deadline);
    let mcp = model_mcp_agent_context(namespace(), authentication, deadline);
    assert!(check_sponsor(&mcp, authentication.sponsor()).is_ok());
    assert!(matches!(
        check_sponsor(&mcp, authentication.agent()),
        Err(AgentContextDocumentError::SponsorAuthorization)
    ));
    let clock = Clock::start_at(MAX_LIFETIME, &mcp, origin, Duration::from_secs(150)).unwrap();
    assert_eq!(clock.expiry.value(), 152_000_000_000);
    let near_expiry =
        Clock::start_at(MAX_LIFETIME, &mcp, origin, Duration::from_millis(199_500)).unwrap();
    assert_eq!(near_expiry.expiry.value(), 200_000_000_000);
    for (monotonic, wall) in [
        (deadline, Duration::from_secs(150)),
        (origin, Duration::from_secs(200)),
        (origin, Duration::from_secs(99)),
    ] {
        assert!(matches!(
            Clock::start_at(MAX_LIFETIME, &mcp, monotonic, wall),
            Err(AgentContextDocumentError::Expired)
        ));
    }

    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let query = InitialQuery::new(&[b"needle".to_vec()], &[]).unwrap();
    let checkpoints = Checkpoints::default();
    let input = AgentContextRequest {
        authorization: &http,
        reference: &reference,
        query: &query,
        checkpoints: &checkpoints,
        retrieval_limits: Default::default(),
        context_limits: Default::default(),
        sponsor: authentication.sponsor(),
        expected_head: None,
        expires_after: MAX_LIFETIME,
        max_output_bytes: 1024 * 1024,
    };
    let http_intent = render::intent(&input);
    let mcp_intent = render::intent(&AgentContextRequest {
        authorization: &mcp,
        ..input
    });
    assert_eq!(
        field(&http_intent, "profile").text(),
        Some(HTTP_AGENT_PROFILE)
    );
    assert_eq!(
        field(&mcp_intent, "profile").text(),
        Some(MCP_AGENT_PROFILE)
    );
    assert_eq!(
        field(&mcp_intent, "authorization_host").text(),
        Some("mcp-sponsored-agent-source-read-credential")
    );
    assert_eq!(
        field(&mcp_intent, "sponsor_authentication").text(),
        Some("canonical-agent-credential")
    );
    assert_eq!(
        field(&mcp_intent, "agent_authentication"),
        field(&http_intent, "agent_authentication")
    );
    // The exact same canonical provenance cannot relabel an HTTP context as
    // MCP: host/profile changes are part of the committed request intent.
    let domain = b"frankengit/agent-context-request/v1\0";
    assert_ne!(
        commitment(domain, mcp_intent.encode(128 * 1024).unwrap().as_bytes()),
        commitment(domain, http_intent.encode(128 * 1024).unwrap().as_bytes())
    );
}

#[test]
fn explicit_index_source_changes_only_the_committed_selector_not_the_host_profile() {
    let authentication = authentication();
    let deadline = Instant::now() + Duration::from_secs(30);
    let contexts = [
        model_context(namespace()),
        model_agent_context(namespace(), authentication, deadline),
        model_mcp_agent_context(namespace(), authentication, deadline),
    ];
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let query = InitialQuery::new(&[b"needle".to_vec()], &[]).unwrap();
    let checkpoints = Checkpoints::default();
    for authorization in &contexts {
        let input = AgentContextRequest {
            authorization,
            reference: &reference,
            query: &query,
            checkpoints: &checkpoints,
            retrieval_limits: Default::default(),
            context_limits: Default::default(),
            sponsor: authentication.sponsor(),
            expected_head: None,
            expires_after: MAX_LIFETIME,
            max_output_bytes: 1024 * 1024,
        };
        let strict = render::intent(&input);
        let strict_bytes = strict.encode(128 * 1024).unwrap();
        assert!(!strict.object().unwrap().contains_key("index_source"));
        let revalidated = render::revalidated_intent(&input);
        assert_eq!(field(&strict, "profile"), field(&revalidated, "profile"));
        assert_eq!(
            field(&strict, "authorization_host"),
            field(&revalidated, "authorization_host")
        );
        assert_eq!(
            field(&revalidated, "index_source").text(),
            Some(CURRENT_NATIVE_INDEX_SOURCE)
        );
        let mut without_selector = revalidated.object().unwrap().clone();
        without_selector.remove("index_source");
        assert_eq!(Value::Object(without_selector), strict);
        let domain = b"frankengit/agent-context-request/v1\0";
        assert_ne!(
            commitment(domain, strict_bytes.as_bytes()),
            commitment(domain, revalidated.encode(128 * 1024).unwrap().as_bytes())
        );
        // The strict API still emits exactly the preexisting intent, including
        // omission of absent agent provenance; invoking the new mode cannot
        // relabel its host or change an earlier strict commitment.
        assert_eq!(
            render::intent(&input).encode(128 * 1024).unwrap(),
            strict_bytes
        );
    }
}
