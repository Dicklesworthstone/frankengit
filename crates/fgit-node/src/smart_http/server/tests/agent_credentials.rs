#![forbid(unsafe_code)]
//! Real bearer requests cross the canonical grant registry, request run,
//! metadata publication and immutable terminal-provenance boundaries.

use super::{profile, *};
use crate::LoopbackReceiveSession;
use fgit_authority::IdempotencyKey;
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_identity::agent::{
    ALL_OPERATIONS, AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant,
    ISSUES_READ, ISSUES_WRITE, SponsorKind, agent_credential_id,
};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-agent-credential-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, directory: &str) -> NodeConfig {
        NodeConfig::new(
            self.0.join(directory),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_object_format(GitHashAlgorithm::Sha256)
        .with_worker_threads(2)
        .with_http_protection_admin()
        .with_http_discussions()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("retaining failed agent HTTP fixture: {}", self.0.display());
        } else {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn actor(value: u8) -> PrincipalId {
    PrincipalId::from_bytes([value; 16])
}
fn credential(node: &OneNode, command: &AgentCredentialCommand, sponsor: PrincipalId, retry: &str) {
    let session = LoopbackReceiveSession::authenticated(
        sponsor,
        IdempotencyKey::new(retry.as_bytes().to_vec()).unwrap(),
    );
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_agent_credential_durable_in(
            &node.request_context(),
            &session,
            command,
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
}
fn reopen(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}

fn exchange(
    profile: &Profile,
    token: &str,
    method: &str,
    target: &str,
    body: &str,
    key: Option<&str>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let retry = key.map_or_else(String::new, |key| format!("Idempotency-Key: {key}\r\n"));
    let media = if target.ends_with("/git-receive-pack") {
        "application/x-git-receive-pack-request"
    } else {
        "application/x-www-form-urlencoded"
    };
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {token}\r\nUser-Agent: frankengit-agent-credential-test\r\nContent-Type: {media}\r\nContent-Length: {}\r\n{retry}\r\n{body}",
        body.len(),
    );
    // The native server must handle a body already buffered with the header.
    peer.write_all(request.as_bytes()).unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let deadline = GitDaemonSessionDeadline::new(
                GitDaemonSessionTimeout::try_new(Duration::from_secs(60)).unwrap(),
                GitDaemonSessionWorkScaling::FLAT,
            );
            serve_connection(stream, deadline, profile)
        });
        let mut response = String::new();
        peer.take(128 * 1024).read_to_string(&mut response).unwrap();
        worker.join().unwrap();
        assert!(!response.contains(token), "bearer must never be reflected");
        response
    })
}
fn status(response: &str, expected: u16) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {expected} ")),
        "{response}"
    );
}
fn committed(response: &str) {
    status(response, 200);
    assert!(response.contains("\"outcome\":\"committed\""), "{response}");
}
fn original_provenance(response: &str) -> &str {
    status(response, 200);
    assert!(response.contains("\"state\":\"committed\""), "{response}");
    assert!(response.contains("\"provenance_error\":null"), "{response}");
    response
        .split_once(",\"principal_provenance\":")
        .unwrap()
        .1
        .rsplit_once(",\"provenance_error\":")
        .unwrap()
        .0
}

#[test]
fn canonical_agent_http_metadata_scope_revocation_and_original_outcome_provenance() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config("repository")).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let config = scratch
        .config("repository")
        .with_expected_repository_incarnation(node.repository_incarnation_id());
    let now = crate::agent_credentials::epoch_seconds().unwrap();
    let original = crate::agent_credentials::generate_agent_credential_token();
    let read_only = crate::agent_credentials::generate_agent_credential_token();
    let write_only = crate::agent_credentials::generate_agent_credential_token();
    let grant = AgentCredentialGrant {
        agent: actor(2),
        sponsor: actor(1),
        sponsor_kind: SponsorKind::Human,
        tenant: TenantId::from_bytes([0xb1; 16]),
        repository: RepositoryId::from_bytes([0xb2; 16]),
        incarnation: node.repository_incarnation_id(),
        issued_at: now - 1,
        expires_at: now + 3600,
        operations: ALL_OPERATIONS,
    };
    for (token, operations, key) in [
        (original.as_str(), ALL_OPERATIONS, "issue-http-original"),
        (read_only.as_str(), ISSUES_READ, "issue-http-read-only"),
        (write_only.as_str(), ISSUES_WRITE, "issue-http-write-only"),
    ] {
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(token.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: AgentCredentialAction::Issue(AgentCredentialGrant {
                    operations,
                    ..grant
                }),
            },
            grant.sponsor,
            key,
        );
    }

    // Deliberately give the canonical bearer a broad legacy-file grant for a
    // different principal. Neither revocation nor a missing canonical record
    // may fall back to it, despite that row being valid for normal tokens.
    let normal = "d".repeat(64);
    let path = scratch.0.join("http-credentials");
    let binding = Binding {
        tenant: grant.tenant,
        repository: grant.repository,
        incarnation: grant.incarnation,
    };
    let mut table = format!(
        "frankengit-http-credentials-v1 {} {} {}\n",
        binding.tenant, binding.repository, binding.incarnation,
    );
    for token in [&original, &normal] {
        let digest = sha256_digest(token.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        table.push_str(&format!(
            "{digest} {} read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write,protection-read,protection-write,discussions-read,discussions-write\n",
            actor(4),
        ));
    }
    fs::write(&path, table).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut selected = profile();
    selected.route = node.git_daemon_repository_path().as_bytes().to_vec();
    selected.config = config.clone();
    selected.credentials = CredentialSource::File { path, binding };
    selected.services = RepositoryHttpServices::NONE
        .with(RepositoryHttpService::Receive, true)
        .with(RepositoryHttpService::Issues, true)
        .with(RepositoryHttpService::Outcomes, true)
        .with(RepositoryHttpService::Pulls, true)
        .with(RepositoryHttpService::Source, true);
    selected.maximum_response_bytes = 64 * 1024;
    selected.timeout = GitDaemonSessionTimeout::try_new(Duration::from_secs(60)).unwrap();
    selected.nodes = Arc::new(NodeLanes::new(
        config.clone(),
        1,
        "agent credential HTTP test",
    ));
    node.shutdown().unwrap();
    let route = String::from_utf8(selected.route.clone()).unwrap();
    let request = |token, method, suffix, body, key| {
        exchange(
            &selected,
            token,
            method,
            &format!("{route}{suffix}"),
            body,
            key,
        )
    };
    let opening = "expected_version=0&title=Sponsored+HTTP+issue&body=Bounded+metadata";
    committed(&request(
        &original,
        "POST",
        "/api/v1/issues/1/open",
        opening,
        Some("http-agent-open-issue"),
    ));
    let read = request(&original, "GET", "/api/v1/issues/1", "", None);
    status(&read, 200);
    assert!(
        read.contains(&format!("\"opened_by\":\"{}\"", grant.agent)),
        "{read}"
    );
    assert!(read.contains("Sponsored HTTP issue"), "{read}");
    status(&request(&original, "GET", "/api/v1/pulls", "", None), 200);
    committed(&request(
        &original,
        "POST",
        "/api/v1/discussions/1/open",
        "expected_version=0&title=Sponsored+discussion&body=Native+conversation",
        Some("http-agent-open-discussion"),
    ));
    status(
        &request(&original, "GET", "/api/v1/discussions/1", "", None),
        200,
    );

    let outcome = request(
        &original,
        "POST",
        "/api/v1/outcomes",
        "",
        Some("http-agent-open-issue"),
    );
    let provenance = original_provenance(&outcome).to_owned();
    for field in [
        "\"state\":\"recorded\"".to_owned(),
        "\"authentication\":\"agent_credential\"".to_owned(),
        format!("\"agent\":\"{}\"", grant.agent),
        format!("\"sponsor\":\"{}\"", grant.sponsor),
        "\"sponsor_kind\":\"human\"".to_owned(),
        format!(
            "\"credential_id\":\"{}\"",
            agent_credential_id(original.as_bytes()).unwrap()
        ),
        "\"run_commitment\":".to_owned(),
        "\"grant_root\":".to_owned(),
    ] {
        assert!(provenance.contains(&field), "missing {field}: {provenance}");
    }

    // Independent positive twins prove that read and write are separate
    // grants, and that unrelated metadata scopes are not implied by either.
    status(
        &request(&read_only, "GET", "/api/v1/issues/1", "", None),
        200,
    );
    status(
        &request(
            &read_only,
            "POST",
            "/api/v1/issues/2/open",
            opening,
            Some("read-cannot-write"),
        ),
        403,
    );
    committed(&request(
        &write_only,
        "POST",
        "/api/v1/issues/2/open",
        opening,
        Some("write-only-opens"),
    ));
    status(
        &request(&write_only, "GET", "/api/v1/issues/2", "", None),
        403,
    );
    for suffix in ["/api/v1/pulls", "/api/v1/discussions"] {
        status(&request(&read_only, "GET", suffix, "", None), 403);
    }
    status(
        &request(
            &read_only,
            "POST",
            "/api/v1/outcomes",
            "",
            Some("http-agent-open-issue"),
        ),
        403,
    );

    // Even a grant containing every supported metadata operation never
    // becomes code publication, review approval, merge or administration.
    for (method, suffix, body) in [
        ("POST", "/git-receive-pack", "0000"),
        ("GET", "/info/refs?service=git-upload-pack", ""),
        ("GET", "/api/v1/source", ""),
        ("GET", "/api/v1/pulls/1/reviews", ""),
        (
            "POST",
            "/api/v1/pulls/1/reviews/approve",
            "expected_version=0",
        ),
        ("POST", "/api/v1/pulls/1/merge", "expected_version=0"),
        ("GET", "/api/v1/protection", ""),
        ("POST", "/api/v1/protection", "expected_version=0"),
        ("POST", "/api/v1/outcomes/receive", ""),
    ] {
        status(
            &request(&original, method, suffix, body, Some("closed-agent-effect")),
            403,
        );
    }
    status(
        &exchange(
            &selected,
            &original,
            "GET",
            "/another-repository/api/v1/issues",
            "",
            None,
        ),
        404,
    );
    status(
        &request("fgagent_invalid", "GET", "/api/v1/issues", "", None),
        401,
    );

    // Same tenant/repository names in a replacement incarnation cannot use
    // this grant. The legacy row above cannot repair its missing binding.
    let (mut replacement, _) = OneNode::init(scratch.config("replacement-incarnation")).unwrap();
    replacement
        .bring_into_service(HeadGeneration::FIRST)
        .unwrap();
    assert_ne!(replacement.repository_incarnation_id(), grant.incarnation);
    let foreign_config = scratch
        .config("replacement-incarnation")
        .with_expected_repository_incarnation(replacement.repository_incarnation_id());
    let mut foreign = selected.clone();
    foreign.config = foreign_config.clone();
    foreign.nodes = Arc::new(NodeLanes::new(foreign_config, 1, "foreign agent HTTP test"));
    replacement.shutdown().unwrap();
    status(
        &exchange(
            &foreign,
            &original,
            "GET",
            &format!("{route}/api/v1/issues"),
            "",
            None,
        ),
        401,
    );
    foreign.nodes.close().unwrap();

    // Keep the original server/pool alive while an operator changes canonical
    // state. Subsequent connections must observe revocation, never a cache or
    // the colliding local-file principal. A replacement authenticates the same
    // agent but recovery still returns the original write's entire witness.
    let node = reopen(config.clone());
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(original.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(1).unwrap()),
            action: AgentCredentialAction::Revoke(grant),
        },
        grant.sponsor,
        "revoke-http-original",
    );
    let rotated = crate::agent_credentials::generate_agent_credential_token();
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(rotated.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(grant),
        },
        grant.sponsor,
        "issue-http-rotated",
    );
    node.shutdown().unwrap();
    status(
        &request(&original, "GET", "/api/v1/issues/1", "", None),
        401,
    );
    status(
        &request(
            &original,
            "POST",
            "/api/v1/issues/3/open",
            opening,
            Some("revoked-no-fallback"),
        ),
        401,
    );
    status(
        &request(
            &original,
            "POST",
            "/api/v1/outcomes",
            "",
            Some("http-agent-open-issue"),
        ),
        401,
    );
    let recovered = request(
        &rotated,
        "POST",
        "/api/v1/outcomes",
        "",
        Some("http-agent-open-issue"),
    );
    assert_eq!(original_provenance(&recovered), provenance);
    status(&request(&rotated, "GET", "/api/v1/issues/1", "", None), 200);

    // Ordinary operator-owned tokens retain their previous behavior and
    // cannot obtain the agent's receipt by guessing its idempotency key.
    committed(&request(
        &normal,
        "POST",
        "/api/v1/issues/3/open",
        opening,
        Some("normal-token-open"),
    ));
    let normal_read = request(&normal, "GET", "/api/v1/issues/3", "", None);
    status(&normal_read, 200);
    assert!(
        normal_read.contains(&format!("\"opened_by\":\"{}\"", actor(4))),
        "{normal_read}"
    );
    let private = request(
        &normal,
        "POST",
        "/api/v1/outcomes",
        "",
        Some("http-agent-open-issue"),
    );
    status(&private, 200);
    assert!(
        private.contains("\"state\":\"key_not_observed\""),
        "{private}"
    );
    assert!(!private.contains(&provenance), "{private}");
    selected.nodes.close().unwrap();
}
