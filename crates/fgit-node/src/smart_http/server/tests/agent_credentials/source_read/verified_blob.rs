//! Real sponsored HTTP binary proofs, independently verified by retained pins.
use super::*;
use crate::smart_http::server::{credentials::Grant, source};
use fgit_identity::agent::{SOURCE_HISTORY_READ, SOURCE_VERIFIED_READ};
use fgit_types::{RepositoryAuthorityHeadId, RootLayoutVersion};
use fgit_verified_read::blob::{decode_verified_blob_envelope, verify_blob_against_head};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head};

struct ProofCredential {
    bearer: String,
    expired: String,
    historical: String,
    grant: AgentCredentialGrant,
}
fn issue_proof(fixture: &mut Fixture) -> ProofCredential {
    let node = reopen(fixture.config.clone());
    let bearer = format!("fgagent_{}", "e5".repeat(32));
    let expired = format!("fgagent_{}", "e6".repeat(32));
    let historical = format!("fgagent_{}", "e7".repeat(32));
    let grant = AgentCredentialGrant {
        operations: SOURCE_VERIFIED_READ,
        ..fixture.grant
    };
    for (token, selected, key) in [
        (&bearer, grant, "proof-only"),
        (
            &expired,
            AgentCredentialGrant {
                issued_at: grant.issued_at - 120,
                expires_at: grant.issued_at - 60,
                ..grant
            },
            "proof-expired",
        ),
        (
            &historical,
            AgentCredentialGrant {
                operations: SOURCE_HISTORY_READ,
                ..grant
            },
            "proof-history",
        ),
    ] {
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(token.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: AgentCredentialAction::Issue(selected),
            },
            grant.sponsor,
            key,
        );
    }
    fixture.generation = generation(&node);
    node.shutdown().unwrap();
    ProofCredential {
        bearer,
        expired,
        historical,
        grant,
    }
}
fn authority(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .basis()
        .id()
}
fn target(
    profile: &Profile,
    reference: &[u8],
    path: &[u8],
    head: RepositoryAuthorityHeadId,
) -> String {
    let id = head.as_internal_object_id();
    format!(
        "{}/api/v1/source/verified-blob?ref_hex={}&path_hex={}&expected_head=alg:{}:{}",
        std::str::from_utf8(&profile.route).unwrap(),
        hex(reference),
        hex(path),
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn raw_head(target: &str, bearer: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {bearer}\r\nUser-Agent: frankengit-agent-proof-test\r\n\r\n"
    )
}
fn exchange_proof(profile: &Profile, bearer: &str, target: &str) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    peer.write_all(raw_head(target, bearer).as_bytes()).unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let deadline =
                GitDaemonSessionDeadline::new(profile.timeout, GitDaemonSessionWorkScaling::FLAT);
            serve_connection(stream, deadline, profile)
        });
        let mut response = Vec::new();
        peer.take(128 * 1024).read_to_end(&mut response).unwrap();
        worker.join().unwrap();
        assert!(
            !response
                .windows(bearer.len())
                .any(|bytes| bytes == bearer.as_bytes())
        );
        response
    })
}
fn parts(response: &[u8]) -> (&str, &[u8]) {
    let boundary = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    (
        std::str::from_utf8(&response[..boundary + 2]).unwrap(),
        &response[boundary + 4..],
    )
}
fn binary_status(response: &[u8], expected: u16) {
    assert!(
        parts(response)
            .0
            .starts_with(&format!("HTTP/1.1 {expected} ")),
        "{}",
        String::from_utf8_lossy(response)
    );
}

#[test]
fn sponsored_http_verified_blob_returns_complete_proofs_without_broad_source_or_transport_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::with_layout(&root, format, RootLayoutVersion::RefStateMerkleV2);
        let proof = issue_proof(&mut fixture);
        let node = reopen(fixture.config.clone());
        let selected = authority(&node);
        node.shutdown().unwrap();
        for (path, expected) in [
            (b"source.rs".as_slice(), SOURCE),
            (b"binary.dat".as_slice(), BINARY),
        ] {
            let response = exchange_proof(
                &fixture.selected,
                &proof.bearer,
                &target(&fixture.selected, b"refs/heads/main", path, selected),
            );
            binary_status(&response, 200);
            let (header, body) = parts(&response);
            assert!(header.contains("Content-Type: application/vnd.frankengit.verified-blob\r\n"));
            assert!(header.contains(&format!("Content-Length: {}\r\n", body.len())));
            let envelope = decode_verified_blob_envelope(body).unwrap();
            let verified = verify_blob_against_head(
                selected,
                &RefName::try_new(b"refs/heads/main").unwrap(),
                path,
                &envelope,
            )
            .unwrap();
            assert_eq!(verified.bytes, expected);
            assert_eq!(verified.source_commit, fixture.commit);
        }
        let query = target(
            &fixture.selected,
            b"refs/heads/main",
            b"source.rs",
            selected,
        );
        for bearer in [
            &fixture.source,
            &fixture.metadata,
            &fixture.legacy,
            &proof.historical,
        ] {
            let denied = exchange_proof(&fixture.selected, bearer, &query);
            binary_status(&denied, 403);
            assert!(
                !parts(&denied)
                    .1
                    .windows(SOURCE.len())
                    .any(|bytes| bytes == SOURCE)
            );
        }
        binary_status(
            &exchange_proof(&fixture.selected, &proof.expired, &query),
            401,
        );
        binary_status(
            &exchange_proof(
                &fixture.selected,
                &proof.bearer,
                &target(&fixture.selected, b"refs/heads/main", b"missing", selected),
            ),
            404,
        );
        for (method, suffix, bytes) in [
            ("POST", "/api/v1/source/blob", "object_format=sha256"),
            ("POST", "/api/v1/source/diff", "object_format=sha256"),
            (
                "POST",
                "/api/v1/pulls/1/diff",
                "object_format=sha256&expected_version=1",
            ),
            ("GET", "/api/v1/pulls/1", ""),
            ("GET", "/info/refs?service=git-upload-pack", ""),
        ] {
            status(
                &fixture.request(&proof.bearer, method, suffix, bytes, None),
                403,
            );
        }
        let mut disabled = fixture.selected.clone();
        disabled.services = disabled.services.with(RepositoryHttpService::Source, false);
        binary_status(&exchange_proof(&disabled, &proof.bearer, &query), 403);
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        // Real canonical hidden policy is checked before a source proof is built.
        let policy = fgit_codec::HiddenRefPolicyBody {
            rules: vec![b"refs/heads/main".to_vec()],
        };
        let context = node.request_context();
        node.runtime()
            .block_on(
                fgit_admission::merge::native::protection::publish_hidden_ref_policy_async(
                    &node.authority,
                    context.authority(),
                    &node.head_key,
                    node.tenant_id,
                    Some(&policy),
                    fgit_codec::harness::tx_id(),
                ),
            )
            .unwrap();
        let current = authority(&node);
        let generation_after_policy = generation(&node);
        drop(context);
        node.shutdown().unwrap();
        // Visible sibling tag still has a valid proof; the old head refuses.
        binary_status(
            &exchange_proof(
                &fixture.selected,
                &proof.bearer,
                &target(
                    &fixture.selected,
                    b"refs/tags/release",
                    b"source.rs",
                    selected,
                ),
            ),
            409,
        );
        binary_status(
            &exchange_proof(
                &fixture.selected,
                &proof.bearer,
                &target(
                    &fixture.selected,
                    b"refs/tags/release",
                    b"source.rs",
                    current,
                ),
            ),
            200,
        );
        let hidden = exchange_proof(
            &fixture.selected,
            &proof.bearer,
            &target(&fixture.selected, b"refs/heads/main", b"source.rs", current),
        );
        let absent = exchange_proof(
            &fixture.selected,
            &proof.bearer,
            &target(
                &fixture.selected,
                b"refs/heads/absent",
                b"source.rs",
                current,
            ),
        );
        binary_status(&hidden, 404);
        assert_eq!(hidden, absent);
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), generation_after_policy);
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_http_verified_blob_retains_operation_deadline_egress_and_current_revocation() {
    let root = Scratch::new();
    let mut fixture = Fixture::with_layout(
        &root,
        GitHashAlgorithm::Sha256,
        RootLayoutVersion::RefStateMerkleV2,
    );
    let proof = issue_proof(&mut fixture);
    let node = reopen(fixture.config.clone());
    let selected_head = authority(&node);
    let query = target(
        &fixture.selected,
        b"refs/heads/main",
        b"source.rs",
        selected_head,
    );
    let raw = raw_head(&query, &proof.bearer);
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let route = source::Request::parse(&envelope).unwrap();
    assert_eq!(route.agent_operation(), Some(SOURCE_VERIFIED_READ));
    let authenticate = |output| {
        node.runtime()
            .block_on(node.authenticate_agent_request_in(
                &node.request_context(),
                proof.bearer.as_bytes(),
                &IdempotencyKey::new(b"proof-budget".to_vec()).unwrap(),
                SOURCE_VERIFIED_READ,
                sha256_digest(raw.as_bytes()),
                256 * 1024,
                output,
            ))
            .unwrap()
    };
    let mut request = authenticate(MAXIMUM as u64);
    let mut profile = fixture.selected.clone();
    profile.credentials = CredentialSource::AgentRequest {
        digest: sha256_digest(proof.bearer.as_bytes()),
        grant: Grant::agent(&request),
    };
    let (session, read) =
        source::authenticate(&route, &envelope, raw.as_bytes(), &profile).unwrap();
    assert!(
        read.is_none(),
        "proof scope cannot manufacture current source read authority"
    );
    let authentication = session.authenticated_session().unwrap().authentication();
    let witness = authentication.agent_provenance().unwrap();
    assert_eq!(witness.agent(), proof.grant.agent);
    assert_eq!(witness.sponsor(), proof.grant.sponsor);
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let execute = |request: Option<&crate::agent_credentials::AgentRequest>, maximum| {
        source::execute(
            &node,
            &route,
            &session,
            None,
            request,
            BodyFraming::Empty,
            &mut &b""[..],
            HttpLimits::default(),
            maximum,
            &deadline,
        )
    };
    let result = execute(Some(&request), MAXIMUM as u64).unwrap();
    let mut bytes = Vec::new();
    result.send(&mut bytes, HttpVersion::Http11).unwrap();
    let exact = parts(&bytes).1.len() as u64;
    assert!(execute(Some(&request), exact).is_ok());
    assert_eq!(
        execute(Some(&request), exact - 1).err().unwrap().status,
        Status::TooLarge
    );
    assert_eq!(
        execute(None, MAXIMUM as u64).err().unwrap().status,
        Status::Forbidden
    );
    // A separately authenticated request with insufficient egress is refused
    // as a budget failure, not incorrectly as expiry.
    let short = authenticate(1);
    let short_session = short.authenticated_session();
    let error = source::execute(
        &node,
        &route,
        &short_session,
        None,
        Some(&short),
        BodyFraming::Empty,
        &mut &b""[..],
        HttpLimits::default(),
        MAXIMUM as u64,
        &deadline,
    )
    .err()
    .unwrap();
    assert_eq!(error.status, Status::TooLarge);
    request.constrain_deadline(std::time::Instant::now() - Duration::from_secs(1));
    assert_eq!(
        execute(Some(&request), MAXIMUM as u64)
            .err()
            .unwrap()
            .status,
        Status::Timeout
    );
    assert_eq!(authority(&node), selected_head);
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(proof.bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(proof.grant),
        },
        proof.grant.sponsor,
        "revoke-proof-reader",
    );
    node.shutdown().unwrap();
    binary_status(
        &exchange_proof(&fixture.selected, &proof.bearer, &query),
        401,
    );
    fixture.selected.nodes.close().unwrap();
}
