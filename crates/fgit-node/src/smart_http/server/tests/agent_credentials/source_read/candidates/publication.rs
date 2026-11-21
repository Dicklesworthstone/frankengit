//! Real scoped Apply requests retain their live sponsor proof, byte reservation,
//! exact retry identity and canonical scope through ordinary native publication.
use super::*;
use fgit_identity::agent::{OUTCOMES_READ, SOURCE_PUBLISH, SourcePublicationScope};

struct Publisher {
    bearer: String,
    grant: AgentCredentialGrant,
    scope: SourcePublicationScope,
}

fn issue_publisher(
    fixture: &mut Fixture,
    byte: &str,
    reference: &[u8],
    paths: &[&[u8]],
) -> Publisher {
    let node = reopen(fixture.config.clone());
    let bearer = format!("fgagent_{}", byte.repeat(32));
    let scope = SourcePublicationScope::new(
        &format!("exact:{}", hex(reference)),
        paths.iter().map(|path| path.to_vec()).collect(),
    )
    .unwrap();
    let grant = AgentCredentialGrant {
        operations: SOURCE_PUBLISH | OUTCOMES_READ,
        ..fixture.grant
    };
    credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(grant, Some(scope.clone())),
        },
        grant.sponsor,
        &format!("issue-http-publisher-{byte}"),
    );
    fixture.generation = generation(&node);
    fixture.selected.maximum_response_bytes = RESPONSE_LIMIT as u64;
    node.shutdown().unwrap();
    Publisher {
        bearer,
        grant,
        scope,
    }
}

fn tip(node: &OneNode) -> GitOid {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .snapshot()
        .refs[&RefName::try_new(b"refs/heads/main").unwrap()]
}

fn published(response: &[u8]) -> Value {
    binary_status(response, 200);
    let receipt = value(split_response(response).1);
    assert_eq!(field(&receipt, "type").text(), Some("source_publication"));
    assert_eq!(field(&receipt, "outcome").text(), Some("committed"));
    assert_eq!(field(&receipt, "refusal_code"), &Value::Null);
    receipt
}

#[test]
fn scoped_http_publication_recovers_original_sponsor_after_rotation_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let reader = issue_candidates(&mut fixture);
        let publisher = issue_publisher(&mut fixture, "f4", b"refs/heads/main", &[b"created.txt"]);
        let (candidate, bundle, _) = extract(
            &exchange_upload(
                &fixture.selected,
                &reader.bearer,
                "prepare",
                &preparation(fixture.commit),
                PATCH,
            ),
            format,
        );
        let form = inspection(fixture.commit, candidate);
        let key = "scoped-http-publication";
        binary_status(
            &exchange_upload(
                &fixture.selected,
                &publisher.bearer,
                "apply",
                &form,
                &bundle,
            ),
            400,
        );
        for service in [
            RepositoryHttpService::Source,
            RepositoryHttpService::Receive,
        ] {
            let mut limited = fixture.selected.clone();
            limited.services = limited.services.with(service, false);
            binary_status(
                &exchange_upload_with_key(
                    &limited,
                    &publisher.bearer,
                    "apply",
                    &form,
                    &bundle,
                    Some(key),
                ),
                403,
            );
        }
        // No broader source or Git operation follows from this publisher.
        for action in [
            "prepare",
            "inspect",
            "initial/apply",
            "rebase/apply",
            "bundle/import",
        ] {
            let command = if action == "prepare" {
                preparation(fixture.commit)
            } else {
                form.clone()
            };
            let payload = if action == "prepare" { PATCH } else { &bundle };
            binary_status(
                &exchange_upload_with_key(
                    &fixture.selected,
                    &publisher.bearer,
                    action,
                    &command,
                    payload,
                    (action != "prepare" && action != "inspect").then_some(key),
                ),
                403,
            );
        }
        status(
            &fixture.request(
                &publisher.bearer,
                "POST",
                "/git-receive-pack",
                "0000",
                Some(key),
            ),
            403,
        );
        let first = exchange_upload_with_key(
            &fixture.selected,
            &publisher.bearer,
            "apply",
            &form,
            &bundle,
            Some(key),
        );
        let receipt = published(&first);
        assert_eq!(
            field(&receipt, "principal_id").text(),
            Some(publisher.grant.agent.to_string().as_str())
        );
        assert_eq!(
            field(&receipt, "candidate_commit").text(),
            Some(candidate.to_string().as_str())
        );
        let outcome = fixture.request(&publisher.bearer, "POST", "/api/v1/outcomes", "", Some(key));
        let original = original_provenance(&outcome).to_owned();
        for expected in [
            format!("\"agent\":\"{}\"", publisher.grant.agent),
            format!("\"sponsor\":\"{}\"", publisher.grant.sponsor),
            format!(
                "\"credential_id\":\"{}\"",
                agent_credential_id(publisher.bearer.as_bytes()).unwrap()
            ),
        ] {
            assert!(original.contains(&expected), "{original}");
        }

        // Canonical authentication must not fall back to a colliding ordinary
        // receive grant after revocation, including after the node is reopened.
        fixture.selected.credentials = CredentialSource::Static {
            digest: sha256_digest(publisher.bearer.as_bytes()),
            principal: actor(4),
        };
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(tip(&node), candidate);
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(publisher.bearer.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: AgentCredentialAction::revocation(publisher.grant, Some(publisher.scope)),
            },
            publisher.grant.sponsor,
            "revoke-http-publisher",
        );
        node.shutdown().unwrap();
        let replacement = issue_publisher(&mut fixture, "f5", b"refs/heads/main", &[b"unrelated"]);
        binary_status(
            &exchange_upload_with_key(
                &fixture.selected,
                &publisher.bearer,
                "apply",
                &form,
                &bundle,
                Some(key),
            ),
            401,
        );
        // Terminal recovery confirms the original sealed command and witness.
        // It neither rechecks a replacement encoding nor upgrades today's scope.
        let mut damaged = bundle;
        *damaged.last_mut().unwrap() ^= 1;
        let recovered = exchange_upload_with_key(
            &fixture.selected,
            &replacement.bearer,
            "apply",
            &form,
            &damaged,
            Some(key),
        );
        assert_eq!(published(&recovered), receipt);
        let outcome = fixture.request(
            &replacement.bearer,
            "POST",
            "/api/v1/outcomes",
            "",
            Some(key),
        );
        assert_eq!(original_provenance(&outcome), original);
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(tip(&node), candidate);
        assert_eq!(generation(&node), fixture.generation);
        node.shutdown().unwrap();
    }
}

#[test]
fn scoped_http_publication_checks_every_native_path_and_exact_branch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let reader = issue_candidates(&mut fixture);
        let publisher = issue_publisher(&mut fixture, "f6", b"refs/heads/main", &[b"created.txt"]);
        let other_ref = issue_publisher(&mut fixture, "f7", b"refs/heads/other", &[b"created.txt"]);
        let outside = std::str::from_utf8(PATCH)
            .unwrap()
            .replace("created.txt", "created.txt-other");
        let mixed = [PATCH, outside.as_bytes()].concat();
        for (patch, token, key) in [
            (outside.as_bytes(), &publisher.bearer, "scope-path-boundary"),
            (
                mixed.as_slice(),
                &publisher.bearer,
                "scope-all-native-paths",
            ),
            (PATCH, &other_ref.bearer, "scope-exact-branch"),
        ] {
            let (candidate, bundle, _) = extract(
                &exchange_upload(
                    &fixture.selected,
                    &reader.bearer,
                    "prepare",
                    &preparation(fixture.commit),
                    patch,
                ),
                format,
            );
            let response = exchange_upload_with_key(
                &fixture.selected,
                token,
                "apply",
                &inspection(fixture.commit, candidate),
                &bundle,
                Some(key),
            );
            binary_status(&response, 409);
            let refusal = value(split_response(&response).1);
            assert_eq!(field(&refusal, "outcome").text(), Some("refused"));
            assert_eq!(
                field(&refusal, "refusal_code").text(),
                Some("CapabilityScopeViolation")
            );
            fixture.selected.nodes.close().unwrap();
            let node = reopen(fixture.config.clone());
            assert_eq!(tip(&node), fixture.commit);
            assert!(node.read_git_object(candidate).is_err());
            node.shutdown().unwrap();
        }
        fixture.selected.nodes.close().unwrap();
    }
}

#[test]
fn scoped_http_publication_requires_original_key_proof_body_budget_and_deadline() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let reader = issue_candidates(&mut fixture);
    let publisher = issue_publisher(&mut fixture, "f8", b"refs/heads/main", &[b"created.txt"]);
    let (candidate, bundle, _) = extract(
        &exchange_upload(
            &fixture.selected,
            &reader.bearer,
            "prepare",
            &preparation(fixture.commit),
            PATCH,
        ),
        GitHashAlgorithm::Sha256,
    );
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    let bytes = upload("apply", &inspection(fixture.commit, candidate), &bundle);
    let key = IdempotencyKey::new(b"publication-original-request".to_vec()).unwrap();
    let raw = raw_head_with_key(
        &fixture.selected,
        &publisher.bearer,
        "apply",
        bytes.len(),
        Some("publication-original-request"),
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let selected = source::Request::parse(&envelope).unwrap();
    let authenticate = |token: &str, operation: u16, input_limit: u64| {
        node.runtime()
            .block_on(node.authenticate_agent_request_in(
                &node.request_context(),
                token.as_bytes(),
                &key,
                operation,
                sha256_digest(raw.as_bytes()),
                input_limit,
                RESPONSE_LIMIT as u64,
            ))
            .unwrap()
    };
    let mut request = authenticate(&publisher.bearer, SOURCE_PUBLISH, 256 * 1024);
    let mut granted = fixture.selected.clone();
    granted.credentials = CredentialSource::AgentRequest {
        digest: sha256_digest(publisher.bearer.as_bytes()),
        grant: crate::smart_http::server::credentials::Grant::agent(&request),
    };
    let (session, current_source) =
        source::authenticate(&selected, &envelope, raw.as_bytes(), &granted).unwrap();
    assert!(current_source.is_none());
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let execute = |session: &LoopbackReceiveSession,
                   request: Option<&crate::agent_credentials::AgentRequest>,
                   deadline: &GitDaemonSessionDeadline| {
        source::execute(
            &node,
            &selected,
            session,
            None,
            request,
            BodyFraming::ContentLength(bytes.len() as u64),
            &mut bytes.as_slice(),
            HttpLimits::default(),
            RESPONSE_LIMIT as u64,
            deadline,
        )
    };
    assert_eq!(
        execute(&session, None, &deadline).err().unwrap().status,
        Status::Forbidden
    );
    let changed_key =
        request.session(IdempotencyKey::new(b"substituted-publication-key".to_vec()).unwrap());
    assert_eq!(
        execute(&changed_key, Some(&request), &deadline)
            .err()
            .unwrap()
            .status,
        Status::Forbidden
    );
    let candidate_request = authenticate(&reader.bearer, SOURCE_CANDIDATES, 256 * 1024);
    assert_eq!(
        execute(
            &candidate_request.authenticated_session(),
            Some(&candidate_request),
            &deadline,
        )
        .err()
        .unwrap()
        .status,
        Status::Forbidden
    );
    // The bundle alone fits; the complete MIME command and body do not.
    let bounded = authenticate(&publisher.bearer, SOURCE_PUBLISH, bundle.len() as u64);
    assert!(bytes.len() > bundle.len());
    assert_eq!(
        execute(&bounded.authenticated_session(), Some(&bounded), &deadline)
            .err()
            .unwrap()
            .status,
        Status::TooLarge
    );
    let mut expired_ingress = deadline.clone();
    expired_ingress.started = std::time::Instant::now()
        .checked_sub(expired_ingress.budget() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        execute(&session, Some(&request), &expired_ingress)
            .err()
            .unwrap()
            .status,
        Status::Timeout
    );
    request.constrain_deadline(std::time::Instant::now());
    assert_eq!(
        execute(&request.authenticated_session(), Some(&request), &deadline)
            .err()
            .unwrap()
            .status,
        Status::Forbidden
    );
    // A stale session cannot be paired with an attenuated replacement proof.
    assert!(execute(&session, Some(&request), &deadline).is_err());
    assert_eq!(generation(&node), fixture.generation);
    assert_eq!(tip(&node), fixture.commit);
    assert!(node.read_git_object(candidate).is_err());
    node.shutdown().unwrap();
}

#[test]
fn scoped_http_publication_reserves_real_bundle_bytes_beyond_metadata_forms() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let reader = issue_candidates(&mut fixture);
    let publisher = issue_publisher(&mut fixture, "f9", b"refs/heads/main", &[b"large.txt"]);
    // Deterministic high-entropy source keeps the actual compressed bundle
    // larger than the metadata-only form ceiling, not just the incoming patch.
    let mut patch = String::from(
        "diff --git a/large.txt b/large.txt\nnew file mode 100644\n--- /dev/null\n+++ b/large.txt\n@@ -0,0 +2048 @@\n",
    );
    let mut random = 0x6a09_e667_f3bc_c909_u64;
    for _ in 0..2048 {
        patch.push('+');
        for _ in 0..100 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            patch.push(char::from(b'!' + ((random >> 32) % 90) as u8));
        }
        patch.push('\n');
    }
    let (candidate, bundle, _) = extract(
        &exchange_upload(
            &fixture.selected,
            &reader.bearer,
            "prepare",
            &preparation(fixture.commit),
            patch.as_bytes(),
        ),
        GitHashAlgorithm::Sha256,
    );
    assert!(bundle.len() > crate::smart_http::server::issues::MAX_FORM_BYTES);
    let form = inspection(fixture.commit, candidate);
    let mut limited = fixture.selected.clone();
    limited.http.max_body_bytes = crate::smart_http::server::issues::MAX_FORM_BYTES as u64;
    binary_status(
        &exchange_upload_with_key(
            &limited,
            &publisher.bearer,
            "apply",
            &form,
            &bundle,
            Some("large-scoped-publication"),
        ),
        413,
    );
    published(&exchange_upload_with_key(
        &fixture.selected,
        &publisher.bearer,
        "apply",
        &form,
        &bundle,
        Some("large-scoped-publication"),
    ));
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(tip(&node), candidate);
    node.shutdown().unwrap();
}
