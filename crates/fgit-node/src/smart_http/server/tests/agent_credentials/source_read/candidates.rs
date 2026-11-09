//! Real sponsored HTTP preparation and inspection, with no source publication.
use super::*;
use crate::smart_http::server::source;
use fgit_identity::agent::SOURCE_CANDIDATES;
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head};

const RESPONSE_LIMIT: usize = 1024 * 1024;
const PATCH: &[u8] = b"diff --git a/created.txt b/created.txt\nnew file mode 100644\n--- /dev/null\n+++ b/created.txt\n@@ -0,0 +1 @@\n+candidate-only work\n";

struct CandidateCredential {
    bearer: String,
    legacy: String,
    expired: String,
    grant: AgentCredentialGrant,
}

fn issue_candidates(fixture: &mut Fixture) -> CandidateCredential {
    let node = reopen(fixture.config.clone());
    let bearer = format!("fgagent_{}", "f1".repeat(32));
    let legacy = format!("fgagent_{}", "f2".repeat(32));
    let expired = format!("fgagent_{}", "f3".repeat(32));
    let grant = AgentCredentialGrant {
        operations: SOURCE_CANDIDATES,
        ..fixture.grant
    };
    for (token, issued, retry) in [
        (bearer.as_str(), grant, "issue-candidate-only"),
        (
            legacy.as_str(),
            AgentCredentialGrant {
                operations: 0x01ff,
                ..grant
            },
            "issue-pre-candidate-mask",
        ),
        (
            expired.as_str(),
            AgentCredentialGrant {
                issued_at: grant.issued_at - 120,
                expires_at: grant.issued_at - 60,
                ..grant
            },
            "issue-expired-candidate",
        ),
    ] {
        credential(
            &node,
            &AgentCredentialCommand {
                id: agent_credential_id(token.as_bytes()).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: AgentCredentialAction::Issue(issued),
            },
            grant.sponsor,
            retry,
        );
    }
    fixture.generation = generation(&node);
    fixture.selected.maximum_response_bytes = RESPONSE_LIMIT as u64;
    // Canonical sponsored authentication must still win over a colliding
    // broadly authorized ordinary token after revocation.
    fixture.selected.credentials = CredentialSource::Static {
        digest: sha256_digest(bearer.as_bytes()),
        principal: actor(4),
    };
    node.shutdown().unwrap();
    CandidateCredential {
        bearer,
        legacy,
        expired,
        grant,
    }
}

fn preparation(base: GitOid) -> String {
    format!(
        "object_format={}&ref=refs/heads/main&expected_commit={base}&author=Agent+%3Cagent%40example.invalid%3E&committer=Agent+%3Cagent%40example.invalid%3E&timestamp=123&message=Exact+candidate&patch_profile=exact-tree-v1",
        base.algorithm().as_str()
    )
}

fn inspection(base: GitOid, candidate: GitOid) -> String {
    format!(
        "object_format={}&ref=refs/heads/main&expected_commit={base}&candidate_commit={candidate}",
        base.algorithm().as_str()
    )
}

fn upload(action: &str, command: &str, payload: &[u8]) -> Vec<u8> {
    let name = if action == "prepare" {
        "patch"
    } else {
        "bundle"
    };
    let mut bytes = format!("--source\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{command}\r\n--source\r\nContent-Disposition: form-data; name=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(b"\r\n--source--\r\n");
    bytes
}

fn raw_head(profile: &Profile, token: &str, action: &str, length: usize) -> String {
    format!(
        "POST {}/api/v1/source/{action} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {token}\r\nContent-Type: multipart/form-data; boundary=source\r\nContent-Length: {length}\r\n\r\n",
        std::str::from_utf8(&profile.route).unwrap()
    )
}

fn exchange_upload(
    profile: &Profile,
    token: &str,
    action: &str,
    command: &str,
    payload: &[u8],
) -> Vec<u8> {
    let bytes = upload(action, command, payload);
    let mut wire = raw_head(profile, token, action, bytes.len()).into_bytes();
    wire.extend_from_slice(&bytes);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    // Buffer the whole small request before acceptance, matching the existing
    // native HTTP fixture while retaining binary input and output bytes.
    peer.write_all(&wire).unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(
                stream,
                GitDaemonSessionDeadline::new(profile.timeout, GitDaemonSessionWorkScaling::FLAT),
                profile,
            )
        });
        let mut response = Vec::new();
        let read = peer
            .take((RESPONSE_LIMIT + 16 * 1024) as u64)
            .read_to_end(&mut response);
        // An intake refusal may close with an unread upload. A reset is only
        // acceptable after a complete framed response, checked below by every
        // caller; it must never turn a truncated response into success.
        if let Err(error) = read {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            split_response(&response);
        }
        worker.join().unwrap();
        assert!(
            !response
                .windows(token.len())
                .any(|bytes| bytes == token.as_bytes())
        );
        response
    })
}

fn split_response(response: &[u8]) -> (&str, &[u8]) {
    let end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let head = std::str::from_utf8(&response[..end]).unwrap();
    let body = &response[end + 4..];
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(length, body.len());
    (head, body)
}

fn binary_status(response: &[u8], expected: u16) {
    let (head, body) = split_response(response);
    assert!(
        head.starts_with(&format!("HTTP/1.1 {expected} ")),
        "{head}\n{}",
        String::from_utf8_lossy(body)
    );
}

fn value(bytes: &[u8]) -> Value {
    json::parse_with(
        bytes,
        json::Limits {
            input: RESPONSE_LIMIT,
            depth: 16,
            nodes: 65536,
            items: 16384,
            string: RESPONSE_LIMIT,
        },
    )
    .unwrap()
}

fn extract(response: &[u8], format: GitHashAlgorithm) -> (GitOid, Vec<u8>, Value) {
    binary_status(response, 200);
    let (head, bytes) = split_response(response);
    let boundary = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Type: multipart/mixed; boundary="))
        .unwrap();
    let bytes = bytes
        .strip_prefix(format!("--{boundary}\r\n").as_bytes())
        .unwrap();
    let start = bytes.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let bytes = &bytes[start..];
    let delimiter = format!("\r\n--{boundary}\r\n");
    let end = bytes
        .windows(delimiter.len())
        .position(|x| x == delimiter.as_bytes())
        .unwrap();
    let metadata = value(&bytes[..end]);
    let bytes = &bytes[end + delimiter.len()..];
    let start = bytes.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let bundle = bytes[start..]
        .strip_suffix(format!("\r\n--{boundary}--\r\n").as_bytes())
        .unwrap()
        .to_vec();
    assert_eq!(
        field(field(&metadata, "bundle"), "sha256").text(),
        Some(hex(&sha256_digest(&bundle)).as_str())
    );
    assert_eq!(
        field(field(&metadata, "bundle"), "bytes").unsigned(),
        Some(bundle.len() as u64)
    );
    for name in [
        "objects_staged",
        "transaction_created",
        "published",
        "publication_authorized",
    ] {
        assert_eq!(field(&metadata, name), &Value::Bool(false));
    }
    let candidate =
        GitOid::from_hex(format, field(&metadata, "candidate_commit").text().unwrap()).unwrap();
    (candidate, bundle, metadata)
}

#[test]
fn sponsored_candidates_prepare_inspect_and_preserve_authority_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut fixture = Fixture::new(&root, format);
        let credential = issue_candidates(&mut fixture);
        let form = preparation(fixture.commit);
        let prepared = exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            PATCH,
        );
        let (candidate, bundle, metadata) = extract(&prepared, format);
        assert_ne!(candidate, fixture.commit);
        assert_eq!(
            field(&metadata, "source_commit").text(),
            Some(fixture.commit.to_string().as_str())
        );
        // The native candidate is deterministic across independently verified
        // requests; no mutable candidate database supplies this repeat result.
        assert_eq!(
            exchange_upload(
                &fixture.selected,
                &credential.bearer,
                "prepare",
                &form,
                PATCH
            ),
            prepared
        );
        let inspected = exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "inspect",
            &inspection(fixture.commit, candidate),
            &bundle,
        );
        binary_status(&inspected, 200);
        let inspected_value = value(split_response(&inspected).1);
        assert_eq!(
            field(&inspected_value, "type").text(),
            Some("source_inspection")
        );
        assert_eq!(
            field(&inspected_value, "publication_authorized"),
            &Value::Bool(false)
        );
        assert!(
            String::from_utf8_lossy(split_response(&inspected).1)
                .contains(&hex(b"candidate-only work\n"))
        );
        for action in ["prepare", "inspect"] {
            let command = if action == "prepare" {
                form.clone()
            } else {
                inspection(fixture.commit, candidate)
            };
            let payload = if action == "prepare" {
                PATCH
            } else {
                bundle.as_slice()
            };
            for (token, expected) in [
                (&fixture.source, 403),
                (&fixture.metadata, 403),
                (&credential.legacy, 403),
                (&credential.expired, 401),
            ] {
                binary_status(
                    &exchange_upload(&fixture.selected, token, action, &command, payload),
                    expected,
                );
            }
        }
        binary_status(
            &exchange_upload(
                &fixture.selected,
                &credential.bearer,
                "apply",
                &inspection(fixture.commit, candidate),
                &bundle,
            ),
            403,
        );
        for action in ["commit", "tree", "log", "agent-context", "bundle/export"] {
            status(
                &fixture.post(
                    &credential.bearer,
                    action,
                    &format!("object_format={}&ref=refs/heads/main", format.as_str()),
                ),
                403,
            );
        }
        for (method, target, body) in [
            ("GET", "/info/refs?service=git-upload-pack", ""),
            ("POST", "/git-receive-pack", "0000"),
            ("GET", "/api/v1/pulls", ""),
            ("POST", "/api/v1/pulls/1/diff", "object_format=sha256"),
        ] {
            status(
                &fixture.request(&credential.bearer, method, target, body, None),
                403,
            );
        }
        let mut disabled = fixture.selected.clone();
        disabled.services = disabled.services.with(RepositoryHttpService::Source, false);
        binary_status(
            &exchange_upload(&disabled, &credential.bearer, "prepare", &form, PATCH),
            403,
        );
        fixture.selected.nodes.close().unwrap();
        let node = reopen(fixture.config.clone());
        assert_eq!(generation(&node), fixture.generation);
        node.shutdown().unwrap();
    }
}

#[test]
fn sponsored_candidate_uploads_exceed_metadata_forms_but_retain_intake_and_output_limits() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let credential = issue_candidates(&mut fixture);
    let form = preparation(fixture.commit);
    let patch = format!(
        "diff --git a/large.txt b/large.txt\nnew file mode 100644\n--- /dev/null\n+++ b/large.txt\n@@ -0,0 +1 @@\n+{}\n",
        "x".repeat(70 * 1024)
    );
    assert!(patch.len() > crate::smart_http::server::issues::MAX_FORM_BYTES);
    extract(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            patch.as_bytes(),
        ),
        GitHashAlgorithm::Sha256,
    );
    let mut limited = fixture.selected.clone();
    limited.http.max_body_bytes = 64 * 1024;
    binary_status(
        &exchange_upload(
            &limited,
            &credential.bearer,
            "prepare",
            &form,
            patch.as_bytes(),
        ),
        413,
    );
    limited = fixture.selected.clone();
    limited.maximum_response_bytes = 512;
    binary_status(
        &exchange_upload(&limited, &credential.bearer, "prepare", &form, PATCH),
        413,
    );
    let stale = form.replace(&fixture.commit.to_string(), &"01".repeat(32));
    binary_status(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &stale,
            PATCH,
        ),
        409,
    );
    let absent = form.replace("refs/heads/main", "refs/heads/missing");
    binary_status(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &absent,
            PATCH,
        ),
        404,
    );
    let traversal = std::str::from_utf8(PATCH)
        .unwrap()
        .replace("created.txt", "../escape");
    binary_status(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            traversal.as_bytes(),
        ),
        400,
    );
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), fixture.generation);
    node.shutdown().unwrap();
}

#[test]
fn candidate_execution_requires_the_original_reservation_and_cannot_refresh_expiry() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let credential = issue_candidates(&mut fixture);
    let node = reopen(fixture.config.clone());
    let bytes = upload("prepare", &preparation(fixture.commit), PATCH);
    let raw = raw_head(
        &fixture.selected,
        &credential.bearer,
        "prepare",
        bytes.len(),
    );
    let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let selected = source::Request::parse(&envelope).unwrap();
    let mut request = node
        .runtime()
        .block_on(node.authenticate_agent_request_in(
            &node.request_context(),
            credential.bearer.as_bytes(),
            &IdempotencyKey::new(b"candidate-http-reservation".to_vec()).unwrap(),
            SOURCE_CANDIDATES,
            sha256_digest(raw.as_bytes()),
            256 * 1024,
            RESPONSE_LIMIT as u64,
        ))
        .unwrap();
    let mut granted = fixture.selected.clone();
    granted.credentials = CredentialSource::AgentRequest {
        digest: sha256_digest(credential.bearer.as_bytes()),
        grant: crate::smart_http::server::credentials::Grant::agent(&request),
    };
    let (_, current_source) =
        source::authenticate(&selected, &envelope, raw.as_bytes(), &granted).unwrap();
    assert!(current_source.is_none());
    let session = request.authenticated_session();
    let execute = |session: &LoopbackReceiveSession,
                   agent: Option<&crate::agent_credentials::AgentRequest>| {
        source::execute(
            &node,
            &selected,
            session,
            None,
            agent,
            BodyFraming::ContentLength(bytes.len() as u64),
            &mut bytes.as_slice(),
            HttpLimits::default(),
            RESPONSE_LIMIT as u64,
        )
    };
    assert_eq!(
        execute(&session, None).err().unwrap().status,
        Status::Forbidden
    );
    let result = execute(&session, Some(&request)).unwrap();
    let mut response = Vec::new();
    result.send(&mut response, HttpVersion::Http11).unwrap();
    extract(&response, GitHashAlgorithm::Sha256);
    request.constrain_deadline(std::time::Instant::now());
    assert!(execute(&request.authenticated_session(), Some(&request)).is_err());
    // An old session also cannot be paired with a newly attenuated reservation.
    assert!(execute(&session, Some(&request)).is_err());
    assert_eq!(generation(&node), fixture.generation);
    node.shutdown().unwrap();
    fixture.selected.nodes.close().unwrap();
}

#[test]
fn sponsored_candidate_revocation_survives_reopen_without_static_token_fallback() {
    let root = Scratch::new();
    let mut fixture = Fixture::new(&root, GitHashAlgorithm::Sha256);
    let credential = issue_candidates(&mut fixture);
    let form = preparation(fixture.commit);
    let (candidate, bundle, _) = extract(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            PATCH,
        ),
        GitHashAlgorithm::Sha256,
    );
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    super::super::credential(
        &node,
        &AgentCredentialCommand {
            id: agent_credential_id(credential.bearer.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: AgentCredentialAction::Revoke(credential.grant),
        },
        credential.grant.sponsor,
        "revoke-candidate",
    );
    let after = generation(&node);
    node.shutdown().unwrap();
    binary_status(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "prepare",
            &form,
            PATCH,
        ),
        401,
    );
    binary_status(
        &exchange_upload(
            &fixture.selected,
            &credential.bearer,
            "inspect",
            &inspection(fixture.commit, candidate),
            &bundle,
        ),
        401,
    );
    fixture.selected.nodes.close().unwrap();
    let node = reopen(fixture.config.clone());
    assert_eq!(generation(&node), after);
    node.shutdown().unwrap();
}
