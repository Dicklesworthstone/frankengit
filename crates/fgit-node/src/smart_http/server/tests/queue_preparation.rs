use super::*;
use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Credentials(PathBuf);
impl Credentials {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-http-queue-preparation-grants-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn preparation_head(operation: &str, token: char, extra: &str) -> Vec<u8> {
    format!(
        "POST /repo.git/api/v1/queues/1/{operation} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1024\r\nExpect: 100-continue\r\nAuthorization: Bearer {}\r\n{extra}\r\n",
        token.to_string().repeat(64),
    )
    .into_bytes()
}

fn authenticate_preparation(
    profile: &Profile,
    bytes: &[u8],
) -> Result<LoopbackReceiveSession, issues::ApiError> {
    let envelope = fgit_wire::smart_http::head::parse(bytes, profile.http)
        .unwrap()
        .unwrap();
    let request = queues::Request::parse(&envelope)?;
    assert!(!request.is_mutation() && request.accepts_body());
    queues::authenticate(&request, &envelope, bytes, profile)
}

#[test]
fn queue_preparation_requires_both_deployment_switches_and_all_three_token_reads() {
    for operation in ["prepare", "prepare-prefix"] {
        exercise_preparation_grants(operation);
    }
}

fn exercise_preparation_grants(operation: &str) {
    let credentials = Credentials::new();
    let binding = Binding {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: fgit_types::RepositoryIncarnationId::from_bytes([4; 16]),
    };
    let principal = PrincipalId::from_bytes([3; 16]);
    let mut table = format!(
        "frankengit-http-credentials-v2 {} {} {}\n",
        binding.tenant, binding.repository, binding.incarnation,
    );
    for (token, scopes) in [
        ('0', "read,pulls-read,queues-read"),
        ('1', "pulls-read,queues-read"),
        ('2', "read,queues-read"),
        ('3', "read,pulls-read"),
        ('4', "read"),
        ('5', "pulls-read"),
        ('6', "queues-read"),
        (
            '7',
            "receive,pulls-write,reviews-write,merges-write,queues-write,queues-land",
        ),
    ] {
        let digest: String = sha256_digest(token.to_string().repeat(64).as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        // All rows deliberately share a principal. Their grants cannot union,
        // and even the successful reader has no reference-write ceiling.
        table.push_str(&format!("{digest} {principal} {scopes} none\n"));
    }
    let path = credentials.0.join("tokens");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(table.as_bytes()).unwrap();
    drop(file);
    let mut enabled = profile();
    enabled.config = enabled.config.clone().with_http_queue_management();
    enabled.services = RepositoryHttpServices::NONE.with(RepositoryHttpService::Pulls, true);
    enabled.credentials = CredentialSource::File { path, binding };

    let session =
        authenticate_preparation(&enabled, &preparation_head(operation, '0', "")).unwrap();
    let authenticated = session.authenticated_session().unwrap();
    assert_eq!(authenticated.principal_id(), principal);
    assert!(!authenticated.permits_ref_write_bytes(b"refs/heads/main"));
    assert_eq!(
        authenticated.authentication(),
        fgit_admission::evidence::AdmissionAuthentication::HttpToken,
    );
    for token in ['1', '2', '3', '4', '5', '6', '7'] {
        let error = authenticate_preparation(&enabled, &preparation_head(operation, token, ""))
            .unwrap_err();
        assert_eq!(error.status, Status::Forbidden, "token {token}");
        assert!(!error.outcome_unknown);
    }
    for (allow_pulls, allow_queues) in [(false, true), (true, false)] {
        let mut selected = enabled.clone();
        selected.services = selected
            .services
            .with(RepositoryHttpService::Pulls, allow_pulls);
        if !allow_queues {
            selected.config = profile().config;
        }
        let error =
            authenticate_preparation(&selected, &preparation_head(operation, '0', "")).unwrap_err();
        assert_eq!(error.status, Status::Forbidden);
        assert!(!error.outcome_unknown);
    }
    let key = authenticate_preparation(
        &enabled,
        &preparation_head(operation, '0', "Idempotency-Key: not-a-mutation\r\n"),
    )
    .unwrap_err();
    assert_eq!(key.code, "idempotency_key_not_allowed");
    assert!(!key.outcome_unknown);
    assert_eq!(
        authenticate_preparation(&enabled, &preparation_head(operation, 'f', ""))
            .unwrap_err()
            .status,
        Status::Unauthorized,
    );
}
