use super::*;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fgit_crypto::sha256_digest;
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_wire::smart_http::{HttpLimits, head};

use super::super::credentials::Binding;
use super::super::{RepositoryHttpService, RepositoryHttpServices, serve_connection_with_routes};
use crate::node_lanes::NodeLanes;
use crate::{
    GitDaemonSessionTimeout, GitDaemonSessionWorkScaling, NodeConfig, PushQuota, WriterGate,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-http-discovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn credentials(&self, name: &str, binding: Binding, grants: &[(&str, &str)]) -> PathBuf {
        let path = self.0.join(name);
        private_write(&path, &table(binding, grants));
        path
    }

    fn replace(&self, path: &Path, contents: &str) {
        let replacement = self.0.join("replacement");
        private_write(&replacement, contents);
        fs::rename(replacement, path).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding(tenant: u8, incarnation: u8) -> Binding {
    Binding {
        tenant: TenantId::from_bytes([tenant; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([incarnation; 16]),
    }
}

fn table(binding: Binding, grants: &[(&str, &str)]) -> String {
    let mut contents = format!(
        "frankengit-http-credentials-v1 {} {} {}\n",
        binding.tenant, binding.repository, binding.incarnation,
    );
    for (token, scopes) in grants {
        let digest: String = sha256_digest(token.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        contents.push_str(&format!(
            "{digest} {} {scopes}\n",
            PrincipalId::from_bytes([4; 16])
        ));
    }
    contents
}

fn private_write(path: &Path, contents: &str) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
}

fn profile(path: &str, credentials: PathBuf, binding: Binding, source: bool) -> Profile {
    // No repository is created: this endpoint must never open a node just to
    // discover an already configured route, or create canonical authority.
    let config = NodeConfig::new(
        credentials.with_extension("no-node"),
        binding.tenant,
        binding.repository,
    )
    .with_expected_repository_incarnation(binding.incarnation);
    Profile {
        nodes: Arc::new(NodeLanes::new(
            config.clone(),
            0,
            "repository discovery test",
        )),
        config,
        route: path.as_bytes().to_vec(),
        credentials: CredentialSource::File {
            path: credentials,
            binding,
        },
        services: RepositoryHttpServices::NONE.with(RepositoryHttpService::Source, source),
        #[cfg(unix)]
        lfs: None,
        http: HttpLimits::default(),
        maximum_response_bytes: MAX_RESPONSE_BYTES as u64,
        timeout: GitDaemonSessionTimeout::DEFAULT,
        quota: Arc::new(PushQuota::default()),
        outcome_quota: Arc::new(PushQuota::default()),
        source_quota: Arc::new(PushQuota::default()),
        writers: Arc::new(WriterGate::new(1)),
    }
}

fn routed(profiles: Vec<Profile>) -> Profiles {
    Profiles::Routed {
        routes: profiles
            .into_iter()
            .map(|profile| (String::from_utf8(profile.route.clone()).unwrap(), profile))
            .collect(),
        ingress: HttpLimits::default(),
    }
}

fn list(routes: &Profiles, authorization: Option<&str>) -> Result<String, Status> {
    collect(
        routes.first(),
        Some(routes),
        authorization,
        MAX_RESPONSE_BYTES,
        &mut || true,
    )
}

fn deadline() -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    )
}

fn exchange(routes: &Profiles, request: &[u8]) -> (bool, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            serve_connection_with_routes(stream, deadline(), routes.first(), Some(routes))
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        (server.join().unwrap(), response)
    })
}

fn request(method: &str, path: &str, extra: &str) -> Vec<u8> {
    format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").into_bytes()
}

#[test]
fn fresh_grants_are_checked_independently_for_every_tenant_and_route() {
    let scratch = Scratch::new();
    let token = "a".repeat(64);
    let other = "b".repeat(64);
    let a = binding(1, 3);
    let b = binding(2, 3);
    let c = binding(1, 4);
    let routes = routed(vec![
        profile(
            "/zeta/shared.git",
            scratch.credentials("zeta", a, &[(&token, "read")]),
            a,
            true,
        ),
        profile(
            "/alpha/shared.git",
            scratch.credentials("alpha", b, &[(&other, "read"), (&token, "receive")]),
            b,
            true,
        ),
        profile(
            "/beta/clone.git",
            scratch.credentials("beta", c, &[(&token, "read")]),
            c,
            false,
        ),
    ]);
    assert_eq!(
        list(&routes, Some(&format!("Bearer {token}"))).unwrap(),
        concat!(
            "{\"type\":\"repository_catalog\",\"schema_version\":1,\"complete\":true,\"repositories\":[",
            "{\"path\":\"/beta/clone.git\",\"source_url\":null},",
            "{\"path\":\"/zeta/shared.git\",\"source_url\":\"/zeta/shared.git/ui/\"}]}",
        )
    );
    let other_result = list(&routes, Some(&format!("Bearer {other}"))).unwrap();
    assert!(other_result.contains("/alpha/shared.git"));
    assert!(!other_result.contains("/zeta/") && !other_result.contains("/beta/"));
    routes.close().unwrap();
}

#[test]
fn atomic_replacement_revokes_and_regrants_without_retained_authority() {
    let scratch = Scratch::new();
    let token = "a".repeat(64);
    let identity = binding(1, 3);
    let path = scratch.credentials("live", identity, &[(&token, "read")]);
    let routes = Profiles::Single(profile("/repo.git", path.clone(), identity, true));
    let authorization = format!("Bearer {token}");
    assert!(list(&routes, Some(&authorization)).is_ok());
    scratch.replace(&path, &table(identity, &[]));
    assert_eq!(
        list(&routes, Some(&authorization)),
        Err(Status::Unauthorized)
    );
    scratch.replace(&path, &table(identity, &[(&token, "receive")]));
    assert_eq!(list(&routes, Some(&authorization)), Err(Status::Forbidden));
    scratch.replace(&path, &table(identity, &[(&token, "read")]));
    assert!(list(&routes, Some(&authorization)).is_ok());
    routes.close().unwrap();
}

#[test]
fn wrong_binding_and_bad_later_rows_refuse_the_complete_catalog() {
    let scratch = Scratch::new();
    let token = "a".repeat(64);
    let a = binding(1, 3);
    let b = binding(2, 4);
    let hidden = scratch.credentials("hidden", b, &[(&token, "read")]);
    let routes = routed(vec![
        profile(
            "/alpha/visible.git",
            scratch.credentials("visible", a, &[(&token, "read")]),
            a,
            true,
        ),
        profile("/zeta/hidden.git", hidden.clone(), b, true),
    ]);
    let authorization = format!("Authorization: Bearer {token}\r\n");
    for invalid in [
        table(a, &[(&token, "read")]),
        table(binding(2, 5), &[(&token, "read")]),
        format!("{}malformed final grant\n", table(b, &[(&token, "read")])),
    ] {
        scratch.replace(&hidden, &invalid);
        let (served, response) = exchange(&routes, &request("GET", API, &authorization));
        assert!(!served);
        assert!(response.starts_with("HTTP/1.1 503 "));
        assert!(response.contains("\"code\":\"catalog_unavailable\""));
        assert_eq!(response.matches("HTTP/1.1").count(), 1);
        assert!(!response.contains("visible.git") && !response.contains("hidden.git"));
        assert!(!response.contains(&token));
    }
    scratch.replace(&hidden, &table(b, &[(&token, "read")]));
    assert!(list(&routes, Some(&format!("Bearer {token}"))).is_ok());
    fs::remove_file(&hidden).unwrap();
    assert_eq!(
        list(&routes, Some(&format!("Bearer {token}"))),
        Err(Status::Unavailable)
    );
    routes.close().unwrap();
}

#[test]
fn missing_basic_malformed_and_sponsored_credentials_never_probe_files() {
    let scratch = Scratch::new();
    let identity = binding(1, 3);
    let routes = Profiles::Single(profile(
        "/repo.git",
        scratch.0.join("missing"),
        identity,
        true,
    ));
    for authorization in [
        None,
        Some("Basic ZmdpdDph".to_owned()),
        Some(format!("Bearer fgagent_{}", "a".repeat(64))),
        Some(format!("Bearer {}", "A".repeat(64))),
        Some(format!("Bearer  {}", "a".repeat(64))),
        Some(format!("Bearer {}", "a".repeat(63))),
    ] {
        assert_eq!(
            list(&routes, authorization.as_deref()),
            Err(Status::Unauthorized)
        );
    }
    // A structurally valid operator token does consult the current file. An
    // unavailable file remains a configuration failure, never unknown-token.
    assert_eq!(
        list(&routes, Some(&format!("Bearer {}", "a".repeat(64)))),
        Err(Status::Unavailable)
    );
    routes.close().unwrap();
}

#[test]
fn single_repository_static_profile_keeps_its_read_grant_but_not_basic_authentication() {
    let scratch = Scratch::new();
    let token = "a".repeat(64);
    let mut profile = profile("/repo.git", scratch.0.join("unused"), binding(1, 3), true);
    profile.credentials = CredentialSource::Static {
        digest: sha256_digest(token.as_bytes()),
        principal: PrincipalId::from_bytes([4; 16]),
    };
    let body = collect(
        &profile,
        None,
        Some(&format!("Bearer {token}")),
        MAX_RESPONSE_BYTES,
        &mut || true,
    )
    .unwrap();
    assert!(body.contains("\"path\":\"/repo.git\""));
    const BASIC: &str = "Basic Z2l0OmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
    assert!(profile.credentials.authenticate(Some(BASIC)).is_ok());
    assert_eq!(
        collect(&profile, None, Some(BASIC), MAX_RESPONSE_BYTES, &mut || {
            true
        }),
        Err(Status::Unauthorized),
    );
    profile.nodes.close().unwrap();
}

#[test]
fn catalog_boundary_deadline_and_response_bounds_fail_before_disclosure() {
    let scratch = Scratch::new();
    let token = "a".repeat(64);
    let identity = binding(1, 3);
    let profile = profile(
        "/repo.git",
        scratch.credentials("read", identity, &[(&token, "read")]),
        identity,
        true,
    );
    let authorization = format!("Bearer {token}");
    let routes = Profiles::Single(profile.clone());
    assert_eq!(
        collect(
            &profile,
            Some(&routes),
            Some(&authorization),
            32,
            &mut || true
        ),
        Err(Status::TooLarge)
    );
    let mut checkpoints = 0;
    assert_eq!(
        collect(
            &profile,
            Some(&routes),
            Some(&authorization),
            MAX_RESPONSE_BYTES,
            &mut || {
                checkpoints += 1;
                checkpoints < 2
            }
        ),
        Err(Status::Timeout)
    );
    assert_eq!(
        checkpoints, 2,
        "expiration immediately after the credential file was read"
    );
    assert!(list(&routes, Some(&authorization)).is_ok());
    let mut expired = deadline();
    expired.started = Instant::now()
        .checked_sub(Duration::from_secs(600))
        .unwrap();
    let raw = request("GET", API, &format!("Authorization: {authorization}\r\n"));
    let envelope = head::parse(&raw, profile.http).unwrap().unwrap();
    let mut output = Vec::new();
    assert_eq!(
        serve(
            &profile,
            Some(&routes),
            &envelope,
            &[],
            &mut output,
            &expired
        ),
        Err(Status::Timeout)
    );
    assert!(!String::from_utf8(output).unwrap().contains("/repo.git"));
    let too_many = routed(
        (0..=MAX_HTTP_REPOSITORY_ROUTES)
            .map(|index| {
                let mut profile = profile.clone();
                profile.route = format!("/tenant/repo-{index}").into_bytes();
                profile
            })
            .collect(),
    );
    assert_eq!(
        list(&too_many, Some(&authorization)),
        Err(Status::Unavailable)
    );
    let empty = Profiles::Routed {
        routes: BTreeMap::new(),
        ingress: HttpLimits::default(),
    };
    assert_eq!(
        collect(
            &profile,
            Some(&empty),
            Some(&authorization),
            MAX_RESPONSE_BYTES,
            &mut || true
        ),
        Err(Status::Unavailable)
    );
    routes.close().unwrap();
    too_many.close().unwrap();
}

#[test]
fn full_bounded_catalog_is_sorted_and_uses_only_read_quotas() {
    let scratch = Scratch::new();
    let token = "a".repeat(64);
    let identity = binding(1, 3);
    let template = profile(
        "/tenant/repo",
        scratch.credentials("read", identity, &[(&token, "read")]),
        identity,
        true,
    );
    let routes = routed(
        (0..MAX_HTTP_REPOSITORY_ROUTES)
            .rev()
            .map(|index| {
                let mut value = template.clone();
                value.route = format!("/tenant/repo-{index:02}").into_bytes();
                value.source_quota = Arc::new(PushQuota::default());
                value
            })
            .collect(),
    );
    let principal = PrincipalId::from_bytes([4; 16]);
    for _ in 0..120 {
        template.quota.evaluate(&principal).unwrap();
        template.outcome_quota.evaluate(&principal).unwrap();
    }
    let body = list(&routes, Some(&format!("Bearer {token}"))).unwrap();
    assert_eq!(body.matches("\"path\":").count(), 64);
    assert!(body.find("repo-00").unwrap() < body.find("repo-63").unwrap());
    assert!(body.len() < MAX_RESPONSE_BYTES);
    for _ in 0..119 {
        template.source_quota.evaluate(&principal).unwrap();
    }
    let single = Profiles::Single(template.clone());
    assert!(list(&single, Some(&format!("Bearer {token}"))).is_ok());
    assert_eq!(
        list(&single, Some(&format!("Bearer {token}"))),
        Err(Status::RateLimited)
    );
    routes.close().unwrap();
    single.close().unwrap();
}

#[test]
fn native_root_routing_preserves_auth_method_framing_and_static_shell_boundaries() {
    let scratch = Scratch::new();
    let token = "a".repeat(64);
    let identity = binding(1, 3);
    let routes = routed(vec![profile(
        "/tenant/repo.git",
        scratch.credentials("read", identity, &[(&token, "read")]),
        identity,
        true,
    )]);
    let authorization = format!("Authorization: Bearer {token}\r\n");
    let (served, response) = exchange(&routes, &request("GET", API, &authorization));
    assert!(served);
    assert!(response.starts_with("HTTP/1.1 200 "));
    assert!(
        response.contains("Vary: Authorization\r\n")
            && response.contains("Cache-Control: no-store\r\n")
    );
    assert!(response.contains("\"path\":\"/tenant/repo.git\""));
    let (header, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(header.contains(&format!("Content-Length: {}\r\n", body.len())));
    for (method, target, extra, status) in [
        ("GET", API, String::new(), 401),
        ("POST", API, authorization.clone(), 405),
        (
            "GET",
            "/api/v1/repositories?tenant=hidden",
            authorization.clone(),
            400,
        ),
        (
            "GET",
            API,
            format!("{authorization}Expect: 100-continue\r\nContent-Length: 1\r\n"),
            400,
        ),
        (
            "GET",
            API,
            format!("{authorization}Git-Protocol: version=2\r\n"),
            400,
        ),
        (
            "GET",
            API,
            format!("{authorization}Transfer-Encoding: chunked\r\n"),
            400,
        ),
        (
            "POST",
            API,
            "Origin: https://evil.invalid\r\n".to_owned(),
            403,
        ),
    ] {
        let (served, response) = exchange(&routes, &request(method, target, &extra));
        assert!(!served);
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{response}"
        );
        assert!(!response.contains("/tenant/repo.git") && !response.contains(&token));
        assert!(!response.contains("100 Continue"));
        if status == 401 {
            assert!(response.contains("WWW-Authenticate: Bearer realm=\"frankengit\"\r\n"));
        }
        if status == 405 {
            assert!(response.contains("Allow: GET\r\n"));
        }
    }
    for target in [HOME, SCRIPT_PATH, STYLE_PATH] {
        let (served, response) = exchange(&routes, &request("GET", target, ""));
        assert!(served);
        assert!(response.starts_with("HTTP/1.1 200 "));
        assert!(response.contains("Content-Security-Policy: default-src 'none'"));
        assert!(!response.contains("/tenant/repo.git") && !response.contains(&token));
    }
    assert!(!routes.first().config.storage_root.exists());
    routes.close().unwrap();
}

#[test]
fn literal_safe_paths_never_normalize_or_admit_external_links() {
    for path in ["/repo.git", "/tenant/repo.git", "/A.B/repo_1-2"] {
        assert!(safe_path(path));
    }
    for path in [
        "",
        "/",
        "//evil.invalid/a",
        "/tenant/../repo",
        "/tenant/%2e%2e",
        "/tenant/repo?token=a",
        "/tenant/repo#x",
        "/tenant/repo\\x",
        "/-tenant/repo",
        "/tenant/repo/",
    ] {
        assert!(!safe_path(path), "{path}");
    }
    assert!(!safe_path(&format!("/{}", "a".repeat(512))));
    assert!(!is_route("/tenant/repo/api/v1/repositories"));
    assert!(!is_route("/api/v1/repositories/hidden"));
}
