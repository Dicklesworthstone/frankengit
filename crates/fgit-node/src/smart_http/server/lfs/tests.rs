use super::*;

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::sha256_digest;
use fgit_object_fabric::artifact::storage::lfs::LfsOid;
use fgit_schema::json::{self, Value};
use fgit_types::PrincipalId;
use fgit_wire::smart_http::{HttpLimits, head};

use super::super::credentials::{Binding, CredentialSource};
use crate::node_lanes::NodeLanes;
use crate::{
    GitDaemonSessionTimeout, GitDaemonSessionWorkScaling, NodeConfig, PushQuota, WriterGate,
};

static NEXT: AtomicU64 = AtomicU64::new(1);
const TENANT: TenantId = TenantId::from_bytes([1; 16]);
const REPO: RepositoryId = RepositoryId::from_bytes([2; 16]);
const INCARNATION: RepositoryIncarnationId = RepositoryIncarnationId::from_bytes([3; 16]);

struct Fixture {
    root: PathBuf,
    profile: Profile,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-lfs-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("credentials");
        let mut table = format!("frankengit-http-credentials-v1 {TENANT} {REPO} {INCARNATION}\n");
        for (token, principal, scopes) in [
            ('a', 4, "lfs-read,lfs-write"),
            ('b', 5, "lfs-read"),
            ('c', 6, "lfs-write"),
            ('d', 7, "read,receive"),
        ] {
            let digest: String = sha256_digest(token.to_string().repeat(64).as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            table.push_str(&format!(
                "{digest} {} {scopes}\n",
                PrincipalId::from_bytes([principal; 16])
            ));
        }
        fs::write(&path, table).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let config = NodeConfig::new(root.clone(), TENANT, REPO);
        let profile = Profile {
            config: config.clone(),
            route: b"/repo.git".to_vec(),
            credentials: CredentialSource::File {
                path,
                binding: Binding {
                    tenant: TENANT,
                    repository: REPO,
                    incarnation: INCARNATION,
                },
            },
            lfs: Some(Service::open(&root, TENANT, REPO, INCARNATION).unwrap()),
            allow_receive: false,
            allow_issues: false,
            allow_outcomes: false,
            allow_pulls: false,
            allow_source: false,
            http: HttpLimits::default(),
            maximum_response_bytes: 128 * 1024 * 1024,
            timeout: GitDaemonSessionTimeout::DEFAULT,
            quota: Arc::new(PushQuota::default()),
            outcome_quota: Arc::new(PushQuota::default()),
            source_quota: Arc::new(PushQuota::default()),
            writers: Arc::new(WriterGate::new(1)),
            nodes: Arc::new(NodeLanes::new(config, 1, "LFS fixture")),
        };
        Self { root, profile }
    }

    fn request(&self, method: &str, path: &str, token: char, body: &[u8]) -> Reply {
        self.request_with(method, path, token, body, false, "localhost:9418", "")
    }

    fn request_with(
        &self,
        method: &str,
        path: &str,
        token: char,
        bytes: &[u8],
        chunked: bool,
        host: &str,
        extra: &str,
    ) -> Reply {
        let media = if method == "PUT" {
            BINARY_MEDIA
        } else {
            JSON_MEDIA
        };
        let framing = if chunked {
            "Transfer-Encoding: chunked\r\n".to_owned()
        } else {
            format!("Content-Length: {}\r\n", bytes.len())
        };
        let input = if chunked && !bytes.is_empty() {
            let mut encoded = format!("{:x}\r\n", bytes.len()).into_bytes();
            encoded.extend_from_slice(bytes);
            encoded.extend_from_slice(b"\r\n0\r\n\r\n");
            encoded
        } else if chunked {
            b"0\r\n\r\n".to_vec()
        } else {
            bytes.to_vec()
        };
        let header = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: {media}\r\n{framing}{extra}\r\n",
            token.to_string().repeat(64)
        );
        let envelope = head::parse(header.as_bytes(), self.profile.http)
            .unwrap()
            .unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let mut output = Vec::new();
        // A mixed read-ahead/input path exercises the live gateway composition.
        let prefix = input.len() / 2;
        let result = serve(
            &self.profile,
            &envelope,
            &input[..prefix],
            &mut Cursor::new(&input[prefix..]),
            &mut output,
            &deadline,
            Some("127.0.0.1:9418".parse().unwrap()),
        );
        Reply { result, output }
    }

    fn batch(&self, operation: &str, token: char, objects: &[LfsObject]) -> Reply {
        let objects = objects
            .iter()
            .map(|object| format!("{{\"oid\":\"{}\",\"size\":{}}}", object.oid, object.size))
            .collect::<Vec<_>>()
            .join(",");
        self.request(
            "POST",
            "/repo.git/info/lfs/objects/batch",
            token,
            format!("{{\"operation\":\"{operation}\",\"objects\":[{objects}]}}").as_bytes(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

struct Reply {
    result: Result<(), Status>,
    output: Vec<u8>,
}

impl Reply {
    fn body(&self) -> &[u8] {
        let start = self
            .output
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        &self.output[start..]
    }
    fn json(&self) -> Value {
        json::parse(self.body()).unwrap()
    }
}

fn object(bytes: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(bytes),
        size: bytes.len() as u64,
    }
}

fn path(object: LfsObject) -> String {
    format!("/repo.git/info/lfs/objects/{}/{}", object.oid, object.size)
}

#[test]
fn route_selection_preserves_git_routes_with_lfs_in_the_repository_name() {
    for repository_route in [
        "/repo.git",
        "/info/lfs-repo.git",
        "/prefix/info/lfs/repo.git",
    ] {
        for suffix in [
            "/info/refs?service=git-upload-pack",
            "/git-upload-pack",
            "/git-receive-pack",
            "/info/lfs-extra",
        ] {
            assert!(!is_route(
                &format!("{repository_route}{suffix}"),
                repository_route.as_bytes()
            ));
        }
        for suffix in [
            "/info/lfs",
            "/info/lfs/",
            "/info/lfs/objects/batch",
            "/info/lfs/unsupported?query=1",
        ] {
            assert!(is_route(
                &format!("{repository_route}{suffix}"),
                repository_route.as_bytes()
            ));
        }
        let header = format!(
            "POST {repository_route}/info/lfs/objects/batch HTTP/1.1\r\nHost: localhost\r\nContent-Type: {JSON_MEDIA}\r\nContent-Length: 0\r\n\r\n"
        );
        let envelope = head::parse(header.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let request = Request::parse(&envelope).unwrap();
        assert_eq!(request.repository_route, repository_route);
        assert_eq!(request.endpoint, Endpoint::Batch);
    }
    assert!(!is_route("/other.git/info/lfs/objects/batch", b"/repo.git"));
    assert!(!is_route(
        "/repo.git-extra/info/lfs/objects/batch",
        b"/repo.git"
    ));
}

#[test]
fn batch_upload_verify_download_retry_and_reopen_preserve_exact_bytes() {
    for chunked in [false, true] {
        let mut fixture = Fixture::new();
        for bytes in [b"".as_slice(), b"an asset\0with\xffbinary bytes".as_slice()] {
            let object = object(bytes);
            let missing = fixture.batch("download", 'a', &[object]);
            assert_eq!(missing.result, Ok(()));
            assert!(String::from_utf8_lossy(missing.body()).contains("\"code\":404"));
            let upload = fixture.batch("upload", 'a', &[object]);
            assert_eq!(upload.result, Ok(()));
            let text = String::from_utf8_lossy(upload.body());
            assert!(text.contains("\"transfer\":\"basic\""));
            assert!(text.contains("\"upload\":") && text.contains("\"verify\":"));
            assert!(!text.contains("Authorization") && !text.contains(&"a".repeat(64)));
            let value = upload.json();
            let Some(Value::Array(objects)) = value.object().unwrap().get("objects") else {
                panic!()
            };
            assert_eq!(objects.len(), 1);
            let uploaded = fixture.request_with(
                "PUT",
                &path(object),
                'a',
                bytes,
                chunked,
                "localhost:9418",
                "",
            );
            assert_eq!(
                uploaded.result,
                Ok(()),
                "{}",
                String::from_utf8_lossy(&uploaded.output)
            );
            assert_eq!(
                fixture.request("PUT", &path(object), 'a', bytes).result,
                Ok(())
            );
            let verify = format!("{{\"oid\":\"{}\",\"size\":{}}}", object.oid, object.size);
            assert_eq!(
                fixture
                    .request(
                        "POST",
                        &format!("{}/verify", path(object)),
                        'a',
                        verify.as_bytes()
                    )
                    .result,
                Ok(())
            );
            let exists = fixture.batch("upload", 'a', &[object]);
            assert!(!String::from_utf8_lossy(exists.body()).contains("actions"));
            let download = fixture.batch("download", 'a', &[object]);
            assert!(String::from_utf8_lossy(download.body()).contains("\"download\":"));
            fixture.profile.lfs =
                Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
            let retrieved = fixture.request("GET", &path(object), 'a', b"");
            assert_eq!(retrieved.result, Ok(()));
            assert_eq!(retrieved.body(), bytes);
        }
    }
}

#[test]
fn read_and_write_scopes_are_independent_and_basic_uses_the_same_grant() {
    let fixture = Fixture::new();
    let bytes = b"scoped asset";
    let object = object(bytes);
    assert_eq!(fixture.batch("download", 'b', &[object]).result, Ok(()));
    assert_eq!(
        fixture.batch("upload", 'b', &[object]).result,
        Err(Status::Forbidden)
    );
    assert_eq!(fixture.batch("upload", 'c', &[object]).result, Ok(()));
    assert_eq!(
        fixture.batch("download", 'c', &[object]).result,
        Err(Status::Forbidden)
    );
    assert_eq!(
        fixture.request("PUT", &path(object), 'b', bytes).result,
        Err(Status::Forbidden)
    );
    assert_eq!(
        fixture.request("PUT", &path(object), 'c', bytes).result,
        Ok(())
    );
    assert_eq!(
        fixture.request("GET", &path(object), 'c', b"").result,
        Err(Status::Forbidden)
    );
    assert_eq!(
        fixture.request("GET", &path(object), 'b', b"").body(),
        bytes
    );
    assert_eq!(
        fixture.request("GET", &path(object), 'd', b"").result,
        Err(Status::Forbidden)
    );
    assert_eq!(
        fixture.request("GET", &path(object), 'e', b"").result,
        Err(Status::Unauthorized)
    );
    // The credentials module independently verifies the full Basic grammar;
    // this known encoding is git:<64 lowercase a bytes>.
    let basic = "Z2l0OmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: localhost:9418\r\nAuthorization: Basic {basic}\r\n\r\n",
        path(object)
    );
    let envelope = head::parse(head.as_bytes(), fixture.profile.http)
        .unwrap()
        .unwrap();
    let request = Request::parse(&envelope).unwrap();
    assert!(
        authorize(&fixture.profile, &envelope, &request)
            .unwrap()
            .permits_lfs(false)
    );
}

#[test]
fn scope_rotation_revocation_repository_incarnation_and_disabled_service_refuse() {
    let mut fixture = Fixture::new();
    let bytes = b"private asset";
    let object = object(bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', bytes).result,
        Ok(())
    );
    fixture.profile.lfs = Some(
        Service::open(
            &fixture.root,
            TENANT,
            REPO,
            RepositoryIncarnationId::from_bytes([9; 16]),
        )
        .unwrap(),
    );
    assert_eq!(
        fixture.request("GET", &path(object), 'a', b"").result,
        Err(Status::NotFound)
    );
    fixture.profile.lfs = Some(
        Service::open(
            &fixture.root,
            TenantId::from_bytes([9; 16]),
            REPO,
            INCARNATION,
        )
        .unwrap(),
    );
    assert_eq!(
        fixture.request("GET", &path(object), 'a', b"").result,
        Err(Status::NotFound)
    );
    fixture.profile.lfs = Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
    assert_eq!(
        fixture
            .request(
                "GET",
                &path(object).replace("repo.git", "other.git"),
                'a',
                b""
            )
            .result,
        Err(Status::NotFound)
    );
    fs::write(
        fixture.root.join("credentials"),
        format!("frankengit-http-credentials-v1 {TENANT} {REPO} {INCARNATION}\n"),
    )
    .unwrap();
    assert_eq!(
        fixture.request("GET", &path(object), 'a', b"").result,
        Err(Status::Unauthorized)
    );
    fixture.profile.credentials = CredentialSource::Static {
        digest: sha256_digest("a".repeat(64).as_bytes()),
        principal: PrincipalId::from_bytes([4; 16]),
    };
    assert_eq!(
        fixture.request("GET", &path(object), 'a', b"").result,
        Err(Status::Forbidden)
    );
    fixture.profile.lfs = None;
    assert_eq!(
        fixture.request("GET", &path(object), 'a', b"").result,
        Err(Status::Forbidden)
    );
}

#[test]
fn rejected_uploads_never_install_the_declared_object_and_corruption_discloses_nothing() {
    let fixture = Fixture::new();
    let expected = object(b"right");
    for bytes in [b"wrong".as_slice(), b"shorter", b"bad"] {
        assert!(
            fixture
                .request("PUT", &path(expected), 'a', bytes)
                .result
                .is_err()
        );
        assert_eq!(
            fixture.request("GET", &path(expected), 'a', b"").result,
            Err(Status::NotFound)
        );
    }
    assert_eq!(
        fixture
            .request("PUT", &path(expected), 'a', b"right")
            .result,
        Ok(())
    );
    let directory = fs::read_dir(&fixture.root)
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("scope-"))
        .unwrap()
        .path();
    let payload = fs::read_dir(directory)
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_name().len() == 64)
        .unwrap()
        .path();
    let mut bytes = fs::read(&payload).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    fs::write(payload, bytes).unwrap();
    let refused = fixture.request("GET", &path(expected), 'a', b"");
    assert_eq!(refused.result, Err(Status::Unavailable));
    assert!(!refused.body().windows(5).any(|part| part == b"right"));
    let verify = format!(
        "{{\"oid\":\"{}\",\"size\":{}}}",
        expected.oid, expected.size
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("{}/verify", path(expected)),
                'a',
                verify.as_bytes()
            )
            .result,
        Err(Status::Unavailable)
    );
    assert!(
        String::from_utf8_lossy(fixture.batch("download", 'a', &[expected]).body())
            .contains("\"code\":503")
    );
}

#[test]
fn incomplete_http_bodies_cannot_publish_even_after_all_declared_payload_bytes_arrive() {
    let fixture = Fixture::new();
    let expected = object(b"asset");
    for (framing, wire) in [
        ("Content-Length: 5", b"asse".as_slice()),
        ("Transfer-Encoding: chunked", b"5\r\nasset\r\n".as_slice()),
        (
            "Transfer-Encoding: chunked",
            b"5\r\nasset\r\n0\r\n".as_slice(),
        ),
        (
            "Transfer-Encoding: chunked",
            b"5\r\nasset\r\n0\r\n\r\nNEXT".as_slice(),
        ),
    ] {
        let header = format!(
            "PUT {} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: {BINARY_MEDIA}\r\n{framing}\r\n\r\n",
            path(expected),
            "a".repeat(64)
        );
        let envelope = head::parse(header.as_bytes(), fixture.profile.http)
            .unwrap()
            .unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let mut output = Vec::new();
        assert_eq!(
            serve(
                &fixture.profile,
                &envelope,
                wire,
                &mut io::empty(),
                &mut output,
                &deadline,
                Some("127.0.0.1:9418".parse().unwrap())
            ),
            Err(Status::BadRequest)
        );
        assert_eq!(
            fixture.request("GET", &path(expected), 'a', b"").result,
            Err(Status::NotFound)
        );
    }
    assert_eq!(
        fixture
            .request("PUT", &path(expected), 'a', b"asset")
            .result,
        Ok(())
    );
    assert_eq!(
        fixture.request("GET", &path(expected), 'a', b"").body(),
        b"asset"
    );
}

#[test]
fn action_origin_never_reflects_host_and_batch_resource_failures_are_per_object() {
    let mut fixture = Fixture::new();
    let expected = object(b"asset");
    let body = format!(
        "{{\"operation\":\"upload\",\"objects\":[{{\"oid\":\"{}\",\"size\":{}}}]}}",
        expected.oid, expected.size
    );
    let reply = fixture.request_with(
        "POST",
        "/repo.git/info/lfs/objects/batch",
        'a',
        body.as_bytes(),
        false,
        "attacker.example",
        "",
    );
    let text = String::from_utf8_lossy(reply.body());
    assert!(text.contains("http://127.0.0.1:9418/repo.git/info/lfs/"));
    assert!(!text.contains("attacker.example"));
    fixture.profile.config = fixture.profile.config.clone().with_http_trusted_origin(
        crate::HttpTrustedOrigin::try_new("https://forge.example").unwrap(),
    );
    let reply = fixture.batch("upload", 'a', &[expected]);
    assert!(String::from_utf8_lossy(reply.body()).contains("https://forge.example/repo.git/"));
    let oversized = LfsObject {
        oid: expected.oid,
        size: MAX_OBJECT_BYTES + 1,
    };
    let exact = LfsObject {
        oid: expected.oid,
        size: MAX_OBJECT_BYTES,
    };
    let reply = fixture.batch("upload", 'a', &[oversized, exact, expected]);
    assert_eq!(reply.result, Ok(()));
    let text = String::from_utf8_lossy(reply.body());
    assert_eq!(text.matches("\"code\":413").count(), 2);
    assert_eq!(text.matches("\"upload\":").count(), 1);
}

#[test]
fn credentials_and_declared_limits_are_checked_before_continue_or_body_read() {
    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("refusal read upload bytes")
        }
    }
    let fixture = Fixture::new();
    let expected = object(b"asset");
    for (token, path, size, expected_status) in [
        ('e', path(expected), expected.size, Status::Unauthorized),
        ('b', path(expected), expected.size, Status::Forbidden),
        ('a', path(expected), expected.size + 1, Status::BadRequest),
        (
            'a',
            path(LfsObject {
                oid: expected.oid,
                size: MAX_OBJECT_BYTES + 1,
            }),
            MAX_OBJECT_BYTES + 1,
            Status::TooLarge,
        ),
    ] {
        let header = format!(
            "PUT {path} HTTP/1.1\r\nHost: localhost:9418\r\nAuthorization: Bearer {}\r\nContent-Type: {BINARY_MEDIA}\r\nContent-Length: {size}\r\nExpect: 100-continue\r\n\r\n",
            token.to_string().repeat(64)
        );
        let envelope = head::parse(header.as_bytes(), fixture.profile.http)
            .unwrap()
            .unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::FLAT,
        );
        let mut output = Vec::new();
        assert_eq!(
            serve(
                &fixture.profile,
                &envelope,
                b"",
                &mut NoRead,
                &mut output,
                &deadline,
                Some("127.0.0.1:9418".parse().unwrap())
            ),
            Err(expected_status)
        );
        assert!(!String::from_utf8_lossy(&output).contains("100 Continue"));
    }
}

#[test]
fn malformed_verify_wrong_method_and_path_never_mutate_custody() {
    let fixture = Fixture::new();
    let expected = object(b"asset");
    assert_eq!(
        fixture
            .request("PUT", &path(expected), 'a', b"asset")
            .result,
        Ok(())
    );
    assert!(
        fixture
            .request(
                "POST",
                &format!("{}/verify", path(expected)),
                'a',
                b"{\"size\":5}"
            )
            .result
            .is_err()
    );
    assert_eq!(
        fixture.request("DELETE", &path(expected), 'a', b"").result,
        Err(Status::Method)
    );
    assert!(
        fixture
            .request("GET", &format!("{}?other=1", path(expected)), 'a', b"")
            .result
            .is_err()
    );
    assert!(
        fixture
            .request("GET", &format!("{}/extra", path(expected)), 'a', b"")
            .result
            .is_err()
    );
    assert_eq!(
        fixture.request("GET", &path(expected), 'a', b"").body(),
        b"asset"
    );
}
