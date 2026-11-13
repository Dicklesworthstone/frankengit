//! Exact route authorization and canonical node selection. The wire-session
//! tests in fgit-ssh separately exercise the encrypted command boundary.

use super::*;
use crate::ssh::{GitDaemonSessionDeadline, GitDaemonSessionTimeout, GitDaemonSessionWorkScaling};
use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyScope};
use fgit_ssh::{SigningKey, StaticDeployKeyAuthorizer};
use fgit_types::GitHashAlgorithm;
use std::io::Cursor;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-ssh-routes-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn node(root: PathBuf, tenant: u8, format: GitHashAlgorithm) -> OneNode {
    let configuration = NodeConfig::new(
        root,
        TenantId::from_bytes([tenant; 16]),
        // Repositories with the same identifier in different tenants must
        // never share authorization, node pools or native object format.
        RepositoryId::from_bytes([0x72; 16]),
    )
    .with_object_format(format)
    .with_worker_threads(2);
    let (mut node, _) = OneNode::init(configuration).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}

fn peer_key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn source(node: &OneNode, principal: u8, seed: u8) -> Arc<dyn SshCommandAuthorizer> {
    Arc::new(StaticDeployKeyAuthorizer::new(vec![
        DeployKeyBinding::register(
            node.repository_id,
            PrincipalId::from_bytes([principal; 16]),
            fgit_crypto::VerifyingKey::from_bytes(peer_key(seed)),
            &[DeployKeyScope::Read, DeployKeyScope::Write],
        )
        .unwrap(),
    ]))
}

fn route(node: &OneNode, path: &str, principal: u8, seed: u8, receive: bool) -> SshRepositoryRoute {
    SshRepositoryRoute::try_new(path.into(), node, source(node, principal, seed), receive).unwrap()
}

fn command(service: SshGitService, path: &str) -> SshGitCommand {
    SshGitCommand::parse(&format!("{service} '{path}'")).unwrap()
}

fn deadline() -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    )
}

#[test]
fn route_paths_have_one_literal_tenant_and_repository_spelling() {
    for path in ["team/repo.git", "Team-2/repo_3", "a/b", "a/.hidden.git"] {
        SshRepositoryRoute::validate_path(path).unwrap();
        let parsed = command(SshGitService::UploadPack, &format!("/{path}"));
        assert_eq!(parsed.repository_path(), path);
    }
    for path in [
        "",
        "repo.git",
        "/team/repo.git",
        "//team/repo.git",
        "team//repo.git",
        "team/repo.git/",
        "team/nested/repo.git",
        ". /repo.git",
        "./repo.git",
        "team/..",
        "../repo.git",
        "-team/repo.git",
        "team/-repo.git",
        "team/repo name",
        "team/repo;name",
        "team/repo'",
        "team/repo\\name",
        "tém/repo.git",
    ] {
        assert!(SshRepositoryRoute::validate_path(path).is_err(), "{path}");
    }
    let limit = format!("a/{}", "b".repeat(510));
    SshRepositoryRoute::validate_path(&limit).unwrap();
    assert!(SshRepositoryRoute::validate_path(&(limit + "b")).is_err());
}

#[test]
fn a_route_captures_only_a_serving_repository_and_pins_its_incarnation() {
    let scratch = Scratch::new();
    let configuration = NodeConfig::new(
        scratch.0.join("node"),
        TenantId::from_bytes([0x71; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
    .with_worker_threads(2);
    let (mut node, _) = OneNode::init(configuration).unwrap();
    assert!(matches!(
        SshRepositoryRoute::try_new("team/repo.git".into(), &node, source(&node, 1, 2), true),
        Err(NodeSshRefusal::NotServing)
    ));
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    let route = route(&node, "team/repo.git", 1, 2, true);
    assert_eq!(
        route
            .configuration
            .resolution_input
            .unwrap()
            .repository_incarnation_id(),
        node.repository_incarnation_id(),
    );
    assert_eq!(route.configuration.storage_root, route.root);
    assert!(route.root.is_absolute());
    node.shutdown().unwrap();
}

#[test]
fn catalog_validation_rejects_ambiguous_paths_identities_and_storage_roots() {
    let scratch = Scratch::new();
    let first = node(scratch.0.join("first"), 0x71, GitHashAlgorithm::Sha1);
    let second = node(scratch.0.join("second"), 0x81, GitHashAlgorithm::Sha256);
    let a = route(&first, "alpha/repo.git", 1, 2, true);
    let b = route(&second, "beta/repo.git", 3, 4, true);
    assert!(matches!(
        Services::routed(Vec::new(), 2),
        Err(NodeSshRefusal::InvalidRoutes(_))
    ));
    assert!(matches!(
        Services::routed(vec![a.clone(); MAX_SSH_REPOSITORY_ROUTES + 1], 2),
        Err(NodeSshRefusal::InvalidRoutes(_))
    ));
    let mut same_path = b.clone();
    same_path.path = a.path.clone();
    assert!(matches!(
        Services::routed(vec![a.clone(), same_path], 2),
        Err(NodeSshRefusal::InvalidRoutes("duplicate route path"))
    ));
    let mut same_identity = a.clone();
    same_identity.path = "alpha/alias.git".into();
    assert!(matches!(
        Services::routed(vec![a.clone(), same_identity], 2),
        Err(NodeSshRefusal::InvalidRoutes(
            "duplicate repository identity"
        ))
    ));
    for root in [a.root.clone(), a.root.join("nested"), scratch.0.clone()] {
        let mut overlapping = b.clone();
        overlapping.root = root;
        assert!(matches!(
            Services::routed(vec![a.clone(), overlapping], 2),
            Err(NodeSshRefusal::InvalidRoutes(
                "overlapping repository roots"
            ))
        ));
    }
    Services::routed(vec![a, b], 1).unwrap().close().unwrap();
    first.shutdown().unwrap();
    second.shutdown().unwrap();
}

#[test]
fn exact_authorization_selects_the_matching_tenant_native_format_and_principal() {
    let scratch = Scratch::new();
    let first = node(scratch.0.join("first"), 0x71, GitHashAlgorithm::Sha1);
    let second = node(scratch.0.join("second"), 0x81, GitHashAlgorithm::Sha256);
    let services = Services::routed(
        vec![
            route(&first, "alpha/repo.git", 1, 2, true),
            route(&second, "beta/repo.git", 3, 4, true),
        ],
        1,
    )
    .unwrap();
    for (path, seed, principal, tenant, format) in [
        ("alpha/repo.git", 2, 1, 0x71, GitHashAlgorithm::Sha1),
        ("/beta/repo.git", 4, 3, 0x81, GitHashAlgorithm::Sha256),
    ] {
        let command = command(SshGitService::UploadPack, path);
        let grant = services
            .authorize_repository_command(&peer_key(seed), &command)
            .unwrap();
        assert_eq!(grant.principal(), PrincipalId::from_bytes([principal; 16]));
        let selected = services.selected(&command).unwrap();
        let leased = selected.nodes.lease().unwrap();
        assert_eq!(leased.tenant_id, TenantId::from_bytes([tenant; 16]));
        assert_eq!(leased.object_format, format);
        let mut response = Vec::new();
        leased
            .serve_ssh_upload_pack(
                &mut Cursor::new(b"0000"),
                &mut response,
                b"",
                &|| true,
                &deadline(),
            )
            .unwrap();
        assert!(
            response
                .windows(format!("object-format={}", format.as_str()).len())
                .any(|bytes| { bytes == format!("object-format={}", format.as_str()).as_bytes() })
        );
        selected.nodes.restore(leased).unwrap();
    }
    services.close().unwrap();
    first.shutdown().unwrap();
    second.shutdown().unwrap();
}

#[test]
fn a_captured_route_cannot_open_a_recreated_repository_incarnation() {
    let scratch = Scratch::new();
    let root = scratch.0.join("node");
    let original = node(root.clone(), 0x71, GitHashAlgorithm::Sha1);
    let old_incarnation = original.repository_incarnation_id();
    let stale = route(&original, "alpha/repo.git", 1, 2, true);
    original.shutdown().unwrap();
    std::fs::rename(&root, scratch.0.join("retired")).unwrap();
    let replacement = node(root, 0x71, GitHashAlgorithm::Sha1);
    assert_ne!(replacement.repository_incarnation_id(), old_incarnation);
    let current = route(&replacement, "alpha/repo.git", 1, 2, true);
    let command = command(SshGitService::UploadPack, "alpha/repo.git");
    let stale = Services::routed(vec![stale], 1).unwrap();
    // Possession of a still-authorized key cannot silently rebind the route to
    // a newly created canonical incarnation at the same filesystem path.
    stale
        .authorize_repository_command(&peer_key(2), &command)
        .unwrap();
    assert!(stale.selected(&command).unwrap().nodes.lease().is_none());
    stale.close().unwrap();
    let current = Services::routed(vec![current], 1).unwrap();
    current
        .authorize_repository_command(&peer_key(2), &command)
        .unwrap();
    let selected = current.selected(&command).unwrap();
    let leased = selected.nodes.lease().unwrap();
    assert_eq!(
        leased.repository_incarnation_id(),
        replacement.repository_incarnation_id()
    );
    selected.nodes.restore(leased).unwrap();
    current.close().unwrap();
    replacement.shutdown().unwrap();
}

#[cfg(unix)]
#[test]
fn route_key_files_reload_principals_and_ref_ceilings_without_replacing_the_catalog() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let scratch = Scratch::new();
    let node = node(scratch.0.join("node"), 0x71, GitHashAlgorithm::Sha1);
    let path = scratch.0.join("keys");
    let replace = |principal: Option<u8>, ceiling: &str| {
        let next = path.with_extension("next");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&next)
            .unwrap();
        if let Some(principal) = principal {
            let key: String = peer_key(2)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            writeln!(
                file,
                "frankengit-ssh-deploy-keys-v2\n{key} {} read,write {ceiling}",
                PrincipalId::from_bytes([principal; 16])
            )
            .unwrap();
        }
        file.sync_all().unwrap();
        drop(file);
        std::fs::rename(next, &path).unwrap();
    };
    replace(Some(1), "prefix:726566732f68656164732f6167656e742f");
    let source = crate::ssh::FileDeployKeyAuthorizer::try_new(
        path.clone(),
        node.repository_id,
        node.repository_id,
    )
    .unwrap();
    let route = SshRepositoryRoute::try_new("alpha/repo.git".into(), &node, Arc::new(source), true)
        .unwrap();
    let services = Services::routed(vec![route], 1).unwrap();
    let command = command(SshGitService::ReceivePack, "alpha/repo.git");
    let first = services
        .authorize_repository_command(&peer_key(2), &command)
        .unwrap();
    assert_eq!(first.principal(), PrincipalId::from_bytes([1; 16]));
    assert!(
        first
            .ref_write_scope()
            .unwrap()
            .permits(b"refs/heads/agent/topic")
    );
    assert!(!first.ref_write_scope().unwrap().permits(b"refs/heads/main"));
    replace(None, "none");
    assert_eq!(
        services.authorize_repository_command(&peer_key(2), &command),
        Err(denied())
    );
    replace(Some(3), "none");
    let next = services
        .authorize_repository_command(&peer_key(2), &command)
        .unwrap();
    assert_eq!(next.principal(), PrincipalId::from_bytes([3; 16]));
    assert!(
        !next
            .ref_write_scope()
            .unwrap()
            .permits(b"refs/heads/agent/topic")
    );
    assert!(
        first
            .ref_write_scope()
            .unwrap()
            .permits(b"refs/heads/agent/topic")
    );
    assert_eq!(first.principal(), PrincipalId::from_bytes([1; 16]));
    services.close().unwrap();
    node.shutdown().unwrap();
}

#[test]
fn denied_routes_keys_services_and_legacy_aliases_have_one_fixed_refusal() {
    let scratch = Scratch::new();
    let node = node(scratch.0.join("node"), 0x71, GitHashAlgorithm::Sha1);
    let services = Services::routed(vec![route(&node, "alpha/repo.git", 1, 2, false)], 1).unwrap();
    for (path, seed, service) in [
        ("beta/repo.git".to_owned(), 2, SshGitService::UploadPack),
        ("repo.git".to_owned(), 2, SshGitService::UploadPack),
        (
            format!("{}.git", node.repository_id),
            2,
            SshGitService::UploadPack,
        ),
        ("alpha/repo".to_owned(), 2, SshGitService::UploadPack),
        ("Alpha/repo.git".to_owned(), 2, SshGitService::UploadPack),
        ("alpha/repo.git".to_owned(), 4, SshGitService::UploadPack),
        ("alpha/repo.git".to_owned(), 2, SshGitService::ReceivePack),
    ] {
        assert_eq!(
            services.authorize_repository_command(&peer_key(seed), &command(service, &path)),
            Err(denied()),
        );
    }
    assert_eq!(
        services.authorize_command_grant(
            &peer_key(2),
            node.repository_id,
            SshGitService::UploadPack
        ),
        Err(denied()),
        "an exact catalog never grants through a repository-ID-only entry point",
    );
    services
        .authorize_repository_command(
            &peer_key(2),
            &command(SshGitService::UploadPack, "alpha/repo.git"),
        )
        .unwrap();
    services.close().unwrap();
    node.shutdown().unwrap();
}

struct Exact<F>(F);
impl<F> SshCommandAuthorizer for Exact<F>
where
    F: Fn(&[u8; 32], &SshGitCommand) -> Result<SshCommandGrant, AuthRefusal> + Send + Sync,
{
    fn authorize_command(
        &self,
        _: &[u8; 32],
        _: RepositoryId,
        _: SshGitService,
    ) -> Result<PrincipalId, AuthRefusal> {
        panic!("exact route forwarding must not fall back to the legacy callback")
    }
    fn authorize_repository_command(
        &self,
        key: &[u8; 32],
        command: &SshGitCommand,
    ) -> Result<SshCommandGrant, AuthRefusal> {
        (self.0)(key, command)
    }
}

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    (client, peer)
}

#[test]
fn session_wrapper_forwards_the_exact_path_and_rejects_late_authorization() {
    for disconnect in [false, true] {
        let (client, peer) = pair();
        let client = Mutex::new(Some(client));
        let check = peer.try_clone().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let source = crate::ssh::SessionCommandAuthorizer {
            source: Arc::new(Exact(move |key: &[u8; 32], command: &SshGitCommand| {
                observed.fetch_add(1, Ordering::Relaxed);
                assert_eq!(key, &peer_key(2));
                assert_eq!(command.repository_path(), "alpha/repo.git");
                if disconnect {
                    let client = client.lock().unwrap().take().unwrap();
                    client.shutdown(Shutdown::Both).unwrap();
                    drop(client);
                    let start = Instant::now();
                    while crate::tcp_peer_connected(&check) {
                        assert!(start.elapsed() < Duration::from_secs(3));
                        std::thread::yield_now();
                    }
                }
                Ok(SshCommandGrant::unrestricted(PrincipalId::from_bytes(
                    [1; 16],
                )))
            })),
            deadline: deadline(),
            peer,
        };
        let result = source.authorize_repository_command(
            &peer_key(2),
            &command(SshGitService::UploadPack, "alpha/repo.git"),
        );
        if disconnect {
            assert_eq!(result, Err(AuthRefusal::AuthorizationSourceUnavailable));
        } else {
            assert_eq!(
                result.unwrap().principal(),
                PrincipalId::from_bytes([1; 16])
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn expired_routed_sessions_do_not_consult_the_authorization_source() {
    let (client, peer) = pair();
    let mut expired = deadline();
    expired.started = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
    let source = crate::ssh::SessionCommandAuthorizer {
        source: Arc::new(Exact(|_: &[u8; 32], _: &SshGitCommand| {
            panic!("expired session consulted its source")
        })),
        deadline: expired,
        peer,
    };
    assert_eq!(
        source.authorize_repository_command(
            &peer_key(2),
            &command(SshGitService::UploadPack, "alpha/repo.git")
        ),
        Err(AuthRefusal::AuthorizationSourceUnavailable),
    );
    drop(client);
}

#[test]
fn routed_listener_validates_the_whole_catalog_before_acceptance() {
    let scratch = Scratch::new();
    let node = node(scratch.0.join("node"), 0x71, GitHashAlgorithm::Sha1);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(matches!(
        node.serve_ssh_routes_bounded(
            &listener,
            crate::ssh::SshServerLimits::try_new(1, 1).unwrap(),
            SigningKey::from_bytes(&[9; 32]),
            Vec::new(),
        ),
        Err(NodeSshRefusal::InvalidRoutes(_))
    ));
    let route = route(&node, "alpha/repo.git", 1, 2, true);
    let receipt = node
        .serve_ssh_routes_until_stopped(
            listener,
            1,
            SigningKey::from_bytes(&[9; 32]),
            vec![route],
            &|| Ok(true),
        )
        .unwrap();
    assert_eq!(receipt.accepted_sessions, 0);
    assert_eq!(receipt.completed_sessions, 0);
    assert_eq!(receipt.refused_sessions, 0);
    node.shutdown().unwrap();
}
