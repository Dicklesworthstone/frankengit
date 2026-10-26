//! Live command authorization through the encrypted SSH state machine.

use super::*;
use fgit_identity::revocation::RevocationEvidence;
use fgit_ssh::{AuthRefusal, SshCommandAuthorizer, SshGitService, authorize_deploy_key};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Query {
    key: [u8; 32],
    repository: RepositoryId,
    service: SshGitService,
}

struct MutableAuthorizer {
    current: Mutex<Result<Vec<DeployKeyBinding>, AuthRefusal>>,
    queries: Mutex<Vec<Query>>,
}

impl MutableAuthorizer {
    fn new(bindings: Vec<DeployKeyBinding>) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(Ok(bindings)),
            queries: Mutex::new(Vec::new()),
        })
    }

    fn replace(&self, next: Result<Vec<DeployKeyBinding>, AuthRefusal>) {
        *self.current.lock().unwrap() = next;
    }

    fn queries(&self) -> Vec<Query> {
        self.queries.lock().unwrap().clone()
    }
}

impl SshCommandAuthorizer for MutableAuthorizer {
    fn authorize_command(
        &self,
        key: &[u8; 32],
        repository: RepositoryId,
        service: SshGitService,
    ) -> Result<PrincipalId, AuthRefusal> {
        self.queries.lock().unwrap().push(Query {
            key: *key,
            repository,
            service,
        });
        let current = self.current.lock().unwrap();
        match &*current {
            Ok(bindings) => {
                authorize_deploy_key(bindings, key, repository, service, RevocationEvidence::Live)
            }
            Err(refusal) => Err(refusal.clone()),
        }
    }
}

fn peer_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x22; 32])
}

fn named_repository(path: &str) -> RepositoryId {
    let digest = sha256_digest(path.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    RepositoryId::from_bytes(bytes)
}

fn grants(principal: u8, scopes: &[DeployKeyScope]) -> Vec<DeployKeyBinding> {
    vec![
        DeployKeyBinding::register(
            named_repository("repo.git"),
            PrincipalId::from_bytes([principal; 16]),
            fgit_crypto::VerifyingKey::from_bytes(peer_key().verifying_key().to_bytes()),
            scopes,
        )
        .unwrap(),
    ]
}

fn ready(source: &Arc<MutableAuthorizer>, seed: u64) -> (SshServerSession, Client) {
    let authorizer: Arc<dyn SshCommandAuthorizer> = source.clone();
    let (mut session, mut client, key) = key_exchange_with_authorizer(
        Arc::new(DetEntropy::new(seed)),
        true,
        [0x33; 32],
        Some(authorizer),
    );
    open_channel(&mut session, &mut client, &key, 4096, 1024);
    assert_eq!(*session.phase(), SessionPhase::ChannelReady);
    assert_eq!(session.authenticated_principal(), None);
    assert_eq!(session.active_command(), None);
    (session, client)
}

fn exec_payload(command: &str) -> Vec<u8> {
    let mut request = WireWriter::new();
    request.write_u8(msg::CHANNEL_REQUEST);
    request.write_u32(0);
    request.write_utf8("exec");
    request.write_bool(true);
    request.write_utf8(command);
    request.into_bytes()
}

fn exec(session: &mut SshServerSession, client: &mut Client, command: &str) -> Vec<Vec<u8>> {
    client.send(session, &exec_payload(command));
    client.receive_all(session)
}

fn allowed(session: &SshServerSession, packets: &[Vec<u8>], principal: u8, service: SshGitService) {
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0][0], msg::CHANNEL_SUCCESS);
    assert_eq!(*session.phase(), SessionPhase::ActiveChannel);
    assert_eq!(
        session.authenticated_principal(),
        Some(PrincipalId::from_bytes([principal; 16])),
    );
    assert_eq!(session.active_command().unwrap().service(), service);
}

fn refused(session: &SshServerSession, packets: &[Vec<u8>]) -> Vec<u8> {
    assert_eq!(session.authenticated_principal(), None);
    assert_eq!(session.active_command(), None);
    assert_ne!(*session.phase(), SessionPhase::ActiveChannel);
    assert_eq!(
        packets.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
        [
            msg::CHANNEL_FAILURE,
            msg::CHANNEL_EXTENDED_DATA,
            msg::CHANNEL_REQUEST,
            msg::CHANNEL_CLOSE,
        ],
        "denied exec emits no success or Git data",
    );
    let mut diagnostic = WireReader::new(&packets[1][1..]);
    assert_eq!(diagnostic.read_u32().unwrap(), 0);
    assert_eq!(diagnostic.read_u32().unwrap(), 1);
    let text = diagnostic.read_string().unwrap().to_vec();
    assert!(text.starts_with(b"ERR: "));
    let mut exit = WireReader::new(&packets[2][1..]);
    assert_eq!(exit.read_u32().unwrap(), 0);
    assert_eq!(exit.read_utf8().unwrap(), "exit-status");
    assert!(!exit.read_bool().unwrap());
    assert_eq!(exit.read_u32().unwrap(), 1);
    text
}

#[test]
fn a_key_added_after_userauth_can_authorize_its_first_exec() {
    let source = MutableAuthorizer::new(Vec::new());
    let (mut session, mut client) = ready(&source, 41);
    assert!(source.queries().is_empty(), "no startup membership lookup");

    source.replace(Ok(grants(0xa1, &[DeployKeyScope::Write])));
    let packets = exec(&mut session, &mut client, "git-receive-pack 'repo.git'");
    allowed(&session, &packets, 0xa1, SshGitService::ReceivePack);
    assert_eq!(
        source.queries(),
        [Query {
            key: peer_key().verifying_key().to_bytes(),
            repository: named_repository("repo.git"),
            service: SshGitService::ReceivePack,
        }],
    );
}

#[test]
fn revocation_between_userauth_and_exec_prevents_git_from_starting() {
    for revoke in [false, true] {
        let source = MutableAuthorizer::new(grants(0xa1, &[DeployKeyScope::Read]));
        let (mut session, mut client) = ready(&source, 42);
        assert!(source.queries().is_empty());
        if revoke {
            source.replace(Ok(Vec::new()));
        }
        let packets = exec(&mut session, &mut client, "git-upload-pack 'repo.git'");
        if revoke {
            refused(&session, &packets);
        } else {
            allowed(&session, &packets, 0xa1, SshGitService::UploadPack);
        }
        assert_eq!(source.queries().len(), 1);
    }
}

#[test]
fn a_scope_downgrade_preserves_read_and_refuses_write() {
    for service in [SshGitService::UploadPack, SshGitService::ReceivePack] {
        let source =
            MutableAuthorizer::new(grants(0xa1, &[DeployKeyScope::Read, DeployKeyScope::Write]));
        let (mut session, mut client) = ready(&source, 43);
        source.replace(Ok(grants(0xa1, &[DeployKeyScope::Read])));
        let command = match service {
            SshGitService::UploadPack => "git-upload-pack 'repo.git'",
            SshGitService::ReceivePack => "git-receive-pack 'repo.git'",
        };
        let packets = exec(&mut session, &mut client, command);
        if service == SshGitService::UploadPack {
            allowed(&session, &packets, 0xa1, service);
        } else {
            let diagnostic = refused(&session, &packets);
            assert!(String::from_utf8(diagnostic).unwrap().contains("write"));
        }
        assert_eq!(source.queries().len(), 1);
        assert_eq!(source.queries()[0].service, service);
    }
}

#[test]
fn principal_rotation_changes_new_execs_and_preserves_active_commands() {
    let source = MutableAuthorizer::new(grants(0xa1, &[DeployKeyScope::Write]));
    let (mut first, mut first_client) = ready(&source, 44);
    let packets = exec(&mut first, &mut first_client, "git-receive-pack 'repo.git'");
    allowed(&first, &packets, 0xa1, SshGitService::ReceivePack);

    let (mut next, mut next_client) = ready(&source, 45);
    source.replace(Ok(grants(0xb2, &[DeployKeyScope::Write])));
    let packets = exec(&mut next, &mut next_client, "git-receive-pack 'repo.git'");
    allowed(&next, &packets, 0xb2, SshGitService::ReceivePack);

    source.replace(Err(AuthRefusal::AuthorizationSourceUnavailable));
    let rejected = exec(&mut first, &mut first_client, "git-upload-pack 'repo.git'");
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0][0], msg::CHANNEL_FAILURE);
    assert_eq!(
        source.queries().len(),
        2,
        "no second authorization for one command"
    );
    assert_eq!(
        first.authenticated_principal(),
        Some(PrincipalId::from_bytes([0xa1; 16]))
    );
    assert_eq!(
        first.active_command().unwrap().service(),
        SshGitService::ReceivePack
    );
    assert_eq!(
        next.authenticated_principal(),
        Some(PrincipalId::from_bytes([0xb2; 16]))
    );
}

#[test]
fn unavailable_source_never_reuses_a_grant_and_recovery_accepts_current_grants() {
    let source = MutableAuthorizer::new(grants(0xa1, &[DeployKeyScope::Read]));
    let (mut first, mut first_client) = ready(&source, 46);
    let packets = exec(&mut first, &mut first_client, "git-upload-pack 'repo.git'");
    allowed(&first, &packets, 0xa1, SshGitService::UploadPack);

    source.replace(Err(AuthRefusal::AuthorizationSourceUnavailable));
    let (mut blocked, mut blocked_client) = ready(&source, 47);
    let packets = exec(
        &mut blocked,
        &mut blocked_client,
        "git-upload-pack 'repo.git'",
    );
    assert_eq!(
        refused(&blocked, &packets),
        b"ERR: SSH command authorization source is unavailable\n",
    );

    source.replace(Ok(grants(0xb2, &[DeployKeyScope::Read])));
    let (mut recovered, mut recovered_client) = ready(&source, 48);
    let packets = exec(
        &mut recovered,
        &mut recovered_client,
        "git-upload-pack 'repo.git'",
    );
    allowed(&recovered, &packets, 0xb2, SshGitService::UploadPack);
    assert_eq!(source.queries().len(), 3);
}

#[test]
fn invalid_signatures_and_commands_do_not_consult_the_authorizer() {
    let source = MutableAuthorizer::new(grants(0xa1, &[DeployKeyScope::Read]));
    let authorizer: Arc<dyn SshCommandAuthorizer> = source.clone();
    let (mut session, mut client, key) = key_exchange_with_authorizer(
        Arc::new(DetEntropy::new(49)),
        true,
        [0x33; 32],
        Some(authorizer),
    );
    let blob = encode_ed25519_public_key(&key.verifying_key().to_bytes());
    let preimage = build_userauth_signature_preimage(
        &session.session_id().unwrap(),
        "git",
        "ssh-connection",
        &blob,
    );
    let wrong_signer = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let signature = sign_ed25519(&wrong_signer, &preimage);
    let mut auth = WireWriter::new();
    auth.write_u8(msg::USERAUTH_REQUEST);
    auth.write_utf8("git");
    auth.write_utf8("ssh-connection");
    auth.write_utf8("publickey");
    auth.write_bool(true);
    auth.write_utf8("ssh-ed25519");
    auth.write_string(&blob);
    auth.write_string(&signature);
    client.send(&mut session, &auth.into_bytes());
    assert_eq!(
        client.receive_all(&mut session)[0][0],
        msg::USERAUTH_FAILURE
    );
    assert!(source.queries().is_empty());
    assert_eq!(session.authenticated_principal(), None);

    open_channel(&mut session, &mut client, &key, 4096, 1024);
    let packets = exec(&mut session, &mut client, "sh 'repo.git'");
    refused(&session, &packets);
    assert!(source.queries().is_empty());

    let (mut valid, mut valid_client) = ready(&source, 50);
    let packets = exec(&mut valid, &mut valid_client, "git-upload-pack 'repo.git'");
    allowed(&valid, &packets, 0xa1, SshGitService::UploadPack);
    assert_eq!(source.queries().len(), 1);
}

#[test]
fn unauthenticated_exec_is_rejected_before_authorization() {
    let source = MutableAuthorizer::new(grants(0xa1, &[DeployKeyScope::Read]));
    let authorizer: Arc<dyn SshCommandAuthorizer> = source.clone();
    let (mut session, mut client, _) = key_exchange_with_authorizer(
        Arc::new(DetEntropy::new(51)),
        true,
        [0x33; 32],
        Some(authorizer),
    );
    let wire = client
        .out
        .encrypt_packet(&exec_payload("git-upload-pack 'repo.git'"), &[0; 16]);
    assert!(matches!(
        session.handle_incoming_bytes(&wire),
        Err(SshSessionError::ProtocolViolation { .. })
    ));
    assert!(source.queries().is_empty());
    assert_eq!(session.authenticated_principal(), None);
    assert_eq!(session.active_command(), None);
}

#[test]
fn repository_selection_reaches_the_source_without_borrowing_another_grant() {
    for (path, repository, permitted) in [
        ("repo.git", named_repository("repo.git"), true),
        ("different.git", named_repository("different.git"), false),
        (
            "/11111111111111111111111111111111.git",
            RepositoryId::from_bytes([0x11; 16]),
            false,
        ),
    ] {
        let source = MutableAuthorizer::new(grants(0xa1, &[DeployKeyScope::Read]));
        let (mut session, mut client) = ready(&source, 52);
        let packets = exec(
            &mut session,
            &mut client,
            &format!("git-upload-pack '{path}'"),
        );
        if permitted {
            allowed(&session, &packets, 0xa1, SshGitService::UploadPack);
        } else {
            refused(&session, &packets);
        }
        assert_eq!(
            source.queries(),
            [Query {
                key: peer_key().verifying_key().to_bytes(),
                repository,
                service: SshGitService::UploadPack,
            }]
        );
    }
}

#[test]
fn the_existing_static_constructor_keeps_its_read_and_write_grants() {
    for (command, service) in [
        ("git-upload-pack 'repo.git'", SshGitService::UploadPack),
        ("git-receive-pack 'repo.git'", SshGitService::ReceivePack),
    ] {
        let (mut session, mut client, key) =
            key_exchange(Arc::new(DetEntropy::new(53)), false, [0x33; 32]);
        open_channel(&mut session, &mut client, &key, 4096, 1024);
        let packets = exec(&mut session, &mut client, command);
        allowed(&session, &packets, 0xab, service);
    }
}
