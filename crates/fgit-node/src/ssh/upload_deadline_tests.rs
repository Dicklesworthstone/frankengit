//! Encrypted channel-window regressions for terminal upload reporting.

use super::*;
use asupersync::util::DetEntropy;
use fgit_crypto::sha256_digest;
use fgit_identity::deploy_key::DeployKeyScope;
use fgit_ssh::auth::build_userauth_signature_preimage;
use fgit_ssh::crypto::{
    Curve25519Kex, OpenSshChaCha20Poly1305, derive_key, encode_ed25519_public_key, sign_ed25519,
    verify_ed25519,
};
use fgit_ssh::session::{DEFAULT_MAX_PACKET_SIZE, KEX_STRICT_CLIENT, SERVER_IDENTIFICATION, msg};
use fgit_ssh::wire::{WireReader, WireWriter, decode_cleartext_packet, encode_cleartext_packet};
use fgit_types::PrincipalId;
use std::time::Instant;

const CLIENT_IDENT: &[u8] = b"SSH-2.0-FrankenGit-Upload-Deadline-Test\r\n";
const PEER_CHANNEL: u32 = 37;
// One Fatal sideband packet followed by flush, before any pack bytes.
const REPORT: &[u8] = b"000c\x03failed\n0000";

struct Peer {
    outbound: OpenSshChaCha20Poly1305,
    inbound: OpenSshChaCha20Poly1305,
}

impl Peer {
    fn round_trip(&mut self, session: &mut SshServerSession, payload: &[u8]) -> Vec<u8> {
        session
            .handle_incoming_bytes(&self.outbound.encrypt_packet(payload, &[0; 16]))
            .unwrap();
        let wire = session.take_outgoing_bytes();
        let length: [u8; 4] = wire[..4].try_into().unwrap();
        assert_eq!(
            wire.len(),
            4 + self.inbound.decrypt_packet_length(&length) as usize + 16,
            "the setup exchange must produce exactly one packet"
        );
        self.inbound.decrypt_packet(&wire).unwrap()
    }

    fn send(&mut self, stream: &mut TcpStream, payload: &[u8]) {
        stream
            .write_all(&self.outbound.encrypt_packet(payload, &[0; 16]))
            .unwrap();
    }

    fn receive(&mut self, stream: &mut TcpStream) -> Vec<u8> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).unwrap();
        let packet_len = self.inbound.decrypt_packet_length(&length) as usize;
        assert!(packet_len <= 64 * 1024, "unexpectedly large test response");
        let mut packet = vec![0u8; 4 + packet_len + 16];
        packet[..4].copy_from_slice(&length);
        stream.read_exact(&mut packet[4..]).unwrap();
        self.inbound.decrypt_packet(&packet).unwrap()
    }
}

fn channel_packet(kind: u8) -> WireWriter {
    let mut packet = WireWriter::new();
    packet.write_u8(kind);
    packet.write_u32(0); // The server's channel, distinct from PEER_CHANNEL.
    packet
}

/// A transcript-verified strict KEX and real deploy-key authorization, adapted
/// from fgit-ssh's channel-boundary tests. No channel internals are overridden.
fn active_channel() -> (SshServerSession, Peer) {
    let host = SigningKey::from_bytes(&[0x11; 32]);
    let key = SigningKey::from_bytes(&[0x22; 32]);
    let mut repo = [0u8; 16];
    repo.copy_from_slice(&sha256_digest(b"repo.git")[..16]);
    let principal = PrincipalId::from_bytes([0xab; 16]);
    let binding = DeployKeyBinding::register(
        RepositoryId::from_bytes(repo),
        principal,
        fgit_crypto::VerifyingKey::from_bytes(key.verifying_key().to_bytes()),
        &[DeployKeyScope::Read],
    )
    .unwrap();
    let mut session = SshServerSession::new(
        host.clone(),
        vec![binding],
        Arc::new(DetEntropy::new(0x5550_4c44)),
    );
    session.start();
    assert_eq!(
        session.take_outgoing_bytes(),
        format!("{SERVER_IDENTIFICATION}\r\n").as_bytes()
    );
    session.handle_incoming_bytes(CLIENT_IDENT).unwrap();
    let server_kex_wire = session.take_outgoing_bytes();
    let server_kex = decode_cleartext_packet(&server_kex_wire).unwrap();
    let mut client_kex = WireWriter::new();
    client_kex.write_u8(msg::KEXINIT);
    client_kex.write_raw(&[0x5a; 16]);
    client_kex.write_name_list(&["curve25519-sha256", KEX_STRICT_CLIENT]);
    client_kex.write_name_list(&["ssh-ed25519"]);
    for _ in 0..2 {
        client_kex.write_name_list(&["chacha20-poly1305@openssh.com"]);
    }
    for _ in 0..4 {
        client_kex.write_name_list(&["none"]);
    }
    for _ in 0..2 {
        client_kex.write_name_list(&[]);
    }
    client_kex.write_bool(false);
    client_kex.write_u32(0);
    let client_kex = client_kex.into_bytes();
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&client_kex, &[0; 16]))
        .unwrap();
    let ephemeral = Curve25519Kex::from_private_bytes([0x33; 32]);
    let mut init = WireWriter::new();
    init.write_u8(msg::KEX_ECDH_INIT);
    init.write_string(ephemeral.public_key());
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&init.into_bytes(), &[0; 16]))
        .unwrap();
    let reply_wire = session.take_outgoing_bytes();
    let reply = decode_cleartext_packet(&reply_wire).unwrap();
    let reply_len = 4 + u32::from_be_bytes(reply_wire[..4].try_into().unwrap()) as usize;
    assert_eq!(
        decode_cleartext_packet(&reply_wire[reply_len..]).unwrap(),
        &[msg::NEWKEYS]
    );
    let mut reader = WireReader::new(reply);
    assert_eq!(reader.read_u8().unwrap(), msg::KEX_ECDH_REPLY);
    let host_blob = reader.read_string().unwrap();
    let server_public: [u8; 32] = reader.read_string().unwrap().try_into().unwrap();
    let signature = reader.read_string().unwrap();
    let shared = ephemeral.compute_shared_secret(&server_public).unwrap();
    let mut encoded_shared = WireWriter::new();
    encoded_shared.write_mpint(&shared);
    let encoded_shared = encoded_shared.into_bytes();
    let mut exchange = WireWriter::new();
    exchange.write_string(&CLIENT_IDENT[..CLIENT_IDENT.len() - 2]);
    exchange.write_string(SERVER_IDENTIFICATION.as_bytes());
    exchange.write_string(&client_kex);
    exchange.write_string(server_kex);
    exchange.write_string(host_blob);
    exchange.write_string(ephemeral.public_key());
    exchange.write_string(&server_public);
    exchange.write_raw(&encoded_shared);
    let hash = sha256_digest(&exchange.into_bytes());
    verify_ed25519(&host.verifying_key().to_bytes(), &hash, signature).unwrap();
    let outbound: [u8; 64] = derive_key(&encoded_shared, &hash, b'C', &hash, 64)
        .try_into()
        .unwrap();
    let inbound: [u8; 64] = derive_key(&encoded_shared, &hash, b'D', &hash, 64)
        .try_into()
        .unwrap();
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&[msg::NEWKEYS], &[0; 16]))
        .unwrap();
    assert!(session.strict_kex());
    assert_eq!(session.session_id(), Some(hash));
    let mut peer = Peer {
        outbound: OpenSshChaCha20Poly1305::new_with_sequence(&outbound, 0),
        inbound: OpenSshChaCha20Poly1305::new_with_sequence(&inbound, 0),
    };
    let mut service = WireWriter::new();
    service.write_u8(msg::SERVICE_REQUEST);
    service.write_utf8("ssh-userauth");
    assert_eq!(
        peer.round_trip(&mut session, &service.into_bytes())[0],
        msg::SERVICE_ACCEPT
    );
    let blob = encode_ed25519_public_key(&key.verifying_key().to_bytes());
    let preimage = build_userauth_signature_preimage(&hash, "git", "ssh-connection", &blob);
    let signature = sign_ed25519(&key, &preimage);
    let mut auth = WireWriter::new();
    auth.write_u8(msg::USERAUTH_REQUEST);
    auth.write_utf8("git");
    auth.write_utf8("ssh-connection");
    auth.write_utf8("publickey");
    auth.write_bool(true);
    auth.write_utf8("ssh-ed25519");
    auth.write_string(&blob);
    auth.write_string(&signature);
    assert_eq!(
        peer.round_trip(&mut session, &auth.into_bytes()),
        [msg::USERAUTH_SUCCESS]
    );
    let mut open = WireWriter::new();
    open.write_u8(msg::CHANNEL_OPEN);
    open.write_utf8("session");
    open.write_u32(PEER_CHANNEL);
    open.write_u32(0); // No output is possible until a real WINDOW_ADJUST.
    open.write_u32(DEFAULT_MAX_PACKET_SIZE);
    let confirmation = peer.round_trip(&mut session, &open.into_bytes());
    let mut confirmation = WireReader::new(&confirmation);
    assert_eq!(
        confirmation.read_u8().unwrap(),
        msg::CHANNEL_OPEN_CONFIRMATION
    );
    assert_eq!(confirmation.read_u32().unwrap(), PEER_CHANNEL);
    assert_eq!(confirmation.read_u32().unwrap(), 0);
    let mut exec = channel_packet(msg::CHANNEL_REQUEST);
    exec.write_utf8("exec");
    exec.write_bool(true);
    exec.write_utf8("git-upload-pack 'repo.git'");
    let accepted = peer.round_trip(&mut session, &exec.into_bytes());
    let mut accepted = WireReader::new(&accepted);
    assert_eq!(accepted.read_u8().unwrap(), msg::CHANNEL_SUCCESS);
    assert_eq!(accepted.read_u32().unwrap(), PEER_CHANNEL);
    assert_eq!(session.phase(), &SessionPhase::ActiveChannel);
    assert_eq!(session.authenticated_principal(), Some(principal));
    assert_eq!(session.client_window(), 0);
    (session, peer)
}

struct Connection {
    state: RefCell<SshConnectionState>,
    peer: Peer,
    client: TcpStream,
    work: GitDaemonSessionDeadline,
}

fn connected(timeout: Duration) -> Connection {
    let (session, peer) = active_channel();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut work = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(timeout).unwrap(),
        GitDaemonSessionWorkScaling::FLAT,
    );
    work.started = Instant::now()
        .checked_sub(timeout)
        .and_then(|instant| instant.checked_sub(Duration::from_secs(1)))
        .expect("test clock supports the expired work deadline");
    Connection {
        state: RefCell::new(SshConnectionState {
            session,
            stream,
            deadline: work.clone(),
            read_buf: Vec::new(),
            read_pos: 0,
        }),
        peer,
        client,
        work,
    }
}

#[test]
fn terminal_fatal_waits_for_encrypted_window_adjust_without_admitting_git_input() {
    let mut connection = connected(Duration::from_secs(5));
    let mut writer = SshWriter(&connection.state);
    assert_eq!(
        writer.write(REPORT).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    connection.work.begin_terminal_response();
    let pending_git = b"unconsumed git input";
    let mut input = channel_packet(msg::CHANNEL_DATA);
    input.write_string(pending_git);
    connection
        .peer
        .send(&mut connection.client, &input.into_bytes());
    let mut adjust = channel_packet(msg::CHANNEL_WINDOW_ADJUST);
    adjust.write_u32(u32::try_from(REPORT.len()).unwrap());
    connection
        .peer
        .send(&mut connection.client, &adjust.into_bytes());
    writer.write_all(REPORT).unwrap();
    writer.flush().unwrap();
    let packet = connection.peer.receive(&mut connection.client);
    let mut packet = WireReader::new(&packet);
    assert_eq!(packet.read_u8().unwrap(), msg::CHANNEL_DATA);
    assert_eq!(packet.read_u32().unwrap(), PEER_CHANNEL);
    assert_eq!(packet.read_string().unwrap(), REPORT);
    assert_eq!(packet.remaining(), 0);
    assert_eq!(
        SshReader(&connection.state)
            .read(&mut [0u8; 32])
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(connection.work.expired());
    assert_eq!(
        connection
            .work
            .shared
            .admitted_bytes
            .load(Ordering::Relaxed),
        0
    );
    let mut state = connection.state.borrow_mut();
    assert_eq!(state.session.client_window(), 0);
    assert_eq!(state.session.take_channel_input(), pending_git);
    assert!(state.read_buf.is_empty());
}

#[test]
fn peer_close_stops_a_terminal_fatal_while_its_channel_window_is_empty() {
    let mut connection = connected(Duration::from_secs(5));
    connection.work.begin_terminal_response();
    connection.peer.send(
        &mut connection.client,
        &channel_packet(msg::CHANNEL_CLOSE).into_bytes(),
    );
    let error = SshWriter(&connection.state).write_all(REPORT).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let packet = connection.peer.receive(&mut connection.client);
    let mut packet = WireReader::new(&packet);
    assert_eq!(packet.read_u8().unwrap(), msg::CHANNEL_CLOSE);
    assert_eq!(packet.read_u32().unwrap(), PEER_CHANNEL);
    assert_eq!(packet.remaining(), 0);
    assert!(connection.state.borrow().session.is_channel_closed());
    assert!(connection.work.expired());
    assert_eq!(
        connection
            .work
            .shared
            .admitted_bytes
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn a_silent_encrypted_channel_cannot_hold_terminal_output_past_its_allowance() {
    let connection = connected(Duration::from_millis(40));
    connection.work.begin_terminal_response();
    let started = Instant::now();
    let error = SshWriter(&connection.state).write_all(REPORT).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(connection.state.borrow().session.client_window(), 0);
    assert!(connection.work.expired());
    assert_eq!(
        connection
            .work
            .shared
            .admitted_bytes
            .load(Ordering::Relaxed),
        0
    );
}
