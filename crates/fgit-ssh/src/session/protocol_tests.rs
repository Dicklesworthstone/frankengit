//! Packet-level regression tests. The fixture installs already-exchanged
//! transport keys; ssh_session_flow/ssh_session_security exercise real ECDH.

use super::*;
use crate::auth::build_userauth_signature_preimage;
use fgit_identity::deploy_key::DeployKeyScope;

const REMOTE_CHANNEL: u32 = 37;
const SESSION_ID: [u8; 32] = [0x55; 32];
const CLIENT_KEY: [u8; 64] = [0x61; 64];
const SERVER_KEY: [u8; 64] = [0x62; 64];

struct Peer {
    out: OpenSshChaCha20Poly1305,
    inbound: OpenSshChaCha20Poly1305,
}

impl Peer {
    fn send(&mut self, session: &mut SshServerSession, payload: &[u8]) -> Result<(), SshSessionError> {
        session.handle_incoming_bytes(&self.out.encrypt_packet(payload, &[0; 16]))
    }

    fn receive(&mut self, session: &mut SshServerSession) -> Vec<Vec<u8>> {
        let wire = session.take_outgoing_bytes();
        let mut rest = wire.as_slice();
        let mut packets = Vec::new();
        while !rest.is_empty() {
            let length: [u8; 4] = rest[..4].try_into().expect("packet length");
            let total = 4 + self.inbound.decrypt_packet_length(&length) as usize + 16;
            packets.push(self.inbound.decrypt_packet(&rest[..total]).expect("authenticated response"));
            rest = &rest[total..];
        }
        packets
    }
}

fn transport() -> (SshServerSession, Peer) {
    let signing = SigningKey::from_bytes(&[0x22; 32]);
    let digest = sha256_digest(b"repo.git");
    let repo = RepositoryId::from_bytes(digest[..16].try_into().expect("repository id"));
    let binding = DeployKeyBinding::register(
        repo,
        PrincipalId::from_bytes([0xab; 16]),
        fgit_crypto::VerifyingKey::from_bytes(signing.verifying_key().to_bytes()),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    ).expect("binding");
    let mut session = SshServerSession::new(
        SigningKey::from_bytes(&[0x11; 32]),
        vec![binding],
        Arc::new(asupersync::util::DetEntropy::new(7)),
    );
    session.phase = SessionPhase::UserAuth;
    session.session_id = Some(SESSION_ID);
    session.inbound_cipher = Some(OpenSshChaCha20Poly1305::new_with_sequence(&CLIENT_KEY, 0));
    session.outbound_cipher = Some(OpenSshChaCha20Poly1305::new_with_sequence(&SERVER_KEY, 0));
    session.userauth_service_accepted = true;
    let peer = Peer {
        out: OpenSshChaCha20Poly1305::new_with_sequence(&CLIENT_KEY, 0),
        inbound: OpenSshChaCha20Poly1305::new_with_sequence(&SERVER_KEY, 0),
    };
    (session, peer)
}

fn auth(seed: u8, service: &str) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let blob = encode_ed25519_public_key(&key.verifying_key().to_bytes());
    let signature = sign_ed25519(&key, &build_userauth_signature_preimage(&SESSION_ID, "git", service, &blob));
    let mut w = WireWriter::new();
    w.write_u8(msg::USERAUTH_REQUEST);
    w.write_utf8("git");
    w.write_utf8(service);
    w.write_utf8("publickey");
    w.write_bool(true);
    w.write_utf8(SSH_ED25519_ALGORITHM);
    w.write_string(&blob);
    w.write_string(&signature);
    w.into_bytes()
}

fn open(remote: u32, window: u32, maximum: u32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(msg::CHANNEL_OPEN);
    w.write_utf8("session");
    w.write_u32(remote);
    w.write_u32(window);
    w.write_u32(maximum);
    w.into_bytes()
}

fn channel_message(kind: u8, channel: u32) -> WireWriter {
    let mut w = WireWriter::new();
    w.write_u8(kind);
    w.write_u32(channel);
    w
}

fn data(channel: u32, bytes: &[u8]) -> Vec<u8> {
    let mut w = channel_message(msg::CHANNEL_DATA, channel);
    w.write_string(bytes);
    w.into_bytes()
}

fn request(channel: u32, command: &str, reply: bool) -> Vec<u8> {
    let mut w = channel_message(msg::CHANNEL_REQUEST, channel);
    w.write_utf8("exec");
    w.write_bool(reply);
    w.write_utf8(command);
    w.into_bytes()
}

fn env(channel: u32, name: &str) -> Vec<u8> {
    let mut w = channel_message(msg::CHANNEL_REQUEST, channel);
    w.write_utf8("env");
    w.write_bool(true);
    w.write_utf8(name);
    w.write_utf8("version=2");
    w.into_bytes()
}

fn authenticate(session: &mut SshServerSession, peer: &mut Peer) {
    peer.send(session, &auth(0x22, "ssh-connection")).expect("valid authentication");
    assert_eq!(peer.receive(session), vec![vec![msg::USERAUTH_SUCCESS]]);
    assert_eq!(session.phase, SessionPhase::ChannelReady);
}

fn connected() -> (SshServerSession, Peer) {
    let (mut session, mut peer) = transport();
    authenticate(&mut session, &mut peer);
    peer.send(&mut session, &open(REMOTE_CHANNEL, DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE)).expect("open");
    let response = peer.receive(&mut session);
    assert_eq!(response.len(), 1);
    assert_eq!(response[0][0], msg::CHANNEL_OPEN_CONFIRMATION);
    (session, peer)
}

fn assert_response_channel(packet: &[u8], kind: u8, channel: u32) {
    let mut r = WireReader::new(packet);
    assert_eq!(r.read_u8().expect("message kind"), kind);
    assert_eq!(r.read_u32().expect("recipient channel"), channel);
}

fn assert_protocol_refusal(result: Result<(), SshSessionError>) {
    assert!(matches!(result, Err(SshSessionError::ProtocolViolation { .. })), "{result:?}");
}

#[test]
fn every_connection_message_requires_authentication_and_an_actual_channel() {
    for kind in [msg::CHANNEL_DATA, msg::CHANNEL_WINDOW_ADJUST, msg::CHANNEL_REQUEST, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE] {
        let packet = match kind {
            msg::CHANNEL_DATA => data(0, b"git input"),
            msg::CHANNEL_WINDOW_ADJUST => {
                let mut w = channel_message(kind, 0);
                w.write_u32(1);
                w.into_bytes()
            }
            msg::CHANNEL_REQUEST => env(0, "GIT_PROTOCOL"),
            _ => channel_message(kind, 0).into_bytes(),
        };
        let (mut session, mut peer) = transport();
        assert_protocol_refusal(peer.send(&mut session, &packet));
        assert!(session.channel_input_data.is_empty());
        assert_eq!(session.phase, SessionPhase::Closed);

        // Authenticated but unopened is a different invalid state.
        let (mut session, mut peer) = transport();
        authenticate(&mut session, &mut peer);
        assert_protocol_refusal(peer.send(&mut session, &packet));
        assert!(session.client_channel_id.is_none());

        // The same bytes are legal once that exact channel exists.
        let (mut session, mut peer) = connected();
        peer.send(&mut session, &packet).expect("permitted channel twin");
    }
    let (mut session, mut peer) = transport();
    assert_protocol_refusal(peer.send(&mut session, &open(REMOTE_CHANNEL, 100, 40)));
    assert!(session.client_channel_id.is_none());
}

#[test]
fn userauth_requires_inbound_newkeys_even_for_legacy_non_strict_clients() {
    let (mut session, _) = transport();
    session.inbound_cipher = None;
    session.pending_inbound_key = Some(CLIENT_KEY);
    assert_protocol_refusal(session.handle_incoming_bytes(&encode_cleartext_packet(&auth(0x22, "ssh-connection"), &[0; 16])));
    assert!(session.authenticated_key.is_none());
    let (mut session, mut peer) = transport();
    authenticate(&mut session, &mut peer);
}

#[test]
fn authentication_is_bound_to_both_requested_services() {
    let (mut session, mut peer) = transport();
    session.userauth_service_accepted = false;
    assert_protocol_refusal(peer.send(&mut session, &auth(0x22, "ssh-connection")));

    let (mut session, mut peer) = transport();
    session.userauth_service_accepted = false;
    let mut service = WireWriter::new();
    service.write_u8(msg::SERVICE_REQUEST);
    service.write_utf8("ssh-userauth");
    peer.send(&mut session, &service.into_bytes()).expect("service request");
    assert_eq!(peer.receive(&mut session)[0][0], msg::SERVICE_ACCEPT);
    authenticate(&mut session, &mut peer);

    let (mut session, mut peer) = transport();
    assert_protocol_refusal(peer.send(&mut session, &auth(0x22, "not-ssh-connection")));
    assert!(session.authenticated_key.is_none());
}

#[test]
fn successful_authentication_and_exec_cannot_be_replaced() {
    let (mut session, mut peer) = connected();
    peer.send(&mut session, &request(0, "git-upload-pack 'repo.git'", true)).expect("first exec");
    assert_response_channel(&peer.receive(&mut session)[0], msg::CHANNEL_SUCCESS, REMOTE_CHANNEL);
    let key = session.authenticated_key;
    let principal = session.authenticated_principal;
    assert!(principal.is_some());

    // A valid signature by a different key used to reset the phase and key.
    peer.send(&mut session, &auth(0x44, "ssh-connection")).expect("late auth is ignored");
    assert!(peer.receive(&mut session).is_empty());
    assert_eq!(session.authenticated_key, key);
    assert_eq!(session.phase, SessionPhase::ActiveChannel);

    for reply in [true, false] {
        peer.send(&mut session, &request(0, "git-receive-pack 'repo.git'", reply)).expect("second exec refused without closing worker");
        let responses = peer.receive(&mut session);
        if reply {
            assert_eq!(responses.len(), 1);
            assert_response_channel(&responses[0], msg::CHANNEL_FAILURE, REMOTE_CHANNEL);
        } else {
            assert!(responses.is_empty());
        }
        assert_eq!(session.authenticated_principal, principal);
        assert_eq!(session.active_command.as_ref().expect("original command").service(), crate::command::SshGitService::UploadPack);
    }
    peer.send(&mut session, &data(0, b"still the original worker")).expect("original channel remains usable");
    assert_eq!(session.take_channel_input(), b"still the original worker".to_vec());
}

#[test]
fn another_channel_is_refused_without_overwriting_the_first() {
    let (mut session, mut peer) = connected();
    peer.send(&mut session, &open(99, 1, 40)).expect("channel-open refusal response");
    let responses = peer.receive(&mut session);
    assert_eq!(responses.len(), 1);
    assert_response_channel(&responses[0], msg::CHANNEL_OPEN_FAILURE, 99);
    assert_eq!(session.client_channel_id, Some(REMOTE_CHANNEL));
    assert_eq!(session.client_window_size, DEFAULT_WINDOW_SIZE);
    peer.send(&mut session, &data(0, b"first channel")).expect("first channel is intact");
    assert_eq!(session.take_channel_input(), b"first channel".to_vec());
}

#[test]
fn local_and_remote_channel_identifiers_are_never_interchangeable() {
    for kind in [msg::CHANNEL_DATA, msg::CHANNEL_WINDOW_ADJUST, msg::CHANNEL_REQUEST, msg::CHANNEL_EOF, msg::CHANNEL_CLOSE] {
        let (mut session, mut peer) = connected();
        let packet = match kind {
            msg::CHANNEL_DATA => data(REMOTE_CHANNEL, b"wrong channel"),
            msg::CHANNEL_WINDOW_ADJUST => {
                let mut w = channel_message(kind, REMOTE_CHANNEL);
                w.write_u32(1);
                w.into_bytes()
            }
            msg::CHANNEL_REQUEST => env(REMOTE_CHANNEL, "GIT_PROTOCOL"),
            _ => channel_message(kind, REMOTE_CHANNEL).into_bytes(),
        };
        assert_protocol_refusal(peer.send(&mut session, &packet));
        assert!(session.channel_input_data.is_empty());
        assert_eq!(session.client_window_size, DEFAULT_WINDOW_SIZE);
        assert!(!session.channel_teardown.eof_received);
        assert!(!session.channel_teardown.close_received);
    }
    let (mut session, mut peer) = connected();
    for (name, kind) in [("GIT_PROTOCOL", msg::CHANNEL_SUCCESS), ("LD_PRELOAD", msg::CHANNEL_FAILURE)] {
        peer.send(&mut session, &env(0, name)).expect("properly addressed request");
        assert_response_channel(&peer.receive(&mut session)[0], kind, REMOTE_CHANNEL);
    }
    peer.send(&mut session, &request(0, "not-a-git-command", true)).expect("typed exec refusal");
    let responses = peer.receive(&mut session);
    assert_eq!(responses.len(), 4);
    for (packet, kind) in responses.iter().zip([msg::CHANNEL_FAILURE, msg::CHANNEL_EXTENDED_DATA, msg::CHANNEL_REQUEST, msg::CHANNEL_CLOSE]) {
        assert_response_channel(packet, kind, REMOTE_CHANNEL);
    }
}

#[test]
fn malformed_or_trailing_packets_do_not_mutate_or_leave_a_resumable_session() {
    let valid = channel_message(msg::CHANNEL_EOF, 0).into_bytes();
    for packet in [vec![msg::CHANNEL_EOF], [valid.as_slice(), &[1]].concat(), [data(0, b"uncommitted input").as_slice(), &[1]].concat()] {
        let (mut session, mut peer) = connected();
        assert!(peer.send(&mut session, &packet).is_err());
        assert!(!session.channel_teardown.eof_received);
        assert!(session.channel_input_data.is_empty());
        assert_eq!(session.phase, SessionPhase::Closed);
        assert!(matches!(peer.send(&mut session, &data(0, b"retry")), Err(SshSessionError::Disconnected { .. })));
        assert_eq!(session.send_channel_data(b"late output"), 0);
    }
    let (mut session, mut peer) = connected();
    peer.send(&mut session, &valid).expect("well-formed EOF");
    assert!(session.channel_teardown.eof_received);
}

#[test]
fn advertised_packet_limit_and_eof_are_enforced_before_buffering() {
    for size in [DEFAULT_MAX_PACKET_SIZE as usize, DEFAULT_MAX_PACKET_SIZE as usize + 1] {
        let (mut session, mut peer) = connected();
        let bytes = vec![b'x'; size];
        let result = peer.send(&mut session, &data(0, &bytes));
        if size == DEFAULT_MAX_PACKET_SIZE as usize {
            result.expect("exact packet ceiling is accepted");
            assert_eq!(session.take_channel_input(), bytes);
        } else {
            assert_protocol_refusal(result);
            assert!(session.channel_input_data.is_empty());
            assert_eq!(session.server_window_size, DEFAULT_WINDOW_SIZE);
        }
    }
    let (mut session, mut peer) = connected();
    peer.send(&mut session, &channel_message(msg::CHANNEL_EOF, 0).into_bytes()).expect("EOF");
    assert_protocol_refusal(peer.send(&mut session, &data(0, b"after EOF")));
    assert!(session.channel_input_data.is_empty());
}

#[test]
fn window_overflow_is_refused_but_the_exact_uint32_boundary_is_valid() {
    for increment in [1, 2] {
        let (mut session, mut peer) = connected();
        session.client_window_size = u32::MAX - 1;
        let mut w = channel_message(msg::CHANNEL_WINDOW_ADJUST, 0);
        w.write_u32(increment);
        let result = peer.send(&mut session, &w.into_bytes());
        if increment == 1 {
            result.expect("exact boundary");
            assert_eq!(session.client_window_size, u32::MAX);
        } else {
            assert_protocol_refusal(result);
            assert_eq!(session.client_window_size, u32::MAX - 1);
        }
    }
}

#[test]
fn unusable_packet_sizes_do_not_create_a_channel_and_a_usable_retry_succeeds() {
    let (mut session, mut peer) = transport();
    authenticate(&mut session, &mut peer);
    for maximum in [0, CHANNEL_DATA_OVERHEAD] {
        peer.send(&mut session, &open(REMOTE_CHANNEL, 100, maximum)).expect("open refusal");
        assert_response_channel(&peer.receive(&mut session)[0], msg::CHANNEL_OPEN_FAILURE, REMOTE_CHANNEL);
        assert!(session.client_channel_id.is_none());
    }
    peer.send(&mut session, &open(REMOTE_CHANNEL, 100, CHANNEL_DATA_OVERHEAD + 1)).expect("usable retry");
    assert_response_channel(&peer.receive(&mut session)[0], msg::CHANNEL_OPEN_CONFIRMATION, REMOTE_CHANNEL);
    assert_eq!(session.send_channel_data(b"xy"), 2);
    for packet in peer.receive(&mut session) {
        assert_eq!(packet.len(), CHANNEL_DATA_OVERHEAD as usize + 1);
    }
}

#[test]
fn unsolicited_newkeys_and_rekey_do_not_reset_an_authenticated_session() {
    for kind in [msg::NEWKEYS, msg::KEXINIT, msg::KEX_ECDH_INIT] {
        let (mut session, mut peer) = connected();
        assert_protocol_refusal(peer.send(&mut session, &[kind]));
        assert_eq!(session.session_id, Some(SESSION_ID));
        assert_eq!(session.phase, SessionPhase::Closed);
    }
    // A pending first NEWKEYS is accepted, unlike the unsolicited messages.
    let (mut session, mut peer) = transport();
    session.inbound_cipher = None;
    session.pending_inbound_key = Some(CLIENT_KEY);
    session.strict_kex = true;
    session.handle_incoming_bytes(&encode_cleartext_packet(&[msg::NEWKEYS], &[0; 16])).expect("pending initial NEWKEYS");
    authenticate(&mut session, &mut peer);
}
