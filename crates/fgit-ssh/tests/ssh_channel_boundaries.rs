#![forbid(unsafe_code)]
//! Encrypted, transcript-verified regression tests for the single-channel boundary.
//! Both strict and legacy KEX run through the production SANS-I/O engine.

use std::sync::Arc;

use asupersync::util::DetEntropy;
use ed25519_dalek::SigningKey;
use fgit_crypto::sha256_digest;
use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyScope};
use fgit_ssh::auth::build_userauth_signature_preimage;
use fgit_ssh::crypto::{
    Curve25519Kex, OpenSshChaCha20Poly1305, derive_key, encode_ed25519_public_key,
    sign_ed25519, verify_ed25519,
};
use fgit_ssh::session::{
    DEFAULT_MAX_PACKET_SIZE, DEFAULT_WINDOW_SIZE, KEX_STRICT_CLIENT, SERVER_IDENTIFICATION,
    SessionPhase, SshServerSession, SshSessionError, msg,
};
use fgit_ssh::wire::{
    WireReader, WireWriter, decode_cleartext_packet, encode_cleartext_packet,
};
use fgit_types::{PrincipalId, RepositoryId};

const CLIENT_IDENT: &[u8] = b"SSH-2.0-FrankenGit-Boundary-Test\r\n";
const SEED: u64 = 0x4348_414e;

struct Peer {
    out: OpenSshChaCha20Poly1305,
    inbound: OpenSshChaCha20Poly1305,
    key: SigningKey,
    session_id: [u8; 32],
}

impl Peer {
    fn send(&mut self, session: &mut SshServerSession, payload: &[u8]) -> Result<(), SshSessionError> {
        session.handle_incoming_bytes(&self.out.encrypt_packet(payload, &[0; 16]))
    }

    fn receive(&mut self, session: &mut SshServerSession) -> Vec<Vec<u8>> {
        let wire = session.take_outgoing_bytes();
        let mut offset = 0;
        let mut packets = Vec::new();
        while offset < wire.len() {
            let length: [u8; 4] = wire[offset..offset + 4].try_into().unwrap();
            let total = 4 + self.inbound.decrypt_packet_length(&length) as usize + 16;
            packets.push(self.inbound.decrypt_packet(&wire[offset..offset + total]).unwrap());
            offset += total;
        }
        packets
    }

    fn authentication(&self, service: &str) -> Vec<u8> {
        let blob = encode_ed25519_public_key(&self.key.verifying_key().to_bytes());
        let preimage = build_userauth_signature_preimage(&self.session_id, "git", service, &blob);
        let signature = sign_ed25519(&self.key, &preimage);
        let mut w = WireWriter::new();
        w.write_u8(msg::USERAUTH_REQUEST);
        w.write_utf8("git");
        w.write_utf8(service);
        w.write_utf8("publickey");
        w.write_bool(true);
        w.write_utf8("ssh-ed25519");
        w.write_string(&blob);
        w.write_string(&signature);
        w.into_bytes()
    }
}

fn kexinit(strict: bool) -> Vec<u8> {
    let mut algorithms = vec!["curve25519-sha256"];
    if strict {
        algorithms.push(KEX_STRICT_CLIENT);
    }
    let mut w = WireWriter::new();
    w.write_u8(msg::KEXINIT);
    w.write_raw(&[0x5a; 16]);
    w.write_name_list(&algorithms);
    w.write_name_list(&["ssh-ed25519"]);
    w.write_name_list(&["chacha20-poly1305@openssh.com"]);
    w.write_name_list(&["chacha20-poly1305@openssh.com"]);
    w.write_name_list(&["none"]);
    w.write_name_list(&["none"]);
    w.write_name_list(&["none"]);
    w.write_name_list(&["none"]);
    w.write_name_list(&[]);
    w.write_name_list(&[]);
    w.write_bool(false);
    w.write_u32(0);
    w.into_bytes()
}

fn fresh() -> (SshServerSession, SigningKey, SigningKey) {
    let host = SigningKey::from_bytes(&[0x11; 32]);
    let key = SigningKey::from_bytes(&[0x22; 32]);
    let mut repo = [0u8; 16];
    repo.copy_from_slice(&sha256_digest(b"repo.git")[..16]);
    let binding = DeployKeyBinding::register(
        RepositoryId::from_bytes(repo),
        PrincipalId::from_bytes([0xab; 16]),
        fgit_crypto::VerifyingKey::from_bytes(key.verifying_key().to_bytes()),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .unwrap();
    (
        SshServerSession::new(host.clone(), vec![binding], Arc::new(DetEntropy::new(SEED))),
        host,
        key,
    )
}

/// Establish real bidirectional encryption and verify the host's transcript
/// signature. Return before SERVICE_REQUEST so tests can cover that boundary.
fn encrypted(strict: bool) -> (SshServerSession, Peer) {
    exchange(strict, true)
}

fn exchange(strict: bool, finish_newkeys: bool) -> (SshServerSession, Peer) {
    let (mut session, host, key) = fresh();
    session.start();
    assert_eq!(session.take_outgoing_bytes(), format!("{SERVER_IDENTIFICATION}\r\n").as_bytes());
    session.handle_incoming_bytes(CLIENT_IDENT).unwrap();
    let server_kex_wire = session.take_outgoing_bytes();
    let server_kex = decode_cleartext_packet(&server_kex_wire).unwrap();
    let client_kex = kexinit(strict);
    session.handle_incoming_bytes(&encode_cleartext_packet(&client_kex, &[0; 16])).unwrap();
    let ephemeral = Curve25519Kex::from_private_bytes([0x33; 32]);
    let mut init = WireWriter::new();
    init.write_u8(msg::KEX_ECDH_INIT);
    init.write_string(ephemeral.public_key());
    session.handle_incoming_bytes(&encode_cleartext_packet(&init.into_bytes(), &[0; 16])).unwrap();
    let wire = session.take_outgoing_bytes();
    let reply = decode_cleartext_packet(&wire).unwrap();
    let first_length = 4 + u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
    assert_eq!(decode_cleartext_packet(&wire[first_length..]).unwrap(), &[msg::NEWKEYS]);
    let mut r = WireReader::new(reply);
    assert_eq!(r.read_u8().unwrap(), msg::KEX_ECDH_REPLY);
    let host_blob = r.read_string().unwrap();
    let server_public: [u8; 32] = r.read_string().unwrap().try_into().unwrap();
    let signature = r.read_string().unwrap();
    let shared = ephemeral.compute_shared_secret(&server_public).unwrap();
    let mut k = WireWriter::new();
    k.write_mpint(&shared);
    let k = k.into_bytes();
    let mut h = WireWriter::new();
    h.write_string(&CLIENT_IDENT[..CLIENT_IDENT.len() - 2]);
    h.write_string(SERVER_IDENTIFICATION.as_bytes());
    h.write_string(&client_kex);
    h.write_string(server_kex);
    h.write_string(host_blob);
    h.write_string(ephemeral.public_key());
    h.write_string(&server_public);
    h.write_raw(&k);
    let hash = sha256_digest(&h.into_bytes());
    verify_ed25519(&host.verifying_key().to_bytes(), &hash, signature).unwrap();
    let c: [u8; 64] = derive_key(&k, &hash, b'C', &hash, 64).try_into().unwrap();
    let s: [u8; 64] = derive_key(&k, &hash, b'D', &hash, 64).try_into().unwrap();
    if finish_newkeys {
        session.handle_incoming_bytes(&encode_cleartext_packet(&[msg::NEWKEYS], &[0; 16])).unwrap();
    }
    assert_eq!(session.session_id(), Some(hash));
    let sequence = if strict { 0 } else { 3 };
    (
        session,
        Peer {
            out: OpenSshChaCha20Poly1305::new_with_sequence(&c, sequence),
            inbound: OpenSshChaCha20Poly1305::new_with_sequence(&s, sequence),
            key,
            session_id: hash,
        },
    )
}

fn authenticate(session: &mut SshServerSession, peer: &mut Peer) {
    let mut service = WireWriter::new();
    service.write_u8(msg::SERVICE_REQUEST);
    service.write_utf8("ssh-userauth");
    peer.send(session, &service.into_bytes()).unwrap();
    assert_eq!(peer.receive(session)[0][0], msg::SERVICE_ACCEPT);
    let auth = peer.authentication("ssh-connection");
    peer.send(session, &auth).unwrap();
    assert_eq!(peer.receive(session)[0][0], msg::USERAUTH_SUCCESS);
}

fn open_packet(peer_id: u32, window: u32, maximum: u32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(msg::CHANNEL_OPEN);
    w.write_utf8("session");
    w.write_u32(peer_id);
    w.write_u32(window);
    w.write_u32(maximum);
    w.into_bytes()
}

fn ready(strict: bool, peer_id: u32, window: u32) -> (SshServerSession, Peer) {
    let (mut session, mut peer) = encrypted(strict);
    authenticate(&mut session, &mut peer);
    peer.send(&mut session, &open_packet(peer_id, window, DEFAULT_MAX_PACKET_SIZE)).unwrap();
    let packets = peer.receive(&mut session);
    assert_eq!(packets.len(), 1);
    assert_channel_reply(&packets[0], msg::CHANNEL_OPEN_CONFIRMATION, peer_id);
    (session, peer)
}

fn channel_packet(kind: u8, recipient: u32, body: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(kind);
    w.write_u32(recipient);
    w.write_raw(body);
    w.into_bytes()
}

fn data_packet(recipient: u32, data: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_string(data);
    channel_packet(msg::CHANNEL_DATA, recipient, &w.into_bytes())
}

fn exec_packet(recipient: u32, command: &str) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_utf8("exec");
    w.write_bool(true);
    w.write_utf8(command);
    channel_packet(msg::CHANNEL_REQUEST, recipient, &w.into_bytes())
}

fn env_packet(recipient: u32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_utf8("env");
    w.write_bool(true);
    w.write_utf8("GIT_PROTOCOL");
    w.write_utf8("version=2");
    channel_packet(msg::CHANNEL_REQUEST, recipient, &w.into_bytes())
}

fn assert_channel_reply(packet: &[u8], kind: u8, recipient: u32) {
    let mut r = WireReader::new(packet);
    assert_eq!(r.read_u8().unwrap(), kind);
    assert_eq!(r.read_u32().unwrap(), recipient);
}

fn assert_protocol_refusal(result: Result<(), SshSessionError>) {
    assert!(matches!(result, Err(SshSessionError::ProtocolViolation { .. })), "{result:?}");
}

#[test]
fn connection_packets_cannot_bypass_encrypted_authentication() {
    for strict in [false, true] {
        let (mut session, mut peer) = encrypted(strict);
        assert_protocol_refusal(peer.send(&mut session, &open_packet(7, 1024, 1024)));
        assert_eq!(session.client_channel_id(), None);
        assert_eq!(session.authenticated_principal(), None);
        assert!(session.take_channel_input().is_empty());
        let (session, _) = ready(strict, 7, 1024);
        assert_eq!(session.client_channel_id(), Some(7));
    }
}

#[test]
fn replies_use_the_peer_channel_id_and_normal_lifecycle_survives_fragmentation() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 1024);
        peer.send(&mut session, &env_packet(0)).unwrap();
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_SUCCESS, 37);
        assert_eq!(session.git_protocol(), Some(b"version=2".as_slice()));
        let exec = exec_packet(0, "git-upload-pack 'repo.git'");
        let wire = peer.out.encrypt_packet(&exec, &[0; 16]);
        for byte in wire {
            session.handle_incoming_bytes(&[byte]).unwrap();
        }
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_SUCCESS, 37);
        assert_eq!(session.authenticated_principal(), Some(PrincipalId::from_bytes([0xab; 16])));
        peer.send(&mut session, &data_packet(0, b"0000")).unwrap();
        peer.send(&mut session, &channel_packet(msg::CHANNEL_EOF, 0, &[])).unwrap();
        assert_eq!(session.take_channel_input(), b"0000");
        assert!(session.is_channel_eof_received());
        assert_eq!(session.send_channel_data(b"response"), 8);
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_DATA, 37);
        session.send_channel_exit_and_close(0);
        let packets = peer.receive(&mut session);
        assert_eq!(packets.len(), 2);
        assert_channel_reply(&packets[0], msg::CHANNEL_REQUEST, 37);
        assert_channel_reply(&packets[1], msg::CHANNEL_CLOSE, 37);
        peer.send(&mut session, &channel_packet(msg::CHANNEL_CLOSE, 0, &[])).unwrap();
        assert!(session.is_channel_closed());
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert!(peer.receive(&mut session).is_empty(), "close is acknowledged once");
    }
}

#[test]
fn foreign_channel_ids_never_mutate_the_live_channel() {
    let hostile = [
        data_packet(99, b"injected Git request"),
        channel_packet(msg::CHANNEL_WINDOW_ADJUST, 99, &50u32.to_be_bytes()),
        channel_packet(msg::CHANNEL_EOF, 99, &[]),
        channel_packet(msg::CHANNEL_CLOSE, 99, &[]),
        env_packet(99),
        exec_packet(99, "git-receive-pack 'repo.git'"),
    ];
    for strict in [false, true] {
        for packet in &hostile {
            let (mut session, mut peer) = ready(strict, 37, 1024);
            assert_protocol_refusal(peer.send(&mut session, packet));
            assert_eq!(session.client_channel_id(), Some(37));
            assert_eq!(session.client_window(), 1024);
            assert!(!session.is_channel_eof_received());
            assert!(!session.is_channel_closed());
            assert!(session.active_command().is_none());
            assert_eq!(session.authenticated_principal(), None);
            assert_eq!(session.git_protocol(), None);
            assert!(session.take_channel_input().is_empty());
        }
    }
}

#[test]
fn additional_channel_and_exec_cannot_retarget_an_authorized_git_stream() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 1024);
        peer.send(&mut session, &exec_packet(0, "git-upload-pack 'repo.git'")).unwrap();
        peer.receive(&mut session);
        let principal = session.authenticated_principal();
        let command = session.active_command().unwrap().clone();
        peer.send(&mut session, &open_packet(99, 1, 1)).unwrap();
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_OPEN_FAILURE, 99);
        assert_eq!(session.client_channel_id(), Some(37));
        assert_eq!(session.client_window(), 1024);
        peer.send(&mut session, &exec_packet(0, "git-receive-pack 'repo.git'")).unwrap();
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_FAILURE, 37);
        assert_eq!(session.active_command().unwrap().service(), command.service());
        assert_eq!(session.authenticated_principal(), principal);
        peer.send(&mut session, &data_packet(0, b"still-original-stream")).unwrap();
        assert_eq!(session.take_channel_input(), b"still-original-stream");
    }
}

#[test]
fn malformed_eof_and_close_require_a_complete_recipient() {
    for strict in [false, true] {
        for kind in [msg::CHANNEL_EOF, msg::CHANNEL_CLOSE] {
            let (mut session, mut peer) = ready(strict, 37, 1024);
            assert!(peer.send(&mut session, &[kind, 0, 0]).is_err());
            assert!(!session.is_channel_eof_received());
            assert!(!session.is_channel_closed());
        }
    }
}

#[test]
fn input_after_eof_is_refused_but_half_closed_output_is_permitted() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 1024);
        peer.send(&mut session, &channel_packet(msg::CHANNEL_EOF, 0, &[])).unwrap();
        assert_eq!(session.send_channel_data(b"final"), 5);
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_DATA, 37);
        session.send_channel_extended_data(37, b"diagnostic");
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_EXTENDED_DATA, 37);
        session.send_channel_extended_data(99, b"wrong recipient");
        assert!(peer.receive(&mut session).is_empty());
        assert_protocol_refusal(peer.send(&mut session, &data_packet(0, b"late")));
        assert!(session.take_channel_input().is_empty());
    }
}

#[test]
fn channel_packet_and_window_limits_are_checked_before_mutation() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, u32::MAX - 1);
        let adjust = channel_packet(msg::CHANNEL_WINDOW_ADJUST, 0, &1u32.to_be_bytes());
        peer.send(&mut session, &adjust).unwrap();
        assert_eq!(session.client_window(), u32::MAX);
        assert_protocol_refusal(peer.send(&mut session, &adjust));
        assert_eq!(session.client_window(), u32::MAX);
        let (mut session, mut peer) = ready(strict, 37, DEFAULT_WINDOW_SIZE);
        let legal = vec![0x61; DEFAULT_MAX_PACKET_SIZE as usize];
        peer.send(&mut session, &data_packet(0, &legal)).unwrap();
        assert_eq!(session.take_channel_input(), legal);
        let oversized = vec![0x61; DEFAULT_MAX_PACKET_SIZE as usize + 1];
        assert_protocol_refusal(peer.send(&mut session, &data_packet(0, &oversized)));
        assert!(session.take_channel_input().is_empty());
    }
}

#[test]
fn zero_packet_channels_are_refused_without_poisoning_a_later_open() {
    for strict in [false, true] {
        let (mut session, mut peer) = encrypted(strict);
        authenticate(&mut session, &mut peer);
        peer.send(&mut session, &open_packet(37, 1024, 0)).unwrap();
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_OPEN_FAILURE, 37);
        assert_eq!(session.client_channel_id(), None);
        peer.send(&mut session, &open_packet(38, 1024, 1024)).unwrap();
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_OPEN_CONFIRMATION, 38);
    }
}

#[test]
fn closed_or_absent_channels_cannot_emit_more_data_or_repeated_close() {
    for strict in [false, true] {
        let (mut session, mut peer) = encrypted(strict);
        assert_eq!(session.send_channel_data(b"no channel"), 0);
        session.send_channel_eof();
        session.send_channel_extended_data(0, b"no channel");
        session.send_channel_exit_and_close(0);
        assert!(peer.receive(&mut session).is_empty());
        let (mut session, mut peer) = ready(strict, 37, 1024);
        session.send_channel_exit_and_close(0);
        assert_eq!(peer.receive(&mut session).len(), 2);
        session.send_channel_exit_and_close(0);
        assert_eq!(session.send_channel_data(b"closed"), 0);
        session.send_channel_eof();
        session.send_channel_extended_data(37, b"closed");
        assert!(peer.receive(&mut session).is_empty());
    }
}

#[test]
fn plaintext_service_and_premature_newkeys_are_terminal_refusals() {
    let mut service = WireWriter::new();
    service.write_u8(msg::SERVICE_REQUEST);
    service.write_utf8("ssh-userauth");
    for payload in [service.into_bytes(), vec![msg::NEWKEYS]] {
        let (mut session, _, _) = fresh();
        session.start();
        session.take_outgoing_bytes();
        session.handle_incoming_bytes(CLIENT_IDENT).unwrap();
        session.take_outgoing_bytes();
        assert_protocol_refusal(session.handle_incoming_bytes(&encode_cleartext_packet(&payload, &[0; 16])));
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert_eq!(session.session_id(), None);
        assert_eq!(session.authenticated_principal(), None);
        assert!(session.take_outgoing_bytes().is_empty());
        assert!(session.handle_incoming_bytes(&encode_cleartext_packet(&kexinit(false), &[0; 16])).is_err());
    }
    // Permitted twin: both legal KEX profiles still establish the channel.
    for strict in [false, true] {
        let (session, _) = ready(strict, 37, 1024);
        assert_eq!(*session.phase(), SessionPhase::ChannelReady);
    }
}

#[test]
fn a_signed_auth_request_requires_encrypted_service_negotiation() {
    for strict in [false, true] {
        let (mut session, mut peer) = encrypted(strict);
        let auth = peer.authentication("ssh-connection");
        assert_protocol_refusal(peer.send(&mut session, &auth));
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert_eq!(session.authenticated_principal(), None);
        assert!(peer.receive(&mut session).is_empty());
        let (mut session, mut peer) = encrypted(strict);
        authenticate(&mut session, &mut peer);
        assert_eq!(*session.phase(), SessionPhase::ChannelReady);
    }
}

#[test]
fn valid_signatures_for_other_services_do_not_authenticate_ssh_connection() {
    for strict in [false, true] {
        let (mut session, mut peer) = encrypted(strict);
        let mut service = WireWriter::new();
        service.write_u8(msg::SERVICE_REQUEST);
        service.write_utf8("ssh-userauth");
        peer.send(&mut session, &service.into_bytes()).unwrap();
        peer.receive(&mut session);
        let wrong_service = peer.authentication("unavailable-service");
        assert_protocol_refusal(peer.send(&mut session, &wrong_service));
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert_eq!(session.authenticated_principal(), None);
        assert!(peer.receive(&mut session).is_empty());
        // Main already treats a different authenticated service as terminal.
        // A fresh connection with the exact service remains the permitted twin.
        let (mut session, mut peer) = encrypted(strict);
        authenticate(&mut session, &mut peer);
        assert_eq!(*session.phase(), SessionPhase::ChannelReady);
    }
}

#[test]
fn successful_authentication_is_never_replaced_by_a_later_key() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 1024);
        peer.send(&mut session, &exec_packet(0, "git-upload-pack 'repo.git'")).unwrap();
        peer.receive(&mut session);
        let principal = session.authenticated_principal();
        let command = session.active_command().unwrap().clone();
        peer.key = SigningKey::from_bytes(&[0x55; 32]);
        let replacement = peer.authentication("ssh-connection");
        peer.send(&mut session, &replacement).unwrap();
        assert!(peer.receive(&mut session).is_empty(), "authentication success is sent once");
        assert_eq!(*session.phase(), SessionPhase::ActiveChannel);
        assert_eq!(session.authenticated_principal(), principal);
        assert_eq!(session.active_command(), Some(&command));
        peer.send(&mut session, &data_packet(0, b"original-authority")).unwrap();
        assert_eq!(session.take_channel_input(), b"original-authority");
    }
}

#[test]
fn duplicate_key_exchange_messages_cannot_restart_authentication() {
    for strict in [false, true] {
        let (mut session, _, _) = fresh();
        session.start();
        session.handle_incoming_bytes(CLIENT_IDENT).unwrap();
        let init = encode_cleartext_packet(&kexinit(strict), &[0; 16]);
        session.handle_incoming_bytes(&init).unwrap();
        assert_protocol_refusal(session.handle_incoming_bytes(&init));
        assert_eq!(session.session_id(), None);
        assert_eq!(*session.phase(), SessionPhase::Closed);
        let (mut session, mut peer) = encrypted(strict);
        assert_protocol_refusal(peer.send(&mut session, &[msg::NEWKEYS]));
        assert_eq!(*session.phase(), SessionPhase::Closed);
    }
}

#[test]
fn unsupported_rekey_cannot_reset_an_active_channel_to_userauth() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 1024);
        peer.send(&mut session, &exec_packet(0, "git-upload-pack 'repo.git'")).unwrap();
        peer.receive(&mut session);
        let session_id = session.session_id();
        let error = peer.send(&mut session, &kexinit(strict)).unwrap_err();
        assert!(matches!(error, SshSessionError::ProtocolViolation { ref reason }
            if reason.contains("unsupported rekey")));
        assert_eq!(session.session_id(), session_id);
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert!(session.active_command().is_none());
        assert!(peer.receive(&mut session).is_empty());
    }
}

#[test]
fn fatal_refusal_cannot_be_resumed_or_release_queued_git_input() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 1024);
        peer.send(&mut session, &exec_packet(0, "git-upload-pack 'repo.git'")).unwrap();
        peer.receive(&mut session);
        assert!(session.authenticated_principal().is_some());
        assert!(session.active_command().is_some());
        peer.send(&mut session, &data_packet(0, b"queued-before-refusal")).unwrap();
        assert_protocol_refusal(peer.send(&mut session, &data_packet(99, b"wrong-channel")));
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert!(session.take_channel_input().is_empty());
        assert!(session.authenticated_principal().is_none());
        assert!(session.active_command().is_none());
        assert!(matches!(
            peer.send(&mut session, &data_packet(0, b"resume")),
            Err(SshSessionError::Disconnected { .. })
        ));
        assert_eq!(session.send_channel_data(b"must-not-send"), 0);
        session.send_channel_eof();
        session.send_channel_extended_data(37, b"must-not-send");
        session.send_channel_exit_and_close(0);
        assert!(peer.receive(&mut session).is_empty());
    }
}

#[test]
fn strict_key_exchange_still_accepts_a_real_peer_disconnect() {
    let (mut session, _, _) = fresh();
    session.start();
    session.handle_incoming_bytes(CLIENT_IDENT).unwrap();
    session.handle_incoming_bytes(&encode_cleartext_packet(&kexinit(true), &[0; 16])).unwrap();
    let mut disconnect = WireWriter::new();
    disconnect.write_u8(msg::DISCONNECT);
    disconnect.write_u32(11);
    disconnect.write_utf8("client cancelled");
    disconnect.write_utf8("");
    let result = session.handle_incoming_bytes(&encode_cleartext_packet(&disconnect.into_bytes(), &[0; 16]));
    assert!(matches!(result, Err(SshSessionError::Disconnected { .. })));
    assert_eq!(*session.phase(), SessionPhase::Closed);
}

#[test]
fn pending_inbound_newkeys_does_not_authorize_cleartext_authentication() {
    for strict in [false, true] {
        for send_authentication in [false, true] {
            let (mut session, peer) = exchange(strict, false);
            // The exchange hash already exists and the signature is valid,
            // but the peer has not activated the inbound encrypted transport.
            let payload = if send_authentication {
                peer.authentication("ssh-connection")
            } else {
                let mut service = WireWriter::new();
                service.write_u8(msg::SERVICE_REQUEST);
                service.write_utf8("ssh-userauth");
                service.into_bytes()
            };
            let wire = encode_cleartext_packet(&payload, &[0; 16]);
            assert_protocol_refusal(session.handle_incoming_bytes(&wire));
            assert_eq!(*session.phase(), SessionPhase::Closed);
            assert_eq!(session.authenticated_principal(), None);
            assert!(session.take_outgoing_bytes().is_empty());
        }
        let (session, _) = ready(strict, 37, 1024);
        assert_eq!(*session.phase(), SessionPhase::ChannelReady);
    }
}

#[test]
fn draining_input_replenishes_only_an_open_receive_window() {
    for strict in [false, true] {
        // State zero is the live permitted twin; the other states close the
        // receive direction before the application drains its buffered input.
        for terminal in 0..4 {
            let (mut session, mut peer) = ready(strict, 37, 1024);
            let chunk = vec![b'x'; DEFAULT_MAX_PACKET_SIZE as usize];
            let chunks = DEFAULT_WINDOW_SIZE / 2 / DEFAULT_MAX_PACKET_SIZE;
            for _ in 0..chunks {
                peer.send(&mut session, &data_packet(0, &chunk)).unwrap();
            }
            match terminal {
                0 => {}
                1 => peer.send(&mut session, &channel_packet(msg::CHANNEL_EOF, 0, &[])).unwrap(),
                2 => session.send_channel_exit_and_close(0),
                3 => peer.send(&mut session, &channel_packet(msg::CHANNEL_CLOSE, 0, &[])).unwrap(),
                _ => unreachable!(),
            }
            peer.receive(&mut session);
            let input = session.take_channel_input();
            assert_eq!(input.len(), chunks as usize * chunk.len());
            assert!(input.iter().all(|byte| *byte == b'x'));
            let packets = peer.receive(&mut session);
            if terminal == 0 {
                assert_eq!(packets.len(), 1);
                assert_channel_reply(&packets[0], msg::CHANNEL_WINDOW_ADJUST, 37);
                let mut reader = WireReader::new(&packets[0][5..]);
                assert_eq!(reader.read_u32().unwrap(), DEFAULT_WINDOW_SIZE / 2);
                assert_eq!(reader.remaining(), 0);
            } else {
                assert!(packets.is_empty(), "draining a closed receive direction must not reopen it");
            }
        }
    }
}
