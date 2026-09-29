//! Real encrypted re-exchange transcripts, not manually installed server keys.
//! The parent fixture executes the initial ECDH and verifies the host signature.
use super::*;

fn offer(marker: bool, guess: bool) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(msg::KEXINIT);
    w.write_raw(&[0x5a; 16]);
    let mut algorithms = Vec::new();
    if guess {
        algorithms.push("unimplemented-kex@example.invalid");
    }
    algorithms.push("curve25519-sha256");
    if marker {
        algorithms.push(KEX_STRICT_CLIENT);
    }
    w.write_name_list(&algorithms);
    w.write_name_list(&["ssh-ed25519"]);
    for _ in 0..2 {
        w.write_name_list(&["chacha20-poly1305@openssh.com"]);
    }
    for _ in 0..4 {
        w.write_name_list(&["none"]);
    }
    w.write_name_list(&[]);
    w.write_name_list(&[]);
    w.write_bool(guess);
    w.write_u32(0);
    w.into_bytes()
}

fn packet(cipher: &mut OpenSshChaCha20Poly1305, wire: &mut &[u8]) -> Vec<u8> {
    assert!(wire.len() >= 20);
    let header = wire[..4].try_into().unwrap();
    let total = 4 + cipher.decrypt_packet_length(&header) as usize + 16;
    assert!(wire.len() >= total);
    let payload = cipher.decrypt_packet(&wire[..total]).unwrap();
    *wire = &wire[total..];
    payload
}

fn begin(session: &mut SshServerSession, peer: &mut Peer, server: bool, client: &[u8]) -> Vec<u8> {
    if server {
        session.request_rekey().unwrap();
        // Coalescing local requests must not generate a duplicate KEXINIT.
        session.request_rekey().unwrap();
        let offered = peer.receive(session);
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0][0], msg::KEXINIT);
        peer.send(session, client).unwrap();
        assert!(peer.receive(session).is_empty());
        offered.into_iter().next().unwrap()
    } else {
        peer.send(session, client).unwrap();
        let offered = peer.receive(session);
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0][0], msg::KEXINIT);
        offered.into_iter().next().unwrap()
    }
}

struct Exchanged {
    client_key: [u8; 64],
    exchange_hash: [u8; 32],
    server_public: [u8; 32],
    deferred: Vec<Vec<u8>>,
}

/// Consumes the old-key ECDH_REPLY/NEWKEYS, installs ONLY the client's receive
/// key and decodes any subsequent server output under that new receive key.
fn exchange_again(
    session: &mut SshServerSession,
    peer: &mut Peer,
    strict: bool,
    client_offer: &[u8],
    server_offer: &[u8],
    seed: u8,
) -> Exchanged {
    let ephemeral = Curve25519Kex::from_private_bytes([seed; 32]);
    let mut w = WireWriter::new();
    w.write_u8(msg::KEX_ECDH_INIT);
    w.write_string(ephemeral.public_key());
    // Header, ciphertext and MAC may each arrive in a different network read.
    let init = peer.out.encrypt_packet(&w.into_bytes(), &[0; 16]);
    for byte in init {
        session.handle_incoming_bytes(&[byte]).unwrap();
    }
    let wire = session.take_outgoing_bytes();
    let mut rest = wire.as_slice();
    let reply = packet(&mut peer.inbound, &mut rest);
    assert_eq!(packet(&mut peer.inbound, &mut rest), [msg::NEWKEYS]);
    let mut r = WireReader::new(&reply);
    assert_eq!(r.read_u8().unwrap(), msg::KEX_ECDH_REPLY);
    let host_blob = r.read_string().unwrap();
    let host = SigningKey::from_bytes(&[0x11; 32]);
    assert_eq!(
        host_blob,
        encode_ed25519_public_key(&host.verifying_key().to_bytes()).as_slice()
    );
    let server_public: [u8; 32] = r.read_string().unwrap().try_into().unwrap();
    let signature = r.read_string().unwrap();
    assert_eq!(r.remaining(), 0);
    let shared = ephemeral.compute_shared_secret(&server_public).unwrap();
    let mut k = WireWriter::new();
    k.write_mpint(&shared);
    let k = k.into_bytes();
    let mut h = WireWriter::new();
    h.write_string(&CLIENT_IDENT[..CLIENT_IDENT.len() - 2]);
    h.write_string(SERVER_IDENTIFICATION.as_bytes());
    h.write_string(client_offer);
    h.write_string(server_offer);
    h.write_string(host_blob);
    h.write_string(ephemeral.public_key());
    h.write_string(&server_public);
    h.write_raw(&k);
    let exchange_hash = sha256_digest(&h.into_bytes());
    verify_ed25519(&host.verifying_key().to_bytes(), &exchange_hash, signature).unwrap();
    // Crucially, key derivation uses the ORIGINAL session ID, not this H.
    let client_key = derive_key(&k, &exchange_hash, b'C', &peer.session_id, 64)
        .try_into()
        .unwrap();
    let server_key = derive_key(&k, &exchange_hash, b'D', &peer.session_id, 64)
        .try_into()
        .unwrap();
    let next = if strict {
        0
    } else {
        peer.inbound.sequence_number()
    };
    peer.inbound = OpenSshChaCha20Poly1305::new_with_sequence(&server_key, next);
    let mut deferred = Vec::new();
    while !rest.is_empty() {
        deferred.push(packet(&mut peer.inbound, &mut rest));
    }
    assert_eq!(session.session_id(), Some(peer.session_id));
    assert_ne!(exchange_hash, peer.session_id);
    assert!(
        session.is_rekeying(),
        "inbound NEWKEYS is still outstanding"
    );
    Exchanged {
        client_key,
        exchange_hash,
        server_public,
        deferred,
    }
}

/// The client's NEWKEYS is protected by its OLD send key. Only the following
/// bytes use the new one, including when both packets share a network read.
fn newkeys(peer: &mut Peer, keys: &Exchanged, strict: bool) -> Vec<u8> {
    let wire = peer.out.encrypt_packet(&[msg::NEWKEYS], &[0; 16]);
    let next = if strict {
        0
    } else {
        peer.out.sequence_number()
    };
    peer.out = OpenSshChaCha20Poly1305::new_with_sequence(&keys.client_key, next);
    wire
}

pub(super) fn round_trip(
    session: &mut SshServerSession,
    peer: &mut Peer,
    strict: bool,
    server: bool,
    seed: u8,
) {
    let client = offer(false, false); // strict extension is deliberately absent
    let offered = begin(session, peer, server, &client);
    let keys = exchange_again(session, peer, strict, &client, &offered, seed);
    assert!(keys.deferred.is_empty());
    let wire = newkeys(peer, &keys, strict);
    session.handle_incoming_bytes(&wire).unwrap();
    assert!(!session.is_rekeying());
    assert_eq!(session.strict_kex(), strict);
}

#[test]
fn repeated_peer_and_server_rekeys_keep_the_exact_command_windows_and_stream() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 4096);
        peer.send(&mut session, &env_packet(0)).unwrap();
        peer.send(&mut session, &exec_packet(0, "git-upload-pack 'repo.git'"))
            .unwrap();
        peer.receive(&mut session);
        let principal = session.authenticated_principal();
        let command = session.active_command().unwrap().clone();
        let mut previous_hash = peer.session_id;
        let mut previous_public = [0; 32];
        let mut previous_cookie = Vec::new();
        for round in 0..4 {
            peer.send(
                &mut session,
                &data_packet(0, b"preserved buffered Git input"),
            )
            .unwrap();
            let client = offer(!strict, false); // no upgrade or downgrade after initial KEX
            let offered = begin(&mut session, &mut peer, round % 2 == 1, &client);
            assert_ne!(&offered[1..17], previous_cookie.as_slice());
            previous_cookie = offered[1..17].to_vec();
            assert!(!String::from_utf8_lossy(&offered).contains("kex-strict"));
            assert_eq!(session.send_channel_data(b"blocked bulk"), 0);
            assert_eq!(session.client_window(), 4096 - round * 5);
            let keys = exchange_again(
                &mut session,
                &mut peer,
                strict,
                &client,
                &offered,
                0x40 + round as u8,
            );
            assert_ne!(keys.exchange_hash, previous_hash);
            assert_ne!(keys.server_public, previous_public);
            previous_hash = keys.exchange_hash;
            previous_public = keys.server_public;
            // Outbound traffic resumes after OUR NEWKEYS, independently of the
            // client's pending NEWKEYS and without resetting the remote window.
            assert_eq!(session.send_channel_data(b"hello"), 5);
            let replies = peer.receive(&mut session);
            assert_eq!(replies.len(), 1);
            assert_channel_reply(&replies[0], msg::CHANNEL_DATA, 37);
            let mut wire = newkeys(&mut peer, &keys, strict);
            wire.extend_from_slice(
                &peer
                    .out
                    .encrypt_packet(&data_packet(0, b"after rekey"), &[0; 16]),
            );
            for chunk in wire.chunks(3) {
                session.handle_incoming_bytes(chunk).unwrap();
            }
            assert!(!session.is_rekeying());
            assert_eq!(session.strict_kex(), strict);
            assert_eq!(*session.phase(), SessionPhase::ActiveChannel);
            assert_eq!(session.authenticated_principal(), principal);
            assert_eq!(session.active_command(), Some(&command));
            assert_eq!(session.git_protocol(), Some(b"version=2".as_slice()));
            assert_eq!(
                session.take_channel_input(),
                b"preserved buffered Git inputafter rekey"
            );
        }
    }
}

#[test]
fn server_initiation_accepts_in_flight_data_but_defers_application_replies() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 4096);
        session.request_rekey().unwrap();
        let offered = peer.receive(&mut session).remove(0);
        // This env was in flight before the peer observed our KEXINIT.
        peer.send(&mut session, &env_packet(0)).unwrap();
        peer.send(&mut session, &data_packet(0, b"in flight"))
            .unwrap();
        assert!(
            peer.receive(&mut session).is_empty(),
            "env response must wait"
        );
        assert_eq!(session.take_channel_input(), b"in flight");
        let client = offer(false, false);
        peer.send(&mut session, &client).unwrap();
        let keys = exchange_again(&mut session, &mut peer, strict, &client, &offered, 0x55);
        assert_eq!(keys.deferred.len(), 1);
        assert_channel_reply(&keys.deferred[0], msg::CHANNEL_SUCCESS, 37);
        let wire = newkeys(&mut peer, &keys, strict);
        session.handle_incoming_bytes(&wire).unwrap();
        peer.send(&mut session, &data_packet(0, b"resumed"))
            .unwrap();
        assert_eq!(session.take_channel_input(), b"resumed");
    }
}

#[test]
fn no_application_packet_can_cross_the_peers_kexinit_to_newkeys_interval() {
    for strict in [false, true] {
        for payload in [
            data_packet(0, b"too early"),
            env_packet(0),
            channel_packet(msg::CHANNEL_EOF, 0, &[]),
            channel_packet(msg::CHANNEL_WINDOW_ADJUST, 0, &1u32.to_be_bytes()),
            vec![msg::USERAUTH_REQUEST],
            vec![msg::NEWKEYS],
        ] {
            let (mut session, mut peer) = ready(strict, 37, 4096);
            begin(&mut session, &mut peer, false, &offer(false, false));
            assert!(peer.send(&mut session, &payload).is_err());
            assert_eq!(*session.phase(), SessionPhase::Closed);
            assert!(session.take_channel_input().is_empty());
            assert!(session.terminal_error().is_some());
        }
        // Every refused case has a real complete re-exchange counterpart.
        let (mut session, mut peer) = ready(strict, 37, 4096);
        round_trip(&mut session, &mut peer, strict, false, 0x56);
        peer.send(&mut session, &data_packet(0, b"permitted"))
            .unwrap();
        assert_eq!(session.take_channel_input(), b"permitted");
    }
}

#[test]
fn deferred_stderr_eof_and_exit_status_follow_newkeys_in_order() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 4096);
        let client = offer(false, false);
        let offered = begin(&mut session, &mut peer, false, &client);
        session.send_channel_extended_data(37, b"diagnostic");
        session.send_channel_eof();
        session.send_channel_exit_and_close(7);
        assert!(peer.receive(&mut session).is_empty());
        let keys = exchange_again(&mut session, &mut peer, strict, &client, &offered, 0x57);
        assert_eq!(keys.deferred.len(), 4);
        for (payload, kind) in keys.deferred.iter().zip([
            msg::CHANNEL_EXTENDED_DATA,
            msg::CHANNEL_EOF,
            msg::CHANNEL_REQUEST,
            msg::CHANNEL_CLOSE,
        ]) {
            assert_channel_reply(payload, kind, 37);
        }
        let mut exit = WireReader::new(&keys.deferred[2][5..]);
        assert_eq!(exit.read_utf8().unwrap(), "exit-status");
        assert!(!exit.read_bool().unwrap());
        assert_eq!(exit.read_u32().unwrap(), 7);
        session
            .handle_incoming_bytes(&newkeys(&mut peer, &keys, strict))
            .unwrap();
        peer.send(&mut session, &channel_packet(msg::CHANNEL_CLOSE, 0, &[]))
            .unwrap();
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert!(peer.receive(&mut session).is_empty());
    }
}

#[test]
fn old_ciphertext_and_a_premature_new_send_key_are_not_accepted() {
    for strict in [false, true] {
        for premature in [false, true] {
            let (mut session, mut peer) = ready(strict, 37, 4096);
            let client = offer(false, false);
            let offered = begin(&mut session, &mut peer, false, &client);
            let keys = exchange_again(&mut session, &mut peer, strict, &client, &offered, 0x58);
            let mut old = peer.out.clone();
            let switch = newkeys(&mut peer, &keys, strict);
            let payload = data_packet(0, b"wrong key epoch");
            let hostile = if premature {
                peer.out.encrypt_packet(&payload, &[0; 16])
            } else {
                session.handle_incoming_bytes(&switch).unwrap();
                old.encrypt_packet(&payload, &[0; 16])
            };
            assert!(session.handle_incoming_bytes(&hostile).is_err());
            assert_eq!(*session.phase(), SessionPhase::Closed);
            assert!(session.take_channel_input().is_empty());
        }
    }
}

#[test]
fn authentication_after_rekey_still_signs_the_original_session_identifier() {
    for strict in [false, true] {
        let (mut session, mut peer) = encrypted(strict);
        let client = offer(false, false);
        let offered = begin(&mut session, &mut peer, false, &client);
        let keys = exchange_again(&mut session, &mut peer, strict, &client, &offered, 0x59);
        session
            .handle_incoming_bytes(&newkeys(&mut peer, &keys, strict))
            .unwrap();
        assert_eq!(*session.phase(), SessionPhase::UserAuth);
        authenticate(&mut session, &mut peer);
        peer.send(&mut session, &open_packet(37, 1024, 1024))
            .unwrap();
        peer.receive(&mut session);
        peer.send(&mut session, &exec_packet(0, "git-upload-pack 'repo.git'"))
            .unwrap();
        assert!(session.authenticated_principal().is_some());
    }
}

#[test]
fn guessed_key_exchange_discards_exactly_one_packet_without_authentication_effects() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 4096);
        let client = offer(false, true);
        let offered = begin(&mut session, &mut peer, false, &client);
        let auth = peer.authentication("ssh-connection");
        peer.send(&mut session, &auth).unwrap();
        assert!(peer.receive(&mut session).is_empty());
        let keys = exchange_again(&mut session, &mut peer, strict, &client, &offered, 0x5a);
        session
            .handle_incoming_bytes(&newkeys(&mut peer, &keys, strict))
            .unwrap();
        assert_eq!(*session.phase(), SessionPhase::ChannelReady);
        peer.send(&mut session, &data_packet(0, b"only Git input"))
            .unwrap();
        assert_eq!(session.take_channel_input(), b"only Git input");
    }
}

#[test]
fn a_crossed_peer_close_is_acknowledged_only_after_the_outbound_key_switch() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 4096);
        session.request_rekey().unwrap();
        let offered = peer.receive(&mut session).remove(0);
        peer.send(&mut session, &channel_packet(msg::CHANNEL_CLOSE, 0, &[]))
            .unwrap();
        assert!(session.is_channel_closed());
        assert_ne!(*session.phase(), SessionPhase::Closed);
        assert!(peer.receive(&mut session).is_empty());
        let client = offer(false, false);
        peer.send(&mut session, &client).unwrap();
        let keys = exchange_again(&mut session, &mut peer, strict, &client, &offered, 0x5b);
        assert_eq!(keys.deferred.len(), 1);
        assert_channel_reply(&keys.deferred[0], msg::CHANNEL_CLOSE, 37);
        session
            .handle_incoming_bytes(&newkeys(&mut peer, &keys, strict))
            .unwrap();
        assert_eq!(*session.phase(), SessionPhase::Closed);
        assert!(session.terminal_error().is_none());
    }
}

#[test]
fn control_queue_has_exact_byte_and_packet_bounds_and_fails_closed() {
    for by_bytes in [false, true] {
        for over in [false, true] {
            let (mut session, mut peer) = ready(true, 37, DEFAULT_WINDOW_SIZE);
            let client = offer(false, false);
            let offered = begin(&mut session, &mut peer, false, &client);
            let (count, data) = if by_bytes {
                (2, vec![b'x'; 32755])
            } else {
                (128, Vec::new())
            };
            for _ in 0..count {
                session.send_channel_extended_data(37, &data);
            }
            assert!(session.terminal_error().is_none());
            assert!(peer.receive(&mut session).is_empty());
            if over {
                session.send_channel_extended_data(37, b"one more");
                assert_eq!(*session.phase(), SessionPhase::Closed);
                assert!(
                    session
                        .terminal_error()
                        .unwrap()
                        .to_string()
                        .contains("budget")
                );
                assert!(session.authenticated_principal().is_none());
                assert!(session.active_command().is_none());
                assert_eq!(session.send_channel_data(b"no restart"), 0);
            } else {
                let keys = exchange_again(&mut session, &mut peer, true, &client, &offered, 0x5c);
                assert_eq!(keys.deferred.len(), count);
                session
                    .handle_incoming_bytes(&newkeys(&mut peer, &keys, true))
                    .unwrap();
                assert!(session.terminal_error().is_none());
            }
        }
    }
}

#[test]
fn unsupported_or_duplicate_rekey_offers_are_terminal_but_do_not_replace_identity() {
    for strict in [false, true] {
        for duplicate in [false, true] {
            let (mut session, mut peer) = ready(strict, 37, 4096);
            let id = session.session_id();
            let mut client = offer(false, false);
            if duplicate {
                begin(&mut session, &mut peer, false, &client);
            } else {
                // Same-length unsupported KEX name, with a complete valid frame.
                let at = client
                    .windows(b"curve25519-sha256".len())
                    .position(|w| w == b"curve25519-sha256")
                    .unwrap();
                client[at] = b'x';
            }
            assert!(peer.send(&mut session, &client).is_err());
            assert_eq!(session.session_id(), id);
            assert_eq!(*session.phase(), SessionPhase::Closed);
            assert!(session.active_command().is_none());
            assert!(peer.receive(&mut session).is_empty());
        }
    }
}

#[test]
fn receive_window_credit_is_deferred_without_losing_consumed_input() {
    let (mut session, mut peer) = ready(true, 37, DEFAULT_WINDOW_SIZE);
    let data = vec![b'x'; DEFAULT_MAX_PACKET_SIZE as usize];
    for _ in 0..(DEFAULT_WINDOW_SIZE / 2 / DEFAULT_MAX_PACKET_SIZE) {
        peer.send(&mut session, &data_packet(0, &data)).unwrap();
    }
    let client = offer(false, false);
    let offered = begin(&mut session, &mut peer, false, &client);
    assert_eq!(
        session.take_channel_input().len(),
        DEFAULT_WINDOW_SIZE as usize / 2
    );
    assert!(peer.receive(&mut session).is_empty());
    let keys = exchange_again(&mut session, &mut peer, true, &client, &offered, 0x5d);
    assert_eq!(keys.deferred.len(), 1);
    assert_channel_reply(&keys.deferred[0], msg::CHANNEL_WINDOW_ADJUST, 37);
    let mut credit = WireReader::new(&keys.deferred[0][5..]);
    assert_eq!(credit.read_u32().unwrap(), DEFAULT_WINDOW_SIZE / 2);
    assert_eq!(credit.remaining(), 0);
    session
        .handle_incoming_bytes(&newkeys(&mut peer, &keys, true))
        .unwrap();
    assert!(session.take_channel_input().is_empty());
    assert!(
        peer.receive(&mut session).is_empty(),
        "credit is not sent twice"
    );
}

#[test]
fn key_rotation_does_not_reopen_authentication_or_authorize_a_second_exec() {
    for strict in [false, true] {
        let (mut session, mut peer) = ready(strict, 37, 4096);
        peer.send(&mut session, &exec_packet(0, "git-upload-pack 'repo.git'"))
            .unwrap();
        peer.receive(&mut session);
        let principal = session.authenticated_principal();
        let command = session.active_command().unwrap().clone();
        round_trip(&mut session, &mut peer, strict, true, 0x5e);
        peer.key = SigningKey::from_bytes(&[0x44; 32]);
        let auth = peer.authentication("ssh-connection");
        peer.send(&mut session, &auth).unwrap();
        assert!(peer.receive(&mut session).is_empty());
        peer.send(&mut session, &exec_packet(0, "git-receive-pack 'repo.git'"))
            .unwrap();
        assert_channel_reply(&peer.receive(&mut session)[0], msg::CHANNEL_FAILURE, 37);
        assert_eq!(session.authenticated_principal(), principal);
        assert_eq!(session.active_command(), Some(&command));
        peer.send(&mut session, &data_packet(0, b"original stream"))
            .unwrap();
        assert_eq!(session.take_channel_input(), b"original stream");
    }
}
