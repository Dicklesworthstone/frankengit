//! Framing and negotiation boundary twins, including coalesced NEWKEYS and
//! encrypted service packets. Transport fixtures are not substitutes for the
//! separate complete ECDH/signature interoperability tests.

use super::*;

const CLIENT_KEY: [u8; 64] = [0x61; 64];
const SERVER_KEY: [u8; 64] = [0x62; 64];

fn fresh() -> SshServerSession {
    SshServerSession::new(
        SigningKey::from_bytes(&[0x11; 32]),
        Vec::new(),
        Arc::new(asupersync::util::DetEntropy::new(19)),
    )
}

fn identified() -> SshServerSession {
    let mut session = fresh();
    session.handle_incoming_bytes(b"SSH-2.0-test_1\r\n").expect("identification");
    let _ = session.take_outgoing_bytes();
    session
}

fn ready() -> SshServerSession {
    let mut session = fresh();
    session.phase = SessionPhase::ChannelReady;
    session.session_id = Some([0x55; 32]);
    session.authenticated_key = Some([0x22; 32]);
    session.client_channel_id = Some(37);
    session.inbound_cipher = Some(OpenSshChaCha20Poly1305::new_with_sequence(&CLIENT_KEY, 0));
    session.outbound_cipher = Some(OpenSshChaCha20Poly1305::new_with_sequence(&SERVER_KEY, 0));
    session
}

fn lists() -> [&'static str; 10] {
    [
        KEX_CURVE25519_SHA256, SSH_ED25519_ALGORITHM,
        CIPHER_CHACHA20_POLY1305, CIPHER_CHACHA20_POLY1305,
        "hmac-sha2-256", "hmac-sha2-512", "none", "none", "", "",
    ]
}

fn kex(lists: [&str; 10], follows: bool) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(msg::KEXINIT);
    w.write_raw(&[0x5a; 16]);
    for list in lists { w.write_utf8(list); }
    w.write_bool(follows);
    w.write_u32(0);
    w.into_bytes()
}

fn clear(session: &mut SshServerSession, payload: &[u8]) -> Result<(), SshSessionError> {
    session.handle_incoming_bytes(&encode_cleartext_packet(payload, &[0; 16]))
}

fn ecdh() -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(msg::KEX_ECDH_INIT);
    w.write_string(Curve25519Kex::from_private_bytes([0x33; 32]).public_key());
    w.into_bytes()
}

fn channel_data(bytes: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(msg::CHANNEL_DATA);
    w.write_u32(0);
    w.write_string(bytes);
    w.into_bytes()
}

#[test]
fn every_required_algorithm_offer_is_enforced_before_creating_a_transcript() {
    for (index, unsupported) in [
        (0, "diffie-hellman-group14-sha256"), (1, "ssh-rsa"),
        (2, "aes256-ctr"), (3, "aes256-ctr"), (6, "zlib"), (7, "zlib"),
    ] {
        let mut offer = lists();
        offer[index] = unsupported;
        let mut session = identified();
        assert!(matches!(clear(&mut session, &kex(offer, false)), Err(SshSessionError::ProtocolViolation { .. })));
        assert!(session.client_kexinit_payload.is_none());
        assert!(session.ephemeral_kex.is_none());
        assert!(session.take_outgoing_bytes().is_empty());
    }
    // AEAD does not require a common separately advertised MAC.
    let mut session = identified();
    clear(&mut session, &kex(lists(), false)).expect("supported directional offers");
    assert!(session.ephemeral_kex.is_some());
    clear(&mut session, &ecdh()).expect("negotiated ECDH");
    assert!(session.session_id.is_some());
}

#[test]
fn empty_and_malformed_name_lists_and_extension_only_kex_are_refused() {
    for bad in [
        "", "curve25519-sha256,", ",curve25519-sha256",
        "curve25519-sha256,,other", "curve25519-sha256,bad name",
        "curve25519-sha256,\u{03bb}", KEX_STRICT_CLIENT,
    ] {
        let mut offer = lists();
        offer[0] = bad;
        assert!(clear(&mut identified(), &kex(offer, false)).is_err());
    }
    for index in 0..8 {
        let mut offer = lists();
        offer[index] = "";
        assert!(clear(&mut identified(), &kex(offer, false)).is_err());
    }
    let mut offer = lists();
    offer[0] = "unsupported,curve25519-sha256@libssh.org";
    offer[8] = "en-US,en-GB";
    let mut session = identified();
    clear(&mut session, &kex(offer, false)).expect("supported legacy alias and languages");
    clear(&mut session, &ecdh()).expect("no guessed packet to skip");
    assert!(session.session_id.is_some());
}

#[test]
fn every_truncated_kex_and_invalid_tail_is_refused_without_partial_negotiation() {
    let packet = kex(lists(), false);
    for end in 0..packet.len() {
        let mut session = identified();
        assert!(clear(&mut session, &packet[..end]).is_err(), "truncation at {end}");
        assert!(session.client_kexinit_payload.is_none());
        assert!(session.ephemeral_kex.is_none());
    }
    let mut trailing = packet.clone();
    trailing.push(0);
    let mut reserved = packet.clone();
    *reserved.last_mut().expect("reserved field") = 1;
    let mut boolean = packet.clone();
    let flag = boolean.len() - 5; // final boolean is followed by one uint32
    boolean[flag] = 2;
    for malformed in [trailing, reserved, boolean] {
        assert!(clear(&mut identified(), &malformed).is_err());
    }
    clear(&mut identified(), &packet).expect("complete canonical KEXINIT");
}

#[test]
fn wrong_guesses_discard_exactly_one_packet_and_correct_guesses_are_processed() {
    for strict in [false, true] {
        for wrong_host in [false, true] {
            let mut offer = lists();
            offer[0] = if strict {
                "unsupported,curve25519-sha256,kex-strict-c-v00@openssh.com"
            } else { "unsupported,curve25519-sha256" };
            if wrong_host {
                offer[0] = if strict {
                    "curve25519-sha256,kex-strict-c-v00@openssh.com"
                } else { KEX_CURVE25519_SHA256 };
                offer[1] = "ssh-rsa,ssh-ed25519";
            }
            let mut session = identified();
            clear(&mut session, &kex(offer, true)).expect("KEXINIT with a wrong guess");
            // A discarded payload must have no application side effects.
            let mut service = WireWriter::new();
            service.write_u8(msg::SERVICE_REQUEST);
            service.write_utf8("ssh-userauth");
            clear(&mut session, &service.into_bytes()).expect("discard exactly one guessed packet");
            assert!(!session.userauth_service_accepted);
            assert!(session.session_id.is_none());
            assert!(!session.discard_next_kex_packet);
            clear(&mut session, &ecdh()).expect("actual negotiated ECDH is processed");
            assert!(session.session_id.is_some());
        }
    }
    let mut session = identified();
    clear(&mut session, &kex(lists(), true)).expect("correct guess");
    clear(&mut session, &ecdh()).expect("correct guessed ECDH is not skipped");
    assert!(session.session_id.is_some());
}

#[test]
fn identification_is_validated_and_the_255_byte_limit_has_an_exact_twin() {
    for invalid in [
        &b"not-ssh\r\n"[..], &b"SSH-1.5-old\r\n"[..], &b"SSH-2.0-\r\n"[..],
        &b"SSH-2.0- version\r\n"[..], &b"SSH-2.0-x\0\r\n"[..], &b"SSH-2.0-x\ry\n"[..],
    ] {
        let mut session = fresh();
        assert!(session.handle_incoming_bytes(invalid).is_err());
        assert!(session.client_ident.is_none());
        assert!(session.take_outgoing_bytes().is_empty());
    }
    let mut exact = b"SSH-2.0-".to_vec();
    exact.extend(vec![b'A'; MAX_IDENTIFICATION_BYTES - exact.len() - 2]);
    exact.extend_from_slice(b"\r\n");
    assert_eq!(exact.len(), MAX_IDENTIFICATION_BYTES);
    let mut session = fresh();
    for byte in &exact {
        session.handle_incoming_bytes(&[*byte]).expect("fragmented exact-limit banner");
    }
    assert_eq!(session.phase, SessionPhase::KeyExchange);
    exact.insert(exact.len() - 2, b'A');
    assert!(fresh().handle_incoming_bytes(&exact).is_err());
    fresh().handle_incoming_bytes(b"SSH-2.0-test comment\n").expect("legacy LF and printable comment");
}

#[test]
fn huge_invalid_bursts_are_rejected_without_copying_the_body() {
    let mut banner = fresh();
    assert!(banner.handle_incoming_bytes(&vec![b'A'; 1024 * 1024]).is_err());
    assert!(banner.incoming_buffer.capacity() <= 2 * MAX_IDENTIFICATION_BYTES);

    let mut input = u32::MAX.to_be_bytes().to_vec();
    input.extend(vec![0; 1024 * 1024]);
    let mut session = identified();
    assert!(matches!(session.handle_incoming_bytes(&input), Err(SshSessionError::Wire(WireError::PacketTooLarge { .. }))));
    assert!(session.incoming_buffer.capacity() <= 2 * MAX_IDENTIFICATION_BYTES);

    // The encrypted header alone suffices to reject an oversized declaration.
    let mut cipher = OpenSshChaCha20Poly1305::new_with_sequence(&CLIENT_KEY, 0);
    let oversized = cipher.encrypt_packet(&vec![0; MAX_PACKET_BYTES + 1], &[0; 16]);
    let mut session = ready();
    assert!(matches!(session.handle_incoming_bytes(&oversized[..4]), Err(SshSessionError::Wire(WireError::PacketTooLarge { .. }))));
    assert!(session.incoming_buffer.capacity() <= 2 * MAX_IDENTIFICATION_BYTES);

    let mut session = identified();
    session.handle_incoming_bytes(&(MAX_PACKET_BYTES as u32).to_be_bytes()).expect("legal incomplete frame waits for its body");
    assert_eq!(session.incoming_buffer.len(), 4);
}

#[test]
fn banner_and_kex_are_independent_of_every_input_split() {
    let offer = kex(lists(), false);
    let mut wire = b"SSH-2.0-fragmented\r\n".to_vec();
    wire.extend(encode_cleartext_packet(&offer, &[0; 16]));
    for split in 0..=wire.len() {
        let mut session = fresh();
        session.handle_incoming_bytes(&wire[..split]).expect("prefix");
        session.handle_incoming_bytes(&wire[split..]).expect("suffix");
        assert_eq!(session.client_kexinit_payload.as_deref(), Some(offer.as_slice()));
        assert!(session.incoming_buffer.is_empty());
        assert!(session.ephemeral_kex.is_some());
    }
}

#[test]
fn newkeys_switches_framing_even_inside_one_burst_or_at_any_split() {
    let mut service = WireWriter::new();
    service.write_u8(msg::SERVICE_REQUEST);
    service.write_utf8("ssh-userauth");
    let mut cipher = OpenSshChaCha20Poly1305::new_with_sequence(&CLIENT_KEY, 0);
    let mut wire = encode_cleartext_packet(&[msg::NEWKEYS], &[0; 16]);
    wire.extend(cipher.encrypt_packet(&service.into_bytes(), &[0; 16]));
    for split in 0..=wire.len() {
        let mut session = fresh();
        session.phase = SessionPhase::UserAuth;
        session.session_id = Some([0x55; 32]);
        session.pending_inbound_key = Some(CLIENT_KEY);
        session.outbound_cipher = Some(OpenSshChaCha20Poly1305::new_with_sequence(&SERVER_KEY, 0));
        session.strict_kex = true;
        session.handle_incoming_bytes(&wire[..split]).expect("prefix across NEWKEYS");
        session.handle_incoming_bytes(&wire[split..]).expect("suffix across NEWKEYS");
        assert!(session.userauth_service_accepted);
        assert!(session.incoming_buffer.is_empty());
        assert!(session.pending_inbound_key.is_none());
        let mut inbound = OpenSshChaCha20Poly1305::new_with_sequence(&SERVER_KEY, 0);
        assert_eq!(inbound.decrypt_packet(&session.take_outgoing_bytes()).expect("service response")[0], msg::SERVICE_ACCEPT);
    }
}

#[test]
fn encrypted_channel_frames_preserve_data_at_every_fragment_boundary() {
    let mut cipher = OpenSshChaCha20Poly1305::new_with_sequence(&CLIENT_KEY, 0);
    let mut wire = cipher.encrypt_packet(&channel_data(b"first"), &[0; 16]);
    wire.extend(cipher.encrypt_packet(&channel_data(b"second"), &[0; 16]));
    for split in 0..=wire.len() {
        let mut session = ready();
        session.handle_incoming_bytes(&wire[..split]).expect("encrypted prefix");
        session.handle_incoming_bytes(&wire[split..]).expect("encrypted suffix");
        assert_eq!(session.take_channel_input(), b"firstsecond".to_vec());
        assert!(session.incoming_buffer.is_empty());
    }
}

#[test]
fn a_large_legal_coalesced_burst_retains_only_one_wire_frame_at_a_time() {
    let mut cipher = OpenSshChaCha20Poly1305::new_with_sequence(&CLIENT_KEY, 0);
    let chunk = vec![0x61; 30 * 1024];
    let packet = channel_data(&chunk);
    let mut wire = Vec::new();
    for _ in 0..64 { wire.extend(cipher.encrypt_packet(&packet, &[0; 16])); }
    let mut session = ready();
    session.handle_incoming_bytes(&wire).expect("many legal frames in one caller burst");
    assert!(session.incoming_buffer.is_empty());
    assert!(session.incoming_buffer.capacity() <= MAX_PACKET_BYTES + 20);
    assert_eq!(session.take_channel_input().len(), 64 * chunk.len());
}

#[test]
fn disconnect_remains_terminal_even_when_a_guessed_packet_is_pending() {
    let mut offer = lists();
    offer[0] = "unsupported,curve25519-sha256";
    let mut session = identified();
    clear(&mut session, &kex(offer, true)).expect("pending wrong guess");
    let mut disconnect = WireWriter::new();
    disconnect.write_u8(msg::DISCONNECT);
    disconnect.write_u32(11);
    disconnect.write_utf8("client finished");
    disconnect.write_utf8("");
    assert!(matches!(clear(&mut session, &disconnect.into_bytes()), Err(SshSessionError::Disconnected { .. })));
    assert_eq!(session.phase, SessionPhase::Closed);
    assert!(!session.discard_next_kex_packet);
}
