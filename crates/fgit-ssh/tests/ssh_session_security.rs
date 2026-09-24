#![forbid(unsafe_code)]
//! Confidentiality and resource-bound regressions for the SSH session engine.
//!
//! Every refusal here has a near-identical permitted twin. The handshake
//! helper drives the real `SshServerSession` state machine as an OpenSSH-like
//! client would, including the strict-KEX sequence reset.

use std::sync::Arc;

use asupersync::util::{DetEntropy, EntropySource, OsEntropy};
use fgit_crypto::sha256_digest;
use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyScope};
use fgit_ssh::auth::build_userauth_signature_preimage;
use fgit_ssh::crypto::{
    Curve25519Kex, OpenSshChaCha20Poly1305, constant_time_eq, derive_key,
    encode_ed25519_public_key, sign_ed25519,
};
use fgit_ssh::session::{
    DEFAULT_WINDOW_SIZE, KEX_STRICT_CLIENT, SessionPhase, SshServerSession, SshSessionError, msg,
};
use fgit_ssh::wire::{
    MAX_PACKET_BYTES, WireError, WireReader, WireWriter, decode_cleartext_packet,
    encode_cleartext_packet,
};
use fgit_types::{PrincipalId, RepositoryId};

const CLIENT_IDENT: &[u8] = b"SSH-2.0-OpenSSH_9.9\r\n";

fn binding(client: &ed25519_dalek::SigningKey) -> DeployKeyBinding {
    let digest = sha256_digest(b"repo.git");
    let mut repo = [0u8; 16];
    repo.copy_from_slice(&digest[..16]);
    DeployKeyBinding::register(
        RepositoryId::from_bytes(repo),
        PrincipalId::from_bytes([0xAB; 16]),
        fgit_crypto::VerifyingKey::from_bytes(client.verifying_key().to_bytes()),
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("deploy key binding")
}

fn client_kexinit(strict: bool) -> Vec<u8> {
    let mut kex = vec!["curve25519-sha256"];
    if strict {
        kex.push(KEX_STRICT_CLIENT);
    }
    let mut w = WireWriter::new();
    w.write_u8(msg::KEXINIT);
    w.write_raw(&[0x5a; 16]);
    w.write_name_list(&kex);
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

/// What the client side observed and holds after a completed handshake.
struct Client {
    out: OpenSshChaCha20Poly1305,
    inbound: OpenSshChaCha20Poly1305,
    server_cookie: [u8; 16],
    server_ephemeral: [u8; 32],
    client_ephemeral_public: [u8; 32],
    shared_secret: [u8; 32],
}

impl Client {
    fn send(&mut self, session: &mut SshServerSession, payload: &[u8]) {
        let wire = self.out.encrypt_packet(payload, &[0; 16]);
        session
            .handle_incoming_bytes(&wire)
            .expect("server accepts client packet");
    }

    /// Decrypts every packet the server queued.
    fn receive_all(&mut self, session: &mut SshServerSession) -> Vec<Vec<u8>> {
        let mut wire = session.take_outgoing_bytes();
        let mut packets = Vec::new();
        while !wire.is_empty() {
            let mut len = [0u8; 4];
            len.copy_from_slice(&wire[..4]);
            let total = 4 + self.inbound.decrypt_packet_length(&len) as usize + 16;
            packets.push(
                self.inbound
                    .decrypt_packet(&wire[..total])
                    .expect("decrypt"),
            );
            wire.drain(..total);
        }
        packets
    }
}

/// Runs identification and key exchange, returning the session and client
/// state just after NEWKEYS (before user authentication).
fn key_exchange(
    entropy: Arc<dyn EntropySource>,
    strict: bool,
    client_private: [u8; 32],
) -> (SshServerSession, Client, ed25519_dalek::SigningKey) {
    let host = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let client_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
    let mut session = SshServerSession::new(host.clone(), vec![binding(&client_key)], entropy);
    session.start();
    let _banner = session.take_outgoing_bytes();
    session.handle_incoming_bytes(CLIENT_IDENT).expect("ident");
    let server_kexinit_wire = session.take_outgoing_bytes();
    let server_kexinit = decode_cleartext_packet(&server_kexinit_wire)
        .expect("server kexinit")
        .to_vec();
    let mut server_cookie = [0u8; 16];
    server_cookie.copy_from_slice(&server_kexinit[1..17]);

    let kexinit = client_kexinit(strict);
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&kexinit, &[0; 16]))
        .expect("kexinit");
    assert_eq!(session.strict_kex(), strict);

    let ephemeral = Curve25519Kex::from_private_bytes(client_private);
    let mut init = WireWriter::new();
    init.write_u8(msg::KEX_ECDH_INIT);
    init.write_string(ephemeral.public_key());
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&init.into_bytes(), &[0; 16]))
        .expect("ecdh init");

    let reply_wire = session.take_outgoing_bytes();
    let reply = decode_cleartext_packet(&reply_wire)
        .expect("ecdh reply")
        .to_vec();
    let consumed =
        4 + u32::from_be_bytes([reply_wire[0], reply_wire[1], reply_wire[2], reply_wire[3]])
            as usize;
    assert_eq!(
        decode_cleartext_packet(&reply_wire[consumed..]).expect("newkeys")[0],
        msg::NEWKEYS
    );
    let mut reader = WireReader::new(&reply[1..]);
    let host_blob = reader.read_string().expect("host blob").to_vec();
    let mut server_ephemeral = [0u8; 32];
    server_ephemeral.copy_from_slice(reader.read_string().expect("server ephemeral"));
    let signature = reader.read_string().expect("signature").to_vec();

    let shared_secret = ephemeral
        .compute_shared_secret(&server_ephemeral)
        .expect("shared secret");
    let mut k = WireWriter::new();
    k.write_mpint(&shared_secret);
    let k = k.into_bytes();
    let mut h = WireWriter::new();
    h.write_string(&CLIENT_IDENT[..CLIENT_IDENT.len() - 2]);
    h.write_string(b"SSH-2.0-FrankenGit-0.1");
    h.write_string(&kexinit);
    h.write_string(&server_kexinit);
    h.write_string(&host_blob);
    h.write_string(ephemeral.public_key());
    h.write_string(&server_ephemeral);
    h.write_raw(&k);
    let hash = sha256_digest(&h.into_bytes());
    fgit_ssh::crypto::verify_ed25519(&host.verifying_key().to_bytes(), &hash, &signature)
        .expect("server signature over the exchange hash");

    let mut c = [0u8; 64];
    c.copy_from_slice(&derive_key(&k, &hash, b'C', &hash, 64));
    let mut s = [0u8; 64];
    s.copy_from_slice(&derive_key(&k, &hash, b'D', &hash, 64));
    // Strict KEX restarts both sequence numbers at zero after NEWKEYS; the
    // legacy protocol continues from the three cleartext packets exchanged.
    let sequence = if strict { 0 } else { 3 };
    let mut newkeys = WireWriter::new();
    newkeys.write_u8(msg::NEWKEYS);
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&newkeys.into_bytes(), &[0; 16]))
        .expect("newkeys");

    let mut client = Client {
        out: OpenSshChaCha20Poly1305::new_with_sequence(&c, sequence),
        inbound: OpenSshChaCha20Poly1305::new_with_sequence(&s, sequence),
        server_cookie,
        server_ephemeral,
        client_ephemeral_public: *ephemeral.public_key(),
        shared_secret,
    };
    // Prove the negotiated keys work in both directions.
    let mut request = WireWriter::new();
    request.write_u8(msg::SERVICE_REQUEST);
    request.write_utf8("ssh-userauth");
    client.send(&mut session, &request.into_bytes());
    assert_eq!(client.receive_all(&mut session)[0][0], msg::SERVICE_ACCEPT);
    assert_eq!(session.session_id(), Some(hash));
    (session, client, client_key)
}

/// Continues from key exchange through authentication and channel open.
fn open_channel(
    session: &mut SshServerSession,
    client: &mut Client,
    client_key: &ed25519_dalek::SigningKey,
    window: u32,
    max_packet: u32,
) {
    let blob = encode_ed25519_public_key(&client_key.verifying_key().to_bytes());
    let hash = session.session_id().expect("session id after key exchange");
    let preimage = build_userauth_signature_preimage(&hash, "git", "ssh-connection", &blob);
    let signature = sign_ed25519(client_key, &preimage);
    let mut auth = WireWriter::new();
    auth.write_u8(msg::USERAUTH_REQUEST);
    auth.write_utf8("git");
    auth.write_utf8("ssh-connection");
    auth.write_utf8("publickey");
    auth.write_bool(true);
    auth.write_utf8("ssh-ed25519");
    auth.write_string(&blob);
    auth.write_string(&signature);
    client.send(session, &auth.into_bytes());
    assert_eq!(client.receive_all(session)[0][0], msg::USERAUTH_SUCCESS);

    let mut open = WireWriter::new();
    open.write_u8(msg::CHANNEL_OPEN);
    open.write_utf8("session");
    open.write_u32(0);
    open.write_u32(window);
    open.write_u32(max_packet);
    client.send(session, &open.into_bytes());
    assert_eq!(
        client.receive_all(session)[0][0],
        msg::CHANNEL_OPEN_CONFIRMATION
    );
}

#[test]
fn every_session_draws_a_fresh_ephemeral_key_and_cookie() {
    let (_, a, _) = key_exchange(Arc::new(OsEntropy), false, [0x33; 32]);
    let (_, b, _) = key_exchange(Arc::new(OsEntropy), false, [0x33; 32]);
    assert_ne!(
        a.server_ephemeral, b.server_ephemeral,
        "ephemeral key reused across sessions"
    );
    assert_ne!(
        a.server_cookie, b.server_cookie,
        "KEXINIT cookie reused across sessions"
    );
    assert_ne!(a.shared_secret, b.shared_secret);
    let old_constant = Curve25519Kex::from_private_bytes([0x77; 32]);
    assert_ne!(
        &a.server_ephemeral,
        old_constant.public_key(),
        "the published constant key is gone"
    );
}

#[test]
fn the_transcript_alone_no_longer_yields_the_shared_secret() {
    // Before this fix the server key was the constant [0x77; 32]; an observer
    // derived K from the client's public value on the wire. That derivation
    // must now fail, while the real client still agrees with the server.
    let (_, client, _) = key_exchange(Arc::new(OsEntropy), false, [0x44; 32]);
    let attacker = Curve25519Kex::from_private_bytes([0x77; 32])
        .compute_shared_secret(&client.client_ephemeral_public)
        .expect("attacker computation");
    assert_ne!(attacker, client.shared_secret);
}

#[test]
fn seeded_entropy_is_reproducible_and_seeds_are_independent() {
    let (_, a, _) = key_exchange(Arc::new(DetEntropy::new(1)), false, [0x33; 32]);
    let (_, b, _) = key_exchange(Arc::new(DetEntropy::new(1)), false, [0x33; 32]);
    let (_, c, _) = key_exchange(Arc::new(DetEntropy::new(2)), false, [0x33; 32]);
    assert_eq!(a.server_ephemeral, b.server_ephemeral);
    assert_ne!(a.server_ephemeral, c.server_ephemeral);
}

#[test]
fn an_oversized_packet_declaration_is_refused_before_buffering() {
    let host = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let mut session = SshServerSession::new(host.clone(), Vec::new(), Arc::new(DetEntropy::new(3)));
    session.start();
    session.handle_incoming_bytes(CLIENT_IDENT).expect("ident");
    let refused = session
        .handle_incoming_bytes(&[0x7f, 0xff, 0xff, 0xff])
        .unwrap_err();
    assert!(
        matches!(
            refused,
            SshSessionError::Wire(WireError::PacketTooLarge { .. })
        ),
        "{refused:?}"
    );

    // Permitted twin: a legal length waits for the rest of the packet.
    let mut session = SshServerSession::new(host, Vec::new(), Arc::new(DetEntropy::new(3)));
    session.start();
    session.handle_incoming_bytes(CLIENT_IDENT).expect("ident");
    let legal = u32::try_from(MAX_PACKET_BYTES).unwrap().to_be_bytes();
    session
        .handle_incoming_bytes(&legal)
        .expect("partial legal packet is buffered");
}

#[test]
fn an_overlong_identification_line_is_refused() {
    let host = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let mut session = SshServerSession::new(host.clone(), Vec::new(), Arc::new(DetEntropy::new(4)));
    session.start();
    assert!(session.handle_incoming_bytes(&[b'A'; 300]).is_err());

    // Permitted twin: a partial, short identification waits for its newline.
    let mut session = SshServerSession::new(host, Vec::new(), Arc::new(DetEntropy::new(4)));
    session.start();
    session
        .handle_incoming_bytes(b"SSH-2.0-Open")
        .expect("partial ident");
    session
        .handle_incoming_bytes(b"SSH_9.9\r\n")
        .expect("completed ident");
    assert_eq!(*session.phase(), SessionPhase::KeyExchange);
}

#[test]
fn channel_output_respects_the_client_window_and_packet_size() {
    let (mut session, mut client, key) =
        key_exchange(Arc::new(DetEntropy::new(5)), false, [0x33; 32]);
    open_channel(&mut session, &mut client, &key, 100, 40);
    let data = vec![0xc3; 250];
    assert_eq!(
        session.send_channel_data(&data),
        100,
        "only the advertised window is sent"
    );
    assert_eq!(
        session.send_channel_data(&data[100..]),
        0,
        "an exhausted window sends nothing"
    );
    let packets = client.receive_all(&mut session);
    let mut delivered = 0;
    for packet in &packets {
        assert_eq!(packet[0], msg::CHANNEL_DATA);
        let mut r = WireReader::new(&packet[1..]);
        let _channel = r.read_u32().unwrap();
        let chunk = r.read_string().unwrap();
        assert!(
            chunk.len() <= 40 - 9,
            "chunk {} exceeds the client's max packet",
            chunk.len()
        );
        delivered += chunk.len();
    }
    assert_eq!(delivered, 100);

    let mut adjust = WireWriter::new();
    adjust.write_u8(msg::CHANNEL_WINDOW_ADJUST);
    adjust.write_u32(0);
    adjust.write_u32(150);
    client.send(&mut session, &adjust.into_bytes());
    assert_eq!(session.send_channel_data(&data[100..]), 150);
}

#[test]
fn consuming_input_reopens_the_receive_window_and_overruns_are_refused() {
    let (mut session, mut client, key) =
        key_exchange(Arc::new(DetEntropy::new(6)), false, [0x33; 32]);
    open_channel(&mut session, &mut client, &key, 1 << 20, 32 * 1024);
    let chunk = vec![0x61; 30 * 1024];
    let mut sent = 0usize;
    while sent + chunk.len() <= (DEFAULT_WINDOW_SIZE as usize) / 2 + chunk.len() {
        let mut data = WireWriter::new();
        data.write_u8(msg::CHANNEL_DATA);
        data.write_u32(0);
        data.write_string(&chunk);
        client.send(&mut session, &data.into_bytes());
        sent += chunk.len();
    }
    assert_eq!(session.take_channel_input().len(), sent);
    let packets = client.receive_all(&mut session);
    let adjust = packets
        .iter()
        .find(|p| p[0] == msg::CHANNEL_WINDOW_ADJUST)
        .expect("window adjust");
    let mut r = WireReader::new(&adjust[1..]);
    let _channel = r.read_u32().unwrap();
    assert_eq!(r.read_u32().unwrap() as usize, sent);

    // A client that keeps sending past the window without it being reopened
    // is a protocol violation, not a reason to buffer without bound.
    let (mut session, mut client, key) =
        key_exchange(Arc::new(DetEntropy::new(6)), false, [0x33; 32]);
    open_channel(&mut session, &mut client, &key, 1 << 20, 32 * 1024);
    let mut refused = None;
    for _ in 0..=(DEFAULT_WINDOW_SIZE as usize / chunk.len()) {
        let mut data = WireWriter::new();
        data.write_u8(msg::CHANNEL_DATA);
        data.write_u32(0);
        data.write_string(&chunk);
        let wire = client.out.encrypt_packet(&data.into_bytes(), &[0; 16]);
        if let Err(error) = session.handle_incoming_bytes(&wire) {
            refused = Some(error);
            break;
        }
    }
    assert!(
        matches!(refused, Some(SshSessionError::ProtocolViolation { .. })),
        "{refused:?}"
    );
}

#[test]
fn strict_kex_resets_sequences_and_refuses_injected_messages() {
    // Positive: a strict client using sequence zero after NEWKEYS completes
    // the handshake (asserted inside key_exchange via SERVICE_ACCEPT).
    let (session, _, _) = key_exchange(Arc::new(DetEntropy::new(8)), true, [0x33; 32]);
    assert!(session.strict_kex());

    // Negative: under strict KEX an IGNORE before NEWKEYS is refused...
    let host = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let mut session = SshServerSession::new(host.clone(), Vec::new(), Arc::new(DetEntropy::new(9)));
    session.start();
    session.handle_incoming_bytes(CLIENT_IDENT).expect("ident");
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&client_kexinit(true), &[0; 16]))
        .expect("strict kexinit");
    let ignore = encode_cleartext_packet(&[msg::IGNORE, 0, 0, 0, 0], &[0; 16]);
    assert!(session.handle_incoming_bytes(&ignore).is_err());

    // ...while the legacy protocol still tolerates it (permitted twin).
    let mut session = SshServerSession::new(host.clone(), Vec::new(), Arc::new(DetEntropy::new(9)));
    session.start();
    session.handle_incoming_bytes(CLIENT_IDENT).expect("ident");
    session
        .handle_incoming_bytes(&encode_cleartext_packet(&client_kexinit(false), &[0; 16]))
        .expect("legacy kexinit");
    session
        .handle_incoming_bytes(&ignore)
        .expect("legacy ignore");

    // Strict KEX also requires KEXINIT to be the client's first packet.
    let mut session = SshServerSession::new(host, Vec::new(), Arc::new(DetEntropy::new(9)));
    session.start();
    session.handle_incoming_bytes(CLIENT_IDENT).expect("ident");
    session
        .handle_incoming_bytes(&ignore)
        .expect("pre-kexinit ignore is legal on its own");
    assert!(
        session
            .handle_incoming_bytes(&encode_cleartext_packet(&client_kexinit(true), &[0; 16]))
            .is_err()
    );
}

#[test]
fn tag_comparison_is_exact() {
    assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
    assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
    assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
}
