#![forbid(unsafe_code)]

use fgit_crypto::sha256_digest;
use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyScope};
use fgit_ssh::auth::build_userauth_signature_preimage;
use fgit_ssh::command::SshGitService;
use fgit_ssh::crypto::{
    Curve25519Kex, OpenSshChaCha20Poly1305, derive_key, encode_ed25519_public_key, sign_ed25519,
};
use fgit_ssh::session::{SessionPhase, SshServerSession, msg};
use fgit_ssh::wire::{WireReader, WireWriter, decode_cleartext_packet, encode_cleartext_packet};
use fgit_types::{PrincipalId, RepositoryId};

#[test]
fn test_end_to_end_ssh_session_flow() {
    let host_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
    let client_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
    let client_verifying_key = client_signing_key.verifying_key();
    let client_pub_bytes = client_verifying_key.to_bytes();

    let digest = sha256_digest(b"my-repo.git");
    let mut repo_bytes = [0u8; 16];
    repo_bytes.copy_from_slice(&digest[..16]);
    let repo_id = RepositoryId::from_bytes(repo_bytes);
    let principal = PrincipalId::from_bytes([0xAA; 16]);

    let fgit_verifying_key = fgit_crypto::VerifyingKey::from_bytes(client_pub_bytes);
    let binding = DeployKeyBinding::register(
        repo_id,
        principal,
        fgit_verifying_key,
        &[DeployKeyScope::Read, DeployKeyScope::Write],
    )
    .expect("register deploy key failed");

    let mut session = SshServerSession::new(host_signing_key.clone(), vec![binding]);

    // 1. Start session: server emits identification
    session.start();
    let server_out = session.take_outgoing_bytes();
    assert!(server_out.starts_with(b"SSH-2.0-FrankenGit-0.1\r\n"));

    // 2. Feed client identification
    let client_ident = b"SSH-2.0-OpenSSH_9.5\r\n";
    session.handle_incoming_bytes(client_ident).expect("handle ident failed");

    // Server should have emitted its KEXINIT
    let server_kexinit_wire = session.take_outgoing_bytes();
    assert!(!server_kexinit_wire.is_empty());
    let server_kexinit_payload = decode_cleartext_packet(&server_kexinit_wire)
        .expect("decode server kexinit failed");
    assert_eq!(server_kexinit_payload[0], msg::KEXINIT);

    // 3. Client sends its KEXINIT
    let mut client_kexinit = WireWriter::new();
    client_kexinit.write_u8(msg::KEXINIT);
    client_kexinit.write_raw(&[0x99; 16]); // cookie
    client_kexinit.write_name_list(&["curve25519-sha256"]);
    client_kexinit.write_name_list(&["ssh-ed25519"]);
    client_kexinit.write_name_list(&["chacha20-poly1305@openssh.com"]);
    client_kexinit.write_name_list(&["chacha20-poly1305@openssh.com"]);
    client_kexinit.write_name_list(&["none"]);
    client_kexinit.write_name_list(&["none"]);
    client_kexinit.write_name_list(&["none"]);
    client_kexinit.write_name_list(&["none"]);
    client_kexinit.write_name_list(&[]);
    client_kexinit.write_name_list(&[]);
    client_kexinit.write_bool(false);
    client_kexinit.write_u32(0);
    let client_kexinit_payload = client_kexinit.into_bytes();
    let client_kexinit_wire = encode_cleartext_packet(&client_kexinit_payload, &[0; 16]);
    session.handle_incoming_bytes(&client_kexinit_wire).expect("handle client kexinit failed");

    // 4. Client generates ephemeral Curve25519 key and sends KEX_ECDH_INIT
    let client_ephemeral = Curve25519Kex::from_private_bytes([0x33; 32]);
    let mut ecdh_init = WireWriter::new();
    ecdh_init.write_u8(msg::KEX_ECDH_INIT);
    ecdh_init.write_string(client_ephemeral.public_key());
    let ecdh_init_wire = encode_cleartext_packet(&ecdh_init.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&ecdh_init_wire).expect("handle ecdh init failed");

    // Server sends KEX_ECDH_REPLY and NEWKEYS
    let reply_wire = session.take_outgoing_bytes();
    assert!(!reply_wire.is_empty());

    // Parse KEX_ECDH_REPLY
    let (ecdh_reply_payload, consumed) = {
        let p = decode_cleartext_packet(&reply_wire).expect("decode ecdh reply failed");
        (p.to_vec(), 4 + u32::from_be_bytes([reply_wire[0], reply_wire[1], reply_wire[2], reply_wire[3]]) as usize)
    };
    assert_eq!(ecdh_reply_payload[0], msg::KEX_ECDH_REPLY);
    let mut reader = WireReader::new(&ecdh_reply_payload[1..]);
    let host_pub_blob = reader.read_string().expect("read host key blob failed");
    let server_ephemeral_pub = reader.read_string().expect("read server ephemeral pub failed");
    let sig_blob = reader.read_string().expect("read sig blob failed");

    let mut server_pub_arr = [0u8; 32];
    server_pub_arr.copy_from_slice(server_ephemeral_pub);
    let shared_secret = client_ephemeral.compute_shared_secret(&server_pub_arr).expect("compute shared secret failed");

    // Client verifies exchange hash and signature
    let mut mpint_writer = WireWriter::new();
    mpint_writer.write_mpint(&shared_secret);
    let k_mpint = mpint_writer.into_bytes();

    let mut hash_writer = WireWriter::new();
    hash_writer.write_string(b"SSH-2.0-OpenSSH_9.5");
    hash_writer.write_string(b"SSH-2.0-FrankenGit-0.1");
    hash_writer.write_string(&client_kexinit_payload);
    hash_writer.write_string(server_kexinit_payload);
    hash_writer.write_string(host_pub_blob);
    hash_writer.write_string(client_ephemeral.public_key());
    hash_writer.write_string(server_ephemeral_pub);
    hash_writer.write_raw(&k_mpint);
    let hash_h = sha256_digest(&hash_writer.into_bytes());

    fgit_ssh::crypto::verify_ed25519(&host_signing_key.verifying_key().to_bytes(), &hash_h, sig_blob)
        .expect("verify server signature failed");

    // Check second packet: NEWKEYS
    let newkeys_wire = &reply_wire[consumed..];
    let newkeys_payload = decode_cleartext_packet(newkeys_wire).expect("decode newkeys failed");
    assert_eq!(newkeys_payload[0], msg::NEWKEYS);

    // Client derives keys
    let client_key = derive_key(&k_mpint, &hash_h, b'C', &hash_h, 64);
    let server_key = derive_key(&k_mpint, &hash_h, b'D', &hash_h, 64);

    let mut c_key_arr = [0u8; 64];
    let mut s_key_arr = [0u8; 64];
    c_key_arr.copy_from_slice(&client_key);
    s_key_arr.copy_from_slice(&server_key);

    let mut client_out_cipher = OpenSshChaCha20Poly1305::new_with_sequence(&c_key_arr, 3);
    let mut client_in_cipher = OpenSshChaCha20Poly1305::new_with_sequence(&s_key_arr, 3);

    // 5. Client sends NEWKEYS
    let mut client_newkeys = WireWriter::new();
    client_newkeys.write_u8(msg::NEWKEYS);
    let client_newkeys_wire = encode_cleartext_packet(&client_newkeys.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&client_newkeys_wire).expect("handle client newkeys failed");

    // 6. Client requests service "ssh-userauth" (encrypted)
    let mut svc_req = WireWriter::new();
    svc_req.write_u8(msg::SERVICE_REQUEST);
    svc_req.write_utf8("ssh-userauth");
    let svc_wire = client_out_cipher.encrypt_packet(&svc_req.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&svc_wire).expect("handle service request failed");

    // Server answers with SERVICE_ACCEPT (encrypted)
    let server_svc_wire = session.take_outgoing_bytes();
    let server_svc_payload = client_in_cipher.decrypt_packet(&server_svc_wire).expect("decrypt svc accept failed");
    assert_eq!(server_svc_payload[0], msg::SERVICE_ACCEPT);

    // 7. Client authenticates via publickey
    let client_pub_blob = encode_ed25519_public_key(&client_pub_bytes);
    let userauth_preimage = build_userauth_signature_preimage(
        &hash_h,
        "git",
        "ssh-connection",
        &client_pub_blob,
    );
    let client_sig_blob = sign_ed25519(&client_signing_key, &userauth_preimage);

    let mut auth_req = WireWriter::new();
    auth_req.write_u8(msg::USERAUTH_REQUEST);
    auth_req.write_utf8("git");
    auth_req.write_utf8("ssh-connection");
    auth_req.write_utf8("publickey");
    auth_req.write_bool(true);
    auth_req.write_utf8("ssh-ed25519");
    auth_req.write_string(&client_pub_blob);
    auth_req.write_string(&client_sig_blob);

    let auth_wire = client_out_cipher.encrypt_packet(&auth_req.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&auth_wire).expect("handle auth request failed");

    // Server sends USERAUTH_SUCCESS
    let server_auth_wire = session.take_outgoing_bytes();
    let server_auth_payload = client_in_cipher.decrypt_packet(&server_auth_wire).expect("decrypt auth success failed");
    assert_eq!(server_auth_payload[0], msg::USERAUTH_SUCCESS);
    assert_eq!(*session.phase(), SessionPhase::ChannelReady);

    // 8. Client opens session channel
    let mut chan_open = WireWriter::new();
    chan_open.write_u8(msg::CHANNEL_OPEN);
    chan_open.write_utf8("session");
    chan_open.write_u32(0); // sender channel
    chan_open.write_u32(2 * 1024 * 1024);
    chan_open.write_u32(32 * 1024);
    let chan_open_wire = client_out_cipher.encrypt_packet(&chan_open.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&chan_open_wire).expect("handle channel open failed");

    // Server sends CHANNEL_OPEN_CONFIRMATION
    let server_chan_wire = session.take_outgoing_bytes();
    let server_chan_payload = client_in_cipher.decrypt_packet(&server_chan_wire).expect("decrypt chan open confirm failed");
    assert_eq!(server_chan_payload[0], msg::CHANNEL_OPEN_CONFIRMATION);

    // 9. Client sends exec request: git-upload-pack 'my-repo.git'
    let mut exec_req = WireWriter::new();
    exec_req.write_u8(msg::CHANNEL_REQUEST);
    exec_req.write_u32(0); // recipient channel
    exec_req.write_utf8("exec");
    exec_req.write_bool(true);
    exec_req.write_utf8("git-upload-pack 'my-repo.git'");
    let exec_wire = client_out_cipher.encrypt_packet(&exec_req.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&exec_wire).expect("handle exec request failed");

    // Server sends CHANNEL_SUCCESS
    let server_exec_wire = session.take_outgoing_bytes();
    let server_exec_payload = client_in_cipher.decrypt_packet(&server_exec_wire).expect("decrypt chan success failed");
    assert_eq!(server_exec_payload[0], msg::CHANNEL_SUCCESS);
    assert_eq!(*session.phase(), SessionPhase::ActiveChannel);
    assert_eq!(session.authenticated_principal(), Some(principal));
    assert_eq!(session.active_command().unwrap().service(), SshGitService::UploadPack);
    assert_eq!(session.active_command().unwrap().repository_path(), "my-repo.git");

    // 10. Data exchange over channel
    let git_client_data = b"0014command=ls-refs\n0000";
    let mut data_msg = WireWriter::new();
    data_msg.write_u8(msg::CHANNEL_DATA);
    data_msg.write_u32(0);
    data_msg.write_string(git_client_data);
    let data_wire = client_out_cipher.encrypt_packet(&data_msg.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&data_wire).expect("handle channel data failed");

    let input = session.take_channel_input();
    assert_eq!(&input, git_client_data);

    // Server sends output to client
    let git_server_response = b"0008NAK\n";
    session.send_channel_data(git_server_response);
    let server_data_wire = session.take_outgoing_bytes();
    let server_data_payload = client_in_cipher.decrypt_packet(&server_data_wire).expect("decrypt server data failed");
    assert_eq!(server_data_payload[0], msg::CHANNEL_DATA);
    let mut reader = WireReader::new(&server_data_payload[1..]);
    let _chan = reader.read_u32().unwrap();
    let payload = reader.read_string().unwrap();
    assert_eq!(payload, git_server_response);

    // 11. Channel EOF and Close
    let mut eof_msg = WireWriter::new();
    eof_msg.write_u8(msg::CHANNEL_EOF);
    eof_msg.write_u32(0);
    let eof_wire = client_out_cipher.encrypt_packet(&eof_msg.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&eof_wire).expect("handle eof failed");
    assert!(session.is_channel_eof_received());

    let mut close_msg = WireWriter::new();
    close_msg.write_u8(msg::CHANNEL_CLOSE);
    close_msg.write_u32(0);
    let close_wire = client_out_cipher.encrypt_packet(&close_msg.into_bytes(), &[0; 16]);
    session.handle_incoming_bytes(&close_wire).expect("handle close failed");
    assert!(session.is_channel_closed());
    assert_eq!(*session.phase(), SessionPhase::Closed);
}
