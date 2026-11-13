#![forbid(unsafe_code)]

//! Real encrypted TCP requests through one listener and two canonical nodes.
//! This is native transport integration, not an upstream-client differential.

use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyScope};
use fgit_node::{NodeConfig, OneNode, SshRepositoryRoute, SshServerLimits};
use fgit_ssh::auth::build_userauth_signature_preimage;
use fgit_ssh::crypto::{
    Curve25519Kex, OpenSshChaCha20Poly1305, derive_key, encode_ed25519_public_key, sign_ed25519,
    verify_ed25519,
};
use fgit_ssh::session::{DEFAULT_MAX_PACKET_SIZE, KEX_STRICT_CLIENT, SERVER_IDENTIFICATION, msg};
use fgit_ssh::wire::{WireReader, WireWriter, decode_cleartext_packet, encode_cleartext_packet};
use fgit_ssh::{SigningKey, SshCommandAuthorizer, SshGitService, StaticDeployKeyAuthorizer};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};
use fgit_wire::{Packet, WireLimits, encode_packets};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        for _ in 0..128 {
            let root = std::env::temp_dir().join(format!(
                "fg-ssh-route-transport-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&root) {
                Ok(()) => return Self(root),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create SSH route fixture: {error}"),
            }
        }
        panic!("SSH route fixture collision budget exhausted")
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

fn route(node: &OneNode, path: &str, principal: u8, seed: u8) -> SshRepositoryRoute {
    let key = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let source: Arc<dyn SshCommandAuthorizer> = Arc::new(StaticDeployKeyAuthorizer::new(vec![
        DeployKeyBinding::register(
            node.repository_id(),
            PrincipalId::from_bytes([principal; 16]),
            fgit_crypto::VerifyingKey::from_bytes(key),
            &[DeployKeyScope::Read, DeployKeyScope::Write],
        )
        .unwrap(),
    ]));
    SshRepositoryRoute::try_new(path.into(), node, source, true).unwrap()
}

fn reopen_configuration(root: PathBuf, node: &OneNode) -> NodeConfig {
    NodeConfig::new(root, node.tenant_id(), node.repository_id())
        .with_object_format(node.object_format())
        .with_expected_repository_incarnation(node.repository_incarnation_id())
        .with_worker_threads(2)
}

const CLIENT_IDENT: &[u8] = b"SSH-2.0-FrankenGit-Route-Test\r\n";
const CLIENT_CHANNEL: u32 = 37;

struct Peer {
    stream: TcpStream,
    outbound: OpenSshChaCha20Poly1305,
    inbound: OpenSshChaCha20Poly1305,
    channel: u32,
    active: bool,
}

struct Receipt {
    data: Vec<u8>,
    diagnostic: Vec<u8>,
    exit: u32,
}

fn clear_packet(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let count = u32::from_be_bytes(length) as usize;
    assert!(count <= 64 * 1024);
    let mut bytes = vec![0; count + 4];
    bytes[..4].copy_from_slice(&length);
    stream.read_exact(&mut bytes[4..]).unwrap();
    decode_cleartext_packet(&bytes).unwrap().to_vec()
}

impl Peer {
    fn connect(
        address: SocketAddr,
        key_seed: u8,
        service: SshGitService,
        path: &str,
    ) -> (Self, bool) {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut identification = Vec::new();
        while !identification.ends_with(b"\r\n") {
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).unwrap();
            identification.push(byte[0]);
            assert!(identification.len() <= 255);
        }
        assert_eq!(
            identification,
            format!("{SERVER_IDENTIFICATION}\r\n").as_bytes()
        );
        stream.write_all(CLIENT_IDENT).unwrap();
        let server_kex = clear_packet(&mut stream);
        assert_eq!(server_kex[0], msg::KEXINIT);
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
        stream
            .write_all(&encode_cleartext_packet(&client_kex, &[0; 16]))
            .unwrap();

        let ephemeral = Curve25519Kex::from_private_bytes([0x33; 32]);
        let mut init = WireWriter::new();
        init.write_u8(msg::KEX_ECDH_INIT);
        init.write_string(ephemeral.public_key());
        stream
            .write_all(&encode_cleartext_packet(&init.into_bytes(), &[0; 16]))
            .unwrap();
        let reply = clear_packet(&mut stream);
        assert_eq!(clear_packet(&mut stream), [msg::NEWKEYS]);
        let mut reader = WireReader::new(&reply);
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
        exchange.write_string(&server_kex);
        exchange.write_string(host_blob);
        exchange.write_string(ephemeral.public_key());
        exchange.write_string(&server_public);
        exchange.write_raw(&encoded_shared);
        let hash = sha256_digest(&exchange.into_bytes());
        let host = SigningKey::from_bytes(&[9; 32]);
        assert_eq!(
            host_blob,
            encode_ed25519_public_key(&host.verifying_key().to_bytes())
        );
        verify_ed25519(&host.verifying_key().to_bytes(), &hash, signature).unwrap();
        let outbound = derive_key(&encoded_shared, &hash, b'C', &hash, 64)
            .try_into()
            .unwrap();
        let inbound = derive_key(&encoded_shared, &hash, b'D', &hash, 64)
            .try_into()
            .unwrap();
        stream
            .write_all(&encode_cleartext_packet(&[msg::NEWKEYS], &[0; 16]))
            .unwrap();
        let mut peer = Self {
            stream,
            outbound: OpenSshChaCha20Poly1305::new_with_sequence(&outbound, 0),
            inbound: OpenSshChaCha20Poly1305::new_with_sequence(&inbound, 0),
            channel: 0,
            active: false,
        };
        let mut request = WireWriter::new();
        request.write_u8(msg::SERVICE_REQUEST);
        request.write_utf8("ssh-userauth");
        peer.send(&request.into_bytes());
        assert_eq!(peer.receive()[0], msg::SERVICE_ACCEPT);
        let key = SigningKey::from_bytes(&[key_seed; 32]);
        let blob = encode_ed25519_public_key(&key.verifying_key().to_bytes());
        let signature = sign_ed25519(
            &key,
            &build_userauth_signature_preimage(&hash, "git", "ssh-connection", &blob),
        );
        let mut auth = WireWriter::new();
        auth.write_u8(msg::USERAUTH_REQUEST);
        auth.write_utf8("git");
        auth.write_utf8("ssh-connection");
        auth.write_utf8("publickey");
        auth.write_bool(true);
        auth.write_utf8("ssh-ed25519");
        auth.write_string(&blob);
        auth.write_string(&signature);
        peer.send(&auth.into_bytes());
        assert_eq!(peer.receive(), [msg::USERAUTH_SUCCESS]);
        let mut open = WireWriter::new();
        open.write_u8(msg::CHANNEL_OPEN);
        open.write_utf8("session");
        open.write_u32(CLIENT_CHANNEL);
        open.write_u32(2 * 1024 * 1024);
        open.write_u32(DEFAULT_MAX_PACKET_SIZE);
        peer.send(&open.into_bytes());
        let packet = peer.receive();
        let mut response = WireReader::new(&packet);
        assert_eq!(response.read_u8().unwrap(), msg::CHANNEL_OPEN_CONFIRMATION);
        assert_eq!(response.read_u32().unwrap(), CLIENT_CHANNEL);
        peer.channel = response.read_u32().unwrap();
        let mut exec = peer.channel_packet(msg::CHANNEL_REQUEST);
        exec.write_utf8("exec");
        exec.write_bool(true);
        exec.write_utf8(&format!("{service} '{path}'"));
        peer.send(&exec.into_bytes());
        let response = peer.receive();
        assert!(matches!(
            response[0],
            msg::CHANNEL_SUCCESS | msg::CHANNEL_FAILURE
        ));
        peer.active = response[0] == msg::CHANNEL_SUCCESS;
        let active = peer.active;
        (peer, active)
    }

    fn channel_packet(&self, kind: u8) -> WireWriter {
        let mut packet = WireWriter::new();
        packet.write_u8(kind);
        packet.write_u32(self.channel);
        packet
    }

    fn send(&mut self, payload: &[u8]) {
        self.stream
            .write_all(&self.outbound.encrypt_packet(payload, &[0; 16]))
            .unwrap();
    }

    fn receive(&mut self) -> Vec<u8> {
        let mut length = [0; 4];
        self.stream.read_exact(&mut length).unwrap();
        let count = self.inbound.decrypt_packet_length(&length) as usize;
        assert!(count <= 64 * 1024);
        let mut bytes = vec![0; 4 + count + 16];
        bytes[..4].copy_from_slice(&length);
        self.stream.read_exact(&mut bytes[4..]).unwrap();
        self.inbound.decrypt_packet(&bytes).unwrap()
    }

    fn data_and_eof(&mut self, bytes: &[u8]) {
        let mut packet = self.channel_packet(msg::CHANNEL_DATA);
        packet.write_string(bytes);
        self.send(&packet.into_bytes());
        self.send(&self.channel_packet(msg::CHANNEL_EOF).into_bytes());
    }

    fn advertisement(&mut self) -> Vec<u8> {
        let mut data = Vec::new();
        for _ in 0..64 {
            let packet = self.receive();
            let mut reader = WireReader::new(&packet);
            let kind = reader.read_u8().unwrap();
            assert_eq!(reader.read_u32().unwrap(), CLIENT_CHANNEL);
            if kind == msg::CHANNEL_WINDOW_ADJUST {
                continue;
            }
            assert_eq!(kind, msg::CHANNEL_DATA);
            data.extend_from_slice(reader.read_string().unwrap());
            assert!(data.len() < 128 * 1024);
            if data.ends_with(b"0000") {
                return data;
            }
        }
        panic!("Git advertisement did not finish")
    }

    fn finish(mut self) -> Receipt {
        let mut receipt = Receipt {
            data: Vec::new(),
            diagnostic: Vec::new(),
            exit: u32::MAX,
        };
        for _ in 0..128 {
            let packet = self.receive();
            let mut reader = WireReader::new(&packet);
            let kind = reader.read_u8().unwrap();
            assert_eq!(reader.read_u32().unwrap(), CLIENT_CHANNEL);
            match kind {
                msg::CHANNEL_DATA => receipt
                    .data
                    .extend_from_slice(reader.read_string().unwrap()),
                msg::CHANNEL_EXTENDED_DATA => {
                    assert_eq!(reader.read_u32().unwrap(), 1);
                    receipt
                        .diagnostic
                        .extend_from_slice(reader.read_string().unwrap());
                }
                msg::CHANNEL_REQUEST => {
                    assert_eq!(reader.read_utf8().unwrap(), "exit-status");
                    assert!(!reader.read_bool().unwrap());
                    receipt.exit = reader.read_u32().unwrap();
                }
                msg::CHANNEL_WINDOW_ADJUST | msg::CHANNEL_EOF => {}
                msg::CHANNEL_CLOSE => {
                    if self.active {
                        self.send(&self.channel_packet(msg::CHANNEL_CLOSE).into_bytes());
                    }
                    return receipt;
                }
                other => panic!("unexpected terminal SSH packet {other}"),
            }
            assert!(receipt.data.len() + receipt.diagnostic.len() < 128 * 1024);
        }
        panic!("SSH command did not close")
    }
}

fn push_body(format: GitHashAlgorithm, byte: u8) -> (GitOid, Vec<u8>) {
    let oid = git_object_id(format, GitObjectKind::Blob, &[byte]);
    let zero = "0".repeat(format.digest_len() * 2);
    let mut bytes = encode_packets(
        &[
            Packet::Data(
                format!(
                    "{zero} {oid} refs/tags/shared\0report-status object-format={}",
                    format.as_str()
                )
                .into_bytes(),
            ),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&[0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, byte]);
    let sum = u32::from(byte) + 1;
    pack.extend_from_slice(&((sum << 16) | sum).to_be_bytes());
    let digest = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&digest);
    bytes.extend_from_slice(&pack);
    (oid, bytes)
}

#[test]
fn one_encrypted_listener_isolates_pushes_and_advertisements_across_tenants_and_restart() {
    let scratch = Scratch::new();
    let first = node(scratch.0.join("first"), 0x71, GitHashAlgorithm::Sha1);
    let second = node(scratch.0.join("second"), 0x81, GitHashAlgorithm::Sha256);
    let routes = vec![
        route(&first, "alpha/repo.git", 1, 2),
        route(&second, "beta/repo.git", 3, 4),
    ];
    let configurations = [
        reopen_configuration(scratch.0.join("first"), &first),
        reopen_configuration(scratch.0.join("second"), &second),
    ];
    second.shutdown().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let result = first.serve_ssh_routes_bounded(
            &listener,
            SshServerLimits::try_new(6, 2).unwrap(),
            SigningKey::from_bytes(&[9; 32]),
            routes,
        );
        first.shutdown().unwrap();
        result.unwrap()
    });
    let mut rejected = None;
    for path in ["beta/repo.git", "missing/repo.git"] {
        let (peer, permitted) = Peer::connect(address, 2, SshGitService::ReceivePack, path);
        assert!(!permitted);
        let receipt = peer.finish();
        assert!(receipt.data.is_empty());
        assert_eq!(receipt.exit, 1);
        if let Some(expected) = &rejected {
            assert_eq!(&receipt.diagnostic, expected);
        } else {
            rejected = Some(receipt.diagnostic);
        }
    }
    let inputs = [
        ("alpha/repo.git", 2, GitHashAlgorithm::Sha1, b'A'),
        ("beta/repo.git", 4, GitHashAlgorithm::Sha256, b'B'),
    ];
    let mut tips = Vec::new();
    for (path, key, format, byte) in inputs {
        let (mut peer, permitted) = Peer::connect(address, key, SshGitService::ReceivePack, path);
        assert!(permitted);
        let advertisement = peer.advertisement();
        assert!(
            String::from_utf8_lossy(&advertisement)
                .contains(&format!("object-format={}", format.as_str()))
        );
        let (oid, body) = push_body(format, byte);
        tips.push(oid);
        peer.data_and_eof(&body);
        let receipt = peer.finish();
        assert_eq!(
            receipt.exit,
            0,
            "{}",
            String::from_utf8_lossy(&receipt.diagnostic)
        );
        assert!(String::from_utf8_lossy(&receipt.data).contains("ok refs/tags/shared"));
    }
    for (index, (path, key, _, _)) in inputs.into_iter().enumerate() {
        let (mut peer, permitted) = Peer::connect(address, key, SshGitService::UploadPack, path);
        assert!(permitted);
        let advertisement = peer.advertisement();
        let text = String::from_utf8_lossy(&advertisement);
        assert!(text.contains(&tips[index].to_string()));
        assert!(!text.contains(&tips[1 - index].to_string()));
        peer.data_and_eof(b"0000");
        let receipt = peer.finish();
        assert_eq!(receipt.exit, 0);
    }
    let receipt = worker.join().unwrap();
    assert_eq!(receipt.accepted_sessions(), 6);
    assert_eq!(receipt.completed_sessions(), 4);
    assert_eq!(receipt.refused_sessions(), 2);
    for (index, configuration) in configurations.into_iter().enumerate() {
        let reopened = OneNode::open_existing(configuration).unwrap();
        let snapshot = reopened
            .runtime()
            .block_on(reopened.materialize_admission())
            .unwrap();
        assert_eq!(snapshot.snapshot().refs.len(), 1);
        assert_eq!(
            snapshot.snapshot().refs[&RefName::try_new(b"refs/tags/shared").unwrap()],
            tips[index]
        );
        assert_eq!(
            reopened.read_git_object(tips[index]).unwrap().payload(),
            &[inputs[index].3]
        );
        drop(snapshot);
        reopened.shutdown().unwrap();
    }
}
