//! SSH-2.0 protocol session state machine and channel management.
//!
//! Provides a pure-Rust, SANS-I/O SSH server state machine that executes
//! identification exchange, KEX negotiation, user authentication, channel multiplexing,
//! and typed Git command dispatch.

use core::fmt::{self, Display, Formatter};

use ed25519_dalek::SigningKey;
use fgit_crypto::sha256_digest;
use fgit_identity::deploy_key::DeployKeyBinding;
use fgit_identity::revocation::RevocationEvidence;
use fgit_types::{PrincipalId, RepositoryId};

use crate::auth::{AuthRefusal, authorize_deploy_key, verify_client_signature};
use crate::command::{CommandParseRefusal, SshGitCommand};
use crate::crypto::{
    CIPHER_CHACHA20_POLY1305, CryptoError, Curve25519Kex, KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBSSH, OpenSshChaCha20Poly1305, SSH_ED25519_ALGORITHM, derive_key,
    encode_ed25519_public_key, sign_ed25519,
};
use crate::wire::{
    WireError, WireReader, WireWriter, decode_cleartext_packet, encode_cleartext_packet,
};

/// FrankenGit SSH identification string.
pub const SERVER_IDENTIFICATION: &str = "SSH-2.0-FrankenGit-0.1";

/// Maximum window size for SSH channel flow control (2 MiB).
pub const DEFAULT_WINDOW_SIZE: u32 = 2 * 1024 * 1024;
/// Maximum channel packet size (32 KiB).
pub const DEFAULT_MAX_PACKET_SIZE: u32 = 32 * 1024;

/// SSH message type codes (RFC 4250 / RFC 4253 / RFC 4254).
pub mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const KEX_ECDH_INIT: u8 = 30;
    pub const KEX_ECDH_REPLY: u8 = 31;
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_PK_OK: u8 = 60;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
}

/// Errors occurring during SSH session protocol operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshSessionError {
    Wire(WireError),
    Crypto(CryptoError),
    Auth(AuthRefusal),
    Command(CommandParseRefusal),
    ProtocolViolation { reason: String },
    Disconnected { reason: String },
}

impl Display for SshSessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(err) => write!(formatter, "SSH wire error: {err}"),
            Self::Crypto(err) => write!(formatter, "SSH crypto error: {err}"),
            Self::Auth(err) => write!(formatter, "SSH authentication refusal: {err}"),
            Self::Command(err) => write!(formatter, "SSH command refusal: {err}"),
            Self::ProtocolViolation { reason } => write!(formatter, "SSH protocol violation: {reason}"),
            Self::Disconnected { reason } => write!(formatter, "SSH session disconnected: {reason}"),
        }
    }
}

impl core::error::Error for SshSessionError {}

impl From<WireError> for SshSessionError {
    fn from(err: WireError) -> Self {
        Self::Wire(err)
    }
}

impl From<CryptoError> for SshSessionError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<AuthRefusal> for SshSessionError {
    fn from(err: AuthRefusal) -> Self {
        Self::Auth(err)
    }
}

impl From<CommandParseRefusal> for SshSessionError {
    fn from(err: CommandParseRefusal) -> Self {
        Self::Command(err)
    }
}

/// Phase in the SSH session lifecycle.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionPhase {
    /// Reading/writing identification strings.
    Identification,
    /// Exchanging KEXINIT and Curve25519 ECDH keys.
    KeyExchange,
    /// Authenticating user via publickey.
    UserAuth,
    /// Ready for channel open and exec request.
    ChannelReady,
    /// Channel open and Git command active.
    ActiveChannel,
    /// Session closed or disconnected.
    Closed,
}

/// A server-side SSH session.
pub struct SshServerSession {
    phase: SessionPhase,
    server_signing_key: SigningKey,
    deploy_keys: Vec<DeployKeyBinding>,
    server_ident: String,
    client_ident: Option<String>,
    server_kexinit_payload: Option<Vec<u8>>,
    client_kexinit_payload: Option<Vec<u8>>,
    ephemeral_kex: Option<Curve25519Kex>,
    session_id: Option<[u8; 32]>,
    inbound_cipher: Option<OpenSshChaCha20Poly1305>,
    pending_inbound_cipher: Option<OpenSshChaCha20Poly1305>,
    outbound_cipher: Option<OpenSshChaCha20Poly1305>,
    authenticated_key: Option<[u8; 32]>,
    authenticated_principal: Option<PrincipalId>,
    client_channel_id: Option<u32>,
    server_channel_id: u32,
    client_window_size: u32,
    server_window_size: u32,
    active_command: Option<SshGitCommand>,
    outgoing_bytes: Vec<u8>,
    channel_input_data: Vec<u8>,
    channel_eof_received: bool,
    channel_closed_received: bool,
}

impl SshServerSession {
    /// Creates a new SSH server session with given host signing key and deploy key bindings.
    #[must_use]
    pub fn new(server_signing_key: SigningKey, deploy_keys: Vec<DeployKeyBinding>) -> Self {
        Self {
            phase: SessionPhase::Identification,
            server_signing_key,
            deploy_keys,
            server_ident: SERVER_IDENTIFICATION.to_owned(),
            client_ident: None,
            server_kexinit_payload: None,
            client_kexinit_payload: None,
            ephemeral_kex: None,
            session_id: None,
            inbound_cipher: None,
            pending_inbound_cipher: None,
            outbound_cipher: None,
            authenticated_key: None,
            authenticated_principal: None,
            client_channel_id: None,
            server_channel_id: 0,
            client_window_size: DEFAULT_WINDOW_SIZE,
            server_window_size: DEFAULT_WINDOW_SIZE,
            active_command: None,
            outgoing_bytes: Vec::new(),
            channel_input_data: Vec::new(),
            channel_eof_received: false,
            channel_closed_received: false,
        }
    }

    /// The current lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> &SessionPhase {
        &self.phase
    }

    /// The authenticated principal, if publickey authentication has succeeded.
    #[must_use]
    pub const fn authenticated_principal(&self) -> Option<PrincipalId> {
        self.authenticated_principal
    }

    /// The active Git command, if authorized and running.
    #[must_use]
    pub const fn active_command(&self) -> Option<&SshGitCommand> {
        self.active_command.as_ref()
    }

    /// The client channel ID, if a channel has been opened.
    #[must_use]
    pub const fn client_channel_id(&self) -> Option<u32> {
        self.client_channel_id
    }

    /// Whether the client sent EOF on the active channel.
    #[must_use]
    pub const fn is_channel_eof_received(&self) -> bool {
        self.channel_eof_received
    }

    /// Whether the client sent close on the active channel.
    #[must_use]
    pub const fn is_channel_closed(&self) -> bool {
        self.channel_closed_received
    }

    /// Takes queued outgoing bytes to send to the network transport.
    pub fn take_outgoing_bytes(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing_bytes)
    }

    /// Takes queued channel data (stdin to Git).
    pub fn take_channel_input(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.channel_input_data)
    }

    /// Begins the session by emitting the identification banner.
    pub fn start(&mut self) {
        let banner = format!("{}\r\n", self.server_ident);
        self.outgoing_bytes.extend_from_slice(banner.as_bytes());
    }

    /// Feeds incoming raw wire bytes into the session engine.
    ///
    /// # Errors
    ///
    /// Returns [`SshSessionError`] if a wire error, cryptographic failure,
    /// or protocol violation occurs.
    pub fn handle_incoming_bytes(&mut self, mut input: &[u8]) -> Result<(), SshSessionError> {
        if self.phase == SessionPhase::Identification {
            // Find line break for client identification
            if let Some(pos) = input.windows(2).position(|w| w == b"\r\n") {
                let ident_bytes = &input[..pos];
                let ident = core::str::from_utf8(ident_bytes)
                    .map_err(|_| SshSessionError::ProtocolViolation {
                        reason: "client identification is not valid UTF-8".to_owned(),
                    })?
                    .to_owned();
                self.client_ident = Some(ident);
                input = &input[pos + 2..];
                self.phase = SessionPhase::KeyExchange;
                self.send_kexinit();
            } else if let Some(pos) = input.iter().position(|&b| b == b'\n') {
                let ident_bytes = &input[..pos];
                let ident = core::str::from_utf8(ident_bytes)
                    .map_err(|_| SshSessionError::ProtocolViolation {
                        reason: "client identification is not valid UTF-8".to_owned(),
                    })?
                    .to_owned();
                self.client_ident = Some(ident);
                input = &input[pos + 1..];
                self.phase = SessionPhase::KeyExchange;
                self.send_kexinit();
            } else {
                // Incomplete line
                return Ok(());
            }
        }

        // Process packets from input
        while !input.is_empty() {
            let (payload, consumed) = self.decode_packet(input)?;
            input = &input[consumed..];
            self.handle_packet(&payload)?;
        }

        Ok(())
    }

    /// Decodes a packet from incoming slice, returning payload and bytes consumed.
    fn decode_packet(&mut self, input: &[u8]) -> Result<(Vec<u8>, usize), SshSessionError> {
        if let Some(ref mut cipher) = self.inbound_cipher {
            if input.len() < 20 {
                return Err(WireError::UnexpectedEof {
                    expected: 20,
                    available: input.len(),
                }.into());
            }
            let mut len_arr = [0u8; 4];
            len_arr.copy_from_slice(&input[0..4]);
            let packet_len = cipher.decrypt_packet_length(&len_arr) as usize;
            let total = 4 + packet_len + 16;
            if input.len() < total {
                return Err(WireError::UnexpectedEof {
                    expected: total,
                    available: input.len(),
                }.into());
            }
            let payload = cipher.decrypt_packet(&input[..total])?;
            Ok((payload, total))
        } else {
            if input.len() < 5 {
                return Err(WireError::UnexpectedEof {
                    expected: 5,
                    available: input.len(),
                }.into());
            }
            let packet_len = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
            let total = 4 + packet_len;
            if input.len() < total {
                return Err(WireError::UnexpectedEof {
                    expected: total,
                    available: input.len(),
                }.into());
            }
            let payload = decode_cleartext_packet(&input[..total])?.to_vec();
            Ok((payload, total))
        }
    }

    /// Sends a packet with payload.
    fn send_packet(&mut self, payload: &[u8]) {
        if let Some(ref mut cipher) = self.outbound_cipher {
            let wire = cipher.encrypt_packet(payload, &[0u8; 16]);
            self.outgoing_bytes.extend_from_slice(&wire);
        } else {
            let wire = encode_cleartext_packet(payload, &[0u8; 16]);
            self.outgoing_bytes.extend_from_slice(&wire);
        }
    }

    /// Sends server KEXINIT packet.
    fn send_kexinit(&mut self) {
        let mut writer = WireWriter::new();
        writer.write_u8(msg::KEXINIT);
        // 16-byte cookie
        writer.write_raw(&[0x42; 16]);
        // KEX algorithms
        writer.write_name_list(&[KEX_CURVE25519_SHA256, KEX_CURVE25519_SHA256_LIBSSH]);
        // Server host key algorithms
        writer.write_name_list(&[SSH_ED25519_ALGORITHM]);
        // Ciphers
        writer.write_name_list(&[CIPHER_CHACHA20_POLY1305]);
        writer.write_name_list(&[CIPHER_CHACHA20_POLY1305]);
        // MACs
        writer.write_name_list(&["none"]);
        writer.write_name_list(&["none"]);
        // Compression
        writer.write_name_list(&["none"]);
        writer.write_name_list(&["none"]);
        // Languages
        writer.write_name_list(&[]);
        writer.write_name_list(&[]);
        // first_kex_packet_follows
        writer.write_bool(false);
        // reserved
        writer.write_u32(0);

        let payload = writer.into_bytes();
        self.server_kexinit_payload = Some(payload.clone());
        self.send_packet(&payload);
    }

    /// Handles a decrypted packet payload.
    fn handle_packet(&mut self, payload: &[u8]) -> Result<(), SshSessionError> {
        let mut reader = WireReader::new(payload);
        let msg_type = reader.read_u8()?;

        match msg_type {
            msg::DISCONNECT => {
                let reason_code = reader.read_u32().unwrap_or(0);
                let desc = reader.read_utf8().unwrap_or("");
                self.phase = SessionPhase::Closed;
                return Err(SshSessionError::Disconnected {
                    reason: format!("peer sent disconnect ({reason_code}): {desc}"),
                });
            }
            msg::IGNORE => {}
            msg::KEXINIT => {
                self.client_kexinit_payload = Some(payload.to_vec());
                // Prepare Curve25519 ephemeral key
                self.ephemeral_kex = Some(Curve25519Kex::from_private_bytes([0x77; 32]));
            }
            msg::KEX_ECDH_INIT => {
                let client_pub = reader.read_string()?;
                if client_pub.len() != 32 {
                    return Err(CryptoError::InvalidPublicKeyLength {
                        observed: client_pub.len(),
                    }.into());
                }
                let mut client_pub_arr = [0u8; 32];
                client_pub_arr.copy_from_slice(client_pub);

                let kex = self.ephemeral_kex.as_ref().ok_or_else(|| {
                    SshSessionError::ProtocolViolation {
                        reason: "KEX_ECDH_INIT received before KEXINIT".to_owned(),
                    }
                })?;

                let shared_secret = kex.compute_shared_secret(&client_pub_arr)?;

                // Format shared secret as mpint
                let mut mpint_writer = WireWriter::new();
                mpint_writer.write_mpint(&shared_secret);
                let k_mpint = mpint_writer.into_bytes();

                // Compute exchange hash H
                let host_pub_key = self.server_signing_key.verifying_key();
                let host_key_blob = encode_ed25519_public_key(&host_pub_key.to_bytes());

                let mut hash_writer = WireWriter::new();
                hash_writer.write_string(self.client_ident.as_ref().unwrap().as_bytes());
                hash_writer.write_string(self.server_ident.as_bytes());
                hash_writer.write_string(self.client_kexinit_payload.as_ref().unwrap());
                hash_writer.write_string(self.server_kexinit_payload.as_ref().unwrap());
                hash_writer.write_string(&host_key_blob);
                hash_writer.write_string(&client_pub_arr);
                hash_writer.write_string(kex.public_key());
                hash_writer.write_raw(&k_mpint);

                let hash_h = sha256_digest(&hash_writer.into_bytes());

                // Set session ID if initial key exchange
                if self.session_id.is_none() {
                    self.session_id = Some(hash_h);
                }
                let session_id = self.session_id.unwrap();

                // Sign exchange hash H
                let sig_blob = sign_ed25519(&self.server_signing_key, &hash_h);

                // Send KEX_ECDH_REPLY
                let mut reply = WireWriter::new();
                reply.write_u8(msg::KEX_ECDH_REPLY);
                reply.write_string(&host_key_blob);
                reply.write_string(kex.public_key());
                reply.write_string(&sig_blob);
                self.send_packet(&reply.into_bytes());

                // Derive keys per RFC 4253 section 7.2
                // C->S key (char 'C'): 64 bytes
                let client_key = derive_key(&k_mpint, &hash_h, b'C', &session_id, 64);
                // S->C key (char 'D'): 64 bytes
                let server_key = derive_key(&k_mpint, &hash_h, b'D', &session_id, 64);

                let mut c_key_arr = [0u8; 64];
                let mut s_key_arr = [0u8; 64];
                c_key_arr.copy_from_slice(&client_key);
                s_key_arr.copy_from_slice(&server_key);

                // Send NEWKEYS
                let mut newkeys = WireWriter::new();
                newkeys.write_u8(msg::NEWKEYS);
                self.send_packet(&newkeys.into_bytes());

                // Activate outbound cipher
                self.outbound_cipher = Some(OpenSshChaCha20Poly1305::new(&s_key_arr));

                // Stash inbound cipher to activate upon receiving client NEWKEYS
                self.pending_inbound_cipher = Some(OpenSshChaCha20Poly1305::new(&c_key_arr));
                self.phase = SessionPhase::UserAuth;
            }
            msg::NEWKEYS => {
                // Client has activated encryption. Future inbound packets use this cipher.
                self.inbound_cipher = self.pending_inbound_cipher.take();
            }
            msg::SERVICE_REQUEST => {
                let service = reader.read_utf8()?;
                if service == "ssh-userauth" {
                    let mut accept = WireWriter::new();
                    accept.write_u8(msg::SERVICE_ACCEPT);
                    accept.write_utf8("ssh-userauth");
                    self.send_packet(&accept.into_bytes());
                } else {
                    let mut disc = WireWriter::new();
                    disc.write_u8(msg::DISCONNECT);
                    disc.write_u32(2); // SSH_DISCONNECT_PROTOCOL_ERROR
                    disc.write_utf8("unsupported service");
                    disc.write_utf8("");
                    self.send_packet(&disc.into_bytes());
                }
            }
            msg::USERAUTH_REQUEST => {
                let user_name = reader.read_utf8()?;
                let service_name = reader.read_utf8()?;
                let method = reader.read_utf8()?;

                if method == "publickey" {
                    let has_sig = reader.read_bool()?;
                    let algo = reader.read_utf8()?;
                    let key_blob = reader.read_string()?;

                    if algo != SSH_ED25519_ALGORITHM {
                        self.send_auth_failure();
                        return Ok(());
                    }

                    if has_sig {
                        let sig_blob = reader.read_string()?;
                        let session_id = self.session_id.ok_or_else(|| {
                            SshSessionError::ProtocolViolation {
                                reason: "session ID unavailable during userauth".to_owned(),
                            }
                        })?;

                        match verify_client_signature(&session_id, user_name, service_name, key_blob, sig_blob) {
                            Ok(pub_key_bytes) => {
                                self.authenticated_key = Some(pub_key_bytes);
                                self.phase = SessionPhase::ChannelReady;
                                let mut success = WireWriter::new();
                                success.write_u8(msg::USERAUTH_SUCCESS);
                                self.send_packet(&success.into_bytes());
                            }
                            Err(_) => {
                                self.send_auth_failure();
                            }
                        }
                    } else {
                        // Key query: send PK_OK
                        let mut ok = WireWriter::new();
                        ok.write_u8(msg::USERAUTH_PK_OK);
                        ok.write_utf8(SSH_ED25519_ALGORITHM);
                        ok.write_string(key_blob);
                        self.send_packet(&ok.into_bytes());
                    }
                } else {
                    self.send_auth_failure();
                }
            }
            msg::CHANNEL_OPEN => {
                let channel_type = reader.read_utf8()?;
                let sender_channel = reader.read_u32()?;
                let initial_window = reader.read_u32()?;
                let _max_packet = reader.read_u32()?;

                if channel_type == "session" {
                    self.client_channel_id = Some(sender_channel);
                    self.client_window_size = initial_window;
                    let mut confirm = WireWriter::new();
                    confirm.write_u8(msg::CHANNEL_OPEN_CONFIRMATION);
                    confirm.write_u32(sender_channel);
                    confirm.write_u32(self.server_channel_id);
                    confirm.write_u32(self.server_window_size);
                    confirm.write_u32(DEFAULT_MAX_PACKET_SIZE);
                    self.send_packet(&confirm.into_bytes());
                } else {
                    let mut fail = WireWriter::new();
                    fail.write_u8(msg::CHANNEL_OPEN_FAILURE);
                    fail.write_u32(sender_channel);
                    fail.write_u32(3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
                    fail.write_utf8("only session channels supported");
                    fail.write_utf8("");
                    self.send_packet(&fail.into_bytes());
                }
            }
            msg::CHANNEL_REQUEST => {
                let recipient_channel = reader.read_u32()?;
                let request_type = reader.read_utf8()?;
                let want_reply = reader.read_bool()?;

                if request_type == "exec" {
                    let command_str = reader.read_utf8()?;
                    let parsed_command = match SshGitCommand::parse(command_str) {
                        Ok(cmd) => cmd,
                        Err(refusal) => {
                            if want_reply {
                                self.send_channel_failure(recipient_channel);
                            }
                            self.send_channel_extended_data(
                                recipient_channel,
                                format!("ERR: {refusal}\n").as_bytes(),
                            );
                            self.send_channel_close(recipient_channel, 1);
                            return Ok(());
                        }
                    };

                    // Authorize command against authenticated public key and deploy keys
                    let pub_key = match self.authenticated_key {
                        Some(ref k) => k,
                        None => {
                            if want_reply {
                                self.send_channel_failure(recipient_channel);
                            }
                            self.send_channel_extended_data(
                                recipient_channel,
                                b"ERR: unauthenticated session\n",
                            );
                            self.send_channel_close(recipient_channel, 1);
                            return Ok(());
                        }
                    };

                    let digest = sha256_digest(parsed_command.repository_path().as_bytes());
                    let mut repo_bytes = [0u8; 16];
                    repo_bytes.copy_from_slice(&digest[..16]);
                    let repo_id = RepositoryId::from_bytes(repo_bytes);

                    match authorize_deploy_key(
                        &self.deploy_keys,
                        pub_key,
                        repo_id,
                        parsed_command.service(),
                        RevocationEvidence::Live,
                    ) {
                        Ok(principal) => {
                            self.authenticated_principal = Some(principal);
                            self.active_command = Some(parsed_command);
                            self.phase = SessionPhase::ActiveChannel;
                            if want_reply {
                                let mut succ = WireWriter::new();
                                succ.write_u8(msg::CHANNEL_SUCCESS);
                                succ.write_u32(recipient_channel);
                                self.send_packet(&succ.into_bytes());
                            }
                        }
                        Err(refusal) => {
                            if want_reply {
                                self.send_channel_failure(recipient_channel);
                            }
                            self.send_channel_extended_data(
                                recipient_channel,
                                format!("ERR: {refusal}\n").as_bytes(),
                            );
                            self.send_channel_close(recipient_channel, 1);
                        }
                    }
                } else if want_reply {
                    self.send_channel_failure(recipient_channel);
                }
            }
            msg::CHANNEL_DATA => {
                let _recipient_channel = reader.read_u32()?;
                let data = reader.read_string()?;
                self.channel_input_data.extend_from_slice(data);
            }
            msg::CHANNEL_WINDOW_ADJUST => {
                let _recipient_channel = reader.read_u32()?;
                let bytes_to_add = reader.read_u32()?;
                self.client_window_size = self.client_window_size.saturating_add(bytes_to_add);
            }
            msg::CHANNEL_EOF => {
                self.channel_eof_received = true;
            }
            msg::CHANNEL_CLOSE => {
                self.channel_closed_received = true;
                let recipient = self.client_channel_id.unwrap_or(0);
                let mut close = WireWriter::new();
                close.write_u8(msg::CHANNEL_CLOSE);
                close.write_u32(recipient);
                self.send_packet(&close.into_bytes());
                self.phase = SessionPhase::Closed;
            }
            _ => {
                // Send unimplemented
                let mut unimpl = WireWriter::new();
                unimpl.write_u8(msg::UNIMPLEMENTED);
                unimpl.write_u32(0);
                self.send_packet(&unimpl.into_bytes());
            }
        }

        Ok(())
    }

    /// Sends standard user authentication failure.
    fn send_auth_failure(&mut self) {
        let mut fail = WireWriter::new();
        fail.write_u8(msg::USERAUTH_FAILURE);
        fail.write_name_list(&["publickey"]);
        fail.write_bool(false);
        self.send_packet(&fail.into_bytes());
    }

    /// Sends channel failure for `recipient_channel`.
    fn send_channel_failure(&mut self, recipient_channel: u32) {
        let mut fail = WireWriter::new();
        fail.write_u8(msg::CHANNEL_FAILURE);
        fail.write_u32(recipient_channel);
        self.send_packet(&fail.into_bytes());
    }

    /// Sends channel extended data (stderr).
    pub fn send_channel_extended_data(&mut self, recipient_channel: u32, data: &[u8]) {
        let mut ext = WireWriter::new();
        ext.write_u8(msg::CHANNEL_EXTENDED_DATA);
        ext.write_u32(recipient_channel);
        ext.write_u32(1); // SSH_EXTENDED_DATA_STDERR
        ext.write_string(data);
        self.send_packet(&ext.into_bytes());
    }

    /// Sends Git stdout data over the active channel.
    pub fn send_channel_data(&mut self, data: &[u8]) {
        let channel = self.client_channel_id.unwrap_or(0);
        let mut msg = WireWriter::new();
        msg.write_u8(msg::CHANNEL_DATA);
        msg.write_u32(channel);
        msg.write_string(data);
        self.send_packet(&msg.into_bytes());
    }

    /// Sends channel EOF.
    pub fn send_channel_eof(&mut self) {
        let channel = self.client_channel_id.unwrap_or(0);
        let mut msg = WireWriter::new();
        msg.write_u8(msg::CHANNEL_EOF);
        msg.write_u32(channel);
        self.send_packet(&msg.into_bytes());
    }

    /// Closes the channel with an exit status code.
    pub fn send_channel_close(&mut self, recipient_channel: u32, exit_status: u32) {
        // 1. Send exit-status
        let mut status = WireWriter::new();
        status.write_u8(msg::CHANNEL_REQUEST);
        status.write_u32(recipient_channel);
        status.write_utf8("exit-status");
        status.write_bool(false);
        status.write_u32(exit_status);
        self.send_packet(&status.into_bytes());

        // 2. Send channel close
        let mut close = WireWriter::new();
        close.write_u8(msg::CHANNEL_CLOSE);
        close.write_u32(recipient_channel);
        self.send_packet(&close.into_bytes());
    }

    /// Closes the active client channel with an exit status code.
    pub fn send_channel_exit_and_close(&mut self, exit_status: u32) {
        let recipient = self.client_channel_id.unwrap_or(0);
        self.send_channel_close(recipient, exit_status);
    }
}
