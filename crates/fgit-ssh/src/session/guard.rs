//! Read-only protocol validation before any session or channel state changes.
//!
//! SSH packet integrity is not permission to use a different protocol phase,
//! replace a running command, or address a channel that was never opened.

use super::{DEFAULT_MAX_PACKET_SIZE, SessionPhase, SshServerSession, SshSessionError, msg};
use crate::wire::WireReader;

fn require(condition: bool, reason: &'static str) -> Result<(), SshSessionError> {
    if condition {
        Ok(())
    } else {
        Err(SshSessionError::ProtocolViolation {
            reason: reason.to_owned(),
        })
    }
}

impl SshServerSession {
    /// Validate the entire supported message before the dispatcher's first
    /// mutation. Unknown methods/requests have opaque payloads and are denied
    /// by the dispatcher; they never reach a supported operation accidentally.
    pub(super) fn validate_packet(&self, payload: &[u8]) -> Result<(), SshSessionError> {
        require(
            !matches!(self.phase, SessionPhase::Identification | SessionPhase::Closed),
            "SSH packet outside a live identified session",
        )?;
        let mut reader = WireReader::new(payload);
        let kind = reader.read_u8()?;
        if kind >= 80 {
            self.require_authenticated_connection()?;
        }
        // RFC 4252 sections 5.1/5.3: successful authentication is final.
        // Ignore subsequent authentication messages instead of replacing the
        // key underneath an already authorized command.
        if (50..80).contains(&kind) && self.authenticated_key.is_some() {
            return Ok(());
        }
        match kind {
            msg::KEXINIT => {
                require(
                    self.phase == SessionPhase::KeyExchange
                        && self.session_id.is_none()
                        && self.client_kexinit_payload.is_none()
                        && self.server_kexinit_payload.is_some()
                        && self.client_ident.is_some(),
                    "duplicate or unsupported rekey KEXINIT",
                )?;
                // Negotiation is parsed by the KEXINIT handler. Rekey must
                // not reset authentication or reuse the initial transcript.
                return Ok(());
            }
            msg::KEX_ECDH_INIT => {
                require(
                    self.phase == SessionPhase::KeyExchange
                        && self.ephemeral_kex.is_some()
                        && self.client_kexinit_payload.is_some()
                        && self.server_kexinit_payload.is_some()
                        && self.client_ident.is_some()
                        && self.session_id.is_none(),
                    "ECDH_INIT outside the initial key exchange",
                )?;
                reader.read_string()?;
            }
            msg::NEWKEYS => {
                require(
                    self.phase == SessionPhase::UserAuth
                        && self.pending_inbound_key.is_some()
                        && self.inbound_cipher.is_none()
                        && self.outbound_cipher.is_some(),
                    "NEWKEYS without a pending key exchange",
                )?;
            }
            msg::SERVICE_REQUEST => {
                self.require_userauth_transport()?;
                require(!self.userauth_service_accepted, "authentication service already accepted")?;
                require(reader.read_utf8()? == "ssh-userauth", "unsupported SSH service")?;
            }
            msg::USERAUTH_REQUEST => {
                self.require_userauth_transport()?;
                require(self.userauth_service_accepted, "authentication service was not requested")?;
                reader.read_utf8()?; // username is signed, never an authorization grant
                require(reader.read_utf8()? == "ssh-connection", "unsupported authenticated service")?;
                let method = reader.read_utf8()?;
                if method != "publickey" {
                    return Ok(()); // unsupported methods receive USERAUTH_FAILURE
                }
                let signed = reader.read_bool()?;
                reader.read_utf8()?; // algorithm checked before signature verification
                reader.read_string()?;
                if signed {
                    reader.read_string()?;
                }
            }
            msg::CHANNEL_OPEN => {
                let channel_type = reader.read_utf8()?;
                reader.read_u32()?; // sender's channel, not our local channel
                reader.read_u32()?; // window may legitimately start at zero
                reader.read_u32()?;
                if channel_type != "session" {
                    return Ok(()); // unknown channel types have their own opaque fields
                }
            }
            msg::CHANNEL_REQUEST => {
                self.validate_channel(&mut reader)?;
                require(!self.channel_teardown.close_sent, "request after channel close")?;
                let request = reader.read_utf8()?;
                reader.read_bool()?;
                match request {
                    "exec" => { reader.read_utf8()?; }
                    "env" => {
                        reader.read_utf8()?;
                        reader.read_string()?;
                    }
                    _ => return Ok(()), // unsupported request; no state mutation
                }
            }
            msg::CHANNEL_DATA => {
                self.validate_channel(&mut reader)?;
                require(
                    !self.channel_teardown.eof_received && !self.channel_teardown.close_sent,
                    "channel data after EOF or close",
                )?;
                let data = reader.read_string()?;
                require(
                    data.len() <= DEFAULT_MAX_PACKET_SIZE as usize,
                    "channel data exceeds the advertised maximum packet size",
                )?;
                require(
                    data.len() <= self.server_window_size as usize,
                    "client sent channel data beyond the advertised window",
                )?;
            }
            msg::CHANNEL_WINDOW_ADJUST => {
                self.validate_channel(&mut reader)?;
                let increment = reader.read_u32()?;
                require(
                    self.client_window_size.checked_add(increment).is_some(),
                    "channel window adjustment overflows uint32",
                )?;
            }
            msg::CHANNEL_EOF | msg::CHANNEL_CLOSE => {
                self.validate_channel(&mut reader)?;
            }
            // DISCONNECT and transport-extension messages cannot grant a
            // principal or start a command. Strict KEX has its own allowlist.
            _ => return Ok(()),
        }
        require(reader.remaining() == 0, "trailing bytes in SSH message")
    }

    fn require_userauth_transport(&self) -> Result<(), SshSessionError> {
        require(
            self.phase == SessionPhase::UserAuth
                && self.inbound_cipher.is_some()
                && self.outbound_cipher.is_some()
                && self.pending_inbound_key.is_none()
                && self.session_id.is_some(),
            "user authentication requires completed encrypted key exchange",
        )
    }

    fn require_authenticated_connection(&self) -> Result<(), SshSessionError> {
        require(
            matches!(self.phase, SessionPhase::ChannelReady | SessionPhase::ActiveChannel)
                && self.authenticated_key.is_some()
                && self.inbound_cipher.is_some()
                && self.outbound_cipher.is_some(),
            "SSH connection message before authentication",
        )
    }

    fn validate_channel(&self, reader: &mut WireReader<'_>) -> Result<(), SshSessionError> {
        self.require_authenticated_connection()?;
        require(self.client_channel_id.is_some(), "SSH channel has not been opened")?;
        require(
            reader.read_u32()? == self.server_channel_id,
            "SSH message addressed to an unknown local channel",
        )
    }
}
