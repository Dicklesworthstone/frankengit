//! Key re-exchange is a transport operation, not a new authentication or Git
//! session. Directional NEWKEYS boundaries leave channel state untouched.

use super::{SessionPhase, SshServerSession, SshSessionError, msg};

/// Aggregate ceiling for application/control replies deferred behind KEXINIT.
/// Bulk channel data uses backpressure instead of this queue.
pub(super) const MAX_DEFERRED_BYTES: usize = 64 * 1024;
pub(super) const MAX_DEFERRED_PACKETS: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum RekeyPhase {
    #[default]
    Idle,
    AwaitKexinit,
    AwaitEcdh,
    AwaitNewkeys,
}

#[derive(Default)]
pub(super) struct RekeyState {
    pub(super) phase: RekeyPhase,
    deferred: Vec<Vec<u8>>,
    deferred_bytes: usize,
}
impl RekeyState {
    pub(super) fn blocks_output(&self) -> bool {
        matches!(self.phase, RekeyPhase::AwaitKexinit | RekeyPhase::AwaitEcdh)
    }
    pub(super) fn blocks_input(&self) -> bool {
        matches!(self.phase, RekeyPhase::AwaitEcdh | RekeyPhase::AwaitNewkeys)
    }
}

fn refusal(reason: &'static str) -> SshSessionError {
    SshSessionError::ProtocolViolation { reason: reason.to_owned() }
}

impl SshServerSession {
    /// True until both directions have installed the new keys. Authentication,
    /// channel windows and the active command remain those of this session.
    #[must_use]
    pub fn is_rekeying(&self) -> bool {
        self.rekey.phase != RekeyPhase::Idle
    }

    /// The typed terminal error, including a deferred-output budget refusal
    /// observed through a void output API. A peer's normal close has no error.
    #[must_use]
    pub const fn terminal_error(&self) -> Option<&SshSessionError> {
        self.terminal_error.as_ref()
    }

    pub(super) fn can_start_rekey(&self) -> bool {
        matches!(self.phase, SessionPhase::UserAuth | SessionPhase::ChannelReady | SessionPhase::ActiveChannel)
            && self.rekey.phase == RekeyPhase::Idle
            && self.inbound_cipher.is_some()
            && self.outbound_cipher.is_some()
            && self.session_id.is_some()
            && self.client_ident.is_some()
            && self.pending_inbound_key.is_none()
            && self.ephemeral_kex.is_none()
    }

    /// Initiate encrypted key rotation. This emits one KEXINIT under the
    /// current key; feed incoming bytes and drain outgoing bytes normally.
    /// In-flight peer traffic remains admissible until its own KEXINIT.
    /// Repeated local requests coalesce without restarting the exchange.
    /// The host still owns socket/deadline enforcement; this engine has no clock.
    pub fn request_rekey(&mut self) -> Result<(), SshSessionError> {
        if self.phase != SessionPhase::Closed && self.is_rekeying() {
            return Ok(());
        }
        if !self.can_start_rekey() {
            return Err(refusal("rekey requires a completed encrypted transport"));
        }
        self.rekey.phase = RekeyPhase::AwaitKexinit;
        self.client_kexinit_payload = None;
        self.send_kexinit();
        Ok(())
    }

    /// Generic transport traffic can cross KEX; service and connection replies
    /// cannot. Bound both bytes and packet count BEFORE copying any payload.
    pub(super) fn defer_rekey_output(&mut self, payload: &[u8]) -> Result<bool, SshSessionError> {
        let transport = payload.first().is_some_and(|kind| {
            (1..50).contains(kind) && !matches!(*kind, msg::SERVICE_REQUEST | msg::SERVICE_ACCEPT)
        });
        if !self.rekey.blocks_output() || transport {
            return Ok(false);
        }
        let bytes = self.rekey.deferred_bytes.checked_add(payload.len())
            .filter(|total| *total <= MAX_DEFERRED_BYTES)
            .ok_or_else(|| refusal("deferred rekey output exceeds byte budget"))?;
        if self.rekey.deferred.len() >= MAX_DEFERRED_PACKETS {
            return Err(refusal("deferred rekey output exceeds packet budget"));
        }
        self.rekey.deferred.try_reserve(1)
            .map_err(|_| refusal("deferred rekey output allocation refused"))?;
        let mut packet = Vec::new();
        packet.try_reserve_exact(payload.len())
            .map_err(|_| refusal("deferred rekey output allocation refused"))?;
        packet.extend_from_slice(payload);
        self.rekey.deferred.push(packet);
        self.rekey.deferred_bytes = bytes;
        Ok(true)
    }

    /// Runs only after our NEWKEYS and outbound cipher activation. The peer
    /// may still owe its NEWKEYS, so inbound authentication uses its old key.
    pub(super) fn flush_rekey_output(&mut self) {
        let packets = core::mem::take(&mut self.rekey.deferred);
        self.rekey.deferred_bytes = 0;
        for packet in packets {
            self.send_packet(&packet);
        }
    }

    pub(super) fn fail_session(&mut self, error: SshSessionError) {
        self.phase = SessionPhase::Closed;
        self.terminal_error = Some(error);
        self.incoming_buffer.clear();
        self.channel_input_data.clear();
        self.ephemeral_kex = None;
        self.pending_inbound_key = None;
        self.discard_next_kex_packet = false;
        self.userauth_service_accepted = false;
        self.authenticated_key = None;
        self.authenticated_principal = None;
        self.active_command = None;
        self.rekey = RekeyState::default();
    }
}
