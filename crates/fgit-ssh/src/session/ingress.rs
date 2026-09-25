//! Incremental ingress: retain at most one admitted frame, never an arbitrary
//! caller-provided burst. Read and bound the length before copying its body.

use super::{
    MAX_IDENTIFICATION_BYTES, MAX_PACKET_BYTES, SessionPhase, SshServerSession,
    SshSessionError, WireError,
};

fn identification_refusal(reason: &'static str) -> SshSessionError {
    SshSessionError::ProtocolViolation { reason: reason.to_owned() }
}

impl SshServerSession {
    pub(super) fn process_incoming_bytes(&mut self, mut input: &[u8]) -> Result<(), SshSessionError> {
        while !input.is_empty() {
            if self.phase == SessionPhase::Closed {
                return Err(SshSessionError::Disconnected { reason: "session is closed".to_owned() });
            }
            if self.phase == SessionPhase::Identification {
                let room = MAX_IDENTIFICATION_BYTES - self.incoming_buffer.len();
                if room == 0 {
                    return Err(identification_refusal("client identification exceeds 255 bytes"));
                }
                // Examine only the bounded prefix, not a potentially huge
                // burst following the banner. A coalesced first packet is
                // handled independently after the identification transition.
                let prefix = &input[..input.len().min(room)];
                let take = prefix.iter().position(|&byte| byte == b'\n')
                    .map_or(prefix.len(), |end| end + 1);
                self.incoming_buffer.extend_from_slice(&prefix[..take]);
                input = &input[take..];
                if self.incoming_buffer.last() == Some(&b'\n') {
                    self.accept_identification()?;
                } else if self.incoming_buffer.len() == MAX_IDENTIFICATION_BYTES {
                    return Err(identification_refusal("client identification exceeds 255 bytes"));
                }
                continue;
            }

            if self.incoming_buffer.len() < 4 {
                let take = input.len().min(4 - self.incoming_buffer.len());
                self.incoming_buffer.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.incoming_buffer.len() < 4 {
                    continue;
                }
            }
            let length = [
                self.incoming_buffer[0], self.incoming_buffer[1],
                self.incoming_buffer[2], self.incoming_buffer[3],
            ];
            let packet_len = match &self.inbound_cipher {
                Some(cipher) => cipher.decrypt_packet_length(&length),
                None => u32::from_be_bytes(length),
            } as usize;
            if packet_len > MAX_PACKET_BYTES {
                return Err(WireError::PacketTooLarge {
                    observed: packet_len, limit: MAX_PACKET_BYTES,
                }.into());
            }
            // Cleartext decode needs the padding-length byte even for an
            // invalid zero declaration. AEAD additionally needs its 16-byte tag.
            let total = if self.inbound_cipher.is_some() {
                4 + packet_len + 16
            } else {
                (4 + packet_len).max(5)
            };
            // Reserve only after the declared size is admitted. This also
            // avoids geometric growth when a peer fragments a large frame.
            if self.incoming_buffer.capacity() < total {
                self.incoming_buffer.reserve_exact(total - self.incoming_buffer.len());
            }
            let take = input.len().min(total - self.incoming_buffer.len());
            self.incoming_buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.incoming_buffer.len() < total {
                continue;
            }
            // The whole declared frame is present. An UnexpectedEof from a
            // payload decoder now means malformed data, not more input to await.
            let (payload, consumed) = Self::decode_packet(&mut self.inbound_cipher, &self.incoming_buffer)?;
            debug_assert_eq!(consumed, total);
            self.incoming_buffer.clear();
            self.inbound_packet_count = self.inbound_packet_count.wrapping_add(1);
            self.handle_packet(&payload)?;
        }
        Ok(())
    }

    fn accept_identification(&mut self) -> Result<(), SshSessionError> {
        let line = &self.incoming_buffer[..self.incoming_buffer.len() - 1];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let version = line.strip_prefix(b"SSH-2.0-")
            .ok_or_else(|| identification_refusal("only SSH-2.0 identification is supported"))?;
        if version.is_empty() || version[0] == b' '
            || !version.iter().all(|byte| (0x20..=0x7e).contains(byte))
        {
            return Err(identification_refusal("invalid SSH software identification"));
        }
        let ident = core::str::from_utf8(line)
            .map_err(|_| identification_refusal("invalid SSH identification encoding"))?
            .to_owned();
        self.client_ident = Some(ident);
        self.incoming_buffer.clear();
        self.phase = SessionPhase::KeyExchange;
        self.send_kexinit();
        Ok(())
    }
}
