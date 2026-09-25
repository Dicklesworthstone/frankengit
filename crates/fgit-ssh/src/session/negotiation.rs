//! Initial SSH algorithm negotiation. No algorithm is selected merely because
//! the server implements it: both directional offers must actually admit it.

use super::{
    CIPHER_CHACHA20_POLY1305, Curve25519Kex, KEX_CURVE25519_SHA256,
    KEX_CURVE25519_SHA256_LIBSSH, KEX_STRICT_CLIENT, SSH_ED25519_ALGORITHM,
    SshServerSession, SshSessionError, WireReader, msg,
};

fn refusal(reason: &'static str) -> SshSessionError {
    SshSessionError::ProtocolViolation { reason: reason.to_owned() }
}

fn contains(list: &str, algorithm: &str) -> bool {
    list.split(',').any(|name| name == algorithm)
}

fn valid_names(list: &str) -> bool {
    list.is_empty() || list.split(',').all(|name| {
        !name.is_empty() && name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    })
}

impl SshServerSession {
    pub(super) fn accept_kexinit(&mut self, payload: &[u8]) -> Result<(), SshSessionError> {
        let mut reader = WireReader::new(payload);
        if reader.read_u8()? != msg::KEXINIT {
            return Err(refusal("expected KEXINIT"));
        }
        reader.read_exact(16)?;
        // Borrow all ten lists. Even a packet full of commas cannot allocate
        // a Vec entry per name, and no state changes precede full validation.
        let lists = [
            reader.read_utf8()?, reader.read_utf8()?,
            reader.read_utf8()?, reader.read_utf8()?,
            reader.read_utf8()?, reader.read_utf8()?,
            reader.read_utf8()?, reader.read_utf8()?,
            reader.read_utf8()?, reader.read_utf8()?,
        ];
        let follows = reader.read_bool()?;
        let reserved = reader.read_u32()?;
        if reserved != 0 || reader.remaining() != 0 {
            return Err(refusal("noncanonical KEXINIT tail"));
        }
        if lists[..8].iter().any(|list| list.is_empty())
            || lists.iter().any(|list| !valid_names(list))
        {
            return Err(refusal("invalid SSH algorithm name-list"));
        }
        // RFC 4253 section 7.1: client order chooses the first common KEX.
        // Extension markers are not key-exchange methods.
        let selected_kex = lists[0].split(',').find(|name| {
            *name == KEX_CURVE25519_SHA256 || *name == KEX_CURVE25519_SHA256_LIBSSH
        }).ok_or_else(|| refusal("no mutually supported key-exchange algorithm"))?;
        if !contains(lists[1], SSH_ED25519_ALGORITHM) {
            return Err(refusal("no mutually supported host-key algorithm"));
        }
        if !contains(lists[2], CIPHER_CHACHA20_POLY1305)
            || !contains(lists[3], CIPHER_CHACHA20_POLY1305)
        {
            return Err(refusal("no mutually supported cipher in both directions"));
        }
        // ChaCha20-Poly1305 authenticates its own packets; the separately
        // offered MAC algorithms are not selected for this AEAD cipher.
        if !contains(lists[6], "none") || !contains(lists[7], "none") {
            return Err(refusal("compression is unsupported in one or both directions"));
        }
        let strict = contains(lists[0], KEX_STRICT_CLIENT);
        if strict && self.inbound_packet_count != 1 {
            return Err(refusal("strict KEX requires KEXINIT to be the first packet"));
        }
        let wrong_guess = lists[0].split(',').next() != Some(selected_kex)
            || lists[1].split(',').next() != Some(SSH_ED25519_ALGORITHM);

        self.strict_kex = strict;
        self.discard_next_kex_packet = follows && wrong_guess;
        self.client_kexinit_payload = Some(payload.to_vec());
        self.ephemeral_kex = Some(Curve25519Kex::from_private_bytes(self.random_bytes()));
        Ok(())
    }
}
