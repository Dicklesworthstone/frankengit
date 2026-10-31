//! Issuance of the existing detached operator approval, after native preflight.
//! The canonical statement, decoder, PAE verifier and trust binding stay shared.

use super::*;
use fgit_crypto::DsseEd25519SigningKey;

const ED25519_PKCS8_PREFIX: &[u8; 16] =
    b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

#[derive(Clone, Debug)]
pub(in super::super) struct Declarations {
    pub identity: Identity,
    pub generation: u64,
    pub expires_at: Option<String>,
    #[cfg(test)]
    pub clock: Option<Arc<AtomicI64>>,
}

impl Declarations {
    pub(in super::super) fn match_archive(&self, header: &StreamHeader) -> Result<(), String> {
        if self.generation == 0
            || self.identity != header.identity
            || header.authority.head.as_ref().map(|head| head.generation) != Some(self.generation)
        {
            return Err(
                "backup attestation declarations do not match the natively verified archive".into(),
            );
        }
        Ok(())
    }

    pub(in super::super) fn check_current(&self, deadline: Deadline) -> Result<i64, String> {
        deadline.check()?;
        #[cfg(test)]
        let now = self
            .clock
            .as_ref()
            .map_or_else(now_millis, |clock| Ok(clock.load(Ordering::SeqCst)))?;
        #[cfg(not(test))]
        let now = now_millis()?;
        if !(0..=MAX_TIME_MILLIS).contains(&now) {
            return Err("backup attestation clock is outside the supported UTC range".into());
        }
        if self
            .expires_at
            .as_deref()
            .map(instant)
            .transpose()?
            .is_some_and(|end| end <= now)
        {
            return Err("backup attestation has expired".into());
        }
        Ok(now)
    }
}

#[derive(Default)]
pub(in super::super) struct DeclarationFlags {
    tenant: Option<TenantId>,
    repository: Option<RepositoryId>,
    incarnation: Option<RepositoryIncarnationId>,
    format: Option<GitHashAlgorithm>,
    generation: Option<u64>,
    expiry: Option<String>,
}

impl DeclarationFlags {
    pub(in super::super) fn accepts(flag: &str) -> bool {
        matches!(
            flag,
            "--tenant-id"
                | "--repository-id"
                | "--incarnation-id"
                | "--object-format"
                | "--head-generation"
                | "--expires-at"
        )
    }

    pub(in super::super) fn set(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--tenant-id" => set_once(&mut self.tenant, TenantId::from_bytes(unhex(value)?), flag),
            "--repository-id" => set_once(
                &mut self.repository,
                RepositoryId::from_bytes(unhex(value)?),
                flag,
            ),
            "--incarnation-id" => set_once(
                &mut self.incarnation,
                RepositoryIncarnationId::from_bytes(unhex(value)?),
                flag,
            ),
            "--object-format" => set_once(&mut self.format, object_format(value)?, flag),
            "--head-generation" => set_once(&mut self.generation, decimal(value, u64::MAX)?, flag),
            "--expires-at" => {
                instant(value)?;
                set_once(&mut self.expiry, value.to_owned(), flag)
            }
            _ => Err("unknown attestation declaration".into()),
        }
    }

    pub(in super::super) fn finish(self) -> Result<Declarations, String> {
        let required = || {
            "attestation requires explicit --tenant-id, --repository-id, --incarnation-id, --object-format and exact --head-generation".to_owned()
        };
        Ok(Declarations {
            identity: Identity {
                tenant: self.tenant.ok_or_else(required)?,
                repository: self.repository.ok_or_else(required)?,
                incarnation: self.incarnation.ok_or_else(required)?,
                format: self.format.ok_or_else(required)?,
            },
            generation: self.generation.ok_or_else(required)?,
            expires_at: self.expiry,
            #[cfg(test)]
            clock: None,
        })
    }
}

/// Canonical RFC 8410 PKCS#8 only: version zero, absent algorithm parameters,
/// exactly the 32-byte Ed25519 seed, and no public-key/attribute extensions.
pub(in super::super) fn signing_key(input: &[u8]) -> Result<DsseEd25519SigningKey, String> {
    if input.is_empty() || input.len() > MAX_KEY_BYTES || !input.is_ascii() {
        return Err("backup attestation requires a bounded canonical Ed25519 private PEM".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "invalid backup private PEM")?;
    let text = text
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .ok_or("expected private PKCS#8 PEM")?;
    let text = text
        .strip_prefix("\r\n")
        .or_else(|| text.strip_prefix('\n'))
        .ok_or("invalid private PEM header")?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let text = text
        .strip_suffix("-----END PRIVATE KEY-----")
        .ok_or("invalid private PEM footer")?;
    let mut encoded: Vec<u8> = text
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .collect();
    let decoded = base64(
        std::str::from_utf8(&encoded).map_err(|_| "invalid private PEM body")?,
        48,
    );
    encoded.fill(0);
    let mut der = decoded?;
    let result = if der.len() == 48 && &der[..16] == ED25519_PKCS8_PREFIX {
        let mut seed = [0; 32];
        seed.copy_from_slice(&der[16..]);
        Ok(DsseEd25519SigningKey::from_seed(seed))
    } else {
        Err("backup attestation requires canonical Ed25519 PKCS#8 DER".into())
    };
    der.fill(0);
    result
}

pub(in super::super) struct IssuedApproval {
    bytes: Vec<u8>,
    authenticated: VerifiedApproval,
}

impl IssuedApproval {
    pub(in super::super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(in super::super) fn check_current(&self) -> Result<(), String> {
        self.authenticated.check_current()
    }
    pub(in super::super) fn trusted_key_id(&self) -> &str {
        &self.authenticated.trusted_key_id
    }
    pub(in super::super) fn statement_json(&self) -> String {
        self.authenticated.statement.canonical()
    }
}

/// Private caller must first match these declarations to typed native preflight
/// evidence. The resulting envelope is independently decoded and verified here.
pub(in super::super) fn issue(
    declarations: &Declarations,
    header: &StreamHeader,
    seal: Seal,
    maximum_archive_bytes: u64,
    key: &DsseEd25519SigningKey,
    deadline: Deadline,
) -> Result<IssuedApproval, String> {
    declarations.match_archive(header)?;
    let now = declarations.check_current(deadline)?;
    let issued_at = utc_second(now)?;
    let statement = Statement {
        identity: declarations.identity,
        generation: declarations.generation,
        issued_millis: instant(&issued_at)?,
        issued_at,
        expires_at: declarations.expires_at.clone(),
        expires_millis: declarations
            .expires_at
            .as_deref()
            .map(instant)
            .transpose()?,
        archive_bytes: seal.bytes,
        digest: seal.digest,
    };
    let payload = statement.canonical();
    // Keep profile validation in the one existing decoder, including canonical
    // JSON spelling, finite sizes, lifetime and full-width positive counters.
    Statement::parse(payload.as_bytes(), maximum_archive_bytes)?;
    let signature = key
        .sign(PAYLOAD_TYPE, payload.as_bytes())
        .map_err(|error| format!("backup attestation signing refused: {error}"))?;
    let mut der = [0; 44];
    der[..12].copy_from_slice(ED25519_SPKI_PREFIX);
    der[12..].copy_from_slice(key.verifying_key().as_bytes());
    let key_id = format!("sha256:{}", hex(&sha256(&der)));
    let bytes = format!(
        "{{\"payloadType\":\"{PAYLOAD_TYPE}\",\"payload\":\"{}\",\"signatures\":[{{\"keyid\":\"{key_id}\",\"sig\":\"{}\"}}]}}\n",
        encode_base64(payload.as_bytes()), encode_base64(&signature),
    ).into_bytes();
    let public_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64(&der)
    );
    let options = ApprovalOptions {
        approval: PathBuf::new(),
        trust_key: PathBuf::new(),
        policy: Policy {
            identity: declarations.identity,
            minimum_generation: declarations.generation,
        },
        #[cfg(test)]
        clock: declarations.clock.clone(),
    };
    let authenticated = options.authenticate_bytes(
        &bytes,
        public_pem.as_bytes(),
        seal.digest,
        maximum_archive_bytes,
        deadline,
    )?;
    authenticated.match_archive(header, seal)?;
    Ok(IssuedApproval {
        bytes,
        authenticated,
    })
}

fn encode_base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let bits = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(char::from(DIGITS[(bits >> 18) as usize]));
        encoded.push(char::from(DIGITS[((bits >> 12) & 63) as usize]));
        encoded.push(if chunk.len() > 1 {
            char::from(DIGITS[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(DIGITS[(bits & 63) as usize])
        } else {
            '='
        });
    }
    encoded
}

fn utc_second(millis: i64) -> Result<String, String> {
    if !(0..=MAX_TIME_MILLIS).contains(&millis) {
        return Err("backup attestation clock is outside the supported UTC range".into());
    }
    let seconds = millis / 1000;
    let day = seconds / 86_400 + 719_468;
    let era = day / 146_097;
    let day_of_era = day - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let date = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = shifted_month + if shifted_month < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let within_day = seconds % 86_400;
    let text = format!(
        "{year:04}-{month:02}-{date:02}T{:02}:{:02}:{:02}Z",
        within_day / 3600,
        within_day / 60 % 60,
        within_day % 60
    );
    if instant(&text)? != seconds * 1000 {
        return Err("backup attestation UTC conversion refused".into());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_issuance_round_trips_boundaries_and_leap_days() {
        for text in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T23:59:59Z",
            "2100-03-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            assert_eq!(utc_second(instant(text).unwrap() + 999).unwrap(), text);
        }
        assert!(utc_second(-1).is_err());
        assert!(utc_second(MAX_TIME_MILLIS + 1).is_err());
    }

    #[test]
    fn emitted_base64_is_accepted_without_reencoding_by_the_existing_decoder() {
        for bytes in [b"".as_slice(), b"a", b"ab", b"abc", b"\0\xff\xfe\x80"] {
            if !bytes.is_empty() {
                assert_eq!(base64(&encode_base64(bytes), bytes.len()).unwrap(), bytes);
            }
        }
    }
}
