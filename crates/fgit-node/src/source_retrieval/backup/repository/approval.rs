//! Native verification of the existing detached repository-source approval.
//! This authenticates an operator's signed statement, not a capsule or authority.
//! The real archive reader and restore engine still verify every source input.

pub(super) mod issuer;
mod observation;
pub(super) mod witness;

pub(super) use observation::{
    AuthenticatedApprovalObservation, SelectionTrustFlags, SelectionTrustOptions,
};

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fgit_crypto::{DigestHasher, Sha256Hasher, VerifyingKey, verify_dsse_ed25519};
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};

use super::super::hex;
use super::archive::{
    Identity,
    stream::{Seal, StreamHeader},
};
use super::profile::Deadline;

#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

const PAYLOAD_TYPE: &str = "application/vnd.frankengit.repository-backup-approval.v1+json";
const STATEMENT_TYPE: &str = "frankengit-repository-backup-approval-v1";
const SCOPE: &str = "authority_and_selected_git_objects";
const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
const MAX_PAYLOAD_BYTES: usize = 4096;
const MAX_KEY_BYTES: usize = 8192;
const MAX_SIGNED_ARCHIVE_BYTES: u64 = 1 << 40;
const MAX_TIME_MILLIS: i64 = 253_402_300_799_999;
// Canonical RFC 8410 Ed25519 SubjectPublicKeyInfo: absent algorithm parameters,
// followed by a 32-byte key in a BIT STRING with zero unused bits.
const ED25519_SPKI_PREFIX: &[u8; 12] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

/// Signed mode is explicit: every trust-policy input is required together.
#[derive(Debug, Default)]
pub(super) struct ApprovalFlags {
    approval: Option<PathBuf>,
    trust_key: Option<PathBuf>,
    tenant: Option<TenantId>,
    repository: Option<RepositoryId>,
    incarnation: Option<RepositoryIncarnationId>,
    format: Option<GitHashAlgorithm>,
    minimum_generation: Option<u64>,
}

impl ApprovalFlags {
    pub(super) fn accepts(flag: &str) -> bool {
        matches!(
            flag,
            "--approval"
                | "--trust-key"
                | "--tenant-id"
                | "--repository-id"
                | "--incarnation-id"
                | "--object-format"
                | "--minimum-head-generation"
        )
    }

    pub(super) fn set(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--approval" => set_once(&mut self.approval, control_path(value)?, flag),
            "--trust-key" => set_once(&mut self.trust_key, control_path(value)?, flag),
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
            "--minimum-head-generation" => set_once(
                &mut self.minimum_generation,
                decimal(value, u64::MAX)?,
                flag,
            ),
            _ => Err("unknown repository backup approval option".into()),
        }
    }

    pub(super) fn finish(self) -> Result<Option<ApprovalOptions>, String> {
        if self.approval.is_none()
            && self.trust_key.is_none()
            && self.tenant.is_none()
            && self.repository.is_none()
            && self.incarnation.is_none()
            && self.format.is_none()
            && self.minimum_generation.is_none()
        {
            return Ok(None);
        }
        let missing = || {
            "signed backup requires --approval, --trust-key, --tenant-id, --repository-id, --incarnation-id, --object-format and --minimum-head-generation".to_owned()
        };
        Ok(Some(ApprovalOptions {
            approval: self.approval.ok_or_else(missing)?,
            trust_key: self.trust_key.ok_or_else(missing)?,
            policy: Policy {
                identity: Identity {
                    tenant: self.tenant.ok_or_else(missing)?,
                    repository: self.repository.ok_or_else(missing)?,
                    incarnation: self.incarnation.ok_or_else(missing)?,
                    format: self.format.ok_or_else(missing)?,
                },
                minimum_generation: self.minimum_generation.ok_or_else(missing)?,
            },
            #[cfg(test)]
            clock: None,
        }))
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate backup approval option: {flag}"));
    }
    *slot = Some(value);
    Ok(())
}

fn control_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.len() > 8192 || value.contains('\0') {
        return Err("invalid backup approval control-file path".into());
    }
    Ok(value.into())
}

#[derive(Clone, Copy, Debug)]
struct Policy {
    identity: Identity,
    minimum_generation: u64,
}

#[derive(Debug)]
pub(super) struct ApprovalOptions {
    approval: PathBuf,
    trust_key: PathBuf,
    policy: Policy,
    #[cfg(test)]
    clock: Option<Arc<AtomicI64>>,
}

impl ApprovalOptions {
    /// Snapshot both bounded control files once. The result owns their verified
    /// meaning and exact resume binding; later checks never reopen either path.
    pub(super) fn authenticate(
        &self,
        expected: [u8; 32],
        maximum_archive_bytes: u64,
        deadline: Deadline,
    ) -> Result<VerifiedApproval, String> {
        let envelope = read_control(&self.approval, MAX_ENVELOPE_BYTES, deadline)?;
        let key = read_control(&self.trust_key, MAX_KEY_BYTES, deadline)?;
        self.authenticate_bytes(&envelope, &key, expected, maximum_archive_bytes, deadline)
    }

    fn authenticate_bytes(
        &self,
        encoded: &[u8],
        key_pem: &[u8],
        expected: [u8; 32],
        maximum_archive_bytes: u64,
        deadline: Deadline,
    ) -> Result<VerifiedApproval, String> {
        deadline.check()?;
        validate_archive_budget(maximum_archive_bytes)?;
        let (key, der) = public_key(key_pem)?;
        let trusted_key_id = format!("sha256:{}", hex(&sha256(&der)));
        let (statement, _) = authenticated_statement(
            encoded,
            &key,
            &trusted_key_id,
            self.policy.identity,
            maximum_archive_bytes,
            deadline,
        )?;
        let verified = VerifiedApproval {
            statement,
            policy: self.policy,
            trusted_key_id,
            binding: binding(encoded, &der, self.policy),
            deadline,
            #[cfg(test)]
            clock: self.clock.clone(),
        };
        verified.check_selected(expected, maximum_archive_bytes)?;
        Ok(verified)
    }

    /// A deterministic wall clock for native expiry-boundary tests only.
    /// Signature verification and the original monotonic deadline are unchanged.
    #[cfg(test)]
    pub(super) fn set_test_clock(&mut self, clock: Arc<AtomicI64>) {
        self.clock = Some(clock);
    }
}

fn validate_archive_budget(maximum_archive_bytes: u64) -> Result<(), String> {
    if maximum_archive_bytes == 0 || maximum_archive_bytes > MAX_SIGNED_ARCHIVE_BYTES {
        return Err("invalid backup approval archive-byte budget".into());
    }
    Ok(())
}

/// Authenticate the original payload before applying its canonical schema and
/// independent namespace. The caller selects a bounded signed-size profile;
/// this helper deliberately makes no lifetime, generation-floor or digest choice.
fn authenticated_statement(
    encoded: &[u8],
    key: &VerifyingKey,
    trusted_key_id: &str,
    identity: Identity,
    maximum_archive_bytes: u64,
    deadline: Deadline,
) -> Result<(Statement, Vec<u8>), String> {
    deadline.check()?;
    let envelope = parse_json(encoded, MAX_ENVELOPE_BYTES)?;
    let envelope = exact_object(&envelope, &["payloadType", "payload", "signatures"])?;
    if string_field(envelope, "payloadType")? != PAYLOAD_TYPE {
        return Err("backup approval payload type is not repository-source approval".into());
    }
    let Some(Value::Array(signatures)) = envelope.get("signatures") else {
        return Err("backup approval requires exactly one signature".into());
    };
    let [signature] = signatures.as_slice() else {
        return Err("backup approval requires exactly one signature".into());
    };
    let signature = exact_object(signature, &["keyid", "sig"])?;
    if string_field(signature, "keyid")? != trusted_key_id {
        return Err("backup approval signer does not match independently trusted key".into());
    }
    let payload = base64(string_field(envelope, "payload")?, MAX_PAYLOAD_BYTES)?;
    let signature: [u8; 64] = base64(string_field(signature, "sig")?, 64)?
        .try_into()
        .map_err(|_| "backup approval signature must have 64 bytes")?;
    verify_dsse_ed25519(key, PAYLOAD_TYPE, &payload, &signature)
        .map_err(|error| format!("backup approval signature refused: {error}"))?;
    deadline.check()?;
    let statement = Statement::parse(&payload, maximum_archive_bytes)?;
    if statement.identity != identity {
        return Err("backup approval identity does not match independent policy".into());
    }
    Ok((statement, payload))
}

/// The only signed-mode value allowed to reach restore ownership/publication.
/// It carries no file paths, private keys, canonical authorization or epoch claim.
#[derive(Debug)]
pub(super) struct VerifiedApproval {
    statement: Statement,
    policy: Policy,
    trusted_key_id: String,
    binding: [u8; 32],
    deadline: Deadline,
    #[cfg(test)]
    clock: Option<Arc<AtomicI64>>,
}

impl VerifiedApproval {
    /// Admission to the existing native recovery boundary, after cryptographic
    /// inspection. Observations cannot bypass any selected-operation constraint.
    fn check_selected(&self, expected: [u8; 32], maximum_archive_bytes: u64) -> Result<(), String> {
        self.deadline.check()?;
        validate_archive_budget(maximum_archive_bytes)?;
        if self.statement.archive_bytes > maximum_archive_bytes {
            return Err("backup approval decimal exceeds its permitted range".into());
        }
        if self.statement.generation < self.policy.minimum_generation {
            return Err(
                "backup approval is below the independently retained generation floor".into(),
            );
        }
        if self.statement.digest != expected {
            return Err(
                "backup approval digest disagrees with independently supplied --expected-sha256"
                    .into(),
            );
        }
        self.check_current()
    }

    pub(super) fn artifact_seal(&self) -> Seal {
        Seal {
            digest: self.statement.digest,
            bytes: self.statement.archive_bytes,
        }
    }

    pub(super) fn check_current(&self) -> Result<(), String> {
        self.deadline.check()?;
        #[cfg(test)]
        let now = if let Some(clock) = &self.clock {
            clock.load(Ordering::SeqCst)
        } else {
            now_millis()?
        };
        #[cfg(not(test))]
        let now = now_millis()?;
        if !(0..=MAX_TIME_MILLIS).contains(&now) {
            return Err("backup approval clock is outside the supported UTC range".into());
        }
        if self.statement.issued_millis > now + 300_000 {
            return Err("backup approval was issued too far in the future".into());
        }
        if self
            .statement
            .expires_millis
            .is_some_and(|expires| expires <= now)
        {
            return Err("backup approval has expired".into());
        }
        Ok(())
    }

    /// This is called after the real reader verifies the pinned bytes, before
    /// destination reservation. It does not replace the later canonical graph.
    pub(super) fn match_archive(&self, header: &StreamHeader, seal: Seal) -> Result<(), String> {
        self.check_current()?;
        if header.identity != self.statement.identity
            || header.authority.head.as_ref().map(|head| head.generation)
                != Some(self.statement.generation)
            || seal != self.artifact_seal()
        {
            return Err("signed backup identity, generation or artifact does not match the verified archive".into());
        }
        Ok(())
    }

    pub(super) const fn binding_digest(&self) -> [u8; 32] {
        self.binding
    }

    /// A JSON value for the caller's `approval` field. Do not check time here:
    /// completed native publication remains completed if output is delayed.
    pub(super) fn receipt_json(&self) -> String {
        format!(
            concat!(
                "{{\"type\":\"repository_backup_approval_authentication\",\"signature_verified\":true,",
                "\"trusted_key_id\":\"{}\",\"binding_sha256\":\"{}\",",
                "\"minimum_head_generation\":\"{}\",\"statement\":{},",
                "\"newest_checkpoint_verified\":false,\"complete_capsule_verified\":false}}"
            ),
            self.trusted_key_id,
            hex(&self.binding),
            self.policy.minimum_generation,
            self.statement.canonical()
        )
    }
}

fn now_millis() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "backup approval clock precedes the Unix epoch")?;
    i64::try_from(duration.as_millis()).map_err(|_| "backup approval clock overflows".into())
}

#[derive(Debug)]
struct Statement {
    identity: Identity,
    generation: u64,
    issued_at: String,
    expires_at: Option<String>,
    issued_millis: i64,
    expires_millis: Option<i64>,
    archive_bytes: u64,
    digest: [u8; 32],
}

impl Statement {
    fn parse(payload: &[u8], maximum_archive_bytes: u64) -> Result<Self, String> {
        let parsed = parse_json(payload, MAX_PAYLOAD_BYTES)?;
        let parsed = exact_object(
            &parsed,
            &[
                "type",
                "tenant_id",
                "repository_id",
                "incarnation_id",
                "object_format",
                "head_generation",
                "issued_at",
                "expires_at",
                "artifact",
                "scope",
            ],
        )?;
        if string_field(parsed, "type")? != STATEMENT_TYPE
            || string_field(parsed, "scope")? != SCOPE
        {
            return Err("backup approval statement type or scope is unsupported".into());
        }
        let identity = Identity {
            tenant: TenantId::from_bytes(unhex(string_field(parsed, "tenant_id")?)?),
            repository: RepositoryId::from_bytes(unhex(string_field(parsed, "repository_id")?)?),
            incarnation: RepositoryIncarnationId::from_bytes(unhex(string_field(
                parsed,
                "incarnation_id",
            )?)?),
            format: object_format(string_field(parsed, "object_format")?)?,
        };
        let generation = decimal(string_field(parsed, "head_generation")?, u64::MAX)?;
        let issued_at = string_field(parsed, "issued_at")?.to_owned();
        let issued_millis = instant(&issued_at)?;
        let (expires_at, expires_millis) = match parsed.get("expires_at") {
            Some(Value::Null) => (None, None),
            Some(Value::String(value)) => (Some(value.clone()), Some(instant(value)?)),
            _ => return Err("backup approval expiry must be a UTC time or null".into()),
        };
        if expires_millis.is_some_and(|expires| expires <= issued_millis) {
            return Err("backup approval expiry must be later than issuance".into());
        }
        let artifact = parsed
            .get("artifact")
            .ok_or("backup approval has no artifact")?;
        let artifact = exact_object(artifact, &["bytes", "sha256"])?;
        let statement = Self {
            identity,
            generation,
            issued_at,
            expires_at,
            issued_millis,
            expires_millis,
            archive_bytes: decimal(string_field(artifact, "bytes")?, maximum_archive_bytes)?,
            digest: unhex(string_field(artifact, "sha256")?)?,
        };
        // Signatures authenticate the original decoded bytes. Canonicality is
        // an additional profile rule; no rewritten payload is ever verified.
        if statement.canonical().as_bytes() != payload {
            return Err("backup approval statement is not the canonical original JSON".into());
        }
        Ok(statement)
    }

    fn canonical(&self) -> String {
        let expires = self
            .expires_at
            .as_ref()
            .map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""));
        format!(
            concat!(
                "{{\"type\":\"frankengit-repository-backup-approval-v1\",",
                "\"tenant_id\":\"{}\",\"repository_id\":\"{}\",\"incarnation_id\":\"{}\",",
                "\"object_format\":\"{}\",\"head_generation\":\"{}\",\"issued_at\":\"{}\",",
                "\"expires_at\":{},\"artifact\":{{\"bytes\":\"{}\",\"sha256\":\"{}\"}},",
                "\"scope\":\"authority_and_selected_git_objects\"}}"
            ),
            self.identity.tenant,
            self.identity.repository,
            self.identity.incarnation,
            self.identity.format.as_str(),
            self.generation,
            self.issued_at,
            expires,
            self.archive_bytes,
            hex(&self.digest)
        )
    }
}

fn binding(encoded: &[u8], der: &[u8; 44], policy: Policy) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    // Local restore ownership binding, not a canonical repository identity.
    // The one variable-length field has an explicit length; every other field
    // has a fixed width. Whitespace changes to the envelope change the binding.
    hash.update(b"repository_backup_restore_approval_v1\0");
    hash.update(&(encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    hash.update(der);
    hash.update(policy.identity.tenant.as_bytes());
    hash.update(policy.identity.repository.as_bytes());
    hash.update(policy.identity.incarnation.as_bytes());
    hash.update(&[match policy.identity.format {
        GitHashAlgorithm::Sha1 => 1,
        GitHashAlgorithm::Sha256 => 2,
    }]);
    hash.update(&policy.minimum_generation.to_be_bytes());
    hash.finish()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}

fn read_control(path: &Path, maximum: usize, deadline: Deadline) -> Result<Vec<u8>, String> {
    deadline.check()?;
    let before =
        fs::symlink_metadata(path).map_err(|e| format!("backup approval control read: {e}"))?;
    if !before.is_file() || before.len() == 0 || before.len() > maximum as u64 {
        return Err("backup approval control input must be a bounded nonempty regular file".into());
    }
    let mut file = File::open(path).map_err(|e| format!("backup approval control open: {e}"))?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !same_control(&before, &opened) {
        return Err("backup approval control input changed while opening".into());
    }
    let mut bytes = Vec::with_capacity(maximum.min(opened.len() as usize));
    file.by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("backup approval control read: {e}"))?;
    deadline.check()?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if bytes.len() != opened.len() as usize
        || bytes.len() > maximum
        || !same_control(&opened, &after)
        || !same_control(&after, &named)
    {
        return Err("backup approval control input changed while reading".into());
    }
    Ok(bytes)
}

fn same_control(left: &Metadata, right: &Metadata) -> bool {
    if !left.is_file()
        || !right.is_file()
        || left.len() != right.len()
        || left.modified().ok() != right.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if left.dev() != right.dev()
            || left.ino() != right.ino()
            || left.ctime() != right.ctime()
            || left.ctime_nsec() != right.ctime_nsec()
        {
            return false;
        }
    }
    true
}

fn public_key(input: &[u8]) -> Result<(VerifyingKey, [u8; 44]), String> {
    if input.is_empty() || input.len() > MAX_KEY_BYTES || !input.is_ascii() {
        return Err("backup approval requires a bounded canonical Ed25519 public PEM".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "invalid backup public PEM")?;
    let text = text
        .strip_prefix("-----BEGIN PUBLIC KEY-----")
        .ok_or("expected public SPKI PEM")?;
    let text = text
        .strip_prefix("\r\n")
        .or_else(|| text.strip_prefix('\n'))
        .ok_or("invalid public PEM header")?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let text = text
        .strip_suffix("-----END PUBLIC KEY-----")
        .ok_or("invalid public PEM footer")?;
    let body: String = text
        .chars()
        .filter(|ch| !matches!(ch, '\r' | '\n'))
        .collect();
    let der: [u8; 44] = base64(&body, MAX_KEY_BYTES)?
        .try_into()
        .map_err(|_| "backup approval requires canonical Ed25519 SPKI DER")?;
    if &der[..12] != ED25519_SPKI_PREFIX {
        return Err("backup approval requires canonical Ed25519 SPKI DER".into());
    }
    let mut key = [0; 32];
    key.copy_from_slice(&der[12..]);
    Ok((VerifyingKey::from_bytes(key), der))
}

fn object_format(value: &str) -> Result<GitHashAlgorithm, String> {
    match value {
        "sha1" => Ok(GitHashAlgorithm::Sha1),
        "sha256" => Ok(GitHashAlgorithm::Sha256),
        _ => Err("backup approval object format must be sha1 or sha256".into()),
    }
}

fn decimal(value: &str, maximum: u64) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 20
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("backup approval requires canonical positive decimal strings".into());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= maximum)
        .ok_or_else(|| "backup approval decimal exceeds its permitted range".into())
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("backup approval requires exact lowercase hexadecimal identity/digest".into());
    }
    let nibble = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    let mut out = [0; N];
    for (slot, pair) in out
        .iter_mut()
        .zip(text.as_bytes().as_chunks::<2>().0.iter())
    {
        *slot = 16 * nibble(pair[0]) + nibble(pair[1]);
    }
    Ok(out)
}

/// The JS issuer requires padded canonical RFC 4648 base64, including zero pad bits.
fn base64(text: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let invalid = || "backup approval contains noncanonical base64".to_owned();
    if text.is_empty() || !text.len().is_multiple_of(4) || text.len() > maximum.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let digit = |byte: u8| -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let padding = if text.ends_with("==") {
        2
    } else {
        usize::from(text.ends_with('='))
    };
    let decoded_bytes = text.len() / 4 * 3 - padding;
    if decoded_bytes > maximum {
        return Err(invalid());
    }
    let mut out = Vec::with_capacity(decoded_bytes);
    for (index, quad) in text.as_bytes().as_chunks::<4>().0.iter().enumerate() {
        let last = (index + 1) * 4 == text.len();
        let a = digit(quad[0]).ok_or_else(invalid)?;
        let b = digit(quad[1]).ok_or_else(invalid)?;
        let c = if quad[2] == b'=' && last {
            0
        } else {
            digit(quad[2]).ok_or_else(invalid)?
        };
        let d = if quad[3] == b'=' && last {
            0
        } else {
            digit(quad[3]).ok_or_else(invalid)?
        };
        if quad[2] == b'=' && (quad[3] != b'=' || b & 15 != 0)
            || quad[3] == b'=' && quad[2] != b'=' && c & 3 != 0
        {
            return Err(invalid());
        }
        out.push((a << 2) | (b >> 4));
        if quad[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if quad[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    if out.len() > maximum {
        return Err(invalid());
    }
    Ok(out)
}

/// Exact UTC second spelling and real proleptic Gregorian dates, years 0000..9999.
fn instant(text: &str) -> Result<i64, String> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit())
    {
        return Err("backup approval time must be YYYY-MM-DDTHH:MM:SSZ".into());
    }
    let number = |range: std::ops::Range<usize>| {
        bytes[range]
            .iter()
            .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let (hour, minute, second) = (number(11..13), number(14..16), number(17..19));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err("backup approval time is not a real UTC calendar instant".into());
    }
    // March-based Gregorian eras make leap-day handling independent of locale
    // and host time zones. Euclidean division also covers January of year zero.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let unix_days = era * 146_097 + day_of_era - 719_468;
    Ok((unix_days * 86_400 + hour * 3600 + minute * 60 + second) * 1000)
}

// The existing approval wire needs strings, null, arrays and objects only.
// Unknown values, duplicate decoded keys, invalid UTF-8/escapes, trailing bytes,
// more than 64 values, or nesting beyond four containers refuse. This is an
// application control parser, never the source archive or authority decoder.
#[derive(Debug)]
enum Value {
    Null,
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

fn parse_json(bytes: &[u8], maximum: usize) -> Result<Value, String> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("backup approval JSON byte limit".into());
    }
    let source = std::str::from_utf8(bytes).map_err(|_| "backup approval JSON is not UTF-8")?;
    let mut input = JsonReader {
        rest: source,
        remaining: 64,
    };
    let value = input.value(0)?;
    input.space();
    if !input.rest.is_empty() {
        return Err("trailing backup approval JSON".into());
    }
    Ok(value)
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a BTreeMap<String, Value>, String> {
    let Value::Object(value) = value else {
        return Err("backup approval field must be an object".into());
    };
    if value.len() != fields.len() || fields.iter().any(|field| !value.contains_key(*field)) {
        return Err("backup approval object has missing or unexpected fields".into());
    }
    Ok(value)
}

fn string_field<'a>(object: &'a BTreeMap<String, Value>, field: &str) -> Result<&'a str, String> {
    match object.get(field) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(format!("backup approval {field} must be a string")),
    }
}

struct JsonReader<'a> {
    rest: &'a str,
    remaining: usize,
}

impl JsonReader<'_> {
    fn space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\r', '\n', '\t']);
    }
    fn take(&mut self, token: &str) -> bool {
        self.space();
        if let Some(rest) = self.rest.strip_prefix(token) {
            self.rest = rest;
            true
        } else {
            false
        }
    }
    fn character(&mut self) -> Result<char, String> {
        let ch = self
            .rest
            .chars()
            .next()
            .ok_or("truncated backup approval JSON")?;
        self.rest = &self.rest[ch.len_utf8()..];
        Ok(ch)
    }
    fn hex_quad(&mut self) -> Result<u32, String> {
        let mut value = 0;
        for _ in 0..4 {
            value = value * 16
                + self
                    .character()?
                    .to_digit(16)
                    .ok_or("invalid backup JSON escape")?;
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<String, String> {
        if !self.take("\"") {
            return Err("expected backup approval JSON string".into());
        }
        let mut text = String::new();
        loop {
            match self.character()? {
                '"' => return Ok(text),
                '\\' => {
                    let value = match self.character()? {
                        '"' => '"',
                        '\\' => '\\',
                        '/' => '/',
                        'b' => '\u{0008}',
                        'f' => '\u{000c}',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'u' => {
                            let high = self.hex_quad()?;
                            let scalar = if (0xd800..=0xdbff).contains(&high) {
                                self.rest = self
                                    .rest
                                    .strip_prefix("\\u")
                                    .ok_or("unpaired backup JSON surrogate")?;
                                let low = self.hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err("unpaired backup JSON surrogate".into());
                                }
                                0x1_0000 + ((high - 0xd800) << 10) + low - 0xdc00
                            } else {
                                high
                            };
                            char::from_u32(scalar).ok_or("invalid backup JSON scalar")?
                        }
                        _ => return Err("invalid backup approval JSON escape".into()),
                    };
                    text.push(value);
                }
                ch if ch <= '\u{001f}' => return Err("control byte in backup approval JSON".into()),
                ch => text.push(ch),
            }
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > 4 || self.remaining == 0 {
            return Err("backup approval JSON complexity limit".into());
        }
        self.remaining -= 1;
        self.space();
        if self.rest.starts_with('"') {
            return self.string().map(Value::String);
        }
        if self.take("null") {
            return Ok(Value::Null);
        }
        if self.take("[") {
            let mut values = Vec::new();
            if self.take("]") {
                return Ok(Value::Array(values));
            }
            loop {
                values.push(self.value(depth + 1)?);
                if self.take("]") {
                    break;
                }
                if !self.take(",") {
                    return Err("invalid backup approval JSON array".into());
                }
            }
            return Ok(Value::Array(values));
        }
        if self.take("{") {
            let mut values = BTreeMap::new();
            if self.take("}") {
                return Ok(Value::Object(values));
            }
            loop {
                let key = self.string()?;
                if !self.take(":") {
                    return Err("invalid backup approval JSON object".into());
                }
                let value = self.value(depth + 1)?;
                if values.insert(key, value).is_some() {
                    return Err("duplicate backup approval JSON field".into());
                }
                if self.take("}") {
                    break;
                }
                if !self.take(",") {
                    return Err("invalid backup approval JSON object".into());
                }
            }
            return Ok(Value::Object(values));
        }
        Err("unsupported backup approval JSON value".into())
    }
}

#[cfg(test)]
mod tests;
