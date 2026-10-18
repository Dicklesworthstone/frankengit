//! Bounded lossless storage spelling. Artifact identity remains owned by artifact.rs.
use super::*;
use crate::{ArtifactPayloadKind, MediaType, RetentionProfile};

pub(super) fn scope_bytes(scope: &ArtifactScope, out: &mut Vec<u8>) {
    out.extend_from_slice(scope.tenant.as_bytes());
    out.extend_from_slice(scope.repository.as_bytes());
    out.extend_from_slice(scope.incarnation.as_bytes());
    field(out, scope.trust.as_bytes());
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn hash(out: &mut Vec<u8>, value: &Digest) -> Result<(), ArtifactStorageError> {
    valid_digest(value)?;
    out.extend_from_slice(value.bytes().as_bytes());
    Ok(())
}
pub(super) fn encode(
    scope: &ArtifactScope,
    identity: &ArtifactIdentity,
) -> Result<Vec<u8>, ArtifactStorageError> {
    if let RetentionProfile::LegalHold { reason, .. } = identity.retention_profile() {
        if reason.len() > 1024 {
            return Err(ArtifactStorageError::InvalidInput(
                "retention description too long",
            ));
        }
    }
    let mut out = Vec::new();
    scope_bytes(scope, &mut out);
    hash(&mut out, identity.payload_digest())?;
    out.extend_from_slice(&identity.payload_len().to_be_bytes());
    out.push(identity.payload_kind().wire_code());
    field(&mut out, identity.media_type().as_str().as_bytes());
    for value in [
        identity.build_capsule_id(),
        identity.check_receipt_id(),
        identity.source_rcr(),
    ] {
        out.push(u8::from(value.is_some()));
        if let Some(value) = value {
            hash(&mut out, value)?;
        }
    }
    field(&mut out, &identity.retention_profile().encode_canonical());
    hash(&mut out, identity.artifact_id())?;
    if out.len() > HEADER_BYTES {
        return Err(ArtifactStorageError::InvalidEncoding);
    }
    Ok(out)
}
pub(super) fn decode(
    bytes: &[u8],
    scope: &ArtifactScope,
    expected: &Digest,
) -> Result<ArtifactIdentity, ArtifactStorageError> {
    if bytes.len() > HEADER_BYTES {
        return Err(ArtifactStorageError::InvalidEncoding);
    }
    valid_digest(expected)?;
    let mut input = Input(bytes);
    let found = ArtifactScope::new(
        TenantId::from_bytes(input.array()?),
        RepositoryId::from_bytes(input.array()?),
        RepositoryIncarnationId::from_bytes(input.array()?),
        input.text(256)?,
    )?;
    if &found != scope {
        return Err(ArtifactStorageError::ScopeMismatch);
    }
    let payload = input.hash()?;
    let len = u64::from_be_bytes(input.array()?);
    let kind = ArtifactPayloadKind::from_wire_code(input.byte()?)?;
    let media = MediaType::parse(input.text(128)?)?;
    let capsule = input.optional()?;
    let receipt = input.optional()?;
    let rcr = input.optional()?;
    let retention = RetentionProfile::decode_canonical(input.field(1040)?)?;
    let stored_id = input.hash()?;
    if !input.0.is_empty() {
        return Err(ArtifactStorageError::InvalidEncoding);
    }
    let identity =
        ArtifactIdentity::new(payload, len, media, kind, capsule, receipt, rcr, retention);
    if identity.artifact_id() != expected || &stored_id != expected {
        return Err(ArtifactStorageError::IdentityMismatch);
    }
    if encode(scope, &identity)? != bytes {
        return Err(ArtifactStorageError::InvalidEncoding);
    }
    Ok(identity)
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ArtifactStorageError> {
        let value = self
            .0
            .get(..length)
            .ok_or(ArtifactStorageError::InvalidEncoding)?;
        self.0 = &self.0[length..];
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ArtifactStorageError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ArtifactStorageError::InvalidEncoding)
    }
    fn byte(&mut self) -> Result<u8, ArtifactStorageError> {
        Ok(self.array::<1>()?[0])
    }
    fn field(&mut self, maximum: usize) -> Result<&'a [u8], ArtifactStorageError> {
        let length = u16::from_be_bytes(self.array()?) as usize;
        if length > maximum {
            return Err(ArtifactStorageError::InvalidEncoding);
        }
        self.take(length)
    }
    fn text(&mut self, maximum: usize) -> Result<&'a str, ArtifactStorageError> {
        std::str::from_utf8(self.field(maximum)?).map_err(|_| ArtifactStorageError::InvalidEncoding)
    }
    fn hash(&mut self) -> Result<Digest, ArtifactStorageError> {
        let bytes = self.take(32)?;
        Ok(Digest::new(
            DigestAlgorithmId::try_new(2).expect("SHA-256"),
            DigestBytes::try_new(bytes).map_err(|_| ArtifactStorageError::InvalidIdentity)?,
        ))
    }
    fn optional(&mut self) -> Result<Option<Digest>, ArtifactStorageError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.hash().map(Some),
            _ => Err(ArtifactStorageError::InvalidEncoding),
        }
    }
}
