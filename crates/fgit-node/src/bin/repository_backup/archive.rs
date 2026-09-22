//! Versioned local recovery transport, NOT a canonical body or a signed capsule.
//! No host paths, compression, offsets, SQL statements or source CAS privileges
//! are interpreted here. The enclosing trusted checksum authenticates these bytes.
use fgit_authority_fsqlite::{ExportBundle, import_bundle};
use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, RepositoryId,
    RepositoryIncarnationId, TenantId};

pub(super) const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_OBJECTS: usize = 100_000;
pub(super) const MAX_OBJECT_BYTES: usize = 32 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"FGSRC001";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Identity {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub format: GitHashAlgorithm,
}
#[derive(Debug)]
pub(super) struct Record<'a> {
    pub oid: GitOid,
    pub kind: GitObjectKind,
    pub payload: &'a [u8],
}
#[derive(Debug)]
pub(super) struct Archive<'a> {
    pub identity: Identity,
    pub authority: ExportBundle,
    pub records: Vec<Record<'a>>,
}
#[derive(Debug)]
pub(super) struct Encoder {
    bytes: Vec<u8>,
    identity: Identity,
    remaining: usize,
    previous: Option<GitOid>,
    failed: bool,
}
impl Encoder {
    pub fn new(identity: Identity, authority: &[u8], objects: usize) -> Result<Self, String> {
        if objects > MAX_OBJECTS { return Err("repository backup object-count limit".into()); }
        if authority.is_empty() { return Err("missing authority transport".into()); }
        let mut out = Self { bytes: Vec::new(), identity, remaining: objects, previous: None, failed: false };
        out.push(MAGIC)?;
        out.push(identity.tenant.as_bytes())?;
        out.push(identity.repository.as_bytes())?;
        out.push(identity.incarnation.as_bytes())?;
        out.push(&[match identity.format { GitHashAlgorithm::Sha1 => 1, GitHashAlgorithm::Sha256 => 2 }])?;
        out.push(&(authority.len() as u64).to_be_bytes())?;
        out.push(authority)?;
        out.push(&(objects as u64).to_be_bytes())?;
        Ok(out)
    }
    /// Source fabric has already verified the original independent commitment.
    /// Preserve it in the transport rather than silently inventing a replacement.
    pub fn object(&mut self, oid: GitOid, kind: GitObjectKind, payload: &[u8],
        commitment: &[u8; 32],
    ) -> Result<(), String> {
        if self.failed { return Err("repository backup encoder previously failed".into()); }
        let result = self.object_inner(oid, kind, payload, commitment);
        self.failed = result.is_err();
        result
    }
    fn object_inner(&mut self, oid: GitOid, kind: GitObjectKind, payload: &[u8],
        commitment: &[u8; 32],
    ) -> Result<(), String> {
        if self.remaining == 0 || oid.algorithm() != self.identity.format || oid.is_zero()
            || self.previous.is_some_and(|last| last >= oid)
        { return Err("repository backup object order/domain mismatch".into()); }
        if payload.len() > MAX_OBJECT_BYTES { return Err("repository backup object-byte limit".into()); }
        self.push(oid.as_bytes())?;
        self.push(&[kind_byte(kind)])?;
        self.push(&(payload.len() as u64).to_be_bytes())?;
        self.push(commitment)?;
        self.push(payload)?;
        self.remaining -= 1;
        self.previous = Some(oid);
        Ok(())
    }
    pub fn finish(self) -> Result<Vec<u8>, String> {
        if self.failed || self.remaining != 0 { return Err("incomplete repository backup object set".into()); }
        Ok(self.bytes)
    }
    fn push(&mut self, part: &[u8]) -> Result<(), String> {
        self.bytes.len().checked_add(part.len()).filter(|n| *n <= MAX_ARCHIVE_BYTES)
            .ok_or("repository backup exceeds 64 MiB transport limit")?;
        self.bytes.try_reserve(part.len()).map_err(|_| "repository backup allocation refused")?;
        self.bytes.extend_from_slice(part);
        Ok(())
    }
}
fn kind_byte(kind: GitObjectKind) -> u8 {
    match kind { GitObjectKind::Commit => 1, GitObjectKind::Tree => 2,
        GitObjectKind::Blob => 3, GitObjectKind::Tag => 4 }
}
fn kind(byte: u8) -> Result<GitObjectKind, String> {
    match byte { 1 => Ok(GitObjectKind::Commit), 2 => Ok(GitObjectKind::Tree),
        3 => Ok(GitObjectKind::Blob), 4 => Ok(GitObjectKind::Tag),
        _ => Err("repository backup contains a non-Git object type".into()) }
}
struct Reader<'a> { bytes: &'a [u8] }
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let part = self.bytes.get(..count).ok_or("truncated repository backup")?;
        self.bytes = &self.bytes[count..];
        Ok(part)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?.try_into().map_err(|_| "truncated repository backup field".into())
    }
    fn length(&mut self, limit: usize) -> Result<usize, String> {
        usize::try_from(u64::from_be_bytes(self.array()?)).ok().filter(|n| *n <= limit)
            .ok_or_else(|| "repository backup declared length/count exceeds its limit".into())
    }
}
/// Verify framing, native identity and original payload commitments before a
/// caller creates destination state. Graph/selection checks additionally need
/// the canonical authority materializer; successful decoding grants no authority.
pub(super) fn decode(bytes: &[u8], mut live: impl FnMut() -> Result<(), String>)
    -> Result<Archive<'_>, String>
{
    live()?;
    if bytes.len() > MAX_ARCHIVE_BYTES { return Err("repository backup input exceeds 64 MiB".into()); }
    let mut input = Reader { bytes };
    if input.take(MAGIC.len())? != MAGIC { return Err("unsupported repository backup transport".into()); }
    let tenant = TenantId::from_bytes(input.array()?);
    let repository = RepositoryId::from_bytes(input.array()?);
    let incarnation = RepositoryIncarnationId::from_bytes(input.array()?);
    let format = match input.array::<1>()?[0] {
        1 => GitHashAlgorithm::Sha1, 2 => GitHashAlgorithm::Sha256,
        _ => return Err("unsupported repository backup object format".into()),
    };
    let size = input.length(MAX_ARCHIVE_BYTES)?;
    let authority = import_bundle(input.take(size)?).map_err(|error| format!("invalid repository authority transport: {error}"))?;
    live()?;
    if authority.head.is_none() { return Err("repository backup has no authority head".into()); }
    let count = input.length(MAX_OBJECTS)?;
    // Refuse impossible counts BEFORE reserving the record table.
    let minimum = format.digest_len() + 1 + 8 + 32;
    if count > input.bytes.len() / minimum { return Err("truncated repository backup object inventory".into()); }
    let mut records = Vec::new();
    records.try_reserve_exact(count).map_err(|_| "repository backup record allocation refused")?;
    let mut previous = None;
    for _ in 0..count {
        live()?;
        let raw = input.take(format.digest_len())?;
        let oid = GitOid::from_hex(format, &super::super::hex(raw)).map_err(|_| "invalid native object ID")?;
        if oid.is_zero() || previous.is_some_and(|last| last >= oid) {
            return Err("repository backup object order/domain mismatch".into());
        }
        let kind = kind(input.array::<1>()?[0])?;
        let length = input.length(MAX_OBJECT_BYTES)?;
        let commitment = input.array::<32>()?;
        let payload = input.take(length)?;
        if git_object_id(format, kind, payload) != oid {
            return Err(format!("repository backup native object identity mismatch: {oid}"));
        }
        let computed = git_payload_commitment(kind, payload, CANONICAL_CODEC_VERSION);
        if computed.digest().as_bytes() != commitment.as_slice() {
            return Err(format!("repository backup payload commitment mismatch: {oid}"));
        }
        live()?;
        records.push(Record { oid, kind, payload });
        previous = Some(oid);
    }
    if !input.bytes.is_empty() { return Err("trailing repository backup bytes".into()); }
    live()?;
    Ok(Archive { identity: Identity { tenant, repository, incarnation, format }, authority, records })
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
