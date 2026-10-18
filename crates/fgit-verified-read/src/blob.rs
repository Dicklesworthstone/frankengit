//! Complete ref-anchored blob proofs. The independently selected authority
//! head authenticates the ref; native Git identities authenticate every
//! commit/tree edge and the complete file bytes. A response never selects its
//! own trusted head, and a symlink is returned as data rather than followed.

use crate::{
    PinnedAuthorityHead, VerifiedReadAnswer, VerifiedReadConfiguration, VerifiedReadEnvelope,
    VerifiedReadRefusal, decode_verified_read_envelope, encode_verified_read_envelope,
    verify_envelope,
};
use fgit_authority::authority_head_identity;
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder, RepositoryAuthorityHeadBody,
    decode_body, encode_body,
};
use fgit_crypto::{GitObjectHasher, GitObjectKind, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body, parse_tree,
};
use fgit_types::{
    DomainTag, GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId, SchemaFamily,
};

/// Maximum complete canonical wire frame, including its authenticated ref proof.
pub const MAX_VERIFIED_BLOB_FRAME_BYTES: usize = 32 * 1024 * 1024 + 128 * 1024;
/// Maximum complete blob. Partial bytes cannot prove a native Git identity.
pub const MAX_VERIFIED_BLOB_BYTES: usize = 16 * 1024 * 1024;
/// One shared allowance for the original commit and all traversed trees.
pub const MAX_VERIFIED_BLOB_METADATA_BYTES: usize = 16 * 1024 * 1024;
/// Total parsed entries across all trees, not a fresh allowance per component.
pub const MAX_VERIFIED_BLOB_TREE_ENTRIES: usize = 100_000;
/// Maximum path depth and number of original tree bodies in the frame.
pub const MAX_VERIFIED_BLOB_COMPONENTS: usize = 64;
const MAX_REF_PROOF_BYTES: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// A typed reason that exact blob verification or its bounded framing failed.
#[derive(Debug)]
pub enum VerifiedBlobRefusal {
    /// An unsupported, empty, ambiguous, or oversized byte path.
    InvalidPath,
    /// The envelope does not contain exactly one ref membership answer.
    RefMembershipRequired,
    /// A trusted expected coordinate disagreed with the supplied answer.
    HeadMismatch,
    /// The response answers a different ref from the one requested.
    RefMismatch,
    /// The response answers a different raw path from the one requested.
    PathMismatch,
    /// The node's authenticated configuration and native objects disagree.
    ObjectFormatMismatch,
    /// A native commit, tree, or blob failed its original Git commitment.
    ObjectHashMismatch,
    /// A required native object is malformed or has an ambiguous edge.
    InvalidObject,
    /// The tree does not contain the exact requested immediate child.
    PathMissing,
    /// A directory was required while traversing an intermediate component.
    DirectoryRequired,
    /// The final entry is a directory, gitlink, or unsupported file mode.
    BlobRequired,
    /// Missing, extra, reordered or duplicated path-level evidence.
    TreeCountMismatch,
    /// A closed byte, entry, or frame bound was exceeded.
    BoundExceeded(&'static str),
    /// Caller-owned cancellation was observed before returning any bytes.
    Cancelled,
    /// Canonical framing refused the untrusted response.
    Codec(Box<CodecRefusal>),
    /// The existing exact-head Merkle verifier refused the ref proof.
    RefProof(Box<VerifiedReadRefusal>),
}

impl std::fmt::Display for VerifiedBlobRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verified blob refused: {self:?}")
    }
}
impl std::error::Error for VerifiedBlobRefusal {}

/// The final entry's verified interpretation. No host file operation is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedBlobKind {
    File,
    Executable,
    Symlink,
}
impl VerifiedBlobKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Executable => "executable",
            Self::Symlink => "symlink",
        }
    }
}

/// Original bytes and closed proof fields. Construction and decoding establish
/// shape and resource bounds only; consumers must call the independent verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobEnvelope {
    ref_proof: VerifiedReadEnvelope,
    path: Vec<u8>,
    commit: Vec<u8>,
    trees: Vec<Vec<u8>>,
    blob: Vec<u8>,
}

impl VerifiedBlobEnvelope {
    /// Retains original bodies without normalizing or regenerating Git bytes.
    pub fn from_parts(
        ref_proof: VerifiedReadEnvelope,
        path: Vec<u8>,
        commit: Vec<u8>,
        trees: Vec<Vec<u8>>,
        blob: Vec<u8>,
    ) -> Result<Self, VerifiedBlobRefusal> {
        let result = Self {
            ref_proof,
            path,
            commit,
            trees,
            blob,
        };
        result.validate_shape()?;
        Ok(result)
    }

    #[must_use]
    pub const fn head(&self) -> &RepositoryAuthorityHeadBody {
        self.ref_proof.head()
    }

    /// The constructor admits only the membership arm, making this total.
    #[must_use]
    pub fn reference(&self) -> &RefName {
        match self.ref_proof.answer() {
            VerifiedReadAnswer::RefMembership { name, .. } => name,
            _ => unreachable!("VerifiedBlobEnvelope construction requires ref membership"),
        }
    }

    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    fn validate_shape(&self) -> Result<(), VerifiedBlobRefusal> {
        let components = validate_blob_path(&self.path)?;
        if self.trees.len() != components {
            return Err(VerifiedBlobRefusal::TreeCountMismatch);
        }
        let VerifiedReadAnswer::RefMembership { proof, .. } = self.ref_proof.answer() else {
            return Err(VerifiedBlobRefusal::RefMembershipRequired);
        };
        if self.ref_proof.version() != crate::VERIFIED_READ_ENVELOPE_V1
            || proof.siblings().len() > 64
        {
            return Err(VerifiedBlobRefusal::BoundExceeded("ref proof"));
        }
        if let Some(VerifiedReadConfiguration::RepositoryV1(configuration)) =
            self.ref_proof.exact_configuration()
        {
            let mut size = 0usize;
            if configuration.hidden_ref_rules.len() > 4096 {
                return Err(VerifiedBlobRefusal::BoundExceeded("configuration rules"));
            }
            for rule in &configuration.hidden_ref_rules {
                size = size
                    .checked_add(rule.len() + 8)
                    .ok_or(VerifiedBlobRefusal::BoundExceeded("configuration rules"))?;
                if rule.len() > MAX_PATH_BYTES || size > MAX_REF_PROOF_BYTES / 2 {
                    return Err(VerifiedBlobRefusal::BoundExceeded("configuration rules"));
                }
            }
        }
        let mut metadata = self.commit.len();
        for tree in &self.trees {
            metadata = metadata
                .checked_add(tree.len())
                .ok_or(VerifiedBlobRefusal::BoundExceeded("metadata bytes"))?;
        }
        if metadata > MAX_VERIFIED_BLOB_METADATA_BYTES {
            return Err(VerifiedBlobRefusal::BoundExceeded("metadata bytes"));
        }
        if self.blob.len() > MAX_VERIFIED_BLOB_BYTES {
            return Err(VerifiedBlobRefusal::BoundExceeded("blob bytes"));
        }
        Ok(())
    }
}

/// Exact verification result. The borrowed bytes cannot outlive the checked frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBlob<'a> {
    pub source_head: RepositoryAuthorityHeadId,
    pub source_commit: GitOid,
    pub object_id: GitOid,
    pub kind: VerifiedBlobKind,
    pub bytes: &'a [u8],
}

/// A byte-preserving repository path. It is never interpreted as a host path,
/// never normalizes Unicode, and never follows a symlink. Raw non-UTF-8 names
/// remain supported. Its fixed bounds also bound proof depth and traversal work.
pub fn validate_blob_path(path: &[u8]) -> Result<usize, VerifiedBlobRefusal> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains(&0) {
        return Err(VerifiedBlobRefusal::InvalidPath);
    }
    let mut count = 0;
    for component in path.split(|b| *b == b'/') {
        count += 1;
        if component.is_empty()
            || component.len() > MAX_COMPONENT_BYTES
            || component == b"."
            || component == b".."
            || count > MAX_VERIFIED_BLOB_COMPONENTS
        {
            return Err(VerifiedBlobRefusal::InvalidPath);
        }
    }
    Ok(count)
}

fn bound(field: &'static str, observed: usize, limit: usize) -> CodecRefusal {
    CodecRefusal::LengthBoundExceeded {
        field,
        observed: observed as u64,
        limit: limit as u64,
    }
}

impl CanonicalBody for VerifiedBlobEnvelope {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/verified-blob/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("verified-blob");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate_shape()
            .map_err(|_| bound("verified_blob.shape", 1, 0))?;
        let proof = encode_verified_read_envelope(&self.ref_proof)
            .map_err(|_| bound("verified_blob.ref_proof", 1, 0))?;
        if proof.len() > MAX_REF_PROOF_BYTES {
            return Err(bound(
                "verified_blob.ref_proof",
                proof.len(),
                MAX_REF_PROOF_BYTES,
            ));
        }
        out.write_bytes("verified_blob.ref_proof", &proof)?;
        out.write_bytes("verified_blob.path", &self.path)?;
        out.write_bytes("verified_blob.commit", &self.commit)?;
        out.write_sequence("verified_blob.trees", &self.trees, |out, tree| {
            out.write_bytes("verified_blob.tree", tree)
        })?;
        out.write_bytes("verified_blob.blob", &self.blob)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let proof = input.read_bytes("verified_blob.ref_proof")?;
        if proof.len() > MAX_REF_PROOF_BYTES {
            return Err(bound(
                "verified_blob.ref_proof",
                proof.len(),
                MAX_REF_PROOF_BYTES,
            ));
        }
        let ref_proof = decode_verified_read_envelope(
            proof,
            DecodeLimits {
                frame_bytes: MAX_REF_PROOF_BYTES as u64,
                byte_string_bytes: MAX_PATH_BYTES as u64,
                elements: 4096,
                depth: 16,
            },
        )
        .map_err(|_| bound("verified_blob.ref_proof", 1, 0))?;
        if !matches!(ref_proof.answer(), VerifiedReadAnswer::RefMembership { .. }) {
            return Err(bound("verified_blob.ref_membership", 1, 0));
        }
        let path = input.read_bytes("verified_blob.path")?;
        let components = validate_blob_path(path)
            .map_err(|_| bound("verified_blob.path", path.len(), MAX_PATH_BYTES))?;
        let path = path.to_vec();
        let commit = input.read_bytes("verified_blob.commit")?;
        let mut metadata = commit.len();
        if metadata > MAX_VERIFIED_BLOB_METADATA_BYTES {
            return Err(bound(
                "verified_blob.metadata",
                metadata,
                MAX_VERIFIED_BLOB_METADATA_BYTES,
            ));
        }
        let commit = commit.to_vec();
        let mut count = 0;
        let trees = input.read_sequence("verified_blob.trees", |input| {
            count += 1;
            if count > components {
                return Err(bound("verified_blob.trees", count, components));
            }
            let tree = input.read_bytes("verified_blob.tree")?;
            metadata = metadata.checked_add(tree.len()).ok_or_else(|| {
                bound(
                    "verified_blob.metadata",
                    usize::MAX,
                    MAX_VERIFIED_BLOB_METADATA_BYTES,
                )
            })?;
            if metadata > MAX_VERIFIED_BLOB_METADATA_BYTES {
                return Err(bound(
                    "verified_blob.metadata",
                    metadata,
                    MAX_VERIFIED_BLOB_METADATA_BYTES,
                ));
            }
            Ok(tree.to_vec())
        })?;
        if count != components {
            return Err(bound("verified_blob.trees", count, components));
        }
        let blob = input.read_bytes("verified_blob.blob")?;
        if blob.len() > MAX_VERIFIED_BLOB_BYTES {
            return Err(bound(
                "verified_blob.blob",
                blob.len(),
                MAX_VERIFIED_BLOB_BYTES,
            ));
        }
        Self::from_parts(ref_proof, path, commit, trees, blob.to_vec())
            .map_err(|_| bound("verified_blob.shape", 1, 0))
    }
}

/// Encodes the closed v1 frame. This does not make an unverified object trusted.
pub fn encode_verified_blob_envelope(
    envelope: &VerifiedBlobEnvelope,
) -> Result<Vec<u8>, VerifiedBlobRefusal> {
    envelope.validate_shape()?;
    let bytes = encode_body(envelope).map_err(|e| VerifiedBlobRefusal::Codec(Box::new(e)))?;
    if bytes.len() > MAX_VERIFIED_BLOB_FRAME_BYTES {
        return Err(VerifiedBlobRefusal::BoundExceeded("frame bytes"));
    }
    Ok(bytes)
}

/// Fully consumes one canonical frame with fixed allocation bounds. No caller
/// can silently disable the per-object, aggregate, path, or entry ceilings.
pub fn decode_verified_blob_envelope(
    bytes: &[u8],
) -> Result<VerifiedBlobEnvelope, VerifiedBlobRefusal> {
    if bytes.len() > MAX_VERIFIED_BLOB_FRAME_BYTES {
        return Err(VerifiedBlobRefusal::BoundExceeded("frame bytes"));
    }
    decode_body(
        bytes,
        DecodeLimits {
            frame_bytes: MAX_VERIFIED_BLOB_FRAME_BYTES as u64,
            byte_string_bytes: MAX_VERIFIED_BLOB_BYTES as u64,
            elements: MAX_VERIFIED_BLOB_COMPONENTS as u64,
            depth: 16,
        },
    )
    .map_err(|e| VerifiedBlobRefusal::Codec(Box::new(e)))
}

/// Verifies a supplied head body against an independent full head commitment,
/// then binds the requested ref, exact byte path, native types and complete data.
pub fn verify_blob_against_head<'a>(
    expected: RepositoryAuthorityHeadId,
    reference: &RefName,
    path: &[u8],
    envelope: &'a VerifiedBlobEnvelope,
) -> Result<VerifiedBlob<'a>, VerifiedBlobRefusal> {
    verify_blob_against_head_while(expected, reference, path, envelope, &|| true)
}

fn checkpoint(live: &dyn Fn() -> bool) -> Result<(), VerifiedBlobRefusal> {
    if live() {
        Ok(())
    } else {
        Err(VerifiedBlobRefusal::Cancelled)
    }
}

fn native_hash(
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    bytes: &[u8],
    live: &dyn Fn() -> bool,
) -> Result<GitOid, VerifiedBlobRefusal> {
    macro_rules! hash {
        ($algorithm:ty) => {{
            let mut hash = GitObjectHasher::<$algorithm>::new(kind, bytes.len() as u64);
            for chunk in bytes.chunks(HASH_CHUNK_BYTES) {
                checkpoint(live)?;
                hash.update(chunk)
                    .map_err(|_| VerifiedBlobRefusal::InvalidObject)?;
            }
            checkpoint(live)?;
            hash.finish()
                .map(NativeObjectIdentity::erase)
                .map_err(|_| VerifiedBlobRefusal::InvalidObject)
        }};
    }
    match format {
        GitHashAlgorithm::Sha1 => hash!(Sha1),
        GitHashAlgorithm::Sha256 => hash!(Sha256),
    }
}

fn parse_limits(format: GitHashAlgorithm, entries: usize) -> ParseLimits {
    ParseLimits {
        max_object_bytes: MAX_VERIFIED_BLOB_METADATA_BYTES,
        max_tree_entries: entries,
        tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    }
}

/// Converts one raw tree edge without allowing its width to select another hash domain.
pub fn blob_edge_oid(
    format: GitHashAlgorithm,
    bytes: &[u8],
) -> Result<GitOid, VerifiedBlobRefusal> {
    if bytes.len() != format.digest_len() {
        return Err(VerifiedBlobRefusal::ObjectFormatMismatch);
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    GitOid::from_hex(format, &hex).map_err(|_| VerifiedBlobRefusal::InvalidObject)
}

/// Identical to [`verify_blob_against_head`] with a caller-owned liveness probe.
/// Hashing checks every 64 KiB; parsing is bounded and checked before and after.
pub fn verify_blob_against_head_while<'a>(
    expected: RepositoryAuthorityHeadId,
    reference: &RefName,
    path: &[u8],
    envelope: &'a VerifiedBlobEnvelope,
    live: &dyn Fn() -> bool,
) -> Result<VerifiedBlob<'a>, VerifiedBlobRefusal> {
    checkpoint(live)?;
    validate_blob_path(path)?;
    envelope.validate_shape()?;
    if authority_head_identity(envelope.head()).map_err(|_| VerifiedBlobRefusal::HeadMismatch)?
        != expected
    {
        return Err(VerifiedBlobRefusal::HeadMismatch);
    }
    if envelope.reference() != reference {
        return Err(VerifiedBlobRefusal::RefMismatch);
    }
    if envelope.path != path {
        return Err(VerifiedBlobRefusal::PathMismatch);
    }
    verify_envelope(
        &PinnedAuthorityHead::new(envelope.head().clone()),
        &envelope.ref_proof,
    )
    .map_err(|e| VerifiedBlobRefusal::RefProof(Box::new(e)))?;
    checkpoint(live)?;
    let VerifiedReadAnswer::RefMembership { oid: commit, .. } = envelope.ref_proof.answer() else {
        return Err(VerifiedBlobRefusal::RefMembershipRequired);
    };
    let format = match envelope.ref_proof.exact_configuration() {
        Some(VerifiedReadConfiguration::RepositoryV1(c)) => c.object_format,
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2(c)) => c.object_format,
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2_1(c)) => c.object_format,
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2_2(c)) => c.object_format,
        None => return Err(VerifiedBlobRefusal::ObjectFormatMismatch),
    };
    if commit.algorithm() != format {
        return Err(VerifiedBlobRefusal::ObjectFormatMismatch);
    }
    if native_hash(format, GitObjectKind::Commit, &envelope.commit, live)? != *commit {
        return Err(VerifiedBlobRefusal::ObjectHashMismatch);
    }
    let ParsedObject::Commit(parsed) = parse_object_body(
        ObjectType::Commit,
        &envelope.commit,
        AcceptanceProfile::GitCompatibleImport,
        &parse_limits(format, 0),
    )
    .map_err(|_| VerifiedBlobRefusal::InvalidObject)?
    else {
        return Err(VerifiedBlobRefusal::InvalidObject);
    };
    // Import parsing preserves original bytes. Require one unambiguous tree
    // header rather than selecting the first of several distinct declarations.
    if parsed
        .headers()
        .iter()
        .filter(|h| h.name == b"tree")
        .count()
        != 1
    {
        return Err(VerifiedBlobRefusal::InvalidObject);
    }
    let tree_text = parsed
        .tree_reference()
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or(VerifiedBlobRefusal::InvalidObject)?;
    let mut next = GitOid::from_hex(format, &tree_text.to_ascii_lowercase())
        .map_err(|_| VerifiedBlobRefusal::InvalidObject)?;
    let mut remaining = MAX_VERIFIED_BLOB_TREE_ENTRIES;
    let mut kind = None;
    for (index, (component, body)) in path.split(|b| *b == b'/').zip(&envelope.trees).enumerate() {
        checkpoint(live)?;
        if native_hash(format, GitObjectKind::Tree, body, live)? != next {
            return Err(VerifiedBlobRefusal::ObjectHashMismatch);
        }
        let entries = parse_tree(
            body,
            AcceptanceProfile::GitCompatibleImport,
            &parse_limits(format, remaining),
        )
        .map_err(|_| VerifiedBlobRefusal::InvalidObject)?;
        remaining = remaining
            .checked_sub(entries.len())
            .ok_or(VerifiedBlobRefusal::BoundExceeded("tree entries"))?;
        checkpoint(live)?;
        let mut matching = entries.iter().filter(|entry| entry.name == component);
        let entry = matching.next().ok_or(VerifiedBlobRefusal::PathMissing)?;
        if matching.next().is_some() {
            return Err(VerifiedBlobRefusal::InvalidObject);
        }
        next = blob_edge_oid(format, &entry.object_id)?;
        if index + 1 == envelope.trees.len() {
            kind = Some(match entry.mode.as_slice() {
                b"100644" => VerifiedBlobKind::File,
                b"100755" => VerifiedBlobKind::Executable,
                b"120000" => VerifiedBlobKind::Symlink,
                _ => return Err(VerifiedBlobRefusal::BlobRequired),
            });
        } else if !entry.is_tree() {
            return Err(VerifiedBlobRefusal::DirectoryRequired);
        }
    }
    if native_hash(format, GitObjectKind::Blob, &envelope.blob, live)? != next {
        return Err(VerifiedBlobRefusal::ObjectHashMismatch);
    }
    checkpoint(live)?;
    Ok(VerifiedBlob {
        source_head: expected,
        source_commit: *commit,
        object_id: next,
        kind: kind.ok_or(VerifiedBlobRefusal::BlobRequired)?,
        bytes: &envelope.blob,
    })
}

#[cfg(test)]
mod tests;
