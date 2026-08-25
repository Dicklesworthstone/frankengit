//! Immutable retained-leaf checkpoints for the cumulative outcome index.
//!
//! The outcome-index commitment is ordered by leaf digest, not insertion
//! sequence. A checkpoint therefore retains the terminal decisions from which
//! authority derives those leaves; retaining only the root would make a later
//! tail impossible to fold. This body is immutable evidence, while the
//! capsule that names its digest remains the root-last publication point.

use core::fmt;
use std::collections::BTreeSet;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore, CumulativeOutcomes,
    HeadKey, HeadRead, ImmutableRead, OutcomeFailure, PutOutcome, body_key_for_id,
    canonical_outcome_index_decisions, collect_cumulative_outcomes,
    collect_cumulative_outcomes_async, collect_cumulative_outcomes_from_checkpoint,
    collect_cumulative_outcomes_from_checkpoint_async,
};
use fgit_codec::attest::{BodyIdentity, body_id};
use fgit_codec::{
    CODEC_VERSION, CanonicalBody, CodecRefusal, DecodeLimits, RepositoryDecision, decode_body,
    encode_body,
};
use fgit_codec::{Decoder, Encoder};
use fgit_crypto::IdentityDomain;
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, ManifestLimits, PlacementReceipt, SegmentManifest, StoreRefusal,
    VerifiedObject, read_verified_manifest_closure,
};
use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, FabricError, MicrosegmentBuilder, MicrosegmentReader,
    ObjectEnvelope, ObjectKind, SegmentLimits, SegmentRecordInput,
};
use fgit_types::{
    DecisionSequence, Digest, DomainTag, GitHashAlgorithm, InternalObjectId, RepositoryCapsuleId,
    RepositoryDecisionBatchId, RepositoryId, SchemaFamily, SegmentManifestId,
};

/// The immutable retained leaf set for one exact decision-log position.
///
/// The body binds the existing object-fabric segment manifest that names the
/// retained decision-leaf chunks. It never inlines the leaf bytes: the manifest
/// identity commits the bounded native-blob closure, which the fabric rereads
/// and reconstructs before a checkpoint can accelerate a fold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeIndexCheckpointBody {
    /// Repository whose decision stream this checkpoint summarizes.
    pub repository_id: RepositoryId,
    /// Exact decision-tail body the retained leaf set includes through.
    pub decision_tail_id: Option<RepositoryDecisionBatchId>,
    /// Exact terminal-decision position the retained leaf set includes through.
    pub latest_decision_sequence: Option<DecisionSequence>,
    /// Digest of the immediate older retained-leaf checkpoint, absent at genesis.
    pub predecessor_checkpoint_root: Option<Digest>,
    /// Existing object-fabric manifest that names this checkpoint's leaf chunks.
    pub leaf_archive_manifest: SegmentManifestId,
}

impl OutcomeIndexCheckpointBody {
    /// Constructs a checkpoint that names an already staged leaf archive.
    pub fn new(
        repository_id: RepositoryId,
        decision_tail_id: Option<RepositoryDecisionBatchId>,
        latest_decision_sequence: Option<DecisionSequence>,
        predecessor_checkpoint_root: Option<Digest>,
        leaf_archive_manifest: SegmentManifestId,
    ) -> Result<Self, OutcomeIndexCheckpointRefusal> {
        if decision_tail_id.is_some() != latest_decision_sequence.is_some() {
            return Err(OutcomeIndexCheckpointRefusal::PositionPairMismatch);
        }
        Ok(Self {
            repository_id,
            decision_tail_id,
            latest_decision_sequence,
            predecessor_checkpoint_root,
            leaf_archive_manifest,
        })
    }

    /// Checks the position pairing after decoding. The manifest closure owns
    /// retained-leaf ordering verification.
    pub fn verify_canonical(&self) -> Result<(), OutcomeIndexCheckpointRefusal> {
        if self.decision_tail_id.is_some() != self.latest_decision_sequence.is_some() {
            return Err(OutcomeIndexCheckpointRefusal::PositionPairMismatch);
        }
        Ok(())
    }
}

/// Native-blob codec namespace for one retained outcome-index leaf chunk.
const OUTCOME_INDEX_LEAF_CHUNK_CODEC_NAMESPACE: &[u8] =
    b"frankengit/outcome-index-checkpoint-leaf-chunk/v1";

/// Bounded count of terminal decisions encoded in any one native blob.
pub const MAX_OUTCOME_INDEX_LEAF_CHUNK_DECISIONS: usize = 1_024;

/// Prepared ordinary native blobs for one manifest-backed checkpoint archive.
///
/// The archive has no authority of its own. Callers stage these verified blobs
/// through [`ImmutableObjectFabric`], then derive the existing
/// [`SegmentManifest`] from the returned placement receipts and bind only that
/// manifest identity in [`OutcomeIndexCheckpointBody`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeIndexLeafArchive {
    namespace: Vec<u8>,
    objects: Vec<VerifiedObject>,
}

impl OutcomeIndexLeafArchive {
    /// Encodes authority-canonical retained decisions into deterministic,
    /// bounded native-blob chunks for one repository.
    pub fn prepare(
        repository_id: RepositoryId,
        object_format: GitHashAlgorithm,
        decisions: &[RepositoryDecision],
    ) -> Result<Self, OutcomeIndexCheckpointRefusal> {
        let canonical = canonical_outcome_index_decisions(decisions)
            .map_err(OutcomeIndexCheckpointRefusal::Outcome)?;
        let namespace = outcome_index_leaf_archive_namespace(repository_id);
        let chunks: Vec<&[RepositoryDecision]> = if canonical.is_empty() {
            vec![&[]]
        } else {
            canonical
                .chunks(MAX_OUTCOME_INDEX_LEAF_CHUNK_DECISIONS)
                .collect()
        };
        let digest = CryptoDigest;
        let mut objects = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.into_iter().enumerate() {
            let index = u32::try_from(index)
                .map_err(|_| OutcomeIndexCheckpointRefusal::LeafChunkIndexOverflow)?;
            let payload = encode_outcome_index_leaf_chunk(index, chunk)?;
            let payload_commitment = digest
                .payload_commitment(ObjectKind::Blob, &payload)
                .map_err(OutcomeIndexCheckpointRefusal::Fabric)?;
            let object_identity = fgit_crypto::git_object_id(
                object_format,
                fgit_crypto::GitObjectKind::Blob,
                &payload,
            );
            let envelope = ObjectEnvelope::new(
                namespace.clone(),
                object_identity,
                ObjectKind::Blob,
                u64::try_from(payload.len())
                    .map_err(|_| OutcomeIndexCheckpointRefusal::LeafChunkTooLarge)?,
                payload_commitment,
                OUTCOME_INDEX_LEAF_CHUNK_CODEC_NAMESPACE.to_vec(),
                payload_commitment,
                None,
                &SegmentLimits::default(),
            )
            .map_err(OutcomeIndexCheckpointRefusal::Fabric)?;
            objects.push(
                VerifiedObject::new(envelope, payload)
                    .map_err(OutcomeIndexCheckpointRefusal::FabricStore)?,
            );
        }
        objects.sort_unstable_by_key(VerifiedObject::identity);
        Ok(Self { namespace, objects })
    }

    /// Verified native blobs in the fabric's required identity order.
    #[must_use]
    pub fn objects(&self) -> &[VerifiedObject] {
        &self.objects
    }

    /// Builds the existing segment manifest after every archive blob has a
    /// caller-observed placement receipt. `placements` must already be in the
    /// fabric's canonical receipt order and contain no duplicates.
    pub fn manifest(
        &self,
        placements: Vec<PlacementReceipt>,
    ) -> Result<SegmentManifest, OutcomeIndexCheckpointRefusal> {
        let limits = SegmentLimits::default();
        let digest = CryptoDigest;
        let mut builder = MicrosegmentBuilder::new(&digest, limits.clone());
        for object in &self.objects {
            builder
                .push(SegmentRecordInput {
                    envelope: object.envelope().clone(),
                    payload: object.payload().to_vec(),
                })
                .map_err(OutcomeIndexCheckpointRefusal::Fabric)?;
        }
        let segment = builder
            .build()
            .map_err(OutcomeIndexCheckpointRefusal::Fabric)?;
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits)
            .map_err(OutcomeIndexCheckpointRefusal::Fabric)?;
        SegmentManifest::from_verified_segment(&reader, placements, &ManifestLimits::default())
            .map_err(OutcomeIndexCheckpointRefusal::FabricStore)
    }

    /// The exact namespace every manifest in this archive must use.
    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }
}

/// Rereads the fabric closure named by a checkpoint and recovers the only
/// authority-owned decision ordering. No manifest metadata is treated as leaf
/// evidence until every native object and the reconstructed microsegment pass
/// the object-fabric verifier.
pub fn load_outcome_index_checkpoint_leaves<F>(
    fabric: &F,
    checkpoint: &OutcomeIndexCheckpointBody,
) -> Result<Vec<RepositoryDecision>, OutcomeIndexCheckpointRefusal>
where
    F: ImmutableObjectFabric + ?Sized,
{
    let closure = read_verified_manifest_closure(
        fabric,
        checkpoint.leaf_archive_manifest,
        &SegmentLimits::default(),
    )
    .map_err(OutcomeIndexCheckpointRefusal::FabricStore)?;
    if closure.manifest().namespace()
        != outcome_index_leaf_archive_namespace(checkpoint.repository_id)
    {
        return Err(OutcomeIndexCheckpointRefusal::LeafArchiveNamespaceMismatch);
    }

    let mut chunks = Vec::with_capacity(closure.objects().len());
    for whole in closure.objects() {
        let envelope = whole.object.envelope();
        if envelope.object_kind() != ObjectKind::Blob {
            return Err(OutcomeIndexCheckpointRefusal::LeafArchiveObjectKind);
        }
        if envelope.codec_namespace() != OUTCOME_INDEX_LEAF_CHUNK_CODEC_NAMESPACE {
            return Err(OutcomeIndexCheckpointRefusal::LeafArchiveCodecNamespaceMismatch);
        }
        if envelope.logical_content_identity() != envelope.payload_commitment() {
            return Err(OutcomeIndexCheckpointRefusal::LeafArchiveLogicalIdentityMismatch);
        }
        chunks.push(decode_outcome_index_leaf_chunk(whole.object.payload())?);
    }
    chunks.sort_unstable_by_key(|(index, _)| *index);
    let mut decisions = Vec::new();
    for (expected, (index, chunk)) in chunks.into_iter().enumerate() {
        if index
            != u32::try_from(expected)
                .map_err(|_| OutcomeIndexCheckpointRefusal::LeafChunkIndexOverflow)?
        {
            return Err(OutcomeIndexCheckpointRefusal::LeafChunkOrderMismatch);
        }
        if chunk.is_empty() && expected != 0 {
            return Err(OutcomeIndexCheckpointRefusal::EmptyLeafChunk);
        }
        if decisions.is_empty() && chunk.is_empty() && closure.objects().len() != 1 {
            return Err(OutcomeIndexCheckpointRefusal::EmptyLeafChunk);
        }
        decisions.extend(chunk);
    }
    let canonical = canonical_outcome_index_decisions(&decisions)
        .map_err(OutcomeIndexCheckpointRefusal::Outcome)?;
    if canonical != decisions {
        return Err(OutcomeIndexCheckpointRefusal::LeafOrderMismatch);
    }
    Ok(decisions)
}

/// Loads a checkpoint only when both its authority-owned predecessor chain and
/// its manifest-selected retained leaves verify.
///
/// This is the fabric-aware acceleration boundary: callers must use the
/// returned decisions with the authority collector at the checkpoint's exact
/// position. A bare checkpoint body or bare manifest identity is never enough
/// to substitute for the retained leaf set.
pub fn load_verified_outcome_index_checkpoint<S, I, F>(
    store: &S,
    identity: &I,
    fabric: &F,
    root: Digest,
) -> Result<(OutcomeIndexCheckpointBody, Vec<RepositoryDecision>), OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
    F: ImmutableObjectFabric + ?Sized,
{
    let checkpoint = verify_outcome_index_checkpoint_chain(store, identity, root)?;
    let decisions = load_outcome_index_checkpoint_leaves(fabric, &checkpoint)?;
    Ok((checkpoint, decisions))
}

/// Asynchronous authority twin of [`load_verified_outcome_index_checkpoint`].
/// Object-fabric closure reads remain explicit synchronous immutable reads;
/// they neither create authority nor borrow the authority runtime context.
pub async fn load_verified_outcome_index_checkpoint_async<S, I, F>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    fabric: &F,
    root: Digest,
) -> Result<(OutcomeIndexCheckpointBody, Vec<RepositoryDecision>), OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
    F: ImmutableObjectFabric + ?Sized,
{
    let checkpoint = verify_outcome_index_checkpoint_chain_async(store, cx, identity, root).await?;
    let decisions = load_outcome_index_checkpoint_leaves(fabric, &checkpoint)?;
    Ok((checkpoint, decisions))
}

fn outcome_index_leaf_archive_namespace(repository_id: RepositoryId) -> Vec<u8> {
    let mut namespace = b"frankengit/outcome-index-checkpoint-leaves/v1/".to_vec();
    namespace.extend_from_slice(repository_id.as_bytes());
    namespace
}

fn encode_outcome_index_leaf_chunk(
    index: u32,
    decisions: &[RepositoryDecision],
) -> Result<Vec<u8>, OutcomeIndexCheckpointRefusal> {
    let mut out = Encoder::new();
    out.write_scalar(index);
    out.write_sequence(
        "outcome_index_leaf_chunk_decisions",
        decisions,
        RepositoryDecision::write_canonical,
    )
    .map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    Ok(out.into_bytes())
}

fn decode_outcome_index_leaf_chunk(
    bytes: &[u8],
) -> Result<(u32, Vec<RepositoryDecision>), OutcomeIndexCheckpointRefusal> {
    let mut input = Decoder::new(bytes, DecodeLimits::DEFAULT);
    let index = input
        .read_scalar("outcome_index_leaf_chunk_index")
        .map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    let decisions = input
        .read_sequence(
            "outcome_index_leaf_chunk_decisions",
            RepositoryDecision::read_canonical,
        )
        .map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    if decisions.len() > MAX_OUTCOME_INDEX_LEAF_CHUNK_DECISIONS {
        return Err(OutcomeIndexCheckpointRefusal::LeafChunkTooLarge);
    }
    input
        .finish()
        .map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    Ok((index, decisions))
}

impl CanonicalBody for OutcomeIndexCheckpointBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/outcome-index-checkpoint/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("outcome-index-checkpoint");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 1;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_option(self.decision_tail_id.as_ref(), |out, tail_id| {
            out.write_internal_object_id(tail_id.as_internal_object_id())
        })?;
        out.write_option(self.latest_decision_sequence.as_ref(), |out, sequence| {
            out.write_scalar(sequence.get());
            Ok(())
        })?;
        out.write_option(self.predecessor_checkpoint_root.as_ref(), |out, root| {
            out.write_digest(root)
        })?;
        out.write_internal_object_id(self.leaf_archive_manifest.as_internal_object_id())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let decision_tail_id = input.read_option("decision_tail_id", |input| {
            RepositoryDecisionBatchId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        let latest_decision_sequence = input.read_option("latest_decision_sequence", |input| {
            DecisionSequence::try_new(input.read_scalar::<u64>("latest_decision_sequence")?)
                .map_err(CodecRefusal::from)
        })?;
        let predecessor_checkpoint_root =
            input.read_option("predecessor_checkpoint_root", Decoder::read_digest)?;
        let leaf_archive_manifest =
            SegmentManifestId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)?;
        Ok(Self {
            repository_id,
            decision_tail_id,
            latest_decision_sequence,
            predecessor_checkpoint_root,
            leaf_archive_manifest,
        })
    }
}

/// Refusals while deriving, staging, or reading retained outcome-index evidence.
#[derive(Debug)]
pub enum OutcomeIndexCheckpointRefusal {
    /// The checkpoint did not name both parts of its exact decision position.
    PositionPairMismatch,
    /// Retained decisions are not in authority's one commitment order.
    LeafOrderMismatch,
    /// A leaf archive manifest belongs to a different repository scope.
    LeafArchiveNamespaceMismatch,
    /// A manifest-selected object is not a native Git blob.
    LeafArchiveObjectKind,
    /// A native blob did not name the fixed outcome-index leaf chunk codec.
    LeafArchiveCodecNamespaceMismatch,
    /// A leaf chunk envelope did not bind its logical identity to its payload.
    LeafArchiveLogicalIdentityMismatch,
    /// Leaf chunks were missing, duplicated, or not numbered contiguously.
    LeafChunkOrderMismatch,
    /// A non-empty archive contained an empty interior leaf chunk.
    EmptyLeafChunk,
    /// A leaf chunk could not fit the fixed bounded chunk contract.
    LeafChunkTooLarge,
    /// The platform could not represent a deterministic leaf chunk index.
    LeafChunkIndexOverflow,
    /// Authority refused duplicate, malformed, or otherwise invalid decisions.
    Outcome(OutcomeFailure),
    /// Canonical body encoding or decoding refused.
    Codec(CodecRefusal),
    /// The configured identity implementation could not identify this body.
    IdentityUnavailable,
    /// The identity result did not use the registered checkpoint domain.
    IdentityDomainMismatch,
    /// A requested immutable checkpoint body was absent.
    NotStaged,
    /// An immutable slot already held different checkpoint bytes.
    SlotConflict,
    /// Exact byte readback after staging did not prove the checkpoint exists.
    ReadbackMismatch,
    /// The body decoded at a requested digest has a different identity.
    IdentityMismatch,
    /// A predecessor cycle would make retained evidence non-terminating.
    PredecessorCycle,
    /// The predecessor chain exceeded its bounded verification budget.
    PredecessorChainTooLong,
    /// A predecessor belongs to another repository.
    PredecessorRepositoryMismatch,
    /// A predecessor does not name an older decision position.
    PredecessorPositionMismatch,
    /// The authority backend refused an immutable operation.
    Authority(AuthorityFailure),
    /// Object-fabric segment construction refused the proposed archive bytes.
    Fabric(FabricError),
    /// Object-fabric storage or closure verification refused the archive.
    FabricStore(StoreRefusal),
}

impl fmt::Display for OutcomeIndexCheckpointRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PositionPairMismatch => formatter.write_str(
                "outcome-index checkpoint must name both decision-tail id and decision sequence",
            ),
            Self::LeafOrderMismatch => formatter
                .write_str("outcome-index checkpoint decisions are not in commitment order"),
            Self::LeafArchiveNamespaceMismatch => formatter.write_str(
                "outcome-index checkpoint leaf archive belongs to another repository namespace",
            ),
            Self::LeafArchiveObjectKind => formatter.write_str(
                "outcome-index checkpoint leaf archive contains a non-blob native object",
            ),
            Self::LeafArchiveCodecNamespaceMismatch => formatter.write_str(
                "outcome-index checkpoint leaf archive uses the wrong native-blob codec namespace",
            ),
            Self::LeafArchiveLogicalIdentityMismatch => formatter.write_str(
                "outcome-index checkpoint leaf archive logical identity differs from payload commitment",
            ),
            Self::LeafChunkOrderMismatch => formatter.write_str(
                "outcome-index checkpoint leaf chunks are not a contiguous canonical sequence",
            ),
            Self::EmptyLeafChunk => formatter.write_str(
                "outcome-index checkpoint leaf archive has an invalid empty chunk",
            ),
            Self::LeafChunkTooLarge => formatter.write_str(
                "outcome-index checkpoint leaf chunk exceeds its bounded codec contract",
            ),
            Self::LeafChunkIndexOverflow => formatter.write_str(
                "outcome-index checkpoint leaf chunk index cannot be represented canonically",
            ),
            Self::Outcome(error) => write!(formatter, "outcome-index checkpoint refused: {error}"),
            Self::Codec(error) => {
                write!(formatter, "outcome-index checkpoint codec refused: {error}")
            }
            Self::IdentityUnavailable => {
                formatter.write_str("outcome-index checkpoint identity was unavailable")
            }
            Self::IdentityDomainMismatch => formatter
                .write_str("outcome-index checkpoint identity used the wrong registered domain"),
            Self::NotStaged => formatter.write_str("outcome-index checkpoint body was not staged"),
            Self::SlotConflict => {
                formatter.write_str("outcome-index checkpoint immutable slot held different bytes")
            }
            Self::ReadbackMismatch => formatter.write_str(
                "outcome-index checkpoint staging was not proven by exact byte readback",
            ),
            Self::IdentityMismatch => formatter.write_str(
                "outcome-index checkpoint bytes did not reproduce the requested identity",
            ),
            Self::PredecessorCycle => {
                formatter.write_str("outcome-index checkpoint predecessor chain contains a cycle")
            }
            Self::PredecessorChainTooLong => formatter.write_str(
                "outcome-index checkpoint predecessor chain exceeded its verification bound",
            ),
            Self::PredecessorRepositoryMismatch => formatter
                .write_str("outcome-index checkpoint predecessor belongs to another repository"),
            Self::PredecessorPositionMismatch => formatter.write_str(
                "outcome-index checkpoint predecessor does not name an older decision position",
            ),
            Self::Authority(error) => {
                write!(
                    formatter,
                    "outcome-index checkpoint authority operation refused: {error}"
                )
            }
            Self::Fabric(error) => {
                write!(formatter, "outcome-index checkpoint fabric construction refused: {error}")
            }
            Self::FabricStore(error) => {
                write!(formatter, "outcome-index checkpoint fabric storage refused: {error}")
            }
        }
    }
}

impl std::error::Error for OutcomeIndexCheckpointRefusal {}

/// Derives the digest a capsule binds for an immutable checkpoint body.
pub fn outcome_index_checkpoint_root<I>(
    identity: &I,
    checkpoint: &OutcomeIndexCheckpointBody,
) -> Result<Digest, OutcomeIndexCheckpointRefusal>
where
    I: BodyIdentity + ?Sized,
{
    checkpoint.verify_canonical()?;
    let id = body_id(identity, checkpoint)
        .map_err(|_| OutcomeIndexCheckpointRefusal::IdentityUnavailable)?;
    if id.domain() != IdentityDomain::OutcomeIndexCheckpoint.domain_tag() {
        return Err(OutcomeIndexCheckpointRefusal::IdentityDomainMismatch);
    }
    Ok(Digest::new(id.algorithm(), *id.digest()))
}

fn checkpoint_key(
    root: Digest,
) -> Result<fgit_authority::ImmutableKey, OutcomeIndexCheckpointRefusal> {
    let domain = IdentityDomain::OutcomeIndexCheckpoint;
    if root.algorithm() != domain.algorithm().id() {
        return Err(OutcomeIndexCheckpointRefusal::IdentityDomainMismatch);
    }
    let id = InternalObjectId::new(
        root.algorithm(),
        domain.domain_tag(),
        CODEC_VERSION,
        *root.bytes(),
    );
    body_key_for_id(&id).map_err(|_| OutcomeIndexCheckpointRefusal::IdentityUnavailable)
}

/// Stages a verified checkpoint and proves the exact canonical bytes are readable.
pub fn stage_outcome_index_checkpoint<S, I>(
    store: &S,
    identity: &I,
    checkpoint: &OutcomeIndexCheckpointBody,
) -> Result<Digest, OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let root = outcome_index_checkpoint_root(identity, checkpoint)?;
    let bytes = encode_body(checkpoint).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    let key = checkpoint_key(root)?;
    match store
        .put_if_absent(&key, &bytes)
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(OutcomeIndexCheckpointRefusal::SlotConflict),
    }
    if !matches!(store.read_immutable(&key), Ok(ImmutableRead::Present(found)) if found == bytes) {
        return Err(OutcomeIndexCheckpointRefusal::ReadbackMismatch);
    }
    Ok(root)
}

/// Asynchronous twin of [`stage_outcome_index_checkpoint`].
pub async fn stage_outcome_index_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    checkpoint: &OutcomeIndexCheckpointBody,
) -> Result<Digest, OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let root = outcome_index_checkpoint_root(identity, checkpoint)?;
    let bytes = encode_body(checkpoint).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    let key = checkpoint_key(root)?;
    match store
        .put_if_absent(cx, &key, &bytes)
        .await
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(OutcomeIndexCheckpointRefusal::SlotConflict),
    }
    if !matches!(store.read_immutable(cx, &key).await, Ok(ImmutableRead::Present(found)) if found == bytes)
    {
        return Err(OutcomeIndexCheckpointRefusal::ReadbackMismatch);
    }
    Ok(root)
}

/// Loads a checkpoint only when its exact requested identity and canonical form agree.
pub fn load_outcome_index_checkpoint<S, I>(
    store: &S,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let key = checkpoint_key(root)?;
    let ImmutableRead::Present(bytes) = store
        .read_immutable(&key)
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    else {
        return Err(OutcomeIndexCheckpointRefusal::NotStaged);
    };
    let checkpoint =
        decode_body(&bytes, DecodeLimits::DEFAULT).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    if outcome_index_checkpoint_root(identity, &checkpoint)? != root {
        return Err(OutcomeIndexCheckpointRefusal::IdentityMismatch);
    }
    Ok(checkpoint)
}

/// Asynchronous twin of [`load_outcome_index_checkpoint`].
pub async fn load_outcome_index_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let key = checkpoint_key(root)?;
    let ImmutableRead::Present(bytes) = store
        .read_immutable(cx, &key)
        .await
        .map_err(OutcomeIndexCheckpointRefusal::Authority)?
    else {
        return Err(OutcomeIndexCheckpointRefusal::NotStaged);
    };
    let checkpoint =
        decode_body(&bytes, DecodeLimits::DEFAULT).map_err(OutcomeIndexCheckpointRefusal::Codec)?;
    if outcome_index_checkpoint_root(identity, &checkpoint)? != root {
        return Err(OutcomeIndexCheckpointRefusal::IdentityMismatch);
    }
    Ok(checkpoint)
}

/// Maximum predecessor links accepted while validating checkpoint evidence.
///
/// A checkpoint chain is acceleration evidence, never an unbounded traversal
/// permission. This mirrors the decision-tail bound while remaining far above
/// a normal compaction cadence.
pub const MAX_CHECKPOINT_PREDECESSORS: usize = 65_536;

/// Verifies the complete predecessor chain and returns the checkpoint named by
/// `root`.
///
/// Every body is reread at its declared digest, has its canonical leaf order
/// checked, belongs to one repository, and strictly advances the decision
/// position over its predecessor. A malformed chain is not usable evidence.
pub fn verify_outcome_index_checkpoint_chain<S, I>(
    store: &S,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    verify_outcome_index_checkpoint_chain_with_bound(
        store,
        identity,
        root,
        MAX_CHECKPOINT_PREDECESSORS,
    )
}

fn verify_outcome_index_checkpoint_chain_with_bound<S, I>(
    store: &S,
    identity: &I,
    root: Digest,
    predecessor_limit: usize,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let first = load_outcome_index_checkpoint(store, identity, root)?;
    let repository_id = first.repository_id;
    let mut current = first.clone();
    let mut seen = BTreeSet::from([root]);
    let mut links = 0_usize;

    while let Some(predecessor_root) = current.predecessor_checkpoint_root {
        if links == predecessor_limit {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorChainTooLong);
        }
        if !seen.insert(predecessor_root) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorCycle);
        }
        let predecessor = load_outcome_index_checkpoint(store, identity, predecessor_root)?;
        if predecessor.repository_id != repository_id {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorRepositoryMismatch);
        }
        if !checkpoint_position_advances(&current, &predecessor) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorPositionMismatch);
        }
        current = predecessor;
        links += 1;
    }
    Ok(first)
}

/// Asynchronous twin of [`verify_outcome_index_checkpoint_chain`].
pub async fn verify_outcome_index_checkpoint_chain_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    root: Digest,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    verify_outcome_index_checkpoint_chain_async_with_bound(
        store,
        cx,
        identity,
        root,
        MAX_CHECKPOINT_PREDECESSORS,
    )
    .await
}

async fn verify_outcome_index_checkpoint_chain_async_with_bound<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    root: Digest,
    predecessor_limit: usize,
) -> Result<OutcomeIndexCheckpointBody, OutcomeIndexCheckpointRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let first = load_outcome_index_checkpoint_async(store, cx, identity, root).await?;
    let repository_id = first.repository_id;
    let mut current = first.clone();
    let mut seen = BTreeSet::from([root]);
    let mut links = 0_usize;

    while let Some(predecessor_root) = current.predecessor_checkpoint_root {
        if links == predecessor_limit {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorChainTooLong);
        }
        if !seen.insert(predecessor_root) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorCycle);
        }
        let predecessor =
            load_outcome_index_checkpoint_async(store, cx, identity, predecessor_root).await?;
        if predecessor.repository_id != repository_id {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorRepositoryMismatch);
        }
        if !checkpoint_position_advances(&current, &predecessor) {
            return Err(OutcomeIndexCheckpointRefusal::PredecessorPositionMismatch);
        }
        current = predecessor;
        links += 1;
    }
    Ok(first)
}

fn checkpoint_position_advances(
    newer: &OutcomeIndexCheckpointBody,
    older: &OutcomeIndexCheckpointBody,
) -> bool {
    match (
        newer.latest_decision_sequence,
        older.latest_decision_sequence,
    ) {
        (Some(newer), Some(older)) => newer > older,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fgit_authority::{MemoryAuthorityStore, StoreInstanceId};
    use fgit_codec::CryptoBodyIdentity;
    use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, OPAQUE_ID_LEN};

    const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff2;

    const fn repository() -> RepositoryId {
        RepositoryId::from_bytes([0x72; OPAQUE_ID_LEN])
    }

    fn checkpoint_tail(position: u64) -> RepositoryDecisionBatchId {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&position.to_be_bytes());
        bytes[31] = 0x72;
        RepositoryDecisionBatchId::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("fixture algorithm is reserved"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&bytes).expect("fixture digest is 32 bytes"),
        )
    }

    fn archive_manifest() -> SegmentManifestId {
        SegmentManifestId::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("fixture algorithm is reserved"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x73; 32]).expect("fixture digest is 32 bytes"),
        )
    }

    fn stage_chain(store: &MemoryAuthorityStore, predecessor_links: usize) -> Digest {
        let mut predecessor = None;
        for position in 1..=predecessor_links + 1 {
            let position = u64::try_from(position).expect("fixture position fits in u64");
            let checkpoint = OutcomeIndexCheckpointBody::new(
                repository(),
                Some(checkpoint_tail(position)),
                Some(DecisionSequence::try_new(position).expect("fixture position is nonzero")),
                predecessor,
                archive_manifest(),
            )
            .expect("manifest-backed retained leaf evidence is canonical");
            predecessor = Some(
                stage_outcome_index_checkpoint(store, &CryptoBodyIdentity, &checkpoint)
                    .expect("fixture checkpoint stages"),
            );
        }
        predecessor.expect("a chain always has its newest checkpoint")
    }

    #[test]
    fn checkpoint_chain_bound_accepts_n_and_refuses_n_plus_one() {
        const TEST_BOUND: usize = 3;

        let at_limit = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7201));
        let at_limit_root = stage_chain(&at_limit, TEST_BOUND);
        assert!(
            verify_outcome_index_checkpoint_chain_with_bound(
                &at_limit,
                &CryptoBodyIdentity,
                at_limit_root,
                TEST_BOUND,
            )
            .is_ok(),
            "exactly TEST_BOUND predecessor links remain accepted"
        );

        let over_limit = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x7202));
        let over_limit_root = stage_chain(&over_limit, TEST_BOUND + 1);
        assert!(matches!(
            verify_outcome_index_checkpoint_chain_with_bound(
                &over_limit,
                &CryptoBodyIdentity,
                over_limit_root,
                TEST_BOUND,
            ),
            Err(OutcomeIndexCheckpointRefusal::PredecessorChainTooLong)
        ));
    }
}

fn load_capsule_at_id<S, I>(
    store: &S,
    identity: &I,
    capsule_id: RepositoryCapsuleId,
) -> Result<Option<crate::RepositoryCapsuleBody>, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let key = body_key_for_id(capsule_id.as_internal_object_id())?;
    let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
        return Ok(None);
    };
    let Ok(capsule) = decode_body(&bytes, DecodeLimits::DEFAULT) else {
        return Ok(None);
    };
    let Ok(found) = crate::capsule_identity(identity, &capsule) else {
        return Ok(None);
    };
    if found != capsule_id {
        return Ok(None);
    }
    Ok(Some(capsule))
}

async fn load_capsule_at_id_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    capsule_id: RepositoryCapsuleId,
) -> Result<Option<crate::RepositoryCapsuleBody>, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let key = body_key_for_id(capsule_id.as_internal_object_id())?;
    let ImmutableRead::Present(bytes) = store.read_immutable(cx, &key).await? else {
        return Ok(None);
    };
    let Ok(capsule) = decode_body(&bytes, DecodeLimits::DEFAULT) else {
        return Ok(None);
    };
    let Ok(found) = crate::capsule_identity(identity, &capsule) else {
        return Ok(None);
    };
    if found != capsule_id {
        return Ok(None);
    }
    Ok(Some(capsule))
}

/// Collects outcome-index leaves from a capsule-bound retained checkpoint when
/// one is usable, otherwise performs today's bounded genesis walk.
///
/// Checkpoint evidence is an acceleration hint, never a second authority. A
/// missing, undecodable, wrongly identified, or malformed checkpoint selects
/// the genesis collector. Backend failures still propagate, and a usable
/// checkpoint whose exact authority position/root cannot be reached is also
/// discarded in favour of that same bounded baseline.
pub fn collect_cumulative_outcomes_from_capsule_checkpoint<S, I>(
    store: &S,
    identity: &I,
    head_key: &HeadKey,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        return collect_cumulative_outcomes(store, head_key);
    };
    let head: fgit_codec::RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT)?;
    collect_cumulative_outcomes_from_checkpoint_hint(store, identity, head_key, &head)
}

/// Collects outcome-index leaves using a head that the caller already
/// authenticated for its publication basis.
///
/// Admission reads and authenticates one exact basis before it resolves the
/// cumulative index. Reusing that head for the optional capsule hint avoids a
/// speculative extra `read_head` while the baseline collector retains its own
/// read, preserving the recovery transcript and its version binding.
pub fn collect_cumulative_outcomes_from_authenticated_capsule_checkpoint<S, I>(
    store: &S,
    identity: &I,
    head_key: &HeadKey,
    authenticated_head: &AuthenticatedHead,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    let head = authenticated_head.body()?;
    collect_cumulative_outcomes_from_checkpoint_hint(store, identity, head_key, &head)
}

/// Fabric-aware counterpart of
/// [`collect_cumulative_outcomes_from_authenticated_capsule_checkpoint`].
///
/// This is the retained-leaf acceleration path. It accepts a capsule hint only
/// after the authority checkpoint chain, object-fabric manifest closure, chunk
/// codec, and authority-owned leaf order all verify. Missing or malformed
/// checkpoint evidence falls back to the existing bounded genesis walk; an
/// authority failure still propagates.
pub fn collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric<S, I, F>(
    store: &S,
    fabric: &F,
    identity: &I,
    head_key: &HeadKey,
    authenticated_head: &AuthenticatedHead,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
    F: ImmutableObjectFabric + ?Sized,
{
    let head = authenticated_head.body()?;
    collect_cumulative_outcomes_from_checkpoint_hint_with_fabric(
        store, fabric, identity, head_key, &head,
    )
}

fn collect_cumulative_outcomes_from_checkpoint_hint_with_fabric<S, I, F>(
    store: &S,
    fabric: &F,
    identity: &I,
    head_key: &HeadKey,
    head: &fgit_codec::RepositoryAuthorityHeadBody,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
    F: ImmutableObjectFabric + ?Sized,
{
    let Some(capsule_id) = head.last_checkpoint_id else {
        return collect_cumulative_outcomes(store, head_key);
    };
    let Some(capsule) = load_capsule_at_id(store, identity, capsule_id)? else {
        return collect_cumulative_outcomes(store, head_key);
    };
    if capsule.repository_id != head.repository_id {
        return collect_cumulative_outcomes(store, head_key);
    }
    let Some(root) = capsule.outcome_index_checkpoint_root else {
        return collect_cumulative_outcomes(store, head_key);
    };
    let (checkpoint, decisions) =
        match load_verified_outcome_index_checkpoint(store, identity, fabric, root) {
            Ok(value) if value.0.repository_id == head.repository_id => value,
            Ok(_) => {
                return collect_cumulative_outcomes(store, head_key);
            }
            Err(OutcomeIndexCheckpointRefusal::Authority(error)) => return Err(error.into()),
            Err(_) => return collect_cumulative_outcomes(store, head_key),
        };
    match collect_cumulative_outcomes_from_checkpoint(
        store,
        head_key,
        &decisions,
        checkpoint.decision_tail_id,
        checkpoint.latest_decision_sequence,
    ) {
        Ok(outcomes) => Ok(outcomes),
        Err(
            OutcomeFailure::CheckpointPositionMismatch | OutcomeFailure::CheckpointRootMismatch,
        ) => collect_cumulative_outcomes(store, head_key),
        Err(error) => Err(error),
    }
}

fn collect_cumulative_outcomes_from_checkpoint_hint<S, I>(
    store: &S,
    identity: &I,
    head_key: &HeadKey,
    head: &fgit_codec::RepositoryAuthorityHeadBody,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    // This compatibility entrypoint has no object-fabric capability. A
    // manifest-backed checkpoint is therefore unavailable evidence here; it
    // must use the existing bounded genesis collector rather than pretending a
    // manifest identity is a retained leaf set. Fabric-aware callers use
    // `load_verified_outcome_index_checkpoint` before invoking the authority
    // checkpoint collector.
    let _ = (identity, head);
    collect_cumulative_outcomes(store, head_key)
}

/// Asynchronous production twin of
/// [`collect_cumulative_outcomes_from_capsule_checkpoint`].
pub async fn collect_cumulative_outcomes_from_capsule_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    head_key: &HeadKey,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    let head: fgit_codec::RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT)?;
    collect_cumulative_outcomes_from_checkpoint_hint_async(store, cx, identity, head_key, &head)
        .await
}

/// Asynchronous sibling of
/// [`collect_cumulative_outcomes_from_authenticated_capsule_checkpoint`].
pub async fn collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    head_key: &HeadKey,
    authenticated_head: &AuthenticatedHead,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    let head = authenticated_head.body()?;
    collect_cumulative_outcomes_from_checkpoint_hint_async(store, cx, identity, head_key, &head)
        .await
}

/// Asynchronous fabric-aware counterpart of
/// [`collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric`].
pub async fn collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric_async<
    S,
    I,
    F,
>(
    store: &S,
    cx: &S::Context,
    fabric: &F,
    identity: &I,
    head_key: &HeadKey,
    authenticated_head: &AuthenticatedHead,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
    F: ImmutableObjectFabric + ?Sized,
{
    let head = authenticated_head.body()?;
    collect_cumulative_outcomes_from_checkpoint_hint_with_fabric_async(
        store, cx, fabric, identity, head_key, &head,
    )
    .await
}

async fn collect_cumulative_outcomes_from_checkpoint_hint_with_fabric_async<S, I, F>(
    store: &S,
    cx: &S::Context,
    fabric: &F,
    identity: &I,
    head_key: &HeadKey,
    head: &fgit_codec::RepositoryAuthorityHeadBody,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
    F: ImmutableObjectFabric + ?Sized,
{
    let Some(capsule_id) = head.last_checkpoint_id else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    let Some(capsule) = load_capsule_at_id_async(store, cx, identity, capsule_id).await? else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    if capsule.repository_id != head.repository_id {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    }
    let Some(root) = capsule.outcome_index_checkpoint_root else {
        return collect_cumulative_outcomes_async(store, cx, head_key).await;
    };
    let (checkpoint, decisions) =
        match load_verified_outcome_index_checkpoint_async(store, cx, identity, fabric, root).await
        {
            Ok(value) if value.0.repository_id == head.repository_id => value,
            Ok(_) => {
                return collect_cumulative_outcomes_async(store, cx, head_key).await;
            }
            Err(OutcomeIndexCheckpointRefusal::Authority(error)) => return Err(error.into()),
            Err(_) => return collect_cumulative_outcomes_async(store, cx, head_key).await,
        };
    match collect_cumulative_outcomes_from_checkpoint_async(
        store,
        cx,
        head_key,
        &decisions,
        checkpoint.decision_tail_id,
        checkpoint.latest_decision_sequence,
    )
    .await
    {
        Ok(outcomes) => Ok(outcomes),
        Err(
            OutcomeFailure::CheckpointPositionMismatch | OutcomeFailure::CheckpointRootMismatch,
        ) => collect_cumulative_outcomes_async(store, cx, head_key).await,
        Err(error) => Err(error),
    }
}

async fn collect_cumulative_outcomes_from_checkpoint_hint_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    head_key: &HeadKey,
    head: &fgit_codec::RepositoryAuthorityHeadBody,
) -> Result<CumulativeOutcomes, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    // See the blocking counterpart: this surface deliberately lacks a fabric
    // capability, so it cannot accept manifest metadata as leaf evidence.
    let _ = (identity, head);
    collect_cumulative_outcomes_async(store, cx, head_key).await
}
