// Shared test support: the corpus digest, a deterministic generator, and the
// fixtures the committed golden corpus was derived from.
#![allow(dead_code)]

use fgit_codec::attest::BodyIdentity;
use fgit_codec::schema::{
    RefusalRecordBody, RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecision,
    RepositoryDecisionBatchBody, TransactionSealBody,
};
use fgit_types::hash::{Digest, DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{
    InternalObjectId, PrincipalSnapshotId, RefusalRecordId, RepositoryAuthorityHeadId,
    RepositoryCapsuleId, RepositoryCommitId, RepositoryDecisionBatchId, TransactionSealId, TxId,
};
use fgit_types::numeric::{
    DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositorySequence,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DomainTag, PrincipalId, RefusalCode, RepositoryId,
    SchemaFamily, SchemaId, TenantId,
};

// -------------------------------------------------------------- corpus digest

/// Registry slot reserved for the golden corpus. It is deliberately at the top
/// of the code-point space so it cannot collide with a production algorithm.
pub const CORPUS_ALGORITHM_CODE_POINT: u16 = 0xfff1;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in data {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The digest preimage, framed the way `fgit-crypto` freezes it.
///
/// Reimplemented here on purpose. The production preimage lives in
/// `fgit-crypto`; writing it a second time in the corpus is what makes the
/// committed identities a cross-check of that framing rather than a copy of
/// it. If the two ever disagree, this is where it shows.
pub fn identity_preimage(domain: DomainTag, schema: SchemaId, canonical_body: &[u8]) -> Vec<u8> {
    let domain = domain.as_bytes();
    let family = schema.family();
    let family = family.as_bytes();
    let mut out = Vec::with_capacity(domain.len() + family.len() + canonical_body.len() + 16);
    out.push(u8::try_from(domain.len()).expect("a label is at most 64 bytes"));
    out.extend_from_slice(domain);
    out.push(u8::try_from(family.len()).expect("a label is at most 64 bytes"));
    out.extend_from_slice(family);
    out.extend_from_slice(&schema.major().to_be_bytes());
    out.extend_from_slice(&schema.minor().to_be_bytes());
    out.extend_from_slice(
        &u64::try_from(canonical_body.len())
            .expect("a canonical body fits in u64")
            .to_be_bytes(),
    );
    out.extend_from_slice(canonical_body);
    out
}

/// A fully specified, non-cryptographic identity function used only by the
/// corpus.
///
/// It exists so the identity path can be exercised end to end before
/// `fgit-crypto` publishes its registry. It is **not** an identity function
/// for production use and carries no collision-resistance claim whatsoever:
/// what it proves here is that a body's identity depends on exactly the body's
/// domain, schema, and canonical bytes, and on nothing else.
pub struct CorpusIdentity;

impl CorpusIdentity {
    /// The two-pass folding used by the corpus.
    #[must_use]
    pub fn digest(&self, bytes: &[u8]) -> DigestBytes {
        let forward = fnv1a64(bytes).to_be_bytes();
        let reversed: Vec<u8> = bytes.iter().copied().rev().collect();
        let backward = fnv1a64(&reversed).to_be_bytes();
        let mut out = [0_u8; 16];
        out[..8].copy_from_slice(&forward);
        out[8..].copy_from_slice(&backward);
        DigestBytes::try_new(&out).expect("16 bytes is the minimum digest length")
    }
}

impl BodyIdentity for CorpusIdentity {
    fn identify(
        &self,
        domain: DomainTag,
        schema: SchemaId,
        canonical_body: &[u8],
    ) -> InternalObjectId {
        let preimage = identity_preimage(domain, schema, canonical_body);
        InternalObjectId::new(
            DigestAlgorithmId::try_new(CORPUS_ALGORITHM_CODE_POINT).expect("nonzero slot"),
            domain,
            CANONICAL_CODEC_VERSION,
            self.digest(&preimage),
        )
    }
}

// ------------------------------------------------------------------ generator

/// `SplitMix64`, so a sweep is identical on every machine and every run.
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value below `bound`, for picking indices.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let draw = usize::try_from(self.next_u64() % u64::MAX).unwrap_or(0);
        draw % bound
    }

    /// Fisher-Yates, so a shuffle is reproducible from the seed alone.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            let swap = self.below(index + 1);
            items.swap(index, swap);
        }
    }
}

// ------------------------------------------------------------------- fixtures

pub const ALGORITHM: u16 = 1;

pub fn algorithm() -> DigestAlgorithmId {
    DigestAlgorithmId::try_new(ALGORITHM).expect("nonzero slot")
}

/// A digest whose body is `length` copies of `fill`.
pub fn digest_of(fill: u8) -> Digest {
    Digest::new(
        algorithm(),
        DigestBytes::try_new(&[fill; 32]).expect("32 bytes is in range"),
    )
}

fn internal(domain: DomainTag, body: &[u8]) -> InternalObjectId {
    InternalObjectId::new(
        algorithm(),
        domain,
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(body).expect("digest body in range"),
    )
}

/// The transaction identity used throughout the corpus: digest body `00..1f`.
pub fn tx_id() -> TxId {
    let mut body = [0_u8; 32];
    for (index, slot) in body.iter_mut().enumerate() {
        *slot = u8::try_from(index).expect("index below 32");
    }
    TxId::from_internal_object_id(internal(TxId::DOMAIN_TAG, &body)).expect("own domain")
}

pub fn seal_id() -> TransactionSealId {
    TransactionSealId::from_internal_object_id(internal(TransactionSealId::DOMAIN_TAG, &[0x51; 32]))
        .expect("own domain")
}

pub fn commit_id() -> RepositoryCommitId {
    RepositoryCommitId::from_internal_object_id(internal(
        RepositoryCommitId::DOMAIN_TAG,
        &[0x52; 32],
    ))
    .expect("own domain")
}

pub fn batch_id() -> RepositoryDecisionBatchId {
    RepositoryDecisionBatchId::from_internal_object_id(internal(
        RepositoryDecisionBatchId::DOMAIN_TAG,
        &[0x53; 32],
    ))
    .expect("own domain")
}

pub fn head_id() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_internal_object_id(internal(
        RepositoryAuthorityHeadId::DOMAIN_TAG,
        &[0x54; 32],
    ))
    .expect("own domain")
}

pub fn refusal_record_id() -> RefusalRecordId {
    RefusalRecordId::from_internal_object_id(internal(RefusalRecordId::DOMAIN_TAG, &[0x55; 32]))
        .expect("own domain")
}

pub fn principal_snapshot_id() -> PrincipalSnapshotId {
    PrincipalSnapshotId::from_internal_object_id(internal(
        PrincipalSnapshotId::DOMAIN_TAG,
        &[0x56; 32],
    ))
    .expect("own domain")
}

pub fn capsule_id() -> RepositoryCapsuleId {
    RepositoryCapsuleId::from_internal_object_id(internal(
        RepositoryCapsuleId::DOMAIN_TAG,
        &[0x57; 32],
    ))
    .expect("own domain")
}

pub fn tenant_id() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

pub fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

pub fn principal_id() -> PrincipalId {
    PrincipalId::from_bytes([0x33; 16])
}

pub fn transaction_seal() -> TransactionSealBody {
    TransactionSealBody {
        tx_id: tx_id(),
        tenant_id: tenant_id(),
        repository_id: repository_id(),
        authenticated_principal_id: principal_id(),
        idempotency_key_digest: digest_of(0x44),
        canonical_request_digest: digest_of(0x55),
        request_schema: SchemaId::new(SchemaFamily::from_static("ref-txn"), 2, 0),
    }
}

pub fn commit_record() -> RepositoryCommitRecord {
    RepositoryCommitRecord {
        repository_id: repository_id(),
        repository_sequence: RepositorySequence::try_new(7).expect("nonzero"),
        parent_rcr_id: Some(commit_id()),
        tx_id: tx_id(),
        principal_snapshot_id: principal_snapshot_id(),
        canonical_request_digest: digest_of(0x60),
        ref_delta_root: digest_of(0x61),
        resulting_ref_root: digest_of(0x62),
        object_closure_root: digest_of(0x63),
        forge_event_batch_root: digest_of(0x64),
        resulting_forge_position_root: digest_of(0x65),
        policy_epoch: PolicyEpoch::try_new(3).expect("nonzero"),
        policy_decision_root: digest_of(0x66),
        invariant_evidence_root: digest_of(0x67),
        outbox_effect_root: digest_of(0x68),
        retention_delta_root: digest_of(0x69),
    }
}

pub fn decision_batch() -> RepositoryDecisionBatchBody {
    RepositoryDecisionBatchBody {
        repository_id: repository_id(),
        predecessor_head_id: head_id(),
        predecessor_head_generation: HeadGeneration::try_new(4).expect("nonzero"),
        first_decision_sequence: DecisionSequence::try_new(9).expect("nonzero"),
        decisions: vec![
            RepositoryDecision {
                tx_id: tx_id(),
                decision_sequence: DecisionSequence::try_new(9).expect("nonzero"),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: commit_id(),
                },
            },
            RepositoryDecision {
                tx_id: tx_id(),
                decision_sequence: DecisionSequence::try_new(10).expect("nonzero"),
                outcome: DecisionOutcome::Refused {
                    code: RefusalCode::ExpectedOldRefMismatch,
                    refusal_record_id: refusal_record_id(),
                },
            },
        ],
        committed_rcrs: vec![commit_record()],
        resulting_ref_root: digest_of(0x70),
        resulting_forge_position_root: digest_of(0x71),
        resulting_outcome_index_root: digest_of(0x72),
        resulting_retention_root: digest_of(0x73),
        resulting_outbox_root: digest_of(0x74),
        resulting_policy_epoch: PolicyEpoch::try_new(3).expect("nonzero"),
        batch_evidence_root: digest_of(0x75),
    }
}

pub fn genesis_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository_id(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest_of(0x80),
        forge_position_root: digest_of(0x81),
        outcome_index_root: digest_of(0x82),
        retention_root: digest_of(0x83),
        outbox_root: digest_of(0x84),
        configuration_root: digest_of(0x85),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

pub fn advanced_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository_id(),
        generation: HeadGeneration::try_new(5).expect("nonzero"),
        predecessor_head_id: Some(head_id()),
        decision_tail_id: Some(batch_id()),
        latest_decision_sequence: Some(DecisionSequence::try_new(10).expect("nonzero")),
        latest_committed_rcr_id: Some(commit_id()),
        latest_repository_sequence: Some(RepositorySequence::try_new(7).expect("nonzero")),
        ref_root: digest_of(0x80),
        forge_position_root: digest_of(0x81),
        outcome_index_root: digest_of(0x82),
        retention_root: digest_of(0x83),
        outbox_root: digest_of(0x84),
        configuration_root: digest_of(0x85),
        policy_epoch: PolicyEpoch::try_new(3).expect("nonzero"),
        format_registry_epoch: RegistryEpoch::try_new(2).expect("nonzero"),
        last_checkpoint_id: Some(capsule_id()),
    }
}

pub fn refusal_record() -> RefusalRecordBody {
    RefusalRecordBody {
        tx_id: tx_id(),
        seal_id: seal_id(),
        decision_sequence: DecisionSequence::try_new(10).expect("nonzero"),
        code: RefusalCode::ExpectedOldRefMismatch,
        policy_epoch: PolicyEpoch::try_new(3).expect("nonzero"),
        detail: "expected-old ref did not match the basis".to_owned(),
        evidence_root: digest_of(0x90),
    }
}

// -------------------------------------------------------------- golden files

/// One parsed golden case.
pub struct GoldenCase {
    pub name: String,
    pub schema: String,
    pub kind: String,
    pub mutation: Option<String>,
    pub expect: Option<String>,
    pub body_id: Option<String>,
    pub frame_len: Option<usize>,
    pub canonical_body_len: Option<usize>,
    pub bytes: Vec<u8>,
}

/// Reads every committed golden, sorted by file name so the order is stable.
///
/// The corpus is read from disk and never written by the suite. Regenerating
/// it is a deliberate act recorded in `docs/ADR-0002-CANONICAL-CODEC.md`, not
/// something a failing test can do for itself.
pub fn load_goldens() -> Vec<GoldenCase> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens");
    let mut paths: Vec<_> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "golden")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "the golden corpus is empty");
    paths.iter().map(|path| parse_golden(path)).collect()
}

fn parse_golden(path: &std::path::Path) -> GoldenCase {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut case = GoldenCase {
        name: path
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default()
            .to_owned(),
        schema: String::new(),
        kind: String::new(),
        mutation: None,
        expect: None,
        body_id: None,
        frame_len: None,
        canonical_body_len: None,
        bytes: Vec::new(),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{}: malformed line {line:?}", case.name));
        let value = value.trim();
        match key.trim() {
            "schema" => case.schema = value.to_owned(),
            "kind" => case.kind = value.to_owned(),
            "mutation" => case.mutation = Some(value.to_owned()),
            "expect" => case.expect = Some(value.to_owned()),
            "body_id" => case.body_id = Some(value.to_owned()),
            "frame_len" => {
                case.frame_len = Some(value.parse().expect("frame_len is a number"));
            }
            "canonical_body_len" => {
                case.canonical_body_len =
                    Some(value.parse().expect("canonical_body_len is a number"));
            }
            "bytes" => case.bytes = decode_hex(&case.name, value),
            other => panic!("{}: unknown golden key {other:?}", case.name),
        }
    }
    assert!(!case.schema.is_empty(), "{}: no schema", case.name);
    assert!(!case.bytes.is_empty(), "{}: no bytes", case.name);
    if let Some(expected) = case.frame_len {
        assert_eq!(
            case.bytes.len(),
            expected,
            "{}: frame_len disagrees with the byte string",
            case.name
        );
    }
    case
}

fn decode_hex(name: &str, text: &str) -> Vec<u8> {
    assert!(
        text.len() % 2 == 0,
        "{name}: hex string has an odd number of digits"
    );
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = nibble(name, pair[0]);
            let low = nibble(name, pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn nibble(name: &str, byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        other => panic!("{name}: {other:?} is not a lowercase hex digit"),
    }
}
