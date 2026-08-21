#![forbid(unsafe_code)]
//! FG-020b independent adversarial corpus for the public microsegment surface.
//!
//! These tests deliberately frame attacks against the bytes accepted by
//! `MicrosegmentReader`; they do not reach into object-fabric implementation
//! state.  The accompanying TSV is a bounded benchmark artifact, not a claim
//! about compressed or delta-packed production repositories.

use std::{
    collections::BTreeMap,
    env, fs,
    path::PathBuf,
    sync::atomic::{AtomicU8, Ordering},
};

use fgit_benchmark::{
    BenchmarkArtifact, BenchmarkPlan, BenchmarkRunner, BenchmarkWorkload, EnvironmentFingerprint,
    MIN_SAMPLES_PER_VARIANT, OptimizationAdmission, OracleReceipt, StorageClasses, SystemMetrics,
    WorkloadDescriptor,
};
use fgit_object_fabric::{
    Commitment, CryptoDigest, CryptoDigestState, DigestAlgorithm, DigestDomain, FabricError,
    Microsegment, MicrosegmentBuilder, MicrosegmentReader, ObjectEnvelope, ObjectKind,
    SegmentLimits, SegmentRecordInput,
};
use fgit_types::{GitOid, GitOidSha1};

// V1's footer is fixed-width.  Keeping the value in this public-API corpus
// makes the splice attack an independently framed wire fixture rather than an
// implementation-private helper.
const V1_FOOTER_BYTES: usize = 92;
const ECONOMICS_TSV: &str = include_str!("corpus/microsegment_economics_v1.tsv");

fn limits() -> SegmentLimits {
    SegmentLimits::default()
}

fn oid(identity: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([identity; GitOidSha1::LEN]))
}

fn record_for<H: DigestAlgorithm>(
    hasher: &H,
    namespace: &[u8],
    identity: u8,
    payload: Vec<u8>,
    segment_limits: &SegmentLimits,
) -> SegmentRecordInput {
    let payload_commitment = hasher
        .payload_commitment(ObjectKind::Blob, &payload)
        .expect("fixture payload commitment must be available");
    let envelope = ObjectEnvelope::new(
        namespace.to_vec(),
        oid(identity),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("fixture payload length must fit u64"),
        payload_commitment,
        b"raw".to_vec(),
        [identity; 32],
        None,
        segment_limits,
    )
    .expect("fixture envelope must be valid");
    SegmentRecordInput { envelope, payload }
}

fn build_segment<H: DigestAlgorithm>(
    hasher: &H,
    namespace: &[u8],
    records: &[(u8, &[u8])],
    segment_limits: &SegmentLimits,
) -> Microsegment {
    let mut builder = MicrosegmentBuilder::new(hasher, segment_limits.clone());
    for (identity, payload) in records {
        builder
            .push(record_for(
                hasher,
                namespace,
                *identity,
                (*payload).to_vec(),
                segment_limits,
            ))
            .expect("ordered fixture record must build");
    }
    builder.build().expect("fixture segment must build")
}

fn read_u32(bytes: &[u8], offset: usize) -> usize {
    usize::try_from(u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixture offset must contain a u32"),
    ))
    .expect("V1 u32 must fit usize")
}

fn record_offsets(bytes: &[u8], namespace_len: usize, record_count: usize) -> Vec<usize> {
    let mut offset = 4 + 2 + 2 + namespace_len + 4;
    let mut offsets = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        offsets.push(offset);
        offset += 4 + read_u32(bytes, offset);
    }
    offsets
}

fn envelope_namespace_offset(record_offset: usize) -> usize {
    // record body length + envelope length + FGEN + version + namespace length
    record_offset + 4 + 4 + 4 + 2 + 2
}

fn envelope_sha1_offset(record_offset: usize, namespace_len: usize) -> usize {
    // record prefix, envelope header/namespace, then the two-byte OID algorithm.
    envelope_namespace_offset(record_offset) + namespace_len + 2
}

fn reader_refusal(bytes: &[u8], segment_limits: &SegmentLimits) -> FabricError {
    match MicrosegmentReader::open(bytes, &CryptoDigest, segment_limits) {
        Ok(_) => panic!("malformed fixture was accepted"),
        Err(error) => error,
    }
}

#[test]
fn every_truncated_v1_prefix_refuses_with_the_structural_error() {
    let segment_limits = limits();
    let segment = build_segment(
        &CryptoDigest,
        b"realm",
        &[(b'a', b"alpha"), (b'b', b"bravo")],
        &segment_limits,
    );
    let bytes = segment.as_bytes();
    let header_bytes = 4 + 2 + 2 + b"realm".len() + 4;

    for prefix_len in 0..bytes.len() {
        let actual = reader_refusal(&bytes[..prefix_len], &segment_limits);
        let expected = if prefix_len < V1_FOOTER_BYTES + header_bytes {
            FabricError::Truncated
        } else {
            // No prefix before the complete message can begin with the V1
            // footer magic at its final 92-byte window.
            FabricError::InvalidMagic
        };
        assert_eq!(
            actual, expected,
            "truncation at byte boundary {prefix_len} must not be accepted or reclassified"
        );
    }
}

#[test]
fn duplicate_and_mixed_namespace_smuggling_refuse_before_index_disclosure() {
    let segment_limits = limits();
    let digest = CryptoDigest;

    let mut duplicate_builder = MicrosegmentBuilder::new(&digest, segment_limits.clone());
    duplicate_builder
        .push(record_for(
            &digest,
            b"realm",
            b'a',
            b"alpha".to_vec(),
            &segment_limits,
        ))
        .expect("first record must build");
    assert_eq!(
        duplicate_builder.push(record_for(
            &digest,
            b"realm",
            b'a',
            b"alpha".to_vec(),
            &segment_limits,
        )),
        Err(FabricError::DuplicateObjectIdentity),
        "the builder must refuse duplicate identities"
    );

    let mut mixed_builder = MicrosegmentBuilder::new(&digest, segment_limits.clone());
    mixed_builder
        .push(record_for(
            &digest,
            b"realm",
            b'a',
            b"alpha".to_vec(),
            &segment_limits,
        ))
        .expect("first record must build");
    assert_eq!(
        mixed_builder.push(record_for(
            &digest,
            b"other",
            b'b',
            b"bravo".to_vec(),
            &segment_limits,
        )),
        Err(FabricError::MixedNamespace),
        "the builder must refuse a namespace smuggling attempt"
    );

    let canonical = build_segment(
        &digest,
        b"realm",
        &[(b'a', b"alpha"), (b'b', b"bravo")],
        &segment_limits,
    );
    let offsets = record_offsets(canonical.as_bytes(), b"realm".len(), 2);

    let mut duplicate_wire = canonical.as_bytes().to_vec();
    let first_oid = envelope_sha1_offset(offsets[0], b"realm".len());
    let second_oid = envelope_sha1_offset(offsets[1], b"realm".len());
    let first_identity = duplicate_wire[first_oid..first_oid + GitOidSha1::LEN].to_vec();
    duplicate_wire[second_oid..second_oid + GitOidSha1::LEN].copy_from_slice(&first_identity);
    assert_eq!(
        reader_refusal(&duplicate_wire, &segment_limits),
        FabricError::DuplicateObjectIdentity,
        "a duplicate identity spliced into the second record must refuse before index use"
    );

    let mut mixed_wire = canonical.as_bytes().to_vec();
    mixed_wire[envelope_namespace_offset(offsets[1])] = b'x';
    assert_eq!(
        reader_refusal(&mixed_wire, &segment_limits),
        FabricError::MixedNamespace,
        "a record envelope from another namespace must refuse before index use"
    );
}

#[test]
fn record_transplant_with_a_matching_index_cannot_relocate_under_the_old_merkle_root() {
    let segment_limits = limits();
    let digest = CryptoDigest;
    let original = build_segment(
        &digest,
        b"realm",
        &[(b'a', b"alpha"), (b'b', b"bravo")],
        &segment_limits,
    );
    let donor = build_segment(
        &digest,
        b"realm",
        &[(b'a', b"cider"), (b'b', b"delta")],
        &segment_limits,
    );
    assert_eq!(
        original.as_bytes().len(),
        donor.as_bytes().len(),
        "the attack requires equally sized records and indexes"
    );

    let mut transplanted = original.as_bytes().to_vec();
    let footer_start = transplanted.len() - V1_FOOTER_BYTES;
    // The attack transports the donor records and their matching index but
    // retains the original authenticated footer.  An index-only check would
    // accept this; the Merkle commitment must bind the records to the footer.
    transplanted[..footer_start].copy_from_slice(&donor.as_bytes()[..footer_start]);
    assert_eq!(
        reader_refusal(&transplanted, &segment_limits),
        FabricError::MerkleRootMismatch,
        "a transplanted record/index cannot relocate beneath another segment root"
    );

    let transcript = b"same record bytes in distinct commitment domains";
    assert_ne!(
        digest
            .digest(DigestDomain::MerkleLeaf, &[transcript])
            .expect("Merkle leaf domain must be registered"),
        digest
            .digest(DigestDomain::Segment, &[transcript])
            .expect("segment domain must be registered"),
        "Merkle leaves and segment bodies must not share a commitment domain"
    );
}

/// A deliberately stateful digest adapter models the historical class of bug
/// where a builder accidentally incorporates a process-local seed.  Payload
/// commitments remain correct so the detector reaches byte construction.
struct SeededBugDigest {
    next_mask: AtomicU8,
}

impl SeededBugDigest {
    const fn new(seed: u8) -> Self {
        Self {
            next_mask: AtomicU8::new(seed),
        }
    }
}

impl DigestAlgorithm for SeededBugDigest {
    type State = CryptoDigestState;

    fn begin(&self, domain: DigestDomain, content_len: usize) -> Result<Self::State, FabricError> {
        CryptoDigest.begin(domain, content_len)
    }

    fn update(&self, state: &mut Self::State, bytes: &[u8]) {
        CryptoDigest.update(state, bytes);
    }

    fn finish(&self, state: Self::State) -> Commitment {
        let mut commitment = CryptoDigest.finish(state);
        commitment[0] ^= self.next_mask.fetch_add(1, Ordering::Relaxed);
        commitment
    }

    fn payload_commitment(
        &self,
        object_kind: ObjectKind,
        payload: &[u8],
    ) -> Result<Commitment, FabricError> {
        CryptoDigest.payload_commitment(object_kind, payload)
    }
}

#[test]
fn deterministic_builder_is_byte_stable_and_the_seeded_bug_variant_is_detected() {
    let segment_limits = limits();
    let records = [(b'a', b"alpha".as_slice()), (b'b', b"bravo".as_slice())];
    let first = build_segment(&CryptoDigest, b"realm", &records, &segment_limits);
    let second = build_segment(&CryptoDigest, b"realm", &records, &segment_limits);
    assert_eq!(
        first.as_bytes(),
        second.as_bytes(),
        "identical ordered input must produce byte-identical canonical bytes"
    );

    let seeded = SeededBugDigest::new(0x5a);
    let buggy_first = build_segment(&seeded, b"realm", &records, &segment_limits);
    let buggy_second = build_segment(&seeded, b"realm", &records, &segment_limits);
    assert_ne!(
        buggy_first.as_bytes(),
        buggy_second.as_bytes(),
        "the corpus must expose a builder that incorporates a process-local seed"
    );
}

#[derive(Debug)]
struct EconomicsRow {
    corpus_id: &'static str,
    object_count: usize,
    payload_bytes_each: usize,
    microsegment_bytes: usize,
    loose_canonical_bytes: usize,
    pack_uncompressed_no_delta_bytes: usize,
    sequential_loose_requests: usize,
    sequential_microsegment_requests: usize,
    sequential_pack_requests: usize,
    random_four_loose_requests: usize,
    random_four_microsegment_requests: usize,
    random_four_pack_requests: usize,
}

#[derive(Clone, Copy)]
struct CorpusSpec {
    id: &'static str,
    object_count: usize,
    payload_bytes_each: usize,
}

const ECONOMICS_CORPORA: [CorpusSpec; 4] = [
    CorpusSpec {
        id: "monorepo-history-window-v1",
        object_count: 32,
        payload_bytes_each: 128,
    },
    CorpusSpec {
        id: "many-small-tenant-v1",
        object_count: 16,
        payload_bytes_each: 8,
    },
    CorpusSpec {
        id: "binary-heavy-replay-v1",
        object_count: 4,
        payload_bytes_each: 4096,
    },
    CorpusSpec {
        id: "agent-write-burst-v1",
        object_count: 8,
        payload_bytes_each: 32,
    },
];

fn decimal_digits(value: usize) -> usize {
    value.to_string().len()
}

fn pack_object_header_bytes(payload_bytes: usize) -> usize {
    let mut remaining = payload_bytes >> 4;
    let mut bytes = 1;
    while remaining != 0 {
        bytes += 1;
        remaining >>= 7;
    }
    bytes
}

fn measure_corpus(corpus: CorpusSpec) -> EconomicsRow {
    let segment_limits = limits();
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, segment_limits.clone());
    for index in 0..corpus.object_count {
        let identity = u8::try_from(index + 1).expect("corpus identity must fit in one byte");
        builder
            .push(record_for(
                &digest,
                b"economics-v1",
                identity,
                vec![identity; corpus.payload_bytes_each],
                &segment_limits,
            ))
            .expect("representative corpus record must build");
    }
    let microsegment = builder.build().expect("representative corpus must build");
    let loose_canonical_bytes = corpus.object_count
        * (6 + decimal_digits(corpus.payload_bytes_each) + corpus.payload_bytes_each);
    let pack_uncompressed_no_delta_bytes = 32
        + corpus.object_count
            * (pack_object_header_bytes(corpus.payload_bytes_each) + corpus.payload_bytes_each);
    let random_window = corpus.object_count.min(4);
    EconomicsRow {
        corpus_id: corpus.id,
        object_count: corpus.object_count,
        payload_bytes_each: corpus.payload_bytes_each,
        microsegment_bytes: microsegment.as_bytes().len(),
        loose_canonical_bytes,
        pack_uncompressed_no_delta_bytes,
        sequential_loose_requests: corpus.object_count,
        sequential_microsegment_requests: 1,
        sequential_pack_requests: 1,
        random_four_loose_requests: random_window,
        random_four_microsegment_requests: 1,
        random_four_pack_requests: 1,
    }
}

#[derive(Clone)]
enum EconomicsReadPath {
    Loose,
    Microsegment(Vec<u8>),
}

struct EconomicsWorkload {
    expected: Vec<(GitOid, Vec<u8>)>,
    read_path: EconomicsReadPath,
    segment_limits: SegmentLimits,
    metrics: SystemMetrics,
    corpus_id: &'static str,
}

impl BenchmarkWorkload for EconomicsWorkload {
    type Output = Vec<(GitOid, Vec<u8>)>;

    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
        let output = match &self.read_path {
            EconomicsReadPath::Loose => self.expected.clone(),
            EconomicsReadPath::Microsegment(bytes) => {
                let reader = MicrosegmentReader::open(bytes, &CryptoDigest, &self.segment_limits)
                    .map_err(|error| error.to_string())?;
                let mut records = Vec::with_capacity(reader.len());
                for index in 0..reader.len() {
                    let record = reader
                        .record(index)
                        .ok_or_else(|| format!("verified record {index} disappeared"))?;
                    records.push((record.envelope.object_identity(), record.payload.to_vec()));
                }
                records
            }
        };
        Ok((output, self.metrics))
    }

    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
        if output != &self.expected {
            return Err(format!(
                "{} ordered native identity/payload transcript differs from the baseline",
                self.corpus_id
            ));
        }
        Ok(OracleReceipt {
            receipt: format!(
                "fg020b-{}-ordered-oid-payload-transcript-{}",
                self.corpus_id,
                output.len()
            ),
        })
    }
}

fn workload_metrics(
    canonical_bytes: usize,
    logical_reachable_git_bytes: usize,
    object_requests: usize,
    object_request_bytes: usize,
) -> SystemMetrics {
    let canonical_bytes = u64::try_from(canonical_bytes).expect("fixture byte count must fit u64");
    let logical_reachable_git_bytes =
        u64::try_from(logical_reachable_git_bytes).expect("fixture byte count must fit u64");
    let object_requests =
        u64::try_from(object_requests).expect("fixture request count must fit u64");
    let object_request_bytes =
        u64::try_from(object_request_bytes).expect("fixture byte count must fit u64");
    SystemMetrics {
        // This bounded in-memory model uses exact bytes traversed as its
        // nonzero CPU-attribution work-unit proxy; it is explicitly not a
        // host CPU-time claim. BenchmarkRunner records observed wall latency.
        cpu_ns: object_request_bytes,
        memory_bytes: canonical_bytes,
        object_requests,
        object_request_bytes,
        egress_bytes: object_request_bytes,
        decisions: 1,
        cas_attempts: 1,
        storage: StorageClasses {
            canonical_bytes,
            repair_bytes: 0,
            replica_bytes: 0,
            retained_derived_bytes: 0,
            logical_reachable_git_bytes,
        },
        ..SystemMetrics::default()
    }
}

struct EconomicsFixture {
    expected: Vec<(GitOid, Vec<u8>)>,
    microsegment_bytes: Vec<u8>,
    row: EconomicsRow,
}

fn build_economics_fixture(corpus: CorpusSpec) -> EconomicsFixture {
    let segment_limits = limits();
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, segment_limits.clone());
    let mut expected = Vec::with_capacity(corpus.object_count);
    for index in 0..corpus.object_count {
        let identity = u8::try_from(index + 1).expect("corpus identity must fit in one byte");
        let payload = vec![identity; corpus.payload_bytes_each];
        expected.push((oid(identity), payload.clone()));
        builder
            .push(record_for(
                &digest,
                b"economics-v1",
                identity,
                payload,
                &segment_limits,
            ))
            .expect("representative corpus record must build");
    }
    let microsegment = builder.build().expect("representative corpus must build");
    EconomicsFixture {
        expected,
        microsegment_bytes: microsegment.as_bytes().to_vec(),
        row: measure_corpus(corpus),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate must be nested under the workspace root")
        .to_path_buf()
}

fn benchmark_plan(corpus: CorpusSpec) -> BenchmarkPlan {
    BenchmarkPlan {
        fingerprint: EnvironmentFingerprint::from_workspace(
            &workspace_root(),
            env::var("FGIT_MICROSEGMENT_SOURCE_REVISION")
                .unwrap_or_else(|_| "unbound-test-revision".to_owned()),
            env::var("FGIT_MICROSEGMENT_SOURCE_TREE")
                .unwrap_or_else(|_| "unbound-test-tree".to_owned()),
            "work-unit proxy: bytes traversed; not a host CPU-time claim",
            std::env::consts::ARCH,
            "test",
        )
        .expect("workspace fingerprint must be readable"),
        workload: WorkloadDescriptor {
            dataset: format!(
                "{}; namespace=economics-v1; SHA-1 OID bytes repeat 1..N; payload bytes repeat their OID value",
                corpus.id
            ),
            workload: "read each ordered object and compare the full native-identity/payload transcript"
                .to_owned(),
            thermal_state: "in-memory bytes; reader opens fresh on every sample".to_owned(),
            cache_state: "no external cache; cpu_ns is bytes-traversed work-unit attribution, not host CPU time"
                .to_owned(),
            commands: vec![
                "cargo test --locked -p fgit-object-fabric --test microsegment_adversarial economics_artifact_records_replayable_size_and_locality_models"
                    .to_owned(),
            ],
            environment_allowlist: BTreeMap::from([
                (
                    "FGIT_MICROSEGMENT_BENCHMARK_OUT".to_owned(),
                    env::var("FGIT_MICROSEGMENT_BENCHMARK_OUT")
                        .unwrap_or_else(|_| "temporary test artifact directory".to_owned()),
                ),
                (
                    "FGIT_MICROSEGMENT_SOURCE_REVISION".to_owned(),
                    env::var("FGIT_MICROSEGMENT_SOURCE_REVISION")
                        .unwrap_or_else(|_| "unbound-test-revision".to_owned()),
                ),
                (
                    "FGIT_MICROSEGMENT_SOURCE_TREE".to_owned(),
                    env::var("FGIT_MICROSEGMENT_SOURCE_TREE")
                        .unwrap_or_else(|_| "unbound-test-tree".to_owned()),
                ),
            ]),
        },
        admission: OptimizationAdmission {
            equivalence_obligation: "baseline and candidate must return the same ordered (native Git OID, payload bytes) sequence for every sample"
                .to_owned(),
            oracle_name: "FG-020b full ordered native-identity/payload transcript oracle"
                .to_owned(),
            replay_command: "FGIT_MICROSEGMENT_BENCHMARK_OUT=<empty-dir> FGIT_MICROSEGMENT_SOURCE_REVISION=<sha> FGIT_MICROSEGMENT_SOURCE_TREE=<tree-id> cargo test --locked -p fgit-object-fabric --test microsegment_adversarial economics_artifact_records_replayable_size_and_locality_models"
                .to_owned(),
            rollback_artifact: "remove only the FGIT_MICROSEGMENT_BENCHMARK_OUT directory; no canonical state is changed"
                .to_owned(),
            hypothesis: "one verified microsegment request may reduce object-store request count for a localized read window; this benchmark emits negative evidence unless observed p95 clears A/A noise"
                .to_owned(),
        },
        samples_per_variant: MIN_SAMPLES_PER_VARIANT,
    }
}

fn evidence_directory(corpus_id: &str) -> (PathBuf, bool) {
    match env::var_os("FGIT_MICROSEGMENT_BENCHMARK_OUT") {
        Some(root) => (PathBuf::from(root).join(corpus_id), false),
        None => (
            env::temp_dir().join(format!(
                "fg020b-microsegment-economics-{}-{}",
                std::process::id(),
                corpus_id
            )),
            true,
        ),
    }
}

fn benchmark_artifact(corpus: CorpusSpec) -> (BenchmarkArtifact, bool, PathBuf) {
    let fixture = build_economics_fixture(corpus);
    let mut baseline = EconomicsWorkload {
        expected: fixture.expected.clone(),
        read_path: EconomicsReadPath::Loose,
        segment_limits: limits(),
        metrics: workload_metrics(
            fixture.row.loose_canonical_bytes,
            fixture.row.loose_canonical_bytes,
            fixture.row.sequential_loose_requests,
            fixture.row.loose_canonical_bytes,
        ),
        corpus_id: corpus.id,
    };
    let mut candidate = EconomicsWorkload {
        expected: fixture.expected,
        read_path: EconomicsReadPath::Microsegment(fixture.microsegment_bytes),
        segment_limits: limits(),
        metrics: workload_metrics(
            fixture.row.microsegment_bytes,
            fixture.row.loose_canonical_bytes,
            fixture.row.sequential_microsegment_requests,
            fixture.row.microsegment_bytes,
        ),
        corpus_id: corpus.id,
    };
    let artifact = BenchmarkRunner::new(benchmark_plan(corpus))
        .expect("complete benchmark plan must be accepted")
        .run(&mut baseline, &mut candidate)
        .expect("every baseline, candidate, and A/A sample must satisfy the transcript oracle");
    let (directory, temporary) = evidence_directory(corpus.id);
    if temporary {
        let _ = fs::remove_dir_all(&directory);
    }
    artifact
        .write_to(&directory)
        .expect("complete raw benchmark evidence, replay, and rollback recipe must be written");
    (artifact, temporary, directory)
}

#[test]
fn economics_artifact_records_replayable_size_and_locality_models() {
    let rows = ECONOMICS_CORPORA.map(measure_corpus);
    let mut actual = String::from(
        "# FG-020b benchmark evidence v1; measured canonical microsegment bytes and explicit request-count models.\n# Non-claim: loose and pack columns are uncompressed/no-delta framing baselines, not an end-to-end storage or latency result.\n# corpus_id uniquely binds deterministic fixture generation: namespace=economics-v1; SHA-1 OID bytes repeat 1..N; blob payload byte repeats its OID value.\ncorpus_id\tobject_count\tpayload_bytes_each\tmicrosegment_bytes\tloose_canonical_bytes\tpack_uncompressed_no_delta_bytes\tsequential_loose_requests\tsequential_microsegment_requests\tsequential_pack_requests\trandom_four_loose_requests\trandom_four_microsegment_requests\trandom_four_pack_requests\tclaim_class\n",
    );
    for row in rows {
        actual.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\tbenchmark\n",
            row.corpus_id,
            row.object_count,
            row.payload_bytes_each,
            row.microsegment_bytes,
            row.loose_canonical_bytes,
            row.pack_uncompressed_no_delta_bytes,
            row.sequential_loose_requests,
            row.sequential_microsegment_requests,
            row.sequential_pack_requests,
            row.random_four_loose_requests,
            row.random_four_microsegment_requests,
            row.random_four_pack_requests,
        ));
    }
    assert_eq!(
        ECONOMICS_TSV, actual,
        "the checked-in benchmark artifact must match the public builder's exact bytes and the stated request model"
    );

    for corpus in ECONOMICS_CORPORA {
        let (artifact, temporary, directory) = benchmark_artifact(corpus);
        assert_eq!(artifact.baseline.len(), MIN_SAMPLES_PER_VARIANT);
        assert_eq!(artifact.candidate.len(), MIN_SAMPLES_PER_VARIANT);
        assert_eq!(artifact.aa_control.len(), MIN_SAMPLES_PER_VARIANT);
        assert!(
            artifact
                .baseline
                .iter()
                .chain(&artifact.candidate)
                .chain(&artifact.aa_control)
                .all(|sample| sample.oracle.receipt.contains(corpus.id)),
            "every raw observation must carry its independent transcript-oracle receipt"
        );
        assert!(artifact.to_ndjson().contains("\"p95_ns\""));
        assert!(artifact.to_ndjson().contains("\"p99_ns\""));
        assert!(artifact.to_ndjson().contains("\"object_requests\""));
        assert!(artifact.to_ndjson().contains("\"amplification_ppm\""));
        assert!(directory.join("benchmark.ndjson").is_file());
        assert!(directory.join("replay-and-rollback.txt").is_file());
        if temporary {
            fs::remove_dir_all(&directory).expect("test-owned temporary evidence must clean up");
        }
    }
}
