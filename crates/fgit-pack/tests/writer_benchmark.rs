#![forbid(unsafe_code)]
//! FG-017b: pack-writer benchmark producer, per plan §38.4.
//!
//! ## The hypothesis, stated before the measurement
//!
//! §38.4 requires a hypothesis and an expected mechanism, and the honest one
//! here is **not** "we are faster" or "we are smaller". It is:
//!
//! > The frozen `STORED_V1` profile emits **stored** DEFLATE blocks. It should
//! > therefore produce substantially *larger* packs than `git pack-objects`,
//! > and the gap should scale with how compressible the corpus is. Any other
//! > result — a size win, or a gap that does not track compressibility — means
//! > the profile is not doing what its documentation says.
//!
//! Recording a predicted loss up front is what keeps this from becoming a
//! benchmark that goes looking for a number to celebrate. The bead asks for
//! negative results to be "constitutionally durable, not embarrassing", and a
//! deliberate design trade-off is exactly that: the size gap is the price
//! `STORED_V1` pays for auditability, and this artifact is the baseline a later
//! compressing profile has to beat.
//!
//! ## What this file does and does not do
//!
//! It is a **producer**, like `writer_roundtrip.rs`: it measures our own writer
//! and emits raw samples, and it never invokes Git.
//! `scripts/e2e/suites/pack/pack_writer_benchmark.sh` runs `git pack-objects`
//! over the *same object set* through the pinned sandboxed oracle and joins the
//! two sides. Comparing against a Git we invoked ourselves from inside a Rust
//! target would violate AGENTS.md §3.1.
//!
//! ## The A/A control
//!
//! §38.4 requires one, and it is the part most benchmarks skip. Two *identical*
//! configurations of our own writer are measured as though they were different
//! arms. Any apparent difference between them is pure measurement noise, so it
//! is the floor below which a candidate-versus-baseline difference means
//! nothing. A run whose A/A spread exceeds its A/B spread has measured its own
//! jitter and is reported as inconclusive rather than as a result.
//!
//! ## Non-claims
//!
//! * These are **microbenchmarks of one component**. §38.4 is explicit that a
//!   microbenchmark win cannot justify an end-to-end claim, and nothing here is
//!   offered as one.
//! * Wall-clock only. This producer does not measure CPU time, RSS, or cache
//!   state; the suite records the environment, and the absence of those
//!   dimensions is stated rather than papered over.
//! * The corpora are small and synthetic. They are chosen to exercise distinct
//!   compressibility regimes, not to represent any real repository's workload.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use fgit_git_object::{ObjectType, Sha1, native_object_oid};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackLimits, PackPlan,
    PackPlanner, PackWriteError, PackWriteProfile, PackWriter,
};

/// Where the benchmark lane asks for samples and object bodies.
const ARTIFACT_ENV: &str = "FGIT_PACK_BENCH_ARTIFACT_DIR";

/// Iterations per arm. Small enough to keep the lane in seconds, large enough
/// that the A/A control has something to average.
const ITERATIONS: usize = 25;

/// Samples discarded before measurement, so the first allocation and any lazy
/// initialization are not counted as steady-state work.
const WARMUP: usize = 10;

// ---------------------------------------------------------------------------
// Corpora, chosen to span compressibility regimes
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct BenchObject {
    id: ObjectId,
    object_type: ObjectType,
    body: Vec<u8>,
    references: Vec<ObjectId>,
}

#[derive(Clone, Debug)]
struct BenchCorpus {
    /// Stable name, used to join the two sides of the comparison.
    name: &'static str,
    /// Why this corpus is in the set, recorded in the artifact so a reader
    /// knows what regime each number describes.
    regime: &'static str,
    objects: Vec<BenchObject>,
    roots: Vec<ObjectId>,
}

struct BenchSource {
    objects: BTreeMap<ObjectId, (BenchObject, u64)>,
}

impl BenchSource {
    fn new(corpus: &BenchCorpus) -> Self {
        let mut objects = BTreeMap::new();
        for (index, object) in corpus.objects.iter().enumerate() {
            objects.insert(
                object.id,
                (object.clone(), u64::try_from(index).unwrap_or(u64::MAX)),
            );
        }
        Self { objects }
    }
}

impl CanonicalObjectSource for BenchSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let (object, recency) = self
            .objects
            .get(id)
            .unwrap_or_else(|| panic!("benchmark corpus is missing {id:?}"));
        Ok(CanonicalPackObject::new(
            object.id,
            object.object_type,
            object.body.clone(),
            object.references.clone(),
            *recency,
            stable_spread(&object.body),
        ))
    }
}

/// Deterministic, non-cryptographic spread. Not a digest; feeds only the
/// frozen profile's grouping heuristic.
fn stable_spread(body: &[u8]) -> u64 {
    let mut accumulator = 0xcbf2_9ce4_8422_2325_u64;
    for byte in body {
        accumulator ^= u64::from(*byte);
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    }
    accumulator
}

fn blob(content: Vec<u8>) -> BenchObject {
    let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &content));
    BenchObject {
        id,
        object_type: ObjectType::Blob,
        body: content,
        references: Vec::new(),
    }
}

fn tree(entries: &[(&str, String, ObjectId)]) -> BenchObject {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|left, right| left.1.cmp(&right.1));
    let mut body = Vec::new();
    let mut references = Vec::new();
    for (mode, name, id) in &sorted {
        body.extend_from_slice(mode.as_bytes());
        body.push(b' ');
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(&raw_oid(*id));
        references.push(*id);
    }
    let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Tree, &body));
    BenchObject {
        id,
        object_type: ObjectType::Tree,
        body,
        references,
    }
}

fn raw_oid(id: ObjectId) -> Vec<u8> {
    match id {
        ObjectId::Sha1(oid) => oid.as_bytes().to_vec(),
        ObjectId::Sha256(oid) => oid.as_bytes().to_vec(),
    }
}

fn hex_oid(id: ObjectId) -> String {
    raw_oid(id).iter().map(|b| format!("{b:02x}")).collect()
}

/// Highly compressible: long runs, which DEFLATE crushes and stored blocks do
/// not. This is where the predicted loss should be largest.
fn corpus_compressible() -> BenchCorpus {
    let mut objects = Vec::new();
    let mut entries = Vec::new();
    for index in 0..24_u32 {
        let body = vec![b'a' + u8::try_from(index % 26).unwrap_or(0); 8192];
        let object = blob(body);
        entries.push(("100644", format!("run{index:03}.txt"), object.id));
        objects.push(object);
    }
    let root = tree(&entries);
    let roots = vec![root.id];
    objects.push(root);
    BenchCorpus {
        name: "compressible",
        regime: "long byte runs; maximally favourable to DEFLATE, maximally unfavourable to stored blocks",
        objects,
        roots,
    }
}

/// Poorly compressible: deterministic pseudo-random bytes. DEFLATE can do
/// little, so the gap should narrow sharply. If it does not, the size gap is
/// not actually explained by compression.
fn corpus_incompressible() -> BenchCorpus {
    let mut objects = Vec::new();
    let mut entries = Vec::new();
    for index in 0..24_u32 {
        let mut state = 0x2545_f491_4f6c_dd1d_u64 ^ u64::from(index);
        let mut body = Vec::with_capacity(8192);
        for _ in 0..8192 {
            // xorshift64*, fixed seed: deterministic across runs and platforms.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            body.push(u8::try_from(state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56).unwrap_or(0));
        }
        let object = blob(body);
        entries.push(("100644", format!("noise{index:03}.bin"), object.id));
        objects.push(object);
    }
    let root = tree(&entries);
    let roots = vec![root.id];
    objects.push(root);
    BenchCorpus {
        name: "incompressible",
        regime: "deterministic pseudo-random bytes; DEFLATE has little to remove, so the size gap should narrow",
        objects,
        roots,
    }
}

/// Many near-identical objects: the regime deltas are for.
fn corpus_similar() -> BenchCorpus {
    let mut objects = Vec::new();
    let mut entries = Vec::new();
    let base: String = (0..200)
        .map(|line| format!("line {line} of a shared document body\n"))
        .collect();
    for index in 0..24_u32 {
        let mut body = base.clone();
        body.push_str(&format!("revision {index}\n"));
        let object = blob(body.into_bytes());
        entries.push(("100644", format!("rev{index:03}.txt"), object.id));
        objects.push(object);
    }
    let root = tree(&entries);
    let roots = vec![root.id];
    objects.push(root);
    BenchCorpus {
        name: "similar",
        regime: "near-identical revisions; the regime delta compression exists for",
        objects,
        roots,
    }
}

fn commit(tree_id: ObjectId, parents: &[ObjectId], message: &str) -> BenchObject {
    let mut body = Vec::new();
    body.extend_from_slice(b"tree ");
    body.extend_from_slice(hex_oid(tree_id).as_bytes());
    body.push(b'\n');
    let mut references = vec![tree_id];
    for parent in parents {
        body.extend_from_slice(b"parent ");
        body.extend_from_slice(hex_oid(*parent).as_bytes());
        body.push(b'\n');
        references.push(*parent);
    }
    // Fixed timestamp: a clock would make pack bytes differ between runs and
    // make every size number here unreproducible.
    body.extend_from_slice(b"author FrankenGit Bench <bench@invalid.example> 1700000000 +0000\n");
    body.extend_from_slice(
        b"committer FrankenGit Bench <bench@invalid.example> 1700000000 +0000\n",
    );
    body.push(b'\n');
    body.extend_from_slice(message.as_bytes());
    body.push(b'\n');
    let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Commit, &body));
    BenchObject {
        id,
        object_type: ObjectType::Commit,
        body,
        references,
    }
}

/// A real commit history, which the other three corpora are not.
///
/// The bead asks for "representative histories", and blobs under one tree are
/// not a history: they exercise no commit or parent-chain packing at all.
/// TurquoiseDog, who owns the writer, recommended this shape directly. Twelve
/// revisions of a file plus a stable subdirectory, each with its own tree and
/// commit, so the pack carries commits, multiple trees, and successive blob
/// revisions the way a real fetch would.
fn corpus_history() -> BenchCorpus {
    let mut objects = Vec::new();
    let nested = blob(b"stable nested content\n".to_vec());
    let sub = tree(&[("100644", "nested.txt".to_owned(), nested.id)]);
    objects.push(nested.clone());
    objects.push(sub.clone());

    let mut parents: Vec<ObjectId> = Vec::new();
    let mut head = None;
    for revision in 0..12_u32 {
        let mut content = String::new();
        for line in 0..120 {
            content.push_str(&format!("document line {line}\n"));
        }
        content.push_str(&format!("revision {revision}\n"));
        let file = blob(content.into_bytes());
        let root = tree(&[
            ("100644", "file.txt".to_owned(), file.id),
            ("40000", "sub".to_owned(), sub.id),
        ]);
        let point = commit(root.id, &parents, &format!("revision {revision}"));
        parents = vec![point.id];
        head = Some(point.id);
        objects.push(file);
        objects.push(root);
        objects.push(point);
    }

    BenchCorpus {
        name: "history",
        regime: "a real twelve-commit history: commits, per-revision trees, a stable subdirectory, and successive blob revisions",
        objects,
        roots: vec![head.expect("the history has at least one commit")],
    }
}

fn all_corpora() -> Vec<BenchCorpus> {
    vec![
        corpus_compressible(),
        corpus_incompressible(),
        corpus_similar(),
        corpus_history(),
    ]
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

fn limits() -> PackLimits {
    PackLimits::default()
}

fn plan_for(corpus: &BenchCorpus) -> PackPlan {
    let planner = PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits());
    let source = BenchSource::new(corpus);
    let mut deadline = || true;
    planner
        .plan(&source, &corpus.roots, &mut deadline)
        .unwrap_or_else(|error| panic!("planning {} failed: {error:?}", corpus.name))
}

/// One arm: plan and write `ITERATIONS` times, returning nanosecond samples and
/// the (invariant) output size.
fn measure(corpus: &BenchCorpus) -> (Vec<u128>, usize) {
    let writer = PackWriter::new(limits());
    let mut samples = Vec::with_capacity(ITERATIONS);
    let mut output_bytes = 0_usize;

    for iteration in 0..(ITERATIONS + WARMUP) {
        let plan = plan_for(corpus);
        let started = Instant::now();
        let mut deadline = || true;
        let (bytes, _) = writer
            .write(&plan, &mut deadline)
            .unwrap_or_else(|error| panic!("writing {} failed: {error:?}", corpus.name));
        let elapsed = started.elapsed().as_nanos();
        if iteration >= WARMUP {
            samples.push(elapsed);
            if output_bytes == 0 {
                output_bytes = bytes.len();
            } else {
                assert_eq!(
                    output_bytes,
                    bytes.len(),
                    "{}: pack size varied between iterations, so no size number here is meaningful",
                    corpus.name
                );
            }
        }
    }
    (samples, output_bytes)
}

fn percentile(sorted: &[u128], fraction: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    // Nearest-rank. Stated explicitly because percentile definitions differ and
    // an unstated one makes numbers incomparable between runs.
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "rank selection over at most a few hundred samples; precision \
                  loss cannot change the selected index at this scale"
    )]
    let rank = ((sorted.len() as f64) * fraction).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

fn summarize(name: &str, samples: &[u128]) -> String {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let total: u128 = sorted.iter().sum();
    let mean = total / u128::try_from(sorted.len().max(1)).unwrap_or(1);
    format!(
        "\"{name}_min_ns\":{},\"{name}_p50_ns\":{},\"{name}_p95_ns\":{},\"{name}_max_ns\":{},\"{name}_mean_ns\":{}",
        sorted.first().copied().unwrap_or(0),
        percentile(&sorted, 0.50),
        percentile(&sorted, 0.95),
        sorted.last().copied().unwrap_or(0),
        mean
    )
}

/// Emits raw samples, summaries, an A/A control, and the object bodies the
/// suite needs to build an equivalent Git repository.
#[test]
#[ignore = "producer for scripts/e2e/suites/pack/pack_writer_benchmark.sh"]
fn emit_benchmark_samples_and_inputs() {
    let directory = env::var_os(ARTIFACT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{ARTIFACT_ENV} must name a writable artifact directory"));
    fs::create_dir_all(&directory)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", directory.display()));

    // PROCESS-LEVEL WARMUP. Per-arm warmup is not enough: the first corpus
    // measured in the process pays one-time allocator growth and page-fault
    // costs that a later corpus does not, which showed up as arm A reading 75ms
    // against an identical arm A-prime at 10ms. Touching every corpus once
    // before any measurement moves that cost outside the measured region. The
    // A/A control below stays regardless, because on a shared machine
    // contention can dominate at any time and the lane must say so rather than
    // report the number anyway.
    for corpus in all_corpora() {
        let plan = plan_for(&corpus);
        let writer = PackWriter::new(limits());
        let mut deadline = || true;
        let _ = writer.write(&plan, &mut deadline);
    }

    let mut records = String::new();
    let mut raw = String::new();

    for corpus in all_corpora() {
        // Arm A and arm A-prime are the SAME configuration. Their difference is
        // the measurement floor.
        let (samples_a, size_a) = measure(&corpus);
        let (samples_a_prime, size_a_prime) = measure(&corpus);
        assert_eq!(
            size_a, size_a_prime,
            "{}: two identical arms produced different pack sizes",
            corpus.name
        );

        let mut sorted_a = samples_a.clone();
        sorted_a.sort_unstable();
        let mut sorted_prime = samples_a_prime.clone();
        sorted_prime.sort_unstable();
        let p50_a = percentile(&sorted_a, 0.50);
        let p50_prime = percentile(&sorted_prime, 0.50);
        let aa_spread = p50_a.abs_diff(p50_prime);

        // Uncompressed source size, so the suite can report a ratio rather than
        // only an absolute byte count.
        let source_bytes: usize = corpus.objects.iter().map(|object| object.body.len()).sum();

        records.push_str(&format!(
            "{{\"schema\":\"frankengit.pack-writer-benchmark.v1\",\"corpus\":\"{}\",\"regime\":\"{}\",\
             \"profile\":\"{}\",\"iterations\":{},\"warmup\":{},\"objects\":{},\"source_bytes\":{},\
             \"fgit_pack_bytes\":{},{},{},\"aa_control_p50_delta_ns\":{}}}\n",
            corpus.name,
            corpus.regime,
            PackWriteProfile::STORED_V1.id,
            ITERATIONS,
            WARMUP,
            corpus.objects.len(),
            source_bytes,
            size_a,
            summarize("fgit_a", &samples_a),
            summarize("fgit_a_prime", &samples_a_prime),
            aa_spread
        ));

        // Raw samples, because §38.4 requires them and a summary alone cannot
        // be re-analysed by anyone who doubts the summary.
        for (index, sample) in samples_a.iter().enumerate() {
            raw.push_str(&format!(
                "{{\"corpus\":\"{}\",\"arm\":\"a\",\"iteration\":{index},\"ns\":{sample}}}\n",
                corpus.name
            ));
        }
        for (index, sample) in samples_a_prime.iter().enumerate() {
            raw.push_str(&format!(
                "{{\"corpus\":\"{}\",\"arm\":\"a_prime\",\"iteration\":{index},\"ns\":{sample}}}\n",
                corpus.name
            ));
        }

        // The object bodies, so the suite can load the SAME object set into a
        // real repository. Comparing our pack of one object set against Git's
        // pack of a different one would be meaningless.
        let bodies = directory.join(format!("{}-objects", corpus.name));
        fs::create_dir_all(&bodies)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", bodies.display()));
        let mut index_lines = String::new();
        for object in &corpus.objects {
            let kind = match object.object_type {
                ObjectType::Blob => "blob",
                ObjectType::Tree => "tree",
                ObjectType::Commit => "commit",
                ObjectType::Tag => "tag",
            };
            let file = bodies.join(hex_oid(object.id));
            fs::write(&file, &object.body)
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", file.display()));
            index_lines.push_str(&format!("{}\t{}\n", kind, hex_oid(object.id)));
        }
        let index_path = directory.join(format!("{}-objects.tsv", corpus.name));
        fs::write(&index_path, index_lines)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", index_path.display()));

        println!(
            "corpus={} objects={} source_bytes={} fgit_pack_bytes={} aa_p50_delta_ns={}",
            corpus.name,
            corpus.objects.len(),
            source_bytes,
            size_a,
            aa_spread
        );
    }

    let summary_path = directory.join("fgit-samples.ndjson");
    fs::write(&summary_path, records)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", summary_path.display()));
    let raw_path = directory.join("fgit-raw-samples.ndjson");
    fs::write(&raw_path, raw)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", raw_path.display()));
}
