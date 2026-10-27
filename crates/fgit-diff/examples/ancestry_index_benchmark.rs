#![forbid(unsafe_code)]
//! x2mv.4.36: source-labelled ancestry microbenchmark, not transport evidence.
//!
//! Run a release build with --help for the required provenance environment.
//! Every measured result is checked against the known synthetic graph answer.
//! The retained scalar implementation is the merge-base baseline. Fast-forward
//! uses an independent exact parent walk without generations. Both operate on
//! in-memory synthetic 256-bit IDs, so timings exclude Git parsing and I/O.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::hint::black_box;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

use fgit_diff::{
    AncestryQueryScratch, AncestryQueryWork, CommitAncestryIndex, CommitGraph, MergeBaseLimits,
    MergeBaseResult, ParentSet, merge_bases_all,
};

type CommitId = [u8; 32];

const SCHEMA: &str = "frankengit.ancestry-index.microbenchmark.v1";
const USAGE: &str = "\
Usage: ancestry_index_benchmark [--commits 100000..1000000] [--samples 3..31]
                                [--mode chain|merge-heavy|all]

Required environment (labels must describe the measured binary):
  FGIT_ANCESTRY_SOURCE_REVISION    exact source commit
  FGIT_ANCESTRY_SOURCE_TREE        exact source tree/diff identity, including dirtiness
  FGIT_ANCESTRY_LOCK_SHA256        SHA-256 of the build's Cargo.lock
  FGIT_ANCESTRY_TOOLCHAIN          exact rustc -Vv identity
  FGIT_ANCESTRY_TARGET             target triple
  FGIT_ANCESTRY_PROFILE            selected Cargo profile
  FGIT_ANCESTRY_CPU                measured CPU/host description

Stdout is NDJSON: provenance, index setup, every raw timing, and summaries.
Each sample measures baseline, fresh index plus query, reused index query, and
an identical second baseline (A-A). Every result is checked outside the timer.
Inputs are in-memory synthetic 256-bit IDs and parent adjacency. Git object
parsing, network, storage I/O, native fast-forward publication, and process
startup are excluded. This does not establish end-to-end product speedup.
The ancestry baseline validates endpoints and walked parents; fresh indexes
validate the complete closure before querying. Reused indexes were validated
in setup. Merge-base scalar and candidate both validate the complete closure.
An absent terminal record means the campaign did not finish successfully.
";

struct Options {
    commits: usize,
    samples: usize,
    mode: String,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        for pair in args.chunks(2) {
            if pair.len() != 2
                || !matches!(pair[0].as_str(), "--commits" | "--samples" | "--mode")
                || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err(USAGE.into());
            }
        }
        let commits = values
            .get("--commits")
            .copied()
            .unwrap_or("100000")
            .parse::<usize>()
            .map_err(|_| "invalid --commits")?;
        let samples = values
            .get("--samples")
            .copied()
            .unwrap_or("7")
            .parse::<usize>()
            .map_err(|_| "invalid --samples")?;
        let mode = values.get("--mode").copied().unwrap_or("all").to_owned();
        if !(100_000..=1_000_000).contains(&commits)
            || !(3..=31).contains(&samples)
            || !matches!(mode.as_str(), "chain" | "merge-heavy" | "all")
        {
            return Err(USAGE.into());
        }
        Ok(Self {
            commits,
            samples,
            mode,
        })
    }
}

fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            value if value < '\u{0020}' => {
                use std::fmt::Write as _;
                write!(out, "\\u{:04x}", u32::from(value)).expect("writing a String cannot fail");
            }
            value => out.push(value),
        }
    }
    out.push('"');
    out
}

fn fingerprint() -> Result<String, String> {
    let mut fields = Vec::new();
    for (field, variable) in [
        ("source_revision", "FGIT_ANCESTRY_SOURCE_REVISION"),
        ("source_tree", "FGIT_ANCESTRY_SOURCE_TREE"),
        ("cargo_lock_sha256", "FGIT_ANCESTRY_LOCK_SHA256"),
        ("toolchain", "FGIT_ANCESTRY_TOOLCHAIN"),
        ("target", "FGIT_ANCESTRY_TARGET"),
        ("build_profile", "FGIT_ANCESTRY_PROFILE"),
        ("cpu", "FGIT_ANCESTRY_CPU"),
    ] {
        let value = env::var(variable).map_err(|_| format!("missing {variable}"))?;
        if value.trim().is_empty() || value.len() > 16_384 {
            return Err(format!(
                "{variable} must be nonempty and at most 16384 bytes"
            ));
        }
        fields.push(format!("{}:{}", quoted(field), quoted(&value)));
    }
    fields.push(format!("\"os\":{}", quoted(env::consts::OS)));
    fields.push(format!("\"architecture\":{}", quoted(env::consts::ARCH)));
    fields.push(format!("\"debug_assertions\":{}", cfg!(debug_assertions)));
    Ok(format!("{{{}}}", fields.join(",")))
}

// Opaque reproducible IDs. These are not hashes of native Git commit objects.
fn identity(index: usize) -> CommitId {
    let value = u64::try_from(index).expect("bounded graph ordinal");
    let mut identity = [0_u8; 32];
    let mut state = value ^ 0x7862_6d76_3436_0002;
    for chunk in identity.as_chunks_mut::<8>().0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_be_bytes());
    }
    // Preserve injectivity independently of the deterministic mixer.
    identity[24..].copy_from_slice(&value.to_be_bytes());
    identity
}

struct Graph {
    rows: BTreeMap<CommitId, Vec<CommitId>>,
    reads: Cell<usize>,
}

impl Graph {
    fn new(count: usize, merge_heavy: bool) -> Self {
        let mut rows = BTreeMap::new();
        for ordinal in 0..count {
            let mut parents = if ordinal == 0 {
                Vec::new()
            } else {
                vec![ordinal - 1]
            };
            if merge_heavy {
                if ordinal < count - 5 {
                    if ordinal > 17 && ordinal % 17 == 0 {
                        parents.push(ordinal - 17);
                    }
                    if ordinal > 53 && ordinal % 53 == 0 {
                        parents.push(ordinal - 53);
                    }
                } else if ordinal < count - 2 {
                    parents = vec![count - 6];
                } else {
                    parents = vec![count - 5, count - 4, count - 3];
                    if ordinal == count - 1 {
                        parents.reverse();
                    }
                }
            }
            rows.insert(
                identity(ordinal),
                parents.into_iter().map(identity).collect(),
            );
        }
        Self {
            rows,
            reads: Cell::new(0),
        }
    }

    fn reset_reads(&self) {
        self.reads.set(0);
    }
}

impl CommitGraph for Graph {
    type CommitId = CommitId;
    type Error = &'static str;

    fn parents_of(&self, commit: &CommitId) -> Result<ParentSet<CommitId>, Self::Error> {
        self.reads.set(self.reads.get() + 1);
        self.rows
            .get(commit)
            .cloned()
            .map(ParentSet::Complete)
            .ok_or("missing synthetic commit")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Answer {
    Ancestor(bool),
    Bases(MergeBaseResult<CommitId>),
}

impl Answer {
    fn to_json(&self) -> String {
        match self {
            Self::Ancestor(value) => format!("{{\"is_ancestor\":{value}}}"),
            Self::Bases(MergeBaseResult::NoCommonAncestor) => "{\"bases\":[]}".into(),
            Self::Bases(MergeBaseResult::Bases(bases)) => format!(
                "{{\"bases\":[{}]}}",
                bases
                    .iter()
                    .map(|id| quoted(&hex(id)))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Query {
    name: &'static str,
    left: CommitId,
    right: CommitId,
    expected: Answer,
}

fn queries(count: usize, merge_heavy: bool) -> Vec<Query> {
    let mut expected_bases = if merge_heavy {
        vec![
            identity(count - 5),
            identity(count - 4),
            identity(count - 3),
        ]
    } else {
        vec![identity(count / 2)]
    };
    expected_bases.sort_unstable();
    vec![
        Query {
            name: "fast_forward_permitted",
            left: identity(count / 4),
            right: identity(count - 1),
            expected: Answer::Ancestor(true),
        },
        Query {
            name: "fast_forward_refused",
            left: identity(if merge_heavy { count - 2 } else { count - 1 }),
            right: identity(if merge_heavy { count - 1 } else { count / 4 }),
            expected: Answer::Ancestor(false),
        },
        Query {
            name: "all_best_merge_bases",
            left: identity(if merge_heavy { count - 2 } else { count - 1 }),
            right: identity(if merge_heavy { count - 1 } else { count / 2 }),
            expected: Answer::Bases(MergeBaseResult::Bases(expected_bases)),
        },
    ]
}

// Exact independent ancestry baseline: no index, generations or candidate
// scratch. An unknown object remains an error, never a negative answer.
fn walk_is_ancestor(
    graph: &Graph,
    ancestor: CommitId,
    descendant: CommitId,
) -> Result<(bool, usize, usize), String> {
    if !graph.rows.contains_key(&ancestor) || !graph.rows.contains_key(&descendant) {
        return Err("unknown synthetic ancestry endpoint".into());
    }
    let mut pending = vec![descendant];
    let mut seen = BTreeSet::new();
    let mut examined_edges = 0;
    while let Some(commit) = pending.pop() {
        if !seen.insert(commit) {
            continue;
        }
        if commit == ancestor {
            return Ok((true, seen.len(), examined_edges));
        }
        let ParentSet::Complete(parents) = graph.parents_of(&commit)? else {
            return Err("unexpected synthetic shallow boundary".into());
        };
        examined_edges += parents.len();
        pending.extend(parents);
    }
    Ok((false, seen.len(), examined_edges))
}

struct Observation {
    answer: Answer,
    source_reads: usize,
    visited_commits: Option<usize>,
    examined_edges: Option<usize>,
}

fn baseline(graph: &Graph, query: &Query, limits: MergeBaseLimits) -> Result<Observation, String> {
    graph.reset_reads();
    let (answer, visited_commits, examined_edges) = match &query.expected {
        Answer::Ancestor(_) => {
            let (answer, visits, edges) = walk_is_ancestor(graph, query.left, query.right)?;
            (Answer::Ancestor(answer), Some(visits), Some(edges))
        }
        Answer::Bases(_) => {
            let answer = merge_bases_all(graph, query.left, query.right, limits)
                .map_err(|error| format!("scalar merge-base: {error:?}"))?;
            // Source reads count closure loading only. The scalar oracle does
            // not expose traversal work, so do not invent that metric.
            (Answer::Bases(answer), None, None)
        }
    };
    Ok(Observation {
        answer,
        source_reads: graph.reads.get(),
        visited_commits,
        examined_edges,
    })
}

fn indexed(
    graph: &Graph,
    index: &CommitAncestryIndex<CommitId>,
    scratch: &mut AncestryQueryScratch,
    query: &Query,
    limits: MergeBaseLimits,
) -> Result<Observation, String> {
    let answer = match &query.expected {
        Answer::Ancestor(_) => Answer::Ancestor(
            index
                .is_ancestor(&query.left, &query.right, scratch, limits, || {
                    Ok::<(), &'static str>(())
                })
                .map_err(|error| format!("indexed ancestry: {error:?}"))?,
        ),
        Answer::Bases(_) => Answer::Bases(
            index
                .merge_bases_all(&query.left, &query.right, scratch, limits, || {
                    Ok::<(), &'static str>(())
                })
                .map_err(|error| format!("indexed merge-base: {error:?}"))?,
        ),
    };
    let AncestryQueryWork {
        visited_commits,
        examined_edges,
    } = scratch.work();
    Ok(Observation {
        answer,
        source_reads: graph.reads.get(),
        visited_commits: Some(visited_commits),
        examined_edges: Some(examined_edges),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Variant {
    Baseline,
    FreshIndex,
    ReusedIndex,
    AaControl,
}

impl Variant {
    const fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::FreshIndex => "candidate_build_and_query",
            Self::ReusedIndex => "candidate_reused_index",
            Self::AaControl => "aa_control",
        }
    }
}

struct Sample {
    variant: Variant,
    elapsed_ns: u128,
}

fn optional(value: Option<usize>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn write_row(out: &mut impl Write, row: &str) -> Result<(), String> {
    writeln!(out, "{row}").map_err(|error| format!("benchmark output: {error}"))
}

fn quantile(samples: &[Sample], variant: Variant, numerator: usize, denominator: usize) -> u128 {
    let mut sorted = samples
        .iter()
        .filter(|sample| sample.variant == variant)
        .map(|sample| sample.elapsed_ns)
        .collect::<Vec<_>>();
    sorted.sort_unstable();
    sorted[(sorted.len() * numerator)
        .div_ceil(denominator)
        .saturating_sub(1)]
}

fn run_mode(out: &mut impl Write, options: &Options, mode: &str) -> Result<usize, String> {
    let merge_heavy = mode == "merge-heavy";
    let graph = Graph::new(options.commits, merge_heavy);
    let edges = graph.rows.values().map(Vec::len).sum::<usize>();
    let limits = MergeBaseLimits {
        max_commits: options.commits,
        // The generation-ordered query examines each closure edge at most once.
        max_edges: edges,
    };
    let tips = if merge_heavy {
        vec![identity(options.commits - 2), identity(options.commits - 1)]
    } else {
        vec![identity(options.commits - 1)]
    };
    let started = Instant::now();
    let index = CommitAncestryIndex::build(&graph, tips, limits)
        .map_err(|error| format!("index setup: {error:?}"))?;
    let setup_ns = started.elapsed().as_nanos();
    if index.commit_count() != options.commits || index.edge_count() != edges {
        return Err("index setup did not preserve the complete workload".into());
    }
    write_row(
        out,
        &format!(
            "{{\"schema\":\"{SCHEMA}\",\"kind\":\"setup\",\"mode\":{},\"commits\":{},\"edges\":{edges},\"index_build_ns\":{setup_ns},\"source_reads\":{},\"input_identity_payload_bytes\":{},\"input_parent_payload_bytes\":{},\"memory_scope\":\"payload only; excludes maps, vectors, capacities, index and allocator overhead\"}}",
            quoted(mode),
            options.commits,
            graph.reads.get(),
            options.commits * 32,
            edges * 32,
        ),
    )?;

    let mut scratch = AncestryQueryScratch::default();
    let mut total_samples = 0;
    for query in queries(options.commits, merge_heavy) {
        graph.reset_reads();
        let warmup = indexed(&graph, &index, &mut scratch, &query, limits)?;
        if warmup.answer != query.expected || warmup.source_reads != 0 {
            return Err(format!("warmup oracle failed for {mode}/{}", query.name));
        }
        let mut samples = Vec::new();
        for sample_number in 0..options.samples {
            for variant in [
                Variant::Baseline,
                Variant::FreshIndex,
                Variant::ReusedIndex,
                Variant::AaControl,
            ] {
                graph.reset_reads();
                let started = Instant::now();
                let observation = match variant {
                    Variant::Baseline | Variant::AaControl => baseline(&graph, &query, limits),
                    Variant::FreshIndex => {
                        let fresh =
                            CommitAncestryIndex::build(&graph, [query.left, query.right], limits)
                                .map_err(|error| format!("fresh index: {error:?}"))?;
                        indexed(
                            &graph,
                            &fresh,
                            &mut AncestryQueryScratch::default(),
                            &query,
                            limits,
                        )
                        // The fresh index and its scratch are destroyed in
                        // this measured arm, matching scalar temporary state.
                    }
                    Variant::ReusedIndex => indexed(&graph, &index, &mut scratch, &query, limits),
                }?;
                black_box(&observation.answer);
                let elapsed_ns = started.elapsed().as_nanos();
                if observation.answer != query.expected {
                    return Err(format!(
                        "oracle mismatch at {mode}/{} sample {sample_number} {}: {:?} != {:?}",
                        query.name,
                        variant.name(),
                        observation.answer,
                        query.expected
                    ));
                }
                if variant == Variant::ReusedIndex && observation.source_reads != 0 {
                    return Err("reused index unexpectedly reopened its source".into());
                }
                write_row(
                    out,
                    &format!(
                        "{{\"schema\":\"{SCHEMA}\",\"kind\":\"sample\",\"mode\":{},\"operation\":{},\"variant\":{},\"sample\":{sample_number},\"elapsed_ns\":{elapsed_ns},\"source_reads\":{},\"visited_commits\":{},\"examined_edges\":{},\"oracle\":\"matched\",\"result\":{}}}",
                        quoted(mode),
                        quoted(query.name),
                        quoted(variant.name()),
                        observation.source_reads,
                        optional(observation.visited_commits),
                        optional(observation.examined_edges),
                        observation.answer.to_json(),
                    ),
                )?;
                samples.push(Sample {
                    variant,
                    elapsed_ns,
                });
                total_samples += 1;
            }
        }
        let baseline_p95 = quantile(&samples, Variant::Baseline, 95, 100);
        let aa_p95 = quantile(&samples, Variant::AaControl, 95, 100);
        let aa_noise = baseline_p95.abs_diff(aa_p95);
        for variant in [
            Variant::Baseline,
            Variant::FreshIndex,
            Variant::ReusedIndex,
            Variant::AaControl,
        ] {
            let p95 = quantile(&samples, variant, 95, 100);
            let improves_beyond_aa = baseline_p95 > p95 && baseline_p95 - p95 > aa_noise;
            write_row(
                out,
                &format!(
                    "{{\"schema\":\"{SCHEMA}\",\"kind\":\"summary\",\"mode\":{},\"operation\":{},\"variant\":{},\"samples\":{},\"p50_ns\":{},\"p95_ns\":{p95},\"p99_ns\":{},\"aa_p95_noise_ns\":{aa_noise},\"improvement_exceeds_aa_noise\":{improves_beyond_aa},\"claim_scope\":\"in-memory graph microbenchmark only\"}}",
                    quoted(mode),
                    quoted(query.name),
                    quoted(variant.name()),
                    options.samples,
                    quantile(&samples, variant, 50, 100),
                    quantile(&samples, variant, 99, 100),
                ),
            )?;
        }
    }
    Ok(total_samples)
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args == ["--help"] {
        print!("{USAGE}");
        return Ok(());
    }
    let options = Options::parse(&args)?;
    let fingerprint = fingerprint()?;
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    write_row(
        &mut out,
        &format!(
            "{{\"schema\":\"{SCHEMA}\",\"kind\":\"provenance\",\"fingerprint\":{fingerprint},\"commits_per_mode\":{},\"samples_per_variant\":{},\"generator\":\"opaque-256-bit-chain-and-three-base-octopus-v1\",\"generator_seed\":\"78626d7634360002\",\"input_state\":\"prebuilt in-memory adjacency\",\"warm_index_state\":\"built once; scratch primed outside timers\",\"fresh_index_state\":\"closure discovery, index build, query and temporary teardown included\",\"baseline\":\"exact parent walk for ancestry; retained merge_bases_all scalar for merge bases, in the same binary\",\"validation_scope\":\"ancestry baseline validates endpoints and walked parents; index build and scalar merge bases validate complete closure; reused index was validated during setup\",\"aa_control\":\"second execution of the identical baseline\",\"variant_sequence\":\"baseline,candidate_build_and_query,candidate_reused_index,aa_control\",\"quantile_method\":\"nearest rank; small sample tails are descriptive only\",\"excluded\":\"native Git parsing, object-store I/O, network, transport, authority publication and process startup\",\"acceptance\":\"x2mv.4.36.2 microbenchmark component\"}}",
            options.commits, options.samples,
        ),
    )?;
    let modes: &[&str] = match options.mode.as_str() {
        "chain" => &["chain"],
        "merge-heavy" => &["merge-heavy"],
        _ => &["chain", "merge-heavy"],
    };
    let mut total_samples = 0;
    for mode in modes {
        total_samples += run_mode(&mut out, &options, mode)?;
    }
    let expected_samples = modes.len() * 3 * 4 * options.samples;
    if total_samples != expected_samples {
        return Err("benchmark sample denominator mismatch".into());
    }
    write_row(
        &mut out,
        &format!(
            "{{\"schema\":\"{SCHEMA}\",\"kind\":\"terminal\",\"expected_samples\":{expected_samples},\"completed_samples\":{total_samples},\"all_oracles_matched\":true,\"end_to_end_performance_claim\":false}}"
        ),
    )?;
    out.flush()
        .map_err(|error| format!("benchmark output flush: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ancestry benchmark refused: {error}");
        std::process::exit(1);
    }
}
