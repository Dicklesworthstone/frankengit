#![forbid(unsafe_code)]
//! Command-line driver for the benchmark harness's checked-in self-test.

use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use fgit_benchmark::{
    BenchmarkPlan, BenchmarkRefusal, BenchmarkRunner, BenchmarkWorkload, EnvironmentFingerprint,
    MIN_SAMPLES_PER_VARIANT, OptimizationAdmission, OracleReceipt, StorageClasses, SystemMetrics,
    WorkloadDescriptor,
    transport::{CacheState, ServerKind, TransportConfig, TransportWorkload},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("fgit-benchmark: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), BenchmarkRefusal> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("self-test") => {
            let output = parse_output(arguments)?;
            let root = workspace_root()?;
            let plan = self_test_plan(&root)?;
            let runner = BenchmarkRunner::new(plan)?;
            let mut baseline = KnownCost::new(25_000, 0);
            // Same logical result, intentionally more work: the checked-in
            // self-test must exercise the automatic negative-evidence path,
            // never make a speedup claim from scheduler noise.
            let mut candidate = KnownCost::new(25_000, 1_000_000);
            let artifact = runner.run(&mut baseline, &mut candidate)?;
            let written = artifact.write_to(&output)?;
            println!("artifact={}", written.evidence_path.display());
            println!("replay={}", written.replay_path.display());
            if let Some(ledger) = written.negative_evidence_path {
                println!("negative_evidence={}", ledger.display());
            }
            Ok(())
        }
        Some("transport-baseline") => {
            let output = parse_output(arguments)?;
            let root = workspace_root()?;
            let config = transport_config_from_environment()?;
            let samples = transport_samples()?;
            let plan = transport_plan(&root, &config, samples)?;
            let runner = BenchmarkRunner::new(plan)?;
            // Baseline is upstream, candidate is this project. The runner reuses
            // the baseline subject for the A/A pass, so the noise floor is
            // measured on the same arm rather than assumed.
            let mut baseline =
                TransportWorkload::new(config.clone(), ServerKind::UpstreamGitDaemon);
            let mut candidate = TransportWorkload::new(config, ServerKind::FgitNode);
            let artifact = runner.run(&mut baseline, &mut candidate)?;
            let written = artifact.write_to(&output)?;
            println!("artifact={}", written.evidence_path.display());
            println!("replay={}", written.replay_path.display());
            println!("samples_per_variant={samples}");
            // Nearest-rank p99 over n samples is the maximum whenever n < 100.
            // Printing the caveat next to the number keeps a reader from taking
            // "p99" as a hundred-sample tail estimate.
            if samples < 100 {
                println!(
                    "p99_caveat=nearest-rank p99 over {samples} samples is the observed maximum, not a 99th-percentile estimate"
                );
            }
            if let Some(ledger) = written.negative_evidence_path {
                println!("negative_evidence={}", ledger.display());
            }
            Ok(())
        }
        _ => Err(BenchmarkRefusal::MissingRequiredField(
            "command: self-test --out <directory> | transport-baseline --out <directory>",
        )),
    }
}

/// Reads the transport experiment's inputs from the environment.
///
/// Every path is required and explicit. Nothing falls back to a `PATH` lookup:
/// an ambient `git` would make the differential unpinned, and a defaulted `fg`
/// could measure a stale binary from an earlier build.
fn transport_config_from_environment() -> Result<TransportConfig, BenchmarkRefusal> {
    Ok(TransportConfig {
        fg_binary: required_path("FG_BENCH_FG_BINARY")?,
        git_binary: required_path("FG_BENCH_GIT_BINARY")?,
        git_exec_path: required_path("FG_BENCH_GIT_EXEC_PATH")?,
        empty_template_dir: required_path("FG_BENCH_TEMPLATE_DIR")?,
        storage_root: required_path("FG_BENCH_STORAGE_ROOT")?,
        upstream_base_path: required_path("FG_BENCH_UPSTREAM_BASE_PATH")?,
        tenant: required_var("FG_BENCH_TENANT")?,
        repository: required_var("FG_BENCH_REPOSITORY")?,
        work_root: required_path("FG_BENCH_WORK_ROOT")?,
        port_base: required_var("FG_BENCH_PORT_BASE")?.parse().map_err(|_| {
            BenchmarkRefusal::InvalidMetric {
                field: "FG_BENCH_PORT_BASE",
                detail: "must be a u16 port number".to_owned(),
            }
        })?,
        expected_head: required_var("FG_BENCH_EXPECTED_HEAD")?,
        expected_commits: required_var("FG_BENCH_EXPECTED_COMMITS")?
            .parse()
            .map_err(|_| BenchmarkRefusal::InvalidMetric {
                field: "FG_BENCH_EXPECTED_COMMITS",
                detail: "must be a commit count".to_owned(),
            })?,
        cache_state: match required_var("FG_BENCH_CACHE_STATE")?.as_str() {
            "warm" => CacheState::Warm,
            "cold" => CacheState::ColdPageCache,
            _ => {
                return Err(BenchmarkRefusal::InvalidMetric {
                    field: "FG_BENCH_CACHE_STATE",
                    detail: "must be exactly \"warm\" or \"cold\"".to_owned(),
                });
            }
        },
        python_binary: required_path("FG_BENCH_PYTHON")?,
        logical_reachable_bytes: required_var("FG_BENCH_LOGICAL_BYTES")?
            .parse()
            .map_err(|_| BenchmarkRefusal::InvalidMetric {
                field: "FG_BENCH_LOGICAL_BYTES",
                detail: "must be the corpus's reachable byte count".to_owned(),
            })?,
    })
}

fn transport_samples() -> Result<usize, BenchmarkRefusal> {
    let samples = match env::var("FG_BENCH_SAMPLES") {
        Ok(value) => value.parse().map_err(|_| BenchmarkRefusal::InvalidMetric {
            field: "FG_BENCH_SAMPLES",
            detail: "must be a sample count".to_owned(),
        })?,
        Err(_) => MIN_SAMPLES_PER_VARIANT,
    };
    if samples < MIN_SAMPLES_PER_VARIANT {
        return Err(BenchmarkRefusal::InsufficientSamples {
            configured: samples,
            minimum: MIN_SAMPLES_PER_VARIANT,
        });
    }
    Ok(samples)
}

fn required_var(name: &'static str) -> Result<String, BenchmarkRefusal> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(BenchmarkRefusal::MissingRequiredField(name))
}

fn required_path(name: &'static str) -> Result<PathBuf, BenchmarkRefusal> {
    required_var(name).map(PathBuf::from)
}

fn transport_plan(
    root: &Path,
    config: &TransportConfig,
    samples: usize,
) -> Result<BenchmarkPlan, BenchmarkRefusal> {
    let candidate = TransportWorkload::new(config.clone(), ServerKind::FgitNode);
    Ok(BenchmarkPlan {
        fingerprint: EnvironmentFingerprint::from_workspace(
            root,
            required_var("FG_BENCH_SOURCE_REVISION")?,
            required_var("FG_BENCH_SOURCE_TREE")?,
            cpu_model(),
            env::var("TARGET").unwrap_or_else(|_| std::env::consts::ARCH.to_owned()),
            env::var("PROFILE").unwrap_or_else(|_| "release".to_owned()),
        )?,
        workload: WorkloadDescriptor {
            dataset: required_var("FG_BENCH_DATASET")?,
            workload: candidate.workload_line(),
            thermal_state: format!(
                "{}; one cold server process per sample",
                config.cache_state.as_str()
            ),
            cache_state: match config.cache_state {
                CacheState::Warm => "warm: the corpus is left page-cached between samples, so \
                     both arms see the same warm filesystem"
                    .to_owned(),
                CacheState::ColdPageCache => "cold: the served corpus is evicted with \
                     posix_fadvise(POSIX_FADV_DONTNEED) before EVERY sample and before the \
                     server starts; a sample that evicts nothing is refused rather than \
                     reported as cold"
                    .to_owned(),
            },
            commands: vec![
                "fg init <storage> <tenant> <repository>".to_owned(),
                "fg import <storage> <tenant> <repository> <principal> <key> <source>".to_owned(),
                "git clone --bare <source> <upstream-base>/<repository>.git".to_owned(),
                "cargo run --release -p fgit-benchmark -- transport-baseline --out <directory>"
                    .to_owned(),
            ],
            environment_allowlist: transport_allowlist(config, samples),
        },
        admission: OptimizationAdmission {
            equivalence_obligation:
                "every measured clone must resolve HEAD to the corpus tip and carry the corpus \
                 commit count; a well-formed clone of a different history is a failed sample, \
                 not a fast one"
                    .to_owned(),
            oracle_name: "clone-tip-and-commit-count equality against the pinned corpus".to_owned(),
            replay_command:
                "scripts/e2e/suites/benchmark/perf_baseline.sh (sets every FG_BENCH_* input)"
                    .to_owned(),
            rollback_artifact:
                "delete the generated evidence directory; the experiment mutates no repository \
                 state outside its own scratch tree"
                    .to_owned(),
            hypothesis:
                "ANCHOR, NOT A SPEEDUP CLAIM: this run records where fgit-node stands against \
                 upstream git daemon on one corpus and one host. Baseline is upstream, candidate \
                 is fgit-node, so `speedup_admissible` reads as 'fgit-node beat upstream p95 by \
                 more than this host's A/A noise'. A false value is the expected and honest \
                 outcome for a pre-optimization anchor."
                    .to_owned(),
        },
        samples_per_variant: samples,
    })
}

fn transport_allowlist(config: &TransportConfig, samples: usize) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "FG_BENCH_FG_BINARY".to_owned(),
            config.fg_binary.display().to_string(),
        ),
        (
            "FG_BENCH_GIT_BINARY".to_owned(),
            config.git_binary.display().to_string(),
        ),
        (
            "FG_BENCH_GIT_EXEC_PATH".to_owned(),
            config.git_exec_path.display().to_string(),
        ),
        ("FG_BENCH_TENANT".to_owned(), config.tenant.clone()),
        ("FG_BENCH_REPOSITORY".to_owned(), config.repository.clone()),
        (
            "FG_BENCH_EXPECTED_HEAD".to_owned(),
            config.expected_head.clone(),
        ),
        (
            "FG_BENCH_EXPECTED_COMMITS".to_owned(),
            config.expected_commits.to_string(),
        ),
        ("FG_BENCH_SAMPLES".to_owned(), samples.to_string()),
        (
            "FG_BENCH_PORT_BASE".to_owned(),
            config.port_base.to_string(),
        ),
    ])
}

fn parse_output(mut arguments: impl Iterator<Item = String>) -> Result<PathBuf, BenchmarkRefusal> {
    match (arguments.next().as_deref(), arguments.next()) {
        (Some("--out"), Some(path)) if arguments.next().is_none() => Ok(PathBuf::from(path)),
        _ => Err(BenchmarkRefusal::MissingRequiredField("self-test --out")),
    }
}

fn workspace_root() -> Result<PathBuf, BenchmarkRefusal> {
    let mut directory = env::current_dir().map_err(|error| BenchmarkRefusal::Io {
        operation: "read current directory",
        detail: error.to_string(),
    })?;
    loop {
        if directory.join("Cargo.lock").is_file() && directory.join("rust-toolchain.toml").is_file()
        {
            return Ok(directory);
        }
        if !directory.pop() {
            return Err(BenchmarkRefusal::MissingRequiredField("workspace root"));
        }
    }
}

fn self_test_plan(root: &Path) -> Result<BenchmarkPlan, BenchmarkRefusal> {
    Ok(BenchmarkPlan {
        fingerprint: EnvironmentFingerprint::from_workspace(
            root,
            env::var("FG_BENCH_SOURCE_REVISION").unwrap_or_else(|_| "self-test".to_owned()),
            env::var("FG_BENCH_SOURCE_TREE").unwrap_or_else(|_| "self-test".to_owned()),
            cpu_model(),
            env::var("TARGET").unwrap_or_else(|_| std::env::consts::ARCH.to_owned()),
            env::var("PROFILE").unwrap_or_else(|_| "debug".to_owned()),
        )?,
        workload: WorkloadDescriptor {
            dataset: "fgit-benchmark-known-cost-v1".to_owned(),
            workload: "deterministic arithmetic accumulation".to_owned(),
            thermal_state: "synthetic-known-cost".to_owned(),
            cache_state: "not-applicable; no external cache".to_owned(),
            commands: vec!["cargo run -p fgit-benchmark -- self-test --out <directory>".to_owned()],
            environment_allowlist: BTreeMap::from([
                (
                    "FG_BENCH_SOURCE_REVISION".to_owned(),
                    env::var("FG_BENCH_SOURCE_REVISION").unwrap_or_else(|_| "self-test".to_owned()),
                ),
                (
                    "FG_BENCH_SOURCE_TREE".to_owned(),
                    env::var("FG_BENCH_SOURCE_TREE").unwrap_or_else(|_| "self-test".to_owned()),
                ),
            ]),
        },
        admission: OptimizationAdmission {
            equivalence_obligation: "all known-cost sums are exact and checked".to_owned(),
            oracle_name: "known-cost sum oracle".to_owned(),
            replay_command: "cargo run -p fgit-benchmark -- self-test --out <directory>".to_owned(),
            rollback_artifact: "remove generated evidence directory".to_owned(),
            hypothesis: "self-test validates evidence capture rather than claiming a speedup"
                .to_owned(),
        },
        samples_per_variant: MIN_SAMPLES_PER_VARIANT,
    })
}

fn cpu_model() -> String {
    if let Ok(value) = env::var("FG_BENCH_CPU_MODEL") {
        return value;
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpu_info) = std::fs::read_to_string("/proc/cpuinfo")
            && let Some(model) = cpu_info
                .lines()
                .find_map(|line| line.strip_prefix("model name\t: "))
        {
            return model.to_owned();
        }
    }
    "unavailable; set FG_BENCH_CPU_MODEL".to_owned()
}

struct KnownCost {
    input: u32,
    padding: u32,
}

impl KnownCost {
    const fn new(input: u32, padding: u32) -> Self {
        Self { input, padding }
    }
}

impl BenchmarkWorkload for KnownCost {
    type Output = u64;

    fn measure(&mut self) -> Result<(Self::Output, SystemMetrics), String> {
        let mut sum = 0_u64;
        for value in 0..self.input {
            sum = sum.wrapping_add(u64::from(value).wrapping_mul(3));
        }
        let mut padding = 0_u64;
        for value in 0..self.padding {
            padding = padding.wrapping_add(u64::from(value).wrapping_mul(7));
        }
        std::hint::black_box(padding);
        Ok((
            sum,
            SystemMetrics {
                cpu_ns: u64::from(self.input).saturating_add(u64::from(self.padding)),
                memory_bytes: 64,
                object_requests: 0,
                object_request_bytes: 0,
                egress_bytes: 0,
                decisions: 1,
                cas_attempts: 1,
                storage: StorageClasses {
                    canonical_bytes: 1,
                    repair_bytes: 0,
                    replica_bytes: 0,
                    retained_derived_bytes: 0,
                    logical_reachable_git_bytes: 1,
                },
                ..SystemMetrics::default()
            },
        ))
    }

    fn verify(&mut self, output: &Self::Output) -> Result<OracleReceipt, String> {
        let expected = u64::from(self.input)
            .saturating_sub(1)
            .saturating_mul(u64::from(self.input))
            .checked_div(2)
            .unwrap_or(0)
            .saturating_mul(3);
        if *output != expected {
            return Err("known-cost sum mismatch".to_owned());
        }
        Ok(OracleReceipt {
            receipt: format!("known-cost-sum-{output}"),
        })
    }
}
