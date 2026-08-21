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
        _ => Err(BenchmarkRefusal::MissingRequiredField(
            "command: self-test --out <directory>",
        )),
    }
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
        if let Ok(cpu_info) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(model) = cpu_info
                .lines()
                .find_map(|line| line.strip_prefix("model name\t: "))
            {
                return model.to_owned();
            }
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
