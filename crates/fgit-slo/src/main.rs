#![forbid(unsafe_code)]
//! The repository-owned multi-cell SLO measurement command (`frankengit-fg036c`).
//!
//! ```text
//! fgit-slo multicell            measure and write NDJSON to stdout
//! ```
//!
//! Exit codes are the contract: `0` measured, `1` measurement failed, `2` usage.
//!
//! Every record is one NDJSON line. Latency records carry the A/A floor
//! measured on the *same* configuration, because a gap that does not clear that
//! floor is not a result — and on this substrate the per-read-mode gaps do not
//! clear it, which is a finding rather than a disappointment.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use fgit_authority::StoreInstanceId;
use fgit_node::{NodeConfig, OneNode};
use fgit_slo::{STATES, labels, legal_path, median_of, sample_block, tree_footprint};
use fgit_types::cell::{CellState, CellTransitionCause, admits_read};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{RepositoryId, TenantId};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;

fn usage() -> ExitCode {
    eprintln!("usage: fgit-slo multicell");
    eprintln!();
    eprintln!("  multicell   measure read modes, state admission and storage");
    eprintln!("              across cell counts; NDJSON on stdout");
    eprintln!();
    eprintln!("exit 0 measured, 1 measurement failed, 2 usage");
    ExitCode::from(2)
}

fn emit(fields: &[(&str, String)]) {
    let body: Vec<String> = fields
        .iter()
        .map(|(key, value)| format!("\"{key}\":{value}"))
        .collect();
    println!("{{{}}}", body.join(","));
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

fn series(values: &[u128]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn joined(states: &[CellState]) -> String {
    states
        .iter()
        .map(|state| format!("{state:?}"))
        .collect::<Vec<_>>()
        .join(" then ")
}

fn config(root: PathBuf, instance: u64) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x11; 16]),
        RepositoryId::from_bytes([0x22; 16]),
    )
    .with_store_instance(StoreInstanceId::from_raw(instance))
}

/// Cell 1 creates the backend; the rest share it.
///
/// That is the fg036a deployment shape — several cells, one authority, one
/// object fabric — and the timings are returned separately because init cost
/// and attach cost are different questions.
fn open_cells(scratch: &Path, count: u64) -> Result<(OneNode, Vec<OneNode>), String> {
    let started = Instant::now();
    let (first, _initialization) = OneNode::init(config(scratch.to_path_buf(), 1))
        .map_err(|error| format!("init: {error:?}"))?;
    let init_ns = started.elapsed().as_nanos();
    let (bytes_after_init, files_after_init) = tree_footprint(scratch);

    let mut companions = Vec::new();
    let mut open_ns = Vec::new();
    for instance in 2..=count {
        let started = Instant::now();
        let node = OneNode::open_existing(config(scratch.to_path_buf(), instance))
            .map_err(|error| format!("open: {error:?}"))?;
        open_ns.push(started.elapsed().as_nanos());
        companions.push(node);
    }

    let (bytes_all, files_all) = tree_footprint(scratch);
    emit(&[
        ("record", quoted("open_cost")),
        ("cells", count.to_string()),
        ("init_ns", init_ns.to_string()),
        ("companion_open_ns", series(&open_ns)),
    ]);
    // EXACT metric. Unlike latency this is a byte count, so host contention
    // cannot touch it. `after_init` is the backend alone, so the difference is
    // precisely what attaching a cell costs.
    emit(&[
        ("record", quoted("storage_footprint")),
        ("cells", count.to_string()),
        ("bytes_after_init", bytes_after_init.to_string()),
        ("files_after_init", files_after_init.to_string()),
        ("bytes_after_attach", bytes_all.to_string()),
        ("files_after_attach", files_all.to_string()),
        (
            "bytes_added_by_companions",
            bytes_all.saturating_sub(bytes_after_init).to_string(),
        ),
    ]);
    Ok((first, companions))
}

/// Samples every read mode against a cell already standing in `target`.
fn measure_modes(
    cell: &OneNode,
    target: CellState,
    count: u64,
    hops: usize,
    visibility: &RefVisibility,
    limits: &WireLimits,
    samples: u32,
) {
    for (mode_name, label) in labels() {
        let predicted = admits_read(target, label.mode()).is_ok();

        // A and A-PRIME: the same configuration, twice, same function. The gap
        // between them is this host's noise floor right now.
        let (served, arrival) = sample_block(cell, visibility, limits, label, samples);
        let (served_prime, arrival_prime) = sample_block(cell, visibility, limits, label, samples);

        let median_a = median_of(&arrival);
        let median_a_prime = median_of(&arrival_prime);
        // Steady state excludes the first sample, which carries the warmup the
        // path walk left behind.
        let steady = if arrival.len() > 1 {
            median_of(&arrival[1..])
        } else {
            0
        };

        emit(&[
            ("record", quoted("read_mode_sample")),
            ("cells", count.to_string()),
            ("state", quoted(&format!("{target:?}"))),
            ("hops_walked", hops.to_string()),
            ("mode", quoted(mode_name)),
            ("types_predicts_served", predicted.to_string()),
            ("node_served", (served > 0).to_string()),
            ("layers_agree", (predicted == (served > 0)).to_string()),
            ("served_count", served.to_string()),
            ("served_a_prime", served_prime.to_string()),
            ("samples", samples.to_string()),
            (
                "first_read_ns",
                arrival.first().copied().unwrap_or(0).to_string(),
            ),
            ("steady_median_ns", steady.to_string()),
            ("median_a_ns", median_a.to_string()),
            ("median_a_prime_ns", median_a_prime.to_string()),
            ("aa_floor_ns", median_a.abs_diff(median_a_prime).to_string()),
            ("arrival_ns", series(&arrival)),
            ("arrival_a_prime_ns", series(&arrival_prime)),
        ]);
    }
}

/// Walks the cell to `target` by a legal path, then measures every read mode.
fn measure_state(
    cell: &mut OneNode,
    target: CellState,
    count: u64,
    visibility: &RefVisibility,
    limits: &WireLimits,
    samples: u32,
) {
    // Walk from the cell's CURRENT state: the previous target left it somewhere
    // else, and planning from the initial state instead is what makes a sweep
    // measure a path rather than a state.
    let here = cell.cell_state();
    let Some(hops) = legal_path(here, target) else {
        emit(&[
            ("record", quoted("unreachable_from_here")),
            ("cells", count.to_string()),
            ("target", quoted(&format!("{target:?}"))),
            ("from", quoted(&format!("{here:?}"))),
        ]);
        return;
    };

    for hop in &hops {
        if cell
            .transition_cell_state(*hop, CellTransitionCause::Operator, HeadGeneration::FIRST)
            .is_err()
        {
            // `fgit-types` admitted the edge and `fgit-node` refused it. That is
            // a cross-layer disagreement and belongs in the record.
            emit(&[
                ("record", quoted("path_refused_by_node")),
                ("cells", count.to_string()),
                ("target", quoted(&format!("{target:?}"))),
                ("refused_hop", quoted(&format!("{hop:?}"))),
                ("planned_path", quoted(&joined(&hops))),
            ]);
            return;
        }
    }

    measure_modes(cell, target, count, hops.len(), visibility, limits, samples);
}

/// Measures one deployment size end to end.
fn measure_cell_count(count: u64, root: &Path, samples: u32) -> Result<(), String> {
    let scratch = root.join(format!("n{count}"));
    std::fs::create_dir_all(&scratch).map_err(|error| format!("scratch root: {error}"))?;

    let (mut cell, companions) = open_cells(&scratch, count)?;
    let limits = WireLimits::default();
    let visibility = RefVisibility::new();

    for target in STATES {
        measure_state(&mut cell, target, count, &visibility, &limits, samples);
    }

    cell.shutdown()
        .map_err(|error| format!("shutdown: {error:?}"))?;
    for node in companions {
        node.shutdown()
            .map_err(|error| format!("companion shutdown: {error:?}"))?;
    }
    Ok(())
}

/// Reports the transition graph, then measures each deployment size.
fn measure() -> Result<(), String> {
    let root = std::env::temp_dir().join(format!("fgit-slo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let samples: u32 = std::env::var("FG_SLO_SAMPLES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(7);

    // The transition graph is reported BEFORE any measurement, so a state that
    // goes unmeasured is visibly unreachable rather than quietly absent.
    for target in STATES {
        let path = legal_path(CellState::Bootstrapping, target);
        emit(&[
            ("record", quoted("reachability_from_bootstrapping")),
            ("target", quoted(&format!("{target:?}"))),
            ("reachable", path.is_some().to_string()),
            ("hops", path.as_ref().map_or(0, Vec::len).to_string()),
            ("path", quoted(&joined(&path.unwrap_or_default()))),
        ]);
    }

    for count in [1_u64, 3, 5] {
        measure_cell_count(count, &root, samples)?;
    }

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(mode) = arguments.next() else {
        return usage();
    };
    if arguments.next().is_some() || mode != "multicell" {
        return usage();
    }
    match measure() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("fgit-slo: measurement failed: {reason}");
            ExitCode::from(1)
        }
    }
}
