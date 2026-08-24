//! The workflow subset: what it accepts, what it refuses, and why each refusal
//! is distinguishable from the permitted case next to it.
//!
//! AGENTS.md §16.3 requires every forbidden case to pair with a near-identical
//! permitted one. That is not ceremony here: most of these refusals are one
//! character away from an accepted document, and a refusal that also rejects
//! the permitted twin is a parser that refuses everything rather than a subset
//! that is defined.

use fgit_schema::workflow::{ConstructStatus, Limits, WorkflowRefusal, compile, registry};

/// A workflow that uses every accepted construct.
const GOOD: &str = "\
name: ci
on:
  - push
  - pull_request
jobs:
  build:
    runs-on: linux
    steps:
      - name: compile
        run: cargo check
      - run: cargo test
  lint:
    runs-on: linux
    needs: build
    steps:
      - run: cargo clippy
";

fn good() -> fgit_schema::workflow::WorkflowGraph {
    compile(GOOD, &Limits::DEFAULT).expect("the reference workflow lowers")
}

/// Asserts `source` refuses with `kind`, and that the reference workflow still
/// lowers — so the refusal is about the input rather than about the parser.
fn refuses_with(source: &str, kind: &str) -> WorkflowRefusal {
    let refusal = compile(source, &Limits::DEFAULT).expect_err("this document must be refused");
    assert_eq!(refusal.kind(), kind, "{}", refusal);
    assert!(
        compile(GOOD, &Limits::DEFAULT).is_ok(),
        "PERMITTED TWIN: the reference workflow must still lower, or the \
         refusal above says nothing about the construct under test"
    );
    assert!(!refusal.to_string().is_empty(), "a refusal must print");
    assert!(refusal.span().line >= 1, "a refusal must carry a location");
    refusal
}

// ------------------------------------------------------------------ accepted

#[test]
fn the_reference_workflow_lowers_with_every_accepted_construct() {
    let graph = good();
    assert_eq!(graph.name, "ci");
    assert_eq!(
        graph
            .triggers
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        vec!["pull_request", "push"],
        "triggers are sorted, so source order cannot change the bytes"
    );
    assert_eq!(graph.job_ids(), vec!["build", "lint"]);
    assert_eq!(graph.jobs[0].steps.len(), 2);
    assert_eq!(graph.jobs[0].steps[0].name.as_deref(), Some("compile"));
    assert_eq!(graph.jobs[0].steps[1].name, None, "name is optional");
    assert_eq!(graph.jobs[1].needs, vec!["build"]);
}

#[test]
fn lowering_is_deterministic_across_runs() {
    let first = good().canonical_bytes();
    for _ in 0..8 {
        assert_eq!(good().canonical_bytes(), first);
    }
    assert!(first.starts_with("fgit-workflow/v1\n"));
}

#[test]
fn equivalent_spellings_normalize_to_identical_bytes() {
    // The registry promises this equivalence for workflow.on and job.needs, so
    // it is checked rather than assumed. A reordered, duplicated trigger list
    // and a reordered needs list must produce the same graph.
    let reordered = GOOD.replace(
        "  - push\n  - pull_request\n",
        "  - pull_request\n  - push\n  - push\n",
    );
    assert_ne!(reordered, GOOD, "the fixture must actually differ");
    let a = good().canonical_bytes();
    let b = compile(&reordered, &Limits::DEFAULT)
        .expect("the reordered document lowers")
        .canonical_bytes();
    assert_eq!(
        a, b,
        "trigger order and duplication must not change the bytes"
    );
}

#[test]
fn a_scalar_trigger_and_a_one_item_sequence_are_the_same_workflow() {
    let scalar =
        "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n";
    let sequence =
        "name: ci\non:\n  - push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n";
    let left = compile(scalar, &Limits::DEFAULT).expect("scalar form lowers");
    let right = compile(sequence, &Limits::DEFAULT).expect("sequence form lowers");
    assert_eq!(left.canonical_bytes(), right.canonical_bytes());
}

#[test]
fn jobs_are_emitted_in_topological_order_with_a_lexicographic_tie_break() {
    // c depends on nothing, a depends on nothing, b depends on both. a and c
    // could run in either order, so the tie-break decides — and without one the
    // canonical bytes would depend on source order.
    let source = "\
name: ci
on: push
jobs:
  c:
    runs-on: linux
    steps:
      - run: x
  b:
    runs-on: linux
    needs:
      - c
      - a
    steps:
      - run: x
  a:
    runs-on: linux
    steps:
      - run: x
";
    let graph = compile(source, &Limits::DEFAULT).expect("lowers");
    assert_eq!(graph.job_ids(), vec!["a", "c", "b"]);
    assert_eq!(graph.jobs[2].needs, vec!["a", "c"], "needs is sorted too");

    // Same graph, jobs listed in a different order: identical bytes.
    let shuffled = "\
name: ci
on: push
jobs:
  a:
    runs-on: linux
    steps:
      - run: x
  c:
    runs-on: linux
    steps:
      - run: x
  b:
    runs-on: linux
    needs:
      - a
      - c
    steps:
      - run: x
";
    assert_eq!(
        graph.canonical_bytes(),
        compile(shuffled, &Limits::DEFAULT)
            .expect("lowers")
            .canonical_bytes(),
        "source order of jobs must not survive into the canonical bytes"
    );
}

#[test]
fn a_hash_inside_a_quoted_run_is_content_rather_than_a_comment() {
    // Truncating a run line at a shell comment would be a silent drop of the
    // rest of the command, which is worse than refusing the document.
    let source = "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: \"echo a # b\"\n";
    let graph = compile(source, &Limits::DEFAULT).expect("lowers");
    assert_eq!(graph.jobs[0].steps[0].run, "echo a # b");

    // Permitted twin: an actual trailing comment IS stripped.
    let commented = "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: echo a # b\n";
    let stripped = compile(commented, &Limits::DEFAULT).expect("lowers");
    assert_eq!(stripped.jobs[0].steps[0].run, "echo a");
}

// ------------------------------------------------------ YAML-level refusals

#[test]
fn yaml_constructs_outside_the_subset_are_refused_by_name() {
    let cases: &[(&str, &str)] = &[
        (
            "name: &a ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.anchor",
        ),
        (
            "name: *a\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.alias",
        ),
        (
            "name: !!str ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.tag",
        ),
        (
            "name: ci\non: {a: b}\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.flow-mapping",
        ),
        (
            "name: ci\non: [push]\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.flow-sequence",
        ),
        (
            "---\nname: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.document-marker",
        ),
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: |\n",
            "yaml.block-scalar",
        ),
        (
            "name: ci\non: push\njobs:\n\ta:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.tab-indent",
        ),
        (
            "name: ci\non: push\n<<: x\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "yaml.merge-key",
        ),
    ];
    for (source, construct) in cases {
        let refusal = refuses_with(source, "construct_unsupported");
        match &refusal {
            WorkflowRefusal::ConstructUnsupported {
                construct: named,
                reason,
                ..
            } => {
                assert_eq!(named, construct, "wrong construct named");
                // The reason must come from the registry, not be invented at
                // the refusal site, or the table and the message can drift.
                assert_eq!(*reason, registry::reason_for(construct));
                assert_ne!(*reason, "", "the registry must supply a reason");
            }
            other => panic!("expected ConstructUnsupported, got {other:?}"),
        }
    }
}

#[test]
fn a_duplicate_key_is_refused_rather_than_last_wins() {
    let refusal = refuses_with(
        "name: ci\nname: other\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
        "duplicate_key",
    );
    match &refusal {
        WorkflowRefusal::DuplicateKey { key, span } => {
            assert_eq!(&**key, "name");
            assert_eq!(span.line, 2, "the SECOND occurrence is the one reported");
        }
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

// -------------------------------------------------- workflow-level refusals

#[test]
fn workflow_constructs_outside_the_subset_are_refused_by_name() {
    let cases: &[(&str, &str)] = &[
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - uses: actions/checkout\n",
            "step.uses",
        ),
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n        with: y\n",
            "step.with",
        ),
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    strategy: x\n    steps:\n      - run: x\n",
            "job.strategy",
        ),
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    permissions: read\n    steps:\n      - run: x\n",
            "job.permissions",
        ),
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    if: always\n    steps:\n      - run: x\n",
            "job.if",
        ),
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    container: img\n    steps:\n      - run: x\n",
            "job.container",
        ),
        (
            "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    continue-on-error: true\n    steps:\n      - run: x\n",
            "job.continue-on-error",
        ),
        (
            "name: ci\non: push\nenv: x\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "workflow.env",
        ),
        (
            "name: ci\non: push\nconcurrency: g\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "workflow.concurrency",
        ),
        (
            "name: ci\non: push\nsecrets: s\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
            "workflow.secrets",
        ),
    ];
    for (source, construct) in cases {
        let refusal = refuses_with(source, "construct_unsupported");
        match &refusal {
            WorkflowRefusal::ConstructUnsupported {
                construct: named, ..
            } => {
                assert_eq!(named, construct);
            }
            other => panic!("expected ConstructUnsupported, got {other:?}"),
        }
    }
}

#[test]
fn an_ambiguous_construct_is_distinguishable_from_an_unsupported_one() {
    // `if` is Ambiguous and `strategy` is Unsupported. Both refuse, but the
    // registry keeps them apart: unsupported is work nobody has done, ambiguous
    // is work nobody should do until the semantics are pinned.
    assert_eq!(
        registry::lookup("job.if").expect("registered").status,
        ConstructStatus::Ambiguous
    );
    assert_eq!(
        registry::lookup("job.strategy").expect("registered").status,
        ConstructStatus::Unsupported
    );
    assert!(ConstructStatus::Ambiguous.refuses());
    assert!(ConstructStatus::Unsupported.refuses());
    // ... and the accepted ones do not, so `refuses()` is not constant.
    assert!(!ConstructStatus::Accepted.refuses());
    assert!(!ConstructStatus::Normalized.refuses());
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    // The acceptance forbids a silent drop, and ignoring an unknown key is the
    // purest form of one: the workflow would run without doing what it says.
    let refusal = refuses_with(
        "name: ci\non: push\nnonsense: 1\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n",
        "field_unknown",
    );
    match &refusal {
        WorkflowRefusal::FieldUnknown { key, parent, .. } => {
            assert_eq!(&**key, "nonsense");
            assert_eq!(*parent, "a workflow");
        }
        other => panic!("expected FieldUnknown, got {other:?}"),
    }
}

#[test]
fn a_missing_required_field_and_a_wrong_shape_are_different_refusals() {
    let missing = refuses_with(
        "name: ci\non: push\njobs:\n  a:\n    steps:\n      - run: x\n",
        "field_missing",
    );
    assert!(missing.to_string().contains("runs-on"));

    let shape = refuses_with(
        "name: ci\non: push\njobs:\n  a:\n    runs-on:\n      - a\n      - b\n    steps:\n      - run: x\n",
        "field_shape",
    );
    assert!(shape.to_string().contains("must be a scalar"));
    assert_ne!(missing.kind(), shape.kind());
}

#[test]
fn an_unknown_need_and_a_cycle_are_refused_and_a_valid_chain_is_not() {
    let unknown = refuses_with(
        "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    needs: ghost\n    steps:\n      - run: x\n",
        "needs_unknown",
    );
    match &unknown {
        WorkflowRefusal::NeedsUnknown { job, needs, .. } => {
            assert_eq!(&**job, "a");
            assert_eq!(&**needs, "ghost");
        }
        other => panic!("expected NeedsUnknown, got {other:?}"),
    }

    let cycle = refuses_with(
        "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    needs: b\n    steps:\n      - run: x\n  b:\n    runs-on: linux\n    needs: a\n    steps:\n      - run: x\n",
        "needs_cycle",
    );
    match &cycle {
        WorkflowRefusal::NeedsCycle { cycle: members, .. } => {
            // Sorted, so two runs report the same members in the same order.
            assert_eq!(
                members.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
                vec!["a", "b"]
            );
        }
        other => panic!("expected NeedsCycle, got {other:?}"),
    }

    // PERMITTED TWIN: the same shape without the back edge is a valid chain.
    let chain = compile(
        "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n  b:\n    runs-on: linux\n    needs: a\n    steps:\n      - run: x\n",
        &Limits::DEFAULT,
    )
    .expect("an acyclic chain lowers");
    assert_eq!(chain.job_ids(), vec!["a", "b"]);
}

// -------------------------------------------------------------------- limits

#[test]
fn every_limit_refuses_above_the_bound_and_accepts_at_it() {
    // One axis per case. Tightening several bounds at once and then asserting
    // "it refused" cannot tell you WHICH bound fired -- my first version of
    // this test did exactly that and attributed a depth refusal to the scalar
    // limit. Each case now tightens one bound and leaves the rest at default.
    let doc = |scalar: &str| {
        format!(
            "name: {scalar}\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - run: x\n"
        )
    };

    // bytes
    let bounded = Limits {
        max_bytes: 64,
        ..Limits::DEFAULT
    };
    match compile(&doc("ci"), &bounded).expect_err("over the byte bound") {
        WorkflowRefusal::LimitExceeded {
            limit,
            allowed,
            observed,
            ..
        } => {
            assert_eq!(limit, "bytes");
            assert_eq!(allowed, 64);
            assert!(observed > allowed);
        }
        other => panic!("expected a byte limit, got {other:?}"),
    }
    compile(&doc("ci"), &Limits::DEFAULT).expect("accepted under the default byte bound");

    // scalar bytes: over refuses, exactly at the bound is accepted.
    let bounded = Limits {
        max_scalar_bytes: 16,
        ..Limits::DEFAULT
    };
    let over = compile(&doc(&"z".repeat(17)), &bounded).expect_err("over the scalar bound");
    match over {
        WorkflowRefusal::LimitExceeded {
            limit,
            allowed,
            observed,
            ..
        } => {
            assert_eq!(limit, "scalar bytes");
            assert_eq!(allowed, 16);
            assert_eq!(
                observed, 17,
                "off by one at the bound would be invisible without this"
            );
        }
        other => panic!("expected a scalar limit, got {other:?}"),
    }
    compile(&doc(&"z".repeat(16)), &bounded)
        .expect("a scalar EXACTLY at the bound is accepted, so the check is `>` not `>=`");

    // depth
    let bounded = Limits {
        max_depth: 4,
        ..Limits::DEFAULT
    };
    match compile(GOOD, &bounded).expect_err("the reference workflow is five deep") {
        WorkflowRefusal::LimitExceeded { limit, allowed, .. } => {
            assert_eq!(limit, "depth");
            assert_eq!(allowed, 4);
        }
        other => panic!("expected a depth limit, got {other:?}"),
    }
    compile(
        GOOD,
        &Limits {
            max_depth: 5,
            ..Limits::DEFAULT
        },
    )
    .expect("five is exactly deep enough for a step mapping");

    // lines
    let bounded = Limits {
        max_lines: 3,
        ..Limits::DEFAULT
    };
    assert_eq!(
        compile(GOOD, &bounded)
            .expect_err("over the line bound")
            .kind(),
        "limit_exceeded"
    );
    compile(GOOD, &Limits::DEFAULT).expect("accepted under the default line bound");

    // entries per mapping
    let bounded = Limits {
        max_entries: 1,
        ..Limits::DEFAULT
    };
    match compile(GOOD, &bounded).expect_err("the document has a mapping with three keys") {
        WorkflowRefusal::LimitExceeded { limit, allowed, .. } => {
            assert!(
                limit.contains("entries") || limit.contains("items"),
                "got {limit}"
            );
            assert_eq!(allowed, 1);
        }
        other => panic!("expected an entry limit, got {other:?}"),
    }
}

#[test]
fn the_node_budget_is_charged_before_the_node_is_built() {
    // A limit that fires after the allocation protects nothing. Setting the
    // node budget to 1 must refuse the second node, not the last one.
    let stingy = Limits {
        max_nodes: 1,
        ..Limits::DEFAULT
    };
    match compile(GOOD, &stingy).expect_err("one node is not enough") {
        WorkflowRefusal::LimitExceeded {
            limit,
            allowed,
            observed,
            ..
        } => {
            assert_eq!(limit, "nodes");
            assert_eq!(allowed, 1);
            assert_eq!(
                observed, 2,
                "the refusal fires on the SECOND node, not at the end"
            );
        }
        other => panic!("expected a node limit, got {other:?}"),
    }
    // Permitted twin: the default budget accepts the same document.
    compile(GOOD, &Limits::DEFAULT).expect("the default budget is sufficient");
}

// ------------------------------------------------------------------ registry

#[test]
fn the_construct_registry_is_sorted_complete_and_reasoned() {
    let keys: Vec<&str> = registry::CONSTRUCTS.iter().map(|c| c.key).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "the registry must stay in key order");

    let mut seen = std::collections::BTreeSet::new();
    for entry in registry::CONSTRUCTS {
        assert!(
            seen.insert(entry.key),
            "duplicate registry key {}",
            entry.key
        );
        assert!(!entry.reason.is_empty(), "{} has no reason", entry.key);
        assert!(
            entry.reason.len() > 20,
            "{}'s reason is too short to be one",
            entry.key
        );
    }

    let tally = registry::tally();
    let total: usize = tally.iter().map(|(_, count)| count).sum();
    assert_eq!(
        total,
        registry::CONSTRUCTS.len(),
        "the tally must account for every row"
    );
    // Both refusing statuses are populated, so the distinction is not
    // theoretical.
    for (status, count) in tally {
        assert!(count > 0, "{} has no rows", status.as_str());
    }
}

#[test]
fn every_construct_the_lowerer_names_exists_in_the_registry() {
    // The refusal text comes from the registry, so a key the lowerer invents
    // would silently produce "unregistered construct" instead of a reason.
    // These are every key any refusal path can name.
    for key in [
        "yaml.alias",
        "yaml.anchor",
        "yaml.block-scalar",
        "yaml.document-marker",
        "yaml.flow-mapping",
        "yaml.flow-sequence",
        "yaml.merge-key",
        "yaml.tab-indent",
        "yaml.tag",
        "job.container",
        "job.continue-on-error",
        "job.environment",
        "job.if",
        "job.outputs",
        "job.permissions",
        "job.services",
        "job.strategy",
        "job.timeout-minutes",
        "step.if",
        "step.uses",
        "step.with",
        "workflow.concurrency",
        "workflow.env",
        "workflow.secrets",
    ] {
        let entry = registry::lookup(key).unwrap_or_else(|| {
            panic!("{key} is named by the lowerer but absent from the registry")
        });
        assert!(
            entry.status.refuses(),
            "{key} is named in a refusal path but the registry marks it accepted"
        );
    }
}

// ------------------------------------------------------------------- goldens

#[test]
fn the_committed_workflow_golden_matches_the_lowering() {
    // The golden is produced by the repository-owned command, and the e2e suite
    // checks it through that command. Having both means a divergence between
    // the library path and the command path shows up as a disagreement rather
    // than as two green runs of the same code.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/workflow-goldens");
    let source = std::fs::read_to_string(dir.join("ci.workflow.yml")).expect("fixture present");
    let golden = std::fs::read_to_string(dir.join("ci.graph")).expect("golden present");
    let produced = compile(&source, &Limits::DEFAULT)
        .expect("the fixture is inside the subset")
        .canonical_bytes();
    assert_eq!(golden, produced, "the committed graph is stale");

    // The fixture lists `lint` before `build`, and the golden emits `build`
    // first. That is the topological order doing visible work rather than the
    // document happening to arrive already sorted.
    let build_at = golden.find("job\tbuild").expect("build is present");
    let lint_at = golden.find("job\tlint").expect("lint is present");
    assert!(
        build_at < lint_at,
        "a dependency must be emitted before its dependent"
    );
    assert!(
        source.find("  lint:").expect("in source") < source.find("  build:").expect("in source"),
        "the fixture must list them in the OPPOSITE order, or this proves nothing"
    );
}
