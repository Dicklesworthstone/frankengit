#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_cli::{AtReport, CliOutcome, CliRefusal, run};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const ACTOR: &str = "33333333333333333333333333333333";

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frankengit-fg-at-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }

    fn root(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[test]
fn fg_at_summary_on_initialized_node() {
    let scratch = Scratch::new();
    let init_args = words(&["init", &scratch.root(), TENANT, REPOSITORY]);
    assert!(matches!(run(&init_args), Ok(CliOutcome::Initialized(_))));

    // Query latest summary
    let at_args = words(&["at", &scratch.root(), TENANT, REPOSITORY, "latest"]);
    let outcome = run(&at_args).expect("fg at latest succeeds");
    match outcome {
        CliOutcome::At(AtReport::Summary {
            target,
            refs_count,
            prs_count,
            ..
        }) => {
            assert_eq!(target, "latest");
            assert_eq!(refs_count, 0);
            assert_eq!(prs_count, 0);
        }
        other => panic!("expected AtReport::Summary, got {other:?}"),
    }
}

#[test]
fn fg_at_refs_and_prs_subcommands() {
    let scratch = Scratch::new();
    let init_args = words(&["init", &scratch.root(), TENANT, REPOSITORY]);
    assert!(matches!(run(&init_args), Ok(CliOutcome::Initialized(_))));

    // Query refs
    let refs_args = words(&["at", &scratch.root(), TENANT, REPOSITORY, "latest", "refs"]);
    let outcome = run(&refs_args).expect("fg at latest refs succeeds");
    match outcome {
        CliOutcome::At(AtReport::Refs { position, refs }) => {
            assert_eq!(position, "latest");
            assert_eq!(refs, [] as [(std::string::String, std::string::String); 0]);
        }
        other => panic!("expected AtReport::Refs, got {other:?}"),
    }

    // Query prs
    let prs_args = words(&["at", &scratch.root(), TENANT, REPOSITORY, "latest", "prs"]);
    let outcome = run(&prs_args).expect("fg at latest prs succeeds");
    match outcome {
        CliOutcome::At(AtReport::PullRequests {
            position,
            pull_requests,
        }) => {
            assert_eq!(position, "latest");
            assert_eq!(
                pull_requests,
                [] as [(
                    u64,
                    std::string::String,
                    std::string::String,
                    std::string::String
                ); 0]
            );
        }
        other => panic!("expected AtReport::PullRequests, got {other:?}"),
    }
}

#[test]
fn fg_at_diff_subcommand() {
    let scratch = Scratch::new();
    let init_args = words(&["init", &scratch.root(), TENANT, REPOSITORY]);
    assert!(matches!(run(&init_args), Ok(CliOutcome::Initialized(_))));

    // Query diff between latest and decision:1
    let diff_args = words(&[
        "at",
        &scratch.root(),
        TENANT,
        REPOSITORY,
        "latest",
        "diff",
        "decision:1",
    ]);
    let outcome = run(&diff_args).expect("fg at diff succeeds");
    match outcome {
        CliOutcome::At(AtReport::Diff {
            older,
            newer,
            ref_changes_count,
            pr_changes_count,
        }) => {
            assert_eq!(older, "latest");
            assert_eq!(newer, "decision:1");
            assert_eq!(ref_changes_count, 0);
            assert_eq!(pr_changes_count, 0);
        }
        other => panic!("expected AtReport::Diff, got {other:?}"),
    }
}

#[test]
fn fg_at_actor_disclosure_filter() {
    let scratch = Scratch::new();
    let init_args = words(&["init", &scratch.root(), TENANT, REPOSITORY]);
    assert!(matches!(run(&init_args), Ok(CliOutcome::Initialized(_))));

    // Query with actor flag
    let actor_args = words(&[
        "at",
        &scratch.root(),
        TENANT,
        REPOSITORY,
        "latest",
        "--actor",
        ACTOR,
    ]);
    let outcome = run(&actor_args).expect("fg at with actor succeeds");
    match outcome {
        CliOutcome::At(AtReport::Summary { refs_count, .. }) => {
            assert_eq!(refs_count, 0);
        }
        other => panic!("expected AtReport::Summary, got {other:?}"),
    }
}

#[test]
fn fg_at_invalid_position_refusal() {
    let scratch = Scratch::new();
    let init_args = words(&["init", &scratch.root(), TENANT, REPOSITORY]);
    assert!(matches!(run(&init_args), Ok(CliOutcome::Initialized(_))));

    // Invalid position string
    let bad_pos_args = words(&[
        "at",
        &scratch.root(),
        TENANT,
        REPOSITORY,
        "not_a_valid_position",
    ]);
    match run(&bad_pos_args) {
        Err(CliRefusal::InvalidPosition(pos)) => {
            assert_eq!(pos, "not_a_valid_position");
        }
        other => panic!("expected CliRefusal::InvalidPosition, got {other:?}"),
    }
}

#[test]
fn fg_at_usage_refusal_when_insufficient_args() {
    let scratch = Scratch::new();
    let insufficient = words(&["at", &scratch.root(), TENANT]);
    assert!(matches!(run(&insufficient), Err(CliRefusal::Usage)));
}
