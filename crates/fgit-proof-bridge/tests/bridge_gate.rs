//! Evidence for the FG-041d exporter and its staleness gate.
//!
//! Every forbidden case is paired with the near-identical permitted one.

use std::path::{Path, PathBuf};

use fgit_proof_bridge::project::AbstractOp;
use fgit_proof_bridge::{
    ARTIFACT, BridgeRefusal, check, first_difference, project_corpus, render, write,
};

fn goldens() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("fgit-reference/tests/goldens")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fgit-proof-bridge-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

// ------------------------------------------------------------------- the gate

/// `check` must refuse a missing artifact and must not create one.
///
/// A gate that repairs what it finds cannot fail, and a gate that cannot fail is
/// decoration. The second assertion is the one that matters: it is what
/// distinguishes a refusal from a silent regeneration.
#[test]
fn check_refuses_a_missing_artifact_and_leaves_it_missing() {
    let rendered = render(&project_corpus(&goldens()).expect("corpus projects"));
    let dir = scratch("missing");

    match check(&dir, &rendered) {
        Err(BridgeRefusal::ArtifactMissing { path }) => {
            assert_eq!(path, dir.join(ARTIFACT));
        }
        other => panic!("a missing artifact must be refused, got {other:?}"),
    }
    assert!(
        !dir.join(ARTIFACT).exists(),
        "check must never write; a gate that repairs what it finds cannot fail"
    );

    // Permitted twin: the same directory once the artifact is written.
    write(&dir, &rendered).expect("writes");
    assert_eq!(check(&dir, &rendered), Ok(rendered.len()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Staleness names the first differing byte, not merely that something differs.
#[test]
fn a_stale_artifact_is_refused_at_its_first_differing_byte() {
    let rendered = render(&project_corpus(&goldens()).expect("corpus projects"));
    let dir = scratch("stale");
    write(&dir, &rendered).expect("writes");

    // A byte appended at the end differs exactly at the original length, which
    // is where the truncation of the shorter string begins.
    std::fs::write(dir.join(ARTIFACT), format!("{rendered}x")).expect("writes");
    match check(&dir, &rendered) {
        Err(BridgeRefusal::Stale { offset, .. }) => assert_eq!(offset, rendered.len()),
        other => panic!("an extended artifact must be stale, got {other:?}"),
    }

    // And a byte changed in the middle is reported there rather than at the end.
    let mut edited = rendered.clone().into_bytes();
    let middle = edited.len() / 2;
    edited[middle] = if edited[middle] == b'X' { b'Y' } else { b'X' };
    std::fs::write(dir.join(ARTIFACT), edited).expect("writes");
    match check(&dir, &rendered) {
        Err(BridgeRefusal::Stale { offset, .. }) => assert_eq!(offset, middle),
        other => panic!("an edited artifact must be stale, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn first_difference_reports_truncation_where_it_begins_and_nothing_for_equals() {
    assert_eq!(first_difference("abc", "abc"), None);
    assert_eq!(first_difference("abc", "abd"), Some(2));
    assert_eq!(first_difference("abc", "ab"), Some(2));
    assert_eq!(first_difference("ab", "abc"), Some(2));
    assert_eq!(first_difference("", "a"), Some(0));
}

/// The generator is a pure function of its inputs.
///
/// Without this, a clock, a hostname or a tool version in the output would make
/// every `check` fail for reasons unrelated to the corpus, and the gate would be
/// abandoned rather than trusted.
#[test]
fn rendering_the_same_corpus_twice_is_byte_identical() {
    let once = render(&project_corpus(&goldens()).expect("corpus projects"));
    let twice = render(&project_corpus(&goldens()).expect("corpus projects"));
    assert_eq!(first_difference(&once, &twice), None);
}

#[test]
fn corpus_replay_checks_the_full_recorded_head_before_projection() {
    use fgit_proof_bridge::{CorpusRefusal, project};
    use fgit_reference::trace::{DivergenceKind, decode, encode};
    use fgit_types::DecisionSequence;

    let dir = scratch("replay");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("simple_commit.fgtrace");
    let bytes = std::fs::read(goldens().join("simple_commit.fgtrace")).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let expected = project_corpus(&dir).unwrap();
    assert_eq!(
        project("simple_commit", &decode(&bytes).unwrap()).unwrap(),
        expected[0]
    );

    let mut changed = decode(&bytes).unwrap();
    let last = changed.steps.len() - 1;
    let decision = &mut changed.steps[last].head.latest_decision_sequence;
    assert_eq!(*decision, Some(DecisionSequence::FIRST));
    *decision = Some(DecisionSequence::try_new(2).unwrap());
    assert!(matches!(
        project("simple_commit", &changed),
        Err(fgit_proof_bridge::ProjectionRefusal::Diverged {
            concrete_index, kind: DivergenceKind::Head,
        }) if concrete_index == last
    ));
    std::fs::write(&path, encode(&changed).unwrap()).unwrap();
    assert_eq!(
        project_corpus(&dir),
        Err(CorpusRefusal::Diverged {
            golden: "simple_commit".to_owned(),
            step_index: last,
            kind: DivergenceKind::Head,
        })
    );
    std::fs::remove_dir_all(dir).unwrap();
}

// -------------------------------------------------------------- the projection

/// The corpus must actually exercise the abstract operations it claims to.
///
/// This is the assertion that earned its place: the first version of the
/// projection emitted ZERO `decide` operations, because these goldens never use
/// `ModelInput::Decide` — a decision becomes canonical at the head CAS, not at a
/// separate decide step. The vectors compiled, the gate passed, and they proved
/// nothing about any outcome theorem. A census is the only thing that notices
/// that, because every other check is happy with a file full of stutters.
#[test]
fn the_projected_corpus_exercises_seals_publications_and_outcomes() {
    let corpus = project_corpus(&goldens()).expect("corpus projects");
    assert!(!corpus.is_empty(), "the golden corpus must not be empty");

    let mut seals = 0_usize;
    let mut decides = 0_usize;
    let mut publishes = 0_usize;
    let mut interrupted = 0_usize;
    let mut retries = 0_usize;
    let mut ref_effect_publications = 0_usize;
    let mut forge_effect_publications = 0_usize;
    for trace in &corpus {
        for step in &trace.steps {
            for op in &step.operations {
                match op {
                    AbstractOp::SealRequest { .. } => seals += 1,
                    AbstractOp::Decide { .. } => decides += 1,
                    AbstractOp::Publish {
                        ref_effects,
                        forge_effects,
                        ..
                    } => {
                        publishes += 1;
                        if !ref_effects.is_empty() {
                            ref_effect_publications += 1;
                        }
                        if !forge_effects.is_empty() {
                            forge_effect_publications += 1;
                        }
                    }
                    // A re-decide against an already-terminal transaction.
                    AbstractOp::Retry { .. } => retries += 1,
                    AbstractOp::InterruptedPublication { .. } => interrupted += 1,
                }
            }
        }
    }
    assert!(
        seals > 0,
        "no sealRequest projected: the vectors say nothing about sealing"
    );
    assert!(
        decides > 0,
        "no decide projected: the vectors say nothing about any outcome theorem"
    );
    assert!(
        publishes > 0,
        "no publish projected: the vectors say nothing about head continuity"
    );
    assert!(
        interrupted > 0,
        "no interruptedPublication projected: the vectors say nothing about anti-rollback"
    );
    assert!(
        retries > 0,
        "no retry projected: the vectors say nothing about a duplicate decision \
         against an already-terminal transaction"
    );
    assert!(
        ref_effect_publications > 0,
        "no publication carries ref effects: the atomic-visibility data path is unexercised"
    );
    assert!(
        forge_effect_publications > 0,
        "no publication carries forge effects: the atomic-visibility data path is unexercised"
    );
}

/// A won publication decides the capsules its batch staged, in that order.
///
/// The order is load-bearing rather than cosmetic: Lean's `decide` only records
/// an outcome for a target that is already sealed, and the publication is why
/// the decision is canonical at all. Emitting the decide first would describe a
/// machine where outcomes precede the head movement that makes them true.
#[test]
fn a_won_publication_publishes_before_it_decides() {
    let corpus = project_corpus(&goldens()).expect("corpus projects");
    let mut checked = 0_usize;
    for trace in &corpus {
        for step in &trace.steps {
            if step.operations.len() > 1 {
                assert!(
                    matches!(step.operations[0], AbstractOp::Publish { .. }),
                    "a multi-operation step must lead with its publication"
                );
                assert!(
                    step.operations[1..]
                        .iter()
                        .all(|op| matches!(op, AbstractOp::Decide { .. })),
                    "only decisions may follow a publication within one step"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 0,
        "the corpus must contain a won publication that decided something"
    );
}

/// Both labels must survive one atomic publication, even when the batch's
/// repository sequence advanced by one and its decision sequence by two.
#[test]
fn mixed_batch_exports_both_ordered_terminal_decisions() {
    use fgit_proof_bridge::AbstractOutcome::{Committed, Refused};

    let corpus = project_corpus(&goldens()).expect("replayed corpus");
    let mixed = corpus
        .iter()
        .find(|trace| trace.name == "multi_decision_batch")
        .unwrap();
    let last = mixed.steps.last().unwrap();
    assert!(matches!(
        last.operations.as_slice(),
        [
            AbstractOp::Publish { .. },
            AbstractOp::Decide {
                target: 0,
                outcome: Committed
            },
            AbstractOp::Decide {
                target: 1,
                outcome: Refused
            }
        ]
    ));
    assert_eq!(last.decision_sequence_after, 2);
    assert_eq!(last.repository_sequence_after, 1);
}

/// Stuttering steps keep their concrete index, so a divergence names a real step.
#[test]
fn stuttering_steps_are_kept_rather_than_dropped() {
    let corpus = project_corpus(&goldens()).expect("corpus projects");
    let mut stutters = 0_usize;
    for trace in &corpus {
        for (position, step) in trace.steps.iter().enumerate() {
            assert_eq!(
                step.concrete_index, position,
                "step indices must stay dense and aligned with the concrete trace"
            );
            if step.operations.is_empty() {
                stutters += 1;
            }
        }
    }
    // Corpus-wide, not per trace. An earlier version required EVERY history to
    // stutter and failed on one that happens not to -- which conflated "the
    // projection preserves stutters" with "every history has one". Only the
    // first is a property of this code.
    assert!(
        stutters > 0,
        "the concrete model has steps the residue does not observe; dropping them \
         would silently renumber every later step"
    );
}
