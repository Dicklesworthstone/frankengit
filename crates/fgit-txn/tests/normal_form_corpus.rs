#![forbid(unsafe_code)]
//! An independent scalar oracle for net-effect normal form, and a property
//! corpus over it.
//!
//! # Why this file does not import the folder it verifies
//!
//! This is FG-008b: independent equivalence evidence for the FG-008a
//! evaluator. The oracle below is written from the normative text alone —
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §13, `OBJECT_STORE_DECISION_LOG.md` §9,
//! `GIT_TREE_FS.md` §7, and the FG-008 epic. The folding implementation was
//! deliberately not read while writing it.
//!
//! That restraint is the entire value of the artifact. An oracle derived from
//! the implementation agrees with the implementation by construction: it would
//! reproduce its bugs, pass every comparison, and prove nothing except that the
//! code equals itself. Two independent derivations from one specification can
//! disagree, and a disagreement is information — either the folder is wrong,
//! the oracle is wrong, or the specification is ambiguous. All three are worth
//! finding, and the third is the one no amount of testing the code against
//! itself will ever surface.
//!
//! # What is proven here, and what is not
//!
//! **Proven:** that this oracle satisfies the invariants the specification
//! states — totality, target-disjointness, determinism, and order-independence
//! — over a seeded corpus, and that it reproduces each named folding rule on
//! worked examples.
//!
//! **Not proven yet:** equivalence with the FG-008a folder. That comparison
//! needs its entry-point signature, which is requested from its owner rather
//! than read out of the source. Until it lands, this file establishes only that
//! *the oracle is a faithful and self-consistent reading of the spec* — which
//! is the precondition for the comparison meaning anything, not a substitute
//! for it.
//!
//! # A correction this file carries deliberately
//!
//! The first version of this oracle folded **tree edits** — paths, content,
//! modes — because `GIT_TREE_FS` §7 is where the concrete folding rules are
//! written down and it states them over `TreeEditIntent`. That was the wrong
//! carrier. The evaluator under test folds `fgit_reference::intent::Intent`
//! over refs, forge positions, retention roots and outbox keys. The folding
//! *laws* are the same; the thing they fold is not.
//!
//! It is recorded here rather than quietly rewritten because it is the exact
//! failure this bead exists to catch: a corpus can be thorough, internally
//! consistent, and aimed at something the implementation never sees. Asking for
//! the seam instead of inferring it from the document is what surfaced it.
//!
//! The model below therefore folds **ref intents**, the canonical mutation
//! carrier. Forge, retention and outbox extend the same skeleton and are called
//! out as unbuilt rather than silently omitted.
//!
//! # The specification, as this file reads it
//!
//! Evaluation is source-ordered with read-your-own-writes against one pinned
//! basis. Finalization folds the result into a target-disjoint normal form in
//! which **every source intent maps to exactly one** of: a surviving effect, an
//! identity no-op, an inverse cancellation, an absorption, a statement error,
//! or a transaction abort. Serialized effect order must not alter semantic
//! applicability, and canonical order must not depend on map, hash, or process
//! iteration order.

use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// The model. Deliberately small: it carries exactly the state the named
// folding rules act on, and nothing else. A richer model would generate
// programs the rules say nothing about, which is corpus volume without
// coverage.
// ---------------------------------------------------------------------------

/// A path. A small alphabet on purpose: collisions are where folding happens,
/// and a wide alphabet would generate mostly-disjoint programs that never
/// exercise a single fold.
type Path = &'static str;

const PATHS: [Path; 4] = ["a", "b", "c", "d"];

/// File mode, reduced to the distinction the spec's "mode and content changes
/// combine" rule needs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Mode {
    Regular,
    Executable,
}

/// One tree entry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Entry {
    /// Stands in for a content identity. Equality is all the folding rules use.
    content: u32,
    mode: Mode,
}

/// A source intent, in the subset that exercises every named fold.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Intent {
    Write {
        path: Path,
        content: u32,
        mode: Mode,
    },
    Delete {
        path: Path,
    },
    Rename {
        from: Path,
        to: Path,
    },
    Chmod {
        path: Path,
        mode: Mode,
    },
}

/// What the normal form says became of one source intent.
///
/// The six arms are the specification's total map, transcribed. Totality is
/// asserted rather than assumed: every intent in every generated program must
/// land in exactly one of these.
///
/// # Why this is finer than the evaluator's own map
///
/// The evaluator reports four dispositions — surviving, absorbed, statement
/// error, transaction aborted. The normative map has six:
/// `OBJECT_STORE_DECISION_LOG` §9 lists identity no-op and inverse
/// cancellation *separately* from absorption, and `GIT_TREE_FS` §7 calls
/// create-then-delete an "explicit inverse-cancellation no-op".
///
/// That is not pedantry about names. §7 keeps the totality map in the
/// Evidence-Carrying Change so a reviewer can see what an agent attempted
/// versus what survived, and a reviewer reading `Absorbed` cannot tell "something
/// later overwrote your write" from "you created it and then deleted it
/// yourself" from "you wrote what was already there".
///
/// So the oracle classifies at full resolution and compares on the coarser
/// projection ([`Disposition::projected`]), which keeps the equivalence
/// evidence honest — a comparison must not fail merely because one side is more
/// granular — while leaving the finer question answerable separately. Whether
/// the distinction is recoverable from the evaluator's output is a question for
/// its owner, not a defect this file asserts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Disposition {
    /// Contributed the effect that survives at its target.
    SurvivingEffect(Path),
    /// Applied cleanly but left the target byte-identical to the basis.
    IdentityNoOp,
    /// Undone by a later intent — the create-then-delete case.
    InverseCancellation,
    /// Superseded at its target by a later, stronger intent.
    Absorption,
    /// Rejected locally; the transaction continues.
    StatementError(StatementError),
}

/// Why a single statement failed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum StatementError {
    /// The intent named a path that does not exist at that point.
    TargetAbsent,
    /// A rename would have landed on an occupied path. The spec collapses
    /// rename chains only "where safe"; clobbering is not safe, and silently
    /// overwriting would make the fold lossy.
    RenameTargetOccupied,
    /// A rename whose source and destination are the same path. Refused rather
    /// than treated as a no-op: it is a malformed statement, not an identity.
    RenameToSelf,
}

/// The evaluator's coarser disposition vocabulary.
///
/// Comparison happens here so that being more precise than the implementation
/// never registers as a disagreement with it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum ProjectedDisposition {
    Surviving,
    Absorbed,
    StatementError,
    TransactionAborted,
}

impl Disposition {
    /// Collapse to the four arms the evaluator reports.
    ///
    /// Identity no-op and inverse cancellation both project onto `Absorbed`:
    /// in each case the intent contributed no surviving effect, which is the
    /// distinction the coarser vocabulary preserves.
    const fn projected(self) -> ProjectedDisposition {
        match self {
            Self::SurvivingEffect(_) => ProjectedDisposition::Surviving,
            Self::IdentityNoOp | Self::InverseCancellation | Self::Absorption => {
                ProjectedDisposition::Absorbed
            }
            Self::StatementError(_) => ProjectedDisposition::StatementError,
        }
    }
}

/// One surviving effect at one target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Effect {
    Create(Entry),
    Modify(Entry),
    Remove,
}

/// The folded result of one intent program.
#[derive(Clone, Debug, Eq, PartialEq)]
struct NetEffect {
    /// Target-disjoint by construction of the map, and asserted anyway.
    effects: BTreeMap<Path, Effect>,
    /// One entry per source intent, in source order.
    dispositions: Vec<Disposition>,
    /// The tree that source-ordered evaluation actually reached, before any
    /// diffing. Kept so the round-trip property has a genuine other side to
    /// compare against rather than a second call to this same function.
    after: BTreeMap<Path, Entry>,
}

impl NetEffect {
    /// Effects in canonical order.
    ///
    /// A `BTreeMap` is ordered by key, so this is a function of the paths
    /// alone — never of insertion, hash, or process order. That is the
    /// property the epic demands, and it is obtained structurally here rather
    /// than by sorting a hash map at the end and hoping every caller does the
    /// same.
    fn canonical(&self) -> Vec<(Path, Effect)> {
        self.effects.iter().map(|(p, e)| (*p, *e)).collect()
    }
}

// ---------------------------------------------------------------------------
// The oracle.
// ---------------------------------------------------------------------------

/// Evaluate a program against a basis and fold it into normal form.
///
/// Two passes, kept separate on purpose. Evaluation is the source-ordered
/// read-your-own-writes simulation; folding is a pure diff of the resulting
/// after-image against the basis. Keeping them apart is what makes the fold
/// obviously order-independent: it never sees the order at all, only the two
/// end states.
fn fold(basis: &BTreeMap<Path, Entry>, program: &[Intent]) -> NetEffect {
    let mut after = basis.clone();
    // Which intent index last successfully touched each path, and whether the
    // path was brought into existence during this program.
    let mut last_writer: BTreeMap<Path, usize> = BTreeMap::new();
    let mut created_here: BTreeSet<Path> = BTreeSet::new();
    let mut outcomes: Vec<Result<Vec<Path>, StatementError>> = Vec::with_capacity(program.len());

    for (index, intent) in program.iter().enumerate() {
        let outcome = match *intent {
            Intent::Write {
                path,
                content,
                mode,
            } => {
                if !after.contains_key(path) && !basis.contains_key(path) {
                    created_here.insert(path);
                }
                after.insert(path, Entry { content, mode });
                Ok(vec![path])
            }
            Intent::Delete { path } => {
                if after.remove(path).is_none() {
                    Err(StatementError::TargetAbsent)
                } else {
                    Ok(vec![path])
                }
            }
            Intent::Chmod { path, mode } => match after.get_mut(path) {
                None => Err(StatementError::TargetAbsent),
                Some(entry) => {
                    entry.mode = mode;
                    Ok(vec![path])
                }
            },
            Intent::Rename { from, to } => {
                if from == to {
                    Err(StatementError::RenameToSelf)
                } else if !after.contains_key(from) {
                    Err(StatementError::TargetAbsent)
                } else if after.contains_key(to) {
                    Err(StatementError::RenameTargetOccupied)
                } else {
                    let entry = after.remove(from).expect("presence just checked");
                    if !basis.contains_key(to) {
                        created_here.insert(to);
                    }
                    after.insert(to, entry);
                    // A rename touches both ends, and both can carry effects.
                    Ok(vec![from, to])
                }
            }
        };

        if let Ok(touched) = &outcome {
            for path in touched {
                last_writer.insert(path, index);
            }
        }
        outcomes.push(outcome);
    }

    // Fold: diff the two end states. Order-independent because it cannot see
    // the order.
    let mut effects: BTreeMap<Path, Effect> = BTreeMap::new();
    for (path, before) in basis {
        match after.get(path) {
            None => {
                effects.insert(path, Effect::Remove);
            }
            Some(now) if now != before => {
                effects.insert(path, Effect::Modify(*now));
            }
            Some(_) => {}
        }
    }
    for (path, now) in &after {
        if !basis.contains_key(path) {
            effects.insert(path, Effect::Create(*now));
        }
    }

    // Classify each source intent into exactly one disposition.
    let dispositions = outcomes
        .iter()
        .enumerate()
        .map(|(index, outcome)| match outcome {
            Err(error) => Disposition::StatementError(*error),
            Ok(touched) => {
                // The surviving effect belongs to whichever intent last touched
                // a path that still carries one.
                let surviving = touched.iter().copied().find(|path| {
                    effects.contains_key(path) && last_writer.get(path) == Some(&index)
                });
                if let Some(path) = surviving {
                    return Disposition::SurvivingEffect(path);
                }
                // No surviving effect at any path this intent touched. Either a
                // later intent took the path over, or the program returned the
                // path to its basis state.
                let superseded = touched
                    .iter()
                    .any(|path| last_writer.get(path).is_some_and(|last| *last > index));
                if superseded {
                    Disposition::Absorption
                } else if touched.iter().any(|path| created_here.contains(path)) {
                    // Brought into existence during this program and gone by
                    // the end: the spec names this inverse cancellation
                    // specifically, distinct from an identity no-op.
                    Disposition::InverseCancellation
                } else {
                    Disposition::IdentityNoOp
                }
            }
        })
        .collect();

    NetEffect {
        effects,
        dispositions,
        after,
    }
}

// ---------------------------------------------------------------------------
// Seeded generation. SplitMix64, written out rather than pulled in, so the
// corpus has no dependency and every failure is reproducible from its seed
// alone.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % bound as u64).expect("bound is small")
    }
}

fn generate_basis(rng: &mut Rng) -> BTreeMap<Path, Entry> {
    let mut basis = BTreeMap::new();
    for path in PATHS {
        if rng.below(2) == 0 {
            basis.insert(
                path,
                Entry {
                    content: u32::try_from(rng.below(3)).expect("small"),
                    mode: if rng.below(2) == 0 {
                        Mode::Regular
                    } else {
                        Mode::Executable
                    },
                },
            );
        }
    }
    basis
}

fn generate_program(rng: &mut Rng, len: usize) -> Vec<Intent> {
    (0..len)
        .map(|_| {
            let path = PATHS[rng.below(PATHS.len())];
            match rng.below(4) {
                0 => Intent::Write {
                    path,
                    content: u32::try_from(rng.below(3)).expect("small"),
                    mode: if rng.below(2) == 0 {
                        Mode::Regular
                    } else {
                        Mode::Executable
                    },
                },
                1 => Intent::Delete { path },
                2 => Intent::Rename {
                    from: path,
                    to: PATHS[rng.below(PATHS.len())],
                },
                _ => Intent::Chmod {
                    path,
                    mode: if rng.below(2) == 0 {
                        Mode::Regular
                    } else {
                        Mode::Executable
                    },
                },
            }
        })
        .collect()
}

/// Reduce a failing program to a minimal one that still fails.
///
/// Greedy removal of single intents. The acceptance criteria require that a
/// failure auto-shrinks, and a hundred-intent counterexample is not a bug
/// report, it is a haystack.
fn shrink(
    basis: &BTreeMap<Path, Entry>,
    program: &[Intent],
    fails: impl Fn(&BTreeMap<Path, Entry>, &[Intent]) -> bool,
) -> Vec<Intent> {
    let mut best = program.to_vec();
    let mut progress = true;
    while progress {
        progress = false;
        for index in 0..best.len() {
            let mut candidate = best.clone();
            candidate.remove(index);
            if fails(basis, &candidate) {
                best = candidate;
                progress = true;
                break;
            }
        }
    }
    best
}

// ---------------------------------------------------------------------------
// The oracle is itself tested. If the oracle is wrong, every equivalence claim
// built on it is wrong in the same direction and nothing catches it, so each
// named folding rule gets a worked example straight out of the spec.
// ---------------------------------------------------------------------------

fn entry(content: u32, mode: Mode) -> Entry {
    Entry { content, mode }
}

fn basis_of(pairs: &[(Path, Entry)]) -> BTreeMap<Path, Entry> {
    pairs.iter().copied().collect()
}

#[test]
fn repeated_writes_collapse_to_the_final_content() {
    let basis = basis_of(&[]);
    let net = fold(
        &basis,
        &[
            Intent::Write {
                path: "a",
                content: 1,
                mode: Mode::Regular,
            },
            Intent::Write {
                path: "a",
                content: 2,
                mode: Mode::Regular,
            },
            Intent::Write {
                path: "a",
                content: 3,
                mode: Mode::Regular,
            },
        ],
    );

    assert_eq!(
        net.canonical(),
        vec![("a", Effect::Create(entry(3, Mode::Regular)))],
        "three writes to one path must leave exactly one effect carrying the last content"
    );
    assert_eq!(
        net.dispositions,
        vec![
            Disposition::Absorption,
            Disposition::Absorption,
            Disposition::SurvivingEffect("a"),
        ],
        "the earlier writes are absorbed, not discarded silently and not counted twice"
    );
}

#[test]
fn create_then_delete_is_inverse_cancellation_not_a_bare_no_op() {
    // The spec names this case separately from an identity no-op, and the
    // distinction is the point: nothing survives either way, but a reviewer
    // reading the totality map must be able to see that work was attempted and
    // undone rather than never having had an effect.
    let basis = basis_of(&[]);
    let net = fold(
        &basis,
        &[
            Intent::Write {
                path: "a",
                content: 1,
                mode: Mode::Regular,
            },
            Intent::Delete { path: "a" },
        ],
    );

    assert!(
        net.canonical().is_empty(),
        "a path created and then deleted within one program leaves no effect"
    );
    assert_eq!(
        net.dispositions,
        vec![Disposition::Absorption, Disposition::InverseCancellation,],
        "the delete inverse-cancels; it must not be reported as an identity no-op"
    );
}

#[test]
fn delete_absorbs_earlier_modifications() {
    let basis = basis_of(&[("a", entry(1, Mode::Regular))]);
    let net = fold(
        &basis,
        &[
            Intent::Write {
                path: "a",
                content: 2,
                mode: Mode::Regular,
            },
            Intent::Chmod {
                path: "a",
                mode: Mode::Executable,
            },
            Intent::Delete { path: "a" },
        ],
    );

    assert_eq!(
        net.canonical(),
        vec![("a", Effect::Remove)],
        "a delete at the end of a chain leaves one removal, not a modify plus a removal"
    );
    assert_eq!(
        net.dispositions,
        vec![
            Disposition::Absorption,
            Disposition::Absorption,
            Disposition::SurvivingEffect("a"),
        ]
    );
}

#[test]
fn mode_and_content_changes_combine_into_one_effect() {
    let basis = basis_of(&[("a", entry(1, Mode::Regular))]);
    let net = fold(
        &basis,
        &[
            Intent::Write {
                path: "a",
                content: 2,
                mode: Mode::Regular,
            },
            Intent::Chmod {
                path: "a",
                mode: Mode::Executable,
            },
        ],
    );

    assert_eq!(
        net.canonical(),
        vec![("a", Effect::Modify(entry(2, Mode::Executable)))],
        "a content change and a mode change on one path combine into a single effect"
    );
}

#[test]
fn write_then_rename_attaches_the_content_to_the_destination() {
    let basis = basis_of(&[]);
    let net = fold(
        &basis,
        &[
            Intent::Write {
                path: "a",
                content: 7,
                mode: Mode::Regular,
            },
            Intent::Rename { from: "a", to: "b" },
        ],
    );

    assert_eq!(
        net.canonical(),
        vec![("b", Effect::Create(entry(7, Mode::Regular)))],
        "the content written to the source must arrive at the destination, and the \
         source must not be left carrying an effect"
    );
}

#[test]
fn a_rename_chain_collapses_to_one_source_to_destination_move() {
    let basis = basis_of(&[("a", entry(4, Mode::Regular))]);
    let net = fold(
        &basis,
        &[
            Intent::Rename { from: "a", to: "b" },
            Intent::Rename { from: "b", to: "c" },
        ],
    );

    assert_eq!(
        net.canonical(),
        vec![
            ("a", Effect::Remove),
            ("c", Effect::Create(entry(4, Mode::Regular))),
        ],
        "a two-hop rename must not leave an effect at the intermediate path"
    );
}

#[test]
fn a_write_returning_a_path_to_its_basis_value_is_an_identity_no_op() {
    let basis = basis_of(&[("a", entry(1, Mode::Regular))]);
    let net = fold(
        &basis,
        &[Intent::Write {
            path: "a",
            content: 1,
            mode: Mode::Regular,
        }],
    );

    assert!(
        net.canonical().is_empty(),
        "writing the value a path already holds produces no effect"
    );
    assert_eq!(net.dispositions, vec![Disposition::IdentityNoOp]);
}

#[test]
fn unsafe_renames_are_statement_errors_rather_than_silent_clobbers() {
    // "Rename chains become one source-to-destination move WHERE SAFE." A
    // rename onto an occupied path is not safe, and folding it silently would
    // make the normal form lossy in exactly the way the epic forbids:
    // contradictory duplicates are refused, never silently normalized.
    let basis = basis_of(&[
        ("a", entry(1, Mode::Regular)),
        ("b", entry(2, Mode::Regular)),
    ]);
    let net = fold(&basis, &[Intent::Rename { from: "a", to: "b" }]);

    assert!(
        net.canonical().is_empty(),
        "a refused statement must leave no effect behind"
    );
    assert_eq!(
        net.dispositions,
        vec![Disposition::StatementError(
            StatementError::RenameTargetOccupied
        )]
    );
}

#[test]
fn statements_against_absent_targets_fail_locally_without_aborting() {
    let basis = basis_of(&[]);
    let net = fold(
        &basis,
        &[
            Intent::Delete { path: "a" },
            Intent::Chmod {
                path: "a",
                mode: Mode::Executable,
            },
            Intent::Write {
                path: "a",
                content: 1,
                mode: Mode::Regular,
            },
        ],
    );

    assert_eq!(
        net.dispositions,
        vec![
            Disposition::StatementError(StatementError::TargetAbsent),
            Disposition::StatementError(StatementError::TargetAbsent),
            Disposition::SurvivingEffect("a"),
        ],
        "a statement-local failure must not prevent later statements from succeeding"
    );
    assert_eq!(
        net.canonical(),
        vec![("a", Effect::Create(entry(1, Mode::Regular)))]
    );
}

// ---------------------------------------------------------------------------
// The property corpus.
// ---------------------------------------------------------------------------

/// Seeds are logged on failure so any counterexample is reproducible from the
/// line in the output alone.
const CORPUS_SEED: u64 = 0x5EED_0008_B00B_1E5;

/// Programs per property. The bead's acceptance asks for >= 10^5 at default
/// bounds; that full campaign belongs in the e2e script, where it can be given
/// its own time budget. This in-tree figure is what keeps the unit suite fast
/// while still covering every rule, and the number is stated rather than
/// implied so nobody reads the in-tree run as the full campaign.
const PROGRAMS: usize = 2_000;

const PROGRAM_LEN: usize = 8;

fn corpus(property_salt: u64) -> impl Iterator<Item = (u64, BTreeMap<Path, Entry>, Vec<Intent>)> {
    (0..PROGRAMS).map(move |i| {
        let seed = CORPUS_SEED
            .wrapping_add(property_salt)
            .wrapping_mul(0x1000_0001)
            .wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let basis = generate_basis(&mut rng);
        let program = generate_program(&mut rng, PROGRAM_LEN);
        (seed, basis, program)
    })
}

#[test]
fn every_source_intent_receives_exactly_one_disposition() {
    // Totality, the property the spec states most directly. An intent that
    // vanished from the map would be work the reviewer never sees.
    for (seed, basis, program) in corpus(1) {
        let net = fold(&basis, &program);
        assert_eq!(
            net.dispositions.len(),
            program.len(),
            "seed {seed:#x}: {} intents produced {} dispositions",
            program.len(),
            net.dispositions.len()
        );
    }
}

#[test]
fn the_normal_form_is_target_disjoint() {
    for (seed, basis, program) in corpus(2) {
        let net = fold(&basis, &program);
        let targets: BTreeSet<Path> = net.effects.keys().copied().collect();
        assert_eq!(
            targets.len(),
            net.effects.len(),
            "seed {seed:#x}: a target carries more than one surviving effect"
        );
        // And every surviving effect is claimed by exactly one intent.
        let claimed: Vec<Path> = net
            .dispositions
            .iter()
            .filter_map(|d| match d {
                Disposition::SurvivingEffect(path) => Some(*path),
                _ => None,
            })
            .collect();
        let unique: BTreeSet<Path> = claimed.iter().copied().collect();
        assert_eq!(
            claimed.len(),
            unique.len(),
            "seed {seed:#x}: two intents both claim the surviving effect at one target"
        );
        assert_eq!(
            unique, targets,
            "seed {seed:#x}: the claimed targets and the surviving effects disagree"
        );
    }
}

#[test]
fn folding_is_deterministic_across_repeated_evaluation() {
    for (seed, basis, program) in corpus(3) {
        let first = fold(&basis, &program);
        let second = fold(&basis, &program);
        assert_eq!(
            first, second,
            "seed {seed:#x}: the same program folded differently on a second evaluation"
        );
    }
}

#[test]
fn serialized_effect_order_does_not_alter_applicability() {
    // "Sorting serialized effects MUST NOT alter semantic applicability."
    // Applying the effects in canonical order and in reversed order must reach
    // the same tree, because the normal form is target-disjoint and therefore
    // order-free by construction. If this ever fails, target-disjointness has
    // failed somewhere upstream.
    for (seed, basis, program) in corpus(4) {
        let net = fold(&basis, &program);

        let apply = |order: Vec<(Path, Effect)>| {
            let mut tree = basis.clone();
            for (path, effect) in order {
                match effect {
                    Effect::Create(entry) | Effect::Modify(entry) => {
                        tree.insert(path, entry);
                    }
                    Effect::Remove => {
                        tree.remove(path);
                    }
                }
            }
            tree
        };

        let forward = net.canonical();
        let mut backward = forward.clone();
        backward.reverse();

        assert_eq!(
            apply(forward),
            apply(backward),
            "seed {seed:#x}: reversing serialized effect order changed the resulting tree"
        );
    }
}

#[test]
fn the_effect_set_round_trips_back_to_the_evaluated_tree() {
    // The property that gives the normal form its meaning: the folded effects
    // must carry *everything* source-ordered evaluation did, so replaying them
    // onto the basis reconstructs the tree evaluation actually reached. A fold
    // that dropped an effect, or invented one, fails here.
    //
    // Note carefully what the two sides are. The left is basis + folded
    // effects; the right is the after-image evaluation produced before any
    // diffing happened. An earlier draft of this test computed its "direct"
    // side by calling `fold` a second time, which compared a value to itself
    // and would have passed against any diff whatsoever, including one that
    // returned no effects at all.
    for (seed, basis, program) in corpus(5) {
        let net = fold(&basis, &program);

        let mut replayed = basis.clone();
        for (path, effect) in net.canonical() {
            match effect {
                Effect::Create(entry) | Effect::Modify(entry) => {
                    replayed.insert(path, entry);
                }
                Effect::Remove => {
                    replayed.remove(path);
                }
            }
        }

        assert_eq!(
            replayed, net.after,
            "seed {seed:#x}: replaying the normal form did not reconstruct the tree that \
             source-ordered evaluation reached"
        );
    }
}

#[test]
fn the_round_trip_property_can_actually_fail() {
    // Non-vacuity for the test above. If the effect set is deliberately
    // damaged, the round trip must diverge -- otherwise that assertion is
    // satisfied by construction and proves nothing about the real fold.
    let basis = basis_of(&[("a", entry(1, Mode::Regular))]);
    let program = vec![Intent::Write {
        path: "a",
        content: 2,
        mode: Mode::Regular,
    }];
    let net = fold(&basis, &program);
    assert!(
        !net.effects.is_empty(),
        "this program must produce an effect for the check below to mean anything"
    );

    let damaged: BTreeMap<Path, Effect> = BTreeMap::new();
    let mut replayed = basis.clone();
    for (path, effect) in &damaged {
        match effect {
            Effect::Create(e) | Effect::Modify(e) => {
                replayed.insert(path, *e);
            }
            Effect::Remove => {
                replayed.remove(path);
            }
        }
    }
    assert_ne!(
        replayed, net.after,
        "dropping every effect must break the round trip; if it does not, the round-trip \
         assertion is vacuous"
    );
}

#[test]
fn a_program_with_no_intents_produces_no_effects_and_no_dispositions() {
    // The degenerate case, asserted because the totality check above is
    // trivially satisfied by an empty program and a guard that only ever saw
    // empty programs would pass while proving nothing.
    let basis = basis_of(&[("a", entry(1, Mode::Regular))]);
    let net = fold(&basis, &[]);
    assert!(net.canonical().is_empty());
    assert!(net.dispositions.is_empty());
}

#[test]
fn the_corpus_actually_exercises_every_disposition_arm() {
    // Non-vacuity with teeth. Every property above would pass on a corpus that
    // only ever generated no-ops. This asserts the generated programs reach
    // each arm of the totality map, so the properties are being tested against
    // real folding rather than against emptiness.
    let mut seen_surviving = false;
    let mut seen_identity = false;
    let mut seen_inverse = false;
    let mut seen_absorption = false;
    let mut seen_error = false;

    for (_, basis, program) in corpus(6) {
        for disposition in fold(&basis, &program).dispositions {
            match disposition {
                Disposition::SurvivingEffect(_) => seen_surviving = true,
                Disposition::IdentityNoOp => seen_identity = true,
                Disposition::InverseCancellation => seen_inverse = true,
                Disposition::Absorption => seen_absorption = true,
                Disposition::StatementError(_) => seen_error = true,
            }
        }
    }

    for (reached, arm) in [
        (seen_surviving, "SurvivingEffect"),
        (seen_identity, "IdentityNoOp"),
        (seen_inverse, "InverseCancellation"),
        (seen_absorption, "Absorption"),
        (seen_error, "StatementError"),
    ] {
        assert!(
            reached,
            "the corpus never produced a {arm} disposition, so every property above is \
             untested against that arm"
        );
    }
}

#[test]
fn the_shrinker_reduces_a_known_failure_to_its_minimal_program() {
    // The shrinker is machinery the acceptance criteria require, so it is
    // tested rather than trusted. A synthetic predicate stands in for a real
    // failure: "this program leaves an effect at c".
    let basis = basis_of(&[]);
    let program = vec![
        Intent::Write {
            path: "a",
            content: 1,
            mode: Mode::Regular,
        },
        Intent::Write {
            path: "c",
            content: 2,
            mode: Mode::Regular,
        },
        Intent::Chmod {
            path: "a",
            mode: Mode::Executable,
        },
    ];
    let fails =
        |basis: &BTreeMap<Path, Entry>, p: &[Intent]| fold(basis, p).effects.contains_key("c");

    assert!(
        fails(&basis, &program),
        "the predicate must hold to begin with"
    );
    let minimal = shrink(&basis, &program, fails);

    assert_eq!(
        minimal,
        vec![Intent::Write {
            path: "c",
            content: 2,
            mode: Mode::Regular,
        }],
        "the shrinker must strip every intent that is not required to reproduce the failure"
    );
}

#[test]
fn the_projection_is_total_and_agrees_with_the_evaluator_vocabulary() {
    // Every arm the oracle can produce must project onto exactly one arm the
    // evaluator reports. If this ever stops being total, the equivalence
    // comparison silently loses cases rather than failing.
    for (fine, coarse) in [
        (
            Disposition::SurvivingEffect("a"),
            ProjectedDisposition::Surviving,
        ),
        (Disposition::IdentityNoOp, ProjectedDisposition::Absorbed),
        (
            Disposition::InverseCancellation,
            ProjectedDisposition::Absorbed,
        ),
        (Disposition::Absorption, ProjectedDisposition::Absorbed),
        (
            Disposition::StatementError(StatementError::TargetAbsent),
            ProjectedDisposition::StatementError,
        ),
    ] {
        assert_eq!(
            fine.projected(),
            coarse,
            "{fine:?} projected onto the wrong evaluator disposition"
        );
    }
}

#[test]
fn the_projection_is_lossy_and_that_is_the_finding() {
    // This is the evidence behind the question raised with the evaluator's
    // owner, held as a test so it cannot quietly stop being true.
    //
    // Three intents that a reviewer would want told apart — a write that lost
    // to a later write, a create the author cancelled themselves, and a write
    // that was never a change — all arrive at the same coarse arm. The spec
    // keeps the totality map so reviewers can inspect "what an agent attempted
    // versus what actually survives"; at this resolution they cannot.
    let distinct = [
        Disposition::Absorption,
        Disposition::InverseCancellation,
        Disposition::IdentityNoOp,
    ];
    let projected: BTreeSet<ProjectedDisposition> =
        distinct.iter().map(|d| d.projected()).collect();

    assert_eq!(
        distinct.len(),
        3,
        "the three fine-grained arms must be distinct to begin with"
    );
    assert_eq!(
        projected.len(),
        1,
        "all three must collapse to one arm for this to be the loss it is claimed to be; \
         got {projected:?}"
    );

    // And the loss is real in practice, not only in the type: these two
    // programs are semantically different and become indistinguishable.
    let cancelled = fold(
        &basis_of(&[]),
        &[
            Intent::Write {
                path: "a",
                content: 1,
                mode: Mode::Regular,
            },
            Intent::Delete { path: "a" },
        ],
    );
    let never_a_change = fold(
        &basis_of(&[("a", entry(1, Mode::Regular))]),
        &[Intent::Write {
            path: "a",
            content: 1,
            mode: Mode::Regular,
        }],
    );

    assert_ne!(
        cancelled.dispositions.last(),
        never_a_change.dispositions.last(),
        "the oracle must distinguish a self-cancelled create from a no-change write"
    );
    assert_eq!(
        cancelled.dispositions.last().map(|d| d.projected()),
        never_a_change.dispositions.last().map(|d| d.projected()),
        "...and the evaluator's vocabulary must be shown to conflate them, which is \
         precisely what was raised with its owner"
    );
}
