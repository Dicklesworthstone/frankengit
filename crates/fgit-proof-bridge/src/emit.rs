//! Rendering projected histories as Lean test vectors.
//!
//! # Why the emitted file stands alone
//!
//! `proofs/fg041/check.sh` compiles one file: `elan run <toolchain> lean
//! proofs/fg041/OrderedResidue.lean`. There is no lake project, so `import
//! OrderedResidue` has nothing to resolve against without first producing an
//! `.olean` and setting `LEAN_PATH`. Deciding that build story is deliverable
//! (2) of this bead, not (1).
//!
//! So what is emitted here compiles by itself: a namespace of plain data using
//! locally declared structures. That is a real artifact with a real staleness
//! gate today, and it does not pre-commit the harness to an import mechanism
//! chosen before the checker that needs it exists.
//!
//! # Determinism
//!
//! Nothing here reads a clock, a hostname, an environment variable or a tool
//! version. The output is a pure function of the input traces, which is what
//! makes byte-identical regeneration a meaningful gate rather than a
//! coincidence.

use core::fmt::Write as _;

use crate::project::{AbstractOp, ProjectedTrace};

/// The header every generated artifact carries.
const HEADER: &str = "\
-- GENERATED FILE -- do not edit by hand.
--
-- Produced by `fgit-proof-bridge-gen generate` from the checked-in
-- `.fgtrace` goldens in `crates/fgit-reference/tests/goldens`. Regenerate with
-- that command; `fgit-proof-bridge-gen check` refuses if this file is stale.
--
-- These are the reference model's own recorded histories, projected onto the
-- ordered residue that `proofs/fg041/OrderedResidue.lean` models. Steps the
-- abstract model does not observe appear as `Operation.none` stutters, so step
-- indices here still name real steps in the concrete trace.
";

/// Renders every projected history into one Lean source file.
///
/// # Errors
///
/// Never fails on well-formed input; the `Result` exists because formatting
/// into a `String` is fallible in the trait that does it.
#[must_use]
pub fn render(traces: &[ProjectedTrace]) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str(HEADER);
    out.push_str(
        "
namespace FgitBridge

/-- The abstract operations, mirroring `OrderedResidue.Operation` without
importing it. Deliverable (2) of FG-041d is the checker that maps these onto
that type and replays them; until it exists this file is data, and says so. -/
inductive Op where
  | sealRequest (target : Nat)
  | decide (target : Nat) (committed : Bool)
  | publish (predecessor : Nat) (generation : Nat)
  | interruptedPublication (predecessor : Nat) (generation : Nat)
  deriving Repr

/-- One concrete step's projection, paired with the head generation the
reference model recorded after it. `ops` is empty for a stuttering step, and can
hold several operations: a won compare-and-swap both advances the head and makes
every capsule in its batch terminal. -/
structure Step where
  concreteIndex : Nat
  ops : List Op
  generationAfter : Nat
  deriving Repr

/-- One projected history. -/
structure Trace where
  name : String
  steps : List Step
  deriving Repr
",
    );

    for trace in traces {
        let _ = write!(
            out,
            "\n/-- Transactions in `{}`, abstract index to concrete identity:\n",
            trace.name
        );
        for (index, identity) in &trace.transactions {
            let _ = writeln!(out, "    {index} = {identity}");
        }
        let _ = write!(
            out,
            "-/\ndef {} : Trace :=\n  {{ name := \"{}\"\n  , steps :=\n    [",
            lean_ident(&trace.name),
            trace.name
        );
        let mut first = true;
        for step in &trace.steps {
            if first {
                out.push(' ');
                first = false;
            } else {
                out.push_str("\n    , ");
            }
            let ops = step
                .operations
                .iter()
                .map(|op| render_op(*op))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                out,
                "{{ concreteIndex := {}, ops := [{ops}], generationAfter := {} }}",
                step.concrete_index, step.generation_after
            );
        }
        out.push_str("\n    ]\n  }\n");
    }

    let _ = write!(
        out,
        "\n/-- Every projected history in this build. -/\ndef all : List Trace :=\n  ["
    );
    let mut first = true;
    for trace in traces {
        if first {
            out.push(' ');
            first = false;
        } else {
            out.push_str("\n  , ");
        }
        out.push_str(&lean_ident(&trace.name));
    }
    out.push_str("\n  ]\n\nend FgitBridge\n");
    out
}

fn render_op(op: AbstractOp) -> String {
    match op {
        AbstractOp::SealRequest { target } => format!("Op.sealRequest {target}"),
        AbstractOp::Decide { target, outcome } => format!(
            "Op.decide {target} {}",
            matches!(outcome, crate::project::AbstractOutcome::Committed)
        ),
        AbstractOp::Publish {
            predecessor,
            generation,
        } => format!("Op.publish {predecessor} {generation}"),
        AbstractOp::InterruptedPublication {
            predecessor,
            generation,
        } => format!("Op.interruptedPublication {predecessor} {generation}"),
    }
}

/// Turns a golden's file stem into a Lean identifier.
///
/// Deterministic and total: every byte that is not alphanumeric becomes an
/// underscore, so two different goldens cannot collide unless their names
/// already differ only in punctuation.
fn lean_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 6);
    out.push_str("trace_");
    for byte in name.chars() {
        if byte.is_ascii_alphanumeric() {
            out.push(byte);
        } else {
            out.push('_');
        }
    }
    out
}
