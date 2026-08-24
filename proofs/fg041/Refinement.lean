/-
FG-041d: every exported reference-model history is a run of the Lean model.

This is the refinement direction the bead asks for, code to model. Each vector in
Vectors.lean is a history the executable reference model actually produced,
projected onto the ordered residue. Replaying it here and requiring the head
generation to agree at every step is what makes the proof a statement about the
implementation's behaviour rather than about a model free to drift from it.

Discharged with kernel `decide`, never `native_decide`: toolchain.json pins the
trusted base to the Lean kernel and the bundled Init and Std, and native_decide
would widen it to include the Lean compiler. That is a proof-class change hiding
inside a tactic choice, so it is refused here and the vector set stays small
enough for the kernel to reduce.
-/
import OrderedResidue
import Vectors

namespace FrankenGit.Proof.Refinement

open FrankenGit.Proof.OrderedResidue

/-- The abstraction function's only numeric content.

The reference model's head generations begin at its genesis generation; the Lean
model's begin at zero. The vectors carry the concrete numbers so they stay
traceable to the histories they came from, and the offset is applied here, where
a reader of the proof will look for it. -/
def rebase (genesis value : Nat) : Nat := value - genesis

/-- One exported operation as a model operation. -/
def toOperation (genesis : Nat) : FgitBridge.Op → Operation
  | .sealRequest target => .sealRequest target
  | .decide target committed =>
      .decide target (if committed then TerminalOutcome.committed else TerminalOutcome.refused)
  | .publish predecessor generation =>
      .publish { predecessor := rebase genesis predecessor
               , generation := rebase genesis generation
               , refEffects := []
               , forgeEffects := [] }
  | .interruptedPublication predecessor generation =>
      .interruptedPublication { predecessor := rebase genesis predecessor
                              , generation := rebase genesis generation
                              , refEffects := []
                              , forgeEffects := [] }

/-- One concrete step can be several abstract ones, applied in order. -/
def applyStep (genesis : Nat) (state : State) (step : FgitBridge.Step) : State :=
  step.ops.foldl (fun current op => apply (toOperation genesis op) current) state

/-- Replays a history, refusing at the first step whose generation disagrees.

Returning at the first divergence rather than at the end is deliberate: a check
that reported only a final mismatch would say a history diverges without saying
where, and the step index is the whole value of a trace. -/
def checkSteps (genesis : Nat) : State → List FgitBridge.Step → Bool
  | _, [] => true
  | state, step :: rest =>
      let next := applyStep genesis state step
      if next.generation = rebase genesis step.generationAfter then
        checkSteps genesis next rest
      else
        false

/-- A history refines the model when replaying it reproduces every generation. -/
def checkTrace (trace : FgitBridge.Trace) : Bool :=
  checkSteps trace.genesisGeneration initial trace.steps

/-- Every exported history is a run of the model.

Bounded refinement evidence over a finite corpus. NOT a proof that the Rust
implementation refines the model in general, and not an exhaustive exploration:
it says that these histories, which the reference model actually produced, are
admitted by the Lean model. -/
theorem every_exported_history_is_a_run_of_the_model :
    FgitBridge.all.all checkTrace = true := by decide

/-- The corpus is not empty.

Without this the theorem above would hold vacuously for an empty list, and a
generator that silently exported nothing would leave a green lane asserting
nothing at all. -/
theorem the_corpus_is_not_empty : FgitBridge.all.isEmpty = false := by decide

end FrankenGit.Proof.Refinement
