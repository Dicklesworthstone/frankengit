/-
FG-041d: every exported reference-model history is a run of the Lean model.

This is the refinement direction the bead asks for, code to model. Each vector in
Vectors.lean is a history the executable reference model actually produced,
projected onto the ordered residue. Replaying it here and requiring the head
generation to agree at every step is what makes the proof a statement about the
implementation's behaviour rather than about a model free to drift from it.
Published batches now carry their decoded effect vectors, so a history that
moves a ref or advances a forge stream exercises the atomic-visibility theorem's
data path as well.

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

/-- The model starts at zero. A concrete generation below this history's genesis
has no model coordinate. Natural-number subtraction alone would map it to zero. -/
def rebase (genesis value : Nat) : Option Nat :=
  if genesis ≤ value then some (value - genesis) else none

/-- Translate one exported operation, checking each publication coordinate. -/
def toOperation (genesis : Nat) : FgitBridge.Op → Option Operation
  | .sealRequest target => some (.sealRequest target)
  | .decide target committed =>
      some (.decide target (if committed then TerminalOutcome.committed else TerminalOutcome.refused))
  | .retry target committed =>
      some (.retry target (if committed then TerminalOutcome.committed else TerminalOutcome.refused))
  | .publish predecessor generation refEffects forgeEffects => do
      return .publish { predecessor := ← rebase genesis predecessor
                      , generation := ← rebase genesis generation
                      , refEffects := refEffects
                      , forgeEffects := forgeEffects }
  | .interruptedPublication predecessor generation => do
      return .interruptedPublication { predecessor := ← rebase genesis predecessor
                                     , generation := ← rebase genesis generation
                                     , refEffects := [], forgeEffects := [] }

/-- One concrete step can be several abstract operations, applied in order. -/
def applyStep (genesis : Nat) (state : State) (step : FgitBridge.Step) : Option State :=
  step.ops.foldlM (fun current op => do return apply (← toOperation genesis op) current) state

/-- Rebase each recorded observation only when it has a valid model coordinate. -/
def checkSteps (genesis : Nat) : State → List FgitBridge.Step → Bool
  | _, [] => true
  | state, step :: rest =>
      match applyStep genesis state step with
      | none => false
      | some next =>
          rebase genesis step.generationAfter == some next.generation && checkSteps genesis next rest

/-- A history refines the model when replaying it reproduces every generation. -/
def checkTrace (trace : FgitBridge.Trace) : Bool :=
  checkSteps trace.genesisGeneration initial trace.steps

/-- Regression witnesses for the origin of a trace. An unchanged head and an
interrupted publication must validate their coordinates just as a winning CAS does. -/
example :
    checkSteps 1 initial [⟨0, [], 0⟩] = false ∧
    checkSteps 1 initial [⟨0, [.publish 0 2], 2⟩] = false ∧
    checkSteps 1 initial [⟨0, [.interruptedPublication 1 0], 1⟩] = false ∧
    checkSteps 1 initial [⟨0, [], 1⟩] = true ∧
    checkSteps 1 initial [⟨0, [.publish 1 2], 2⟩] = true ∧
    checkSteps 1 initial [⟨0, [.interruptedPublication 1 2], 1⟩] = true := by decide

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
