/-
FG-041d: every exported reference-model history is a run of the Lean model.

This is the refinement direction the bead asks for, code to model. Each vector in
Vectors.lean is a history the executable reference model actually produced,
projected onto the ordered residue. At every step the kernel compares the head
generation, decision sequence, and repository sequence with the recorded values.
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

/-- Winning and interrupted publications use the same coordinate conversion. -/
def toBatch (genesis predecessor generation : Nat) (refEffects forgeEffects : List Nat) :
    Option Batch := do
  return { predecessor := ← rebase genesis predecessor, generation := ← rebase genesis generation,
           refEffects, forgeEffects }

/-- A winning publication exposes new decisions in stream order. Check each
target was sealed and undecided and that the model records the exported label. -/
def applyDecision (progress : State × Nat) : FgitBridge.Op → Option (State × Nat)
  | .decide target committed => do
      let (current, commits) := progress
      guard (current.sealed target && (current.outcomes target).isNone)
      let label := if committed then TerminalOutcome.committed else TerminalOutcome.refused
      let next := apply (.decide target label) current
      guard (next.outcomes target == some label)
      return (next, if committed then commits + 1 else commits)
  | _ => none

/-- A retry observes an existing terminal. A fresh decision can only follow
the winning publication that exposed it. Count new terminals and commits separately. -/
def applyStep (genesis : Nat) (state : State) (step : FgitBridge.Step) : Option (State × Nat × Nat) := do
  match step.ops with
  | [] => return (state, 0, 0)
  | .publish predecessor generation refs forge :: decisions =>
      let batch ← toBatch genesis predecessor generation refs forge
      guard (validSuccessor state batch)
      let (next, commits) ← decisions.foldlM applyDecision (apply (.publish batch) state, 0)
      return (next, decisions.length, commits)
  | [.retry target committed] =>
      let label := if committed then TerminalOutcome.committed else TerminalOutcome.refused
      guard (state.outcomes target == some label)
      return (apply (.retry target label) state, 0, 0)
  | [.sealRequest target] => return (apply (.sealRequest target) state, 0, 0)
  | [.interruptedPublication predecessor generation] =>
      return (apply (.interruptedPublication (← toBatch genesis predecessor generation [] [])) state, 0, 0)
  | _ => none

/-- All three recorded head positions must match after each step, including stutters. -/
def checkSteps (genesis : Nat) (state : State) (decisionSequence repositorySequence : Nat) :
    List FgitBridge.Step → Bool
  | [] => true
  | step :: rest =>
      match applyStep genesis state step with
      | none => false
      | some (next, added, commits) =>
          let sequence := decisionSequence + added
          let committed := repositorySequence + commits
          rebase genesis step.generationAfter == some next.generation &&
            step.decisionSequenceAfter == sequence && step.repositorySequenceAfter == committed &&
            checkSteps genesis next sequence committed rest

/-- The empty genesis head has no terminal decisions. -/
def checkTrace (trace : FgitBridge.Trace) : Bool :=
  checkSteps trace.genesisGeneration initial 0 0 trace.steps

example :
    checkSteps 1 initial 0 0 [⟨0, [], 0, 0, 0⟩] = false ∧
    checkSteps 1 initial 0 0 [⟨0, [.publish 0 2], 2, 0, 0⟩] = false ∧
    checkSteps 1 initial 0 0 [⟨0, [.publish 2 3], 1, 0, 0⟩] = false ∧
    checkSteps 1 initial 0 0 [⟨0, [.publish 1 3], 1, 0, 0⟩] = false ∧
    checkSteps 1 initial 0 0 [⟨0, [.interruptedPublication 1 0], 1, 0, 0⟩] = false ∧
    checkSteps 1 initial 0 0 [⟨0, [], 1, 0, 0⟩] = true ∧
    checkSteps 1 initial 0 0 [⟨0, [.publish 1 2], 2, 0, 0⟩] = true ∧
    checkSteps 1 initial 0 0 [⟨0, [.interruptedPublication 1 2], 1, 0, 0⟩] = true := by decide

/-- A missing decision, a duplicate target, and an incorrect retry can all
preserve generation. Only a valid publication may establish the recorded result. -/
example :
    let seals := [FgitBridge.Step.mk 0 [.sealRequest 0] 1 0 0, ⟨1, [.sealRequest 1], 1, 0, 0⟩]
    let win := FgitBridge.Step.mk 2 [.publish 1 2, .decide 0 true, .decide 1 false] 2 2 1
    checkSteps 1 initial 0 0 (seals ++ [win, ⟨3, [.retry 1 false], 2, 2, 1⟩]) = true ∧
    checkSteps 1 initial 0 0 (seals ++ [win, ⟨3, [.retry 1 true], 2, 2, 1⟩]) = false ∧
    checkSteps 1 initial 0 0 (seals ++ [⟨2, [.publish 1 2], 2, 2, 1⟩]) = false ∧
    checkSteps 1 initial 0 0 (seals ++ [⟨2, [.decide 0 true], 1, 1, 1⟩]) = false ∧
    checkSteps 1 initial 0 0 (seals ++ [⟨2, [.publish 1 2, .decide 0 true, .decide 0 false], 2, 2, 1⟩]) = false ∧
    checkSteps 1 initial 0 0 [⟨0, [.publish 1 2, .decide 0 true], 2, 1, 1⟩] = false ∧
    checkSteps 1 initial 0 0 (seals ++ [⟨2, [.publish 1 2, .decide 0 true, .decide 1 true], 2, 2, 1⟩]) = false ∧
    checkSteps 1 initial 0 0 [⟨0, [.retry 0 false], 1, 0, 0⟩] = false := by decide

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
