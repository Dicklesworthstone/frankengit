import Vectors

namespace FrankenGit.Proof.DporRace

open FgitBridge

/-- The two staged transactions are numbered by the common sealing prefix.
    Only the winner may decide, and the losing CAS must retain its generation. -/
def sealedWritersAndWinner (trace : Trace) : Option (List Nat × Nat) := do
  let lost :: won :: reversedPrefix := trace.steps.reverse | none
  let [.publish predecessor generation _ _, .decide winner true] := won.ops | none
  let [.interruptedPublication lostPredecessor lostGeneration] := lost.ops | none
  guard (predecessor == trace.genesisGeneration && generation == predecessor + 1)
  guard (lostPredecessor == predecessor && lostGeneration == generation)
  guard (won.generationAfter == generation && lost.generationAfter == generation)
  let mut writers := []
  for step in reversedPrefix.reverse do
    guard (step.generationAfter == predecessor)
    match step.ops with
    | [] => pure ()
    | [.sealRequest target] => writers := target :: writers
    | _ => failure
  let [a, b] := writers | none
  guard (a != b && (winner == a || winner == b))
  return (writers, winner)

/-- Head-generation replay alone also accepts two copies of the same decision.
    Require each of the two sealed writers to win once on this input. -/
def coversBothWinners (traces : List Trace) : Bool :=
  match traces.map sealedWritersAndWinner with
  | [some (writers, first), some (others, second)] =>
    writers == others && first != second
  | _ => false

/-- A repeated winner cannot certify two schedules, even if both histories
    pass their individual publication and generation checks. -/
theorem equal_winners_are_rejected (first second : Trace) (left right : List Nat) (winner : Nat)
    (h₁ : sealedWritersAndWinner first = some (left, winner))
    (h₂ : sealedWritersAndWinner second = some (right, winner)) :
    coversBothWinners [first, second] = false := by
  simp [coversBothWinners, h₁, h₂]

theorem both_sealed_writers_win_once : coversBothWinners FgitBridge.all = true := by decide

end FrankenGit.Proof.DporRace
