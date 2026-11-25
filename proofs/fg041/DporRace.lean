import Vectors

namespace FrankenGit.Proof.DporRace

open FgitBridge

/-- The two staged transactions are numbered by the common sealing prefix.
    In the registered fixture each creates a different absent ref. The first
    publication decides the winner; the retry must then commit the other
    original writer at the successor without moving the winner's ref. -/
def sealedWritersAndWinner (trace : Trace) : Option (List Nat × Nat) := do
  let retried :: staged :: prepared :: lost :: won :: reversedPrefix := trace.steps.reverse | none
  let [.publish predecessor generation [wonRef] [], .decide winner true] := won.ops | none
  let [.interruptedPublication lostPredecessor lostGeneration] := lost.ops | none
  let [] := prepared.ops | none
  let [] := staged.ops | none
  let [.publish retryBasis successor [retryRef] [], .decide loser true] := retried.ops | none
  guard (retryBasis == generation && successor == retryBasis + 1 && retried.generationAfter == successor)
  guard (prepared.generationAfter == generation && staged.generationAfter == generation)
  guard (wonRef != retryRef && winner != loser)
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
  guard ((winner == a && loser == b) || (winner == b && loser == a))
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

/-- A relabelled retry or a second decision for the first winner can retain
    the same generation. The registered disjoint requests must both commit. -/
def replaceRetry (trace : Trace) (target : Nat) (committed : Bool) : Trace :=
  match trace.steps.reverse with
  | last :: before =>
    match last.ops with
    | [publish@(.publish _ _ _ _), .decide _ _] =>
      { trace with steps := before.reverse ++
          [{ last with ops := [publish, .decide target committed],
                       repositorySequenceAfter := if committed then 2 else 1 }] }
    | _ => trace
  | [] => trace

example :
    (sealedWritersAndWinner (replaceRetry trace_dpor_first_wins 1 true)).isNone &&
    (sealedWritersAndWinner (replaceRetry trace_dpor_first_wins 0 false)).isNone := by decide

theorem both_sealed_writers_win_once : coversBothWinners FgitBridge.all = true := by decide

end FrankenGit.Proof.DporRace
