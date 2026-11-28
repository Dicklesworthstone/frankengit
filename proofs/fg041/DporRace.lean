import Vectors

namespace FrankenGit.Proof.DporRace

open FgitBridge

/-- The first publication decides one of the initially sealed writers.
    The retry commits the other writer's distinct ref, or records a
    decision-only refusal when both writers asked to create the same ref. -/
def sealedWritersAndWinner (sameRef : Bool) (trace : Trace) : Option (List Nat × Nat) := do
  let retried :: staged :: prepared :: lost :: won :: reversedPrefix := trace.steps.reverse | none
  let [.publish predecessor generation [wonRef] [], .decide winner true] := won.ops | none
  let [.interruptedPublication lostPredecessor lostGeneration] := lost.ops | none
  let [] := prepared.ops | none
  let [] := staged.ops | none
  let [.publish retryBasis successor retryRefs [], .decide loser committed] := retried.ops | none
  guard (retryBasis == generation && successor == retryBasis + 1 && retried.generationAfter == successor)
  guard (prepared.generationAfter == generation && staged.generationAfter == generation)
  guard (retried.decisionSequenceAfter == won.decisionSequenceAfter + 1)
  if sameRef then
    guard (!committed && retryRefs.isEmpty &&
      retried.repositorySequenceAfter == won.repositorySequenceAfter)
  else
    let [retryRef] := retryRefs | none
    guard (committed && wonRef != retryRef &&
      retried.repositorySequenceAfter == won.repositorySequenceAfter + 1)
  guard (winner != loser)
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
def coversBothWinners (sameRef : Bool) (traces : List Trace) : Bool :=
  match traces.map (sealedWritersAndWinner sameRef) with
  | [some (writers, first), some (others, second)] =>
    writers == others && first != second
  | _ => false

/-- A repeated winner cannot certify two schedules, even if both histories
    pass their individual publication and generation checks. -/
theorem equal_winners_are_rejected (sameRef : Bool) (first second : Trace)
    (left right : List Nat) (winner : Nat)
    (h₁ : sealedWritersAndWinner sameRef first = some (left, winner))
    (h₂ : sealedWritersAndWinner sameRef second = some (right, winner)) :
    coversBothWinners sameRef [first, second] = false := by
  simp [coversBothWinners, h₁, h₂]

/-- Change the retry's decision and its corresponding repository sequence,
    leaving the generation and published effects in place. -/
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
    (sealedWritersAndWinner false (replaceRetry trace_dpor_first_wins 1 true)).isNone &&
    (sealedWritersAndWinner false (replaceRetry trace_dpor_first_wins 0 false)).isNone := by decide

example :
    (sealedWritersAndWinner true (replaceRetry trace_dpor_conflict_first_wins 1 true)).isNone &&
    (sealedWritersAndWinner true (replaceRetry trace_dpor_conflict_first_wins 0 false)).isNone := by decide

theorem both_sealed_writers_win_once :
    coversBothWinners false [trace_dpor_first_wins, trace_dpor_second_wins] = true ∧
    coversBothWinners true [trace_dpor_conflict_first_wins, trace_dpor_conflict_second_wins] = true := by
  decide

theorem every_schedule_is_replayed :
    FgitBridge.all = [trace_dpor_first_wins, trace_dpor_second_wins,
                      trace_dpor_conflict_first_wins, trace_dpor_conflict_second_wins] := rfl

end FrankenGit.Proof.DporRace
