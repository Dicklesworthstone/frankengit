import Std.Tactic

/-!
FG-041b's deliberately small, executable ordered-residue model.

It models only the publication boundary: a sealed transaction receives at
most one terminal outcome; a publication is an exact-predecessor successor;
and a successful publication exposes the whole batch as one value.  The
external authority and crash-observation premises are named in
`ASSUMPTIONS.md`; this file proves the consequences of the model, not those
empirical premises themselves.
-/

set_option autoImplicit false

namespace FrankenGit.Proof.OrderedResidue

abbrev TxId := Nat

inductive TerminalOutcome where
  | committed
  | refused
  deriving DecidableEq, Repr

/-! A batch has one coupled ref/forge effect vector.  There is no transition
that can expose either field independently. -/
structure Batch where
  predecessor : Nat
  generation : Nat
  refEffects : List Nat
  forgeEffects : List Nat
  deriving Repr

structure State where
  sealed : TxId -> Bool
  outcomes : TxId -> Option TerminalOutcome
  generation : Nat
  headChain : List Batch
  published : List Batch

def initial : State := {
  sealed := fun _ => false
  outcomes := fun _ => none
  generation := 0
  headChain := []
  published := []
}

def validSuccessor (state : State) (candidate : Batch) : Prop :=
  candidate.predecessor = state.generation /\
    candidate.generation = state.generation + 1

instance validSuccessorDecidable (state : State) (candidate : Batch) :
    Decidable (validSuccessor state candidate) := by
  unfold validSuccessor
  infer_instance

def decide (state : State) (target : TxId) (outcome : TerminalOutcome) : State :=
  if state.sealed target then
    match state.outcomes target with
    | some _ => state
    | none => {
        state with outcomes := fun observed =>
          if observed = target then some outcome else state.outcomes observed
      }
  else state

inductive Operation where
  | sealRequest (target : TxId)
  | decide (target : TxId) (outcome : TerminalOutcome)
  | retry (target : TxId) (outcome : TerminalOutcome)
  | crash
  | lostResponse
  | publish (candidate : Batch)
  | interruptedPublication (candidate : Batch)
  deriving Repr

def apply : Operation -> State -> State
  | .sealRequest target, state => {
      state with sealed := fun observed =>
        if observed = target then true else state.sealed observed
    }
  | .decide target outcome, state => decide state target outcome
  | .retry target outcome, state => decide state target outcome
  | .crash, state => state
  | .lostResponse, state => state
  | .publish candidate, state =>
      if validSuccessor state candidate then {
        state with
          generation := candidate.generation
          headChain := candidate :: state.headChain
          published := candidate :: state.published
      } else state
  | .interruptedPublication _, state => state

def run (state : State) : List Operation -> State
  | [] => state
  | operation :: rest => run (apply operation state) rest

/-- These predicates belong to the authority/transport bridge, not to the
mechanized state machine.  They deliberately have no local producer: the
empirical gates named in `ASSUMPTIONS.md` are the evidence boundary. -/
axiom AuthorityCasSucceeded : State -> Batch -> Prop
axiom AmbiguousResponseOccurred : State -> TxId -> TerminalOutcome -> Prop
axiom RootLastPublicationInterrupted : State -> Batch -> Prop

/-- The named external axioms used by the future trace-refinement bridge.
The model itself can make only `validSuccessor` publications. -/
class AuthorityStoreAxioms : Prop where
  authority_store_linearizable_cas :
    forall (state : State) (candidate : Batch),
      AuthorityCasSucceeded state candidate -> validSuccessor state candidate
  crash_retry_history_is_observed :
    forall (state : State) (target : TxId) (outcome : TerminalOutcome),
      AmbiguousResponseOccurred state target outcome ->
      state.outcomes target = some outcome ->
        (apply .lostResponse state).outcomes target = some outcome
  publication_epochs_preserve_authenticated_head :
    forall (state : State) (candidate : Batch),
      RootLastPublicationInterrupted state candidate ->
      (apply (.interruptedPublication candidate) state).generation = state.generation

/-- A decision may not overwrite an already recorded terminal outcome, even
when the retry presents a different candidate outcome. -/
theorem decide_preserves_existing_terminal
    (state : State) (observed target : TxId)
    (prior attempted : TerminalOutcome)
    (recorded : state.outcomes observed = some prior) :
    (decide state target attempted).outcomes observed = some prior := by
  cases targetOutcome : state.outcomes target with
  | none =>
      cases targetSealed : state.sealed target with
      | false => simp [decide, targetSealed, recorded]
      | true =>
          by_cases sameTarget : observed = target
          · subst observed
            simp_all
          · simp [decide, targetSealed, targetOutcome, sameTarget, recorded]
  | some existing =>
      cases targetSealed : state.sealed target <;>
        simp [decide, targetSealed, targetOutcome, recorded]

/-- An unsealed transaction cannot acquire a terminal outcome through the
decision transition. -/
theorem unsealed_decision_is_not_fabricated
    (state : State) (target : TxId) (outcome : TerminalOutcome)
    (unsealed : state.sealed target = false) :
    (decide state target outcome).outcomes = state.outcomes := by
  simp [decide, unsealed]

/-- Deciding is permitted to update an outcome, never the seal binding. -/
theorem decide_preserves_seal
    (state : State) (observed target : TxId) (outcome : TerminalOutcome) :
    (decide state target outcome).sealed observed = state.sealed observed := by
  cases targetSealed : state.sealed target <;>
    cases targetOutcome : state.outcomes target <;>
      simp [decide, targetSealed, targetOutcome]

/-- A once-sealed transaction stays sealed across every ordered-residue
operation. -/
theorem apply_preserves_existing_seal
    (operation : Operation) (state : State) (target : TxId)
    (sealed : state.sealed target = true) :
    (apply operation state).sealed target = true := by
  cases operation with
  | sealRequest attemptedTarget =>
      by_cases sameTarget : target = attemptedTarget
      · subst target
        simp [apply]
      · simp [apply, sameTarget, sealed]
  | decide attemptedTarget attemptedOutcome =>
      simpa [apply] using
        Eq.trans (decide_preserves_seal state target attemptedTarget attemptedOutcome) sealed
  | retry attemptedTarget attemptedOutcome =>
      simpa [apply] using
        Eq.trans (decide_preserves_seal state target attemptedTarget attemptedOutcome) sealed
  | crash => simp [apply, sealed]
  | lostResponse => simp [apply, sealed]
  | publish candidate =>
      by_cases accepted : validSuccessor state candidate
      · simp [apply, accepted, sealed]
      · simp [apply, accepted, sealed]
  | interruptedPublication candidate => simp [apply, sealed]

/-- Core theorem 1: once sealed/decided, every later decision or retry has the
same terminal outcome for that transaction. -/
theorem terminal_outcome_is_unique
    (state : State) (operations : List Operation)
    (target : TxId) (outcome : TerminalOutcome)
    (sealed : state.sealed target = true)
    (recorded : state.outcomes target = some outcome) :
    (run state operations).outcomes target = some outcome := by
  induction operations generalizing state with
  | nil => simpa [run] using recorded
  | cons operation rest inductionHypothesis =>
      apply inductionHypothesis
      · exact apply_preserves_existing_seal operation state target sealed
      · cases operation with
        | sealRequest attemptedTarget => simpa [apply] using recorded
        | decide attemptedTarget attemptedOutcome =>
            exact decide_preserves_existing_terminal state target attemptedTarget outcome attemptedOutcome recorded
        | retry attemptedTarget attemptedOutcome =>
            exact decide_preserves_existing_terminal state target attemptedTarget outcome attemptedOutcome recorded
        | crash => simpa [apply] using recorded
        | lostResponse => simpa [apply] using recorded
        | publish candidate =>
            by_cases accepted : validSuccessor state candidate
            · simpa [apply, accepted] using recorded
            · simpa [apply, accepted] using recorded
        | interruptedPublication candidate => simpa [apply] using recorded

/-- A successful publication may only move to the immediate generation and
names the exact current head generation as predecessor. -/
theorem accepted_publish_is_continuous
    (state : State) (candidate : Batch)
    (accepted : validSuccessor state candidate) :
    candidate.predecessor = state.generation /\
      (apply (.publish candidate) state).generation = state.generation + 1 /\
      (apply (.publish candidate) state).headChain.head? = some candidate := by
  rcases accepted with ⟨predecessor, generation⟩
  simp [apply, validSuccessor, predecessor, generation]

/-- The explicit FG-004 boundary turns an externally observed successful CAS
into the exact-predecessor publication fact used by the model theorem. -/
theorem externally_successful_cas_is_continuous
    [AuthorityStoreAxioms] (state : State) (candidate : Batch)
    (succeeded : AuthorityCasSucceeded state candidate) :
    candidate.predecessor = state.generation /\
      (apply (.publish candidate) state).generation = state.generation + 1 /\
      (apply (.publish candidate) state).headChain.head? = some candidate := by
  exact accepted_publish_is_continuous state candidate
    (AuthorityStoreAxioms.authority_store_linearizable_cas state candidate succeeded)

/-- No permitted operation moves the canonical generation backwards. -/
theorem apply_generation_is_monotone (operation : Operation) (state : State) :
    state.generation <= (apply operation state).generation := by
  cases operation with
  | sealRequest target => simp [apply]
  | decide target outcome =>
      cases sealed : state.sealed target <;>
        cases observed : state.outcomes target <;>
          simp [apply, decide, sealed, observed]
  | retry target outcome =>
      cases sealed : state.sealed target <;>
        cases observed : state.outcomes target <;>
          simp [apply, decide, sealed, observed]
  | crash => simp [apply]
  | lostResponse => simp [apply]
  | interruptedPublication candidate => simp [apply]
  | publish candidate =>
      by_cases accepted : validSuccessor state candidate
      · rcases accepted with ⟨predecessor, generation⟩
        simp [apply, validSuccessor, predecessor, generation]
      · simp [apply, accepted]

/-- Core theorem 2: every execution preserves head-generation monotonicity;
combined with `accepted_publish_is_continuous`, each advance has an exact
predecessor and no skipped generation. -/
theorem head_chain_is_continuous_and_monotone
    (state : State) (operations : List Operation) :
    state.generation <= (run state operations).generation := by
  induction operations generalizing state with
  | nil => simp [run]
  | cons operation rest inductionHypothesis =>
      exact Nat.le_trans (apply_generation_is_monotone operation state)
        (inductionHypothesis (apply operation state))

/-- Core theorem 3: visibility is atomic because an accepted publication
inserts one batch containing both ref and forge vectors in the same head step. -/
theorem ref_and_forge_visibility_is_atomic
    (state : State) (candidate : Batch)
    (accepted : validSuccessor state candidate) :
    (apply (.publish candidate) state).published.head? = some candidate /\
      (apply (.publish candidate) state).published.head?.map Batch.refEffects =
        some candidate.refEffects /\
      (apply (.publish candidate) state).published.head?.map Batch.forgeEffects =
        some candidate.forgeEffects := by
  rcases accepted with ⟨predecessor, generation⟩
  simp [apply, validSuccessor, predecessor, generation]

/-- Core theorem 4: after an authority decision, a crash, lost response, and
even a retry proposing the opposite outcome converge on the original terminal
outcome.  Crash and lost-response events do not fabricate a decision. -/
theorem crash_retry_does_not_lose_or_fabricate_decision
    (state : State) (target : TxId)
    (recorded retryOutcome : TerminalOutcome)
    (sealed : state.sealed target = true)
    (alreadyTerminal : state.outcomes target = some recorded) :
    (run state [.crash, .lostResponse, .retry target retryOutcome]).outcomes target =
      some recorded := by
  exact terminal_outcome_is_unique state
    [.crash, .lostResponse, .retry target retryOutcome] target recorded sealed alreadyTerminal

/-- The explicit ambiguity boundary has the same non-loss consequence as the
model's lost-response operation. -/
theorem ambiguous_response_is_resolved_from_recorded_history
    [AuthorityStoreAxioms] (state : State) (target : TxId)
    (outcome : TerminalOutcome)
    (ambiguous : AmbiguousResponseOccurred state target outcome)
    (recorded : state.outcomes target = some outcome) :
    (apply .lostResponse state).outcomes target = some outcome := by
  exact AuthorityStoreAxioms.crash_retry_history_is_observed state target outcome ambiguous recorded

/-- Core theorem 5: an interrupted root-last publication changes neither the
visible head generation nor the visible ref/forge batch. -/
theorem interrupted_publication_is_anti_rollback
    (state : State) (candidate : Batch) :
    (apply (.interruptedPublication candidate) state).generation = state.generation /\
      (apply (.interruptedPublication candidate) state).published = state.published := by
  simp [apply]

/-- The external root-last premise is explicitly carried by the bridge while
the model independently proves that its interrupted transition is inert. -/
theorem externally_interrupted_publication_keeps_head
    [AuthorityStoreAxioms] (state : State) (candidate : Batch)
    (interrupted : RootLastPublicationInterrupted state candidate) :
    (apply (.interruptedPublication candidate) state).generation = state.generation := by
  exact AuthorityStoreAxioms.publication_epochs_preserve_authenticated_head state candidate interrupted

end FrankenGit.Proof.OrderedResidue
