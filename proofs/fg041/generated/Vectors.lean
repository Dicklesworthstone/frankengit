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
--
-- Effect vectors on `publish` carry dictionary-encoded identities: ref names
-- and forge streams become small stable indices in order of first appearance
-- within their trace, and forge effects flatten `(stream, position)` pairs so
-- the field stays one list of Nats.

namespace FgitBridge

/-- The abstract operations, mirroring `OrderedResidue.Operation` without
importing it. `retry` mirrors that model's own retry operation; the effect
lists on `publish` fill the corresponding fields of its `Batch`. Deliverable
(2) of FG-041d is the checker that maps these onto those types and replays
them; until it exists this file is data, and says so. -/
inductive Op where
  | sealRequest (target : Nat)
  | decide (target : Nat) (committed : Bool)
  | retry (target : Nat) (committed : Bool)
  | publish (predecessor : Nat) (generation : Nat)
      (refEffects : List Nat := []) (forgeEffects : List Nat := [])
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
  /-- The concrete head generation that `OrderedResidue.initial.generation = 0`
  corresponds to. The checker subtracts this from every generation-valued field,
  which is the whole numeric content of the abstraction function. -/
  genesisGeneration : Nat
  steps : List Step
  deriving Repr

/-- Transactions in `cas_loss_retry`, abstract index to concrete identity:
    0 = 00000000000003ed000000000000000400000000000000000000000000000000
    1 = 00000000000003ed000000000000000d00000000000000000000000000000000
-/
def trace_cas_loss_retry : Trace :=
  { name := "cas_loss_retry"
  , genesisGeneration := 1
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [Op.sealRequest 1], generationAfter := 1 }
    , { concreteIndex := 5, ops := [], generationAfter := 1 }
    , { concreteIndex := 6, ops := [], generationAfter := 1 }
    , { concreteIndex := 7, ops := [], generationAfter := 1 }
    , { concreteIndex := 8, ops := [Op.publish 1 2 [0] [], Op.decide 1 true], generationAfter := 2 }
    , { concreteIndex := 9, ops := [Op.interruptedPublication 1 2], generationAfter := 2 }
    , { concreteIndex := 10, ops := [], generationAfter := 2 }
    , { concreteIndex := 11, ops := [], generationAfter := 2 }
    , { concreteIndex := 12, ops := [Op.publish 2 3 [1] [], Op.decide 0 true], generationAfter := 3 }
    ]
  }

/-- Transactions in `duplicate_decide_terminal_uniqueness`, abstract index to concrete identity:
    0 = 00000000000003ef000000000000000400000000000000000000000000000000
-/
def trace_duplicate_decide_terminal_uniqueness : Trace :=
  { name := "duplicate_decide_terminal_uniqueness"
  , genesisGeneration := 1
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [], generationAfter := 1 }
    , { concreteIndex := 5, ops := [Op.publish 1 2 [0] [], Op.decide 0 true], generationAfter := 2 }
    , { concreteIndex := 6, ops := [], generationAfter := 2 }
    , { concreteIndex := 7, ops := [Op.retry 0 true], generationAfter := 2 }
    ]
  }

/-- Transactions in `genesis`, abstract index to concrete identity:
-/
def trace_genesis : Trace :=
  { name := "genesis"
  , genesisGeneration := 1
  , steps :=
    [
    ]
  }

/-- Transactions in `idempotent_duplicate`, abstract index to concrete identity:
    0 = 00000000000003ee000000000000000400000000000000000000000000000000
-/
def trace_idempotent_duplicate : Trace :=
  { name := "idempotent_duplicate"
  , genesisGeneration := 1
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [], generationAfter := 1 }
    , { concreteIndex := 5, ops := [Op.publish 1 2 [0] [], Op.decide 0 true], generationAfter := 2 }
    , { concreteIndex := 6, ops := [Op.sealRequest 0], generationAfter := 2 }
    ]
  }

/-- Transactions in `multi_decision_batch`, abstract index to concrete identity:
    0 = 00000000000003ec000000000000000400000000000000000000000000000000
    1 = 00000000000003ec000000000000000600000000000000000000000000000000
-/
def trace_multi_decision_batch : Trace :=
  { name := "multi_decision_batch"
  , genesisGeneration := 1
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [Op.sealRequest 1], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [], generationAfter := 1 }
    , { concreteIndex := 5, ops := [], generationAfter := 1 }
    , { concreteIndex := 6, ops := [Op.publish 1 2 [0] []], generationAfter := 2 }
    ]
  }

/-- Transactions in `ref_forge_atomic_visibility`, abstract index to concrete identity:
    0 = 00000000000003f0000000000000000400000000000000000000000000000000
-/
def trace_ref_forge_atomic_visibility : Trace :=
  { name := "ref_forge_atomic_visibility"
  , genesisGeneration := 1
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [Op.publish 1 2 [0] [0, 1], Op.decide 0 true], generationAfter := 2 }
    ]
  }

/-- Transactions in `refusal_only`, abstract index to concrete identity:
    0 = 00000000000003eb000000000000000400000000000000000000000000000000
-/
def trace_refusal_only : Trace :=
  { name := "refusal_only"
  , genesisGeneration := 1
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [Op.publish 1 2 [] [], Op.decide 0 false], generationAfter := 2 }
    ]
  }

/-- Transactions in `simple_commit`, abstract index to concrete identity:
    0 = 00000000000003ea000000000000000400000000000000000000000000000000
-/
def trace_simple_commit : Trace :=
  { name := "simple_commit"
  , genesisGeneration := 1
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [Op.publish 1 2 [0] [], Op.decide 0 true], generationAfter := 2 }
    ]
  }

/-- Every projected history in this build. -/
def all : List Trace :=
  [ trace_cas_loss_retry
  , trace_duplicate_decide_terminal_uniqueness
  , trace_genesis
  , trace_idempotent_duplicate
  , trace_multi_decision_batch
  , trace_ref_forge_atomic_visibility
  , trace_refusal_only
  , trace_simple_commit
  ]

end FgitBridge
