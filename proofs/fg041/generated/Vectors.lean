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

/-- Transactions in `cas_loss_retry`, abstract index to concrete identity:
    0 = 00000000000003ed000000000000000400000000000000000000000000000000
    1 = 00000000000003ed000000000000000d00000000000000000000000000000000
-/
def trace_cas_loss_retry : Trace :=
  { name := "cas_loss_retry"
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [Op.sealRequest 1], generationAfter := 1 }
    , { concreteIndex := 5, ops := [], generationAfter := 1 }
    , { concreteIndex := 6, ops := [], generationAfter := 1 }
    , { concreteIndex := 7, ops := [], generationAfter := 1 }
    , { concreteIndex := 8, ops := [Op.publish 1 2, Op.decide 1 true], generationAfter := 2 }
    , { concreteIndex := 9, ops := [Op.interruptedPublication 1 2], generationAfter := 2 }
    , { concreteIndex := 10, ops := [], generationAfter := 2 }
    , { concreteIndex := 11, ops := [], generationAfter := 2 }
    , { concreteIndex := 12, ops := [Op.publish 2 3, Op.decide 0 true], generationAfter := 3 }
    ]
  }

/-- Transactions in `genesis`, abstract index to concrete identity:
-/
def trace_genesis : Trace :=
  { name := "genesis"
  , steps :=
    [
    ]
  }

/-- Transactions in `idempotent_duplicate`, abstract index to concrete identity:
    0 = 00000000000003ee000000000000000400000000000000000000000000000000
-/
def trace_idempotent_duplicate : Trace :=
  { name := "idempotent_duplicate"
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [], generationAfter := 1 }
    , { concreteIndex := 5, ops := [Op.publish 1 2, Op.decide 0 true], generationAfter := 2 }
    , { concreteIndex := 6, ops := [Op.sealRequest 0], generationAfter := 2 }
    ]
  }

/-- Transactions in `multi_decision_batch`, abstract index to concrete identity:
    0 = 00000000000003ec000000000000000400000000000000000000000000000000
    1 = 00000000000003ec000000000000000600000000000000000000000000000000
-/
def trace_multi_decision_batch : Trace :=
  { name := "multi_decision_batch"
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [Op.sealRequest 1], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [], generationAfter := 1 }
    , { concreteIndex := 5, ops := [], generationAfter := 1 }
    , { concreteIndex := 6, ops := [Op.publish 1 2, Op.decide 0 true, Op.decide 1 true], generationAfter := 2 }
    ]
  }

/-- Transactions in `refusal_only`, abstract index to concrete identity:
    0 = 00000000000003eb000000000000000400000000000000000000000000000000
-/
def trace_refusal_only : Trace :=
  { name := "refusal_only"
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [Op.publish 1 2, Op.decide 0 true], generationAfter := 2 }
    ]
  }

/-- Transactions in `simple_commit`, abstract index to concrete identity:
    0 = 00000000000003ea000000000000000400000000000000000000000000000000
-/
def trace_simple_commit : Trace :=
  { name := "simple_commit"
  , steps :=
    [ { concreteIndex := 0, ops := [Op.sealRequest 0], generationAfter := 1 }
    , { concreteIndex := 1, ops := [], generationAfter := 1 }
    , { concreteIndex := 2, ops := [], generationAfter := 1 }
    , { concreteIndex := 3, ops := [], generationAfter := 1 }
    , { concreteIndex := 4, ops := [Op.publish 1 2, Op.decide 0 true], generationAfter := 2 }
    ]
  }

/-- Every projected history in this build. -/
def all : List Trace :=
  [ trace_cas_loss_retry
  , trace_genesis
  , trace_idempotent_duplicate
  , trace_multi_decision_batch
  , trace_refusal_only
  , trace_simple_commit
  ]

end FgitBridge
