/-!
This is a planted checker control.  `check.sh` requires the pinned Lean
checker to reject it; this file is never imported by `OrderedResidue.lean`.
-/

example : (0 : Nat) = 1 := by
  rfl
