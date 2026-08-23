# FG-041b: ordered-residue Lean lane

Run the local, fail-closed checker with:

```bash
bash proofs/fg041/check.sh
```

The script refuses a missing or mismatched `leanprover/lean4:v4.32.0`
toolchain, never asks `elan` to install one, rejects `sorry`/`admit` in the
artifact, checks every theorem below, and verifies that the same checker
rejects the planted false equality in `FalseVariant.lean` for the expected
reason.

| Bead acceptance | Lean theorem | Machine-check test |
|---|---|---|
| At most one terminal outcome per sealed `TxId` | `terminal_outcome_is_unique` | `check.sh` compiles `OrderedResidue.lean`; opposite-outcome retry is part of the theorem's transition closure. |
| Exact-predecessor head continuity and monotone generation | `accepted_publish_is_continuous`, `head_chain_is_continuous_and_monotone` | `check.sh` compiles both; an external CAS bridge must additionally supply the named FG-004 axiom. |
| Atomic ref/forge visibility | `ref_and_forge_visibility_is_atomic` | `check.sh` proves that one accepted publication exposes both vectors from one batch. |
| No lost/fabricated outcome under crash, lost response, and retry | `unsealed_decision_is_not_fabricated`, `crash_retry_does_not_lose_or_fabricate_decision` | `check.sh` proves both; the retry theorem uses an opposite terminal-outcome candidate. |
| Anti-rollback under interrupted publication | `interrupted_publication_is_anti_rollback` | `check.sh` proves both visible generation and published batch remain unchanged. |

`ASSUMPTIONS.md` maps each explicit Lean axiom to its named FG-004,
fault-conformance, or publication-epoch empirical gate. Those gates are
finite empirical evidence, not hidden universal proof assumptions.

## Non-claims

This is a machine-checked theorem about the contained Lean model. It is not a
proof that the Rust implementation refines the model, a proof-equivalence
lane, a durable-publication proof, or a source of canonical runtime authority.
Those require the future FG-041c trace-refinement and bridge work.
