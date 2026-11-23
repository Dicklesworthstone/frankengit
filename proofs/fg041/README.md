# FG-041 ordered-residue Lean proof and trace replay

Run the local, fail-closed checker with:

```bash
bash proofs/fg041/check.sh
```

The proof E2E lane also runs `bash proofs/fg041/check_dpor.sh`.
It replays the recorded `cas_loss_retry.fgtrace` seed, then lets the
concurrency lab schedule its two competing staged batches at the common head.
For each order the reference model executes both conditional updates. Exactly
one must win, and the losing update must preserve the winner’s head and roots.
The bridge exports both executions to fresh Lean modules. The pinned kernel
checks the head generation at every projected step. This covers a single
two-writer model race. Production storage, native crash recovery, and the
other schedule spaces have separate verification requirements.

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

The kernel checks theorems about the contained Lean model. The reference
goldens and two scheduled executions provide finite comparisons with the Rust
reference model. General implementation refinement and native durable
publication require additional evidence. The repository authority head
continues to decide publication.
