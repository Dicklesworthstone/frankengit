# FG-041 ordered-residue Lean proof and trace replay

Run the local, fail-closed checker with:

```bash
bash proofs/fg041/check.sh
```

The ordinary command replays all checked-in reference histories, compares the
generated vectors byte for byte with the copy the kernel will import, and checks
the projected steps with Lean. Set `FGIT_PROOF_BRIDGE_BIN` to the
`fgit-proof-bridge-gen` built from the source revision under test to use that
executable. Otherwise set `CARGO_TARGET_DIR` to a private target directory.
The checker builds the locked generator for the caller’s host and reads this
checkout. All Lean outputs stay in a temporary directory.

Rust replay checks the recorded outcome, root bytes, and head position after
each step. For each winning publication the exporter reads the newly published
decisions in decision-sequence order and checks each transaction and outcome
against that head's recorded roots. This preserves the commit and refusal in
`multi_decision_batch`. The kernel checks that each new terminal belongs to a
previously sealed, undecided transaction, that retries observe its prior label,
and that the generation, total decisions and committed subset match each recorded head.

Run `./scripts/verify.sh proof` for the corpus, schedule, false-theorem and
registry-demotion checks together. Run `bash proofs/fg041/check.sh --dpor`
to check the corpus and two freshly scheduled publications. The compatibility
entry point `check_dpor.sh` runs the same checks. The concurrency lab schedules the two staged batches in
`cas_loss_retry.fgtrace` at their common predecessor. Exactly one update must
win and the losing CAS must preserve the winning head and roots. In both
orders the bridge reprepares the original losing request on that head and
publishes its revalidated outcome. The kernel checks that each writer wins
the first CAS once and that the other sealed writer commits its distinct ref
in the next generation, as required by the two disjoint requests in this fixture. The reference histories
and this race cover a bounded model. Production storage and native crash
recovery have separate verification lanes.

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

CLM-002 (terminal uniqueness) and CLM-004 (head continuity) bind the checked
vectors and the refinement checker by SHA-256. The proof lane alters a private
copy and requires both claims to demote while the two model-only rows retain
their original bindings. INV-001 also requires the authority CAS and recovery
campaigns before release qualification.

## Non-claims

The kernel checks theorems about the contained Lean model. The reference
goldens and two scheduled executions provide finite comparisons with the Rust
reference model. General implementation refinement and native durable
publication require additional evidence. The repository authority head
continues to decide publication.
