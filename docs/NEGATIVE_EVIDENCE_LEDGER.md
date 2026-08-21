# Negative Evidence Ledger

**Status:** normative evidence profile  
**Version:** 1.0  
**Last revised:** 2026-08-20

FrankenGit records failed hypotheses, invalidated designs, unsafe shortcuts, non-reproducing benchmarks, and incomplete proof attempts as durable project knowledge. Positive evidence alone creates selection bias: agents repeatedly rediscover attractive ideas whose failure artifacts were never preserved.

## 1. Purpose

A negative-evidence entry answers:

- What was proposed?
- What exact assumptions made it plausible?
- What experiment/model/review was run?
- What failed, under which workload and version?
- Was correctness, performance, operability, economics, or evidence quality the blocker?
- Which narrower claim remains valid?
- What changed conditions would justify revisiting it?
- Which code/artifacts/commits reproduce the result?

The ledger is not a graveyard of opinions. Each entry is tied to evidence and has a scope.

## 2. Required entry classes

- `correctness_counterexample`;
- `model_counterexample`;
- `performance_regression`;
- `tail_or_memory_regression`;
- `operational_complexity`;
- `economic_loss`;
- `security_boundary_failure`;
- `conformance_divergence`;
- `non_reproducible_result`;
- `insufficient_evidence`;
- `dependency_rejection`;
- `abandoned_migration`;
- `overclaim_correction`.

## 3. Initial architectural negative evidence

Every entry names its machine row in `registries/negative_evidence.tsv`; the revisit protocol in §4 cites that ID. The two lists must stay in one-to-one correspondence — a prose entry without a registry row, or a registry row without a rationale here, is a ledger defect.

1. **Repository-local C Git as production engine** (`NEG-002`) — rejected by the pure-Rust/memory-safety/dependency constitution. C Git remains an external conformance oracle only.
2. **External relational ref database plus object log as two truths** (`NEG-001`) — rejected in favor of one immutable decision log and CAS authority head. A local FrankenSQLite row may implement the same authority primitive but does not create a competing model.
3. **One lease-owned primary required for correctness** (`NEG-013`) — rejected when authority backend supplies proven linearizable CAS; rendezvous-selected executor is an optimization.
4. **Different ref names imply independent commits** (`NEG-003`) — false because policy, forge entities, quota, retention, merge queue, and shared metadata can overlap. Exact witnesses are required.
5. **Lower-level lock elimination proves end-to-end concurrent-writer scaling** (`NEG-014`) — false in FrankenFS/SQLite-style systems when higher shared metadata remains a first-committer-wins hotspot.
6. **Successful RaptorQ decode is repair** (`NEG-004`) — false until original digest/OID/structure and current placement authority verify.
7. **Search/graph centrality can authorize review or merge** (`NEG-006`) — rejected; rankings are evidence/candidate selection only.
8. **GitHub Actions status is release evidence** (`NEG-005`) — rejected; local DSR lane receipts and signed root-last manifest are authoritative.
9. **Probabilistic have-summary can prove transfer completeness** (`NEG-015`) — false; closure verification and exact repair are mandatory.
10. **A benchmark speedup justifies semantic drift** (`NEG-016`) — rejected by optimization proof and claim-lattice rules.
11. **Silent rollback to an older valid checkpoint is safe** (`NEG-007`) — false when a newer acknowledged generation is structurally present but fails authentication/closure; recovery must fail closed or perform an explicit restore event.
12. **A green CI receipt proves code safety** (`NEG-017`) — false beyond the named runner/input/check evidence class.
13. **Unsafe or FFI shortcuts are required for world-class Git performance** (`NEG-008`) — rejected; algorithmic work reduction, safe SIMD, and layout evidence are the strategy, and any exception would require a public constitutional amendment.
14. **A periodic repository capsule can serve as an ordinary current-state pin** (`NEG-009`) — rejected; an `AuthorityReadReceipt` plus optional checkpoint suffix is required, because a capsule proves a past state, not currentness.
15. **Banning a few known-bad crates is a closed dependency policy** (`NEG-010`) — rejected; closed-world means every resolved dependency, including transitive ones, must match an explicit active allow row.
16. **Search, semantic, and graph shards from different generations may be combined opportunistically** (`NEG-011`) — rejected; exact source positions and declared join receipts are required.
17. **A dormant full/release lane may return success with an explanatory message** (`NEG-012`) — rejected; dormant release-blocking lanes return a typed refusal (exit 3), never a false green.

### Implementation-era entries

Section 3 records what design review rejected before code existed. This subsection records what running code disproved, in the same one-to-one correspondence with the registry.

18. **A canonical decoder that validates every field accepts only canonical bytes** (`NEG-018`) — false, and found by the `FG-002c` mutation campaign rather than by review. The codec validated every field it read and re-verified collection ordering on the way in, but the frame carries a codec minor and a schema minor that a strict decode never compared against its own. Bumping either left the payload untouched, so the mutant decoded to the *canonical value* while carrying different bytes: `encode(decode(b)) == b` failed, which is invariant 1 of `docs/ADR-0002-CANONICAL-CODEC.md`. Identity still differed, because the codec version travels inside it, so this was never an identity collision — it was a second encoding of one value, which is the defect one step upstream of one. The general lesson is the entry: **a field a decoder reads but never compares is a field that admits a second encoding**, and "I validated everything I parsed" is not the same claim as "I accept only what I would emit". Strict decoding now refuses any minor it cannot reproduce; the preserving path still accepts and relays such a body byte-for-byte, so forward compatibility was not the price.

## 4. Revisit protocol

A rejected idea may be revisited only when the proposal identifies:

- the prior ledger ID;
- the exact assumption or implementation condition that changed;
- a new experiment designed to discriminate the old failure mode;
- safety/rollback limits;
- the claim level sought.

A new benchmark on different hardware without addressing the old correctness counterexample is not a revisit.

## 5. Integration with agents

Context Packets for architecture/performance work include relevant negative-evidence rows. An agent proposing a known-rejected dependency or mechanism must cite and rebut the row. The system does not block creative reconsideration; it prevents amnesia.

## 6. Retention

Negative evidence is append-only. A row may be superseded by a later result, but it is not deleted or rewritten. Supersession links preserve both artifacts and explain why the conclusion changed.
