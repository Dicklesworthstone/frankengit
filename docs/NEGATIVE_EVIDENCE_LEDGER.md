# Negative Evidence Ledger

**Status:** normative evidence profile  
**Version:** 1.0  
**Last revised:** 2026-08-19

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

The first ledger rows include:

1. **Repository-local C Git as production engine** — rejected by the pure-Rust/memory-safety/dependency constitution. C Git remains an external conformance oracle only.
2. **External relational ref database plus object log as two truths** — rejected in favor of one immutable decision log and CAS authority head. A local FrankenSQLite row may implement the same authority primitive but does not create a competing model.
3. **One lease-owned primary required for correctness** — rejected when authority backend supplies proven linearizable CAS; rendezvous-selected executor is an optimization.
4. **Different ref names imply independent commits** — false because policy, forge entities, quota, retention, merge queue, and shared metadata can overlap. Exact witnesses are required.
5. **Lower-level lock elimination proves end-to-end concurrent-writer scaling** — false in FrankenFS/SQLite-style systems when higher shared metadata remains a first-committer-wins hotspot.
6. **Successful RaptorQ decode is repair** — false until original digest/OID/structure and current placement authority verify.
7. **Search/graph centrality can authorize review or merge** — rejected; rankings are evidence/candidate selection only.
8. **GitHub Actions status is release evidence** — rejected; local DSR lane receipts and signed root-last manifest are authoritative.
9. **Probabilistic have-summary can prove transfer completeness** — false; closure verification and exact repair are mandatory.
10. **A benchmark speedup justifies semantic drift** — rejected by optimization proof and claim-lattice rules.
11. **Silent rollback to an older valid checkpoint is safe** — false when a newer acknowledged generation is structurally present but fails authentication/closure; recovery must fail closed or perform an explicit restore event.
12. **A green CI receipt proves code safety** — false beyond the named runner/input/check evidence class.

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
