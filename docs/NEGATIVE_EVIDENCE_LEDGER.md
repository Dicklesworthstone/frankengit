# Negative Evidence Ledger

**Status:** normative evidence profile  
**Version:** 1.0  
**Last revised:** 2026-08-22

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
19. **Host-probed BLAKE3 assembly is reproducible and constitutionally admissible** (`NEG-019`) — false. `blake3 1.8.7` chooses x86-64 assembly after probing the host C compiler, so identical source and lockfile can link different native objects on hosts with different toolchains. The `FG-069a` interim remedy forces `blake3/pure` through Cargo feature unification. A fresh-target syntax gate then observed zero BLAKE3 native object/archive artifacts and zero active `_ffi` cfg emissions; its only x86 cfg emissions select Rust intrinsics. This is not a performance claim: the portable path is required until a safe, reproducible SIMD path is admitted.

20. **A stored-block pack profile is size-competitive with upstream `git pack-objects`** (`NEG-020`) — false, and quantified rather than merely asserted. `FG-017b` packed three corpora chosen to span compressibility regimes and handed the *identical object sets* to pinned git 2.54.0:

    | corpus | source | FrankenGit | git | ratio |
    |---|---|---|---|---|
    | compressible (long runs) | 197 520 | 197 901 | 1 513 | **130.80×** |
    | similar (near-identical revisions) | 166 550 | 8 467 | 2 098 | **4.04×** |
    | **history (twelve commits, trees, revisions)** | **28 408** | **5 997** | **3 553** | **1.69×** |
    | incompressible (pseudo-random) | 197 568 | 197 949 | 197 623 | **1.00×** |

    **Read the history row, not the headline.** The 130× is a synthetic worst case built from long byte runs. On a real commit history — commits, per-revision trees, a stable subdirectory, successive blob revisions, which is the shape an actual fetch carries — the penalty is **1.69×**. An earlier revision of this entry published only the synthetic figure and thereby overstated the practical cost; the history corpus was added on the writer owner's recommendation and this row was corrected before the bead was verified.

    The monotone ordering is the mechanism evidence: the gap collapses to framing overhead exactly where DEFLATE has nothing to remove, so the loss *is* compression rather than something else wearing its clothes. Our own delta selection is doing real work — 166 KB to 8.5 KB on the `similar` corpus, a 20× reduction — and git still wins there 4× by deltifying *and* compressing.

    This is a **designed** loss, not a regression: `PackWriteProfile::STORED_V1` documents stored blocks as the price of an especially auditable first slice, and this row is the baseline a later compressing profile must beat. The benchmark lane *asserts* the loss (`FG-017B-BENCH-041`): if FrankenGit ever packs the compressible corpus no larger than git, the profile is not storing and the lane fails loudly rather than quietly reporting an improvement nobody designed.

    Two limits belong with the number. Only **size** was compared; the timing arms are not comparable, because FrankenGit's is an in-process call while git's is a sandboxed process spawn paying fork, exec, linking and sandbox setup before it packs anything, and dividing them would produce a figure that looks like a speed-up and measures process startup. CPU and RSS were not measured at all. The corpora are small and synthetic, and plan §38.4 is explicit that a microbenchmark cannot carry an end-to-end claim — which is moot here, since the only comparable dimension is a loss.

21. **The `FG-014b` flat-combining benchmark can support a latency comparison at the harness minimum sample count** (`NEG-021`) — false, and false in *both* directions, which is the part worth recording. Flat combining is a real structural win on the honest metric the bead names: committed decisions per authority CAS rises from 1 to the batch size, and that is **counted rather than timed**, so it cannot be noise. The latency comparison is a different claim and the measurement will not carry it. Across six runs at `MIN_SAMPLES_PER_VARIANT = 3`, the A/A noise floor swung **36x** (16,951 to 613,409 ns) and the baseline-candidate p95 delta swung **1,348x** (52,568 to 70,838,847 ns, the largest a scheduling outlier), and the "delta clears the noise floor" verdict **flipped between runs**. The first run observed showed the delta comfortably *inside* the floor, which invited the conclusion "combining is not faster" — and that conclusion was as unsupported as the speedup claim it replaced. The general lesson is the entry: **an A/A control does not license a latency claim merely by existing; it licenses one only when the floor is stable relative to the effect being claimed.** A benchmark whose instrument varies by more than its signal is evidence about the instrument. This is the `NEG-014` shape one level down — eliminating compare-and-exchange attempts at one level is not an end-to-end result — and the test pins the sample count so that raising it becomes a deliberate act that revisits this row rather than quietly making a claim admissible.

22. **A successful authority publication establishes the `Durable` epoch** (`NEG-023`) — rejected as an active applicability limit, not as a claim that checkpointing is unreachable. `FsqliteAuthorityStore` witnesses a candidate body as `Staged` before the exact-predecessor head CAS and as `Visible` after CAS plus a head read; `PublicationOutcome::Published` therefore establishes only `Visible`. A checkpoint is driveable and observable from a **test-owned second connection** issuing `PRAGMA wal_checkpoint`, but not from the store's published surface, whose closed statement set has no `PRAGMA`. More importantly, that result is whole-log backfill state (`busy`, `log`, `checkpointed`), not an event attributable to one publication. It cannot answer whether a particular transaction has reached `Durable`; WAL sidecar size is likewise not a per-publication witness. This does not contradict `NEG-022`: that row preserves the disproven hypothesis that the checkpoint-under-load cell was unreachable, whereas this row records the true, expected-to-remain limit of the shipped authority surface. The reopen condition is concrete: a caller that needs durable-before-acknowledge must define the required per-publication durability profile and witness before a new production surface is justified.

### NEG-024 — CALM registry coverage is not enforceable yet (FG-012 acceptance 5c)

**Hypothesis.** Every operation classified in `registries/calm_operations.tsv` can be shown to have a
first-party implementation, making registry *coverage* — a built operation must have a row —
mechanically enforceable.

**Disposition: NOT ENFORCED, recorded as a named open weakness rather than dropped.** Two facts
block it. Zero of the fourteen classified operations have a first-party implementation today, so
there is nothing to check coverage against; and no checker can currently enumerate "the operations
this system implements" in order to prove a built one is missing its row. Enforcing coverage now
would create an obligation nobody can discharge, and quietly dropping it would discard a real future
requirement because it is inconvenient today.

**What IS enforced instead.** FG-012 acceptance 5a: every value in the registry's `class` column must
be one of the seven coordination classes declared in
[`docs/CALM_AND_OBLIGATIONS.md`](CALM_AND_OBLIGATIONS.md) section 1, validated by
`tools/registry-check` and parsed from that document rather than restated in the checker. That makes
the rows load-bearing today — running code branches on them — and guards the vocabulary against
drift while coverage remains unenforceable.

**Revisit condition.** The first operation named in `calm_operations.tsv` gains a first-party
implementation. At that point coverage is checkable for at least that operation, and the enumeration
question stops being hypothetical.

**Why this is retained rather than closed.** The registry is a design-time classification of a system
that is mostly unbuilt. An unenforced obligation that is *named* stays visible to the next reader; an
unenforced obligation that is deleted becomes a gap nobody knows to look for.

## 4. Revisit protocol

A rejected idea may be revisited only when the proposal identifies:

- the prior ledger ID;
- the exact assumption or implementation condition that changed;
- a new experiment designed to discriminate the old failure mode;
- safety/rollback limits;
- the claim level sought.

A new benchmark on different hardware without addressing the old correctness counterexample is not a revisit.

### NEG-025 — a fixed-point Beta expected-loss recurrence returns 0 ppm, silently (FG-054)

**Hypothesis.** `P(theta_b > theta_a)` for two Beta posteriors can be evaluated in bounded
fixed-point integer arithmetic by iterating its exact term recurrence at a large scale, so
`fgit-statistics` needs no arbitrary-precision rationals to implement Beta-Bernoulli expected loss.

**Disposition: DISPROVEN BY MEASUREMENT, and the failure mode is the dangerous one.** A `u128`
implementation at scale `1e24` returns **exactly `0` ppm** for ordinary parameter sizes. That is not
an inaccurate answer, it is a confidently wrong one: `0 ppm` reads as *the candidate policy never
beats the fallback*, which would pin a controller to its fallback permanently while presenting as
evidence. The closed form and its recurrence are exact and were independently confirmed; it is the
fixed-point **evaluation** that fails.

This is recorded because the approach is the obvious one and looks sound from every angle that
usually matters. The recurrence is factorial-free, every factor is a small rational of the
parameters, and nothing in its shape suggests underflow.

**Evidence.** The series spans more dynamic range than any fixed scale can hold. Measured `T0`
against exact rational values:

| parameters | `T0` | peak term |
|---|---|---|
| `Beta(3,4)` vs `Beta(5,2)` | `3.571e-01` | `3.571e-01` |
| `Beta(101,101)` vs `Beta(151,51)` | `7.166e-14` | `3.275e-02` |
| `Beta(501,501)` vs `Beta(601,401)` | `2.955e-96` | `1.053e-02` |
| `Beta(1001,1001)` vs `Beta(1501,501)` | `1.169e-129` | `1.031e-02` |

The peak term is `~1e-2` in every case, so the series **starts negligibly small and grows**,
spanning roughly 127 orders of magnitude between its first term and its peak, while `u128` offers
about 38 decimal digits. `T0` truncates to `0` at scale `1e24`, and every later term is `0 * ratio
= 0`. Exact-rational evaluation agrees with numerical integration on four parameter sets, including
the symmetric control `Beta(2,2)` vs `Beta(3,3)` = `500000` ppm exactly, so the mathematics is not
in question.

**Revisit when** someone implements a mantissa-plus-exponent representation (which is reinventing
floating point and owes its own constitutional argument), or arbitrary-precision rationals (no
admitted crate provides them), or restructures the summation to begin at the peak term and work
outward so no value near `T0` is ever represented. The last is plausible and unanalysed.

**Superseded 2026-08-22 by `529b8a7` (`frankengit-s76z`), on the third route.** The clause above is
discharged as written: `crates/fgit-statistics/src/expected_loss.rs` finds the peak index, evaluates
`T(peak)` directly as a balanced product of consecutive-integer runs, and walks outward in both
directions. No value near `T0` is ever represented.

**The registry row stays `active`, deliberately.** Section 6 speaks of supersession, but
`registries/negative_evidence.tsv` admits only
`active|specified|implemented|verified|experimental|rejected`, so there is no `superseded` value to
set -- and on the merits `active` is the right one anyway. This row warns against evaluating the
recurrence upward from `T0` in fixed point, and that warning is exactly as true now as it was
before. What changed is that one of its three named revisit routes was taken. The supersession is a
link, recorded here, not a retraction. If a machine-readable supersession status is wanted, that is
a checker-vocabulary change and belongs to whoever owns `tools/registry-check`.

Per section 6 this entry is not rewritten, because **most of it is still true and still
load-bearing**:

- the hypothesis as stated — that iterating the recurrence *from `T0`* at a fixed scale suffices —
  remains **disproven**, and the measured `T0` values above remain the reason;
- the dynamic-range analysis is what *selected* the replacement, so it is the entry's most useful
  part, not its obsolete part;
- the underflow region did not disappear. Concentrated far-from-even posteriors still push
  `T(peak)` itself below `2^-96`. What changed is that underflow is now **observable** rather than
  silent: the running value reaches zero and the function returns
  `ExpectedLossRefusal::PeakTermUnrepresentable` instead of a plausible `0 ppm`. Measured over the
  sweep below, every set that refuses has an exact value under `1 ppm`, and that property is
  asserted rather than assumed.

What the replacement owes and pays, measured against exact rational evaluation of the same closed
form (generator committed at `crates/fgit-statistics/tests/oracle/generate.py`, swept by
`crates/fgit-statistics/tests/expected_loss_error_evidence.rs`):

| region | measurement |
|---|---|
| 500 deterministic sets, all parameters in `1..=300` | 457 answer, 43 refuse |
| the 457 answers | every one equals the exact floor **exactly**; 327 have a non-zero exact value |
| direction | **zero overestimates** — every division floors |
| the 43 refusals | every one has an exact value below `1 ppm` |
| exact ppm boundaries (a posterior against itself) | short by **exactly 1 ppm, never more**, over `Beta(n,n)` for `n` in `1..=200` |

The stated bound is therefore **1 ppm, one-directional**, attained only at exact ppm boundaries. The
random sweep alone would have supported a tighter claim of `0`; it is not made, because a randomly
drawn parameter set essentially never lands on a boundary, and the boundary is the only place the
flooring can move the reported integer.

The one-directional half is the part a controller depends on. An under-stated
`P(theta_b exceeds theta_a)` under-states a candidate policy's advantage over its fallback, so the
error can delay a policy switch but never provoke one. Rounding the final conversion to nearest
would make the boundary cases exact and would cost exactly that property, so it is not done.

**Still unattempted, and still owed their own constitutional argument:** the other two routes named
above. Widening the representable region past `2^-96` needs a mantissa-plus-exponent representation
or arbitrary-precision rationals, and neither is introduced here.

## 5. Integration with agents

Context Packets for architecture/performance work include relevant negative-evidence rows. An agent proposing a known-rejected dependency or mechanism must cite and rebut the row. The system does not block creative reconsideration; it prevents amnesia.

## 6. Retention

Negative evidence is append-only. A row may be superseded by a later result, but it is not deleted or rewritten. Supersession links preserve both artifacts and explain why the conclusion changed.
