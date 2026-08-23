# ADR-0016: Proof Toolchain Selection Is Evidence-Gated, and Model/Code Equivalence Is a Failing Local Lane

- **Status:** **accepted (2026-08-23 owner ruling)** — `leanprover/lean4:v4.32.0` is admitted only as the pinned, sandboxed, non-production checker for the FG-041 ordered-residue proof lane. The selected model proof is not a proof of Rust implementation equivalence; that bridge remains an explicit later gate.
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture and verification
- **Scope:** FG-041's ordered residue only: seals, terminal outcomes, batch normal form, authority-head replacement, and root-last publication. This ADR does not broaden the proof target to Git parsing, storage implementations, authorization policy, performance, or the hosted service.
- **Binds:** `frankengit-fg041a-proof-toolchain-cww`, `frankengit-fg041b-proof-theorems-qpa`, `frankengit-fg003-reference-model-gyi`, and `frankengit-fg009-batch-head-km6`
- **Spec sections:** [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md`](../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md) §§40.1–40.8, 41.2–41.5; [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md) §§8.1–8.4, 10, 27, 29–30; [`VERIFY_SPEC.md`](../VERIFY_SPEC.md) §§1–4, 8.1–8.4, 10.2–10.3, 24–27; [`DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md`](DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md) §§2.3, 6–7; [`SECURITY_THREAT_MODEL.md`](../SECURITY_THREAT_MODEL.md) §§1.1, 1.6, 5, 6; and `registries/claim_classes.tsv`.

## Context

The executable `fgit-reference` crate is deliberately the semantic oracle: it
is pure, deterministic, replayable, and has checked-in canonical
`*.fgtrace` histories. The deterministic lab and its DPOR/lincheck-style
campaigns explore bounded schedule classes and emit schedule/bound/replay
receipts. Those are important E2 evidence, but a bounded exploration is not
an unbounded theorem, and a theorem over a hand-copied abstraction is not a
theorem about the Rust implementation.

Plan §40.8 deliberately reserves mechanization for the small ordered residue.
The value of doing that is lost if either of two drift paths remains open:

1. the assistant model differs from `fgit-reference`; or
2. implementation histories differ from the model whose theorem was checked.

This ADR supplies a selection procedure and the required bridge. The owner
ruling recorded above selects the first contained checker under that procedure;
it does not convert the current Lab campaign into a proof claim.

## Settled boundaries

The following are already fixed; a candidate tool may not redefine them.

| Binding | Requirement | Authoritative source |
|---|---|---|
| Canonical linearization | Only an exact-predecessor conditional replacement of `RepositoryAuthorityHead` publishes the batch and its terminal decisions. | `NORMATIVE_PROTOCOL_CONTRACTS.md` §8.3 |
| Canonical algorithm | The proof model may describe only the semantic states/transitions of the canonical transaction algorithm; it may not insert a second commit, policy, or authority path. | `NORMATIVE_PROTOCOL_CONTRACTS.md` §10 |
| Ordered-residue scope | The target is seal/outcome uniqueness, batch/head continuity, atomic ref/forge visibility, crash/retry safety, and anti-rollback. | plan §40.8; `VERIFY_SPEC.md` §§8.1–8.4 |
| Model-to-code connection | A theorem over an abstraction needs executable trace refinement and fault evidence before it supports an implementation claim. | plan §40.5 |
| Claim strength | Bounded exploration needs bounds and replay; a formal proof needs a checker and assumptions; neither may silently upgrade another claim. | `VERIFY_SPEC.md` §2; `NORMATIVE_PROTOCOL_CONTRACTS.md` §27; `registries/claim_classes.tsv` |
| Runtime authority | Proof/model output cannot affect head order, policy, authorization, retention, or canonical publication; it is verification evidence, never a product authority input. | `NORMATIVE_PROTOCOL_CONTRACTS.md` §§8, 10, 29; `SECURITY_THREAT_MODEL.md` §§1.1, 6 |
| Tooling boundary | A proof tool is quarantined verification tooling, not a production dependency. It must be pinned, reviewable, reproducible from tracked inputs, and unable to acquire network or ambient secrets in a local lane. | `DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md` §§2.3, 6–7; `VERIFY_SPEC.md` §§1, 24 |

The reference model's canonical trace format is the bridge's initial common
input vocabulary. `crates/fgit-reference/tests/goldens/*.fgtrace` are not
regenerated to hide a disagreement: a semantic change must visibly change the
golden and then satisfy the bridge lane. That follows the reference-model
acceptance in `docs/INITIAL_ISSUE_BACKLOG.md` FG-003 and the local-evidence
doctrine in `VERIFY_SPEC.md` §§1 and 24.

## Decision (accepted)

### 1. Select a tool by disqualifying gates before scored comparison

The accepted checker is Lean 4.32.0. Any replacement assistant or embedding
MUST identify the exact source revision, release/checker identity, license,
host targets, all package/build dependencies, proof kernel or trusted base,
axioms/unsafe escape hatches, and the command that replays the result locally.
It is refused before scoring if any of the following is false:

1. **Local, pinned, and offline.** The checker and its dependencies are
   identity-bound in a tracked evidence manifest and can run without network,
   ambient secrets, or hosted status. A remote prover may produce advisory
   diagnostics but cannot satisfy a required local lane.
2. **Verification-only containment.** It does not enter a first-party
   production Cargo feature graph, create a second async runtime, add FFI or
   first-party unsafe, or alter canonical code generation by an unreviewed
   side channel. Any helper binary executes only in the verification trust
   zone and has a bounded, recorded invocation.
3. **Checkable theorem artifact.** The candidate has a replayable checker,
   exposes its trusted assumptions, and rejects a planted false theorem. A
   successful command that merely parses source or trusts an opaque cache is
   not a proof checker.
4. **Bridge feasibility.** It can consume a total, versioned projection of
   the reference-model input/output vocabulary, or a generator can derive its
   model input from those definitions. It must support exact comparison over
   the FG-003b golden traces and finite generated state spaces.
5. **Maintained exit path.** The candidate report names the maintenance
   burden (proof/bridge LOC, update workflow, reviewer skills, and expected
   toolchain churn) and a removal path that leaves the Rust reference model
   and its goldens runnable. A tool that owns the only semantic definition is
   disqualified.

Only candidates that clear every gate are compared on four recorded factors:

| Factor | Required evidence, not reputation |
|---|---|
| Dependency-constitution fit | exact supply-chain/unsafe/build-tool inventory, local/offline replay, and containment outside production |
| Rust connection | generated-model or differential-bridge prototype, trace projection coverage, and a planted drift it catches |
| Proof maintenance | small theorem spike, disclosed trusted assumptions, reviewable diff shape, and a dated-toolchain update exercise |
| Community durability | current release/support evidence, documented checker/kernel ownership, and a reproducible clean-host setup at the selected revision |

The candidate report records alternatives, measurements, and negative results.
No weighted score can override a failed disqualifying gate. The accepting
ruling names the selected tool, exact version, runner, checker command,
trusted base, and the evidence manifest. A later version change re-runs the
same decision procedure; it is not a cosmetic tool update.

### Accepted FG-041 checker record

| Field | Accepted value |
|---|---|
| Assistant/checker | Lean 4.32.0, `leanprover/lean4:v4.32.0` |
| Source identity | Lean release commit `8c9756b28d64dab099da31a4c09229a9e6a2ef35` |
| Local command | `bash proofs/fg041/check.sh` |
| Identity manifest | `proofs/fg041/toolchain.json` |
| Trusted base | Lean kernel plus bundled `Init` and `Std` only |
| Containment | External verification process only; no Cargo dependency, production link, runtime path, network installation, or ambient fallback |
| Negative control | The pinned checker must reject `proofs/fg041/FalseVariant.lean` for its false equality, not merely fail for an unrelated setup error |

Lean was chosen because the exact release is already locally installed and can
be invoked through the pinned `elan` selector without installation or network
access. Coq and Isabelle remain recorded alternatives, not implied failures or
inferior proof systems: no equally pinned, locally replayable candidate bundle
for either is accepted by this decision. `DEP-221` and `NEG-028` record the
dependency boundary and the refusal of ambient/unpinned tooling.

### 2. Compare the right alternatives honestly

The selection report MUST evaluate at least these alternatives, using the
gates above rather than treating their names as evidence:

| Alternative | Potential role | Why it is not selected by this ADR |
|---|---|---|
| A theorem assistant with a hand-maintained model (for example, a Lean, Coq, or Isabelle-style development) | Direct machine-checked statements over the ordered residue | A copied transition relation can drift from Rust; selection requires a bridge prototype and checker evidence. |
| A verification language or extraction-oriented embedding (for example, an F*/Why3-style route) | May express contracts or generate a model/program artifact | Extraction is not automatically the shipped Rust semantics; canonical byte, transition, and trace equivalence remain obligations. |
| A Rust-adjacent verifier or embedded proof route | Can keep specifications closer to Rust types and tests | It still needs a clear trusted base and must establish whether its result is proof or bounded analysis, rather than inheriting the word “verification.” |
| A temporal/model checker only | Useful DPOR/state-space complement and counterexample source | It earns only `bounded_model` evidence unless its checked theorem and assumptions meet the higher claim class; it cannot fill the proof role by terminology. |
| No mechanization; retain current Lab/model campaign only | Lowest new-tool cost | Rejected as the FG-041 endpoint because plan §40.8 specifically requires machine-checked theorems; retained as a required bounded-model and counterexample lane. |

### 3. The equivalence bridge has two admissible shapes

The selected tool MUST use one of the following bridge shapes. Both retain
`fgit-reference` as the executable oracle; neither creates a competing source
of canonical truth.

#### 3.1 Generated bridge — preferred when it is genuinely single-source

A versioned reference-definition subset produces the mechanized transition
model and its trace projection from the same checked-in definitions that
`fgit-reference` executes. The generator, input schema, output schema,
version tags, generated artifact digests, and generated-source diff are
checked in. The local lane refuses if regeneration changes an artifact without
an explicit reviewed source change.

“Generated” is the stronger bridge only if all of the following hold:

- generated model inputs cover every in-scope `ModelInput`, terminal output,
  root, and ordered event needed by the theorem;
- every omitted field has an explicit abstraction function and a checked proof
  or executable argument that the theorem cannot observe it;
- the Rust model and generated model are both run on the FG-003b goldens and
  generated finite state spaces as a defense against a generator defect; and
- a planted source/projection mutation makes the local lane fail.

Merely generating syntax from a prose table is not a generated semantic
bridge. Neither is regenerating goldens from the changed model to make a
disagreement disappear.

#### 3.2 Differential bridge — admissible bounded fallback

Until a generated bridge satisfies those conditions, the local
`proof-equivalence` lane compares `fgit-reference` with the mechanized model
over:

1. every checked-in FG-003b `*.fgtrace` history;
2. the deterministic generated state spaces used by the reference campaign,
   with exact bounds, seed/schedule identity, exploration completeness, and
   replay class retained; and
3. a seeded set of refusal, duplicate-seal, CAS-loss/retry, ref/forge, and
   interrupted-publication traces that exercise each selected theorem's
   subject.

For each input, both sides emit a versioned projection containing the input
kind, terminal outcome/refusal, ordered decision/RCR/head projection, roots,
and the relevant witness/counterexample. The comparator refuses on an absent,
extra, reordered, or unequal observable. It reports the first divergent input
and field, preserves both artifacts, and never treats an unsupported mapping
as equal.

The projection is total for the stated theorem scope. A coarser proof model
may quotient data only through a checked-in abstraction manifest that names
the omitted field, its source definition, the abstraction function, and why
the selected theorem does not observe it. An unlisted omission is lane failure.

Differential agreement is `bounded_model` evidence for the declared corpus
and bounds, even where the mechanized theorem itself is stronger. It catches
drift; it does not prove equivalence outside the explored universe.

### 4. A semantic reference-model edit must fail closed until the bridge is updated

The selected local lane is repository-owned and runs whenever either side's
semantic surface changes. Its change set includes at least:

- all `crates/fgit-reference/src/**` files, plus the FG-003b checked-in
  goldens and their fixed scenario definitions;
- the mechanized model, its projection/abstraction manifest, the generator
  where present, and all theorem inputs; and
- the bridge comparator, bounds, and receipt schema.

Every implementation that seeks a theorem-backed claim additionally registers
its trace-exporter and semantic transition paths in that lane's checked-in
manifest. No implementation may inherit model evidence merely because the
reference-model side is unchanged.

The lane's required steps are:

1. reject an unpinned toolchain, missing checker, unsupported projection, or
   incomplete replay input as a non-pass result;
2. replay every golden through both models and compare the canonical bridge
   projection;
3. enumerate the declared generated state-space corpus and compare each
   projection, recording whether the bound exhausted or truncated;
4. run planted model/projection mutations independently of the normal model
   paths and require each to be caught for its intended reason; and
5. emit an immutable receipt binding source tree, reference/generator/proof
   revisions, toolchain/checker identity, projection schema, bounds, seed,
   trace/golden digests, assumptions, result, and replay completeness.

An edit that changes model semantics but lacks an updated bridge result cannot
promote an implementation or proof claim. A false green caused by an ignored
test, untracked input, cache hit, silent golden rewrite, or truncated generated
space is a lane defect, not an acceptable downgrade. `VERIFY_SPEC.md` §§1,
2, 24–27 govern this failure disposition.

### 5. Claim routing and authority boundary

| Evidence artifact | Maximum claim it can support | What it is not allowed to do |
|---|---|---|
| Lab/DPOR/lincheck result with exhaustive stated bound, schedule, and replay | `bounded_model` (`CLAIM-003`) over that exact model/bound | Claim unbounded liveness, code equivalence, or runtime authority. |
| Checked mechanized theorem plus pinned checker and disclosed assumptions | `proof` (`CLAIM-002`) over the named mechanized model and theorem statement | Claim that Rust implements it without bridge and trace-refinement evidence. |
| Generated bridge plus theorem and implementation trace-refinement/fault evidence | A separately registered model/code claim at no more than its weakest required edge; it may be reviewed for `proof`/`invariant` only with the exact checker, assumptions, and scope recorded | Upgrade automatically, erase assumptions, or call a finite test corpus a proof. |
| Differential bridge plus theorem | `proof` for the model theorem; `bounded_model` for the declared model-to-model agreement | Establish universal model/code equivalence. |

Proof and model results are **authoritative only to the local verification
decision that consumes a valid receipt of their declared class**: a required
bridge mismatch blocks that evidence/claim/release path. They remain advisory
to the running product. They do not enter the §10 transaction algorithm, grant
capabilities, select a head, create an RCR, waive a refusal, alter retention,
or substitute for the §8.3 conditional replacement. This preserves the
authority boundary in `NORMATIVE_PROTOCOL_CONTRACTS.md` §§8 and 10 and the
derived-evidence boundary in §29.

## Evidence required before acceptance

Any successor or replacement checker may be accepted only after reviewing a
proposal bundle that
contains:

1. a candidate comparison with every disqualifying gate, all alternatives,
   exact tool/checker dependency evidence, and a local offline replay command;
2. one small machine-checked ordered-residue theorem whose false variant the
   selected checker rejects, with all assumptions and trusted components
   listed;
3. an implemented generated or differential bridge meeting section 3, with
   checked-in projection schema/abstraction manifest and planted drift
   detection;
4. a repository-owned local lane demonstrating that a semantic edit to either
   the reference model or mechanized model fails until the bridge result is
   updated; and
5. a claim-registry proposal that records the theorem's exact scope,
   assumptions, source/tool/checker identities, bridge class, replay class,
   expiry/revalidation rule, and non-claims.

The currently checked-in Lab/DPOR campaign and reference goldens are inputs to
that bundle. They do not satisfy it by themselves.

## Migration and rollback

No production migration occurs. Before a tool is selected, this ADR changes
only the review procedure. Once selected, proof artifacts are versioned
verification inputs. If the checker, generator, or bridge becomes unavailable
or fails, its claim is demoted to the strongest remaining evidence and the
proof-dependent release path refuses; the executable reference model and
ordinary local tests continue to run. No production path falls back to a proof
tool, and no historical canonical record is reinterpreted.

## Dependency, target, and unsafe consequences

`DEP-221` admits the selected assistant as a verification-only external tool;
it is not a Cargo dependency. Any generated Rust source remains first-party source: it must
obey `#![forbid(unsafe_code)]`, use no alternate runtime, and have reproducible
tracked inputs. A proof tool that needs ambient network access, a local unsafe
exception, native production linkage, or an opaque unpinned bootstrap is not
admissible for the required lane.

## Non-claims

- This ADR selects only the pinned Lean checker described above. It does not
  select Coq, Isabelle, F*, Why3, a Rust-adjacent verifier, or a model checker.
- The FG-041b Lean artifact provides machine-checked theorems over its named
  model. This ADR does not claim a generated bridge, differential bridge, or
  proof of Rust implementation equivalence exists today.
- It does not call a bounded Lab/DPOR/lincheck result a proof, an invariant, or
  an unbounded liveness result.
- It does not make proof/model output canonical authority, authorization,
  policy, or a production dependency.
- It does not prove the Rust implementation merely because `fgit-reference`
  replays its own traces. Cross-implementation comparison and trace
  refinement remain explicit required evidence.

## Supersession rule

An accepted successor may name a tool only with the evidence bundle above and
must preserve the claim and authority boundaries in this ADR. It may replace a
tool or bridge mechanism, but cannot silently weaken the fail-closed local
lane, remove checker/assumption identity, promote bounded agreement to proof,
or make proof output a second canonical authority.
