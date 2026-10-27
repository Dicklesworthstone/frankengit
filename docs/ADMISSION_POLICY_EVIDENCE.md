# Durable ref-policy decision evidence

Ordinary ref publication now retains the compiled policy snapshots actually
evaluated by its final durable materializer. The existing RCR
`policy_decision_root` identifies an immutable, replayable record containing the
selected authority head, the exact pre-decision ref root, native ref facts,
policy selection, snapshots, verdicts, and traces.

This applies to the node-owned direct ref materializer used by receive,
source import, workspace publication, and other ordinary ref transitions,
including each child of a receive microbatch. An attempt that changes no refs
retains the historical evidence profile. Native merge evidence retains its
historical profile unless an activated repository DSL policy selects schema
1.2 or 1.3. Metadata remains unchanged; native review/check obligations remain in
their own canonical gates.

## Exact version preservation

| Evidence minor | Retained information | Read behavior |
| --- | --- | --- |
| 1.0 | Transaction ID, request digest, staged principal snapshot ID, policy epoch | Original payload, frame and root remain unchanged. No compiled-policy replay is claimed. |
| 1.1 | The 1.0 fields plus authority-head identity, actual input ref root, native HEAD and review selectors, native old/new ref values, evaluated snapshots, verdicts and traces | Authenticate provenance and replay the recorded snapshots against the recorded structural facts. |
| 1.2 | The complete 1.1 structural receipt plus the canonically activated repository DSL snapshot, direct/native-merge publication kind, verdict and trace | Require exact equality with the snapshot selected by the original authenticated forge frontier, then replay those stored bytes and facts. |
| 1.3 | The same structural commitments and selected snapshot, using the distinct actor-ID factual profile | Replay the exact sealed principal identifier as well as the ref facts; independently verify the principal against the admission context, sealed request and principal snapshot. |

`PolicyDecisionEvidence` remains the exact schema-1.0 canonical type.
`EvaluatedPolicyDecisionEvidence` owns schema 1.1 and
`ActivatedPolicyDecisionEvidence` owns the frozen ref-only schema 1.2.
`ActorPolicyDecisionEvidence` owns schema 1.3. `PolicyDecisionRecord`
dispatches supported minors, reproduces the selected minor's original bytes,
and computes its original root. Unknown minors, profiles, substituted snapshot
identities, malformed inputs, changed verdicts, and changed traces are refused.
No historical record is rewritten or reinterpreted as a newer profile.

The existing immutable namespace and RCR field remain in use. No new mutable
policy authority or configuration field is introduced.

## Selection and factual limits

The authority-reading direct protection gate selects review-required branches
from the exact predecessor's canonical forge frontier. The ref materializer
supplies that predecessor's native symbolic HEAD and its driver-owned ref
overlay. Reference names are byte-oriented data throughout selection; quoted,
long, and non-UTF-8 names never become policy source or wildcard patterns.

Schema 1.1 fixes two small reference-only profiles:

- `admission_head_deletion_v1` evaluates the native HEAD target's affected
  subject and prohibits deletion.
- `admission_direct_review_v1` evaluates affected refs selected by the
  canonical review-required branch set and prohibits direct updates.

Each stored snapshot contains exactly the frozen rule for its profile. Replay
checks that closed rule shape and evaluates the embedded snapshot; it does not
compile historical source text with today's compiler. A supplied always-allow
snapshot cannot replace either profile.

The complete surviving ref effects are recorded as native `{name, previous,
next}` values. They carry no invented authentication strength, force intent,
ancestry classification, time, or approval receipt. Existing-ref updates with
unestablished ancestry use the explicit engine kind `update_unclassified`.
The evaluator refuses any policy that consults fast-forward/non-fast-forward
facts for such an input, including negation and short-circuited branches.
The protected-ref fast-forward gate also refuses unclassified ancestry.
These two recorded profiles only consult deletion or the selected subject's
presence, so they do not need graph facts.

Required status checks still execute at the existing exact-candidate gate.
These ref-only receipts do not represent their results as DSL evaluation or
assert merge-review authorization.

## Microbatch provenance and recovery

All children in a microbatch share one authenticated publication basis. The
second child's actual old refs may include the first accepted child's effects.
Its receipt records that exact pre-decision ref root rather than reusing the
original head's ref root.

Historical replay loads and re-identifies the recorded ref state and checks
every old value against it. It checks every target/new value against the exact
transaction fold, and verifies the policy selectors against the original
authority basis. If the pre-decision root differs from the original head's
root, replay walks authenticated decision history and requires the matching
canonical transaction and policy evidence root in that batch. Earlier RCRs
must produce the claimed overlay in order. An orphaned immutable ref frame
cannot supply an alternative basis.

Live construction remains inside the durable ref materializer, before the
head CAS. Losing or interrupted attempts can leave immutable staged bodies;
they do not grant authority. A replan selects and evaluates the new exact
basis again. Terminal recovery continues to return the historical decision.

## Retention and bounds

Each compiled snapshot frame and each structural input is embedded inside its
policy evidence body. Retaining or exporting that body therefore retains the
bytes needed for deterministic policy evaluation. The pre-decision ref state
already belongs to the canonical predecessor or an earlier committed child
RCR; the new history check prevents orphan roots from becoming replay inputs.
Provenance verification still needs those existing canonical authority and
forge-history objects.

The profile allows at most two evaluations, 65,536 ref subjects, an 8 MiB
record frame, a 64 KiB embedded snapshot frame, and a 2 MiB trace per
evaluation. Subject and evaluation counts are checked before allocation;
borrowed snapshot/trace bytes are bounded before copying. Caller decode limits
can narrow these limits. Evaluation and possible trace work are bounded before
the evaluator's subject/visit graph is allocated.

## Verification coverage

The focused policy tests exercise explicit unknown ancestry, positive and
negated graph predicates, unavailable graph facts hidden behind other
conditions, the protected-ref fast-forward gate, stable existing code points,
and canonical snapshot round trips.

Admission evidence tests cover legacy frame/root preservation, deterministic
replay, snapshot/trace/verdict substitution, missing evaluations, native-byte
selectors, protected/deletion refusal twins, wrong principal/epoch/head/overlay,
and decode bounds. The native persisted node regression publishes a real
two-decision receive microbatch in both Git hash formats and both whole-body
and ref-Merkle layouts, checks the intermediate overlay, rejects an orphaned
alternative, reopens the node, and checks byte-identical replay and cancellation
with a successful retry. Execution status is reported separately from this
coverage inventory; these tests are not transport E2E evidence.

## Activated repository DSL policies

[Canonical ref-policy activation](CANONICAL_REF_POLICY_ACTIVATION.md) now
selects a bounded stored DSL snapshot through the existing protection aggregate
and advances its epoch in the same authority-head CAS. Direct ref publication
and native merges retain schema 1.2 or 1.3 evidence when one is installed. Native
merge evidence names the complete coupled merge/ref fold; its review/check
acceptance remains the existing canonical gate. Original sealed-package clients
can prepare the exact current evidence through the new read-only node helper.

The first profile accepts ref-name/scope and structural create/delete/update
facts. The distinct `reference_actor_id_v1` profile also accepts `actor.id`
selectors against the actual sealed principal, preserving existing transport
trust boundaries. Actor kind, strength, snapshot and membership predicates,
ancestry, force, aggregates and generic evidence remain unavailable and are
rejected before activation, even when negated or unreachable. A relabelled
actor-policy receipt cannot decode as schema 1.2. The incarnation configuration's `policy_root`
continues to identify hidden-ref policy and is never reinterpreted as a compiled
policy ID. Immutable placement alone remains staging. Complete authenticated
input facts, rollout/break-glass and the full policy-integrity bead remain open.
