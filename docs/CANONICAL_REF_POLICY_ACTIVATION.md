# Canonically activated repository ref policy

The `reference_facts_v1`, `reference_actor_id_v1`, and
`reference_authentication_v1` profiles make a stored,
administrator-selected DSL snapshot effective on ordinary ref publication and native merges. It is part
of the existing complete review/check protection policy. It is not selected
by a local file, an immutable object's existence, or the hidden-ref
configuration `policy_root`.

## Operator flow

For a repository at protection version 0 and policy epoch 1, an operator can
install a policy that makes release tags immutable:

```text
policy release_tags {
  rule immutable_tags {
    when ref.name matches "refs/tags/**" and ref.update == delete
    then deny "release tags cannot be deleted"
  }
  default allow
}
```

Use `fg protection show` to obtain the current version, epoch, administrators,
review/check requirements and selected compiled snapshot. Use
`fg protection set ... --policy-source <path>` to compile the source, or
`--policy-frame <path>` to submit a previously stored canonical snapshot frame.
Both paths use the same compiler/profile validator and exact frame decoder.
HTTP and MCP protection administration accept the equivalent source or frame
input and return the exact snapshot identity and canonical frame.

Protection set remains a **complete replacement**: include the administrators,
review requirements, checks and DSL policy intended for the next version.
Omitting the DSL field selects `None`; it does not implicitly carry forward an
old policy. Only the current administrators can replace or remove the policy.
The version and epoch are exact preconditions, not hints to be refreshed after
a race. First installation retains the existing trusted repository-operator
bootstrap boundary. An asserted principal identifier is not remote login.

## Supported facts and semantics

The first profile accepts ordinary DSL boolean composition, ref-name/ref-scope
selectors, and `create`, `delete`, or `update_unclassified` update kinds. Default
allow/deny and bounded multiple rules are supported. Native ref names remain
byte-oriented data; no caller name is interpolated into source. The policy
engine's established deny-precedence semantics apply.

The `reference_actor_id_v1` profile additionally permits `actor.id` equality,
set membership and glob predicates, including boolean composition and negation.
It observes the exact principal identifier from the admission context bound to
the sealed request. IDs use their canonical lowercase 32-hex-digit spelling.
For example, an administrator can restrict release-tag writes to one publisher:

```text
policy releases {
  rule publisher {
    when ref.name matches "refs/tags/**" and
         not actor.id == "33333333333333333333333333333333"
    then deny "release publisher required"
  }
  default allow
}
```

The new profile preserves each transport's existing trust boundary. HTTP uses
the principal established by its credential authorization. Trusted local CLI
and MCP operations use the operator-supplied principal; this does not create a
general remote identity service or prove MFA. A compatibility adapter without
a principal refuses an actor policy instead of substituting a zero identifier.
Inspection reports the smallest supported profile: a policy without actor-ID
predicates remains `reference_facts_v1` with its historical encoding.

The `reference_authentication_v1` profile additionally accepts authentication
comparisons against the method established by the admission boundary. HTTP
tokens and authorized SSH keys establish single-factor strength; explicit
operator assertions establish none. Legacy missing provenance refuses even a
negated authentication condition. [Admission authentication](ADMISSION_AUTHENTICATION.md)
lists supported routes and an installable policy example.

An existing-to-existing ref update is `update_unclassified` because this gate
does not authenticate ancestry. Actor kind/snapshot/membership predicates,
force intent, fast-forward/non-fast-forward, aggregate reads and accepted
evidence predicates are rejected at installation, including negation and
unreachable branches. Empty or invented facts never make those conditions
evaluate successfully. Supporting these facts requires their own authenticated
attempt-bound integration; source text cannot grant it.

Policies apply to surviving ref effects, including creates/deletes and each
driver-owned receive microbatch overlay. A metadata-only protection change is
outside this ref-policy scope, so administrators can replace a deny-all policy.
Identity/no-op operations with no surviving ref effects do not create a new
ref-policy decision. Existing hidden-ref, capability, quota, native object,
required-review and exact-check gates continue to apply independently.

## Canonical selection and publication

The existing `ReviewProtection` aggregate owns the complete settings and
administrator list. Its exact-version transaction publishes a new event,
forge-position root and next policy epoch in one authority-head CAS. The RCR
is authorized under the predecessor epoch, while the successor head selects
the next epoch. CAS loss repeats selection/validation against the new basis;
it cannot silently rebase the submitted policy version or epoch.

Forge event kind 16 retains the exact canonical compiled ref-only policy frame and an
explicit historical review/check/quorum base kind. The frame is bounded,
strictly decoded, re-identified and re-encoded before acceptance. Existing
kinds 9, 13 and 14 retain their original bytes when no DSL policy is selected.
Actor-ID policies require kind 17 with the same bounded protection/frame shape.
Kind 16 refuses actor predicates, and kind 17 refuses a ref-only snapshot, so
upgrading a reader cannot reinterpret old bytes or create a second encoding.
Authentication policies require kind 18 and cannot be relabelled as kinds 16 or
17. Kind 18 likewise refuses a snapshot that belongs to either older profile.
Older readers refuse unknown required kinds rather than treating the policy as absent.
Embedding the frame retains it with the existing forge event; there is no new
mutable authority, policy database or dangling snapshot retention root.

The shared direct-ref materializer evaluates the selected snapshot before
staging evidence and before CAS. The shared native merge driver independently
does the same for merge commits, fast-forwards and squash publication. Legacy
merge packages use the stricter direct-ref protection path. Native merge
review/check validation remains in its existing gate; a DSL allow never
substitutes for a review or check.

## Decision evidence and historical recovery

Policy-decision schema 1.2 embeds the existing 1.1 structural receipt plus the
activated snapshot, its identity, actual verdict and deterministic rule trace.
It distinguishes direct publication from native merge publication. The latter
requires the coupled merge/ref fold; a direct write cannot label itself a
reviewed merge. Every native ref value and the exact pre-decision ref root are
retained. The snapshot is evaluated from stored bytes during replay, without
recompiling source or consulting current policy.

Schema 1.3 records the actor-ID profile with the same structural commitments,
selected snapshot and publication distinction. Its principal is the exact
admission principal retained by the structural receipt and checked against the
sealed request and staged principal snapshot. Replay alone is not principal
authentication: even a substituted principal that also satisfies the policy
must fail the enclosing decision's identity check. Schema 1.2 remains ref-only
and rejects an actor policy, including a relabelled 1.3 payload.

Schema 1.4 records the authentication profile and appends the exact method to
the activated evidence fields. The enclosing decision checks it against
principal snapshot 1.1 before replay can be accepted. Recovery uses that
original receipt, without changing the transaction seal or consulting a retry's
current credential. Historical snapshots never acquire an authentication fact.

The durable reader authenticates the original authority/forge selection and
requires the recorded snapshot to equal the selected snapshot. It rejects a
self-consistent alternative allowing policy and rejects 1.0/1.1-only ref evidence for
an original basis that had an activated policy. Microbatch overlays retain the
existing canonical decision-history checks. Historical 1.0 and 1.1 records
keep their original identities and interpretation.

Original sealed-package clients can call
`OneNode::prepare_sealed_merge_evidence_in` to obtain the exact current evidence
before freezing their supplied `CommitEvidence`. This read-only operation
authenticates the basis, validates native objects and review/check gates, and
computes the complete fold under the activated snapshot. It creates no seal
or decision. The result names the observed head, epoch and original transaction
identity. Publication independently verifies it; a concurrent policy/ref
change can make it stale. The optional workspace snapshot selects the existing
workspace-bound seal profile and does not assert workspace ownership.

## Bounds and verification boundary

Source and compiled frame each have a 64 KiB ceiling. The activated profile
admits at most 64 unique rules, 4,096 predicate/set-member checks and predicate depth 16. Before engine
allocation, each evaluation reserves at most 1,000,000 predicate visits and a
conservative 2 MiB trace envelope. The total policy-decision frame remains
bounded at 8 MiB. Decoders enforce caller limits before copying bounded
fields, and caller limits can only narrow the profile.

Focused regression tests cover profile refusal/permit twins; historical event
byte preservation; administrator/epoch/version fencing; exact frame decoding;
snapshot substitution; structural-fact replay in both Git hash formats; and
bounded evaluation. Persisted node tests cover real import/native merge
denial and permitted twins, replacement, original sealed-package preparation,
restart and historical terminal recovery. HTTP/MCP tests exercise their actual
administration adapters. Execution results are recorded separately; the test
inventory is not a claim of a passed full release, crash or power-loss campaign.

This implements enforce mode for the bounded ref-fact, actor-ID and authentication profiles. Canary/shadow
rollout, break-glass, time windows, authenticated actor attributes/ancestry/evidence facts,
and the complete policy-integrity bead remain separate unfinished work.
