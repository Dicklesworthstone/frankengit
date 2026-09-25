# Admission policy fact boundary

Bridge work: `frankengit-root-doctrine-x2mv.4.6`.

The reference-only receive and net-effect policy adapters do not authenticate a
principal snapshot, verify commit ancestry, collect evidence receipts, or read
repository aggregates. They must not turn missing facts into an MFA-authenticated
human, an empty membership set, a passing ancestry assertion, or a zero aggregate.
An empty set is not a safe substitute: a policy can negate a membership/evidence
predicate and thereby permit a request.

Both adapters now inspect every compiled predicate before constructing their
compatibility input. Actor selectors, evidence, aggregates and ancestry-sensitive
update kinds return `PolicySourceRefusal::MissingAdmissionFacts`. Net effects also
refuse force-intent predicates; receive commands retain their explicit force bit.
Ref names/scopes and create/delete predicates remain supported, including the
existing generated default-branch-deletion and named-branch protections. Negation
and boolean short-circuiting do not hide an unavailable fact.

The snapshot is fetched and identity-checked once, and that exact snapshot is
preflighted and evaluated. The walk shares the compiler's rule, source and depth
envelopes and refuses excessive structure without unbounded recursion or work.
No snapshot identity, canonical schema, transaction derivation or authority
publication rule changes.

Complete integrations use `evaluate_protection` with an attempt-bound
`PolicyInputRoot`. The principal kind, authentication strength, snapshot,
memberships, validated ref-update classification, accepted receipts, aggregates
and evaluation instant are the caller's validation obligations. The low-level
`build_input_root` helper remains a reference-only compatibility shape, explicitly
not an authentication source; it no longer claims MFA.

This is a fail-closed admission boundary, not completion of identity integration,
policy activation/RCR binding, named CI checks or the broader policy-integrity
bead. It does not claim that arbitrary policy selection is deployed on every
transport. The complete-fact evaluator remains the path for those integrations.

## Regression coverage

```sh
cargo test -p fgit-admission policy_bridge
cargo test -p fgit-admission --test planted_bypasses
cargo test -p fgit-admission --test policy_snapshot_replay
```

Coverage includes actor-selector and negation checks, evidence/aggregate refusal twins, ancestry versus force intent,
structural-budget boundaries, both SHA-1 and SHA-256 through the adapters,
complete-fact MFA permit/refuse twins, deterministic verdict/trace repetition and
unchanged reference-only deletion protection.

These Rust tests were added but could not be executed in the authoring environment:
no Rust compiler, Cargo or rustfmt was available. They are not a passing gate,
end-to-end campaign or closure claim.
