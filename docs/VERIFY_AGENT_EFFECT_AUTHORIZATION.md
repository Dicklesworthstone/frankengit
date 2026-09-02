# Verification Campaign: Agent Effect Authorization

**Status:** verification profile; no result implied  
**Parent specification:** [`../VERIFY_SPEC.md`](../VERIFY_SPEC.md)  
**Security addendum:** [`SECURITY_THREAT_MODEL_AGENT_EFFECT_AUTHORIZATION.md`](SECURITY_THREAT_MODEL_AGENT_EFFECT_AUTHORIZATION.md)  
**Implementation contract:** [`AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Claim boundary

This campaign may support only revision-bound claims about the implemented library slice:

- bounded exact-position revocation reads;
- verified non-widening capability ancestry;
- ancestor revocation checks;
- complete-run-bound exact effect authorization;
- request-versus-dispatch freshness separation;
- preservation of reservation/deferred-obligation custody;
- complete-run effect journal, reconciliation, and public cancellation identity.

It does not prove a production revocation service, host integration, canonical policy storage, durable codecs, or general Agent Protocol conformance.

## 2. Required environment identity

Every result records:

```text
source revision
git status and local/remote relation
rustc -Vv
pinned rust-toolchain.toml bytes
Cargo.lock identity
target triple
profile and feature set
relevant environment variables
test command and exit status
raw stdout/stderr artifact identity
```

A result at an ancestor is historical unless an explicit reuse witness covers every changed source and dependency.

## 3. Canonical local lane

At minimum:

```bash
cargo fmt --all --check
cargo test -p fgit-agent --all-targets --no-fail-fast
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check --no-fail-fast
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

GitHub-hosted Actions are neither required nor substitute evidence.

## 4. Capability ancestry matrix

Required cases:

| Case | Required result |
|---|---|
| valid root | accepted |
| valid attenuated child | accepted |
| empty issuer key | typed refusal |
| empty chain | typed refusal |
| chain beyond hard limit | refused before unbounded work |
| duplicate capability ID | typed refusal |
| root claims parent | typed ancestry refusal |
| child omits parent | typed ancestry refusal |
| child names another parent | typed refusal |
| parent tag mismatch | typed refusal |
| body/tag tamper | authenticator refusal |
| operation amplification | typed exact added-class refusal |
| quota amplification | typed resource deficit |
| validity-window widening | typed refusal |
| unknown operation bits | typed refusal |
| identical inputs | identical `VerifiedCapabilityChainId` |
| reordered links | refusal or distinct invalid identity; never same valid chain |

## 5. Revocation read matrix

Required cases:

| Case | Required result |
|---|---|
| exact authenticated read and complete run | deterministic receipt |
| zero maximum age | refusal |
| zero row limit | refusal |
| row limit over system ceiling | refusal |
| request before authority verification | refusal |
| legacy run | refusal |
| same-ID altered run | complete-run refusal |
| reader profile all zero | refusal before adapter call |
| adapter unavailable | typed adapter result |
| adapter policy refusal | typed adapter result |
| response request ID substituted | refusal |
| zero revocation generation | refusal |
| response observation before request | rollback refusal |
| rows over request limit | refusal |
| duplicate revoked IDs | refusal after canonical ordering |
| response at/after run expiry | refusal |
| maximum-age addition overflow | refusal |
| identical input order variants | same canonical receipt identity |
| different evidence/profile/generation | distinct receipt identity |

## 6. Freshness boundaries

For receipt observation `T` and maximum age `A`, test:

```text
T - 1       -> refused
T           -> accepted when other windows allow
T + A - 1   -> accepted
T + A       -> stale refusal
run_expiry  -> refused
leaf_expiry -> refused
```

Also test the minimum deadline when run, leaf, and revocation windows differ.

No test may use wall clock as a substitute for logical time or exact authority read.

## 7. Ancestor revocation matrix

For a chain of at least three links:

| Revoked identity | Required result |
|---|---|
| none | authorization may proceed |
| root | refusal naming index 0 |
| middle parent | refusal naming exact index |
| leaf | refusal naming leaf index |
| unrelated capability | no false refusal |
| duplicate revoked row | receipt construction refusal |

The authorization must not inspect only the leaf.

## 8. Exact effect binding

Starting from one successful authorization, mutate one field at a time:

- numeric run ID;
- complete run commitment;
- authority read;
- verified chain identity;
- leaf capability;
- revocation receipt/generation;
- effect ID;
- parent effect ID;
- operation;
- each resource grade;
- canonical input commitment;
- authorization time.

Every semantic mutation either receives a distinct authorization identity or a typed refusal. No mutation may reuse the original authorization identity.

## 9. Checked broker path separation

Required cases:

- low-risk operation accepted through `request_low_risk`;
- high-value operation refused through `request_low_risk` before budget/journal movement;
- high-value operation accepted only through `request_high_value` with valid evidence;
- revoked/stale evidence refused before broker state moves;
- duplicate effect ID refused before another reservation;
- authorization evidence hard limit enforced;
- accepted `EffectRecord` carries the broker run's exact commitment.

A repository-wide static/API review records every high-value host call site and whether it can reach raw broker admission.

## 10. Request-to-dispatch race matrix

Required cases:

1. request proof fresh; same proof stale at dispatch;
2. root clear at request; revoked at dispatch;
3. intermediate parent clear at request; revoked at dispatch;
4. leaf clear at request; revoked at dispatch;
5. another verified chain presented at dispatch;
6. another leaf presented at dispatch;
7. another effect request attempted at dispatch;
8. fresh exact proof at dispatch;
9. authorization evidence limit reached before dispatch;
10. run or leaf expires between request and dispatch.

For every pre-commit refusal:

```text
same effect reservation remains recoverable
no dispatch authorization is falsely recorded as committed effect
abort remains available
region can become quiescent
```

## 11. Post-commit custody matrix

Required cases:

| Failure point | Required owned result |
|---|---|
| resource commit refusal | recoverable reservation |
| journal failure after commit | recoverable deferred obligation |
| ambiguous downstream result | deferred reconciliation state |
| delivered probe | acknowledged terminal state |
| permanent rejection | terminally failed state |
| unknown after retry budget | named escalation |
| later acknowledgement after escalation | settled acknowledgement |
| later terminal failure after escalation | settled failure |

No failure after downstream-visible commit may return a state that implies non-commit.

## 12. Complete-run effect identity

Construct two runs with the same numeric `RunId` but vary independently:

- exact authority read;
- allowed operation classes;
- resource budget;
- expiry.

Required cases:

- broker records carry distinct commitments;
- dense mixed journal replay refuses `MixedRunCommitment`;
- `RunReconciliationReport` refuses a source effect under the altered run before lifecycle/resource interpretation;
- public cancellation request refuses a source situation paired with altered run;
- public cancellation completion refuses altered-run final report;
- handoff and receiver acceptance retain source effect debt from the exact complete run.

## 13. Resource and adversarial bounds

Test at and just beyond:

```text
MAX_EFFECT_CAPABILITY_CHAIN
MAX_CAPABILITY_REVOCATIONS
MAX_EFFECT_AUTHORIZATIONS
MAX_RECONCILIATION_EFFECTS
MAX_EFFECT_OUTPUT_COMMITMENTS
MAX_EFFECT_RECONCILIATION_TRANSITIONS
```

Verify refusal before excessive retention or work. Include zero, exact-boundary, and boundary-plus-one cases.

Fuzz or property targets should cover:

- chain canonicalization and verification;
- revoked-set sorting and duplicate detection;
- authorization identity determinism;
- half-open time arithmetic and overflow;
- journal replay sequence/run invariants;
- reconciliation parent graph and resource aggregation;
- cancellation frozen-effect identity.

## 14. Determinism

For each identity object, vary input allocation and caller ordering where order is non-semantic:

- revocation row order;
- effect record order before reconciliation;
- independently reconstructed equivalent run values;
- cloned request/receipt/chain objects.

Expected canonical identities must remain equal. Semantic changes must produce distinct identity or typed refusal.

## 15. Host integration gate

Library verification is insufficient for production use. Each host class must demonstrate that high-value effects select the checked broker and cannot call raw admission/dispatch:

```text
network destination
secret provider
sandboxed runner
external integration
forge mutation
publication preparation/submission
delegation
```

For every host:

- trace exact request to checked authorization;
- inject revocation between acceptance and effect;
- verify no downstream call occurs;
- verify reservation/obligation custody;
- verify logs/evidence retain authorization IDs;
- verify cleanup remains available.

Until this gate exists, the supported claim is the library-level boundary only.

## 16. Evidence artifacts

The campaign retains:

- command transcript;
- source revision and dirty-state proof;
- test logs;
- any generated corpus seeds;
- failure and retry traces;
- exact authorization/receipt IDs used in scenario tests;
- journal and reconciliation artifacts;
- static host-call-site inventory;
- known gaps and negative evidence;
- independent verifier identity and independence classification.

## 17. Stop conditions

Do not mark the slice verified when:

- any canonical local command fails;
- tested source differs from delivered source;
- use exactly at freshness deadline is accepted;
- only the leaf is checked for revocation;
- request-time proof is reused at dispatch;
- a pre-commit refusal loses its reservation;
- a post-commit failure loses the deferred obligation;
- same-ID/different-commitment effects replay or reconcile together;
- a concrete high-value host bypasses the checked path;
- the revocation source is partial, unauthenticated, or mixed-position;
- durable migration semantics are required but unspecified.

Leave the claim blocked, implementation-ready, or verification-pending with exact evidence instead of manufacturing closure.
