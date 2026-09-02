# Security Threat Model: Agent Effect Authorization

**Status:** focused security addendum; not an audit claim  
**Parent threat model:** [`../SECURITY_THREAT_MODEL.md`](../SECURITY_THREAT_MODEL.md)  
**Normative protocol:** [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md) §6 and §9  
**Implementation contract:** [`AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md`](AGENT_CONTROL_PLANE_EFFECT_AUTHORIZATION.md)  
**Owning crate:** `crates/fgit-agent`

## 1. Security objective

A high-value agent effect is admitted only when all of the following are true at the consequential boundary:

```text
complete Intent Run is exact and open
capability ancestry authenticates and only narrows
leaf and run both authorize the operation
resource cost fits both capability and run budgets
revocation evidence names the exact authenticated repository read
revocation evidence is fresh at the effect instant
no capability in the ancestry is revoked
exact effect identity, parameters, cost, and input commitment are bound
```

For an external effect, the consequential boundary is downstream dispatch, not merely request parsing or outbox reservation.

A refusal before dispatch must retain the live reservation. A failure after dispatch may not claim non-commit and must retain the deferred obligation for stable-key reconciliation.

## 2. Protected assets

| Asset | Compromise impact |
|---|---|
| complete `IntentRunCommitment` | effects attributed to a same-ID but wider or longer-lived run |
| sealed capability ancestry | forged or amplified operation, quota, or validity authority |
| revocation generation and receipt | revoked authority accepted as current |
| authenticated authority read | revocation data replayed across repository/head/read context |
| exact effect request | authorization reused for another effect, parent, operation, cost, or input |
| run budget reservation | duplicated or leaked resource responsibility |
| outbox obligation | lost custody of a possibly dispatched external effect |
| request/dispatch authorization evidence | inability to prove the authority current at each boundary |
| effect journal and reconciliation report | mixed-run or incomplete responsibility history |
| cancellation evidence | another run's terminal report substituted for the source run |

## 3. Adversaries

The focused model assumes:

- a caller may deliberately reuse one numeric `RunId` with different machine fields;
- an issuer key, capability token, or ancestor may be compromised or revoked;
- a revocation cache may be stale, partial, cross-repository, or based on an unauthenticated head;
- a caller may swap the capability chain or leaf between request acceptance and dispatch;
- a service may accidentally call the raw broker instead of the checked facade;
- a downstream API may commit before returning timeout or journal failure;
- a process may crash after request authorization, reservation, dispatch, or acknowledgement;
- repository or tool output may try to persuade an agent to bypass a stale or revoked result;
- a malicious adapter may return duplicate, excessive, reordered, or fabricated revocation rows;
- a log or replay path may combine effects from distinct complete runs.

## 4. Threats and controls

### 4.1 Numeric run-ID substitution

**Threat**

A caller supplies a run with the same `RunId` but another authority read, operation scope, resource budget, or expiry.

**Controls**

- `IntentRunCommitment` commits every machine-enforced field.
- Revocation requests, effect authorizations, effect records, reconciliation reports, and cancellation records retain the commitment.
- Broker request computes the commitment before budget movement.
- Journal replay refuses mixed complete-run commitments.
- Reconciliation and cancellation reject mismatch before lifecycle interpretation.

**Remaining obligation**

Every host integration must use the complete-run-bearing APIs and must not reconstruct authority from `RunId` alone.

### 4.2 Leaf-only revocation check

**Threat**

The leaf remains absent from the revocation set while its root or an intermediate parent is revoked.

**Controls**

- `VerifiedCapabilityChain` retains every root-first identity.
- Effect authorization checks every ancestry ID against the canonicalized revocation set.
- Refusal identifies the exact capability and chain index.

### 4.3 Stale revocation cache

**Threat**

A previously clear revocation result is reused indefinitely or at its exclusive deadline.

**Controls**

- Every request commits a nonzero maximum age.
- The receipt derives an overflow-checked deadline bounded by run expiry.
- Freshness is half-open: `observed_at <= now < valid_until`.
- Use at `valid_until` is refused.

**Remaining obligation**

A production cache must invalidate on authority/policy movement and must preserve the exact read and receipt identity rather than only a wall-clock timestamp.

### 4.4 Cross-position revocation replay

**Threat**

Revocation data from another repository, head, generation, read event, or complete run is accepted.

**Controls**

- Request binds repository, head, generation, exact `AuthorityReadReceiptId`, `RunId`, and `IntentRunCommitment`.
- Observation must name the exact request.
- Receipt retains the complete authority read.
- Effect authorization compares exact run and authority identities.

### 4.5 Request-to-dispatch TOCTOU

**Threat**

A request is authorized, then the capability is revoked or the receipt becomes stale before the external effect is dispatched.

**Controls**

- Checked broker returns a proof-carrying reservation with no raw dispatch method.
- Dispatch constructs a fresh authorization from the retained exact request at the actual dispatch instant.
- Dispatch requires the same verified chain and leaf as initial acceptance.
- Newly revoked or stale proof returns the still-live reservation.

### 4.6 Chain or leaf swap

**Threat**

A different authenticated chain or leaf is presented at dispatch to exploit another quota or scope.

**Controls**

- Initial authorization commits verified chain and leaf IDs.
- Dispatch authorization is independently valid but must also equal both initial identities.
- Mismatch occurs before obligation commit.

### 4.7 Effect-request substitution

**Threat**

Authorization for one effect is reused with another parent, operation, cost, or input.

**Controls**

- `CapabilityEffectAuthorization` commits the complete `EffectRequest`.
- Proof-carrying outbox reservation reconstructs and retains the request from the accepted broker record.
- Dispatch authorizes that retained request, not caller-supplied replacement fields.
- Effect ID remains an idempotency boundary.

### 4.8 Resource amplification or double reservation

**Threat**

A refused authorization consumes budget, or a duplicate effect reserves twice.

**Controls**

- Duplicate effect ID is checked before identity, capability, and budget work.
- Run identity and revocation authorization occur before budget reservation.
- Capability quota is checked independently from run budget.
- Every pre-dispatch refusal retains the same reservation rather than creating another.

### 4.9 Lost obligation custody

**Threat**

A dispatch refusal drops the reservation, or a post-commit journal failure drops the deferred obligation.

**Controls**

- `AuthorizedOutboxDispatchRefused::into_reserved` returns the reservation on every pre-commit refusal.
- `into_deferred` returns the committed obligation when journal mirroring failed after commit.
- Cleanup types are `#[must_use]`.
- Later abort and reconciliation do not require new effect authority.

### 4.10 Ambiguous downstream outcome

**Threat**

Timeout or disconnect is interpreted as proof that the external effect did not happen, causing unsafe retry.

**Controls**

- Outbox effect uses stable downstream idempotency.
- Dispatch commit hands the obligation to explicit reconciliation.
- Reconciliation records every delivery/probe transition.
- Unknown outcome becomes named escalation rather than success or non-commit.

### 4.11 Journal replay merges distinct runs

**Threat**

Dense journal entries from same-ID runs with different budgets or expiry are combined into one plausible effect history.

**Controls**

- `EffectRecord` carries `run_commitment`.
- Journal establishes numeric and complete run identity from first acceptance.
- Later mismatch is a typed `MixedRun` or `MixedRunCommitment` refusal.
- Reconciliation independently rechecks each row against the supplied complete run.

### 4.12 Cancellation report substitution

**Threat**

A source cancellation is finalized using an empty or terminal report from another same-ID run.

**Controls**

- Public cancellation request v2 commits the complete run.
- Situation, active claim, and initial report must match before request creation.
- Final report commitment is rechecked before the private cancellation engine runs.

### 4.13 Host bypass of checked broker

**Threat**

A network, secret, runner, forge, or publication service uses the lower-level broker directly and omits current revocation evidence.

**Controls present**

- Production-facing checked broker has separated low-risk/high-value methods.
- Its low-risk path refuses revocation-gated operations.
- Its external reservation exposes no raw dispatch.

**Remaining obligation**

- Host services must adopt the checked facade and prevent raw broker selection for high-value operations.
- Integration tests must prove no alternate service path reaches the effect without a current authorization.
- A later API-hardening wave may further narrow visibility once all legacy and conformance consumers migrate.

## 5. Cleanup asymmetry

A revoked capability cannot authorize new work, but revocation must not strand existing responsibility.

Permitted cleanup after revocation includes:

- aborting an undispatched reservation;
- probing a committed/deferred effect;
- acknowledging delivery;
- recording permanent failure;
- resolving or transferring escalation;
- releasing task ownership;
- requesting and completing cancellation;
- recording containment failure.

These paths may not create a new effect, widen scope, renew expiry, or mint a capability.

## 6. Security tests required

The focused source and integration campaign must include:

1. valid root/child ancestry;
2. authenticator tamper;
3. operation, quota, and window amplification;
4. duplicate chain identities;
5. revoked root and intermediate ancestor;
6. stale receipt before request and exactly at deadline;
7. cross-repository/head/read/run receipt replay;
8. same-ID/different-scope run substitution;
9. exact effect-request mutation;
10. revocation between request and reservation;
11. revocation between reservation and dispatch;
12. chain and leaf swap at dispatch;
13. refusal preserving reservation;
14. post-commit failure preserving deferred obligation;
15. acknowledgement and escalation reconciliation after later revocation;
16. journal replay across mixed complete runs;
17. final cancellation report substitution;
18. host-level bypass search for every high-value service.

The exact command campaign is specified by [`VERIFY_AGENT_EFFECT_AUTHORIZATION.md`](VERIFY_AGENT_EFFECT_AUTHORIZATION.md).

## 7. Explicit non-claims

This addendum does not claim:

- the current source has undergone security audit;
- revocation is stored canonically;
- a durable production revocation adapter exists;
- every host service has adopted the checked broker;
- durable codecs or cache invalidation are complete;
- process/workspace/credential cleanup is implemented;
- an in-memory reader proves production behavior;
- local test source or hosted workflow state proves the release-blocking invariants.

Independent revision-bound evidence remains required.
