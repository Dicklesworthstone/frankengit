# Authentication facts in durable admission

The node retains the authentication method established by its existing ingress
verifiers and exposes that bounded fact to canonically activated ref policies.
It supports ordinary Git receive, native HTTP branch commands, buffered and
file-backed bundle import, workspace publication, rebases, and native merge
publication, including reviewed merges and fast-forward PR publication. HTTP
issue, pull request, protection, and conversation writes retain the same fact
in committed and refused admission evidence.

| Entry boundary | Recorded method | Policy strength |
| --- | --- | --- |
| Accepted HTTP token, including Basic token-as-password | `HttpToken` | `single_factor` |
| Authorized SSH deploy-key command | `SshDeployKey` | `single_factor` |
| Configured raw Git principal, local CLI/MCP principal, or public session constructor | `OperatorAssertion` | `none` |
| Historical principal snapshot 1.0 or compatibility projection without provenance | Unknown | Authentication policies refuse missing evidence. |

Only the node's credential boundary can attach HTTP/SSH provenance to a receive
session. Request bodies cannot select it. A principal identifier supplied to a
public embedding constructor remains an explicit operator assertion. The
existing read/write grants, repository selection, ref ceiling, quota and
canonical protection gates continue to apply independently.

## Install an authentication requirement

The existing `fg protection set`, HTTP, and MCP protection administration paths
compile or accept a bounded canonical policy frame. For example:

```text
policy credential_required {
  rule authenticated {
    when actor.authentication >= single_factor then allow
  }
  default deny "a verified credential is required"
}
```

This selects `reference_authentication_v1`. The profile accepts native ref
name/scope/create/delete/update facts, actor ID, and authentication comparisons.
It validates the complete program before evaluation. Principal kind,
memberships, snapshot selectors, evidence, aggregates, time, force intent and
ancestry remain unavailable, including behind negation or unreachable branches.
The restricted input has no fields for invented values of those facts. Ordinary
tokens and SSH keys cannot satisfy `multi_factor` or `hardware_backed`.

Protection activation remains administrator-authorized, exact-version and
exact-epoch, with the existing authority-head CAS as its publication point.
An allow result never substitutes for a required review or CI check.

## Canonical evidence and retries

Principal snapshot 1.1 appends a nonzero authentication-method tag to the
unchanged identity/configuration payload. Principal snapshot 1.0 retains its
original frame and identity and never gains inferred authentication facts.
Explicit operator assertion is therefore distinguishable from unknown legacy
provenance, including for negated authentication predicates.

Required forge event kind 18 selects the new profile. Policy-decision schema
1.4 retains the exact activated snapshot, original structural facts, verdict,
trace, and method. Its method must match the named principal snapshot exactly:
HTTP and SSH methods are not interchangeable merely because they have equal
strength. Historical event kinds 16/17 and policy schemas 1.0–1.3 keep their
original semantics. Unknown versions, malformed frames, changed methods,
substituted snapshots, and changed traces refuse.

Authentication is evidence about an attempt; it is not a new transaction
identity. `TxId`, seals, client keys, complete-session descriptors, and
non-atomic child keys keep their existing derivation. A terminal outcome is
resolved before a retry attempts fresh policy evaluation. Changing the token,
transport, or current policy cannot replace that outcome or reinterpret the
original authentication receipt. A fresh request evaluates the current policy
and the provenance established for that request.

The session-bound sealed-merge preparation API derives the exact offered
evidence from the same verified session used for publication. The existing
context-only preparation API remains an explicit operator assertion. Offering
evidence prepared under a different authentication method cannot substitute a
different principal receipt into a new decision.

Metadata-only commands retain their existing authorization and validation
rules. Their evidence binds the authenticated principal to the exact metadata
request and effects; it does not fabricate a ref-policy evaluation for a
command that changes no references.

## Scope and verification

The receipt contains no credential secret or individual credential handle. It
does not establish an issuer, expiry, sponsor chain, principal kind, membership,
capability root, MFA, or hardware binding. This is the current transport-method
integration, not completion of the full identity model in
`frankengit-root-doctrine-x2mv.4.13`.

Focused tests cover restricted policy evaluation, canonical event/evidence
versions, provenance and trace substitution, refusal evidence, historical
readback, real HTTP branch/merge and metadata publication, native file-backed
bundle import, sealed workspace offers, raw Git versus the authorized SSH
command binding, restart, and exact-key recovery. The SSH command-binding test
does not replace the existing SSH cryptographic-handshake suite. Test execution
status is reported separately from this coverage inventory.
