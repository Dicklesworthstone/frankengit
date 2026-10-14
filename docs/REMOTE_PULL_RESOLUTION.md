# Resolve retained PR conflicts through the native engine

The operator candidate client now turns a retained `conflicted` capture into an
inspected `resolved` candidate. It reuses the existing browser resolution upload
and result validators, native `/pulls/NUMBER/resolve`, native inspection, and
original candidate validation. Production does not invoke Git, perform a merge,
grant approval, or publish a repository mutation. This advances the PR workflow
in plan section 25 and `frankengit-root-doctrine-x2mv.4.20`; it closes neither the
broad product bead nor native integration verification.

## Library

`resolvePullCandidate(capture, choices, token, options)` is exported from
`scripts/operator/pull_candidate_capture.mjs`. Supply a previously validated,
complete automatic conflict capture (no candidate bundle), plus exactly one
explicit choice for every raw conflict path:

```js
const choices = [
  { path_hex: '612e747874', choice: 'theirs' },
  { path_hex: '622e747874', choice: 'file', mode: '100644', content_hex: '6f6b0a' },
];
```

Supported choices are `base`, `ours`, `theirs`, `delete`, and `file`. Here **ours
is the target branch**, and **theirs is the source branch**. Missing sides must
not imply deletion: choose `delete` explicitly. A replacement file has an
explicit regular mode (`100644` or `100755`) and exact lowercase hexadecimal
content, including empty content and non-UTF-8 bytes. Names are byte paths, not
host paths; they are never opened, extracted, or executed. Duplicate, overlapping,
reserved, clean, missing, or unsupported paths/choices refuse before networking.

The original capture fixes endpoint, repository incarnation, hash domain, PR
version, policy epoch, branch names/tips, merge base, commit metadata and method.
No override, current-state refresh, new discovery, approval reuse or strategy
fallback is inferred. The node independently recomputes the conflicts and checks
its current source. Both new responses must match the original source head and
snapshot; even unrelated head movement refuses this strict profile.

The result has the existing `{capture, bundle, usage}` interface. The new capture
schema is `frankengit-pull-resolved-candidate-capture-v1`; the automatic v1 schema
and bytes are unchanged. Resolved captures retain the original preparation
report and normalized choices, the resolved preparation report, the exact bundle
and the native inspection. Ordinary capture cannot accept a resolved response as
automatic success. A resolved capture cannot discard its resolution provenance.

`validateCandidateCapture(capture, bundle)` replays both original and resolved
validation offline. It regenerates only the shared resolution envelope/expected
result from retained choices, validates every returned path, side, mode and result
identity, verifies the bundle checksum and candidate commit/parent checks, and
runs the existing complete inspection validator. No nested chain of captures is
accepted. This is **not an independent reconstruction of the candidate tree or
diff**: native Git closure, conflict detection, ancestry and inspection semantics
remain the server's responsibility. A checksum-bound retained report is not
independent authority or current permission to merge.

## Bounds and failure

At most 128 choices, at most 1 MiB per replacement file and **4 MiB total raw
content plus raw path bytes** are retained. The smaller operator aggregate bound
allows hex choices to fit beside reports in the unchanged 16 MiB capture ceiling;
the complete enclosing capture can still refuse if reports make it too large.
Forms retain 256 KiB bounds, multipart resolution uploads 5 MiB, result bundles
16 MiB, and cumulative response payloads 64 MiB (narrowable with `maxWireBytes`).
These are not peak-memory or network-framing guarantees.

One deadline (default 30 seconds, maximum 300 seconds) covers original validation,
resolution, inspection and final validation. `signal` cancels local work; `ca`
selects bounded explicit TLS trust roots. HTTPS validates certificates/hostnames;
cleartext requires numeric loopback. No transaction key, redirect, ambient
credential or automatic network retry exists. HTTP refusals, inconsistent results,
limits, lost responses and failed inspection yield no successful partial capture.
Synchronous hashing/parsing and OS operations are not hard-preemptible.

## Executed test profile

```sh
node --test tests/operator/pull_resolution.test.mjs
```

The initial 72 tests run on Node 22.16.0 with complete normal production imports,
real HTTP sockets, and independent test-only Git-built SHA-1/SHA-256 conflict
graphs and bundles. Git confirms the source/target graph conflicts, verifies the
bundle, and constructs the exact selected output for each of the five choices
and both merge styles. Tests cover binary/empty/executable replacements, exact
limits, source/choice/method corruption, full offline replay, cancelled/deadline
reads and response failures. HTTP reports are explicit native-schema fixtures,
not a Rust fg server. Native authorization/ancestry/conflict-engine integration,
real deployments, Cargo and the full workspace have not been executed here.
