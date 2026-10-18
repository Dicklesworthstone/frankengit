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

## Command-line workflow

The existing candidate CLI now accepts `resolve`. First capture the native PR
through its normal `capture` command. A conflict exits with the documented
noncandidate code, but still saves the original complete conflict package and
prints its manifest hash. Keep that hash separately; do not substitute a hash
obtained from an untrusted replacement package.

Write an owner-private JSON **array** of choices, one for every reported path.
For example, to keep the source side of the raw filename `file\xff`:

```json
[
  { "path_hex": "66696c65ff", "choice": "theirs" }
]
```

To supply exact replacement bytes instead:

```json
[
  { "path_hex": "66696c65ff", "choice": "file", "mode": "100755", "content_hex": "6f6b0a" }
]
```

The names are illustrative; use the exact set in your captured conflict report.
The choices file can occupy at most 8 MiB + 64 KiB of JSON, independently of the
4 MiB raw content/path ceiling and 1 MiB per-file ceiling. No host file path,
executable, external merge driver, or implicit resolution is accepted in a choice.

```sh
node scripts/fg_pull_candidate.mjs resolve \
  --package /private/pr-7-conflicts \
  --sha256 ORIGINAL_CONFLICT_MANIFEST_HASH \
  --choices /private/resolutions.json \
  --token-file /private/read-token \
  --output-dir /private/pr-7-resolved

node scripts/fg_pull_candidate.mjs inspect \
  --package /private/pr-7-resolved \
  --sha256 RESOLVED_MANIFEST_HASH
```

Both directories must have an owner-private parent outside any Git worktree.
The output directory must not already exist or be inside the original package.
Draft and staging outputs likewise cannot be placed inside their source package:
package inventories are closed, so adding output there would break the next
offline reopen. Sibling output paths are permitted. The original package is never
changed. `resolve` alone adds no repository event, transaction, review or merge:
it sends one body-bearing construction read and one inspection read. Its explicit
read credential needs the native preparation/inspection grants, not a client-
asserted reviewer identity. An optional `--ca-file PRIVATE_PEM` supplies the TLS
trust root, `--max-wire-bytes` narrows the total response allowance, and
`--timeout-ms` bounds the combined local input, network and persistence operation.
The command accepts no endpoint, subject, method, metadata or principal override.

The resolved package retains the original automatic conflict report and your
exact normalized choices in its new resolved capture schema. The package
manifest format and fixed filenames are unchanged. Every reopen checks the
independent manifest pin, complete file hashes, original conflict and requested
results, candidate bundle, and native inspection. There is no chain of nested
resolutions or dependency on the original directory for offline replay.

After inspecting the resolved candidate, use `stage` below or the existing `draft` command with
its exact candidate identity. The existing approval/change-request drafter uses
the full captured reviewer predecessor; the merge drafter requires an explicit
reviewer set and the same merge method. A retained change-request vote is not
converted into approval. Feed the draft and saved bundle to
`remote_pull.mjs prepare`; its separate original-key, candidate and merge-method
confirmation requirements remain in force. A newly resolved candidate must be
reviewed as that candidate, not treated as already approved.

`inspect` and `draft` are offline and accept no credential. Only `capture` and
`resolve` contact the server; `stage` reads an explicit private credential locally
without opening a connection. Missing/corrupted inputs and occupied destinations refuse;
network/refusal/validation failures return no successful resolved package. A kill
or cancellation leaves the original package intact. If output publication is
interrupted, retain the new directory; it is not automatically repaired or
reused. If stdout fails after the package was fully saved, the error diagnostic
retains its path and manifest hash. No automatic retry or write recovery is part
of this read-side operation. Existing remote mutation recovery is unchanged.

Exit 0 means a complete resolved package was saved (or inspection/drafting
completed). Exit 2 denotes local preflight refusal. Exit 3 denotes resolution,
inspection, persistence or output failure after work began. Earlier ordinary
capture exit codes remain unchanged. These are local operator outcomes, not
native merge decisions.

## Direct staging from an inspected package

`stage` removes the separate draft-file/bundle-file handoff to the sender. It
reopens the independently pinned package, validates the original or resolved
capture with all selected bundle bytes, derives the exact review/merge command,
and saves the standard sender request using those verified bytes directly.
It accepts ordinary clean candidates as well as resolved ones. It cannot stage a
conflict report or an already-up-to-date noncandidate.

Supply a private choices object identical to `draft`, for example:

```json
{
  "action": "approve",
  "principal_id": "44444444444444444444444444444444",
  "candidate_commit": "REPLACE_WITH_EXACT_RAW_INSPECTED_CANDIDATE_OID",
  "reason": "Reviewed the explicitly resolved candidate."
}
```

The principal is an explicit expected identity, not a claim of authentication by
the local client. The server authenticates the bearer and enforces its grants on
submission. For `request-changes`, keep `reason`; for `merge`, replace `reason`
with explicit `method` (`merge-commit` or `squash`) and `required_reviewers`. The
candidate must match the inspected OID, the merge method must match the package,
and the submitting principal cannot be a required reviewer of its own merge.

```sh
node scripts/fg_pull_candidate.mjs stage \
  --package /private/pr-7-resolved \
  --sha256 RESOLVED_MANIFEST_HASH \
  --choices /private/review-choices.json \
  --token-file /private/review-token \
  --request-dir /private/pr-7-review-request

node scripts/remote_pull.mjs inspect \
  --request-dir /private/pr-7-review-request

node scripts/remote_pull.mjs send \
  --request-dir /private/pr-7-review-request \
  --token-file /private/review-token \
  --confirm-key SAVED_KEY_FROM_STAGE \
  --confirm-candidate EXACT_RAW_INSPECTED_CANDIDATE_OID \
  --record /private/pr-7-review-result.json
```

A merge send also requires `--confirm-merge-method` matching the saved method.
Staging is offline: the token is used only to bind the new local intent to its
credential fingerprint. It accepts no endpoint override, separately selected
bundle, CA file, network budget, automatic send, or force/reuse flag. It preserves
exact source coordinates, policy epoch and per-reviewer predecessor, including a
stale prior vote's stream version. There is no automatic approval survival rule.

The request directory contains the existing sender's `candidate.bundle` and
`intent.json`, not another request format. The create-only saver copies and
validates the verified bundle before its first asynchronous write, syncs the
bundle, then publishes and syncs the intent selecting it. Stage's receipt binds
the source package hash, exact intent hash, saved key and candidate. It prints
neither the bearer nor review prose. This is per-request-directory custody, not
global deduplication across independently prepared directories.

Local validation respects the remaining operation deadline. Once the original
sender's create-only save begins, it is drained without interruption; filesystem
sync is not hard-preemptible and may exceed that deadline. A late signal cannot
hide completed custody. If the save fails, the partial directory remains and the
error identifies the attempted path, **not a proposed key falsely reported as the
saved key**. An occupied slot is never overwritten. Inspect retained state rather
than automatically choosing another key; a killed process may have completed
its local save even without stdout. Broken stdout after successful staging keeps
the completed receipt in the bounded diagnostic and leaves the request intact.

Staging itself creates no native transaction. Once a separate send has been
attempted, preserve that original request and use the existing `remote_pull.mjs
recover` command. Recovery requires its original `intent.json` but neither the
candidate package nor the bundle; a rotated bearer must still authenticate as the
same original principal. Losing those bodies cannot justify another upload or a
new idempotency key. All sender and native authorization checks remain unchanged.

## Combined verification command

```sh
bash scripts/verify_pull_resolutions.sh
```

The combined Node 22.16.0 lane passes **162 tests**: 72 resolution core/ordinary-
capture tests, 47 executable/CLI/file/packaging cases, and 43 direct-staging and
complete-sender cases. All 18 complete production/test modules pass syntax
checks. The new integration uses the unchanged production command preparer,
private request saver/loader, network sender and original-key recovery client.
It exercises both Git hash domains, both merge styles, all three candidate
publication actions and both native terminal outcomes with real HTTP sockets.
It checks the exact Git-generated bundle and command bytes arriving at the peer,
full-u64 decision sequences, separate send confirmations, lost replies and
rotated-credential recovery after removal of both original package and bundle.
Ordinary clean candidate staging is also exercised through the actual CLI.

File/process cases include concurrent creators, retained partial slots, private
credentials, input detachment and broken stdout. Three source-package placement
regressions fail before the output-separation fix, then pass alongside permitted
sibling outputs. Resolution cases include real verified TLS, SIGTERM/SIGKILL,
explicit binary/empty/executable replacement files and exact resource bounds.

Test-only Git builds genuinely conflicted graphs and valid candidate bundles.
HTTP resolution, inspection, publication and outcome reports remain explicit
native-schema fixtures, not a running Rust forge or executed native conflict,
authorization, policy or ancestry engine. The old separate acquisition-only,
package-only and mutation-client suites are not represented as rerun here.
No full-workspace, release, hostile-parent confinement or universal hardware
power-loss durability verification is claimed.
