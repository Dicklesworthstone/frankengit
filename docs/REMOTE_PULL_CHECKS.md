# Remote PR checks, evidence and retained logs

`node scripts/forge_checks.mjs` lets a remote terminal operator or sponsored
agent select a PR, read its canonical workflow checks, inspect the exact retained
execution report and download evidence or step output. It needs the repository
HTTP service and private credential files; it does not need node storage, a
browser or a local `fg` executable.

This is the PR consumer slice of the headless interface described in plan
§31.6 and FG-051a. It consumes the existing
[native PR checks API](PULL_REQUEST_WORKFLOW_CHECKS.md) and complements the
[remote PR mutation operator](REMOTE_PULL_REQUESTS.md). It does not change
workflow scheduling, check publication or the broader CI work on `.4.12`.

## Select the PR and its exact checks

Use the exact `/ui/pulls/` URL and known tenant/repository IDs. The client derives
the native API routes from that URL. HTTPS is required except on loopback;
redirects, URL credentials and normalization are refused. Optional
`--incarnation-id` and `--object-format sha1|sha256` further constrain the expected
repository. Every subsequent read retains the first observed incarnation,
object format, snapshot and source head.

```bash
node scripts/forge_checks.mjs list \
  --url https://forge.example/team/project.git/ui/pulls/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-reader/pr-token --limit 20 --max-pages 5

node scripts/forge_checks.mjs checks \
  --url https://forge.example/team/project.git/ui/pulls/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-reader/pr-token --number 17 \
  --limit 20 --max-pages 5
```

`show --number N` reads one PR's metadata. `list` preserves both raw ref hex and
optional display text, including byte names that are not UTF-8. Rendered HTML
and unknown metadata extensions are omitted. JSON escapes terminal controls and
bidirectional formatting characters without changing decoded field values.

`checks` first selects the PR and then loads checks at that same snapshot. Each
check retains its exact ID, publisher, run, attempt, graph, job, conclusion,
evidence SHA-256 and decimal-string evidence length. It preserves
`source_current`, `scope: "trusted_workflow_observations"` and
`merge_permission: null`. A stale source produces the native empty checks
observation. An absent PR produces `found: false`. Neither observation establishes
passing CI or that no workflow ran.

List and checks reads default to one page of 20 entries. A bounded prefix returns
exit 4, `complete: false` and a `continuation` with the exact snapshot, cursor and
page size. Resume with `--after` and `--expected-head`; a noninitial cursor without
its original snapshot is rejected. List cursors are PR numbers; checks cursors
are full check IDs. Native historical snapshot availability and current access
checks still apply. A malformed later page, changed source head or revoked grant
fails the whole read, rather than returning its earlier prefix as a complete
result. No command refreshes a stale PR or retries a read automatically.

## Inspect one explicitly selected check

Retain a check's ID, digest and length together with its `snapshot_token` from
the checks result. All four pins are mandatory for `evidence` and `log`.

```bash
node scripts/forge_checks.mjs evidence \
  --url https://forge.example/team/project.git/ui/pulls/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-reader/pr-token --number 17 \
  --expected-head "$SNAPSHOT" --check "$CHECK_ID" \
  --expected-sha256 "$EVIDENCE_SHA256" --expected-bytes "$EVIDENCE_BYTES" \
  --evidence-token-file /srv/fg-reader/evidence-token
```

The reader reselects the PR at that exact snapshot and locates the exact check
under a finite page budget. It refuses a changed pin before requesting evidence.
Then the shipped `CheckEvidenceClient` verifies the evidence length and SHA-256,
the returned check and subject, and the native report's exact framed byte span.
Recognized reports must also satisfy their existing closed schema and outcome
checks. This reuses the browser decoder; the operator does not introduce another
evidence format or infer execution facts from arbitrary artifact content.

The JSON result includes the canonical check and supported report. Retained
stdout/stderr remain exact lowercase hex, so binary bytes are preserved. An
unrecognized evidence format has `report: null`; its raw bytes can still be
downloaded. `action_required` stays `action_required` even when an older report
records local success. Tolerated failures retain their failed step outcome and
nonzero exit code alongside the explicit tolerance fields.

Evidence selection defaults to at most ten pages of 100 checks. Use an exact
`--after` cursor from the same snapshot or an explicit larger `--max-pages` if
needed. Exhausting that budget before finding the selected check is an error,
not permission to select another check or current head.

## Download exact evidence or one log stream

Add `--output /srv/fg-reader/check.evidence` to `evidence` to save the complete
canonical evidence bytes. To save one recognized report's retained stream:

```bash
node scripts/forge_checks.mjs log \
  --url https://forge.example/team/project.git/ui/pulls/ \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --token-file /srv/fg-reader/pr-token --number 17 \
  --expected-head "$SNAPSHOT" --check "$CHECK_ID" \
  --expected-sha256 "$EVIDENCE_SHA256" --expected-bytes "$EVIDENCE_BYTES" \
  --evidence-token-file /srv/fg-reader/evidence-token \
  --step 0 --stream stderr --output /srv/fg-reader/step-0.stderr
```

Step indexes are zero based and must actually exist in the retained report. The
stream is exactly `stdout` or `stderr`. A missing or unsupported report cannot
produce a log. An empty retained stream creates a zero-byte file; arbitrary
binary output is written without decoding or newline conversion.

The output parent must already be an owner-private directory. The reader checks
for an occupied name before network work and publishes through the existing
private artifact-stream writer only after evidence, report and output-envelope
validation. It verifies byte length and SHA-256 again, synchronizes the staged
file and publishes a new `0600` name without replacing another file. No execute
permission is applied. A collision during publication preserves the competing
file. Cancellation before publication leaves no downloaded destination.

Once a file is published, it remains even if later cleanup or stdout delivery
fails. Diagnostics include `output` and `output_may_exist` where applicable;
retain and inspect that file before choosing another destination. A failed CLI
exit is not permission to overwrite it. Export JSON records the payload length
and SHA-256. Log metadata retains the original job/step outcomes,
`output_complete`, exit code and workspace-retention state. A successful
download of incomplete retained output does not make the capture complete.

## Credentials and disclosure boundaries

Credentials stay in memory for the invocation. Private token files contain
either 64 lowercase hexadecimal characters or `fgagent_` followed by 64 lowercase
hexadecimal characters, with at most one final LF. Files must be owner-private,
regular, single-link files; symlinks and unsafe modes are refused. Tokens are
never accepted directly on the command line or written into results.

| Connection | Ordinary repository credential | Sponsored credential |
| --- | --- | --- |
| PR list/show | `pulls-read` | `pulls-read` |
| Checks, including their prerequisite PR selection | `pulls-read` | `pulls-read` and `pulls-feedback-read` |
| Selected evidence request | `pulls-read` and `artifact-read` | `pulls-check-evidence-read` |

Evidence uses the explicitly named `--evidence-token-file`; the PR token is
never reused implicitly. The same file may be selected for both roles when its
current grants permit both. The native service reauthenticates each request.
The sponsored evidence capability discloses only exact canonical check evidence;
it does not supply general workflow artifact access.

The opt-in browser transport profiles used here permit only bodyless PR metadata
and check GETs, or the existing exact evidence GET. They cannot send mutations,
query outcomes, create candidates or read generic artifacts. Existing browser
clients retain their original credential defaults.

## Bounds and validation

Every invocation has a default 30-second deadline covering files, requests and
CLI output; `--timeout-ms` accepts 1–300000. Page size is 1–100 and page budget
1–100. Native evidence remains limited to 1 MiB; responses and final JSON have an
8 MiB ceiling. `--max-output-bytes` can narrow the JSON bound. Later failures do
not release partial result JSON as successful output.

Exit 0 means a complete read or export, including a reported failed check or an
absent PR. Exit 4 means a valid bounded list/checks prefix with continuation.
Exit 2 means invalid input, refused access, failed integrity, incomplete selection,
cancellation or output failure. These exits are read outcomes, not CI verdicts.

Run the focused consumer tests with:

```bash
TMPDIR=/tmp node --test --test-concurrency=1 tests/operator/forge-checks.test.mjs
```

They exercise the production clients and transport through real loopback sockets,
private files and Node subprocesses, with a response-schema peer simulating the
native service. Cases include both Git hash domains, byte refs, pagination,
separate sponsored scopes, revoked access, corrupt evidence/report bindings,
binary/empty logs, concurrent output collisions, deadlines, signals and failed
stdout delivery. This test class does not execute the Rust node, native admission,
workflow execution, or establish independent execution verification.
