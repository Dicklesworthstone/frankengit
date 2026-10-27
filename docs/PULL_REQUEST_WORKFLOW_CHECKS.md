# Pull-request workflow observations

The PR checks read path exposes immutable workflow observations selected by the
authenticated repository authority head. It works with native SHA-1 and SHA-256
repositories and includes only checks for the PR's exact recorded source ref and
commit. Results retain the publisher and original conclusion. Listings summarize
evidence by SHA-256 and byte count. A separate, explicitly authorized HTTP read
returns one selected check's canonical evidence and, when its format is
supported, its retained execution output.

Publish a retained job result with
[`fg workflow publish`](WORKFLOW_PUBLICATION_COMMAND.md), then read it through
any of the interfaces below. Publication requires the reporting branch to name
the exact executed commit.

## Interfaces

- HTTP: `GET /<repository-route>/api/v1/pulls/<number>/checks`. Enable the existing
  pulls API and supply a credential with `pulls-read`. Write or Git-read grants
  do not imply this grant. Optional parameters are `limit` (1–100, default 20),
  `after` (an exact check ID) and `expected_head` (the first page's snapshot token).
- CLI: `fg pr checks <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local [--object-format sha1|sha256] [--limit N]
  [--after ID --expected-head TOKEN]`. Exit 0 returns a complete JSON response,
  4 means the PR is absent/hidden, and 2 means invalid input or a read/cleanup
  failure. `complete` indicates whether more observation pages remain.
- MCP: `frankengit_pull_checks`, enabled by the existing pulls read grant.
  `number` is an exact positive decimal string. `limit` is a JSON integer from
  1–20 (default 5); `after` and `expected_head` have the HTTP semantics.
- Browser: open a PR and select **Load checks at this snapshot**. All subsequent
  pages retain that selected PR snapshot. Refreshing the PR is an explicit action.
  To inspect output, connect a separate evidence credential with both `pulls-read`
  and `artifact-read`, then select **Load evidence and logs** on a listed check.

An `after` cursor always requires `expected_head`. Ordinary later publications
do not change a retained page. Unavailable snapshots return an error; the reader
does not silently switch to a newer head. Current caller visibility and canonical
hidden-ref policy still apply to both PR branches, even for historical reads.

## Response contract

All interfaces return `type: "pull_request_checks"`, `schema_version: 1`, repository
and incarnation bindings, `object_format`, and the decimal-string PR `number`.
For a visible native PR, the response includes:

- `source_head` and continuation `snapshot_token`;
- `pull_request_version` as a decimal string;
- `source_ref_hex`, `target_ref_hex`, `source_tip` and `target_tip`;
- `source_current`, `after`, `limit`, `next_after` and `complete`;
- `checks`, ordered by the full publisher-derived check ID.

Each check contains `id`, `publisher`, `run_id`, `attempt_id`, `graph_root`, `job`,
`conclusion`, `evidence_sha256`, and decimal-string `evidence_bytes`. Missing and
hidden PRs both produce `found: false`, null subject/snapshot fields and an empty
check list; HTTP uses 404 for that response. MCP marks reads `read_only: true`;
the CLI returns only after shutdown and marks `node_closed: true`.

If the source branch at the selected head has moved or disappeared since the
PR's recorded tip, `source_current` is false and both the check list and
continuation are empty. Refreshing PR metadata to a new commit excludes old-tip
observations. A new result appears only after an observation matching that new
source is canonically published. A retained snapshot continues to describe its
own historical source state.

## Selected check evidence and execution output

The evidence endpoint is:

```text
GET /<repository-route>/api/v1/pulls/<number>/checks/evidence?check=<check-id>&expected_head=<snapshot-token>
```

URL-encode both values. Both fields are mandatory; pagination fields, request
bodies, Git protocol headers and idempotency keys are rejected. The pulls API
must be enabled, and the supplied bearer credential must have **both**
`pulls-read` and `artifact-read`. Neither grant alone discloses execution output.
No workflow-artifact root is required: these bytes come from the selected
canonical check event, and its `evidence_sha256` is not an artifact-container ID.

The reader authenticates the pinned head, resolves the PR's source at that head,
applies current caller and canonical hidden-ref visibility to both branches,
then reads only the selected check's authenticated event body. Its source ref
and commit must exactly match the PR. Missing or hidden PRs, missing checks,
checks for another source, and a source already moved at the selected head all
return the same generic HTTP 404 without subject or output metadata. An
unavailable retained snapshot returns 409; it never selects a newer snapshot.

A successful response is a bounded JSON envelope with these fields:

- `type: "pull_request_check_evidence"`, `schema_version: 1`, `read_only: true`;
- `page`: one complete `pull_request_checks` object containing exactly the
  selected row, with `after: null`, `limit: 1`, `next_after: null` and
  `complete: true`; its repository, PR and snapshot coordinates remain intact;
- `evidence_hex`: the exact canonical evidence bytes in lowercase hexadecimal;
- `report`: a validated report span, described below, or `null`.

Decoded evidence is capped at 1 MiB. The HTTP response is capped at 8 MiB and also
obeys the configured response ceiling. A failed limit, integrity check or
cancellation returns an error before a successful body is sent.

On Linux, the existing trusted-observation decoder validates supported evidence
against its committed bytes and exact repository/source/run/attempt/graph/job
coordinates. The decoded outcome must match the canonical conclusion; older
`action_required` observations may retain successful local reports without
upgrading that conclusion. A supported report is returned as:

```json
{"offset": 123, "bytes": 456, "json": "exact original report JSON"}
```

The numbers above are illustrative byte offsets and lengths. The browser checks
the report's exact byte span and preceding unsigned 64-bit big-endian length
against the already hash-checked evidence, then validates the closed report
grammar before displaying output. Unknown or unsupported evidence has
`report: null` and remains available as an exact raw download. Non-Linux hosts
also serve raw evidence without a trusted-local report projection.

The browser renders retained stdout/stderr as inert text, with exact stream
downloads and a separate raw evidence download. A 64 KiB preview limit per
stream does not discard downloaded bytes. Incomplete capture and a clipped
preview are reported separately. Evidence credentials stay in memory and are
independent of the PR connection; disconnect, PR reselection, page exit, and
401/403 responses erase the evidence session and its retained output. These
views preserve `scope: "trusted_workflow_observations"` and
`merge_permission: null`.

## Scope

The conclusions are `action_required`, `success`, `failure`, `cancelled` and
`timed_out`. The canonical publisher retains the actual mapped job outcome;
older observations can retain `action_required`. A `success` observation by
itself does not establish independent execution verification or authorize a
merge. Every checks response has `scope: "trusted_workflow_observations"` and
`merge_permission: null`.
This read capability neither schedules workflows nor publishes check results.
Independent runner attestation and automatic PR/push-triggered CI remain separate
work in the broader CI integration bead `frankengit-root-doctrine-x2mv.4.12`.

The explicit selected-event scan is capped at 65,536 events and 128 MiB of frames,
with pages capped at 100 summaries. These are additional reader bounds, not a
claim that prior authority materialization has no separate cost. Missing,
substituted or corrupt selected frames, cancellation and exhausted budgets
refuse instead of returning an apparently successful partial page.
