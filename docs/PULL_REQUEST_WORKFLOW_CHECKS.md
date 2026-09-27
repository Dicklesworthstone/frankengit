# Pull-request workflow observations

The PR checks read path exposes immutable workflow observations selected by the
authenticated repository authority head. It works with native SHA-1 and SHA-256
repositories and includes only checks for the PR's exact recorded source ref and
commit. Results retain the publisher and original conclusion; evidence is
summarized by SHA-256 and byte count, with no execution output in the response.

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

## Scope

The conclusions are `action_required`, `failure`, `cancelled` and `timed_out`.
A successful trusted-local process still reports `action_required`: it does not
establish independent execution verification or a passing protected check. Every
response has `scope: "trusted_workflow_observations"` and `merge_permission: null`.
This read capability neither schedules workflows nor publishes check results.
Independent runner attestation and automatic PR/push-triggered CI remain separate
work in the broader CI integration bead `frankengit-root-doctrine-x2mv.4.12`.

The explicit selected-event scan is capped at 65,536 events and 128 MiB of frames,
with pages capped at 100 summaries. These are additional reader bounds, not a
claim that prior authority materialization has no separate cost. Missing,
substituted or corrupt selected frames, cancellation and exhausted budgets
refuse instead of returning an apparently successful partial page.
