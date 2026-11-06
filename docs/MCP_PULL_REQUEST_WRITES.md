# Native pull-request mutations through MCP

The operator may independently enable `--allow-pull-writes` on `fg-mcp`.
This exposes PR submission, update, closure and reopening over the existing durable
`OneNode::admit_pull_request_durable_in` boundary. There is no MCP-owned PR
store, caller-selected principal, shell subprocess, or latest-tip lookup.

```sh
fg-mcp "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --allow-pull-writes --allow-pulls --allow-outcomes \
  --principal "$PRINCIPAL" --expected-incarnation "$INCARNATION"
```

`--allow-pulls` and `--allow-outcomes` above are optional independent grants.
PR writes alone permit neither reads nor original-key recovery queries. Issue
writes remain independent. Every writer requires a launch-bound principal and
an exact repository incarnation. An operator explicitly sponsors the connected
process as that principal; this is not remote IAM or an Intent Run broker.
Do not expose the stdio channel to an untrusted remote principal.

The separate sponsored-agent launch profile also permits these lifecycle tools
when `--allow-pull-writes` intersects a current canonical `pulls-write` grant.
The credential supplies the agent and sponsor; no caller principal is accepted.
Reads and original-key recovery still require their independent scopes and
launch ceilings. See [sponsored credentials](SPONSORED_AGENT_CREDENTIALS.md).

## Commands

`frankengit_pull_open`, `frankengit_pull_update`, `frankengit_pull_close`, and
`frankengit_pull_reopen`
all accept a complete explicit command:

```json
{
  "number": "7",
  "expected_version": "0",
  "idempotency_key": "open-feature-7",
  "source_reference": "refs/heads/topic",
  "target_reference": "refs/heads/main",
  "expected_source": "<native source commit hex>",
  "expected_target": "<native target commit hex>",
  "title": "Proposed change",
  "body": "Literal review description"
}
```

Open requires version zero. Update, close and reopen require a positive exact prior
version, not a floating latest version. Numbers and versions are canonical
unsigned decimal strings. Native OIDs must be nonzero, lowercase, and match
the repository's SHA-1 or SHA-256 domain.

Each reference has an alternative `source_reference_hex` or
`target_reference_hex` field for non-UTF-8 branch names. Supply exactly one
encoding for each branch. Names are bounded to 4096 bytes and must be full
`refs/heads/...` references. The schema expresses the alternatives with
`oneOf`; dispatch independently enforces them.

All operations require title and body, including close and reopen. An empty body is an
explicit replacement, not an omitted field. Titles retain the native 256-byte
bound; MCP bodies are at most 16 KiB. Unknown/inapplicable fields, forced
updates, repository selectors, caller principals, approval flags, and bundle
inputs are rejected before admission.

## Publication and recovery

Native admission verifies the exact PR predecessor and the source/target tips
for open/update/reopen. Updating cannot retarget branch identities or reopen a closed
or merged PR. Close requires unchanged full recorded data and remains possible
after a source branch disappears. These are native forge rules, not assumptions
made by a transport-local projection.

Reopen requires a closed, unmerged PR and preserves its source and target branch
identities. The complete command may replace title/body and explicitly refresh
both tips to their current values. For an open at version `1` followed by close
at version `2`, call `frankengit_pull_reopen` with `expected_version: "2"`, a new
durable key and the complete desired metadata. Missing branches, stale tips,
retargeting, already-open PRs and merged PRs refuse. Reopening never recreates a
deleted branch. The original opener remains recorded, and the reopened PR can
be updated or closed through the ordinary exact-version commands.

Accepted PR metadata and its existing outbox obligation publish together through
canonical admission. These commands change no Git ref and provide no review,
check, merge, or publication permission for code. There is no read-after-write
lookup that can replace a known canonical outcome with an infrastructure error.

Replies carry the launch binding, transaction ID, decision sequence, exact
submitted version, action, and canonical committed/refused outcome. A canonical
refusal is an MCP tool error with a terminal receipt, not an ambiguous transport
error. Command text and the durable key are not echoed. `refs_changed=false`;
`delivery_acknowledged=null` does not claim delivery to any external receiver.

Retry the identical complete command with the SAME durable key and a new
JSON-RPC request ID. Do not refresh a stale version under that key. Historical
terminal retries are resolved before current serving/quota/branch checks. A
new key with a stale predecessor receives its own refusal, not an overwrite.
With the separately granted outcome tool, recover the ORIGINAL key after a
lost reply. Disconnects and infrastructure failures are not evidence of rollback.
The existing protocol's terminal-outcome and broken-output handling is reused.

## Verification scope

Parser/schema tests cover both native domains, lossless ref bytes, complete
metadata, exact versions, injected authority fields and semantic-identity
changes. Persisted-node integration tests exercise the MCP handshake, PR
lifecycle, identical retries, stale refusals, unchanged-metadata closure after
branch deletion, explicit tip/metadata refresh on reopening, missing-branch and
retargeting refusals, stopped-intake recovery, independent grants and mutation
annotations. Sponsored tests exercise write-only credentials, launch-ceiling
denial, principal injection, revocation and rotated-credential retry while
preserving the original actor evidence. Existing issue-read/write tests retain
their original grants.

Run `cargo test --locked -p fgit-cli --bin fg-mcp` on the pinned toolchain.
Rust/Cargo are unavailable in the session introducing this implementation;
these Rust tests have been written, not executed. No full FG-096, hosted
multi-principal, CI-check or merge-publication acceptance is claimed.
