# Native pull-request mutations through MCP

The operator may independently enable `--allow-pull-writes` on `fg-mcp`.
This closes the PR submission/update/closure path over the existing durable
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

## Commands

`frankengit_pull_open`, `frankengit_pull_update`, and `frankengit_pull_close`
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

Open requires version zero. Update and close require a positive exact prior
version, not a floating latest version. Numbers and versions are canonical
unsigned decimal strings. Native OIDs must be nonzero, lowercase, and match
the repository's SHA-1 or SHA-256 domain.

Each reference has an alternative `source_reference_hex` or
`target_reference_hex` field for non-UTF-8 branch names. Supply exactly one
encoding for each branch. Names are bounded to 4096 bytes and must be full
`refs/heads/...` references. The schema expresses the alternatives with
`oneOf`; dispatch independently enforces them.

All operations require title and body, including close. An empty body is an
explicit replacement, not an omitted field. Titles retain the native 256-byte
bound; MCP bodies are at most 16 KiB. Unknown/inapplicable fields, forced
updates, repository selectors, caller principals, approval flags, and bundle
inputs are rejected before admission.

## Publication and recovery

Native admission verifies the exact PR predecessor and the source/target tips
for open/update. Updating cannot retarget branch identities or reopen a closed
or merged PR. Close requires unchanged full recorded data and remains possible
after a source branch disappears. These are native forge rules, not assumptions
made by a transport-local projection.

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
branch deletion, stopped-intake recovery, independent grants and mutation
annotations. Existing issue-read/write tests retain their original grants.

Run `cargo test --locked -p fgit-cli --bin fg-mcp` on the pinned toolchain.
Rust/Cargo are unavailable in the session introducing this implementation;
these Rust tests have been written, not executed. No full FG-096, hosted
multi-principal, CI-check or merge-publication acceptance is claimed.
