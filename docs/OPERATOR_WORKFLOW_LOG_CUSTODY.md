# Retained logs in trusted operator workflow automation

Related work: `frankengit-root-doctrine-x2mv.4.12` (still open).

The operator watcher can request the native log-capture contract without
selecting output files. Add this `artifacts` object to a new watcher configuration:

```json
{
  "root": "/private/workflow-artifacts",
  "selections": [],
  "capture_logs": true,
  "maximum_file_mib": 16,
  "total_payload_mib": 64
}
```

The root must satisfy the existing owner-private, nonsymlink artifact-directory
rules. `capture_logs` is an explicit boolean, not a truthy string. Omitting it
or setting it to false preserves the old normalized file-only configuration,
argument list and immutable binding bytes. An empty selection list without
log capture still refuses. Existing explicit output selections and same-attempt
input delivery can be combined with logs; logs cannot substitute for a selected
producer output or authorize cross-run reuse.

The adapter passes `--artifact-logs` to native dispatch and verifies the exact
`log_capture` schema/stream list in both the dispatch and child attempt contracts.
Changing capture in an already-bound watcher namespace refuses rather than
replaying a previous attempt under a new contract. Select a new namespace
explicitly; preserve all unresolved custody from the old one.

## Receipt verification and budget accounting

The shared artifact-report gate checks each `artifact_logs` job against the
already-validated execution report. Every recorded step has exactly one stdout
and one stderr receipt in native order, including zero-length streams. Step
index, optional UTF-8 name, SHA-256 script commitment, stream, outcome, exit code
and completeness must agree. Payload length and SHA-256 are checked against the
exact binary bytes in that execution report. Unknown, duplicate, missing,
partial, unrequested or contradictory receipts refuse settlement.

Files and logs consume the same cumulative `total_payload_mib` allowance across
all workflow children. `maximum_file_mib` applies to each retained payload;
the native execution stream ceiling is not increased. Input delivery remains
separately charged for every consumer copy. Empty payloads are valid, not an
excuse to omit a stream receipt.

A successful job with recorded steps must have complete retained logs. Jobs that
failed or stopped may have no receipt if custody failed; they stay non-successful.
The native log receipt precedes final custody/deadline settlement, so an observed
success can legitimately end refused, cancelled or timed out. An observed failure
may end cancelled or timed out. The gate permits these native downgrades, never a
promotion to success. Skipped or pre-start jobs have no executed-stream receipt.

This is verification of consistency between retained observations, not independent
execution attestation or a replacement for native artifact-store verification.
No receipt grants check publication, cache reuse or repository authority. Logs
remain unredacted binary data and may include secrets printed by trusted scripts.
The host-execution trust boundary and artifact-read authorization are unchanged.

## Focused regression command

```sh
node --test tests/operator/workflow_artifact_logs.test.mjs \
  tests/operator/workflow_artifact_report.test.mjs
```

These tests run the production JavaScript configuration, contract and receipt
gates against explicit native-schema fixtures. They cover legacy byte stability,
binary/empty streams, failed/stopped jobs, contract and receipt substitutions,
combined file/input/log custody, and exact cumulative budget boundaries. They do
not execute native Rust, prove process containment or physical power-loss
behavior, or close the broader CI product-loop acceptance.

The underlying native custody semantics and inspect/export interfaces are in
[`TRUSTED_WORKFLOW_ARTIFACTS.md`](TRUSTED_WORKFLOW_ARTIFACTS.md).
