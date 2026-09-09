# Native pull-request commands

`fg pr` connects the existing native PR command, canonical admission, embedded
node and pinned read APIs to an operator-facing workflow. It creates and edits
PR metadata; it does not create a GitHub PR, run repository code, infer approval,
or publish a merge. `fg merge prepare` and `fg merge apply` remain separate.

**Implementation status (2026-09-09):** the CLI is implemented in
`01947735cbc661915b7d57eb5a2724108ab81010`. Eleven Rust CLI tests are registered.
Rust compilation and native execution were not available in this editing
environment; this guide is not a passing build or production-conformance report.

## Open, update and close

For an existing imported node, with independently selected source/target tips:

```bash
fg pr open "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 7 \
  --trusted-local \
  --principal "$PRINCIPAL_ID" \
  --idempotency-key 'pr-7-open' \
  --source-ref refs/heads/topic --expected-source "$SOURCE_COMMIT" \
  --target-ref refs/heads/main --expected-target "$TARGET_COMMIT" \
  --expected-version 0 \
  --title 'Review the topic branch' \
  --body-file ./pr-body.md
```

The action is `open`, `update` or `close`. All three supply complete desired
metadata. Open requires expected version **0**; update and close require a
positive exact prior aggregate version. There is no automatic number allocation,
latest-version substitution, implicit branch-tip refresh or metadata merge.

Use a distinct key for each deliberately new command. To update the PR opened
above, use `update`, expected version `1`, a new key and the complete desired
title/body/tips. Branch identities cannot change. Opening and updating require
both supplied tips to match current authority. To close that updated PR, use
`close`, expected version `2`, a new key and its exact currently recorded data.
Closing does not silently edit metadata and can preserve recorded tips after a
branch moves or is deleted, subject to the node's retained-object checks.
Closed or merged PRs cannot be resurrected through an update.

Exactly one of `--body <text>` and `--body-file <path>` is required. An explicit
`--body ''` means an empty body, not an omitted field. File bytes are read once,
with no trimming or newline conversion, and must be valid UTF-8 without NUL.
Preserve those exact bytes when retrying a file-backed command; the filename is
not part of the seal, but changed file content changes the command. Switching
between inline and file input with identical bytes does not change semantics.

`--source-ref-hex` and `--target-ref-hex` accept bounded lowercase hexadecimal
reference bytes instead of their text alternatives. Each pair is mutually
exclusive. The result's `source_reference_hex` and `target_reference_hex` fields
can therefore be used without a lossy conversion. Ref validation remains the
existing native `RefName`/same-repository branch contract.

Mutations infer SHA-1 or SHA-256 from the explicit native tips. An optional
`--object-format sha1|sha256` must agree; mixed and zero identities refuse.
Tenant, repository and principal IDs use the existing lowercase-hex spelling.
Numbers and versions use canonical unsigned decimal, with no leading zeros,
signs or wrapping. The implementation does not execute shell expansion on any
field, interpret Markdown as options, or obtain credentials from repository text.

## Read and paginate

```bash
fg pr list "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --limit 20

fg pr show "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 7 \
  --trusted-local
```

Read commands default to SHA-1; add `--object-format sha256` for that repository
format. A list defaults to 50 entries and admits limits 1 through 100. Native PRs
and explicit merge-only receipts are ordered by numeric PR number, not lexical
text. Legacy Digest-only PR streams are outside this explicitly native view.

The list result carries the exact `source_head`, an algorithm-qualified
`snapshot_token`, `has_more`, and an exclusive numeric `next_after`. Continue
with both returned fields:

```bash
fg pr list "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --limit 20 \
  --after "$NEXT_AFTER" --expected-head "$SNAPSHOT_TOKEN"
```

A positive `--after` requires the pin. The token uses the same `alg:N:hex`
spelling as the existing `fg at` position parser, with the head domain and
current canonical codec version implicit in this typed option. It is not an
access capability. The node compares the typed identity before returning rows;
the CLI also verifies its returned window before emitting it.

This is an exact-current-head precondition, **not** a persistent historical read
session. If any canonical decision changes the head, continuation refuses with
`SnapshotMoved`; restart from the first page rather than mixing the two views.
A partial final page has no cursor, as does an exactly full page when no further
visible PR exists. Read failure is never reported as a completed empty list.

`show` returns either the exact number or `found: false, pull_request: null`.
It never substitutes the next larger PR, and hidden and absent exact lookups
remain indistinguishable. Both branch identities must pass the node's current
visibility checks before a row is disclosed.

Rows contain the current version, state, last action, full native metadata,
opener and last metadata actor where available. A merged PR retains its
recorded title/body/opener alongside the exact native merge coordinates.
A merge-only stream is labelled `merge_receipt` with null metadata/opener;
no opening or review history is fabricated. Current metadata actors are not
mislabelled as the merge principal. PR text remains untrusted data, not safe HTML.

## Outcomes, recovery and output

| Exit | Meaning |
|---|---|
| 0 | The command committed, or a list/show read succeeded. |
| 3 | The mutation has a canonical terminal refusal; JSON names its refusal record. |
| 4 | An exact show found no visible native PR; JSON contains no substitute row. |
| 2 | Invalid input, infrastructure, snapshot, cleanup or output failure. |

Mutation receipts report the original transaction ID, decision sequence,
committed RCR or refusal record, submitted action/version/data, principal and
repository coordinates, and explicit node-close status. The private idempotency
key is not echoed in the receipt. `command_committed` describes the requested
PR effect; a refused command can still publish its canonical refusal decision.
`refs_changed` is false for this metadata workflow. `delivery_acknowledged` is
null: creating the canonical outbox obligation does not prove delivery, and a
retry's historical receipt does not observe the current destination state.

The node is explicitly shut down before JSON is emitted. A known commit remains
reported as committed if shutdown, stdout write or flush fails. The error names
the known outcome and any cleanup failure. A nonzero exit by itself is **not**
proof of non-commit. Reconcile by repeating the identical principal, key and full
command. Do not recompute tips, increase its expected version or change the key
to recover an uncertain attempt. After a known terminal refusal, a deliberately
corrected command is a new operation with a new key, not a retry of the old one.

The node API resolves an authenticated exact command's existing terminal result
before charging push quota or requiring the cell to accept new publications.
It revalidates the immutable seal and key binding before returning that result.
This applies to both committed and canonically refused commands, including after
reopening a cell without bringing it into service. New commands still obey
intake and quota limits; a changed command cannot recover the old result by
reusing its key. Request cancellation and authority I/O limits still apply.

JSON is one UTF-8 line. Native refs remain hexadecimal bytes; quotes, backslashes,
C0/C1 controls and Unicode line/paragraph separators are escaped in text. Decoding
preserves the original strings. Consumers must use integer-preserving JSON
handling for the full u64 number/version range rather than rounding via floats.

## Bounds and trust

The parser admits at most 48 argument tokens, 128 KiB of aggregate argument
text and 64 KiB per argument. Titles are at most 256 UTF-8 bytes; bodies are at
most 65,536 bytes. Ref/path arguments have separate 4096-byte bounds. Body-file
checks reject symlinks, devices, invalid UTF-8, NUL and growth beyond the ceiling
before opening repository state. This assumes a stable operator-controlled
file; it does not claim hostile-host path-race isolation.

The list response has a 48 MiB ceiling and does not emit partial JSON when a
read/format limit fails. Existing node authority, event, object and request
budgets still apply independently. No new dependencies or alternate runtime,
PR database, event encoding, authority source or publication protocol are added.

`--trusted-local` acknowledges an already-authorized local operator; it is not a
credential check or a safe remote gateway. Authentication, per-principal remote
policy, fork PRs, reviews/approvals, issue/comment workflows and hosted APIs are
outside this command profile. Unsupported or inapplicable flags fail rather
than being ignored.

## Tests and verification limits

The eleven CLI tests cover both formats, required fields, duplicates, bounds,
exact-version and pin semantics, raw ref encodings, numeric pages, non-disclosing
not-found reads, merge-only rendering, untrusted text, bounded file intake and
write/flush/cleanup failures. The embedded-node tests exercise the real PR
lifecycle and retain exact committed/refused outcomes after cancellation of a
retry, quota containment and reopening without enabling new writes.

The CLI integration target runs the Python campaign below against Cargo's own
`fg` binary. It requires Python 3.11 or newer; an unavailable driver fails the test. Thus
the all-targets test includes both command-level assertions and the native
fresh-process lifecycle/merge path.

The admission fault tests call the PR publisher for all three lifecycle
actions in both hash formats. They inject checkpoint cancellation, interrupted
immutable writes, lost CAS requests/responses and a competing successful CAS.
They check exact retry outcomes and coupled forge/outbox state with unchanged
refs. Their faultable in-memory authority and fixture projection provide
driver-level evidence, separate from file-backed node and process tests.

```bash
cargo test -p fgit-cli --all-targets
cargo test -p fgit-node --lib treefs_workspace::pull_request::tests::
python3 scripts/e2e/pull_request_smoke.py --fg /absolute/path/to/fg
```

The campaign constructs native objects and a reviewed merge bundle independently,
then uses fresh CLI processes for open/update/close, file/inline retry equivalence,
competing versions and key reuse, exact/pinned reads, closed-PR merge refusal,
active-PR merge and metadata retention, historical retry after later publication,
and unchanged unrelated refs. Where `/dev/full` exists it also forces receipt
output failure after a real commit and verifies idempotent recovery. Whether
that fault was exercised is explicit in the campaign report. The supplied binary
is fingerprinted; a missing executable is an error, never a skipped success.

Initial evidence at `524b6d7e` in the editing environment: Python syntax/help
checks, both native fixture formats and pack checksums, **68 damaged-report/JSON checker cases**, a
missing-binary refusal, Rust lexical/delimiter inspection, **36 format-template
argument checks**, and exact Git blob-hash comparisons for all six Rust files.
The separate `--self-test` mode states `rust_executed: false`; it does not execute
`fg`. Cargo, rustc, Rust tests, Clippy, rustfmt and the complete native campaign
were unavailable. These checks do not close FG-029 or establish a production gate.
