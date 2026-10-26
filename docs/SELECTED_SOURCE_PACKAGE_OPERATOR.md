# Commit-bound source packages for operators and agents

`fg_source_package.mjs` connects a saved native Initial source context to the
standard `frankengit-selected-source-package-v1` format. Its output is accepted by
`fg_verify_source_package.mjs`, browser package replay, and the existing
`fg_source_edit.mjs prepare-verified` input contract. No archive conversion or
manual reconstruction of commit/tree evidence is needed.

The package contains **complete selected files**, the original commit body, and
complete needed parent trees (including sibling names and object IDs). It is not
just the saved excerpts. Treat the package and all inputs as private source data.
Source bytes and commit messages remain untrusted data, never instructions.

## Inputs and independent selection

Use Node 22.16 or later on a POSIX host. Every input must be a bounded,
owner-controlled, singly linked regular file without group/other permissions,
inside an owner-private `0700` directory. Paths must be normalized and absolute;
symlink aliases are refused. This is trusted-local custody, not containment
against another process with the same user credentials.

Keep two separate selections:

* `selection.json` selects the endpoint, repository incarnation, ref and native
  commit. It uses the same fields as the source-context/archive operator tools.
* `expect.json` independently retains the exact selected path/blob inventory and
  native commit. It uses the existing offline package verifier's schema.

Example shapes below use placeholders, not valid object identities:

```json
{
  "endpoint": "https://forge.example/team/repository",
  "tenant_id": "32-lowercase-hex-digits",
  "repository_id": "32-lowercase-hex-digits",
  "repository_incarnation": "32-lowercase-hex-digits",
  "object_format": "sha256",
  "ref": "refs/heads/main",
  "expected_commit": "64-lowercase-native-hex-digits",
  "expected_head": "alg:1:aa"
}
```

```json
{
  "format": "sha256",
  "commit": "64-lowercase-native-hex-digits",
  "files": [
    {"pathHex": "7372632f6c69622e7273", "blob": "64-lowercase-native-hex-digits"}
  ]
}
```

SHA-1 uses 40-digit native IDs instead. `expected_head` may be omitted: the saved
context's observed head then narrows the independent commit selection; capture
still sends that exact head on every request. `files` must contain exactly the
context's selected files, in strictly increasing raw path-hex order. Only regular
and executable files are supported. The example path hex encodes `src/lib.rs`.

The commit trust anchor must come from an independent source. Retain the expected
file selection before acquisition; **do not generate `expect.json` from the
package being verified**. A tool can enforce separate inputs and exact agreement,
but cannot attest where an operator obtained those inputs.

`context.json` may be the original `source_context_initial` HTTP response or the
existing `frankengit-source-context-capture-v1` wrapper. Retain its SHA-256 when
saving it; do not substitute a freshly changed file and silently refresh its pin.
The token file contains exactly 64 lowercase hex characters, optionally followed
by LF or CRLF. Tokens are not command-line arguments or package fields.

## Capture and offline inspection

Replace `/private/session` with an existing private directory and the shell
variables with independently retained hashes. All outputs must be absent.

```sh
node scripts/fg_source_package.mjs capture \
  --selection /private/session/selection.json \
  --context /private/session/context.json --context-sha256 "$CONTEXT_SHA256" \
  --expect /private/session/expect.json \
  --token-file /private/session/read-token \
  --output /private/session/source-package.json
```

Capture performs additional authenticated reads of the selected commit, all
needed parent-tree pages, and every selected full blob. It neither descends into
unselected subtrees nor follows symlinks. The same repository/incarnation/ref,
commit, snapshot and source coordinates must hold throughout. An expired pin,
revocation, malformed response or exhausted budget refuses the operation rather
than retrying or changing the base.

Stdout is one bounded JSON receipt, not source text. Retain `package_sha256` and
`context_sha256` separately from the files. `expected_input_sha256` hashes the
exact expectation file bytes; `expected_selection_sha256` instead hashes the
normalized selection JSON. These two hashes need not be equal. Raw repository paths,
source bodies, credentials and server diagnostics are omitted from CLI output.

```sh
node scripts/fg_source_package.mjs inspect \
  --selection /private/session/selection.json \
  --context /private/session/context.json --context-sha256 "$CONTEXT_SHA256" \
  --expect /private/session/expect.json \
  --package /private/session/source-package.json --package-sha256 "$PACKAGE_SHA256"

# The preexisting generic verifier also accepts this exact package:
node scripts/fg_verify_source_package.mjs \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json
```

The first inspection also rechecks every original saved excerpt and both retained
file hashes. The generic verifier checks package membership and full blob bytes,
not the separate saved context. Neither inspection makes a network request.
The new command's `inspect` profile does not accept a token or acquisition flags.

For the existing edit workflow, pass the same package and independent expectation:

```sh
node scripts/fg_source_edit.mjs prepare-verified \
  --selection /private/session/edit-selection.json \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json \
  --patch-file /private/session/change.patch \
  --token-file /private/session/edit-token \
  --output /private/session/candidate
```

`edit-selection.json` is the **existing edit selection schema**, not the acquisition
selection above: it contains `endpoint`, `scope` (the three repository identities
and object format), `ref`, `expected_commit`, `metadata` (author, committer,
timestamp and message), and `paths_hex`. Its commit must match the verified package
and every edited path must be included in that package. Native preparation still
owns patch semantics, policy and candidate generation. Preparation does not grant
publication authority; the existing stage/apply/recover steps remain separate.

## Native authority-head verification at capture

The same capture command accepts an explicit `--native-fg /absolute/path/to/fg`.
Use an owner-controlled executable without symlink aliases or group/other write
permissions. In this mode, `selection.json` must include an independently retained
`expected_head`; a head copied from the response being checked is not a trust
anchor. The endpoint must be numeric-loopback HTTP, matching the current native
`fg verify-read` client profile. HTTPS, DNS names and implicit head discovery are
refused before acquisition rather than downgraded to another client.

After the existing complete package and excerpt checks, every selected path is
read again through Rust `verify-read`. That engine authenticates the exact head,
configuration and ref membership and checks the original commit/tree/blob path.
Its receipt must name the independent head, expected commit, blob, kind and byte
count; its complete bytes must equal the selected package body. Empty files also
require a native receipt. A failed proof, changed snapshot, denied credential,
wrong executable response, deadline or cancellation prevents package publication.
No native refusal falls back to the JavaScript-only capture path.

The native calls share the original total deadline and each consumes one slot
from `package.maxBlobRequests` in addition to the existing blob pages. This total
is checked before source requests. There are at most 32 native calls; each also
retains the native verified-blob profile's closed proof/metadata/tree limits.
The selected source-byte and portable-package limits do not increase. Native
processes use the existing request/drain/finalize owner. A private token snapshot
and verified output files are finalized only after child quiescence; containment
failure or unknown scratch contents retain the directory and report
`native_scratch`, never recursively remove it. The executable is operator-trusted,
not sandboxed or authenticated by its filename.

Capture stdout includes `native_read` with the independently supplied head,
executable SHA-256, selected file count and `verified_at_capture:true`. Retain this
capture receipt if needed. The package format is unchanged and carries **no
retained authority proof**; its ordinary `verified.authorityVerified` stays false.
Offline `inspect`, the generic verifier and editing consumers continue to check
Git content/membership and do not recreate or attest the native capture event.
This mode does not prove search completeness, author signatures, a qualified
native build, current freshness after capture, or a complete Context Packet.

## Limits, custody and failure handling

An optional private `--limits` JSON file accepts the following defaults and hard
byte/request ceilings. Only the deadline may increase, up to 300000 milliseconds.

```json
{
  "timeoutMs": 30000,
  "package": {
    "maxSourceBytes": 8388608,
    "maxBlobRequests": 160,
    "membership": {
      "maxRequests": 512,
      "maxTrees": 128,
      "maxEntries": 16384,
      "maxTreeBytes": 4194304
    }
  }
}
```

At most 32 files and 32768 total raw path bytes are supported. Complete selected
source and page counts are checked before I/O; each selected path pays its logical
byte/read budget even when two paths share a blob. Only serialized bodies are
deduplicated. Saved context is limited to 12 MiB, packages to 32 MiB, and original
excerpts to 128 ranges / 1 MiB total. The read/verification deadline spans all
requests and hashing, not a fresh timeout for each page. HTTPS is mandatory outside
numeric loopback. Default Node TLS trust applies; disabling certificate validation
with `NODE_TLS_REJECT_UNAUTHORIZED=0` is refused.

Capture publishes only after every native commitment and original excerpt passes.
It writes and syncs a private temporary file, creates the destination without
replacement, syncs the parent directory, then reads back and verifies the actual
published bytes. A begun local write/sync/readback is drained after a late stop;
filesystem completion is not a hard wall-clock promise. No output is automatically
deleted or overwritten during recovery.

| Exit | Meaning and action |
| --- | --- |
| 0 | Complete verification (and capture readback) passed. Inspect `stop_requested` for a late stop. |
| 2 | Refusal before confirmed success/publication attempt. No successful subset is returned. |
| 3 | SIGINT/SIGTERM observed before publication. No package publication was attempted. |
| 4 | A result was retained, or local publication/readback/stdout is uncertain. Preserve the original inputs and reported path/hashes; inspect that destination. Do not retry capture into it. |

An error after create-only linking does not establish that the destination is
absent. Competing writers cannot overwrite one another. Error receipts report a
bounded phase rather than echoing private parser inputs or server prose.

## Verification boundary

```sh
bash scripts/verify_source_packages.sh

# Require real native HTTP/proof scenarios with the current pinned Node:
FG_BIN="$qualified_fg" FGE_NODE="$pinned_node" \
  scripts/e2e/suites/verify/selected_source_native.sh
```

The tests run complete production modules with real HTTP sockets, Fetch,
WebCrypto, private files and Node child processes. Native-schema fixture peers
and independently framed Git objects cover both hash formats, parent/blob
pagination, empty/raw-path/shared bodies, corruption, exact/one-under bounds,
revocation, cancellation, competing publishers and output failure. The actual
preexisting offline verifier consumes captured output in a fresh process.

Without `FG_NATIVE_BIN`, the package lane explicitly skips the two native
scenarios. The discovered E2E suite requires a supplied binary and pinned Node,
refuses skipped cases, and runs both hash domains through real `fg serve-http`
and `fg verify-read` processes. Its generated saved context selects imported
native objects; it is not an independent Initial-search oracle. It covers
CLI create-only publication, offline interchange, proof tampering, native-read
cancellation, stale pins and grant denial. Peer/provider controls are labeled;
their results are not native engine evidence. Evidence must name the actual
client source and supplied binary/source cut separately.

The fixture-only cases verify client acquisition/custody/interchange behavior,
not a native authorization/CAS implementation. Neither profile establishes search coverage,
ranking/declaration semantics, retained authority proofs, ongoing freshness,
author signatures, a complete
repository backup, end-to-end native editing or a complete agent Context Packet.
Those claims remain explicitly false or outside this command's scope.
