# Remote lexical source context

`node scripts/fg_source_context.mjs` acquires a bounded set of exact source
excerpts from an existing FrankenGit node and exports a self-contained local
bundle for scripts, investigation, or an agent's **untrusted data** input.
It does not execute repository code, initialize or update indexes, write refs,
publish forge events, follow symlinks, or create an Agent Protocol ContextPacket.

The client calls the existing authenticated `POST /api/v1/source/context-initial`
operation once. Native joined retrieval, source selection, and TreeFS hydration
remain in Rust. The client validates the returned coordinates, query, coverage,
budgets, and excerpt layout; it never approximates the join with separate
content/path requests. It accepts the unranked `raw-path-prefix` selection only.
Newer ranked context APIs do not change this profile implicitly.

## Requirements

Use Node 22.16 or later on a POSIX host with owner-private files/directories.
The server must expose its source-read API and have a persisted lexical index
applicable to the selected reference. A stale, uninitialized, unsupported or
unavailable index is an error, not an empty successful context. This client
never repairs that state or retries with weaker source expectations.

Supply a source-read bearer token (the node's existing 64-character lowercase
hex token format). Keep it in a regular, owner-owned `0600` file whose immediate
parent is an owner-owned `0700` directory. Query and optional CA files have the
same requirements. Symlink components and multiply linked files are refused.
Stable operator-controlled ancestors and a non-hostile same UID are assumed;
these checks are not a sandbox against the operator or filesystem administrator.

HTTPS performs ordinary certificate and hostname verification. `--ca-file`
selects a bounded private PEM trust file. Plain HTTP is accepted only for
numeric loopback addresses, not a DNS name such as `localhost`. There is no TLS
downgrade, redirect following, ambient credential lookup, cookie jar or retry.
An HTTPS deployment may use the node's existing operator-managed TLS gateway;
this tool does not supply or attest that gateway.

## Capture

Create private input and output-parent directories, then write a query. These
example IDs must be replaced with the intended repository's independently known
tenant, repository and incarnation IDs. Do not learn an expected scope from the
very response it is intended to constrain.

```sh
umask 077
mkdir -p /srv/context-inputs /srv/context-exports
chmod 700 /srv/context-inputs /srv/context-exports
cat > /srv/context-inputs/query.json <<'JSON'
{
  "schema": "frankengit-source-context-query-v1",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "object_format": "sha1"
  },
  "reference": "refs/heads/main",
  "terms": ["recover"],
  "prefixes_hex": ["637261746573"],
  "limits": {
    "context_max_files": 8,
    "context_radius_bytes": 128,
    "context_max_excerpt_bytes": 262144
  }
}
JSON
```

Place the existing read token in `/srv/context-inputs/source.token` without
putting it in argv or the query. One optional final LF or CRLF is accepted.
Then select a previously absent bundle directory:

```sh
node scripts/fg_source_context.mjs capture \
  --endpoint https://forge.example/team/repo.git \
  --query-file /srv/context-inputs/query.json \
  --token-file /srv/context-inputs/source.token \
  --output /srv/context-exports/investigation-001 \
  --timeout-ms 30000
```

The command emits a compact JSON receipt with the selected source, completeness,
file counts and `manifest_sha256`. It writes three owner-private files:

* `capture.json`: the checked native response, normalized query, source and index
  identities, explicit local verification limits, and original wire-response
  SHA-256. Source excerpts and paths retain their original lowercase hex bytes.
* `context.txt`: a bounded textual projection with source metadata and JSON-quoted
  excerpts. Control/directional characters are escaped; non-UTF-8 excerpts stay
  hex. Embedded role labels, shell commands, HTML and Markdown remain data.
* `manifest.json`: a last-written marker containing exact payload lengths and
  hashes. Payload files are synced and read back before this marker is written;
  the marker and directories are synced before success is returned.

No file is overwritten. A failed/terminated export can leave a partial directory;
retain and inspect it rather than deleting it to make the command succeed. A
new explicit capture needs a different output directory and may select a newer
source unless the original pins are supplied. Repeating a capture is a new read,
not resumption of a prior snapshot.

## Query and source constraints

Terms are 1–32 whole ASCII alphanumeric/underscore words, at most 128 bytes each.
They are folded to lowercase, deduplicated and sorted. Each native lexical channel
requires its matching documents to contain all selected terms. This profile is
not regex, substring, semantic, symbol or language-server retrieval. Unsupported
query fields are rejected. Prefixes are optional raw path-component prefixes
in lowercase hex, not globs; at most 128 prefixes and 32 KiB decoded in aggregate.
Names retain native byte identity and are never used as local output paths.

Both SHA-1 and SHA-256 repositories are supported. Optional query fields add
constraints rather than granting authority:

```json
{
  "expected_head": "alg:2:<64-lowercase-hex-digest>",
  "expected_commit": "<native-commit-id>",
  "minimum_lexical": {
    "token": "alg:2:<64-lowercase-hex-digest>",
    "number": "18446744073709551615"
  }
}
```

The example above shows field shapes, not actual usable pins. Copy real values
from independently retained observations/configuration. The minimum generation
is a decimal string so all u64 bits survive. A queried generation and the newest
observed maintenance checkpoint are recorded separately: maintenance may advance
an observed head without changing which generation answered the query. Conflicting
or regressed heads are rejected. Source refs, heads, commits, trees, incarnations,
corpus counts and document identities must agree across the joined response.

## Native read-result labels

When the Initial response declares `source-read-result-labels-v1`, the client
requires its whole-repository descriptor, original content/path/symbol row
labels and position domains. It checks each selected file's ordered original
label references, each anchor's originating row and each excerpt's reference to
the file's opaque lineage commitment. Path anchors address raw path bytes;
content/symbol anchors and excerpts address source blob bytes. The declaration
row itself retains its distinct declaration-byte domain.

The original retained-result limit covers both Initial rows/labels and the
separately reported `lineage_metadata_bytes`. The client independently reproduces
that metadata reservation from the selected witnesses and origin references;
an unexplained excess, missing field or mixed labelled/unlabelled result fails.
The normalized summary records the declared descriptor and metadata count;
`capture.json` retains all original wire labels and references in
`native_response`.

Older schema-1 responses without a descriptor are explicitly handled as legacy,
unlabelled data. Their summary representation remains unchanged so independently
pinned existing bundles can still be inspected. Absence of a descriptor never
implies labelled evidence, and partial declarations are rejected.

These checks establish structure and reference membership. The client does not
recompute the native label or lineage digests, authenticate a principal from a
descriptor, prove source authenticity, or acquire permission from a saved label.
The existing independent full-blob hash check below keeps its original scope.

## Bounds and incomplete coverage

Defaults are 100 results per channel, 16 Mi work units, 32 MiB index payload,
2 MiB retained retrieval data, 8 hydrated files, 128 bytes of context radius,
64 MiB source-read budget and 256 KiB total excerpt bytes. Each is explicitly
sent and checked. The client maxima are 32 hydrated files, 4096 anchors,
128 merged excerpt windows, 4096 radius bytes and 1 MiB excerpt bytes. Source
shares match the native rule: `min(8 MiB, source budget / selected file count)`;
a selected file exceeding its share fails the whole operation, not just that file.

At most 8 MiB of wire response is accepted. The acquisition and validation share
one monotonic timeout (1–300000 ms) and cancellation signal. File operations and
stdout have separate lifecycle handling; no hard filesystem latency guarantee is
claimed. Saved captures have a 12 MiB bound because normalizing u64 numbers to
quoted decimal strings and adding the query/summary can enlarge the representation.
Text exports are bounded separately at 8 MiB.

The native `complete` flag requires complete channel coverage and hydration of
all returned candidate paths. It **does not mean every file is present in full**.
Result-limit truncation, lexical omission inventories and the deliberate file
selection cap remain visible. Path-only matches get a bounded preamble; path
byte offsets are never treated as content offsets. A zero context radius retains
only matched bytes, or the native small preamble for path-only hits.

Partial context is exported by default with exit **3**, so callers can use it
without mistaking it for complete coverage. Add `--require-complete` to return
exit 3 without creating an export whenever coverage is incomplete. A genuine
complete no-match result is an empty export with exit 0; an API failure is not.

## Offline inspection and verification limits

Keep the emitted manifest hash independently, then inspect without any token,
network connection, source checkout or `fg` executable:

```sh
node scripts/fg_source_context.mjs inspect \
  --bundle /srv/context-exports/investigation-001 \
  --expected-sha256 "$RETAINED_MANIFEST_SHA256"
```

Inspection checks the exact manifest pin, fixed filenames, file lengths/hashes,
source/query/coverage consistency and regenerated text projection. It makes no
new acquisition and cannot widen a read scope. The retained wire-response hash
identifies the original response but is not independently rechecked offline:
`capture.json` normalizes u64 counters rather than storing original wire framing.

For an excerpt covering an entire blob, the client independently verifies the
native Git blob hash. For partial excerpts it checks coordinates and included
query bytes, but does not claim a full-blob hash, omitted boundary bytes,
complete search correctness, tree membership, ancestry or authority signatures.
An independently retained manifest hash detects bundle changes; it does not
create server authentication or upgrade source text to trusted instructions.
Source may contain secrets already present in the authorized repository; this
is not a secret-redaction or prompt-injection-proofing service.

Exit codes: **0** complete context/inspection; **3** explicit partial coverage or
`--require-complete` refusal; **2** input, API, validation or export failure;
**4** export completed but receipt output failed. A broken output pipe does not
erase a saved bundle. SIGTERM/SIGINT abort and close active reads without a retry.
No mutation outcome, merge approval, workflow success or policy authority is claimed.

## Validation

```sh
node --test tests/operator/source_context.test.mjs \
  tests/operator/source_context_export.test.mjs
```

The tests use real HTTP/TLS sockets, ephemeral private certificates, files, CLI
processes and signals. Their peer is an explicitly labelled native-schema fixture,
**not the Rust `fg` server**. OpenSSL is used only to generate test certificates.
These tests do not establish native index/admission/TreeFS correctness, live TLS
deployment security, hardware-power-loss durability, or a full-workspace pass.
