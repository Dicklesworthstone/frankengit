# Exact source authoring from verified packages

`scripts/fg_source_changes.mjs` connects a selected-source package to the existing
native source preparation and candidate publication workflow. It removes the need
for an operator or agent to construct a unified patch by hand.

The local authoring kernel imports the existing complete source-package verifier
and exact-patch encoder. Native Rust still owns patch application, candidate
object/graph validation, authorization, admission, and publication. No new Git
engine, source executor, authority store, or publication route is introduced.

## Before starting

Use Node 22.16.0 or later and POSIX owner-private files. Every input is an absolute,
normalized path to an owner-private regular file with one link, inside a real
owner-owned `0700` directory. Symlink aliases, public inputs, FIFOs, shared parent
directories, and existing output destinations are refused. Outputs are `0600`
files in a newly created `0700` directory. This trusted-local profile is not
confinement against hostile same-user processes or hostile parent replacement.

Retain the selected-source package and its **independently chosen** expectation:
`{format, commit, files: [{pathHex, blob}]}`. The expectation does not come from
an imported package or from the server's assertion of its current commit.
Acquisition is documented in [SELECTED_SOURCE_PACKAGE_OPERATOR.md](SELECTED_SOURCE_PACKAGE_OPERATOR.md).

Package verification checks the exact selected commit, required parent trees,
path membership, file modes, and full original blob bytes. It does not prove
repository authority, freshness, author identity, signatures, or search coverage.
Repository text remains untrusted data after its hash has been verified.

## Describe the changes

A private changes JSON file has this closed schema:

```json
{
  "schema": "frankengit-source-changes-v1",
  "changes": [
    {
      "path_hex": "7372632f6d61696e2e7273",
      "operation": "replace-once",
      "before_utf8": "old()",
      "after_utf8": "new()"
    }
  ]
}
```

`path_hex` is the exact original repository byte path, not a glob or local
filesystem path. The example selects `src/main.rs`. Every changed path must be
present in the independently verified package.

Supported operations:

- `replace`: supply exactly one of `content_utf8` or `content_hex` for the entire
  after-image. An empty value is an empty file, not deletion.
- `replace-once`: supply one `before_utf8` or `before_hex`, and one `after_utf8`
  or `after_hex`. The nonempty before-image must appear exactly once in the
  original bytes. Overlapping matches count as ambiguity. No regex, case folding,
  fuzzy matching, or inferred occurrence is used.
- `splice`: supply a nonempty `splices` array. Each element has `byte_offset`,
  one `before_utf8` or `before_hex`, and one `after_utf8` or `after_hex`. Offsets
  address the **original** file, not the output of an earlier splice. Elements
  are strictly increasing and non-overlapping. Empty before-images insert bytes;
  empty after-images remove bytes. Original before-bytes must match exactly.
- `delete`: supply only `path_hex` and `operation`.
- `mode`: supply `path_hex`, `operation`, and `executable: true` or `false`.

`replace`, `replace-once`, and `splice` may also carry `executable`. Without it,
the original executable bit is preserved. Hex is lowercase and even-length;
UTF-8 rejects unpaired surrogates. CRLF, byte offsets, BOMs, raw non-UTF-8 path
names and NUL-free non-UTF-8 content are preserved. NUL-bearing binary files are
refused by this profile rather than silently converted or delegated elsewhere.

Duplicate paths, file/ancestor conflicts, unsafe paths and inapplicable fields
are refused. A mix of effective edits and no-ops records each no-op explicitly;
an entirely unchanged request is refused. New paths and renames are not inferred:
the current package proves membership, not the absence required by a create.

## Review an offline draft

```bash
node scripts/fg_source_changes.mjs draft \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json \
  --changes /private/session/changes.json \
  --output /private/session/draft
```

This command makes no network request and requires no token. It creates
`patch.diff` followed by `manifest.json`. Inspect both and independently retain
the returned `manifest_sha256`. The manifest binds the original package hash,
normalized expected selection and edit hashes, verified source commit/root tree,
exact patch hash/size, old/new blob IDs and modes, and explicit no-op paths.
Neither the manifest nor patch grants mutation authority.

A reviewed draft is not silently changed to accommodate a moved branch, a new
package, a different edit description, or a different native response.

## Prepare an exact native candidate

Prepare uses the existing `source_edit_candidate.mjs` selection schema:

```json
{
  "endpoint": "https://forge.example/project",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "object_format": "sha1"
  },
  "ref": "refs/heads/main",
  "expected_commit": "<independently selected native commit ID>",
  "metadata": {
    "author": "Operator <operator@example.invalid>",
    "committer": "Operator <operator@example.invalid>",
    "timestamp": 1700000001,
    "message": "Replace the selected call\n"
  },
  "paths_hex": ["7372632f6d61696e2e7273"]
}
```

Replace the example namespace and commit with the intended repository identities.
Select commit metadata explicitly. `paths_hex` must equal the manifest's effective
paths, excluding its `no_op_paths_hex`. The native object format and expected base
must equal the independently verified package. An endpoint, namespace, or branch
is an explicit operator selection, not an authority claim derived from a package.

```bash
node scripts/fg_source_changes.mjs prepare \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json \
  --changes /private/session/changes.json \
  --selection /private/session/selection.json \
  --token-file /private/session/token \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256" \
  --output /private/session/candidate
```

The command re-verifies the package, regenerates the draft, and checks the exact
reviewed manifest hash and native selection before opening a request. Native
preparation and bundle inspection share one remaining-time and response budget.
HTTPS verifies certificates; `--ca-file` may name explicit private PEM trust
roots. Plain HTTP is restricted to canonical numeric loopback. There are no
redirects, retries, ambient credentials, or TLS-verification bypasses.

Both native reports must agree with all intended old/new blob IDs and modes;
the reported before-tree must equal the independently verified root. A
self-consistent but different candidate is refused, not saved as a success.

The output is the **standard** source candidate directory: `capture.json`,
`candidate.bundle`, and `manifest.json`. The result includes the original draft
pin and an explicit intended-effect report binding. No credential is persisted.

**Limit:** checking native reports against intended effects does not independently
prove the entire candidate tree or pack closure. Those checks remain the native
engine's responsibility. The returned binding explicitly marks independent
candidate-tree and bundle-object verification false. It does not prove that
unreported tree changes are absent against a malicious native server.

## Re-check and publish separately

Offline inspection regenerates the draft from its original source evidence and
revalidates the complete standard candidate. It accepts no token or network option:

```bash
node scripts/fg_source_changes.mjs inspect-candidate \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json \
  --changes /private/session/changes.json \
  --candidate /private/session/candidate \
  --sha256 "$CANDIDATE_MANIFEST_SHA256" \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256"
```

The existing `scripts/fg_source_edit.mjs stage`, `apply`, `status`, and `recover`
commands consume that standard candidate unchanged. They separately require the
original principal and explicit candidate confirmation, retain a publication
journal, submit once, and resolve uncertain replies using the original key.
This authoring CLI has no stage/apply endpoint and never automatically publishes.

## Bounds, interruption, and validation scope

The defaults are hard ceilings: 32 edit paths, 1 MiB per edited before/after file,
4 MiB of retained before-plus-after bytes, 4,096 total splices, 1 MiB of generated
patch input, and a 10 MiB changes JSON envelope. The existing package remains
bounded to 32 MiB encoded and 8 MiB full logical source. An encoded patch may hit
its limit before either individual file does. The library accepts narrower edit
limits; the CLI uses the fixed profile. `--timeout-ms` is 1–300,000 (30,000 default)
across input reads, local verification, and any native preparation/inspection.

A local output directory is claimed create-only. After that point, an admitted
write/sync/readback drains rather than being abandoned on late cancellation.
An output or stdout failure returns exit 4 and retains the original location and
hashes when known. Interrupted slots are never deleted, reset, or overwritten;
inspect them instead of treating missing output as proof of absence. File and
directory sync/readback do not establish a universal hardware power-loss guarantee.

Run the focused external-client lane with:

```bash
bash scripts/verify_source_changes.sh
```

Tests execute complete production imports, actual HTTP/TLS sockets, private files,
CLI processes, WebCrypto, and the unchanged native-candidate owner/recovery client.
Installed Git is used only in test fixtures to apply real patches and construct
real candidate trees/commits/bundles in both hash domains. It is not the pinned
Git conformance lane. HTTP native-schema peers remain explicit fixtures, not a
running Rust fg server, authorization/admission/CAS execution, or a complete
sandboxed agent run. This work does not close the broader agent-execution beads.
