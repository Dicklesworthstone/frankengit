# Exact native patch workflow

`fg patch` turns a bounded Git unified patch into a reviewable native commit
without running `git`, a shell, hooks, an external merge driver, or a host tool.
It does not materialize a working directory. Preparation reads an exact,
authority-selected commit through verified TreeFS objects, applies every file,
and exports ordinary typed edits through the existing TreeFS exporter. Only
separate, explicit publication can move the branch.

## Local-owner commands

Prepare a new bundle against the independently chosen current branch tip:

```bash
fg patch prepare "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main input.patch reviewed.bundle \
  --trusted-local --profile exact-v1 \
  --workspace-id "$WORKSPACE_ID" --expected-base "$BASE_COMMIT" \
  --author 'Author <author@example.invalid>' --timestamp 1789330000 \
  --message 'Apply reviewed patch'
```

The workspace identifier is exactly 16 bytes encoded as 32 lowercase hexadecimal
characters. Metadata is explicit: it is not read from repository configuration
or treated as authentication. `--committer` may differ from the author;
`--message-file` accepts bounded exact message bytes instead of `--message`.
`--ref-hex` decodes the positional branch reference as exact lowercase hex.

The JSON preparation receipt includes the source commit and repository commit
record, candidate commit, candidate tree, patch SHA-256, bundle SHA-256 and
size, packed-object count, and every file's old/new blob identities, resulting
mode, and hunk count. File paths are hexadecimal bytes. The receipt explicitly
states that repository state was not published. The bundle's single prerequisite
is the selected source commit; it is an incremental artifact, not a full clone.

Review the saved bundle independently, including with the existing
`fg workspace inspect` command. Then publish that exact saved artifact:

```bash
fg patch apply "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main reviewed.bundle --trusted-local \
  --principal "$PRINCIPAL_ID" --key-stdin \
  --expected-base "$BASE_COMMIT" --expected-commit "$REVIEWED_COMMIT" \
  < retry-key.bin
```

The retry key is 1–256 exact bytes, including any newline, and is not printed in
receipts. `--idempotency-key` is the command-line alternative. The existing
native authority key domain is unchanged by the CLI's nonempty-key requirement.
Apply does not accept a patch recipe, rerun preparation, or infer the reviewed
commit from untrusted input. It passes the saved bundle through production
quarantine and ordinary expected-old admission. There is no force bypass or new
authority store. Current canonical protection remains part of existing admission.

Exit 0 means prepared or committed; exit 3 means an authenticated canonical
refusal; exit 2 means input, infrastructure, output, or cleanup failure. A known
terminal decision stays in the receipt when shutdown fails. A lost response or
infrastructure failure is not evidence of non-commit: retry identical bundle,
principal, key, branch and expectations, or use existing outcome recovery.

The output writer creates a complete new artifact without replacing a file,
directory or symlink. It reports visibility/finalization uncertainty separately
from repository publication. No bundle is created after preparation or node
shutdown failure. This is a trusted local-owner filesystem boundary, not a
hostile concurrent host-filesystem sandbox.

## Supported exact-v1 input

The parser owns `diff --git` sections for regular files, including creations,
deletions, executable-bit changes, C-quoted raw paths, CRLF content and Git's
missing-final-newline marker. Empty-file additions and deletions and mode-only
changes are supported. Every hunk's context and both coordinate systems must
match exactly. No offset search or whitespace normalization occurs.

When an `index` record is supplied, both old and new full or abbreviated native
blob IDs must match the verified source/result; zero names describe absence.
No SHA-1/SHA-256 guessing occurs. Metadata never grants permission.

Binary patch encoding, symlinks, gitlinks, rename/copy records, combined diffs,
mail wrappers, alternate strip prefixes and ambiguous headers return typed
refusals. A no-net-tree-change patch returns a refusal rather than creating an
empty commit. Duplicate targets and file/descendant target collisions are
rejected; input order cannot introduce sequential rename/replacement semantics.

## Library and resource boundaries

### Explicit inert symlink profile

`fg patch prepare --profile exact-symlink-v1` extends the existing
`exact-tree-v1` grammar with Git symlink mode `120000`. It creates, edits,
deletes and renames link-text blobs, and allows explicit mode changes between
ordinary files and symlinks. Link text remains exact blob data: neither absolute
targets nor `..` components are resolved, opened, or materialized on the host.
Missing-final-newline markers preserve ordinary Git symlink payloads exactly.
Type changes use explicit `old mode` / `new mode` headers. Two delete/create
sections naming the same path still refuse as duplicate targets; this profile
does not reinterpret those sections in sequence. Initial-commit patch profiles
are unchanged and do not admit symlinks.

For example, this creates a link whose stored bytes are `../target`, with no
final newline:

```diff
diff --git a/link b/link
new file mode 120000
--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+../target
\ No newline at end of file
```

The new profile uses the same verified source/index identities, complete
directory preservation, original-coordinate rename rules, shared binary
decoder and cumulative limits as `exact-tree-v1`. Renames require both path
grants and an absent destination; chains and cycles remain refused. Compressed
edited renames, directories, gitlinks and copies remain outside this profile.
Every older profile retains its symlink refusal, including a patch without a
mode header that tries to edit an existing symlink.

The capability-owned native entry point is
`OneNode::prepare_workspace_symlink_patch_in`; the local-owner wrapper is
`OneNode::prepare_trusted_symlink_patch_in`. Preparation and saved-bundle
publication remain separate. `SymlinkPolicy::Refuse` also prevents this profile
from creating or reading symlink entries.

### Explicit opaque gitlink profile

`fg patch prepare --profile exact-gitlink-v1` creates, updates and deletes Git
submodule pointers (mode `160000`) alongside ordinary exact text changes such as
`.gitmodules`. It treats each pointer as an external commit identity, verifies
the old pointer against the selected source tree and emits the new pointer in
the candidate tree. It never reads or imports the foreign commit, hashes a
synthetic pointer line as a blob, checks out a submodule or accesses its URL.

Use the canonical full-index Git submodule diff shape, for example:

```diff
diff --git a/vendor/lib b/vendor/lib
index 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 160000
--- a/vendor/lib
+++ b/vendor/lib
@@ -1 +1 @@
-Subproject commit 1111111111111111111111111111111111111111
+Subproject commit 2222222222222222222222222222222222222222
```

The identities are illustrative; use the actual selected pointer and the exact
intended replacement. All pointer and index IDs must be lowercase, full-width
and in the repository's native hash domain: 40 characters for SHA-1, 64 for
SHA-256. Creation uses `new file mode 160000`, an all-zero old index,
`--- /dev/null`, and `@@ -0,0 +1 @@`; deletion uses `deleted file mode 160000`,
an all-zero new index, `+++ /dev/null`, and `@@ -1 +0,0 @@`. The present side must
be nonzero. Each side is exactly one `Subproject commit <id>` line with a final
LF, matching its index. Abbreviations, dirty suffixes, partial images, extra
context and missing-final-newline markers refuse.

This profile permits regular-file text edits and mode changes, but refuses
binary sections, symlink edits, copies, renames and conversion between gitlinks
and other entry kinds. Every older profile continues to refuse gitlink edits.
Paths remain disjoint, complete-directory disclosure preserves siblings, and
all changes share the existing input, output and cancellation bounds. Synthetic
pointer-image bytes count against the patch budget. Initial-history preparation
is unchanged and does not admit this profile.

The explicit native APIs are `OneNode::prepare_workspace_gitlink_patch_in` and
`OneNode::prepare_trusted_gitlink_patch_in`. HTTP preparation selects
`patch_profile=exact-gitlink-v1`; MCP `prepare_patch` selects
`"profile": "exact-gitlink-v1"`. Both retain the existing source-candidate grant
and require separately authorized, reviewed saved-bundle publication.

For this profile, CLI, HTTP and MCP path receipts use `old_object` and
`new_object` for **every** changed path, since a gitlink target is a commit
pointer rather than a blob. `new_mode` distinguishes a pointer (`160000`, octal)
from an ordinary file; deletion has a null new object and mode. HTTP encodes
modes as JSON numbers, while CLI and MCP receipts use octal strings. All older
profiles retain `old_blob` and `new_blob`. Inspection identifies gitlink entries
without opening their targets. These selectors do not enable gitlink authoring
in the browser editor or the JavaScript source-workspace commands.

### Shared resource bounds

- `fgit_diff::patch::UnifiedPatch` parses borrowed hunk data and applies files
  without storage access. It exposes optional index expectations, which an
  object-store consumer must verify. `fgit_forge::patch` reexports this module.
- `OneNode::prepare_workspace_patch_in` accepts a caller-owned `TreeCapability`.
  Every write must also be readable; all target rights are checked before file
  content is read. Directory completeness checks prevent filtered siblings from
  being deleted. Insufficient scope refuses instead of widening the capability.
- `OneNode::prepare_trusted_patch_in` is only for a local owner already authorized
  to read the whole repository. It discovers complete root scope to preserve
  untouched siblings, with writes limited to the declared patch targets. It is
  not a remote authentication endpoint. Agents use their existing capability.

Default patch ceilings are 16 MiB input, 1,024 files, 4,096 hunks, 262,144
records/lines, 4,096 path bytes, 8 MiB per input/result file, and 32 MiB aggregate
result file bytes. `PatchLimits` can only narrow these ceilings. The CLI exposes
lower input/file-count/hunk-count/output ceilings. Application rechecks narrowed
hunk/line limits even for an already parsed patch.

Trusted local preparation also caps reads at 256 MiB and 100,000 object fetches,
including initial commit/root discovery. Export is bounded to 100,000 objects,
64 MiB and 100,000 tree entries. The first verified storage read remains subject
to the existing fabric's configured stored-object ceiling; the narrower patch
file cap is checked before copying that payload into the patch engine, not
before the fabric's initial allocation. Patch limits do not replace storage
allocation policy. Ordinary node and capability limits remain in force.

## Verification entrypoints

```bash
cargo test --locked -p fgit-diff --lib patch::tests
cargo test --locked -p fgit-diff --lib patch::gitlink_tests
cargo test --locked -p fgit-node --test workspace_patch
cargo test --locked -p fgit-node --test workspace_gitlink_edits --test workspace_gitlink_patch
cargo test --locked -p fgit-node --lib sponsored_http_gitlink
cargo test --locked -p fgit-cli --bin fg patch_command::tests
cargo test --locked -p fgit-cli --bin fg sponsored_mcp_gitlink
cargo test --locked -p fgit-cli --test native_patch_smoke
```

The parser tests include independently constructed whole-file hunks for 6,396
small old/new line sequences, malformed/bounded inputs, exact context/newline
semantics, and cancellation. Node tests use real file-backed authority, verify
exact native trees/commits in both hash formats, preserve unedited content, and
exercise publication and recovery after reopening. CLI tests exercise parsing,
byte-exact keys, and decision-preserving output/cleanup failures. The fresh-
process campaign invokes the real `fg` binary and independently checks emitted
pack checksums, objects and native identities using Python's standard library.
It does not invoke Git or substitute a fake node.

These commands describe the test targets, not a claim that they passed. Native
compilation and execution must use the repository's pinned toolchain and remain
subject to the repository's ownership and batch-verification rules.
