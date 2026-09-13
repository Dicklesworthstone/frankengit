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
cargo test --locked -p fgit-node --test workspace_patch
cargo test --locked -p fgit-cli --bin fg patch_command::tests
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
