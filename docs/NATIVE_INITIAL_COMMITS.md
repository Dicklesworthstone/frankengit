# Native initial commits

A newly initialized node can create its first native Git history without an
imported repository, a host checkout, or an external Git executable. The same
operation can create an absent independent-history branch in a nonempty node.
It never overwrites an existing branch or changes the configured default HEAD.

## Prepare, independently review, then publish

```sh
fg init /data/new-node TENANT_ID REPOSITORY_ID sha1
fg patch prepare-initial /data/new-node TENANT_ID REPOSITORY_ID \
  refs/heads/main initial.patch initial.bundle \
  --trusted-local --profile exact-v1 \
  --author 'Author <author@example.invalid>' --timestamp 1 --message 'Initial commit'

fg patch apply-initial /data/new-node TENANT_ID REPOSITORY_ID \
  refs/heads/main initial.bundle --trusted-local --principal PRINCIPAL_ID \
  --key-stdin --expected-commit INDEPENDENTLY_REVIEWED_COMMIT_ID
```

The application command reads its exact retry key from standard input. A newline
is a key byte; it is not trimmed. `--idempotency-key` is the alternative for local
operators who accept command-line exposure. Keys never appear in receipts.
Application infers the native hash domain from the reviewed commit ID. To prepare
SHA-256 history, initialize with `sha256` and add `--object-format sha256` to the
preparation command. `--ref-hex` decodes the positional branch reference from
bounded lowercase hexadecimal, preserving non-UTF-8 names.

For example, `initial.patch` can contain:

```diff
diff --git a/README.md b/README.md
new file mode 100644
--- /dev/null
+++ b/README.md
@@ -0,0 +1 @@
+Created entirely by FrankenGit.
```

Preparation accepts creation-only `exact-v1` unified patches and explicit author,
committer, timestamp and message inputs. Committer defaults to author, and
`--message-file` supplies byte-exact message data instead of `--message`.
There must be at least one regular file, but a new file may be empty. Executable
files, nested directories, quoted raw paths, CRLF and final-newline markers use
the existing exact patch parser. Existing-file modifications, deletions,
symlinks, gitlinks, rename/copy and binary-patch encodings refuse. All paths and
any index prefixes are validated. There is no synthetic parent or base RCR.

The returned `initial_commit_preparation` JSON includes the selected authority
head, exact branch bytes, zero parent count, native commit and root-tree IDs,
per-file mode/blob/size, patch and bundle SHA-256 values, object count and bundle
length. Identical inputs produce identical native objects; changing patch
section order preserves their native identities while changing the patch hash.
Duplicate blobs and subtrees are shared. Git's virtual-slash tree order is
preserved independently of receipt order.

The complete candidate bundle is a self-contained v2/SHA-1 or v3/SHA-256 Git
bundle, not the single-parent incremental artifact accepted by `fg workspace
inspect`. Inspect its complete native object closure using a compatible bundle
reader and compare the reviewed commit ID independently. `apply-initial` takes
the saved bundle, not a patch recipe or caller-minted closure proof.

After publication, `fg tree`, `fg show`, ordinary `fg patch prepare/apply`, Git
transfer, and the rest of the existing node operate on the new native history.

## Publication and recovery

Preparation only reads authority metadata and computes immutable objects. It
never stages objects, creates a retry seal, changes a ref, alters policy, or
publishes a forge event. Its output file is create-only and is published after
node shutdown; failure is not reported as a complete artifact.

Application independently matches the bundle's sole advertised branch and
commit against the supplied review expectations. This initial profile accepts
exactly one zero-parent commit plus regular-file trees and blobs, without HEAD
advertisement, prerequisites, delta entries, symlinks, gitlinks, tags, or unsafe
names. The existing full-bundle quarantine then independently verifies native
hashes and the entire closure before normal expected-absent receive admission.
Current canonical branch protection still applies. There is no administrator,
review, force, quota, or policy bypass.

Two preparations for the same absent branch may both succeed. Only one can
publish; the other receives the ordinary canonical expected-old refusal. Even
an equal existing tip does not satisfy absence. Other intervening repository
work is not an implicit conflict: the write's predicate is exact branch absence,
not an invented requirement that every byte of the earlier snapshot remain
unchanged. The library's optional expected-head argument pins preparation only.

The transaction identity uses the existing atomic receive seal: tenant,
repository, authenticated principal, byte-exact retry key, and the absent-to-
reviewed-commit ref effect. An already decided identical operation is recovered
before new-publication service, quota, policy, and object checks, including after
restart or branch deletion. Recovery reconfirms the original seal but does not
claim to revalidate retry pack bytes. Changing semantics under a used key fails;
never use a fresh key merely because a response was lost.

`initial_commit_publication` JSON retains the terminal committed/refused outcome,
transaction ID, decision sequence, RCR or refusal identity, expected absence,
reviewed native commit, and cleanup state. Receipt/output or shutdown failure
cannot erase a known commit. An infrastructure error without a terminal outcome
is not evidence of non-commit. Reuse identical inputs/key or resolve with
`fg outcome`. Exit 0 means prepared/committed, exit 3 is canonical refusal, and
exit 2 covers input, infrastructure, cleanup or output failure.

## Scope and bounds

`fgit_forge::initial_commit::prepare_initial_commit` is the pure builder.
`OneNode::prepare_trusted_initial_patch_in` is explicitly a local-owner boundary;
this does not manufacture an agent capability or remote authentication.
`OneNode::apply_initial_patch_bundle_durable_in` consumes a session established
by the embedding authentication boundary. Repository text cannot supply identity.

The default patch envelope is 16 MiB input, 1,024 files, 4,096 hunks, 8 MiB per
file, and 32 MiB aggregate output. For this operation the aggregate output bound
also covers all unique native blob, tree and commit bodies, with a 32,768-object
hard ceiling. Expanded input-file content is bounded independently of content
deduplication. Caller limits may only narrow the supported envelope. Pack,
parser, node and admission limits also apply, and cancellation discards an
incomplete candidate. Range checks precede allocation where applicable.

## Native verification

```sh
bash scripts/verify_initial_commit.sh check
bash scripts/verify_initial_commit.sh test
```

The campaign uses actual forge construction, file-backed node publication,
refusal/recovery, current review protection, byte-exact CLI inputs and terminal
receipts. A fresh-process test starts with `fg init`, independently decodes and
hashes the complete bundle, publishes the root, reads its exact files, exercises
collision and replay, and publishes a second ordinary patch commit in both
native hash domains. There is no foreign Git fixture or production subprocess
fallback. Test presence is not passing evidence; execution binds to a source
revision, compiler and actual command results.
