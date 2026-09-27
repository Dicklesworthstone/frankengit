# Recover Git source from a verified bundle

The Node-based offline recovery command creates a **new bare Git repository**
from a full bundle. This is portable source recovery, not `fg restore` and not a
reconstruction of FrankenGit authority, PRs, issues, policy or credentials.

```sh
node scripts/recover_git_bundle.mjs /backups/repository.bundle /recovery/repository.git \
  --head refs/heads/main \
  --expect-format sha1 \
  --expect-ref "refs/heads/main=$TRUSTED_MAIN_COMMIT"
```

Use Node.js 22 or later on a local POSIX filesystem supporting exclusive file
creation, hard links, directory synchronization and no-follow file opens. The
parent directory must already exist, be operator-controlled and remain
quiescent. The command does not invoke Git, a native inflater, network requests,
hooks, checkout code or a shell. Standard Git is used only by the interoperability
tests. No source file names become filesystem paths and no symlinks are created.

`--head` must explicitly name an advertised branch; `--head-hex` preserves a
byte-only branch name. HEAD is not guessed from an ambiguous bundle advertisement.
The command accepts the same `--expect-sha256`, `--expect-format`, repeated
`--expect-ref` / `--expect-ref-hex` and `--exact-refs` anchors as the offline
verifier. Anchors must come from a separately trusted source, not an unsigned
manifest next to the bundle. `--help` lists the exact grammar. Malformed
expectations are rejected before opening the input.

## What is reconstructed

The shared verifier checks the input pack, reconstructs native SHA-1/SHA-256
objects and validates the complete typed graph from all advertised direct refs.
Only then does recovery prepare Git's idx-v2 fanout, sorted object IDs, compressed
record CRC32s, offsets and native checksums. The original pack bytes are preserved
verbatim. A fixed minimal config selects the native object format. Raw ref names
are kept in packed-refs rather than converted into host paths. Reference names
that cannot coexist as loose refs are rejected. No remotes, alternates, hooks,
config includes, reflogs or worktree files are installed.

The bounded profile remains 16 MiB input, 128 MiB inflated-plus-reconstructed
object data and the verifier's other existing ceilings. Index/file construction
shares the verifier's work and deadline budgets. See
[offline verification](OFFLINE_GIT_BUNDLE_VERIFICATION.md) for exact limits and
non-claims. The resulting directory is a disposable Git materialization, never
a source of canonical FrankenGit authority.

## Publication and failure

The destination must be absent, including no empty directory or dangling
symlink. Exclusive mkdir reserves it with private permissions; files use exclusive
no-follow creation. A recovery receipt and process-ownership lock distinguish
staging from a completed repository. Objects, index, packed refs and config are
written, synchronized and read back first. The fully written HEAD is installed
last using a no-replace hard link, then the directory and parent are synchronized.
The temporary HEAD and ownership lock are removed only after publication.

A successful command exits 0 with a JSON report stating `state: complete`, the
selected HEAD, plan digest and source verification. A failure exits nonzero with
`not_created`, `staging`, `publication_unknown` or `published`. An incomplete
directory is retained for inspection; no recursive cleanup, replacement or
rollback runs. A lost response after HEAD publication does not imply absence of
publication. Cancellation before publication stops further work and closes handles;
after publication the command finalizes the acquired responsibility instead of
claiming rollback. Unsupported filesystem durability operations fail explicitly.

These checks detect substitution and corruption at the checked boundaries; they
are not an openat-based sandbox against a malicious same-user process continuously
rewriting the operator's parent directory. Keep the destination private and do not
modify it while recovery runs. This initial command does not resume an existing
partial directory; a new invocation refuses it rather than guessing ownership.

## Verify the recovered source

A successful directory can be opened or cloned by a compatible standard Git
client. The source-recovery tests compare generated indexes byte-for-byte with
installed Git, run verify-pack and fsck on complete fixtures, clone the result,
and compare original commits, tags and binary/symlink blob bytes. Run:

```sh
node --test tests/browser/bundle-recovery*.test.mjs
```

These are actual JavaScript/CLI/filesystem tests and installed-Git interoperability
observations, not native `fg` server, repository-gate or pinned-oracle evidence.

Recovery does not verify signatures, author identity, current branch freshness,
external gitlink targets or forge state. Transport-only objects remain in the
original pack and are counted separately: their unrelated histories are not part
of the advertised-ref closure guarantee. Do not equate that guarantee with every
upstream fsck policy or a full FrankenGit capsule restore.
