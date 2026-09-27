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
modify it while recovery runs. A normal invocation still refuses every existing
path. Only the explicit resume mode below may continue a matching operation.

## Resume after cancellation, process death or a lost response

Re-run with the **same bundle, destination and explicit HEAD**, adding `--resume`:

```sh
node scripts/recover_git_bundle.mjs /backups/repository.bundle /recovery/repository.git \
  --head refs/heads/main --resume \
  --expect-format sha1 \
  --expect-ref "refs/heads/main=$TRUSTED_MAIN_COMMIT"
```

Resume re-verifies the supplied bundle and regenerates the complete pack/index/
reference/config plan. It compares the recovery receipt and every existing byte
against that regenerated plan, never against a saved claim of success. An
existing correct prefix can be extended; a mismatching prefix is not truncated,
rewritten or silently repaired. Complete files keep their inode and contents,
but are synchronized again: a killed writer can have reached full length without
finishing `fsync`. Native ref names still do not become filesystem paths.

The exact local layout is checked before any claim or source writes. Unexpected
files/directories, hooks, alternates, loose refs, symlinks, foreign hard links,
public permissions, other owners and changed receipts refuse. Once a recovered
repository has been modified by ordinary Git use, resume is not a general repair
command and will refuse additions or changes outside the original plan.

A live owner is never stolen. A same-host original process lock can be superseded
only after its PID is absent; unknown liveness, a foreign host or a reused live
PID refuses. This requires the same host and PID namespace, an operator-controlled
local filesystem and a private quiescent destination. It is not a distributed
lease or a defense against a malicious same-user process.

Subsequent owners use bounded, monotonically numbered records in
`.frankengit-source-recovery-owners/`. A completely written record is installed
by a no-replace hard link. Competing resumptions cannot both acquire the same
number, and a dead owner is superseded rather than removed by rival lock
reapers. A same-inode `.done` link releases ownership only after work settles.
A copied same-byte file does not count as release. Interrupted uninstalled
candidate records grant no authority and are retained. This journal is used by
the command itself, not a source of FrankenGit repository authority.

At most 128 numbered resume attempts and 384 ownership-directory entries are
admitted; exhausted or malformed histories fail closed. If a process dies before
both a complete original ownership record and a usable receipt/prefix exist,
resume refuses to guess ownership. Inspect that directory or choose a new absent
destination. There is no force, automatic deletion or cross-host lock takeover.

A successful resume adds `resumed`, `already_published`, `owner_sequence`,
`reused_bytes` and `appended_bytes` to the JSON result. If HEAD already matches,
the command validates every required file before touching source data, completes
synchronization/temporary-file cleanup, and reports `already_published: true`.
It never recreates, changes or removes a published HEAD. A published but incomplete
or corrupt directory is refused instead of being repaired underneath readers.
An uncertain existing state is reported as `existing_unknown`, not non-publication.

SIGINT/SIGTERM before publication stop work and release only the current owner's
claim. SIGKILL leaves the durable ownership record for the next explicit resume.
Cancellation after a newly published HEAD does not interrupt finalization. Errors
retain the observed publication state, and `cleanup_error` separately identifies
an ownership-finalization failure. A lost stdout response is not proof that HEAD
was never installed.

## Verify the recovered source

A successful directory can be opened or cloned by a compatible standard Git
client. The source-recovery tests compare generated indexes byte-for-byte with
installed Git, run verify-pack and fsck on complete fixtures, clone the result,
and compare original commits, tags and binary/symlink blob bytes. The resume
campaign kills real child processes before and after publication, during an actual
partial pack write, and during repeated resumptions, then runs the actual CLI
without Git on PATH and clones the result. Other tests inject corruption, layout
substitution, copied release records, live-owner contention, cancellation and
bounded ownership histories. Run:

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
