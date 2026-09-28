# Stream signing and authentication of large source backups

The detached-signature command now hashes regular local files incrementally.
A backup larger than the browser's 16 MiB envelope can be signed or authenticated
without allocating the whole file. This is an operator-side artifact function,
not a new Git decoder, native authority store, or alternate restore engine.

```sh
node scripts/attest_git_bundle.mjs sign \
  /backups/repository.bundle /backups/repository.dsse.json \
  --key /private/backup-signing.pem \
  --repository team/repository --sequence 42 \
  --max-input-bytes 10737418240 --timeout-secs 1800

node scripts/attest_git_bundle.mjs check \
  /backups/repository.bundle /backups/repository.dsse.json \
  --trust-key /trusted/backup-public.pem \
  --repository team/repository --minimum-sequence 42 \
  --max-input-bytes 10737418240 --timeout-secs 1800
```

Here the operator permits at most 10 GiB of input and 30 minutes of work.
Neither a signed statement nor the input file can enlarge that allowance.
The default remains 16 MiB and five minutes. A caller can explicitly select
any positive exact JavaScript-safe integer byte ceiling, rather than hitting
an intrinsic 1 GiB archive ceiling. The timeout is a positive whole number of
seconds, at most 86,400. Invalid limits refuse before any command file is opened.
Limits apply to hashing/signature verification, not arbitrary kernel I/O delays;
this profile assumes an operator-controlled, quiescent local filesystem.

Both modes use one data-read buffer of at most 64 KiB. Input is opened with
no-follow and nonblocking flags and must be a nonempty regular file. The signed
length is checked before a verifying reader allocates its buffer. Every chunk
is hashed before buffer reuse. EOF, descriptor identity, nanosecond modification
and change times, size, mode, owner, link count, and final pathname identity are
checked before success. Concurrent replacement, truncation, growth, or mutation
at these boundaries fails rather than signing a mixed or partial artifact.
These checks are not a filesystem sandbox against a malicious same-user process.

Authentication verifies the signature, externally selected key, repository name,
sequence floor and lifetime **before opening the artifact**. Cancellation and
lifetime checks continue during reading; the monotonic deadline includes the
cryptographic operation. Read-only authentication and signing return no success
after an observed cancellation, timeout, mismatch or file change. Handles close
on all exits. Copy publication has the explicit finalization rule below.
Signing still uses exclusive, synchronized detached-envelope publication and
never overwrites an existing output. The command prints no private-key bytes.

The canonical DSSE payload and Ed25519 signature profile are unchanged. For the
same small bytes, metadata and key, streaming produces the same envelope as the
existing in-memory signer. CLI output adds `streaming.read_calls` and
`streaming.maximum_read_bytes`, measured by the reader, not a claim about total
process memory. The externally supplied repository and sequence floor remain
mandatory for checking; see [signed backups](SIGNED_GIT_SOURCE_BACKUPS.md).

## Library and compatibility boundaries

`scripts/lib/source-attestation.mjs` exports `signSourceBackupFile` and
`authenticateSourceBackupFile`. Each accepts `maximumBytes`, `timeoutMs`,
`signal`, and an optional progress callback. Progress reports contain cumulative
byte counts, not file content. The returned authentication report does not
provide bytes and is **not permission to reopen a pathname for recovery**.

`verifySourceAttestation` accepts an explicit `maximumBytes` when validating a
large signed length. Without it, its previous 16 MiB limit is unchanged.
`signSourceBackup`, `authenticateSourceBackup`, `readAuthenticatedSourceBackup`,
and the owned-byte Git verification/recovery commands keep their prior limits.
Large streaming signature success cannot bypass those limits.

This increment does not claim Git pack/object/closure validation, a complete
FrankenGit backup, streaming native `fg restore`, signature revocation, current
branch freshness, or restoration of issues, policy or authority history. The
signature approves exact opaque bundle bytes; the appropriate native Git
validator must still check the contents before use.

Run the focused production-code tests:

```sh
node --test tests/browser/bundle-attestation-stream.test.mjs
```

The suite includes a separate Node process that signs and authenticates a file
larger than 1 GiB, checks the independently computed digest, and records its
actual peak RSS and maximum read size. The fixture is a sparse zero-filled
opaque artifact, not a claim about Git validity or disk-throughput performance.
Other tests cover exact small-envelope equivalence, byte allowances, same-size
substitution, path and metadata mutation, cancellation, deadlines, signer and
policy capture, expiry during reads, and actual sign/check CLI execution.


## Materialize an authenticated large bundle

A successful read-only check is not permission to reopen an untrusted input path
for a later copy. Use the explicit `--copy-to` option to authenticate and copy
**the same streamed bytes** into a new operator-owned staging location:

```sh
node scripts/attest_git_bundle.mjs check \
  /incoming/repository.bundle /incoming/repository.dsse.json \
  --trust-key /trusted/backup-public.pem \
  --repository team/repository --minimum-sequence 42 \
  --max-input-bytes 10737418240 --timeout-secs 1800 \
  --copy-to /recovery/verified-source.bundle
```

Without this option, `check` remains read-only. Signing does not accept
`--copy-to`. The copy destination must be absent, and its existing parent must
be owned by the current user and not writable by group or others. This is a
local POSIX profile requiring no-follow opens, exclusive creation, hard links
and directory synchronization. The parent must remain quiescent; this is not
an openat-based sandbox against a malicious same-user process.

The command authenticates the envelope, key, repository and sequence floor
before opening the input or output directory. It then hashes and copies each
input chunk into a random private 0600 temporary file. The source is never
reopened between the checked read and copying. A changed source, wrong signed
length/hash, exhausted allowance, timeout or prepublication cancellation refuses.

Only after all source checks pass does it synchronize the temporary file and
read it back against the signed hash/length. It checks the held output inode,
pathname, permissions, link count and parent identity before a no-replace hard
link installs the destination. Two competing invocations cannot replace each
other's output. Existing files, directories and dangling symlinks all refuse.
No destination is unlinked or rolled back by this command.

Once the destination is linked, the command owns finalization: expiration or
cancellation does not skip directory synchronization and removal of its own
temporary link. A failing observer still permits finalization and then reports
failure with `state: published`. Other errors distinguish `not_created`,
`staging`, `publication_unknown` and `published` for this attempt; `not_created`
does not assert that a file from another attempt is absent. A lost response
never proves that publication did not happen. There is no automatic retry.

Success adds a `copy` record with the exact destination, digest and size,
readback/synchronization results and whether cancellation was requested after
publication. It still reports `object_closure_verified: false`. This creates
an authenticated **bundle file**, not a bare repository or native authority
store; native object/closure validation remains required before restoration.
The copied path must remain private and unmodified until its consumer checks
and uses it. Signature checking does not make a mutable filesystem immutable.

Failures clean up only this invocation's identified temporary inode. A changed
parent or substituted temporary file is not guessed safe to delete; a separate
`cleanup_error` and temporary path identify incomplete cleanup. SIGKILL can
leave a private `.fgit-authenticated-*.tmp` file. Later invocations do not reap
unknown leftovers, resume them, or count them as verified output. After a kill
following installation, the complete destination may already exist and a new
copy attempt refuses to overwrite it. Read-only authentication can check it.
Power-loss behavior has not been tested by the process-kill tests.

The library entry is `copyAuthenticatedSourceBackup`, with the same external
trust inputs and explicit file limits as the read-only streaming API. Copying,
readback and signature work share one deadline before publication. Data is
passed to the writer internally; no caller-supplied chunk handler may turn an
unverified stream into arbitrary effects.

Run all attestation tests, including real SIGKILL before/after installation:

```sh
node --test tests/browser/bundle-attestation.test.mjs \
  tests/browser/bundle-attestation-stream.test.mjs \
  tests/browser/bundle-attestation-copy.test.mjs
```
