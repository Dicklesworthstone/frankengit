# Retained native PR candidates

The candidate acquisition client already reads one PR/reviewer snapshot, asks the
native node to prepare an explicit merge-commit or squash, and inspects that
exact bundle. `scripts/operator/pull_candidate_files.mjs` retains its output for
offline inspection and the candidate CLI. It does not create a review, seal,
transaction, merge permission, Git ref, or canonical object.

## Save and reopen

```js
import { capturePullCandidate } from '../scripts/operator/pull_candidate_capture.mjs';
import { saveCandidatePackage, loadCandidatePackage } from '../scripts/operator/pull_candidate_files.mjs';

const result = await capturePullCandidate(explicitInput, readToken);
const receipt = await saveCandidatePackage(newPrivateDirectory, result.capture, result.bundle);
// Retain receipt.sha256 independently of the package being transported.
const checked = await loadCandidatePackage(receipt.path, receipt.sha256);
```

Each new private directory has `capture.json`, `manifest.json`, and, for a clean
candidate only, `candidate.bundle`. The manifest binds exact lengths and SHA-256
hashes under fixed filenames. Its own SHA-256 is the package identity. It contains
no token, mutable local path, credential fingerprint, or permission assertion.
The capture retains original PR text, reviewer reasons, native diff/hunk bytes,
commit metadata, and endpoint identity: it is private, potentially hostile data.

Saving reuses `validateCandidateCapture`, writes and syncs complete capture and
bundle bytes, syncs their directory, then writes and syncs the manifest last.
A caller-owned bundle is detached before asynchronous validation. Identical
observations have identical package identities, irrespective of destination.
Files are mode 0600 and directories 0700, subject to a stricter umask.

Loading requires an independently supplied 64-character lowercase manifest hash.
It verifies the closed manifest, exact file inventory, every selected length/hash,
canonical JSON bytes, and the complete existing native capture validators. It
rereads the manifest and inventory before returning detached observations and
bundle bytes. Changed snapshot joins, missing reviewer pages, changed native
commit bodies, and malformed inspections refuse even when someone recomputes
local file hashes. A manifest hash alone is not native authorization or an
independent proof of Git ancestry, bundle closure, or the reported diff.

`conflicted` and `already_up_to_date` reports remain inspectable noncandidates.
They have no bundle or inspection and cannot be treated as empty successful
merges. Reading the package never contacts its endpoint or grants approval.

## Limits, interrupted writes, and trust

Capture JSON and bundle files are independently bounded to 16 MiB; the manifest
is bounded to 4 KiB. Reads check owner, private permissions, regular-file type,
single-link status, exact size and BigInt inode/nanosecond observations before
and after the read. Symlinks, aliased parents, Git-worktree paths, extra entries,
unsafe permissions and partial packages refuse. The reader never executes text,
extracts paths, or follows a manifest-selected filename.

Existing output directories are never overwritten, cleaned up or repaired.
Concurrent creation has one winner. Interrupted directories remain available for
diagnosis; a missing/partial manifest is not a completed package. Read acquisition
can be repeated explicitly into a different new directory, but this mechanism
never retries a repository mutation or reconstructs a publication key.

The default local-operation budget is 30 seconds, at most 300 seconds; optional
`signal` cancellation and deadline checks surround reads and validation. OS file
operations and synchronous bounded hashing/parsing are not hard-preemptible.
Once the complete root has been synced, successful local completion wins a racing
signal. A failed output channel cannot retroactively erase those files.

This is an operator-owned POSIX-filesystem profile, not confinement against a
hostile same-UID process swapping ancestors, a signed remote attestation, or a
universal hardware power-loss guarantee. Retain private original inputs and the
independent package identity; do not replace them with a self-selected new root.

## Verification

```sh
node --test tests/operator/pull_candidate_files.test.mjs
```

Tests use complete unchanged capture/MIME/inspection validators, actual private
files and HTTP sockets, and the existing test-only Git oracle for real SHA-1 and
SHA-256 bundles. HTTP reports remain explicit native-schema fixtures, not an
executed Rust `fg` server. This does not establish native admission/ancestry,
real deployment, or full-workspace verification. It adds no production dependency
and does not close `frankengit-root-doctrine-x2mv.4.13` or `.4.20`.
