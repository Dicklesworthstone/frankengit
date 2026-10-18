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

## Command-line workflow

`node scripts/fg_pull_candidate.mjs --help` exposes `capture`, `inspect`, and
`draft`. Only `capture` accepts credentials or contacts the native node. None of
these commands publishes repository state. The existing `remote_pull.mjs`
remains the separately confirmed sender.

Create an owner-private directory outside a Git worktree, with mode-0600 JSON
and token files. The acquisition input is the existing `capturePullCandidate`
input documented in `REMOTE_PULL_CANDIDATES.md`: exact endpoint and repository
scope, a PR number as a decimal string, explicit author/committer/timestamp/message,
explicit `merge-commit` or `squash`, and an optional retained `expected_head`.
No author, principal, timestamp, branch or merge method is taken from environment
variables, Git configuration or a current-time default.

```sh
node scripts/fg_pull_candidate.mjs capture \
  --input /private/candidate-input.json --token-file /private/read-token \
  --output-dir /private/pr-7-candidate
```

The receipt reports the new directory, state, manifest SHA-256, bundle path (or
null), and acquisition request/payload counts, not private PR prose or tokens.
Retain that manifest SHA-256 independently. Optional `--ca-file PRIVATE_PEM`
adds an explicit trust root without disabling hostname/certificate checks.
`--max-review-pages` (1–8) and `--max-wire-bytes` (up to 64 MiB) narrow acquisition
bounds. All commands accept `--timeout-ms` (1–300000, default 30000), sharing one
remaining-time budget across local input, acquisition, validation and persistence.
Filesystem operations and bounded parsing remain non-preemptible as described
above; a completed synced write is not erased by a racing signal.

Inspect the saved bundle's complete native report offline:

```sh
node scripts/fg_pull_candidate.mjs inspect --package /private/pr-7-candidate \
  --sha256 RETAINED_MANIFEST_SHA256
```

This emits the retained PR, all review pages, preparation, and inspection,
including original hexadecimal path/hunk bytes. JSON escaping keeps control and
bidirectional formatting characters inert in the envelope. This is private
untrusted repository text, not a sanitized public report. A complete native
inspection report does not mean the client independently recomputed the diff,
proved Git closure/ancestry, checked all supplied commit metadata against the
reported commit body, or granted permission to merge.

To draft an approval or change request, supply a private choice file such as:

```json
{
  "action": "approve",
  "principal_id": "00000000000000000000000000000001",
  "candidate_commit": "EXACT_RAW_OID_FROM_INSPECTION",
  "reason": "The exact saved candidate was inspected."
}
```

The illustrative OID must be replaced with the raw, lowercase 40- or 64-character
native digest. `request-changes` has the same shape. A merge choice instead has
`action:"merge"`, the submitting `principal_id`, that exact `candidate_commit`,
explicit `method:"merge-commit"` or `"squash"`, and `required_reviewers` containing
a nonempty distinct set of principal IDs other than the submitter. No reason or
reviewer-stream override is accepted on a merge. The selected method must equal
the method that produced the inspected candidate.

```sh
node scripts/fg_pull_candidate.mjs draft --package /private/pr-7-candidate \
  --sha256 RETAINED_MANIFEST_SHA256 --choices /private/review-choices.json \
  --output /private/review-input.json
node scripts/remote_pull.mjs prepare --input /private/review-input.json \
  --token-file /private/review-token --request-dir /private/new-review-request \
  --bundle /private/pr-7-candidate/candidate.bundle
```

The draft contains the existing sender's input schema, not a publication key or
credential. Scope, source/target refs and tips, policy epoch, PR version, merge
base and candidate are taken only from the revalidated saved inspection. For a
review, the complete captured reviewer stream selects the exact predecessor,
including stale prior votes; zero is used only after complete reviewer pagination
establishes absence. Merge requirements remain explicit even when displayed
reviews request changes: only native admission can decide their acceptability.
Drafting never updates a stale PR, reuses an approval as authority, refreshes
coordinates, chooses another merge strategy, or sends anything. Withdrawal stays
in `fg_pull_review.mjs` so it retains the original vote's possibly stale subject.

Review and merge credentials are independent of capture credentials. Preparation
checks the supplied original token and candidate bytes but does not send. The
existing `remote_pull.mjs send` still requires its exact saved key, candidate and,
for a merge, method confirmations. See `REMOTE_REVIEWED_MERGES.md` for that
publication/recovery lifecycle. Those commands and native authorization rules are
unchanged by this feature.

Draft output is bounded to 512 KiB and written/synced to a private staging file
before create-only final-name publication. Existing files are never replaced.
A failure may retain a `.pending` file; no automatic repair or takeover is
attempted. A broken stdout after capture or draft reports the completed identity
on stderr when possible, while the synced output remains available. SIGTERM and
SIGINT cancel the owned request; SIGKILL can leave an incomplete slot, which is
not a completed package. There are no network retries or automatic publications.

Exit codes: **0** for completed clean capture, offline inspection or draft;
**1** for a captured conflict/up-to-date noncandidate; **2** for local input,
file, hash or drafting refusal; **3** for acquisition/save/output failure after
work began. A saved noncandidate can be inspected, but never drafted as a clean
review or merge. Neither a successful draft nor a failed invocation says that a
repository mutation occurred: this CLI has no publication operation.

Run the complete package/CLI/handoff lane:

```sh
bash scripts/verify_pull_candidate_packages.sh
```

The lane uses unchanged complete acquisition, MIME/inspection and sender modules,
real private files, HTTP/TLS sockets and child processes. The Git oracle generates
real bundles in both hash formats. Sender tests join saved artifacts to exact
publication bytes, original-key confirmation and rotated-credential recovery
through explicit contract peers; they are not native policy or Rust-node tests.
The preexisting acquisition-only suite is separate and is not included in this
lane's count. This feature does not remove the inherited safe-integer profile or
the native forms' missing atomic expected-incarnation precondition.
