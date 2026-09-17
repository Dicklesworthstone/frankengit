# Inspect the actual PR candidate over HTTP

`POST {REPO_URL}/api/v1/pulls/{number}/inspect` returns a complete bounded
comparison of the target-before tree against the ACTUAL uploaded merge candidate.
It does not substitute the PR source branch's diff for the candidate's result.
This is especially important for resolved conflicts and custom candidate content.
The complete native commit body is also returned so metadata-only changes,
authorship, messages and ordered parents are inspectable.

The handler calls `OneNode::inspect_pull_request_bundle_in`, which composes the
existing exact-PR selector and native `inspect_merge_bundle_in`. It neither
stages objects nor creates a transaction, vote, ref update, PR event or outbox
obligation. No alternate diff/Git engine or approval database is introduced.

These are implemented interfaces, not a passing Rust build or live acceptance
claim. The existing loopback, operator-managed deployment remains in effect.

## Permissions and request

Use the existing `fg serve-http --allow-pulls` service with reloadable credentials.
The SAME token must grant both `read` and `pulls-read`. The result discloses code
as well as PR coordinates. Separate tokens for the same principal do not union
their permissions. Review/merge/write grants do not imply either read. Current
canonical hidden-ref policy still applies to both source and target.

Inspection does not require `reviews-read`, because it reads the candidate's
content, not other reviewers' votes. It grants no permission to vote or merge.
Existing static tokens and PR-disabled server entry points remain disabled.
Rotation and revocation are checked at each authentication, as for preparation.

Do not send an `Idempotency-Key`: inspection creates no mutation to recover,
and rejects that header. The complete candidate bundle is required on every
inspection, including when a similar review or merge is already terminal.
Unlike terminal mutation retries, inspection cannot omit the bytes being read.

Send multipart/form-data with exactly one `command` part of type
`application/x-www-form-urlencoded` and one nonempty `bundle` part of type
`application/x-git-bundle` (or application/octet-stream). Part order does not
matter. The command has exactly these nine required fields:

```text
object_format, pull_request_version, policy_epoch,
source_ref, target_ref, source_tip, target_tip,
merge_base, candidate_commit
```

Coordinates are independently chosen by the client: nonzero lowercase native
OIDs in the declared sha1/sha256 domain, distinct full branch names, and exact
positive PR version and policy epoch. The candidate must not alias a parent.
No principal, review decision, path filter, whitespace option, generated proof,
implicit tip refresh, or expected-head override is accepted.

With those fields saved as URL-encoded bytes in `inspect.form`:

```sh
curl --fail-with-body --header @/secure/inspection.headers \
  --form 'command=<inspect.form;type=application/x-www-form-urlencoded' \
  --form 'bundle=@candidate.bundle;type=application/x-git-bundle' \
  --output inspection.json \
  "$REPO_URL/api/v1/pulls/41/inspect"
```

`/prepare` and `/resolve` supply reviewable candidate artifacts, but the same
inspector also checks independently constructed candidates under the existing
native two-parent profile. It validates native identities, prerequisites,
ordered parents, common-base ancestry, candidate closure and pack coverage.
Original objects available to uploaded thin deltas are restricted to the
selected visible parent histories, not the repository's entire admitted set.

## One exact basis, no silently partial report

The node first selects the current open PR, policy and refs, then requires native
inspection to use that same authenticated authority head. A different head during
selection can refuse even a harmless concurrent publication; it never mixes PR
metadata from one head with another head's objects. A successful report carries
its exact `source_head` and `snapshot_token`. Those are evidence coordinates,
not a retained-inspection session or a credential. This endpoint always validates
the current PR subject rather than accepting an old display token.

HTTP 200 returns JSON with `type: "candidate_inspection"`. It includes:

- Repository/incarnation/hash domain, exact subject, merge base, candidate ID,
  ordered parents, prerequisites, and bundle SHA-256/byte/object measurements.
- `candidate_commit_body_hex`: the complete native commit body, without Git's
  outer `commit <length>\0` object header. Hash it with that native object framing
  to independently confirm the candidate ID.
- `comparison`: direct before/after commits and trees, and every changed entry
  in raw-path byte order. Directory records are entries, not regular-file counts.

The subject's authoritative lowercase `source_ref_hex` and `target_ref_hex`
preserve exact native bytes. `source_ref` and `target_ref` retain UTF-8 text or
are null when the corresponding bytes are not UTF-8.

Each entry has `path_hex`, change kind, and before/after OID plus numeric Git
mode (or null for an absent side). Text entries include native algorithm label,
addition/deletion counts, and hunks with `before_hex`/`after_hex`. Hunk coordinates
are zero-based line intervals and half-open byte intervals in the original
blobs. CRLF, missing final LF and non-UTF-8 bytes are preserved exactly.
Context is fixed to three lines. Paths are not filtered and whitespace is not
normalized. No rename heuristics, attributes, external drivers or textconv run.

Content kinds are explicit: `text`, `binary`, `object_only`, or `identical`.
Binary entries include lengths and object identities, NOT their body bytes or
fabricated empty text hunks. Object-only entries do not traverse submodules.
An unchanged tree can legitimately have no entries while its candidate commit
metadata still differs. The raw bundle remains the artifact for binary review.

The report says `all_changed_paths: true` only after the complete bounded native
comparison succeeds. It also explicitly says `binary_bodies_included: false`,
`read_only: true`, `objects_staged: false`, `transaction_created: false`,
`published: false`, and `merge_authorized: false`. These flags do not mean that a
human or independent verifier has approved anything. A report is derived read
data, not an evidence signature, policy exception, vote or merge capability.

Example decoding without treating a repository path as a local filename:

```python
import json
from pathlib import Path

report = json.loads(Path("inspection.json").read_bytes())
assert report["type"] == "candidate_inspection"
assert report["all_changed_paths"] and not report["merge_authorized"]
commit_body = bytes.fromhex(report["candidate_commit_body_hex"])
for entry in report["comparison"]["entries"]:
    raw_git_path = bytes.fromhex(entry["path_hex"])
    print(repr(raw_git_path), entry["kind"], entry["content"]["type"])
    for hunk in entry["content"].get("hunks", []):
        before = bytes.fromhex(hunk["before_hex"])
        after = bytes.fromhex(hunk["after_hex"])
        assert len(before) == hunk["old"]["byte_end"] - hunk["old"]["byte_start"]
        assert len(after) == hunk["new"]["byte_end"] - hunk["new"]["byte_start"]
        print(repr(before), "->", repr(after))
```

After inspection, submit a separate exact-candidate review with an authenticated
reviewer and its own original retry key. Merge still evaluates current reviews,
branch tips, policy and mandatory protection at its publication CAS. An old
inspection cannot authorize a changed candidate or bypass a withdrawn vote.

## Refusals and bounded work

Absent or undisclosed PRs/refs return 404; stale PR versions, tips, policies or
selection heads return 409 `inspection_subject_moved`. Malformed uploads and
invalid candidates are request errors, not canonical transaction refusals.
Missing/corrupt authoritative evidence remains unavailable, not an empty report.
Error JSON uses the existing `pull_request_error` family, with no invented
terminal outcome. Inspection has no mutation ambiguity to report.

Authentication, both grants, declared-size ceilings and the existing intake quota
precede `100 Continue` and body intake. Fixed-length and chunked framing share the
existing bounded decoder. A full valid HTTP/MIME envelope is required before
native inspection; filenames are ignored, never opened or written.

The shared upload profile caps commands at 256 KiB and bundles at 64 MiB, with
separate framing/part/chunk ceilings, further narrowed by server HTTP limits.
Native inspection retains its pack/object/closure/read budgets. Comparison is
bounded to 512 changed entries, 64 text files, 1 MiB blobs, 4096 hunks, 8 MiB
native report bytes and the existing diff-work limits. Exhaustion is an error,
not successful truncation. The complete JSON is built within 32 MiB and the
server response ceiling before any success byte is emitted. Hex expansion is
charged before allocation and checked for cancellation during encoding.

Ingress remains memory-buffered within those bounds. Its buffer is dropped after
native inspection and before JSON construction. No disk spool, durable report
store, candidate cache, retention lease, or new dependency/runtime is added.

```sh
cargo test -p fgit-node --lib smart_http::server::pulls
cargo test -p fgit-node --test candidate_inspection_http \
  --test candidate_preparation_http --test conflict_resolution_http \
  --test review_merge_http --test pull_request_http
```

The tests exercise actual native candidates, TCP serving and embedded authority,
not a substitute inspector. Record the executing toolchain, revision and results
before claiming build, interoperability, security or deployment acceptance.
