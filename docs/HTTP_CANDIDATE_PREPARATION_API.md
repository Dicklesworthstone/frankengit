# Prepare a reviewable native PR candidate over HTTP

`POST {REPO_URL}/api/v1/pulls/{number}/prepare` constructs a native two-parent
merge candidate for an existing open same-repository PR. It completes the
remote preparation -> candidate review -> reviewed merge workflow without
requiring the preparation client to open local node storage.

This is a read-only, body-bearing operation. It does not stage objects, create
an idempotency binding or seal, cast a vote, change a ref, update PR metadata,
or publish an outbox obligation. A returned bundle is an inspection artifact,
not evidence that a merge is accepted. The existing native constructor and
independent object validator own the candidate; the HTTP adapter introduces no
Git engine, PR database, candidate store, or alternate publication mechanism.

This document describes committed interfaces, not a passing Rust build or a
completed compatibility/security campaign. The service remains the bounded
loopback operator-managed deployment, not full hosted IAM or TLS termination.

## Service and permissions

Enable the existing PR service:

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants --allow-pulls
```

The preparation credential must contain BOTH `read` (Git fetch) and `pulls-read`
on the SAME token. The artifact discloses source code and PR coordinates, so
neither permission is sufficient alone. Separate tokens for one principal do
not union their grants. Review and merge write permissions imply neither read.
The existing private credential-file, tenant/repository/incarnation binding,
reload, rotation, revocation and current hidden-ref rules apply.

No new write grant is introduced. A token with `read,pulls-read` can prepare
but cannot vote or publish a merge. Static Git-only credentials and older
serving entry points still leave these PR routes disabled. `--allow-receive`
is not required for this read. `--allow-outcomes` is not required either:
preparation creates no transaction to recover.

Use the repository URL printed by `smart_http_listening` as `REPO_URL`.
Do not send an `Idempotency-Key`: the endpoint rejects one rather than pretending
it records a retryable mutation. Repeating a preparation query reconstructs a
read artifact. It cannot reexecute an earlier review or merge.

## Exact preparation input

The request body is `application/x-www-form-urlencoded`, optionally declaring
`charset=utf-8`. Fixed-length and chunked HTTP framing are supported. All eleven
fields are required; there are no ambient author, timestamp, message, tip or
version defaults:

| Field | Meaning |
|---|---|
| `object_format` | `sha1` or `sha256`, matching the repository. |
| `pull_request_version` | Exact positive PR aggregate version. |
| `policy_epoch` | Exact current policy epoch to bind the review subject. |
| `source_ref`, `target_ref` | Distinct full `refs/heads/...` branch names. |
| `source_tip`, `target_tip` | Exact nonzero lowercase native commit IDs. |
| `author`, `committer` | Explicit Git identities in `Name <address>` form. |
| `timestamp` | Explicit positive Git timestamp, emitted with UTC offset `+0000`. |
| `message` | Exact nonempty UTF-8 commit-message bytes, including any desired final newline. |

Obtain the PR version and coordinates from the PR read API. The existing
`GET .../pulls/{number}/reviews` response supplies the current `policy_epoch`
and PR version even before any votes exist; that read requires its independent
`reviews-read` credential. A cooperating reviewer or the operator can supply
this coordinate. Do not assume the epoch is always 1. The preparation request
is checked again, so separately obtained stale coordinates are not silently
refreshed into another subject.

Git author/committer strings are content, NOT authenticated principals or
permissions. Changing them, the timestamp, or the message can change the
candidate commit even when the merged tree is unchanged. Reviewers must approve
the exact resulting candidate ID, not an earlier artifact with different metadata.

Example, keeping the bearer header in a private file:

```sh
curl --fail-with-body --header @/secure/preparation.headers \
  --data-urlencode "object_format=$OBJECT_FORMAT" \
  --data-urlencode "pull_request_version=$PR_VERSION" \
  --data-urlencode "policy_epoch=$POLICY_EPOCH" \
  --data-urlencode 'source_ref=refs/heads/topic' \
  --data-urlencode 'target_ref=refs/heads/main' \
  --data-urlencode "source_tip=$SOURCE_TIP" \
  --data-urlencode "target_tip=$TARGET_TIP" \
  --data-urlencode 'author=Developer <developer@example.invalid>' \
  --data-urlencode 'committer=Developer <developer@example.invalid>' \
  --data-urlencode 'timestamp=1700000000' \
  --data-urlencode 'message=Reviewed merge candidate' \
  --dump-header candidate.headers --output candidate.body \
  "$REPO_URL/api/v1/pulls/41/prepare"
```

Unknown/duplicate fields, query parameters, NUL, invalid UTF-8, invalid percent
escapes, wrong object formats, inapplicable media types and malformed HTTP bodies
are refused. Authentication, both grants, declared size limits, and intake quota
precede `100 Continue` and body reads. The complete body must finish before
native construction. There is no path that treats the form as a mutation.

## Clean, conflicted and already-integrated results

A clean result is HTTP 200 with `Content-Type: multipart/mixed`. Its first part
is `metadata` (`application/json`), and its second is `bundle`
(`application/x-git-bundle`). The JSON has type `merge_preparation`, schema
version 1, exact `source_head`, `snapshot_token`, object format, complete review
subject, candidate base/commit/tree, and new-object count. Its bundle descriptor
contains exact byte length and a SHA-256 transport checksum.

The bundle is ordinary native Git bundle framing: SHA-1 uses v2; SHA-256 uses v3
with an explicit object-format declaration. It names both parent prerequisites
and the target ref's candidate commit. New objects exist only in the response,
not in the node's object fabric. A fast-forward-capable case still constructs
an explicit two-parent candidate under the existing PathMergeV1 profile.

A conflict returns HTTP 409 JSON with `state: "conflicted"`, `candidate: null`,
`bundle: null`, and bounded conflict diagnostics. Each path is `path_hex` over
its exact Git bytes, including non-UTF-8 names, plus the native conflict kind
and optional base/ours/theirs OIDs and modes. No guessed resolution or
conflict-marker tree is published or returned as a candidate.

An already integrated source returns HTTP 200 JSON with
`state: "already_up_to_date"`, no candidate and no bundle. Neither this result
nor a conflict creates a terminal repository decision. All preparation result
states explicitly carry:

```json
{
  "read_only": true,
  "objects_staged": false,
  "transaction_created": false,
  "published": false,
  "merge_authorized": false
}
```

A stale/closed/merged PR, changed tip, or changed policy coordinate returns
409 `preparation_subject_moved`. Missing or undisclosed PRs/refs return 404.
No common ancestor and multiple best bases are explicit 409 preparation errors,
not arbitrary base choices. Syntax errors are 400, missing credentials 401,
permission/disabled-service errors 403, resource limits 413, unsupported media
415, throttling 429, and infrastructure/evidence failures 503. Error bodies use
the existing `pull_request_error` family. They do not invent a canonical refusal.

The exact-subject node API is `OneNode::prepare_pull_request_bundle_in`. It
selects authenticated current PR/refs/policy, then requires the existing native
constructor to return that SAME authority head before releasing an artifact.
This conservative check can refuse even a harmless concurrent publication.
Retained display tokens do not authorize constructing against an old policy.
New preparation attempts still apply current credentials and hidden-ref policy.
No retention lease or server-side candidate cache is created.

Identical metadata and source coordinates produce the same native candidate.
A restarted node can reconstruct it. An unrelated intervening publication may
change the response's source-head metadata without changing the bundle bytes;
clients must not confuse a transport checksum with a publication identity.

## Extract the two response parts

The following external-client example uses Python's standard MIME and JSON
parsers. It is not part of the production Git engine. It never uses a
server-provided filename or treats response text as an instruction:

```python
from email import policy
from email.parser import BytesParser
from pathlib import Path
import hashlib
import json

# curl may have recorded an interim 100 Continue before the final head.
blocks = [b for b in Path("candidate.headers").read_bytes().split(b"\r\n\r\n") if b.strip()]
status, headers = blocks[-1].split(b"\r\n", 1)
if status.split()[1] != b"200":
    raise ValueError("inspect the preparation error JSON; no candidate was accepted")
body_path = Path("candidate.body")
if body_path.stat().st_size > 66 * 1024 * 1024 + 16 * 1024:
    raise ValueError("preparation response exceeds the supported envelope")
message = BytesParser(policy=policy.default).parsebytes(headers + b"\r\n\r\n" + body_path.read_bytes())
if message.get_content_type() != "multipart/mixed" or message.defects:
    raise ValueError("inspect JSON for a non-clean result; no binary candidate")
parts = list(message.iter_parts())
if len(parts) != 2 or any(p.defects or p.is_multipart() for p in parts):
    raise ValueError("invalid candidate response parts")
if [p.get_param("name", header="content-disposition") for p in parts] != ["metadata", "bundle"]:
    raise ValueError("unexpected part names")
if [p.get_content_type() for p in parts] != ["application/json", "application/x-git-bundle"]:
    raise ValueError("unexpected part types")
metadata = json.loads(parts[0].get_payload(decode=True).decode("utf-8"))
bundle = parts[1].get_payload(decode=True)
if metadata.get("type") != "merge_preparation" or metadata.get("state") != "clean":
    raise ValueError("not a clean preparation artifact")
if len(bundle) != metadata["bundle"]["bytes"] or hashlib.sha256(bundle).hexdigest() != metadata["bundle"]["sha256"]:
    raise ValueError("candidate transport checksum mismatch")
# Fixed, client-owned destinations; exclusive creation avoids accidental overwrite.
with open("candidate.bundle", "xb") as output:
    output.write(bundle)
with open("candidate.json", "x", encoding="utf-8") as output:
    json.dump(metadata, output, ensure_ascii=False, indent=2)
```

The checksum detects transport corruption; it is not an authority receipt or
approval. Review and merge still validate the actual native candidate bytes.
To use the existing review/merge endpoints, map `candidate.commit` to the
`candidate_commit` form field and `candidate.merge_base` to `merge_base`, and
preserve the returned subject's PR version, policy epoch, refs and tips.
Supply the reviewer's own expected stream version/reason or the merger's
explicit required-reviewer set. See [HTTP_REVIEW_MERGE_API.md](HTTP_REVIEW_MERGE_API.md).

A preparation error can be retried as a read. A lost REVIEW or MERGE response is
different: keep its original semantic command and idempotency key and use the
independent outcome API. Preparing a replacement candidate does not resolve an
ambiguous mutation or make a changed candidate an identical retry.

## Resource profile and verification

Forms are capped at 256 KiB encoded with the existing 64 KiB decoded-value
limit; native metadata validation retains its smaller identity bounds. The
planner keeps its existing graph/tree/depth/content/work limits and 32 MiB
new-object output ceiling. Response metadata is capped at 2 MiB, bundles at
64 MiB, and complete responses at their sum plus 16 KiB, all further narrowed
by the configured HTTP response ceiling. Construction completes before HTTP
success; the binary output is written without another bundle-sized copy.
Multipart delimiters are bounded, deterministic and checked for collision with
both parts, with cancellation checkpoints during scanning.

This does not implement rename heuristics, external attribute drivers,
cross-repository PRs, remote conflict resolution, disk-spooled candidates, or
indefinitely retained preparation sessions. It reuses the existing deterministic
PathMergeV1 construction and typed unsupported/error behavior.

Focused checks:

```sh
cargo test -p fgit-node --lib smart_http::server::pulls
cargo test -p fgit-node --test candidate_preparation_http \
  --test review_merge_http --test pull_request_http
```

The tests exercise real TCP, native import, downloaded artifacts, reviewer
admission, coupled merge, restart, unchanged staging/publication state during
preparation, conflicting binary paths, both hash formats, scope separation,
stale subjects, cancellation and resource limits. Their presence is not a claim
of passing execution; record the actual toolchain, revision and result.
