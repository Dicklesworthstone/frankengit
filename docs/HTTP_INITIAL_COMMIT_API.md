# Initial source commits over HTTP

The source gateway can bootstrap an absent branch without importing a local Git
directory or opening node storage on the client. Preparation constructs a native
zero-parent commit and a self-contained bundle; publication is a separate,
explicit expected-absent transaction through the existing native admission path.
These interfaces do not create a repository, change its incarnation, or change
its configured default branch. Initialize/provision the repository separately.

This document describes committed implementation interfaces, not an executed
Rust acceptance result. The service remains loopback-only and operator-managed;
TLS termination, hosted IAM and the complete generated API surface are separate.

## Deployment and independent permissions

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants \
  --allow-source --allow-receive --allow-outcomes
```

The private credential file is provisioned with the existing incarnation-bound
header and token hashes. Use the readiness record's canonical URL as REPO_URL.

| Operation | Credential grant | Required deployment switches |
|---|---|---|
| Prepare an initial candidate | `read` | `--allow-source` |
| Apply the reviewed initial bundle | `receive` | `--allow-source`, `--allow-receive` |
| Recover a lost mutation receipt | `outcomes-read` | `--allow-outcomes` |

Preparation does not gain write authority because its payload contains new
files. A receive-only credential may apply an independently supplied bundle,
but cannot inspect or prepare repository source. Other scopes imply neither
permission. Static-token and older serving entry points leave source routes
disabled. Authentication, endpoint permissions, declared size checks and quotas
precede `100 Continue`; forwarded-user headers do not authenticate.

## Prepare a zero-parent commit

```text
POST {REPO_URL}/api/v1/source/initial/prepare
```

Send multipart/form-data with exactly one `command` part of type
application/x-www-form-urlencoded and one nonempty `patch` part of type
text/x-diff or application/octet-stream. Either part order is accepted. The
shared source upload parser preserves the patch's exact bytes; filenames in
part headers are ignored and never used as host paths. Fixed-length and chunked
HTTP requests must finish completely before native construction begins.

Seven command fields are required:

| Field | Meaning |
|---|---|
| `object_format` | Exactly `sha1` or `sha256`, matching the repository. |
| `ref` | Full absent branch, such as `refs/heads/main`. |
| `expected_absent` | Exactly `true`; absence is explicit, not inferred. |
| `author` | Explicit Git author identity text. |
| `committer` | Explicit Git committer identity text. |
| `timestamp` | Explicit timestamp accepted by native commit metadata validation. |
| `message` | Exact UTF-8 message, including any intended final newline. |

An optional `expected_head` carries an existing algorithm-qualified snapshot
token. Native preparation checks that exact current metadata head before making
an artifact. No expected commit or synthetic all-zero parent is accepted. Author
and committer are Git content, not the authenticated principal.

The patch must contain only regular-file creations. The native engine supports
nested directories, executable files, empty files, quoted non-UTF-8 path bytes,
CRLF and missing final newlines. Modifications, deletions, unsafe structural
paths, duplicate/overlapping paths, incorrect blob-index expectations, symlinks,
gitlinks, binary-patch encodings, and rename/copy records refuse. Every file must
succeed; failure returns no partial candidate. There is no checkout or fuzzy
patch application.

For example, save a deliberately selected creation patch as initial.patch and
encode the complete metadata form without introducing literal form newlines:

```sh
python3 - <<'PY'
from pathlib import Path
from urllib.parse import urlencode
Path('initial.form').write_text(urlencode({
    'object_format': 'sha256',
    'ref': 'refs/heads/main',
    'expected_absent': 'true',
    'author': 'Author <author@example.invalid>',
    'committer': 'Committer <committer@example.invalid>',
    'timestamp': '1',
    'message': 'Initial source\n',
}), encoding='utf-8')
PY
curl --fail-with-body --header @/secure/source-reader.headers \
  --form 'command=<initial.form;type=application/x-www-form-urlencoded' \
  --form 'patch=@initial.patch;type=application/octet-stream' \
  --dump-header initial.headers --output initial.body \
  "$REPO_URL/api/v1/source/initial/prepare"
```

Choose the actual repository format and configured default branch deliberately.
The timestamp and identity values above are explicit reproducible examples,
not ambient credentials or the current time.

Success is multipart/mixed containing JSON `metadata` and binary `bundle`, using
the extraction shape described in [HTTP_CANDIDATE_PREPARATION_API.md](HTTP_CANDIDATE_PREPARATION_API.md).
The metadata type is `initial_source_preparation`. It records the source metadata
head, snapshot token, candidate commit, tree, empty parent/prerequisite lists,
patch checksum, object count, full native commit body as hexadecimal bytes,
transport checksum/length, and byte-exact file paths with blob IDs, modes and
lengths. SHA-1 bundles use v2; SHA-256 bundles declare their native format in v3.
Preparation metadata and publication receipts include authoritative lowercase
`ref_hex` for exact native reference bytes; `ref` retains UTF-8 text or is null
when those bytes are not UTF-8.

Preparation stages no objects, binds no idempotency key, creates no seal, moves
no ref and publishes no forge or outbox work. `publication_authorized: false`
means exactly that. Do not send an Idempotency-Key on this read: it is rejected.
The downloaded bundle can be retained across a node restart and examined by an
independent Git implementation before the explicit publication step.

## Publish at an absent branch

```text
POST {REPO_URL}/api/v1/source/initial/apply
```

Send `command` plus nonempty `bundle` multipart parts. Bundle media is
application/x-git-bundle or application/octet-stream. The command has exactly:

```text
object_format, ref, expected_absent=true, candidate_commit
```

`candidate_commit` is the independently selected nonzero native OID. No force,
parent, expected-old commit, default-branch rewrite or snapshot refresh is
accepted. Unlike preparation, this operation requires a client-selected
Idempotency-Key. Its identity comes from the credential, never from bundle bytes.

With those four encoded fields in publish.form and the extracted initial.bundle:

```sh
curl --fail-with-body --header @/secure/source-writer.headers \
  --header 'Idempotency-Key: initial-source-attempt-1' \
  --form 'command=<publish.form;type=application/x-www-form-urlencoded' \
  --form 'bundle=@initial.bundle;type=application/x-git-bundle' \
  "$REPO_URL/api/v1/source/initial/apply"
```

The native publisher binds the advertised branch and commit to those independent
expectations. New work must contain the complete root-commit closure: one
zero-parent commit plus regular-file trees/blobs, without prerequisites, tags,
symlinks, gitlinks or delta entries in this profile. Native pack integrity,
connectivity, visibility and current policy still apply. No unverified artifact
metadata becomes a publication proof.

Publication uses the existing atomic receive semantic request, seal and exact
predecessor authority CAS. There is no separate HTTP ref database. Concurrent
first commits cannot overwrite each other. An already-present branch refuses
even when its tip equals the candidate under a new key. The prepared head is
not a publication lease: unrelated work may advance authority while an
expected-absent creation remains eligible after canonical revalidation.

A terminal response is `initial_source_publication`: committed outcomes use HTTP
200; canonical refusals use 409. Both include TxId and decision sequence plus
the committed RCR or refusal identity. Key reuse with different semantics is a
pre-decision conflict, not another canonical refusal. No additional Git refs,
forge metadata or default-branch selection are intentionally changed.

An initial commit can also create an independent-history branch beside existing
branches. It does not merge histories. Populating a non-default branch can leave
the configured default branch unborn; this API never silently changes HEAD.

## Retry and recovery

Keep the same original key, reference, candidate identity and bundle when
retrying an ambiguous publication. The native terminal-recovery path precedes
current object/branch checks, so a retry after the branch advanced recovers the
old decision instead of recreating or resetting that branch. Such a receipt
confirms the sealed ref operation, not that retry transport bytes were decoded
again. The apply route still requires its bundle envelope; it is not a
bundleless recovery API.

After a lost receipt or removal of write access, use the separate read-only
outcome API with the original principal and key:

```sh
curl --fail-with-body --request POST \
  --header @/secure/recovery.headers \
  --header 'Idempotency-Key: initial-source-attempt-1' \
  --header 'Content-Length: 0' \
  "$REPO_URL/api/v1/outcomes"
```

This does not upload, reseal or reexecute the candidate. Another principal using
the same textual key does not gain access to the original outcome. Connection
failure, timeout or unavailable evidence is not proof of rollback. See
[HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md) for nonterminal observations.

## Bounds and validation status

The existing native patch profile bounds input to 16 MiB, 1,024 files, 8 MiB per
file, and 32 MiB complete generated object bodies. Initial construction also
bounds the closure to 32,768 native objects. Shared HTTP command/framing limits
apply; bundle transport is capped at 64 MiB. Metadata is capped at 1 MiB, and
the configured server response ceiling can tighten the complete response.
Limits or cancellation return an error rather than a truncated successful
artifact. Input and native candidate storage remain memory-buffered within
these bounds, not disk-spooled.

Invalid initial commands and creation-only patches use typed source_error
responses. An existing preparation destination or stale preparation token is
409; malformed/unsupported input is 400; resource limits are 413; permissions
are 401/403. Native publication infrastructure failures remain conservatively
outcome-unknown. They are not an invitation to change keys and resubmit.

Focused Rust verification:

```sh
cargo test -p fgit-node --lib smart_http::server::source::initial
cargo test -p fgit-node --lib treefs_workspace::initial_commit
cargo test -p fgit-node --test initial_commit_http --test source_change_http \
  --test source_http --test branch_http --test outcome_http
```

The new TCP tests exercise empty repositories, both hash formats, fixed/chunked
requests, no-staging preparation, restart, transition into ordinary source
editing, competing initial publications, equal-tip creation refusal, scoped
recovery after write revocation, malformed bodies and permission denial before
100 Continue. Their presence is not a passing execution claim. Repository
creation, a browser editor, remote workspace sessions, broader initial-bundle
profiles and the separate receive-coordinator migration are not added here.
