# Native linear rebase over HTTP

## Profile and ownership

The source-enabled, credential-file HTTP profile exposes:

```text
POST {repository-route}/api/v1/source/rebase/prepare
POST {repository-route}/api/v1/source/rebase/apply
```

Both use the existing node engine. Preparation is a bounded read; applying the
reviewed candidate is a separate ordinary atomic receive transaction. No host
checkout, Git subprocess, mutable sequencer, external driver, or alternate
publication authority is introduced. This is the operator-managed repository
profile, not hosted IAM, per-path agent authorization, or general REST/OpenAPI
conformance.

Preparation needs the token's explicit `read` grant and rejects
`Idempotency-Key`. Apply needs `receive`, the source and Git-write service
switches, and a bounded `Idempotency-Key`. Receive permission does not imply
read permission. Authentication, repository-incarnation binding and principal
quota precede body intake. Existing canonical hidden-ref policy still applies.

## Prepare a complete series

Use `application/x-www-form-urlencoded`, at most 256 KiB, with explicit fields:

| Field | Meaning |
|---|---|
| `object_format` | `sha1` or `sha256`, matching the repository |
| `profile` | Exactly `linear-v1` |
| `source_ref` / `source_ref_hex` | Exactly one encoding of the branch being rewritten |
| `onto_ref` / `onto_ref_hex` | Exactly one encoding of a distinct destination-base branch |
| `expected_source` | Exact old source tip |
| `upstream` | Exclusive end of the original suffix |
| `expected_onto` | Exact destination-base tip |
| `empty` | Explicit `stop`, `drop`, or `keep` for changes that become empty |
| `committer`, `timestamp` | Explicit new committer and positive Unix timestamp |
| `expected_head` | Optional algorithm-qualified authority snapshot token |

The entire suffix `(upstream, expected_source]` must be single-parent history.
It is processed oldest first. An unrelated upstream or a merge commit in that
suffix refuses; history is not flattened and an arbitrary admitted object is
not a valid source selector. Source and onto refs, visibility, and object
history are selected at one authenticated head.

The original authors (including their times/timezones), messages, and supported
encoding metadata survive rewriting. Original signatures cannot attest to new
bytes and are not copied. Unknown original extension headers refuse in the
native adapter rather than silently disappearing. The supplied committer is
metadata, not an authenticated author claim.

The native limits apply to the **whole series**, not freshly to each step.
Every native preparation limit may be narrowed by the corresponding form
field: `max_commits`, `max_edges`, `max_tree_entries`, `max_depth`,
`max_path_bytes`, `max_content_merges`, `max_text_bytes`, `max_conflicts`,
`max_objects`, and `max_output_bytes`. The HTTP commit-discovery ceiling is
256, matching the bounded publication profile rather than exposing a larger
preparation-only series. Other ceilings remain `PreparationLimits::default()`.
Zero, over-ceiling, unknown, duplicate, and operation-inapplicable fields refuse.

### Replies

A clean result is `multipart/mixed`: JSON `metadata`, then an
`application/x-git-bundle` attachment. Metadata records the snapshot, exact
coordinates, empty policy, original-to-rewritten step mapping, native tree and
candidate IDs, generated/packed/borrowed object counts, and bundle byte length
and SHA-256 digest. Step kinds distinguish replayed, originally-empty preserved,
and newly-empty dropped commits.

The bundle advertises the **source branch** and has **onto as its only external
prerequisite**. Borrowed source objects absent from onto history are included.
No source history is silently assumed present at the receiver.

A stop returns HTTP 409 JSON, `state=conflicted` or `state=became_empty`, the
original commit that stopped, and provisional completed-step explanations.
`series_complete=false`, `candidate_commit=null`, and `bundle=null` are explicit.
Provisional rewritten IDs were not staged or published. A complete suffix is
never simulated by returning only its successful prefix.

Originally empty commits survive all three empty policies. A fully dropped or
zero-length suffix can yield candidate=onto and a real zero-object Git pack;
this remains a valid explicit branch-move candidate, not a fake missing bundle.
The shared artifact writer bounds metadata, checks response length and MIME
boundary collisions, and sends the bundle without a second bundle-sized copy.

## Publish only an independently reviewed candidate

Apply uses the existing bounded `multipart/form-data` source upload: one
`command` form part and one nonempty `bundle` part. A zero-object pack still
has bytes and is not an empty bundle. The form fields are:

```text
object_format=sha1|sha256
profile=linear-v1
ref=<source-branch>              # or ref_hex, never both
expected_source=<original-source-tip>
onto=<artifact-prerequisite>
candidate_commit=<independently-reviewed-final-tip>
```

The principal comes from the credential, not the form. The native publisher
binds the branch, prerequisite, object format, and candidate against those
independent expectations; quarantines and verifies the pack and closure; and
walks the actual candidate bytes to prove a bounded single-parent chain to onto.
It then publishes only the final source ref, with **expected_source as its
exact-old lease**. The onto prerequisite is not substituted for that lease.
No force bit, review approval, PR metadata rewrite or protection bypass is added.
Current protection/policy can therefore refuse a rebase even after preparation.

Successful publication returns `rebase_publication`, `tx_id`, exact coordinates,
terminal outcome, decision sequence and decision-record identity. Terminal
retries bind the original semantic request and recover before mutable source
checks. They confirm that ref transaction, not a new attestation to repackaged
transport bytes. Lost responses use the same principal/key and the existing
`/api/v1/outcomes` endpoint. Cancellation or store failure after admission may
return `outcome_unknown`; it never proves that the branch did not move.

## Validation status

`source_rebase_http` contains real-listener tests for two-commit preparation,
fixed/chunked identity, metadata preservation, explicit publication, restart,
terminal recovery, source/onto separation, read/write scopes, token rotation,
conflict and resource refusal, and stop/drop/keep including a zero-object pack.
Parser/output tests cover raw refs, invalid selections, wrong hash domains,
provisional receipts, empty policies, and error classification.

These tests were authored but not executed in the editing environment, which
had no cargo, rustc, or rustfmt. Source/interface and GitHub diff review are not
compilation, conformance, Clippy, or a repository gate pass. No interactive
reordering/squashing, merge-preserving rebase, partial publication, or generic
multi-operation sequencer is claimed.
