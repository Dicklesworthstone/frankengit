# Inspect the actual candidate before publication

`fg workspace inspect` and `fg merge inspect` read an untrusted candidate bundle,
verify its native objects and complete dependency graph, and compare the target
parent's tree with the **actual candidate tree**. This is different from
`fg pr diff`, which compares the PR's recorded source-side changes. In particular,
a manually resolved merge can contain changes absent from either parent.

The inspector does not stage uploaded objects, seal a transaction, move refs,
append forge events or publish an outbox obligation. It does not record a review
decision, approve the candidate or enforce reviewer policy. The JSON is an
unsigned derived report, not a capability or an authorization receipt.

## Commands

```bash
fg workspace inspect "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./candidate.bundle --trusted-local \
  --expected-base "$PARENT_COMMIT" --expected-commit "$CANDIDATE_COMMIT"

fg merge inspect "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main ./merge.bundle --trusted-local \
  --expected-target "$TARGET_BEFORE" --expected-commit "$MERGE_COMMIT" \
  --source-ref refs/heads/topic --expected-source "$SOURCE_COMMIT" \
  --merge-base "$COMMON_BASE"
```

The expected identities are mandatory and do not come from an implicit latest
lookup or an instruction embedded in the artifact. SHA-1/SHA-256 is inferred
from those identities. An optional `--object-format` must agree. Bundle v2
and the supported v3 object-format envelope reuse the existing publication
parser; the workspace profile still requires exactly one prerequisite, while
the merge profile allows up to 64 unique prerequisite commits.

Both visible branch tips must still equal their explicit expectations. An
optional `--expected-head` pins the authority snapshot. A stale artifact is
refused rather than silently rebased. There is no historical-policy bypass.
The trusted local caller authorizes access; the node also applies supplied ref
visibility and canonical hidden-ref policy. This is not remote authentication.

`--refs-hex` decodes the positional target name; `--source-ref-hex` replaces the
merge command's `--source-ref`. `--path`/`--path-hex`, `--context-lines`,
`--max-changes`, `--max-blob-bytes`, `--max-output-bytes` and `--max-diff-work`
have the existing `fg diff` semantics. A path scope narrows the displayed diff,
not object validation or authorization. The comparison cannot be changed to
merge-base mode: that could conceal changes in the actual candidate result.

## Validation and isolation

Before processing uploaded delta dependencies, the inspector walks the native
closure of each authority-selected visible parent. That exact union is the
allow-list for original-object reads. Merely belonging to the repository's
larger cumulative admitted set is insufficient. Thus a thin REF delta cannot
copy a blob from an unrelated or hidden ref merely by naming its object ID.

The pack checksum, inflater, typed delta resolver and native-object parser are
the existing first-party implementations. Full entries, OFS deltas, forward
pack-local REF deltas and permitted external thin bases are supported. The
bounded identity-discovery pass does not trust an uploaded offset/index table.
Every reconstructed object is parsed and hashed. Duplicate uploaded native IDs
refuse. Missing bases, budget exhaustion and cancellation do not yield partial
successful inspections.

The shared admission object verifier then validates the complete candidate
closure. A workspace candidate must have exactly the expected parent. A merge
candidate must have target-before first and source second, and its declared
base must be an ancestor of both. Required tree/blob/commit kinds are checked;
gitlinks remain external-repository data. Ambiguous tree or parent headers are
not interpreted as a convenient graph. Validation proves the supplied graph,
not that a particular merge algorithm, author or tool produced it.

Extra pack objects must be transitively necessary delta bases of reachable
candidate objects; otherwise inspection refuses. `transport_only_objects`
counts those reconstruction dependencies separately from Git-graph content.
They do not become files, refs or accepted repository history.

## Output and application

The outer `candidate_review` report identifies the input as `untrusted_bundle`
and includes SHA-256 of the complete input, the native candidate, exact ordered
parents, prerequisites, merge-base coordinates when applicable, byte/object
counts, and the complete candidate commit body as hex and optional UTF-8 text.
This exposes commit messages, signatures and author headers without treating
them as trusted instructions. Control characters are escaped.

The nested `review` is the existing byte-exact `path-myers-v1` representation:
its `requested_after` is the candidate, not the current target ref. Both
reference-name fields identify the branch being proposed for update; they do
not assert that its canonical tip has already moved. Its authority head binds
the original parents and disclosure policy, not publication of the candidate.
The full outer report must be retained to preserve that distinction.

Only after independent review should the operator use the separate existing
`workspace apply` or `merge apply` command with the same exact candidate and
reviewed coordinates. Inspection does not auto-apply, sign an approval, waive
publication checks or freeze repository state. If the artifact changes, its
bundle digest changes; if its native content changes, its candidate ID changes.

Exit 0 means a complete inspection for the declared diff scope, after explicit
node shutdown. Exit 2 means no successful report was returned. A write or flush
failure may leave an incomplete JSON prefix; consumers must require a complete
document and a successful exit. No error is evidence of an accepted change.

## Fixed bounds and verification

Input is limited to 128 MiB, 10,000 pack entries, 64 MiB expanded/cached pack
content and 2 MiB candidate commit content. Original reads consume a shared
128 MiB budget. The native graph verifier admits at most 100,000 objects,
400,000 edges and 128 MiB of verified content per traversal, with object reads
also capped by node policy and 32 MiB. The existing review ceilings remain in
force, including 512 changes, 64 text comparisons and 1 MiB compared blobs.
These bounds can reject a valid larger repository; no silent skipping occurs.
JSON is capped at 64 MiB. Cancellation checkpoints surround reads, bounded
resolution and comparison; individual bounded synchronous hashes/diffs are not
represented as preemptible at every instruction.

The implementation adds six native-verifier tests, four embedded-node tests
and three CLI parser tests. Cases include both hash formats, actual candidate
content, no staging/publication, forward/OFS/thin resolution, extra-object
refusal, an unrelated selected ref used as an impermissible thin base, invalid
parents, checksum failure, hidden refs and exhausted diff budgets.

```bash
python3 scripts/e2e/candidate_review_smoke.py --self-test
python3 scripts/e2e/candidate_review_smoke.py --fg /absolute/path/to/fg
```

The fresh-process campaign independently constructs candidate packs and checks
input hashes, native identities, exact commit bytes, parent order, full graph
counts, transport dependencies and reconstruction from reported hunks. It
fingerprints the supplied executable. Its self-test checks fixtures/the checker
only and rejected 32 corrupted reports in the editing environment. Eight
independent pack fixtures (four encodings in both formats) also passed Git
2.47.3's strict index-pack and exact cat-file checks in isolated temporary test
repositories. These are fixture checks, not executions of FrankenGit.

Rust compilation, native tests, the complete binary campaign, rustfmt and
Clippy were not run here: Cargo, rustc and a built `fg` are absent. Lexical and
delimiter checks are not Rust compilation. No bead is closed by this source
integration and no durable review-decision or broader forge completion is claimed.
