# Trusted execution of unpublished candidates

## Implemented boundary

`OneNode::run_trusted_candidate_workflow_in` runs a workflow from an explicitly
selected, unpublished single-parent Git bundle. The complete candidate is
validated without importing it, creating a ref, sealing a repository transaction,
or publishing a forge check. This supplies the missing local pre-publication
execution path: construct a candidate, inspect it, run trusted checks against its
actual tree, and decide independently whether to publish it.

This is a Linux **trusted local-owner** operation. Candidate scripts run with the
host user's privileges, including scripts that differ from the canonical base.
Trusting the base workflow is not sufficient. Input prefixes restrict which
repository files are copied, not which host files or networks scripts can reach.
No HTTP route exposes this operation. It is not hostile-code isolation, a secret
broker, a trigger service, an authoritative check, or a permission to merge.

## Independent identities

The caller supplies a visible branch, its exact expected canonical base commit,
an independently reviewed candidate commit, the actual bundle bytes, explicit
workflow and input paths, a fresh run ID, and a private existing run parent.
An optional authority-head expectation rejects a moved snapshot.

The base branch and its visibility policy are read at one authenticated head.
The bundle must advertise that branch and candidate with exactly the base as
its prerequisite. The candidate must be supplied as a native commit whose only
parent is the base. Base closure, checksum, native objects, typed delta
reconstruction, candidate closure and pack coverage use the existing inspection
and admission validators. Unrelated extra uploaded objects refuse. Only
base-reachable originals can satisfy external delta bases or missing candidate
objects; repository-wide admitted objects do not expand this selection.

`SparseCandidateManifest` is distinct from `SparseManifest`. Its base RCR,
base commit/tree and candidate commit/tree are separate coordinates. It has no
conversion to a canonical source receipt. Internally, native sparse discovery
still owns byte-exact paths, capabilities, content verification and limits.
The existing sparse host adapter binds the candidate identity into its plan,
copies real files and settles the same workspace obligations. Candidate plans
are input-only: edit import refuses, rather than generating an edit log against
an unpublished tree presented as a canonical base. Canonical host-plan bytes
remain unchanged.

## Execution and failure

Both published-source and candidate-source workflows use the same compiler,
whole-graph preflight, job scheduler, step runner, host writer and execution
journal. The workflow file itself is read from the candidate tree. There is no
ambient checkout or substitute Git process. Every job starts with a fresh copy;
steps within a job share that copy. Unsupported runners or inputs refuse before
any process. Validation and materialization consume the run deadline.

A durable local `attempt.json` precedes all jobs. `report.json` is installed
without replacement after execution and workspace cleanup or explicit retention.
Occupied run IDs refuse, including after restart. A missing report or failed
response is not evidence that no command ran. Reconcile effects and descendants
before deciding on another execution; never delete an uncertain slot to bypass
this refusal. Unproved containment retains workspace/capture files and prevents
further job starts. A locally successful report is unsigned and not canonical
check evidence.

The report's `source_head`, `source_rcr`, `source_commit`, `source_tree` and
`source_ref_hex` always identify the canonical **base**. Additive fields are:

- `input_kind`: `canonical` or `unpublished_candidate`;
- `executed_commit` / `executed_tree`: actual immutable workflow inputs;
- `candidate`: null for canonical runs; otherwise exact commit, tree,
  `bundle_sha256` of the input transport, and `admitted: false`.

`workflow_blob` identifies the actual workflow file. These bindings appear in
both the pre-execution marker and final report. `authoritative_check: false`,
`published: false` and `hostile_code_isolated: false` remain explicit.

## Bounds and acceptance

The native bundle inspector retains its existing bounds: at most 128 MiB input,
10,000 pack objects, 64 MiB expanded objects, and 128 MiB cumulative original
object reads. Sparse candidate inputs narrow to 10,000 entries, 16 MiB per file
and 64 MiB retained payload. Replicated job inputs are bounded at 256 MiB and
100,000 entries across the entire run. The existing workflow profile supplies
step, run and captured-output limits. No new external dependency or runtime is
introduced; runner's already-used first-party types dependency is promoted from
test-only to normal use.

`fgit-runner --test candidate_workspace` exercises actual host copying, exact
binary/path data, separate base provenance, metadata-bound host plans, import
refusal, corruption, limits and cancellation cleanup in both hash domains.
`fgit-node --test trusted_candidate_workflow` covers a deliberately failing
canonical-base run versus a successful candidate run, fresh job copies, changed
workflow scripts, complete preflight refusals, unchanged authority/object fabric,
persistent reports, restart/replay refusal and timeout retention.

These are authored regression tests, not recorded pass evidence. Compilation,
execution, formatting, Clippy and full repository gates were unavailable in the
implementation environment. The broader FG-095b check-publication and hostile
runner requirements remain outstanding. Merge/rebase candidates with multiple
parents or an entire rewritten series are outside this single-parent profile.
