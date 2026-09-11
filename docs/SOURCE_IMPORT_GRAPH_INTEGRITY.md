# Typed native graph validation for local source import

The ordinary `fg import` path now validates the complete source-selected native
object graph before placing any of its objects in the node's immutable fabric.
This applies to loose objects, checksum-bound idx-v2/pack-v2 sources, and mixed
sources. It also permits submodule gitlinks whose commits exist only in another
repository, instead of incorrectly demanding those objects locally.

The source-import and receive-quarantine paths share one native edge reader in
`fgit-node::loose_import::graph`. Their source authority and traversal boundaries
remain distinct: an import follows its independently verified local source;
receive follows the requested uploads and an authenticated selected frontier.
The shared reader does not grant access or manufacture a source selection.

## Defects addressed

The former import walk collected bare object IDs, discarded edge kinds, and
staged an object before verifying its descendants. Individually hash-valid
objects could therefore supply a blob as a commit's tree, a tree as a parent,
or a target inconsistent with a tag's declared type. A late missing or invalid
dependency could leave earlier objects placed even though no complete source
had been validated. It also traversed every tree entry as a local dependency,
including gitlinks to external repositories.

`graph::validate` now tracks required kinds at enqueue and verifies every new
constraint, including requirements introduced after an object was already read
as a direct ref target. A root does not escape later parent/tree requirements
merely because its original kind was unconstrained. Duplicate dependencies are
read once, but all edges and their constraints are checked.

Commits require exactly one unambiguous tree reference to a tree and parent
references to commits. Continuations on those structural headers and duplicate
tree headers cannot be discarded in favor of a convenient interpretation.
Directories require trees; regular files and symlinks require blobs. Annotated
tags use the existing typed `parse_annotated_tag` view and require their declared
blob, tree, commit, or tag target. Zero required local references and unknown
tree kinds refuse. Generic import parsing still preserves other unusual bytes.

Gitlink classification uses parsed octal type bits rather than the literal mode
spelling. Both ordinary `160000` and import-compatible padded spellings remain
external-repository references. Their entries consume edge work, but their
objects are neither read nor added to the local closure. No submodule checkout,
network fetch, or alternate object source is introduced.

## Validation before placement

The validator retains the exact original bodies under the existing aggregate
128 MiB source-object ceiling. It returns a private complete validated map;
there is no partially valid proof. Native hashes are recomputed, source parsing
and all required local dependencies must succeed, and canonical ref-state
construction must finish before the first fabric write. Pack decoder caches
are dropped before that placement loop begins.

The staging loop consumes those retained bytes, not a second read of mutable
source files. Thus replacing a source file after its validation cannot silently
replace the bytes that get staged. Filesystem snapshot atomicity and hostile-host
containment are separate properties and are not claimed by this local profile.

Object uniqueness is charged at enqueue, before an oversized pending frontier
can be read. The existing one-million-object ceiling and independent four-million
edge ceiling bound additional graph state and work. Repeated references and
external gitlinks consume edge work. Existing per-object, compressed-file,
pack/index, ref-count and directory bounds remain enforced. These independent
payload and work budgets are not a bound on total process RSS or every backend
allocation.

An invalid or missing source dependency now fails before any object placement.
A storage failure during the subsequent staging loop can still leave verified,
noncanonical objects. Staging is not publication: only the existing sealed
source-import admission and exact-predecessor authority-head CAS can publish
refs. The transaction identity, publication protocol and historical retry
semantics are unchanged.

## Shared receive behavior and explicit limits

Receive quarantine delegates native edge interpretation to this same reader,
while retaining its existing uploaded-object selection, transport-only delta
base responsibility, authenticated frontier-kind checks and shared original
input ledger. It passes its live deadline to the common reader. All earlier
receive tests remain registered; no alternative decoder or object store was
introduced.

The blocking local-source staging API still has no request-deadline parameter.
This change does not claim interruptible import I/O or complete import
cancellation propagation. The shared reader's cancellation test concerns its
explicit deadline, used by receive; it is not evidence about the whole blocking
import operation.

Ref-namespace target rules remain separate from graph integrity. This does not
activate compiled policies, enforce repository-wide mandatory candidate reviews,
or retroactively audit/repair existing canonical history. It adds no production
Git invocation, dependency, lockfile change, database or runtime.

## Tests and current verification

Nine new Rust test functions are registered: five file-backed source/node tests
and four loader/shared-reader tests. They cover both object formats, loose and
packed sources, submodule and nested-tag success, wrong-kind/ambiguous graphs,
missing dependencies without partial staging, contradictory requirements,
inclusive frontier/edge/byte bounds, cancellation of the common reader, native
body substitution, and original durable import with shutdown/reopen/retry. The
27 preexisting local-import tests are preserved byte-for-byte.

```bash
python3 scripts/e2e/source_import_graph_smoke.py --self-test
python3 scripts/e2e/source_import_graph_smoke.py --git-oracle /absolute/path/to/git
python3 scripts/e2e/source_import_graph_smoke.py --fg /absolute/path/to/fg
```

The Python self-test executed and rejected 32 altered pack/index inputs.
The isolated Git 2.47.3 fixture campaign exercised 66 cases across SHA-1/SHA-256
and loose/packed/mixed storage: six strict-valid cases, six padded-gitlink cases,
and 54 malformed or incomplete graph cases. Padded modes deliberately pass
ordinary `fsck --full` with `zeroPaddedFilemode` warnings and fail strict fsck
with that exact diagnostic. FrankenGit's existing import profile preserves those
modes; this is an explicit profile distinction, not a claim of strict-fsck
acceptance. Native object bytes are checked independently from that distinction.

The actual `--fg` campaign is separate. It fingerprints the supplied binary,
imports each source through fresh processes, checks exact canonical refs,
rejects invalid sources without authority movement, and exercises identical
retry and unavailable foreign/unreachable object probes. Its doctor probes do
not replace the Rust tests' direct fabric assertions about no partial staging.

Python compilation/help, Rust lexical/delimiter checks, original-test
preservation, and local/uploaded blob identities were checked. Cargo, rustc,
rustfmt, Clippy and a built `fg` are unavailable in the editing environment.
Rust compilation, all native tests and the actual real-binary campaign were not
run. Git and Python fixture checks do not execute FrankenGit or establish the
repository's revision-bound native gate. No bead is closed on this basis.
