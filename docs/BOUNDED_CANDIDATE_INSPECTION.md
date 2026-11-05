# Bounded candidate inspection

Candidate inspection and trusted candidate workflow inputs prove original-object
access on demand from their independently selected, visible parent commits.
They no longer build or read the parents' entire object closure before unpacking
a merge, squash, fast-forward, or one-parent workspace candidate.

## Original-object access

The authority-selected cumulative object set is a necessary membership check,
but it is not a disclosure capability. That set can include hidden branches,
deleted refs, and history removed by a force-push. Each original object read by
inspection must also be reachable from the exact current parent tips selected
for this request, at the same authenticated repository head.

The request remembers typed native edges learned from verified parent commits
and trees. Reading a reachable commit or tree proves its immediate children.
When a requested identity is not yet known, a bounded breadth-first search
expands reachable commits and trees until it finds that identity or exhausts
the reachable graph. It never reads a blob merely to prove reachability.
Gitlinks refer to another repository and grant no local object access.

Every original read retains the existing hash, kind, object-size, byte-budget,
database-budget, cancellation, and deadline checks. The proof is request-local;
it is neither persisted authority nor a reusable permission across heads.
Graph-object expansion and remembered native edges have separate work bounds,
so an admitted tree's many leaf identities do not imply reading every leaf.
Exhaustion returns a refusal, never a successful partial review.

## Thin packs and partially decoded candidate paths

A candidate can encode both changed directories and changed files as thin REF
deltas against original objects. Those bases may be several directories below
the selected parent tree. Inspection now uses each verified uploaded commit or
tree as soon as reconstruction makes its bytes available. Matching directory
names guide the original proof down the changed path before a deeper external
base falls back to searching unrelated siblings and history.

For example, the uploaded root can identify a changed `z/` directory while that
directory's body still awaits its original delta base. The proof remembers the
unresolved new/old directory pair. After that base reconstructs `z/`, the same
proof continues into `z/deep/`, then authorizes the original file required by its
delta. Independent depth-one deltas can therefore arrive in several decoding
stages without being mistaken for one deeper delta chain. The order of entries
in the pack need not put the directory bases before the file that needs them.

These paths are navigation hints only. Original reads still require both current
selected membership and a typed native-edge chain from the independently
selected visible parent commits. An uploaded tree or claimed commit parent
cannot authorize a base from an unrelated or hidden ref. Pack-local identities
are discovered before external lookup; an explicitly supplied base remains
transport data even if the same identity also exists on a hidden branch.

Each uploaded graph body is parsed and charged once. Waiting path pairs consume
the existing edge allowance before retention, and later stages retain all prior
object, byte, and edge charges. External-base bytes and delta lookup/reconstruction
work likewise share one allowance across all stages. Cancellation and exhaustion
refuse the whole inspection. Native REF discovery retains its existing pass
ceiling, and a final check of the original REF/OFS dependency graph enforces the
actual delta-chain depth even when the resolver reused cached intermediate bytes.

The focused `candidate_thin_frontier` integration target exercises real imported
node state, actual SHA-1/SHA-256 thin packs, thick-pack review equivalence,
restart, hidden-base refusals, explicitly supplied transport bases, and absence
of candidate staging. Its unchanged-sibling fault preserves the original
envelope while corrupting payload bytes: coverage still checks the reused
object's availability and kind, and an unnecessary full payload read fails.
The pack and proof unit cases cover staged depth-one resolution, over-depth
local chains, cumulative limits, and cancellation during later guidance stages.

## Candidate and pack coverage

Native merge, squash, fast-forward, and workspace validators check the candidate
above the selected closure. Exact parent shape and merge ancestry are still
validated. Source access remains narrower than the selected closure: a required
original must pass the parent-reachability proof before its bytes are returned.

Inspection also walks native edges in the uploaded graph, including uploaded
objects whose identities are already selected. This prevents an uploaded tree
from bypassing original-object access for its omitted descendants. Fully supplied
bytes are treated as uploaded content. A thick bundle may resend objects proved
reachable from the selected parents; it need not use the minimal transport.
Unrelated extra objects remain forbidden unless they are required pack-local
delta bases, which retain their separate transport-only count.

`closure_objects` reports the candidate decision's validated object set, including
the named candidate, parent, and common-base commits. It is independent of pack
thickness and is not a count of the repository's complete reachable history.
Fast-forward decisions therefore retain a nonzero count despite adding no
native object. Pack counts, expanded bytes, and transport-only counts continue
to describe the actual uploaded representation.

## Native lifecycle acceptance

With separately built native `FG_BIN` and `FG_MCP_BIN`, run
`scripts/e2e/suites/mcp/reviewed_merge_scale.sh`. It extends the existing reviewed
merge helper with a named 100,000-file profile for both SHA-1 and SHA-256.
The fixture imports an actual native pack and index, then inherits the unchanged
subtree through a divergent pull request. Separate MCP processes prepare and
inspect the candidate, record an independent review, publish, reopen, retry the
original request, and read canonical refs and inherited file bytes.

Before publication, the lane compares the minimal bundle with a thicker bundle
that resends one selected blob. Candidate identity, review, prerequisites and
validated closure must match; transport counts and checksums must describe the
actual bytes. Returned review/publication commands carry their respective input
bundle: the lane checks those bytes exactly and compares every other argument.
A corrupted thicker bundle must refuse without changing refs.
Publication uses the inspected thicker bundle's actual publication arguments.

The helper saves each MCP request before spawning and captures stdout/stderr
directly into per-command files, preserving partial evidence on timeout or
spawn failure. The scale suite first runs real-child capture selftests; those
tests check the runner, while the subsequent native lifecycle checks the forge.
Timeouts and nonzero exits remain failures and never trigger automatic retries.

The ordinary helper's scenarios and 120-second subprocess deadline remain
unchanged. The named scale suite has a 1,800-second outer deadline and runs the
clean merge-commit case for both hash domains; the existing lifecycle suite
continues to cover squash and conflict resolution. These are executable local
acceptance lanes, not a claim that they passed at an unspecified revision or
that a release, remote authorization, or an unbounded repository is qualified.

## Applicability limits

The benefit is avoiding unrelated historical trees and blob bodies, including
large unchanged subtrees that the existing Merkle comparison can skip. It does
not make every inspection independent of repository shape. Proving an old or
renamed object's reachability can require searching parent history. A large flat
changed directory still consumes tree parsing and comparison work. The existing
review limit on the aggregate entries in trees actually compared, changed paths,
text, and diff output remains in force. No work or byte ceiling is increased.

Linear rebase inspection retains its existing complete-closure profile. This
change is not an integrity scrub of untouched admitted descendants, a review
approval, a check result, or permission to publish. Publication still performs
its own admission against the exact current authority basis.
