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
