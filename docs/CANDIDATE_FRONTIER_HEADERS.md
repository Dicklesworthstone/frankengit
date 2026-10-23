# Candidate inspection without rereading inherited blob payloads

Workspace and merge candidate inspection now validates already-admitted native
edges through bounded storage headers after proving disclosure from the exact
visible parent commits. A tiny candidate whose updated root tree directly names
large unchanged blobs no longer consumes their total body size merely to verify
their kinds. The same owner is used for sparse candidate workflow input selection.
There is no new patch, diff, pack, authority or publication engine.

## Two different responsibilities

Uploaded objects still pass the existing pack checksum, native identity, typed
edge and coverage checks. The candidate commit is always parsed and hashed in
full, even when its ID is already in the selected set. Actual changed content,
parent ancestry, thin external delta bases and requested workspace payloads still
use the existing full verified body-read path. The frontier optimization does not
turn a header into body evidence or claim that untouched storage was scrubbed.

For an omitted original object, cumulative repository membership is necessary but
not sufficient. `ParentReachability` proves native typed edges from the current
visible parents before the envelope is read. Uploaded trees cannot authorize
omitted hidden descendants. The envelope must name the selected ID, have the
required native kind, remain present and satisfy the existing per-object size
ceiling. Wrong kinds, missing or malformed envelopes and cancellation refuse.

`ObjectFrontier::with_headers` is the explicit native admission adapter. Supplying
an ordinary selected set retains the historical full-body source behavior and
byte accounting. A metadata provider returning `None` also retains that path;
a metadata error never triggers a fallback. The canonical pack writer interface
is unchanged and cannot emit a header as if it were a payload.

The existing limits remain: bounded uploaded pack/object counts, candidate byte
allowances, native edges, source graph evidence, individual objects and comparison
work. Graph reads still consume their original byte budget; untouched blob lengths
are not falsely counted as bytes fetched. A successful review is not a complete
repository integrity check, and existing scrub/doctor operations retain that role.

## Regression evidence

The focused native tests exercise the admission metadata boundary, visible-parent
proofs and real local object envelopes. They distinguish an unread corrupt blob
payload from a verified content read: metadata selection is not a scrub, while a
subsequent body read still rejects altered payload bytes. Pure validator fixtures
are labelled separately from the actual-node tests.

The discovered `candidate_frontier_bytes.sh` campaign drives the actual compiled
`fg serve-http` in SHA-1 and SHA-256. It constructs a 140 MiB set of seven unchanged
20 MiB blobs directly referenced by the changed root, plus a one-file text edit.
Python independently constructs native trees, commits and minimal/thick bundles.
The campaign checks exact native preparation, complete result inspection, restart
and source-free read-only inspection on the 140 MiB fixture. Separate 20 MiB
permitted controls check ordinary reviewed publication, original-key recovery and
source-free object reads. Linux process read counters bound actual I/O during
large minimal-candidate inspection; no general latency ratio is promised.
No stock Git engine or HTTP stand-in implements those operations.

Receive quarantine remains a separate body-verification obligation: the 140 MiB
fixture still exceeds its existing original-input budget at publication. The
observed HTTP response is `outcome_unknown`, not proof of non-commit or permission
to invent a new key. This change does not weaken that path or claim large-push
completion.

This does not remove all repository-scale limits, stream arbitrarily wide trees,
change rebase-series inspection, or provide hostile-code isolation, release,
physical-power-loss or whole-workspace qualification. The broader candidate
scalability bead `frankengit-t0iw` remains an independent acceptance obligation.
