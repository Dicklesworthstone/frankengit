# Receive ref targets that already exist

Production receive quarantine accepts a checksum-verified zero-object pack
when all non-delete ref targets can be verified from the authenticated visible
repository history. It also accepts a pack that supplies some requested roots
while reusing others. This fixes ordinary branch/tag creation at existing tips
or historical objects without requiring clients to resend objects the server
already has. No new command, dependency, database, or alternate protocol is used.

## Evidence and visibility

There are three distinct inputs: uploaded objects, cumulative authority-selected
membership, and visible refs at the selected authority head. An omitted target
requires both prior selected membership and reachability from that visible ref
set. A merely present fabric object, a hidden-only object, or a selected object
no longer reachable from visible refs cannot become a new ref through this
reuse path. Sharing history with a visible ref does make an object reachable;
a hidden ref does not hide objects also reachable through a visible ref.

`OneNode::production_quarantine_validator` derives the visible roots from the
same authenticated materialization as its selected closure. The existing
basis-bound receive proof keeps this selection tied to that exact head during
admission. A losing publication cannot reuse the old proof as authorization at
a different head. Historical terminal recovery retains its existing precedence;
this does not change transaction seals, idempotency semantics, or the authority
compare-and-swap protocol.

A currently visible tip takes a direct path, but its actual body must still be
read, reproduce its native identity, and fit the original-input budget. Other
omitted targets require a bounded native graph walk from visible refs. This
walk follows typed commit parents, trees and annotated-tag targets using the
shared import/receive edge reader. Stored parents are explored ahead of trees
on the common ancestor-branch path. Gitlinks remain external references and
never supply local reachability. Encountered contradictory kind requirements
refuse, including requirements discovered after an earlier visit.

This is a reachability proof and verified frontier read, not a recursive audit
of every dependency behind every historical target. As with other existing
frontier checks, prior authenticated history remains the basis for dependencies
not traversed by this operation. Missing or corrupt selected bodies are errors,
not permission to substitute a different source.

## Pack evidence is not a staging instruction

An empty pack still has the native PACK header, zero entry count, and its
SHA-1 or SHA-256 trailer. The normal reader verifies framing and checksum.
Missing pack bytes for a non-delete request remain refused by the existing
admission guard; they are not converted to a successful empty-pack receipt.

The resulting closure witness contains selected uploaded objects and exactly
those requested roots that were reused. It does not add every history object
visited while proving reachability. Its size is therefore not the pack's entry
count, which continues to record actual uploaded entries. Every proposed ref
must still be in that witness before admission can lower or seal the request.

The staging loop writes only selected uploaded bodies. Verified existing roots
are retained in the witness without being restaged. Unrelated uploaded objects
remain unselected. A failed existing-root check prevents all upload staging;
a later storage failure during staging retains the usual distinction between
immutable placement and canonical publication. Only the established sealed
admission and exact-head CAS can publish the ref update.

## One original-input ledger

External delta bases, existing-root reachability, and uploaded graph-frontier
checks share the smaller of the selected cache and expanded-byte ceilings.
Previously verified delta bases are borrowed without another body copy or byte
charge. Original kinds verified during reachability are reused by subsequent
frontier checks. Repeated requested roots do not repeatedly read the same body.
No full history-body cache is retained by the walk.

The existing four-million-edge ceiling also covers reachability edges and is
narrowed by the expanded-byte envelope. The new walk bounds its pending/visited
identity state and verified-kind cache at one million objects. Caller-owned
deadline checkpoints remain in reads and graph work. These bounds are not a
claim about total process RSS, constant-time disclosure, or preempting an
operating-system read already in progress.

Ref namespace rules, fast-forward and protected-ref policy, remote transport
authentication, and expected-old conditions remain separate admission duties.
This does not activate repository-wide review policy, modify hidden-ref policy,
or provide request-cancellable source-import I/O.

## Tests and verification

Nine new Rust tests are registered. They cover both object formats, valid empty
packs, mixed uploaded/reused roots, historical commits, nested tags, disconnected
and hidden-only selection stand-ins, missing selected bodies, unrelated uploads,
shared inclusive byte budgets, typed reachability, gitlink exclusion and
cancellation. The integration case imports an actual local Git directory,
passes an empty pack through the production SANS-I/O handoff, creates a branch
at a historical commit, advances it, and checks retry after shutdown/reopen
without rolling back the descendant. Existing quarantine tests are unchanged.

```bash
python3 scripts/e2e/existing_target_receive_smoke.py --self-test
python3 scripts/e2e/existing_target_receive_smoke.py --git-oracle /absolute/path/to/git
python3 scripts/e2e/existing_target_receive_smoke.py --fg /absolute/path/to/fg
```

The checker self-test executed and rejected 89 altered pack/report inputs.
The isolated Git 2.47.3 oracle executed ten raw stateless-receive cases across
SHA-1 and SHA-256: existing tips, historical commits, nested tags, blob tags,
and a new commit with selected dependencies. It checked exact published native
IDs. These are Git protocol/fixture checks, not executions of FrankenGit.

The real-fg mode reuses the existing process-owned raw git-daemon test client.
It checks canonical refs after existing-target and mixed-source receives,
refuses missing/unselected roots without authority movement, probes an unrelated
upload, and fingerprints the supplied binary. Rust compilation, all native
tests, rustfmt, Clippy, and this real-fg mode were not run in the editing
environment: Cargo, rustc and a built fg were unavailable. Source review,
lexical/delimiter checks, Python compilation, and exact uploaded blob checks
were performed; they do not replace a revision-bound native test result.
