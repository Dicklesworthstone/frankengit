# Production receive quarantine: native graph integrity and external-input bounds

The production `ProductionQuarantineValidator` now verifies more than a set of
individually hash-valid objects. Its selected uploaded graph must also resolve
each native edge to the required object kind before staging begins. The same
gate is used by raw receive-pack and bundle-publication paths that construct a
production receive handoff. There is no opt-in CLI switch and no alternate
object store, parser, delta resolver, or transaction publication mechanism.

## Defects addressed

The prior traversal extracted bare OIDs and accepted an edge when its target
was either uploaded or in the authority-selected set. That could admit a
commit whose tree was a blob, a parent that was a tree, a file entry pointing
at a tree, or a tag whose declared target kind disagreed with the actual object.
All objects and the enclosing pack could have correct checksums. Authentic
identity alone does not establish that a graph relation has the required type.

External REF_DELTA bases were also loaded and copied before an aggregate
original-input budget was checked. A literal delta can require a large base
while reconstructing a tiny result. Bounding reconstructed output therefore
does not bound the earlier accumulation of original bodies.

## Enforced graph rules

A commit must have exactly one unambiguous tree edge to a tree; each parent
edge must name a commit. Tree/parent continuation bytes cannot be discarded
and duplicate tree headers cannot select a convenient interpretation. Generic
import parsing still preserves other unusual headers; this is not a change to
its independent byte-preservation contract.

Tree entries use their parsed octal type bits: directories require trees,
regular files and symlinks require blobs. Gitlinks remain external-repository
references and are not fetched, including import-tolerated octal spellings.
They still consume traversal work. Annotated tags use the existing typed
`parse_annotated_tag` view; the declared blob/tree/commit/tag kind must match
the exact target. Zero required local edges and unknown tree kinds refuse.

Every edge is checked even when its target was already visited, so conflicting
requirements cannot be hidden by traversal or command order. Uploaded delta
bases retain their existing transport-closure responsibility, including forward
pack-local REF deltas. Unrelated uploads remain unselected and unstaged.

A native edge ending in prior selected history must resolve to actual verified
bytes of the correct kind. Merely-present, unselected fabric objects remain
ineligible. Missing selected bytes return `EvidenceMissing`; kind mismatches
return `EvidenceInvalid`; ambiguous graph headers return `ObjectHeaderInvalid`.
The existing receive layer carries these typed pre-admission failures; they are
not newly invented canonical terminal decisions.

## Shared original-input budget

Each unique external delta base is charged before another quarantine copy is
made. Its size must fit both object ceilings and the remaining original-input
budget. The budget is the smaller of `PackLimits.max_cached_bytes` and
`PackLimits.max_total_expanded_bytes`. Zero cache capacity consequently does
not permit nonempty external bodies in this profile.

Native selected-frontier reads continue that SAME ledger after delta
reconstruction. A base already verified for a delta is reused for graph-kind
checks without rereading or charging it twice. Other frontier bodies are read
once; only their verified kinds are retained in a per-call cache. This cache
cannot grant membership or survive into another authority basis.

Additional graph verification is bounded by four million edges and one million
cached frontier kinds. The edge ceiling is also narrowed by the admitted
expanded-byte envelope. Allocation/work bounds and caller-owned cancellation
are retained. The fabric still owns its bounded initial read allocation; this
change does not promise that no backend buffer is allocated before quarantine
checks, or that these counters represent total process RSS.

## Publication and applicability boundaries

The staging loop begins only after pack reconstruction and typed graph
verification finish successfully. An invalid graph cannot stage an earlier
valid upload. Storage failure or cancellation DURING staging may still leave
immutable, unselected objects; staging is not canonical publication. The
existing sealed admission, exact-head compare-and-swap, and historical outcome
recovery remain unchanged. Cancellation observed after a fabric read is checked
before converting that read into a missing-object verdict.

This verifies the new uploaded graph and its selected frontier. It is not a
recursive audit or repair of all historical dependencies behind that frontier.
It does not change ref-namespace target policy, activate compiled protection
policies, make candidate reviews mandatory repository-wide, or implement
multi-commit rebase. Loose/packed source import has its own verification path
and is not changed by this slice. Invalid-input refusal is not evidence that
all other mutation paths or all Git compatibility cases are complete.

## Tests and verification status

Thirteen new Rust test functions are registered: four external-input budget
and cancellation tests, and nine typed graph/frontier/handoff tests. The latter
exercise both SHA-1 and SHA-256, all four tag target types, commit/tree edges,
contradictory kind requirements, malformed headers, gitlinks, missing selected
bodies, shared input budgets, forward deltas and transport-only dependencies.
The handoff integration test uses actual authenticated node selection and
canonical admission/retry. Frontier unit fixtures explicitly label their
selection stand-ins. All nine preexisting quarantine tests remain registered
with their original test logic.

```bash
python3 scripts/e2e/quarantine_typed_graph_smoke.py --self-test
python3 scripts/e2e/quarantine_typed_graph_smoke.py --git-oracle /absolute/path/to/git
python3 scripts/e2e/quarantine_typed_graph_smoke.py --fg /absolute/path/to/fg
```

The self-test executed and rejected 53 corrupted pack/report inputs. The
isolated Git 2.47.3 `index-pack --strict` oracle accepted/rejected all 16
independently constructed graph fixtures as expected across both native formats.
These are fixture checks, NOT executions of FrankenGit. The real-binary mode
sends the packs over raw receive-pack so a Git client cannot reject malformed
objects first; it checks framed report-status, canonical state, and server
shutdown, and fingerprints the supplied executable.

Python compilation/help, Rust lexical/delimiter checks, original-test
preservation, and exact local/GitHub blob comparisons were checked. Rust
compilation, native tests, rustfmt, Clippy, and the actual `--fg` campaign were
not run: the editing environment has no Rust toolchain or built `fg`. The
revision-bound native gate remains outstanding; no bead is closed here.
