# Production upload-pack visibility and annotated tags

## Current visible scope, not cumulative historical admission

The node-owned daemon derives one private `VisibleUploadPack` from the exact
`MaterializedAdmission` used for advertisement. Visible ref roots are filtered
by that snapshot's authenticated hidden-ref policy. The production walk requires
every native dependency to belong to the admitted object set, verifies native
bytes and required kinds, and rejects incomplete graphs. Historical admission
or physical object presence alone grants no network disclosure permission.

The same scope governs wants, common-have acknowledgments, and the selected
pack's want-minus-have traversal. Deleted or hidden-only objects are neither
acknowledged as common nor subtracted from another client's response. Objects
shared with a still-visible history remain usable. Gitlinks are foreign-repo
data and are not followed. A hidden symbolic HEAD target is not reintroduced
through protocol-v2 unborn metadata. A proof naming another authority basis is
refused; the canonical historical closures and trusted local exporter remain
unchanged.

This is an exact-snapshot serving boundary. It does not claim immediate
revocation of a transfer when another transaction changes policy after the
snapshot was selected. The current profile eagerly verifies the complete
visible graph before advertising and retains the existing finite node, edge,
byte and deadline envelopes. It is not a streaming large-repository or latency
optimization. No performance or side-channel-freedom claim is made.

## Partial-clone extension

The current node adds filtered packs and capability-gated lazy retrieval as
specified in [Partial-clone serving](PARTIAL_CLONE_SERVING.md). In particular,
it now advertises `allow-reachable-sha1-in-want`; the advertisement-bound legacy
behavior described below is the earlier implementation's measured baseline,
not the current production capability set. The strict no-capability refusal
remains covered in wire tests. Current visibility and historical-retention
boundaries are unchanged.

## Native annotated-tag serving

The graph walk retains the already-verified tag edges and derives request-local
metadata without reading object bodies twice. Nested peels are memoized with a
cycle refusal. This metadata is derived from the private serving proof, not a
second source of canonical refs or an unverified caller-provided peel map.
The materialized admission snapshot's separate tag-evidence API is unchanged.

Legacy v0/v1 advertisements include bounded, sorted `refs/tags/name^{}` records
for annotated tags. The legacy negotiation machine sees the same expanded
advertisement the client received. This matters for a tag-only repository:
its advertised peeled commit is a legitimate want even without a branch at
that commit. Other unadvertised historical wants retain `WantNotAdvertised`;
the daemon does not advertise `allow-reachable-sha1-in-want`.

Protocol v2 receives only actual refs and emits `peeled:<oid>` attributes when
`ls-refs` requests `peel`. It does not receive invented `^{}` ref names. Its
non-advertised wants must still pass the current visible-closure gate.

The legacy daemon now advertises `include-tag`. Both legacy capability
negotiation and the existing v2 `include-tag` argument drive real pack
selection. After normal want-minus-have selection, a bounded reverse walk
adds annotated tags rooted in current visible `refs/tags/*` chains whose
referents are actually transmitted. Nested tag chains are supported. An
unrelated historical tag or a deleted tag pointing at a public commit is not
automatically resurrected. A referent excluded as common does not cause tags
to be sent. Expansion is cancellation-aware, respects the selected-pack object
ceiling, and installs its selected set only after the complete walk succeeds.
The existing native planner, writer and checksum remain responsible for bytes.

## Native regression coverage

The 13 visibility/tag tests include real import, ref deletion, reopen, exact-head
mismatch, hidden policy, shared ancestors, malformed typed graphs, gitlinks,
inclusive resource limits, cancellation, common-have negotiation, and actual
TCP fetch/ls-refs across SHA-1 and SHA-256 and protocol v0/v1/v2. Tag-only
repositories exercise peel metadata, requested tag delivery, deleted-tag
exclusion, and checksum-verified empty packs when a wanted referent is common.
The tests compare actual emitted object bodies, not just success statuses.

The broader native run also exposed a pre-existing external-base fixture that
budgeted two 64-byte originals but omitted the two reconstructed one-byte
outputs. Its correction leaves production accounting untouched: original
intake refuses at 127 and succeeds at 128; reconstruction refuses at aggregate
128 and 129, then succeeds at 130 while the original-input ceiling stays 128.
Every refusal still asserts that neither output was staged.

## Recorded verification

All commands below use the repository-pinned nightly-2026-08-31 toolchain and
locked dependencies. Existing compiler warnings are not a passing lint gate.

At `062cb4e1dedc355c14431df0774318d0530c356d`, `cargo check --locked -p
fgit-node --all-targets` exited 0. The broad `cargo test --locked -p fgit-node
--all-targets --no-fail-fast` invocation reached its 600-second command limit
(exit 124). Its library target reported 224 passed and one failed (the
external-base fixture above); multiple integration targets completed before
the time limit. That run is not a successful full node suite.

At `21feced9df14e258dddd1e7804f7f6c437fecb15`, `cargo check --locked -p
fgit-node --all-targets` exited 0, `cargo test --locked -p fgit-node --lib
upload_visibility -- --nocapture` exited 0 (13 passed, zero failed), and
`cargo test --locked -p fgit-wire --all-targets` exited 0. Existing
pinned-oracle-dependent wire tests remained ignored by their own declarations;
no full pinned-Git differential campaign was executed by that command.

Final source revision: `b0379ba3e52ea7e67bfe6d0f228c06021b1d8d59`.

| Command | Exit | Passed | Failed | Ignored |
|---|---:|---:|---:|---:|
| `cargo test --locked -p fgit-node --lib` | 0 | 229 | 0 | 0 |
| `cargo test --locked -p fgit-node --test git_daemon_deadline --test git_daemon_receive_transport --test git_daemon_v1 --test git_daemon_v2 --test hidden_ref_policy_end_to_end --no-fail-fast` | 0 | 27 | 0 | 0 |
| `cargo test --locked -p fgit-wire --all-targets` | 0 | 227 | 0 | 6 |

Counts above sum completed test-target summaries only. Exit 124 denotes an
interrupted command, not a passing suite. Full target summaries follow.

### node-library

```text
test result: ok. 229 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 195.98s
```

### daemon-integration

```text
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.39s
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.80s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.04s
```

### wire-all-targets

```text
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 2 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

These measurements do not certify the entire workspace, Clippy/rustfmt gates,
release gates, remote authentication, protected-branch policy activation,
shallow/partial clone serving, or all Git features. No bead is closed by this
integration. No dependency, lockfile, or canonical schema was changed.
