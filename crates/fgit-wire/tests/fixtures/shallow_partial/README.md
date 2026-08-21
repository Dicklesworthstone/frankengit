# FG-018b shallow and partial-clone corpus

`shallow_partial_corpus.rs` carries the immutable typed DAG facts because the
closure API is storage-agnostic: every synthetic OID, parent edge, committer
time, tree edge, blob size, expected shallow update, and promised omission is
visible in the test source. The reference walker uses a distinct insertion-order
representation from `fgit_wire::closure` and checks every corpus case.

The E2E companion `scripts/e2e/suites/wire/shallow_partial_corpus.sh` creates
the externally observed depth and filter cells through only the pinned,
Bubblewrap-isolated Git oracle. Its receipt denominator is fifteen acceptance
assertions. The `deepen-since`, `deepen-not`, and `unshallow` cells have no
equivalent one-shot `git clone --depth/--filter` invocation and remain an
explicit non-claim of that E3 oracle cell; they are covered by the checked
reference fixture instead.
