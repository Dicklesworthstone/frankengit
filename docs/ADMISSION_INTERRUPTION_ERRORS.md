# Admission interruption and integrity failures

Bridge work: `frankengit-root-doctrine-x2mv.4.51`.

During asynchronous admission preparation, authority reads and immutable staging
can be cancelled by a caller or an expired runtime deadline. Previously several
projection adapters discarded the underlying error: protection and review reads
reported `AuthorityReceiptInvalid`, forge delivery reads reported `EvidenceInvalid`,
and direct frame or decision-history reads reported `EvidenceMissing`. A healthy
repository could therefore appear corrupt solely because the request ran out of
time.

The shared `AdmissionError::into_projection_unavailable` conversion preserves a
typed infrastructure reason through direct authority, seal and outcome-history
wrappers. Protection, candidate reviews, default merge basis resolution, durable
node materialization and PR preparation now use that conversion.

| Underlying reason | Nonterminal projection code |
| --- | --- |
| Cancelled or expired authority operation | `CancellationInProgress` |
| Lost authority response without a known cancellation cause | `ExternalEffectIndeterminate` |
| Explicit authority throttling or capacity/body-size limit | `ResourceBudgetExceeded` |
| Decision-history replay bound exhausted | `ResourceBudgetExceeded` |
| Unavailable or unsupported authority service | `DurabilityProfileUnavailable` |
| Already classified projection error | Its existing code |
| Actual malformed receipt, invalid evidence or absent selected body | The existing boundary-specific integrity code |

The conversion inspects the error that actually occurred. It does not poll the
current clock to relabel a detected corrupt frame as cancellation. Exact native
budget dimensions already translated by their owning adapter remain unchanged.

## Publication and retry

This conversion applies only while preparing a projection, before a new head CAS.
It returns `ProjectionFailure::Unavailable`, never a terminal policy refusal. A
cancelled attempt cannot publish a permanent cancellation decision or turn an
uncertain immutable write into proof of absence. The stable sealed request can
be retried through normal transaction-outcome lookup.

The publisher's CAS error path is unchanged. A cancelled or lost response after
the CAS may have run retains `AuthorityFailure::Ambiguous` and its effect-unknown
guidance. Recovery still resolves the original transaction identity, and a
recovered terminal decision takes precedence over a new preparation attempt.

## Regression coverage

The deterministic node tests inject cancellation or an already expired native
deadline inside the actual FrankenSQLite read, after the production materializer
or protection evaluator has entered. They cover ref frames, configuration/history
reads, forge delivery and mandatory protection for both native hash domains.
Every interrupted read is followed by a live retry against the same authority
basis. Planted invalid receipts, corrupt forge frames and absent selected ref
frames retain their distinct integrity codes.

The reference-store admission test interrupts the post-fold materializer, checks
that the head remains unchanged, retries the same request to a commit, and
checks that another retry returns that one original decision. The existing
native merge fault campaign independently covers lost requests and responses
around head CAS.

Relevant repository-owned tests are:

```sh
cargo test --locked -p fgit-admission --lib projection_failure
cargo test --locked -p fgit-admission --test async_admission_equivalence
cargo test --locked -p fgit-admission --test native_merge_delivery_faults
cargo test --locked -p fgit-node --lib tests::admission_projection
```

These tests are native and reference-store regression coverage, not an
end-to-end CLI or loaded-host campaign. Acceptance of the bead also requires
the batch verifier's revision-bound `fgit-node` run under load. Test definitions
alone do not establish that gate or close the bead.
