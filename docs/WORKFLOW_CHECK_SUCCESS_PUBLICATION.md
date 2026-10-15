# Successful workflow observation publication

The operator publisher now consumes the native `Success` conclusion introduced
by `e5af246474a9732d95e725322abfc959c1457635`. This repairs the successful-job
path through `fg_workflow_checks once`, `serve` and explicit `resume`: the
publisher previously expected `action_required`, so it rejected the native
successful receipt after the mutation might already have committed.

## Two different conclusion boundaries

Native custody history still reports `action_required` for successful trusted
local execution. It is not canonical check publication. The publisher verifies
each completed custody fact against the exact executed job's journal conclusion;
it cannot accept a contradictory failure or an invented journal success.

The separate native publication verifier binds retained evidence to the source
commit, job, run, attempt and graph. The publisher expects `success` for a
succeeded job at that boundary, `action_required` for a skipped job, and the
unchanged failure/cancellation/timeout conclusions otherwise. A successful
publication remains a trusted-local observation: `authoritative_check` is false,
`merge_permission` is null, and no reference movement is implied.

## Existing plans keep their original identity

The saved conclusion participates in the original plan's request hash and key.
Older plans used `action_required` for both succeeded and skipped jobs. Before
starting or resending any pending job in such a group, the publisher rereads the
original private dispatch report and checks its saved SHA-256 pin. An old
succeeded job refuses with `workflow_check_conclusion_changed` before native
submission. The original plan, start marker, key and terminal are never rewritten.
A genuinely skipped job retains its original meaning and can continue.

Keep the complete original publication directory. For an already started job,
use the existing read-only `recover` command with the original principal and
independently selected outcome endpoint. Recovery does not execute the workflow,
resend the mutation, manufacture a check ID or require the original run files.
A recovered terminal settles only the original request. An absent outcome does
not prove non-commit. A never-started legacy success is deliberately not
re-keyed automatically; that requires a separately reviewed publication intent.
Already terminal plans remain readable without the dispatch report.

## Verification and scope

Focused tests are in `tests/operator/workflow_check_success.test.mjs` and
`tests/operator/workflow_check_submission.test.mjs`. They exercise both native
hash domains, exact terminal binding, full-width decision sequences, immutable
legacy keys, private-file pins, contradictory report data, resource bounds and
cancellation. The existing publisher process tests distinguish journal facts
from canonical publication receipts rather than teaching the peer that both
interfaces return the same conclusion.

This change adds no dependency, native codec, authority source, automatic
execution retry or policy grant. It does not implement trusted issuer selection,
required-check policy activation or production merge enforcement. Node contract
and filesystem tests are not Rust execution or an independent runner attestation.
