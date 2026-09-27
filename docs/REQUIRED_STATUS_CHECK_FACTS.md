# Exact required status-check facts

`frankengit-root-doctrine-x2mv.4.6`, required-check matching (acceptance 4).
The consumer is `fgit-policy::evaluate_protected_ref`: its previous implementation
accepted any live generic `ci_check` receipt for the ref as satisfying every
required name, without binding the proposed commit or a successful result.

## Input contract

`StatusCheckReceipt` is a typed input fact containing an exact `AsciiSlug` check
name, issuer, ref, native Git commit, explicit conclusion and half-open validity
interval. Its constructor checks a nonzero commit and `issued_at < expires_at`.
It does **not** authenticate the issuer, verify execution evidence or grant
authority. The admission boundary must verify those facts and select the current
canonical result at the same authenticated basis as the proposed ref update.
A trusted-local workflow observation remains an observation; its existence or a
successful local process exit does not establish an independently verified
`Success` fact.

`PolicyInputRoot::with_status_checks` attaches a complete result set. Input
construction sorts by `(ref, commit, name)` and refuses duplicate slots even when
their issuers, conclusions or validity intervals differ. This prevents order
from choosing an old success over a conflicting failure. The caller resolves
supersession from canonical history before constructing the input.
Generic and named receipts together must fit `MAX_RECEIPTS`; the bound is checked
before copying or sorting the supplied named facts.

## Evaluation

For every configured required name, the evaluator requires a fact with:

- that exact check name;
- the exact ref being updated;
- the exact proposed new native commit, including SHA-1 versus SHA-256 domain;
- the explicit `Success` conclusion;
- `issued_at <= input.instant < expires_at`.

A receipt for the old tip, another commit, another ref or another name cannot
satisfy the requirement. Failure, cancellation, timeout and action-required
conclusions do not pass. Deletion has no proposed commit and therefore cannot
satisfy a nonempty check requirement. `strict_up_to_date = false` never relaxes
the exact-commit requirement. More than `MAX_REQUIRED_CHECKS` configured names
refuses; each permitted name uses logarithmic lookup in the sorted fact set.
Names are evaluated in their canonical order so the first refusal is stable.

## Compatibility and scope

`EvidenceReceipt`, its constructors and existing generic policy-language
semantics are unchanged. `PolicyInputRoot::try_new` initially has no named check
facts. Generic `ci_check` receipts remain generic evidence and cannot satisfy
named protected-ref checks; callers supply verified typed facts through
`with_status_checks`. Empty check requirements are unchanged.

This input model has no published canonical codec. The change does not alter
policy snapshot bytes, transaction identity, authority publication, or existing
forge workflow-check event formats. It does not complete CI triggering, runner
attestation, stored-policy activation or transport integration for the broader
policy-integrity bead.

## Regression coverage

`crates/fgit-policy/tests/required_status_checks.rs` covers both native hash
domains, exact-name/ref/commit matching, all required names, explicit conclusions,
half-open expiry, generic-receipt refusal with a typed permitted twin, duplicate
and conflicting slots, all permutations of a three-record input, zero identity,
invalid intervals, deletion and configured/input collection bounds. Existing
protected-ref vocabulary tests use explicitly named success facts for their
permitted CI cases. These are Rust evaluator tests, not an end-to-end runner or
authentication claim.
