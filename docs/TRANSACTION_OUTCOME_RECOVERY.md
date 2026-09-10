# Recover a transaction outcome without its original artifacts

`fg outcome` queries an existing sealed request using its original client key
and authenticated principal. It does not reconstruct, retry, cancel, or publish
the mutation. A lost response no longer requires keeping a candidate bundle,
workspace, PR body file, or the transaction ID just to discover the result.

This is a local-operator interface over `OneNode::recover_transaction_in` and
`fgit_authority::key_recovery`. It uses the existing idempotency binding, seal,
transaction-identity derivation, and authenticated outcome resolver. It does
not introduce another transaction registry, mutable outcome table, or history
walker. It does not activate compiled policies or make the opt-in candidate
review gate mandatory across other mutation paths.

## Command

```bash
fg outcome "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$ORIGINAL_PRINCIPAL_ID" \
  --idempotency-key "$ORIGINAL_KEY"
```

For a key that should not appear in command-line arguments:

```bash
printf '%s' "$ORIGINAL_KEY" | fg outcome \
  "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$ORIGINAL_PRINCIPAL_ID" --key-stdin
```

Use `--object-format sha256` for a SHA-256 node; the default is SHA-1.
`--idempotency-key-hex` accepts lowercase hexadecimal for arbitrary key bytes.
Supply exactly one key source. The limit is 256 bytes, and input is exact:
stdin does not trim a trailing newline, case-fold, normalize Unicode, or reject
an empty key that the authority protocol admits. The raw key is not emitted in
JSON; only its typed digest is reported. This does not promise zeroization of
local process memory or protect a secret already exposed in shell history.

The scope must be the original tenant, repository, and principal. A key is not
a credential. `--trusted-local` acknowledges the operator's preexisting access;
a remote gateway must independently authenticate the session and authorize the
repository. There is no arbitrary-transaction lookup that treats knowledge of a
TxId as permission. A different principal normally observes an absent binding,
not another principal's transaction.

## Interpret the observation, not merely the exit code

| JSON state | Exit | What was observed |
| --- | --- | --- |
| `committed` | 0 | A verified terminal commitment, with exact transaction, decision sequence and RCR identity. |
| `refused` | 3 | A verified canonical refusal, with exact decision sequence, code and refusal-record identity. |
| `undecided` | 4 | A verified seal but no terminal decision in the authenticated history observed by the resolver. |
| `seal_not_observed` | 4 | The key binding was present, but its seal was not observed. The binding's unverified target is not disclosed. |
| `key_not_observed` | 4 | No binding was observed for that exact scope and key. |

Input, repository, authority, integrity, cancellation, shutdown and output
errors use exit 2. An error is not converted into a successful absence result.
A missing repository is an error, not `key_not_observed`.

**None of the three nonterminal states proves rollback or authorizes a retry
under a new key.** A concurrent request may still bind, seal, or publish. A
missing seal can also reflect unavailable metadata; it is not an abort
certificate. Nonterminal results are observations across several reads, not an
atomic snapshot or a permanent promise. The result explicitly sets
`absence_proves_non_commit` to false and never instructs the client to invent a
new key. Recovery does not cancel the original request.

A decided outcome is historical. A later branch update, PR close, withdrawn
review, exhausted push quota, or stopped serving state does not turn a past
commit into a refusal. A past refusal does not become a commit when current
preconditions improve. The node can perform this metadata query without
bringing itself into service, but its runtime and authority store must still
be live and readable.

## Verification and failure boundary

The recovery core first reads and authenticates the repository head, including
its slot, repository, store instance and generation. It then reads the exact
scoped binding. The binding must be one canonical TxId with no trailing bytes
or foreign identity domain. A present seal must match the supplied tenant,
repository, principal and key digest, and its transaction identity is rederived
from the caller's key and the stored canonical-request digest. Seal bytes must
round-trip exactly, and its canonical seal identity is derived for the receipt.

The terminal result comes from the existing resolver, which walks authenticated
history and cross-checks the outcome accelerator. The recovery module does not
infer commitment from a binding, seal, staged object, candidate record, or an
accelerator entry alone. Malformed or substituted metadata is an error. A
missing required history body is not downgraded to an undecided transaction.

Binding decoding is limited to 256 bytes and seal/head metadata to 8192 bytes;
individual decoded strings, collections and nesting also have explicit limits.
The authority backend owns its returned-value allocation bound. The existing
history resolver retains its own replay bound. Production calls await the
original runtime-owned authority context; a caller checkpoint preserves the
distinction between cancellation and resource exhaustion.

After a terminal outcome has been resolved, a late cancellation does not erase
it. The CLI closes the node before emitting its report. If shutdown fails, a
known terminal result remains in the JSON with `node_closed:false` and
`cleanup_error`, and the process returns an error. Write/flush diagnostics also
preserve a known transaction and terminal status. Consumers must parse a complete
document and inspect its fields; neither a nonzero exit nor a truncated output
proves non-commit. Repeating the outcome query never repeats the mutation.

## Applicability

The command works for authority-sealed mutation keys, including PR lifecycle,
review and merge requests. It does not reexecute an undecided request or recover
missing command bodies. Repository creation has a separate attempt protocol.
Non-atomic receive sessions derive per-command keys; their base session key is
not silently expanded into a batch of unrelated identities. Query the exact
sealed key. No command, object, policy, or transaction history is enumerated.

Repository-wide mandatory protection and authenticated policy activation remain
unfinished. This read-only recovery path neither closes nor weakens those
boundaries. See [the exact-candidate review workflow](EXACT_CANDIDATE_REVIEW_WORKFLOW.md)
and [persisted policy snapshots](PERSISTED_POLICY_SNAPSHOTS.md).

## Tests and current evidence

Thirteen Rust test functions are registered: six authority reference/shared-core
tests, three embedded-node tests, and four CLI tests. They cover exact scopes,
identity substitution, truncated and oversized metadata, incomplete sealing,
opaque key bytes, committed/refused recovery, unchanged authority state,
reopen without original inputs or serving admission, cancellation semantics,
input refusal, and output failures. Reference-store tests are model evidence;
the embedded-node tests use the real async authority but have not run here.

```bash
python3 scripts/e2e/transaction_outcome_smoke.py --self-test
python3 scripts/e2e/transaction_outcome_smoke.py --fg /absolute/path/to/fg
```

The fresh-process campaign constructs independent SHA-1/SHA-256 fixtures, records
real PR mutation receipts, removes the original source and PR body file, and
compares recovered transaction/decision identities with those receipts. It also
checks text/hex/stdin equivalence, wrong-principal non-disclosure, bounded input,
and unchanged canonical history. The campaign fingerprints its supplied binary;
it does not substitute a Python implementation for FrankenGit.

The Python checker self-test executed successfully and rejected 46 corrupted
reports. Python compilation/help, Rust lexical/delimiter checks, and remote
commit/blob/diff checks were performed. Cargo, rustc and a built `fg` are absent
in the editing environment: Rust compilation, native test execution, rustfmt,
Clippy and the complete binary campaign were not run. Restart/absent-input
fixtures are not a process-death-during-CAS, power-loss or host-filesystem fault
campaign. No bead is closed and no passing native gate is claimed.
