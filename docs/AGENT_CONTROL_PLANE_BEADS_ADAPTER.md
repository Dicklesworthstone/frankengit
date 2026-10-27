# Native Beads task adapter

The `fgit-agent::beads` module reads real Beads records, prepares bounded native
claims from existing agent control objects, and confirms native ownership from
the database and its flushed export. The `fgit-cli::agent_tasks` host supplies
the bounded `br` process transport and an authenticated task inspection command.
Beads remains the task authority; the adapter does not maintain another task
database and does not edit the collaborative export directly.

The selected profile is **`beads-rust-0.7.6-native-claim-v1`**. It deliberately
does not implement `TaskProjectionStore` or produce `PersistedTaskClaim`.
Its confirmation proves native task ownership and retained history. It cannot
activate agent work or publish repository state.

## Inspect a real task

```bash
fg agent task show /absolute/node-storage TENANT_HEX REPOSITORY_HEX fg-123 \
  --trusted-local --sponsor PRINCIPAL_HEX \
  --beads-root /absolute/project/.beads \
  --br /absolute/tools/br
```

The node and tracker must already exist. `--br` selects an explicitly trusted
Beads 0.7.6 executable; it is never resolved through an inherited `PATH`.
`--beads-root` selects the directory containing `beads.db` and `issues.jsonl`.
The sponsor is local operator attribution, not a credential supplied by task
text. The command does not claim a task or import/export task state.

The default lifetime is 30 seconds. `--expires-after-secs 1..300` selects a
different bound, and the global `fg --timeout-secs` can shorten it. Authority
authentication, executable validation, task acquisition and rendering share
that bound. `--object-format sha256` selects a SHA-256 repository. Output
defaults to 2 MiB and may be bounded with `--max-output-bytes 1..8388608`; the
external task response remains capped at 1 MiB. Oversized responses refuse
instead of truncating a task or dropping its history.

Successful JSON includes the exact authority-read identity, source head and
generation, invocation-local complete run commitment, task ID and selected
tracker, raw-response SHA-256, and the canonical `unclaimed_snapshot` when
available. An assigned or closed task still returns its stored document and
history, with an explicit reason why an initial unclaimed snapshot is absent.
`untrusted_task_document` contains the Beads content. Both
`publication_authorized` and `task_claim_activation_authorized` are false.

Exit 0 means the requested single-task read completed. Exit 2 returns a
structured error on stderr and no task JSON on stdout. Output is buffered until
the process, signal observer and native node have settled. This command does not
claim a complete multi-task situation or freshness after the selected read.

## Why native ownership and exact task persistence differ

Beads 0.7.6 provides `update --if-unchanged UPDATED_AT`. The comparison occurs
inside the update transaction, and `--claim` independently checks assignment,
status, and deferral before installing the selected actor. The additional SQL
predicate prevents two different native claimants from both acquiring an
unassigned task.

However, the ordinary update token is assigned from `Utc::now()`, without a
contract that it is unique and monotone across writes, clock changes, or import.
It is useful concurrency protection, but is not a proof of the generic exact
generation replacement required by FrankenGit's task persistence gate.

The source contracts are owned upstream:

- [Beads 0.7.6 command arguments](https://github.com/Dicklesworthstone/beads_rust/blob/v0.7.6/src/cli/mod.rs)
- [Native update transaction and claim predicates](https://github.com/Dicklesworthstone/beads_rust/blob/v0.7.6/src/storage/sqlite.rs)
- [Concurrent-update regression tests](https://github.com/Dicklesworthstone/beads_rust/blob/v0.7.6/tests/e2e_update_if_unchanged.rs)
- [Native claim regressions](https://github.com/Dicklesworthstone/beads_rust/blob/v0.7.6/tests/e2e_claim_atomic.rs)

Accordingly, generic release, transfer, lease renewal, and activation through the
ordinary persisted task gate remain unsupported. Native confirmation is a
separate type with no conversion into a claim receipt or an active lease. The
full task-store and persistent agent-execution Beads remain open.

## Read and prepare

`BeadsTaskRecord::parse_show_json` consumes the actual one-element array emitted
by `br show ID --json`. It requires the returned full ID to equal the requested
ID, rejects duplicate decoded JSON keys, and bounds input to 1 MiB before
parsing. Canonical JSON of the complete observation and the repository identity
determine the initial projected generation. Repository identity plus the full
external task ID determine its stable projected task identity.

An unclaimed projection requires an open, unassigned record with no prior
reserved history and an independently authenticated `AuthorityReadReceipt`.
Task descriptions and inherited instructions remain untrusted data; they cannot
supply that receipt or grant run capabilities.

`BeadsClaimRequest::prepare` accepts the existing
`AuthorityBoundTaskClaimApplication`, `AgentControlPulse`, `AgentChangePlan`,
and complete `IntentRun`. It runs ordinary `TaskClaimReceipt::admit`, validates
the exact predecessor observation, freezes the existing
`TaskProjectionMutationEnvelope`, and binds the adapter profile. The temporary
in-memory admission receipt is not exposed to the caller. A different run body
with the same numeric run ID fails these checks.

## Authoritative history

The adapter preserves all existing object members in `agent_context` and adds
one reserved member, `frankengit_task_v1`. Beads serializes `agent_context` as a
JSON string in its normal row; the adapter parses that string as bounded JSON.
The complete merged value is capped at 32 KiB. Non-object contexts and existing
reserved history refuse new initial claims rather than being overwritten.

History records retain:

- repository and projected task identities, external Beads ID, and native actor;
- the original exact authority-read receipt identity;
- the prepared envelope, predecessor and successor snapshot identities;
- predecessor and claimed generations, transition and inner-transition identities;
- complete run commitment, numeric run ID, and plan identity;
- original claim instant, expiry, and all reserved surfaces;
- adapter and evidence commitments, observed `updated_at`, and predecessor record commitment.

The actor includes the full envelope commitment, so two different prepared
envelopes cannot masquerade as the same native claimant merely by reusing a
numeric run ID. History is retained in the actual Beads row and export, not in a
FrankenGit sidecar. Parsing it after restart recovers evidence; it never
reconstructs authenticated authority from a serialized identity alone.

## One attempt and conservative recovery

The transport orchestration performs these steps:

1. Check the current logical time against the prepared run and native lease.
2. Re-read the exact task from the live database and compare the complete
   predecessor. An already identical stored history can proceed to export
   confirmation without another claim.
3. Require the exact full ID in `br ready --unassigned --json`, and check the
   logical expiry again immediately before dispatch.
4. Invoke at most one `br update ID --claim --actor ACTOR --if-unchanged TOKEN
   --agent-context JSON --json`. No force flag, batch update, or shell is used.
5. Invoke `br sync --flush-only` and wait for the process to complete.
6. Re-read the database and the export through `br show`, using `--no-db` for
   the export view. Both must retain the complete expected history and the same
   current update token before native ownership is confirmed.

A successful update's partial JSON response is insufficient. A lost response
can still be confirmed by the exact database and export observations after the
writer has stopped. A failed export, unavailable read, or mismatching successor
returns `NeedsReconciliation` with the original request. Seeing the predecessor
after an ambiguous write does not prove non-commit and never triggers a retry.

`reconcile_beads_claim` only reads. It does not repeat the claim or implicitly
flush. A host may finish a previously interrupted export through the explicit
transport and then probe the retained request. A process that could not be
reaped prevents confirmation, including when the outstanding process was an
export writer. A never-attempted request cannot be confirmed through this path.

## Process host and remaining limits

The product host selects an explicit operator-owned executable, exact Beads
directory and database, clears the environment, disables automatic imports and
exports, and bounds the entire operation with one deadline and cancellation
check. It drains bounded output and reaps its child before returning. This is a
trusted local integration, not a sandbox for an arbitrary executable.

Explicit `--db` alone does not disable upstream cross-project routing. The host
therefore refuses route and redirect configurations outside its selected local
profile before invoking a tracker operation. Metadata export paths must stay
within the selected directory. Upstream ownership is documented in
[routing.rs](https://github.com/Dicklesworthstone/beads_rust/blob/v0.7.6/src/config/routing.rs)
and [config/mod.rs](https://github.com/Dicklesworthstone/beads_rust/blob/v0.7.6/src/config/mod.rs).

The readiness result is an eligibility observation, not an atomic promise about
all dependencies or unrelated task fields. The adapter does not claim a complete
multi-task snapshot, generic exact-generation CAS, activated restart execution,
cross-head transfer, broker durability, or an ECC publication path.

## Focused verification

`cargo test --locked --offline -p fgit-cli --bin fg agent_tasks::beads_tests` exercises complete
history, preserved user context, control substitution, deadline expiry, ready
filtering, bounded hostile JSON, lost replies, flush failures, unavailable
exports, and non-quiescent writers.

The explicit native test uses the real checksum-verified Beads 0.7.6 executable
and creates its own temporary tracker. It races two different prepared runs,
checks retained history through fresh processes, loses a successful response,
and stops after the database mutation but before export:

```sh
FGIT_BEADS_NATIVE_BR=/absolute/path/to/br \
  cargo test --locked --offline -p fgit-cli --bin fg \
  agent_tasks::beads_tests::native::real_br_two_clients_history_and_fresh_process_reconciliation \
  -- --ignored --nocapture
```

It never reads or mutates the repository's authoritative tracker. These focused
checks do not establish the unimplemented exact-store or agent-execution claims.
