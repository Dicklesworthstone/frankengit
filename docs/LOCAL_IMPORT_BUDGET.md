# Local source-import work budget

Bridge work: `frankengit-root-doctrine-x2mv.4.28`.

The `fg import` binary entrypoint uses `OneNode::import_request_context` before
reading the local source. The context is retained through source validation,
immutable placement, sealing, admission retries and head publication. No fresh
context is created after preparation; an exhausted caller cannot resume with a
new allowance inside the operation.

```text
fg import <storage-root> <tenant-id> <repository-id> <principal-id> <key> <source>
  [--expected-incarnation <incarnation-id>]
  [--timeout-secs <positive-integer>] [--json]
```

Without an explicit timeout, the node reserves its existing bounded import
profile (128 MiB of expanded object bodies) using the receive session's base,
per-byte rate and maximum extension. It also uses the existing receive-admission
poll and cost calculation, rather than the ordinary Database class's flat
15-second / 50,000-poll allowance. This is an up-front resource reservation,
not a claim that source bytes have already been read or admitted. The existing
source validator enforces the same expanded-byte bound.

With `--timeout-secs`, the chosen duration is a strict operation ceiling: reserved
bytes do not extend it. Native runtime root bounds continue to apply. Opening
and shutting down the embedded node keep their separate existing lifecycle
budgets; the import deadline begins immediately before source work.

The command preserves the positional import syntax, existing-repository object
format selection, optional exact incarnation binding, explicit caller principal
and retry key, native source validation and establish-if-absent admission.
Unknown/duplicate options, malformed identities and invalid timeouts fail before
opening the node. Successful text output remains `published N source-import ref
commands`. Output or shutdown failure after a known commit explicitly says that
publication occurred; interruption during admission is never labelled rollback.

Library callers should mint `node.import_request_context(None)` (or supply an
explicit `GitDaemonSessionTimeout`) and pass it to
`import_loose_git_directory_durable_in`. That `_in` API still honors arbitrary
caller-owned contexts unchanged. The older `fgit_cli::run` library dispatcher
retains its legacy context; the executable routes import to the dedicated
command module, as it does for other extended commands.

## Limits and evidence

This does not enlarge the import's 128 MiB aggregate body limit, 32 MiB default
individual-object limit, pack/index limits or object-count limit. It does not
claim the bead's multi-hundred-MiB acceptance, remote identity integration or a
completed durability profile. Source validation and one head CAS remain the
publication boundary; local object placement is not publication.

Focused tests cover strict versus scaled timeouts, custom scaling and its hard
ceiling, finite native budgets, expiry before source I/O with unchanged head,
and option/refusal twins. These tests must be executed at the candidate revision:

```sh
cargo test -p fgit-node --lib loose_import::control::budget::tests
cargo test -p fgit-cli --bin fg import_command::
```

No test execution or bead-closure claim is made by this document.

## Machine-readable, recoverable outcomes

Add `--json` after the six positional arguments, in any order with the timeout
and incarnation options. A completed admission prints one
`source_import_outcome` JSON object with schema version 1. It binds the tenant,
repository, observed incarnation and principal to the exact transaction ID,
decision sequence and either Repository Commit Record ID or refusal record/code.
`atomic: true` and `command_count` describe the complete native command mapping;
empty or inconsistent mappings cannot be rendered as successful imports.

`state: "committed"` means that logical import has an authenticated terminal
commit, not that its original refs remain the latest state. A retry after a later
branch update returns the same old decision and must not rewind the branch.
`node_closed` and `cleanup_error` report shutdown separately; a known commit is
not turned into a rollback by cleanup or stdout failure. Retry keys and the
mutable source path are not copied into the receipt. Error text may still name
the local operation or filesystem path that failed.

JSON-mode exit codes are 0 for committed, 3 for canonical refusal, and 2 for
input, infrastructure, output or cleanup errors. Errors without a terminal
observation remain stderr errors, not invented terminal JSON records. Plain
mode retains the original successful text and exit behavior. No timeout, JSON
flag or source pathname participates in transaction identity.

Recover without re-reading or re-importing the source:

```sh
fg outcome <storage-root> <tenant-id> <repository-id> --trusted-local \
  --principal <original-principal-id> --idempotency-key <original-key> \
  --object-format sha1
```

Use `--object-format sha256` for SHA-256 repositories. This is the existing
read-only recovery path, not a second journal or retry engine.

The repository-owned binary campaign is:

```sh
FG_BIN=/absolute/path/to/fg bash scripts/e2e/suites/admission/import_recovery.sh
```

It constructs isolated deterministic Git fixtures, runs fresh native `fg`
processes for both object formats, and checks: complete atomic publication;
exact replay with a different timeout; changed-semantics key rejection; a later
import followed by a real fast-forward branch update; old-import replay without
rewinding the branch; canonical all-or-nothing refusal including a new ref;
legacy text output; and read-only recovery of both terminal decisions after the
source directory is made unavailable. Different-principal key lookup must not
disclose the original decision. The shared harness retains command outputs,
input identities and failure artifacts, bounds native command duration, and
records the executable digest. Missing `FG_BIN` is a non-pass.

The campaign does not claim process-death injection or multi-hundred-MiB
acceptance. Fixture validation with stock Git is not execution of FrankenGit.
The receipt renderer has focused mapping, identity, escaping, and output-failure
tests under `import_command::receipt::tests`; run them with the CLI test command
above. Neither those tests nor the binary campaign are claimed passed here.
