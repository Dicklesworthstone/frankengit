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
  [--timeout-secs <positive-integer>]
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
cargo test -p fgit-cli --bin fg import_command::tests
```

No test execution or bead-closure claim is made by this document.
