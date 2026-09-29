# Command time policy

Every `fg` command, and every MCP tool call, reads and writes canonical state
under one authority context with one wall-clock budget
(frankengit-root-doctrine-x2mv.4.50).

## Default

A command runs on its node's session timeout: 300 s unless the node is configured
otherwise. Before this policy existed, commands used the Database runtime class
default, a flat 15 s. On a loaded host an ordinary write such as `fg pr open`
could then end "ambiguous: cancelled after transmission" while its CAS was still
resolving.

The Database class keeps its poll and cost floors as a liveness backstop. Only the
wall clock comes from this policy. HTTP requests already work the same way, on the
session's own deadline.

## Choosing a timeout

```sh
fg --timeout-secs 30 pr open <storage-root> <tenant-id> <repository-id> ...
fg --timeout-secs 0.5 branch list <storage-root> <tenant-id> <repository-id> --trusted-local
```

- **Position:** `--timeout-secs` is a global option and must come before the
  command name. A command's own options, such as `fg import --timeout-secs` or
  `fg backup ... --timeout-secs`, still govern that command's own work and are
  separate from this one.
- **Value:** positive decimal seconds, with at most nine fractional digits. Zero,
  a missing value, signs, units, exponents and repeats are refused with exit 2,
  and the message names the option, before any work starts.
- **Expiry:** when the timeout expires, a write ends with the command's typed
  non-terminal result (for example "no terminal branch outcome returned ... this
  is not evidence of non-commit") and never reports success. Resolve it read-only
  with `fg outcome` using the original key, or retry the identical command.
  Either way it reaches exactly one terminal decision.

## Evidence

- `crates/fgit-node/src/lib.rs`, `tests::a_command_runs_on_one_operator_clock_with_database_floors`:
  - the default command clock is the session timeout, not 15 s;
  - the class poll floor is kept;
  - an explicit timeout is the ceiling;
  - a tiny timeout expires and refuses a real authority read, and the default twin reads the head.
- `crates/fgit-cli/src/lib.rs`, `command_time_policy_tests`:
  - option parsing, with its refusals;
  - a source scan that fails if any non-test CLI or MCP code mints the class-default context.
- `scripts/e2e/suites/node/command_time_policy.sh`, driving the real `fg` and git:
  - a microsecond budget gives the typed ambiguous outcome;
  - `fg outcome` reports non-terminal (4);
  - the identical retry commits, `fg outcome` then reports committed (0), a second retry returns the same decision, and exactly one branch exists.

## Non-claims

The default does not make every command finish on every host. It bounds each
command by the operator's session timeout instead of a 15 s class constant. A
timeout never proves that a write did not commit.
