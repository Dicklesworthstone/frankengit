# Local source import size profiles

`fg import` uses bounded disk-backed quarantine for reachable native object
bodies. The complete required-kind graph validates before the first fabric
placement. Exact spool bytes are re-identified before immutable placement;
mutable source paths are never reread after validation. Ref publication still
uses the original sealed admission and authority-head compare-and-swap path.

The default reachable-body ceiling remains **512 MiB**. A trusted local operator
may explicitly choose a ceiling from 1 to 16,384 MiB:

```sh
fg import ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  33333333333333333333333333333333 \
  migration-20261016 ./source.git --max-expanded-mib 1024 --json
```

The principal and idempotency key have their existing trusted-local semantics.
The byte limit does not become part of transaction identity: equivalent source
refs retried under another sufficient profile resolve the same terminal result.
A smaller limit can refuse before publication and leaves canonical refs unchanged.
An interruption during publication remains ambiguous; recover using `fg outcome`
or the original source and key, rather than assuming rollback.

The profile reserves one finite deadline/poll/cost allowance before source I/O,
using the existing receive work-scaling policy. `--timeout-secs` is a strict
wall-clock ceiling, not a base that the larger profile extends. No phase mints a
replacement context. The library exposes `import_request_context_with_byte_limit`
and `import_loose_git_directory_with_byte_limit_durable_in`; callers pass the same
byte ceiling to both, and smaller or cancelled caller contexts are still honored.

This does **not** raise independent per-object, compressed-input, pack-cache,
index, object-count, graph-edge or ref limits. In particular, the existing
64 MiB per-pack and 128 MiB aggregate hydrated-pack limits remain. A large loose
source and a large single pack are different profiles. The 16 GiB ceiling is an
operator bound, not a claim that every repository of that size was tested.

Quarantine uses one file and bounded offset/type metadata, not one file or
resident body per object. On Unix the exclusive 0600 file is unlinked before
payload writes; the owned descriptor survives until cleanup. An interruption
between exclusive creation and unlink can leave an empty name. Other platforms
remove the exclusive filename on normal cleanup, without claiming crash cleanup
or isolation from a malicious local host. Scratch custody is not a backup,
resumable import, or durability receipt. Immutable placement retains its existing
durability protocol; disk exhaustion and damaged spool bytes fail closed.

## Executable coverage

```sh
cargo test -p fgit-node --lib loose_import:: -- --test-threads=2
cargo test -p fgit-cli --bin fg import_command:: -- --test-threads=2
cargo test -p fgit-node --test large_loose_import -- --test-threads=1
FG_BIN=/path/to/fg bash scripts/e2e/suites/admission/import_profiles.sh
FG_BIN=/path/to/fg bash scripts/e2e/suites/admission/import_recovery.sh
```

The large integration target contains a 288 MiB default-profile round trip and
an explicit-profile 576 MiB round trip. Both use real durable admission, remove
the source directory, reopen the node, and re-verify exact native objects and refs.
The binary suite pairs a 1 MiB refusal with a 4 MiB admission for the same 2 MiB
source in SHA-1 and SHA-256, then checks larger-profile and default-profile replay
and source-free outcome recovery. Test presence is not a completed batch gate;
executed results remain revision-bound.
