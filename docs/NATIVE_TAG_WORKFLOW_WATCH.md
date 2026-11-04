# Native release-tag workflows

Related: `frankengit-root-doctrine-x2mv.4.12`,
[native ref watching](NATIVE_REF_WORKFLOW_WATCH.md),
[branch filters](NATIVE_WORKFLOW_BRANCH_FILTERS.md), and
[completed-watch recovery](NATIVE_WORKFLOW_WATCH_RECOVERY.md).

Native trusted-local workflows can execute the commit selected by an explicit
`refs/tags/*` reference. Lightweight, annotated, and nested annotated tags use
the existing native tag reader; no Git subprocess or external CI service selects
their source. The operator must trust the selected scripts with host-user
privileges, as with branch workflows.

## Select release tags

```yaml
name: release
on:
  push:
    tags:
      - 'v*'
      - '!v*-rc*'
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - run: ./release.sh
```

`tags` is an ordered inclusion list: a later leading `!` pattern excludes, and a
later positive pattern may reinclude. At least one positive pattern is required.
`tags-ignore` excludes matches and accepts other tag names; it cannot contain
leading `!` or coexist with `tags` on the same event. Only `push` admits tag
filters. Tag filters on `pull_request` or `workflow_dispatch` refuse compilation.

The namespace is part of selection:

| Push declaration | Branch pushes | Tag pushes |
| --- | --- | --- |
| No branch or tag filters | Selected | Selected |
| Only `branches` / `branches-ignore` | Apply branch filter | Excluded |
| Only `tags` / `tags-ignore` | Excluded | Apply tag filter |
| Both branch and tag filters | Apply branch filter | Apply tag filter |

Patterns match the exact bytes after `refs/tags/`. Case and UTF-8 spelling are
not normalized. `*` does not cross `/`; `**` may cross it, and component-boundary
`**/` also matches zero directories. Bounds are 32 patterns, 256 bytes per pattern,
4096 aggregate pattern bytes per filter, and 1024 reference bytes. Unsupported
operators, malformed mappings, expressions, and over-budget patterns refuse with
a source span. Matching remains bounded and cancellable.

Tag pushes do not evaluate `paths` or `paths-ignore`, including when those fields
appear alongside `tags`. They do not invent a branch diff for the release commit.
Branch and PR path filters retain their complete changed-path requirements.
Single-workflow manual `run` commands still execute the requested workflow without
consulting event filters.

Graphs containing explicit tag filters use `fgit-workflow/v7`; their ordered
`trigger-tag` records commit the mode and patterns. Existing graphs without tag
filters retain their prior v1-v6 canonical bytes. An old compiler refuses the new
mapping instead of silently ignoring tag selection.

## Run a native watcher

```sh
fg --timeout-secs 300 workflow watch NODE TENANT REPOSITORY refs/tags/v1.2.3 \
  --trusted-local --workflow ci --input ci --input release.sh \
  --run-parent /private/runs
```

The run parent must already be a private, nonsymlink `0700` directory. Declare all
source paths the workflow needs. Existing artifact capture, log capture, output
budgets, and finite polling flags apply. `--ref-hex` preserves raw reference bytes.
`--object-format sha256` selects a SHA-256 repository.

For continued observation of that same explicit tag, use:

```sh
fg workflow watch NODE TENANT REPOSITORY refs/tags/v1.2.3 \
  --trusted-local --workflow ci --input ci --input release.sh \
  --run-parent /private/runs --continuous \
  --stop-file /private/control/release.stop --attempt-timeout-secs 300
```

The normal stop-file, signal, finite-attempt, and permanent-custody rules apply.
The HTTP workflow controller also accepts an ordinary tag selection through
`--workflow-ref refs/tags/v1.2.3` with its existing operator configuration. This
does not add discovery of all tags or a remote execution endpoint.

Tag watches reject automatic canonical check publication, PR selection, PR
collection, merge queues, and merge candidates before opening the service or
starting execution. Those profiles currently bind branch references. Their
existing branch behavior remains available. In particular, a tag run is not a
branch-protection check or permission to land a release.

## Exact source identity and recovery

The source reader verifies tag objects against the authenticated canonical
closure, native object identities, and every declared target kind. Peeling is
bounded to 64 annotations, 1 MiB per object, and 4 MiB aggregate, including the
terminal commit body even for lightweight tags. A blob/tree tag,
missing target, malformed annotation, cycle, hidden reference, or stale snapshot
cannot start a workflow. Both SHA-1 and SHA-256 repositories follow the same path.

The selected authority head and raw tag tip remain pinned while the workflow
snapshot is opened. `source_commit` and `source_tree` describe the peeled commit
actually executed. Tag dispatch plans, attempt markers, and reports additionally
carry `source_tag_tip`, including for lightweight tags. Explicit expected-commit
pins name the peeled commit. Branch/candidate identities omit the new field and
retain their historical bytes.

The watcher selects the latest authenticated ref-change decision and writes the
`latest-canonical-tag-update-v1` event profile. Its event records `tag_tip`,
`previous_tag_tip`, and the peeled `commit`. The previous raw tip may be null after
a creation or a deletion. A changed annotation can produce a new event even when
its peeled commit is unchanged. Unrelated repository decisions do not retrigger
the tag. This remains latest-state observation: intermediate updates missed
between polls are coalesced.

Restart suppression and unresolved-event fencing use the existing durable
dispatcher, job journals, and completion handoff. A missing final settlement is
recoverable only when the original completion records verify. Recovery checks the
raw tag tip across the event, dispatch, and attempt, as well as the original head,
peeled commit, workflow graph, and journal bindings. Replacing a raw annotation
OID with its peeled commit is a mismatch. Recovery never reruns a script.

## Verification commands

The schema regression suite includes `workflow_tags` and the existing workflow
targets. The generated construct artifact is checked by `fgit-schema-gen check`.
Native tests use actual tag admission and process execution, covering tag shapes,
both object formats, raw/peeled identity, path selection, reannotation, stale pins,
restart suppression, interruption fencing, and tampered settlement metadata:

```sh
cargo test --locked -p fgit-schema --test workflow_tags --test workflow_triggers
cargo run --locked -p fgit-schema --bin fgit-schema-gen -- check
cargo test --locked -p fgit-node --lib durable::tests::tag_tests -- --test-threads=1
cargo test --locked -p fgit-node --lib trigger::service::tests -- --test-threads=1
cargo test --locked -p fgit-node --test trusted_ref_workflow -- --test-threads=1
cargo test --locked -p fgit-cli --bin fg workflow_command::watch
```

Native process tests require a Linux environment with `/proc` mounted for the
same PID namespace as the test process. A mismatched process view cannot prove
process-group completion or provide the runner's descriptor-backed input paths.
