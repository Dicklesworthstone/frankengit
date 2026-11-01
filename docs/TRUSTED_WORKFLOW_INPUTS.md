# Nested source inputs for trusted workflows

Trusted workflows can select exact repository files and nested directory
prefixes. A component run can materialize `crates/component` without copying
every other crate, and can select one workflow file without copying unrelated
workflow definitions. This applies to canonical source, unpublished candidates,
merge candidates, directory dispatch, durable watches, and the HTTP service's
operator-configured workflow worker.

## Selecting a component

The following is a command template. Replace the storage, tenant, repository,
private run parent, and paths with the actual values for the repository. Select
all source and configuration files the component needs.

```sh
fg workflow run "$STORAGE" "$TENANT" "$REPOSITORY" refs/heads/main \
  --trusted-local \
  --workflow .github/workflows/component.yml \
  --input .github/workflows/component.yml \
  --input crates/component \
  --input Cargo.toml --input Cargo.lock \
  --run-parent "$RUN_PARENT" \
  --run-id 8b8e4a9328dc468489b0ea348cf3c561
```

Use a fresh run ID for an intentionally new execution, following the existing
[execution and recovery rules](TRUSTED_WORKFLOW_EXECUTION.md). Reusing this
example ID after an attempt already exists does not authorize another run.

For directory dispatch or a watch, the selected inputs must cover the workflow
**directory**. For example, use `--workflow .github/workflows --input
.github/workflows`. Selecting only `.github/workflows/component.yml` covers a
single-file run, but does not cover that directory for discovery.

The equivalent HTTP workflow service selectors are:

```text
--workflow-dir .github/workflows
--workflow-input .github/workflows
--workflow-input crates/component
--workflow-input Cargo.toml
--workflow-input Cargo.lock
```

These are operator service options, not request-supplied execution settings.
The remaining explicit trust, credential, readiness, custody, and stop controls
are described in [the service guide](NATIVE_HTTP_WORKFLOW_SERVICE.md).

## Exact selection and bounds

Inputs are literal, normalized repository paths, not glob patterns. A directory
selects its descendants. An exact file selects only that file. Paths remain
byte-valued; standalone workflow commands support `--input-hex` for native
names that are not conveniently represented as text.

Selections must be distinct and must not overlap. For example, `crates` together
with `crates/component` refuses; choose the breadth that is actually required.
`crates/component` and `crates/component-old` are separate paths and are allowed.
Absolute paths, empty components, `.` or `..` components, repeated or trailing
slashes, and invalid native paths refuse before workflow execution.

The existing bounds remain: standalone workflow commands accept at most 1024
input prefixes and at most 64 KiB of combined prefix bytes; the HTTP service CLI
accepts at most 64 prefixes within that byte bound. Source manifests still have
the existing entry, per-file, total-byte, and aggregate job-materialization
limits. Nested selection reduces the selected inventory rather than increasing
those limits.

## Traversal and workspace behavior

TreeFS verifies the parent trees needed to reach a selected descendant and
creates its parent directories in each job workspace. That traversal does not
grant permission to read a parent as a file, list unrelated siblings, or fetch
their payloads. A file, symlink, or submodule encountered where a parent directory
is required refuses the traversal. Capability expiry, revocation, object
identity verification, and fetch accounting still apply.

Canonical and candidate workflows use the same sparse selection. Candidate
inputs come from the actual verified candidate tree. Each job still receives
private writable inodes; the existing verified reflink cache or private-copy
fallback can share immutable source extents without sharing job edits. Reports
retain the exact declared input paths and source coordinates.

Inputs select materialized repository content. Trusted scripts continue to run
as the host user, with the existing trusted-local execution model. A narrower
input selection does not create a process sandbox or change publication,
approval, check, or source-write authority. Retained watch execution intents
continue to require their original configuration when recovering an attempt.
