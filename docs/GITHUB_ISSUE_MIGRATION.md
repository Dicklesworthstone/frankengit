# Complete pinned issue-migration preparation

FG-049's external operator composes the existing issue importer across every
batch in one independently pinned inventory. It does not implement Git, add
repository authority, or convert GitHub authors into native principals.

`prepareGithubIssueMigration` in `scripts/lib/github-issue-migration.mjs` accepts
an inventory path and its independently retained SHA-256, an explicit complete
array of `{ batch, path, sha256 }` captures, a new work directory, one destination
URL/tenant/repository, an explicit native token file and one number offset.
Every capture requires its own retained digest. The fixed inventory partition
must be covered exactly once; empty populations, duplicate/missing batches,
changed repository/issue aliases, repeated comment identities, unrepresentable
native commands and resource overflow refuse before native request preparation.

The preparer first owns all validated capture bytes. It then creates a private
directory containing `inventory.json`, `capture-NNNNNN.json`, and the existing
importer's `batch-NNNNNN/` directories. Those children retain the unchanged
capture, manifest and original per-step request/key formats. No HTTP request is
made by preparation. The final `migration.json` binds every input digest,
child-plan digest, offset, destination, count and byte total. It is written last,
after complete child readback, through the existing synced create-only writer.
Retain the returned migration `plan_sha256` independently for subsequent use.

`inspectGithubIssueMigration` revalidates the root, complete inventory, every
capture and every child request against that pin and the original native
credential, without network access. The shared child verifier is
`inspectPreparedGithubIssueImport`; it is also available for a single existing
prepared batch. Synchronizing immutable custody is not a canonical outcome
query and does not establish that any mutation was submitted or committed.

A completed migration directory no longer depends on the original inventory or
capture locations. Keep the entire directory and the original credential. Never
reprepare a submitted or uncertain child with new keys. A failed preparation
retains its incomplete directory and original child keys, without a runnable
migration root; it cannot be overwritten as a retry. Child plans remain in the
existing importer format for explicit diagnosis, not automatic fallback.

## Bounds and trust

The profile permits at most 128 fixed batches, 64 MiB of captured source,
128 MiB of saved native request records and 10,000 native mutation steps. Each
child keeps the existing 100-issue, 2,000-comment, 1-MiB capture and 16-MiB request
ceilings. A caller may lower capture/request/step budgets. The remaining global
request-byte allowance is passed into each child's writer, so a failing child
cannot overspend the session's saved-request bound. This option leaves existing
single-batch callers and their manifest format unchanged.

Preparation and inspection have one finite, cooperative operation deadline;
child calls share the parent's cancellation signal. Source files must be private,
owner-controlled regular files with one link. Output directories are private and
create-only. Roots and children may not be redirected through symlinks; exposed
preparation callbacks are synchronous and followed by root-identity checks.
These controls are not a hostile same-UID sandbox or a power-loss durability
proof. The operator must keep the custody tree stable and protect its independent
pins and native credential.

This is issue-only migration, not an atomic GitHub snapshot, a cross-batch
transaction, PR/review import, attachment migration or permission import.
The broader FG-049 bead remains open. Focused tests use actual private files and
production capture/import helpers. They do not run Rust fg or establish native
authority, full-product compatibility or physical crash durability.
