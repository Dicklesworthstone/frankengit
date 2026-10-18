# Pinned repository-wide GitHub issue discovery

FG-049 (`frankengit-fg049-github-compat-xdo`), plan §31.3 and migration risk R20.
The existing importer captures at most 100 explicitly named issues per package.
`discoverGithubIssues` adds bounded repository-wide selection without changing
native issue limits, identity, authorization, or publication/retry custody.
This is an external Node operator adapter, not a replacement Git or forge engine.

## Selection and provenance

`scripts/lib/github-issue-inventory.mjs` reads the repository issues endpoint with
`state=all`, `sort=created`, `direction=asc`, and `per_page=100`. It consumes every
observed page, verifies repository identity before and after each enumeration,
and requires two equal complete populations. Rows are normalized by issue number:
transferred issues and tied creation times need not arrive in numerical order.
Duplicate IDs or numbers, including across pages and entity kinds, refuse instead
of silently dropping rows. Full pages without a next link get a further probe;
a short or empty terminal page ends that enumeration.

GitHub lists pull requests through its issues endpoint. These are explicitly
retained under `excluded_pull_requests`, never converted into native issues.
Their `issue_id` is the GitHub **issue alias**, not a pull-request API ID.
The inventory retains issue numbers, exact decimal-string issue/repository IDs,
repository name, fixed batch size, exclusions, and its consistency declaration.
It contains no issue bodies, credentials, imported principals, or permissions.

`complete: true` means both bounded API enumerations terminated and agreed; it
is not an atomic GitHub snapshot, an independent proof of completeness, or a
claim to enumerate entities the credential cannot see. Quiesce source edits and
keep the same intended source visibility during migration. A malicious server,
concurrent delete/recreate cycle, or consistently withheld content is not ruled
out by two equal observations. Discovery does not capture issue/comment bodies;
those are freshly verified by the existing capture path.

## API

```js
import { discoverGithubIssues, parseIssueInventory, selectIssueInventoryBatch }
  from './scripts/lib/github-issue-inventory.mjs';

const discovered = await discoverGithubIssues({
  repository: 'owner/project', batchSize: 25, signal,
  // token: explicitly supplied GitHub read credential, never persisted
});
// Preserve discovered.bytes privately and retain discovered.sha256 separately.
const inventory = parseIssueInventory(discovered.bytes);
const selection = selectIssueInventoryBatch(inventory, discovered.sha256, 1);
```

Batch numbers are one-based. The batch size is part of the pinned inventory,
not a per-retry option; the final batch can be shorter. `selection` owns the
source identity and `(number, id)` pairs plus `numbers`, `next_batch`, and
`total_batches`. Selection alone does not capture, submit, or acknowledge a
native mutation. An empty or all-PR repository has zero batches; requesting a
batch refuses rather than constructing an empty import. A wrong independent
SHA-256 pin refuses before selection can be used for network work.

The SHA-256 pin detects substitution against the operator's independently
retained value, not GitHub authenticity. Do not recompute an approval from the
same untrusted file you are approving. Stored records are strict canonical JSON
plus one newline: hidden fields, alternate number encodings, duplicate keys,
noncanonical order, BOM, trailing data and oversized/shared buffers refuse.

## Command workflow and native import handoff

All three operations run through the existing issue-import command. Use a
private, owner-controlled output directory. Source access is read-only; a native
credential is neither needed nor accepted for inventory inspection.

```sh
node scripts/import_github_issues.mjs discover \
  --repository OWNER/REPO --out /private/migration/inventory.json \
  --batch-size 25 --token-file /private/github-read-token

# Set INVENTORY_SHA to the independently retained sha256 from discovery.
# Do not derive this approval from a replacement copy of the inventory.
node scripts/import_github_issues.mjs inspect-inventory \
  --inventory /private/migration/inventory.json --confirm "$INVENTORY_SHA"

node scripts/import_github_issues.mjs capture-batch \
  --inventory /private/migration/inventory.json --confirm "$INVENTORY_SHA" \
  --batch 1 --out /private/migration/capture-1.json \
  --token-file /private/github-read-token

node scripts/import_github_issues.mjs inspect \
  --capture /private/migration/capture-1.json
```

`discover` reports issue/exclusion counts, fixed batch size, total batches,
source identity and the saved inventory digest. `inspect-inventory` without a
batch prints the exact population, including every excluded pull-request alias.
Adding `--batch N` instead prints that fixed selection and `next_batch`. Neither
inspection reads GitHub or a native server. Empty and all-PR populations remain
inspectable but cannot produce a capture batch.

`capture-batch` first checks the private inventory, independent digest and batch
range, then reads the optional explicit GitHub token. It constrains **each**
capture pass to the original repository name/ID and selected issue number/ID
pairs. Repository substitution refuses before issue reads; issue substitution
refuses before comment reads. IDs are copied before asynchronous work. A batch
never rediscovers membership, follows an alternate repository, changes its size,
or silently includes issues created after the inventory. Captured bodies and
comments are fresh two-observation source reads, not bodies frozen at discovery.

The saved output is the unchanged `frankengit-github-issue-capture-v1` format,
including complete captured comments and attributed source metadata. The
existing `captureBytes`, `parseCapture`, `issueImportSteps`, and native command
form constraints remain the validators; this feature does not invent another
publication format. The command summary separately carries `selection`, binding
the output digest to its inventory digest, batch and exact membership. Keep that
summary with the inventory and capture for selection provenance; it is not a
native mutation receipt.

To import a reviewed capture, use the **existing**, separately authorized phases:

```sh
node scripts/import_github_issues.mjs prepare \
  --capture /private/migration/capture-1.json \
  --workdir /private/migration/native-batch-1 \
  --url https://HOST/REPOSITORY_ROUTE/ui/issues/ \
  --tenant-id TENANT_HEX --repository-id REPOSITORY_HEX \
  --token-file /private/native-issue-token

# Review and independently retain prepare's plan_sha256 as PLAN_SHA.
node scripts/import_github_issues.mjs run \
  --workdir /private/migration/native-batch-1 \
  --url https://HOST/REPOSITORY_ROUTE/ui/issues/ \
  --tenant-id TENANT_HEX --repository-id REPOSITORY_HEX \
  --token-file /private/native-issue-token --confirm "$PLAN_SHA"
```

Use the original import command's `status` and explicit `--retry-unresolved`
semantics for uncertain native outcomes. **Do not recapture a batch, rediscover
an inventory, recreate a work directory or choose a new key to resolve an
uncertain publication.** The original importer retains the source copy and each
exact request/key. `prepare`, `run` and `status` are unchanged by this feature;
source retries do not become mutation retries. Number collisions remain native
refusals, not permission to renumber silently; the original explicit `--offset`
is available at inspection/preparation. Imports are not one atomic transaction
across issues or batches.

A later capture can resume at its original `--batch` using the same inventory and
independent pin. This resumes **source selection**, not a failed native mutation.
There is no mutable "last successful batch" cursor to become a second authority.
A newly discovered population requires separate review. Native publication of
pull requests/reviews, attachments, actor permissions and a whole-forge atomic
snapshot remain unsupported by this issue-only path.

Command arguments and numerical bounds are validated before filesystem I/O.
Outputs are create-only private records through the existing synced/readback IO
helper; existing files, output/input collisions, wrong ownership, symlink final
components and linked input files refuse. Source cancellation or failure yields
no successful package. An error during local publication can leave a retained
incomplete file; never overwrite it as a retry. A completed file survives a
failed stdout write, which exits nonzero and reports the completed result on
stderr when possible. Neither state proves any native publication.

## Budgets and failure

The inventory is at most 1 MiB and includes at most 10,000 combined issue/PR
records. `maxRecords` can lower that ceiling, never return a truncated success.
The fixed page ceiling is 101 pages per pass, including a terminal probe.
Batches contain 1–100 issues; the package's existing 1 MiB, 2,000-comment and
native text/form limits still apply. A population inventory does not promise
every batch fits those payload bounds.

All reads share the existing source HTTP owner: one operation deadline, byte
budget, request budget, explicit retry allowance, cancellation and body cleanup.
There are no automatic source retries by default. Discovery only issues GETs to
constructed `api.github.com/repos/...` paths. Link headers may use the same
repository's numeric alias, but may not change repository, query selection,
page progression, origin or credentials; their URLs are never followed.
Errors produce no successful inventory. No native mutations or attachments are
requested, no fallback source is selected, and no authentication is inferred.

## Verification scope

```sh
node --test tests/operator/github-issue-inventory.test.mjs \
  tests/operator/github-issue-batch.test.mjs \
  tests/operator/github-issue-inventory-command.test.mjs \
  tests/operator/github-issue-source.test.mjs
```

The tests execute the production discovery/codec/selection and shared HTTP
lifetime with response-schema fixtures, including 10,000 records, all-PR and
empty populations, full-width aliases, exact budgets, changed populations,
malformed pages, hostile continuation, source retry, cancellation and pin refusal.
The command tests additionally execute real processes/private files with an
explicit GitHub response fixture: discover, inspect, capture across restarts,
original capture inspection, source replacement, competing creators, SIGTERM,
deadlines and genuinely closed stdout. Batch captures are compared byte-for-byte
with the original manual-selection path and passed through the existing native
issue command proposal compiler. The unchanged capture regression target runs
alongside them. These tests do not execute `prepare`/`run` against a native forge.
They are not live GitHub, Rust `fg`, full-workspace or physical-durability evidence.
No compatibility/import bead is closed by this bounded selection slice.
