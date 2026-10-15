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
node --test tests/operator/github-issue-inventory.test.mjs
```

The tests execute the production discovery/codec/selection and shared HTTP
lifetime with response-schema fixtures, including 10,000 records, all-PR and
empty populations, full-width aliases, exact budgets, changed populations,
malformed pages, hostile continuation, source retry, cancellation and pin refusal.
They are not live GitHub, Rust `fg`, full-workspace or physical-durability evidence.
No compatibility/import bead is closed by this bounded selection slice.
