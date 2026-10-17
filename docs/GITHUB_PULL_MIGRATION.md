# GitHub pull-request migration

FG-049 (`frankengit-fg049-github-compat-xdo`), comprehensive plan §31.3.
The GitHub issue importer deliberately excludes pull requests. This separate
foreign-source profile retains PR metadata, discussion comments, submitted review
observations, and inline review locations without inventing native identities.
It reuses the existing bounded GitHub source transport and private-file custody.

## Capture and inspect

```sh
node scripts/migrate_github_pulls.mjs capture \
  --repository OWNER/REPO --pull 9 --pull 17 \
  --token-file /srv/import/github-reader.token \
  --out /srv/import/github-pulls.json

node scripts/migrate_github_pulls.mjs inspect-capture \
  --capture /srv/import/github-pulls.json --confirm "$CAPTURE_SHA256"
```

Keep the returned `capture_sha256` independently. A source token is optional for
public resources; it is never accepted as an argument value or retained in the
capture. All files are owner-private, with new output created exclusively outside
Git worktrees. Existing or partial files are not overwritten or repaired.
Inspection is offline and requires the exact capture pin. Output failure retains
the completed capture and pin rather than repeating requests. Exit 0 is success,
2 is refusal, and 4 reports retained/potentially published custody or output error.

The command captures 1–100 explicitly selected PR numbers, not an implicit whole
repository. Each observation reads the repository identity, brackets each PR's
three complete paginated streams with metadata reads, and rechecks repository
identity. Two complete normalized observations must agree. Changed tips, bodies,
review states, inline locations or repository identity cause refusal. No prefix
is called complete. This is **not an atomic GitHub snapshot**: quiesce edits while
capturing; equal observations cannot prove that no intervening change occurred.
The package retains that limitation as a machine-readable consistency field.

Pagination links may select only the next page of the same stream and selected
repository (including its numeric repository alias); requests are constructed
locally, never by following arbitrary response URLs. Discussion and inline counts
must match the bracketing metadata. Duplicate records or missing continuations
refuse. Source reads use the existing API version and source HTTP/byte/deadline
limits. No automatic source retry, attachment download or fork traversal occurs.

## Retained observations

PR fields include title/body (including null), GitHub IDs, actors, lifecycle,
draft/lock state, timestamps, exact SHA-1 head/base coordinates and repository
aliases, merge observation, labels, assignees and milestone summary. A deleted
fork is retained as a null repository, not replaced by an invented source repo.
Each submitted review retains its author, decision, body, reviewed commit and
submission time. Inline comments retain literal path/diff hunk/body, original
and current commit/line/side/position fields, review ID and reply-to ID. These
locations are historical observations, not recreated native anchored reviews.
Pending/unsubmitted or unknown review states refuse; finish or discard pending
reviews before capturing. Nullable authors and outdated locations remain null.

Only named fields are retained. Requested teams/reviewers, reactions, attachments,
checks, files/commit inventories, edits/deletions, hidden or inaccessible data and
timeline events are outside this profile. No Git objects are downloaded. Source
URLs are provenance only and are never authority. The SHA-1 input profile refuses
other hash domains rather than translating object IDs. No active approval, merge
permission, policy, timestamped native audit history or principal is imported.

## Bounds and verification

At most 100 PRs, 2,000 total discussion/review/inline records and 1 MiB of normalized
capture content. Source response bytes and requests are cumulative across both
observations (defaults 64 MiB and 4,096 requests; configurable lower request bound
and source byte allowance up to the existing 256 MiB ceiling). An individual
response retains the shared transport's 8 MiB ceiling. A command deadline is
1–300,000 ms, including local preflight and output. Data exceeding a limit refuses,
never truncates. The output file is not a canonical backup or a signed source proof.

```sh
bash scripts/verify_github_pull_migration.sh
```

Tests run the unchanged production GitHub transport and file helpers with actual
loopback HTTP response-schema peers, plus fresh Node CLI processes. A test-only
fetch adapter maps the fixed api.github.com origin to the local peer; the product
has no custom source endpoint or URL override. Tests cover three-stream pagination,
changed observations, scope/refusal/budgets, offline inspection, broken output,
and real SIGTERM/SIGINT/SIGKILL during incomplete responses. They do not contact
GitHub live, exercise native Rust admission/CAS or establish hardware durability.

Protocol references: GitHub's REST documentation for [PRs](https://docs.github.com/en/rest/pulls/pulls),
[reviews](https://docs.github.com/en/rest/pulls/reviews),
[inline comments](https://docs.github.com/en/rest/pulls/comments), and
[discussion comments](https://docs.github.com/en/rest/issues/comments).
