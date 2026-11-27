# Remote milestone and release planning

`node scripts/forge_milestones.mjs` exposes the native milestone lifecycle from a
remote terminal. It creates, edits, closes and reopens milestones, reads bounded
lists and histories with member-issue counts, and recovers uncertain writes
through their original durable request records. Issue membership and filtering
are available through `scripts/forge_issues.mjs`.

The operator uses the shipped `MilestoneClient`, native request codecs and
shared private-record custody. The authoritative behavior remains
[Native milestones](NATIVE_MILESTONES.md) and
[Normative protocol contracts §20.2.4](NORMATIVE_PROTOCOL_CONTRACTS.md#2024-native-milestones-and-issue-membership).

## Connection and credentials

Use the exact repository URL ending in `/ui/milestones/`. The existing
`/ui/issues/` selector is also accepted for milestone operations. HTTPS is
required except for explicit loopback HTTP. Tenant and repository identifiers
are 32 lowercase hexadecimal characters. The server authenticates the principal.

Token files contain a 64-character lowercase hexadecimal repository token, or a
sponsored `fgagent_` token followed by 64 lowercase hexadecimal characters,
with at most one final LF. Token files, body files and recovery records must be
regular, single-link files owned by the current user with no group/other
permissions. Recovery-record parent directories must already exist, belong to
the current user, and have no group/other permissions. These custody checks use
the supported Unix profile.

| Operation | Repository-token grants | Sponsored-credential scopes |
| --- | --- | --- |
| Milestone list/show | `issues-read` | `milestones-read` |
| Fresh milestone lifecycle write | `issues-read` and `issues-write` | `milestones-read` and `milestones-write` |
| Issue membership write | `issues-read` and `issues-write` | `issues-read` and `issues-write` |
| Observe an original outcome | `outcomes-read` | `outcomes-read` |
| Retry after an unresolved outcome | `outcomes-read` and the original family's write grant | `outcomes-read` and the original family's write scope |

A write grant does not imply read. Fresh writes read the exact entity/version
before saving custody; explicit recovery observes the original outcome first.
Issue membership does not perform an extra milestone read: the native
transaction checks the caller's exact target version atomically.

For the examples below, set the connection values and existing private paths
for your deployment. Keep credentials in the token file. These shell helpers
pass the supplied operation and fields directly to the CLI:

```bash
milestone_url=https://forge.example/team/repository/ui/milestones/
issue_url=https://forge.example/team/repository/ui/issues/
tenant_id=0123456789abcdef0123456789abcdef
repository_id=fedcba9876543210fedcba9876543210
credential_file=/private/frankengit/token
custody_dir=/private/frankengit/requests

milestones() {
  node scripts/forge_milestones.mjs "$@" \
    --url "$milestone_url" --tenant-id "$tenant_id" \
    --repository-id "$repository_id" --token-file "$credential_file"
}
issues() {
  node scripts/forge_issues.mjs "$@" \
    --url "$issue_url" --tenant-id "$tenant_id" \
    --repository-id "$repository_id" --token-file "$credential_file"
}
```

## Create and maintain a release plan

Milestone numbers are positive safe integers in this client. Opening a new
number requires expected version zero; every later mutation supplies the exact
observed positive version. Read the current milestone before choosing each
version, especially when multiple planners are active.

```bash
milestones open --number 7 --expected-version 0 \
  --title 'Next release' --body-file /private/frankengit/release-plan.txt \
  --due-at 1893456000 --record "$custody_dir/release-7-open.json"

milestones show --number 7

milestones edit --number 7 --expected-version 1 \
  --title 'Next release candidate' --clear-due-at \
  --record "$custody_dir/release-7-edit.json"

milestones close --number 7 --expected-version 2 \
  --record "$custody_dir/release-7-close.json"

milestones reopen --number 7 --expected-version 3 \
  --record "$custody_dir/release-7-reopen.json"
```

Titles must be nonblank, single-line text within 256 UTF-8 bytes. Bodies accept
up to 65,536 UTF-8 bytes, preserve literal text and reject NUL. An omitted body
defaults to empty on open. On edit, omitted fields retain their current values;
`--body ''` or an empty private body file clears the body. `--body` and
`--body-file` are mutually exclusive. Body files must contain valid UTF-8.

`--due-at` accepts UTC Unix seconds from `0` through `253402300799`.
Omitting it on open creates an undated milestone. Omitting it on edit preserves
the existing date; `--clear-due-at` explicitly removes it. Clearing is an edit
operation and cannot be combined with `--due-at`. Empty edits and fields that
do not apply to an operation are refused before network access.

A closed milestone can still be edited. Closing and reopening affect milestone
metadata only: member issue state, locks and membership remain unchanged.

## Assign issues and find unplanned work

Adding an issue to a milestone requires both the exact current issue version
and the exact version of an open target milestone. For example, after the
lifecycle above reaches milestone version four:

```bash
issues set-milestone --number 14 --expected-version 6 \
  --milestone 7 --expected-milestone-version 4 \
  --record "$custody_dir/issue-14-release-7.json"

issues search --milestone 7 --state open --label bug --max-pages 5
issues search --milestone none --state open --max-pages 5

issues clear-milestone --number 14 --expected-version 7 \
  --record "$custody_dir/issue-14-clear-release.json"
```

The native transaction checks issue and target milestone versions against the
same authority basis. A missing or stale target returns `EvidenceStale`; a
closed target returns `ProtectedRefTransitionDenied`. The operator retains
that terminal decision and does not refresh versions or invent a new request.

Membership changes are allowed on open, closed and locked issues. They advance
the issue version and preserve its other metadata. Clearing requires the exact
issue version and no target milestone version. It remains available after the
target closes. Neither operation changes the milestone's version.

`search --milestone N` selects one milestone; `search --milestone none`
selects issues without membership. This filter intersects with the existing
state, opening-principal, literal-text and label filters. Search continuations
retain the complete predicate, scan budget and snapshot token. Strict
`comment` and independent `append-comment` keep their existing grammars.

## Bounded, snapshot-pinned reads

`list` returns milestone rows including `due_at`, state,
`open_issues` and `closed_issues`. `show --number N` returns the current
milestone and its ordered lifecycle history. A missing number returns a checked
`found: false` response with no milestone or events.

Reads default to one page of 20 records. A page size can be 1–100; the maximum
page budget is 100. Use a finite budget appropriate for the invocation:

```bash
milestones list --limit 20 --max-pages 5
milestones show --number 7 --limit 20 --max-pages 5
```

A bounded prefix exits with code 4 and includes `complete: false`,
`stop_reason: "page_budget"` and a `continuation`. Copy its
`expected_head` into `--expected-head` and `after` into `--after`.
For a history continuation, also keep the same milestone number. A nonzero
cursor without its original snapshot is rejected.

```bash
milestones list --after "$next_after" --expected-head "$snapshot_token" \
  --limit 20 --max-pages 5
milestones show --number 7 --after "$next_version" \
  --expected-head "$snapshot_token" --limit 20 --max-pages 5
```

The first response pins all later pages to the same repository snapshot.
Milestone counts are derived from issue membership at that snapshot. Counts
can change when issues change even while the milestone's metadata version stays
the same; the snapshot token is the read boundary.

The native client validates response identity, family, counts, cursor
progression and history continuity. The CLI emits checked canonical text and
fields, omitting rendered HTML and unknown response extensions. A malformed or
failed later page fails the entire read, so an incomplete prefix is not
reported as a complete answer.

`--max-output-bytes` bounds the aggregate serialized output, including the
envelope, up to 8 MiB. Every command accepts `--timeout-ms` from 1 through
300,000, defaulting to 30,000, for the whole operation. Reads never create a
mutation record or submit a mutation.

## Recover uncertain writes

Each fresh mutation requires a new `--record` path. Before sending, the
operator validates the exact repository/version, saves and synchronizes the
original native request/key to that private record, and establishes the
sender's durability barrier. Existing records are never overwritten. Records
contain the exact request, including private text, and a credential fingerprint;
they do not contain the bearer credential.

After a lost response, interruption or unknown outcome, keep the record and
the original connection selection:

```bash
milestones status --record "$custody_dir/release-7-open.json"
milestones retry --record "$custody_dir/release-7-open.json"

issues status --record "$custody_dir/issue-14-release-7.json"
issues retry --record "$custody_dir/issue-14-release-7.json"
```

`status` only observes. `retry` observes first and, if still unresolved,
may resend the exact original request and key once. A known committed or
refused outcome is returned without another mutation. An absent outcome does
not establish non-commit. Recovery does not accept replacement entity numbers,
versions or fields, and it does not infer a new intent from current metadata.

Use the original token and exact URL spelling, including the original
`/ui/issues/` or `/ui/milestones/` selector. Changing credentials, repository
identity, family or record contents cannot reinterpret the saved request.

| Exit | Meaning |
| --- | --- |
| 0 | Observed committed terminal outcome, or complete read |
| 2 | Unknown outcome, validation/transport/output failure, or cancellation |
| 3 | Observed native terminal refusal |
| 4 | Checked bounded read prefix with an explicit continuation |

The CLI emits bounded JSON; literal control characters are escaped. Error
diagnostics retain recovery state and record identity without echoing private
request bodies or bearer tokens.

## Verification scope

The focused Node tests exercise the production CLI, native browser request and
response validation, private custody, real child processes and HTTP sockets
against the repository's explicit response-schema milestone peer:

```bash
node --test tests/operator/forge-milestones.test.mjs \
  tests/operator/forge-milestones-read.test.mjs \
  tests/operator/forge-issues-milestones.test.mjs \
  tests/operator/forge_milestone_operator.test.mjs
```

Those peers simulate native responses; they do not establish Rust authority
integration or production deployment evidence. Native authority behavior is
covered by the owning milestone and issue engine/server tests referenced in
[Native milestones](NATIVE_MILESTONES.md).
