# Remote default-branch administration

`node scripts/forge_default_branch.mjs` reads canonical symbolic `HEAD`,
lists branch candidates and selects an existing default branch through the
native administrator API. This determines what ordinary Git clones check out
and which branch the native default-branch deletion guard protects.

The operator uses the shipped `DefaultBranchClient`, its restricted transport
and native validators, and shared synchronized private-file custody. The
authoritative contracts remain [HTTP default-branch administration](HTTP_DEFAULT_BRANCH_API.md)
and [normative §16.6](NORMATIVE_PROTOCOL_CONTRACTS.md#166-canonical-default-branch-changes).

## Connection and authorization

Use the exact repository URL ending in `/ui/default-branch/`, with explicit
32-character lowercase hexadecimal tenant and repository IDs. HTTPS is required
except for loopback HTTP. Keep the bearer token in an owner-private regular,
single-link file: 64 lowercase hexadecimal characters and at most one final LF.

Reads require `--allow-source` and a `read` grant. Fresh writes additionally
require `--enable-default-branch-admin`, a `default-branch-write` grant and
an already installed canonical administrator policy. The authenticated principal
must remain a current administrator at native admission. Git receive and
protection-edit grants do not imply default-branch administration.

Recovery requires the independent `outcomes-read` grant and
`--allow-outcomes`. An unresolved retry also needs the original write grant;
recovery performs no new source read.

Sponsored tokens are rejected. The native profile also refuses canonically
declared agents authenticated with ordinary tokens. The remote operator cannot
bootstrap administrator ownership or replace those native checks.

These examples use explicit connection values and private paths:

```bash
default_branch_url=https://forge.example/team/repository/ui/default-branch/
tenant_id=0123456789abcdef0123456789abcdef
repository_id=fedcba9876543210fedcba9876543210
credential_file=/private/frankengit/token
custody_dir=/private/frankengit/requests

default_branch() {
  node scripts/forge_default_branch.mjs "$@" \
    --url "$default_branch_url" --tenant-id "$tenant_id" \
    --repository-id "$repository_id" --token-file "$credential_file"
}
```

The custody directory must already exist, belong to the current user and grant
no group/other permissions. Records use new, owner-private, regular single-link
files. The supported custody profile is Unix.

## Read the default and candidates

```bash
default_branch show
default_branch list --limit 50 --max-pages 5
```

`show` performs one read-only default-branch request. It reports the exact
`default_reference_hex`, typed native `tip`, `unborn`, authenticated
principal/repository/incarnation and snapshot token.

A null reference means symbolic HEAD is absent. A named target with a null tip
is unborn. Those states require different mutation expectations.

`list` reads branch pages pinned to the same default observation, snapshot and
source head. Canonical reference fields are `ref_hex` and `object_id`;
`ref` is null for names that are not valid UTF-8. Output contains only
validated fields, with literal terminal control characters escaped.

The default budget is one page of 100 branches. Page size is 1–100 and
`--max-pages` is 1–100. A bounded prefix exits with code 4 and a continuation.
Resume using its exact `after_hex` and `expected_head`:

```bash
default_branch list --after-hex "$next_after_hex" \
  --expected-head "$snapshot_token" --limit 50 --max-pages 5
```

A cursor requires its snapshot. Native source pins compare the current authority
head: an intervening publication returns a conflict. They do not reopen a
historical snapshot or silently refresh it. `show --expected-head TOKEN`
provides the same strict pin.

Malformed later pages, changed scope, stalled cursors, revoked access and
resource failures fail the entire read. The earlier prefix is not reported as a
complete result. Reads create no mutation record or default-branch write.

## Select an existing branch with exact expectations

Supply the exact old symbolic target, destination branch and typed destination
commit observed above:

```bash
default_branch set-default \
  --expected-default refs/heads/main \
  --ref refs/heads/trunk \
  --expected-tip "sha1:$trunk_commit_hex" \
  --record "$custody_dir/select-trunk.json"
```

For SHA-256 repositories use `sha256:OID`; untyped IDs are rejected.
Names must be complete `refs/heads/*` references. `--ref-hex` and
`--expected-default-hex` preserve arbitrary valid Git branch bytes. The
native default-branch profile limits names to 1,024 bytes.

If the read reported an absent symbolic target, use `--expect-no-default`
instead of an old-name option. An unborn named target still requires its exact
name. Exactly one original-default expectation is mandatory.

The operator loads the current default and destination from one pinned
reference snapshot, then compares both caller-supplied expectations before
preparing or saving a mutation. A mismatch refuses without creating a record.
Fresh selection searches at most 2,048 visible references through the existing
native client, bounded by `--max-pages 1..21` (default 21). Exhausting that
budget refuses without guessing a tip or submitting.

Native admission revalidates the same old default, destination commit,
visibility and current administrator policy. A race remains a native decision
on the original request; the operator does not refresh either expectation.
A same-target request is an authorized audited no-op. Changing canonical HEAD
does not move direct refs, rewrite PR bases or install policy.

## Recover the original request

Every fresh selection needs a new record path. The complete native receipt is
saved and synchronized before sending. Every sender, including an explicit
retry, establishes its own exact-file and parent-directory durability barrier.
Existing records are never overwritten.

Records bind the original URL, tenant, repository, incarnation, principal,
credential fingerprint, expectations and native key. They contain repository
metadata, but no bearer token.

```bash
default_branch status --record "$custody_dir/select-trunk.json"
default_branch retry --record "$custody_dir/select-trunk.json"
```

`status` only observes. `retry` observes first and may send the identical
request/key once if still unresolved. A known committed or refused outcome is
returned without another mutation, even if HEAD changed again or source-read
access was revoked. Recovery requires the original credential fingerprint and
exact connection selection.

An absent outcome, timeout or lost response never proves non-commit. Keep the
original record and inspect its status; replacing expectations or the key
would create a different intent.

## Bounds and verification

Every command accepts `--timeout-ms 1..300000`, default 30,000, for the whole
invocation. Read commands accept `--max-output-bytes` up to 8 MiB, including
serialization and envelope overhead.

| Exit | Meaning |
| --- | --- |
| 0 | Complete read or observed committed terminal outcome |
| 2 | Unknown outcome, invalid input, cancellation or transport/output failure |
| 3 | Observed native terminal refusal |
| 4 | Checked bounded list prefix with an explicit continuation |

```bash
node --test tests/operator/forge-default-branch.test.mjs \
  tests/browser/default-branch.test.mjs \
  tests/browser/default-branch-view.test.mjs
```

The operator tests exercise production codecs, private custody, HTTP sockets
and fresh Node processes against an explicitly simulated native response peer.
They cover both Git hash domains, byte names, absent/unborn defaults, stale
expectations, lost responses, cancellation after durable custody, original-key
recovery and bounded reads. They do not establish Rust authority integration;
native coverage is described in [HTTP default-branch administration](HTTP_DEFAULT_BRANCH_API.md).
