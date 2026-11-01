# Native milestones and issue planning

Milestones group repository issues with a title, description, optional due date
and an open/closed lifecycle. Their history and issue memberships are canonical
forge events admitted through the existing repository authority. Open and closed
issue counts come from one selected repository snapshot, including when reading
a retained historical snapshot. There is no milestone database or mutable
counter competing with that history.

## Create and maintain a milestone

```sh
fg milestone open "$ROOT" "$TENANT" "$REPOSITORY" 7 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key release-7-open --expected-version 0 \
  --title 'Release 1.0' --body-file ./release-goals.md \
  --due-at 1798761600

fg milestone edit "$ROOT" "$TENANT" "$REPOSITORY" 7 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key release-7-edit --expected-version 1 \
  --title 'Release 1.0 acceptance' --clear-due-at

fg milestone close "$ROOT" "$TENANT" "$REPOSITORY" 7 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key release-7-close --expected-version 2

fg milestone reopen "$ROOT" "$TENANT" "$REPOSITORY" 7 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key release-7-reopen --expected-version 3
```

These examples are one sequential history. Use the actual version when starting
a new action. After an uncertain response, retry the **identical command and
key**, retaining both its original content and expected version, or use `fg
outcome`. Refreshing a predecessor would change the request. Recovery returns
the original terminal decision even if the milestone has since changed.

Numbers are positive, repository-local and caller-selected; this interface does
not race to allocate the current maximum plus one. Add `--object-format sha256`
for a SHA-256 node; SHA-1 remains the default. Open requires `--expected-version 0`;
all later changes require the exact positive predecessor. The title is at most
256 UTF-8 bytes and the body at most 65,536 bytes. Text is data, including literal
Markdown and HTML. Body files must be regular files under the local operator's
control, with valid UTF-8 and no NUL.

Due dates use UTC Unix seconds from zero through `253402300799`. They do not run
timers, close milestones or change permissions. Editing preserves every omitted
field. Use `--body ''` to clear the description, `--due-at N` to set the date, or
`--clear-due-at` to remove it. A milestone can be edited while closed. Closing an
already closed milestone, or reopening an open one, refuses; exact retries still
recover their original decision.

## Attach, move and detach issues

Read the issue and milestone versions, then submit both explicitly:

```sh
fg issue set-milestone "$ROOT" "$TENANT" "$REPOSITORY" 42 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key issue-42-release-7 --expected-version 5 \
  --milestone 7 --expected-milestone-version 4

fg issue clear-milestone "$ROOT" "$TENANT" "$REPOSITORY" 42 \
  --trusted-local --principal "$PRINCIPAL" \
  --idempotency-key issue-42-clear-release --expected-version 6

fg issue search "$ROOT" "$TENANT" "$REPOSITORY" --trusted-local \
  --milestone 7 --state open --limit 50

fg issue search "$ROOT" "$TENANT" "$REPOSITORY" --trusted-local \
  --milestone none
```

Each issue has zero or one milestone. Setting another milestone moves the
membership. Set validates the issue predecessor and the selected open milestone
at one publication basis; a concurrent milestone edit or close cannot be silently
ignored. A stale or missing milestone refuses with `EvidenceStale`, and a closed
milestone refuses with `ProtectedRefTransitionDenied`.

Closing a milestone preserves all memberships. Clearing membership remains
available afterward. Both membership commands work on closed or discussion-locked
issues and preserve their title, body, labels, assignments, comments, lifecycle
and lock. Even a repeated set or clear submitted as a **new request** advances the
issue version. Neither changes the milestone's own version. An exact retry creates
no extra event.

The milestone filter combines with the existing state, author, label and text
filters. `none` selects unassigned issues; omission imposes no milestone filter.
Search keeps its independent result and scan ceilings. A partial empty page still
requires continuation with the original filters and snapshot token.

## Read history and progress consistently

```sh
fg milestone list "$ROOT" "$TENANT" "$REPOSITORY" --trusted-local --limit 20
fg milestone show "$ROOT" "$TENANT" "$REPOSITORY" 7 --trusted-local --limit 20
```

List rows include `number`, `version`, `title`, `body`, `due_at`, `state`,
`opened_by`, `last_actor`, `open_issues` and `closed_issues`. Show returns the same
summary plus exact paged lifecycle actions. Progress reflects issue membership
and issue open/closed state, not the milestone's own state. The source head and
algorithm-qualified `snapshot_token` bind all those values together.

Continue lists with `--after` and histories with `--after-version`, always passing
the original `--expected-head` token. Limits are 1–100, default 50. Ordinary later
publications do not change that retained snapshot. Unavailable history, unknown
tokens, changed retention/policy boundaries and exhausted replay limits produce
explicit refusals, never a successful partial count. Reads create no transaction.

CLI exit codes are 0 for committed/read, 3 for a canonical refusal, 4 for an absent
milestone, and 2 for input, infrastructure or output failures. A failed receipt
write after publication still reports the original committed/refused transaction;
it does not turn the outcome into non-commit.

## Authenticated HTTP and MCP

The native HTTP server and stdio MCP expose the same lifecycle, exact-version
membership commands and snapshot reads. They reuse the existing independent
issue grants: `issues-read` for milestone reads and `issues-write` for milestone
mutations and issue membership. A write grant does not imply read, and Git grants
imply neither. HTTP uses its authenticated bearer principal; MCP uses its bound
launch principal. No title, body, identifier or tool argument may impersonate one.

With the existing `--allow-issues` service enabled, HTTP exposes:

| Method | Route under the configured repository URL | Purpose |
| --- | --- | --- |
| GET | `/api/v1/milestones` | Numeric milestone page and same-snapshot counts |
| GET | `/api/v1/milestones/{number}` | Summary and paged lifecycle history |
| POST | `/api/v1/milestones/{number}/open` | Explicit new-stream creation |
| POST | `/api/v1/milestones/{number}/edit` | Exact-version metadata edit |
| POST | `/api/v1/milestones/{number}/close` | Close without detaching issues |
| POST | `/api/v1/milestones/{number}/reopen` | Reopen the exact closed predecessor |
| POST | `/api/v1/issues/{number}/set-milestone` | Set membership with both selected versions |
| POST | `/api/v1/issues/{number}/clear-milestone` | Clear membership at the exact issue version |

Mutations use `application/x-www-form-urlencoded`, an explicit
`expected_version`, and the existing `Idempotency-Key` header. Opening requires
`title` and `body`; `due_at` is optional. An edit accepts supplied `title`, `body`
and `due_at`, or `clear_due_at=true` to remove the date. Setting membership also
requires `milestone` and `expected_milestone_version`. Unknown, duplicate and
inapplicable fields refuse before publication. Read pagination uses the existing
`limit`, `after`/`after_version` and `expected_head` conventions. HTTP issue search
accepts `milestone=NUMBER` or `milestone=none` alongside its other conjunctive
filters. Existing Origin, framing, body, output, cancellation and credential
revocation checks apply to these routes.

MCP milestone tools are `frankengit_milestone_list`, `frankengit_milestone_show`,
`frankengit_milestone_open`, `frankengit_milestone_edit`,
`frankengit_milestone_close` and `frankengit_milestone_reopen`. MCP retains its
decimal-string convention for 64-bit integers. Native CLI/HTTP JSON uses integer
tokens; clients must preserve integer precision when handling large IDs.
Issue membership uses `frankengit_issue_set_milestone` and
`frankengit_issue_clear_milestone`. In an MCP edit, omit `due_at` to preserve the
date, supply its decimal string to replace it, or supply `null` to clear it.

Milestone webhook selection uses the explicit `milestone` family or `kind:22`.
An issue-only subscription does not silently gain milestone lifecycle events.
The existing scoped `issues-pulls-v1` event API retains its declared families;
milestone history is available through the milestone read surface.

## Compatibility and verification scope

The [normative byte and publication contract](NORMATIVE_PROTOCOL_CONTRACTS.md#2024-native-milestones-and-issue-membership)
adds required aggregate kind 9, event kind 22, and issue action tags 10/11. Old
encodings and request identities remain unchanged. Older readers refuse new
required kinds. Legacy issue JSON without `milestone` means no membership.

The frozen issue archive/import v1/v2 formats do not map milestones between
repositories. They explicitly refuse active milestone membership or membership
history, including a set followed by clear, rather than discard history or
reinterpret the destination's same-numbered milestone. Native history remains
complete. Dedicated browser milestone controls, standalone discussions,
notification preferences and inbox delivery are separate remaining product work.

The `native_milestones` CLI integration target and discovered
`scripts/e2e/suites/forge/milestones.sh` campaign run actual `fg` processes for both
object formats. They cover lifecycle, due-date clearing, issue moves, same-head
progress, retained snapshots, exact retries after close/reopen, stale and closed
milestone refusals, locked/closed issue maintenance, pagination, malformed body
files and stable-key recovery after source files disappear. Core and adapter
tests cover canonical encodings, independent admission and grants. Checked-in
coverage is not an executed result; use revision-bound verification outcomes.
