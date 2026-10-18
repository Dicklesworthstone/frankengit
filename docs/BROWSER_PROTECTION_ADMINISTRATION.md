# Independent browser review-protection administration

The repository-scoped `/ui/protection/` page uses the existing native
`GET/POST /api/v1/protection` and read-only original-key outcome APIs and shared `ProtectionClient`. It does not require
source browsing or pull-request UI enablement: all page assets are gated by the
existing `http_protection_admin_enabled()` profile. The native endpoint still
requires the independent protection-read grant. Static assets contain no policy
state or credentials and do not grant API access.

The page displays the complete native policy with its authority snapshot,
repository incarnation, full-width decimal policy version and epoch. Branch
names retain exact hex bytes even when their names are not UTF-8. Initial
administrator installation remains local-only. An installed policy with no
branches is distinguished from an uninstalled policy.

The entrypoint loads the existing protection client, not the PR page controller.
A closed page-coordinate adapter selects the same repository root understood by
that client; it neither requests the PR shell nor calls a PR API. That shared
origin/route is also the namespace of existing protection recovery receipts.
There is no second protection protocol or duplicated authorization logic.

Tokens remain in memory only, are removed from the input before connection, and
are discarded on disconnect/pagehide. Explicit inspection may select a newer
policy. Errors and stale asynchronous replies do not manufacture a snapshot.
The displayed expected principal does not prove token ownership or authorize a
policy change; native credentials and policy administrators retain that role.

## Guarded complete replacement and uncertain-write recovery

Connect selects a credential and an explicit expected principal locally; it does
not claim authentication or fetch a new policy. Inspect explicitly to load the
complete native policy. Edit the full administrator set and branch rules, then
freeze the replacement. The shared client's `load()` and `stage()` methods own
snapshot validation and canonical request construction. This corrects the first
inspection checkpoint's mistaken `inspect()` call on that client.

A send requires confirmation of the frozen request. Removing the submitting
principal as an administrator requires an additional acknowledgment. Clearing
all branch rules requires an explicit flag and an empty rules field. The editor
never infers authority from the proposed administrators and never truncates a
policy to fit a budget; native form and policy bounds refuse oversized commands.
Successful policy replacement advances the native policy epoch and invalidates
candidate approvals from the earlier epoch.

The view sends the saved body and original key, not the live editor fields.
Unknown outcomes retain the pending intent, block new inspection/replacement,
and require explicit unchanged retry or read-only outcome lookup. Native
committed/refused terminals are displayed separately from delivery acknowledgment.
No policy is silently reread after a terminal. Disconnect clears displayed data
and credentials without discarding unresolved publication responsibility.

Export/restore uses the shared client's token-free receipt format. Save receipts
securely: they include private policy data, original keys and credential
fingerprints. Export does not imply that a file was saved or delivered. The
original credential can explicitly retry; rotated credentials require an
explicit recovery-only connection for the same original principal and cannot
read policy, edit, discard or resubmit. Outcome absence is not proof of rollback.
Receipts can move between this page and the existing PR protection panel for
exactly the same origin and repository route. No credentials move with them.

## Validation boundary

Run both focused targets:

```sh
node --test tests/browser/protection-standalone.test.mjs tests/browser/protection-standalone-client.test.mjs
```

The first executes the production view with an explicit native-client peer and
the actual HTML. The second uses `ProtectionClient`, WebCrypto and Response
streams with native-schema HTTP fixtures, including the production entrypoint,
full replacement, principal mismatch, ambiguity, receipt integrity, key recovery,
credential rotation and disconnect/revocation. A planted baseline check reproduces
the original missing-method defect; the corrected client target requires an
actual GET and validated policy rendering.

The authoring run executed the unchanged protection portion of `pulls-actions`
and its used helpers in source-isolated modules (805e6671 / 763dce35 / 3e9dccd0),
not the unrelated PR/Transport module portions. These local validation slices
are not shipped as production files. The checked-in tests import the ordinary
production module paths in a complete repository checkout. It tests exact
identity rendering, refusal, independent asset routing, byte-only names,
credential clearing, concurrent clicks and late replies after disconnect.
These are view unit and source-contract tests, not a native-server or browser
integration pass. The native route includes two Rust tests; they require the
repository toolchain and are not claimed executed by a Node run.

Related capability: `frankengit-root-doctrine-x2mv.4.20`. This independent shell
does not close the broader protection capability or grant verification credit.
