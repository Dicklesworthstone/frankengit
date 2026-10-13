# Independent browser review-protection administration

The repository-scoped `/ui/protection/` page uses the existing native
`GET /api/v1/protection` API and shared `ProtectionClient`. It does not require
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

## Validation boundary

`node --test tests/browser/protection-standalone.test.mjs` executes the production
view with an explicit native-client peer and the actual HTML. It tests exact
identity rendering, refusal, independent asset routing, byte-only names,
credential clearing, concurrent clicks and late replies after disconnect.
These are view unit and source-contract tests, not a native-server or browser
integration pass. The native route includes two Rust tests; they require the
repository toolchain and are not claimed executed by a Node run.

Related capability: `frankengit-root-doctrine-x2mv.4.20`. This independent shell
does not close the broader protection capability or grant verification credit.
