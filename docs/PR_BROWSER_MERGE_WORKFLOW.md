# Fast-forward merges from the PR page

The served `/ui/pulls/` page now offers **Prepare fast-forward merge** for an
open PR with representable recorded branch names and distinct source/target
tips. This completes the browser interaction on top of the existing
[fast-forward HTTP command](FAST_FORWARD_PULL_REQUEST_HTTP.md), rather than
introducing another publication path.

Select a PR, inspect its recorded changes, and prepare the fast-forward request.
The page copies the selected PR number, version, hash format and both recorded
branch names/tips. Editing the separate metadata form cannot replace those
coordinates. Preparation sends no request, creates no candidate commit, and
clears any previous confirmation. The saved request appears in the existing
publication panel. Confirm it explicitly and use **Send / retry exact request**.

The native endpoint remains responsible for current authority, live branch
preconditions, ancestry, independent grants, branch protection, and atomic
publication of the ref move and PR transition. The button is not an ancestry
oracle, approval, or protection bypass. Divergence/refusal never selects force
or a different merge algorithm automatically. The reviewed candidate workflow
remains separate and unchanged.

A terminal response consumes the selected merge observation: explicitly reload
the PR before preparing another fast-forward. A missing, malformed, revoked,
interrupted or lost reply retains the original pending request. Outcome lookup
does not resend it, and absence does not prove non-commit. Export/restore uses
the existing credential-fingerprint-bound receipt with its original command and
idempotency key; no token or candidate bundle is written into this receipt.
Closed/merged PRs, byte-only names, equal tips, wrong scope/hash domains, and
exhausted exact-integer versions do not become actionable proposals.

## Reproduction and evidence boundary

```sh
node --test tests/browser/pulls-fast-forward-view.test.mjs
CHROME=/path/to/chromium node tests/browser/pulls-fast-forward-chromium.mjs
```

The first command exercises the production view, client, command codecs and
WebCrypto with a controlled DOM/Fetch boundary. It covers both hash domains,
confirmation, hostile form edits, refused proposals, canonical refusal,
disconnect, malformed receipts, and saved-receipt recovery with unchanged keys.
It is not a native-server or real-browser suite.

The second command drives the checked-in HTML and modules in Chromium over a
bounded local HTTP fixture under a restrictive CSP. It requires an explicitly
supplied browser, refuses missing clients, and closes the browser, server and
temporary profile. Its API is controlled: even a pass establishes browser
wiring and HTTP behavior, not native admission or policy correctness. Managed
browsers that disallow loopback cannot run this fixture; that is a non-pass,
not a reason to change the browser's security policy.

No Rust source, canonical schema, dependency, server permission, or required-
check semantics changes. Native `fg serve-http` integration, full-workspace
gates and independent bead acceptance remain separate obligations.
