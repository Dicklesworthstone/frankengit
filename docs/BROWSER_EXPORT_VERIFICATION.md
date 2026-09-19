# Complete export snapshots and offline manifest checks

The source-enabled gateway serves `<repository-route>/ui/transfers/verify/`,
linked from source browsing. This read-only view reuses the existing native
bundle transfer client and parser. It neither uploads local verification files
nor calls import, mapped fetch, publication or outcome recovery. Those remain
separate workflows documented in `BROWSER_PORTABLE_TRANSFERS.md` and
`SOURCE_BUNDLE_HTTP.md`.

This is a functional export-verification slice under FG-058, not completion of
that bead or a replacement for the repository's signed capsule/backup design.
No dependency, runtime, authority source, or native object store is added.

## Live export

Connect a source-read credential and select SHA-1 or SHA-256. Build audited
snapshot export first selects one explicit authority head, then reads every
visible direct reference in bounded pages. All pages and the bundle export
compare that same snapshot. They must agree on tenant, repository incarnation,
hash format, source head and cursor. Ref names are compared as raw bytes, not
lossy UTF-8. Invalid order, repeated names, incomplete pagination, stale heads
and oversized inventories refuse the entire operation.

The downloaded bundle must advertise exactly those reference names and native
targets. This catches a missing or substituted advertised ref even when both
the bundle SHA-256 and native pack-trailer checksum are internally consistent.
An optional HEAD advertisement remains only the existing bundle transport hint;
it does not change default-branch configuration.

After all checks finish, explicitly save **both** `repository.bundle` and
`repository.export.json`. The manifest records exact artifact length and
SHA-256, bundle format, header size, pack count, advertised refs, scope and
source snapshot. It contains no access token. Save failures do not mutate the
repository; a replaced/cancelled export exposes no stale downloadable artifact.
Download object URLs are released after use and on disconnect or page exit.

The existing programmatic `TransferClient.exportBundle()` remains compatible.
Call `exportBundle({ verifyInventory: true })` for complete ref comparison;
`exportManifest()` refuses unless that comparison completed. This option
neither changes import/fetch request identities nor refreshes their saved
expected-old leases. An outstanding transfer blocks a new audited export.

## Offline verification

Choose the saved bundle and manifest and press **Verify local files**. No token
or active server connection is required. Both sizes are checked before either
file read. The shared parser checks the bounded full-bundle envelope, native
pack checksum and whole-artifact digest again; every ref identity and other
saved bundle field must match. Missing/extra fields and stronger unsupported
claims refuse. Origin URLs in manifests are never fetched.

A successful check means only that these local bytes match this unsigned
manifest. It does **not**:

- authenticate the recorded source server, scope or original snapshot;
- repeat the original live reference listing or establish currentness;
- decompress every object or prove the native Git closure is complete;
- restore or back up issues, PRs, policy, accounts, credentials or default-branch configuration.

The report explicitly retains `independently_authenticated: false`,
`live_snapshot_rechecked: false` and `objects_verified: false`. Co-modified
artifacts and manifests are not a signature. Native import/quarantine and any
independent backup trust policy retain their own full verification duties.

Changing either selected file invalidates the old offline result. File reads,
network requests and asynchronous hashes cannot restore cleared results after
cancellation, replacement, disconnect or page exit. Repository strings are DOM
text; non-UTF-8 refs remain hex identities, and directional controls are escaped.

## Bounds and existing restrictions

This view keeps the existing browser parser's 16 MiB bundle, 256 KiB header and
1,024 advertised-record ceilings. Complete inventories additionally bound the
sum of raw name bytes to 256 KiB; each page contains at most 100 refs. Manifests
are at most 1 MiB. This is deliberately narrower than native export's envelope.
Resource exhaustion refuses rather than silently treating a prefix as complete.

The current native ref API accepts only UTF-8 continuation names. A byte-only
final row can be verified, but a byte-only cursor on an intermediate page is
still refused by the native endpoint. Prerequisite/incremental and filtered
bundles remain unsupported by this full-export workflow. No hidden-ref,
publication or object-admission rule is weakened.

## Executable evidence and limits

```sh
node --test tests/browser/export-integrity.test.mjs tests/browser/export-verify-view.test.mjs
node --test tests/browser/*.test.mjs
node tests/browser/export-integrity-git-oracle.mjs /absolute/git 'git version X' <sha256-of-binary>
```

The implementation run passed 68 focused tests (45 client/protocol, 23 UI and
static-route/import checks) and 227 tests in a restored selected-file fixture,
with zero failures or skips. HTTP/DOM/File fixtures are test doubles, not a live
native node or a complete checkout at current HEAD.

The explicitly non-production Git oracle requires an absolute binary path,
exact version and binary SHA-256 before running in disposable repositories.
The run with Git 2.47.3 passed 28 checks across SHA-1 and SHA-256, using real
bundles with multiple ref pages, annotated tags, binary contents and non-UTF-8
paths. Download bytes matched; mirror clones and strict fsck passed; ref-omission
and checksum-corruption probes refused. HTTP here is still a test double over
actual Git-generated artifacts, not execution of FrankenGit's native exporter.

A Chromium 144 smoke attempt was blocked at the initial loopback navigation by
administrator policy (`ERR_BLOCKED_BY_ADMINISTRATOR`); no real-browser pass is
claimed. Three Rust static-route tests are supplied but were not executed:
Rust/Cargo was unavailable. Native compilation/interoperability, full-workspace,
Clippy, independent batch verification and release gates remain unverified.
