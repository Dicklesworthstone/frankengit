# Bounded native issue search

`fg issue search` filters authority-selected native issue snapshots. It uses the existing retained-head issue reader, not a new database or index. The forge predicate and bounded pagination engine are shared library functionality; the local CLI is its initial adapter.

```sh
fg issue search "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --state open --label bug --query 'timeout' --limit 25 --max-scan 1000
```

The local interface assumes operator-controlled storage and does not provide remote authentication or per-issue ACLs. It opens only an existing repository, supports explicit `--object-format sha1|sha256`, never admits a transaction, and emits its result only after node shutdown succeeds.

## Matching and limits

All supplied predicates are conjunctive. `--state` accepts `open`, `closed`, or `all` (the default). `--opened-by` matches the original principal, not the latest actor. Repeated `--label` values require every exact label and must be unique; at most 32 bounded labels are accepted. CLI input order is normalized to the issue label ordering.

`--query` is a literal, nonempty UTF-8 string of at most 256 bytes without NUL. It matches the title OR body independently; comment text is not searched and a match cannot span those fields. Default case handling folds ASCII only. `--case-sensitive` requires a query and preserves all bytes. Neither mode performs regex evaluation, Unicode normalization, stemming, fuzzy ranking or locale-dependent matching. The reusable matcher has linear text work and no per-issue text-copy allocation.

`--limit` bounds returned matches (1..100; default 50). `--max-scan` independently bounds examined issues (1..1000; default 1000). The engine obtains ascending source pages of at most 100 issues and makes at most ten page reads. The reader remains responsible for authorization, retained-snapshot verification, runtime cancellation and storage budgets. This is a bounded scan, not an indexed-search performance claim.

## Continuation and completeness

The JSON `issue_search_page` includes the exact `snapshot_token`, normalized `query`, `scanned`, `count`, `complete`, `stop_reason`, `has_more_candidates`, and `next_after`.

- `exhausted`: all candidates after the requested cursor were examined; `complete=true`, `next_after=null`.
- `result_limit`: the match limit stopped the scan while candidates remained.
- `scan_limit`: the scan ceiling stopped it while candidates remained, possibly with zero matches.

A partial result does not prove another match exists. An empty partial page is NOT a complete no-match result. Continue with the same filters and `--after <next_after> --expected-head <snapshot_token>`. The cursor is the last examined issue number, including nonmatches; unread candidates in an already fetched page are not skipped. Changing the predicate intentionally starts a different query over that suffix; the cursor is not a query-authentication token.

Every page must name the first selected head. An unavailable retained head, changed returned head, invalid ordering/cursor, corrupt examined snapshot, cancellation, or source error refuses the operation; accumulated matches are not emitted as a successful partial result. Ordinary writes do not authorize refreshing a query to a different snapshot. Search changes no refs and creates no transaction.

## Verification scope

Tests cover predicate boundaries and ASCII/UTF-8 behavior, scalar literal equivalence, exact-head continuation, sparse issue numbering, empty partial pages, result/scan-limit interactions, source errors, malformed pages, exhausted tails, parser rejection, and JSON completeness metadata. Exhaustive small-pattern pagination tests compare all eight-issue match patterns across result and scan limits against a scalar filter. These are deterministic unit/contract tests, not a claim of a completed discussion/inbox product or indexed search.
