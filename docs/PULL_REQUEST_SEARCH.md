# Native pull-request search

Search reads native pull-request metadata and explicit merge-only receipts from
one authenticated current or retained authority head. The CLI, HTTP, MCP and PR
browser use the same bounded node search engine. There is no mutable search index,
Git subprocess, new publication schema or search-owned source of PR truth.

## Filters

All supplied filters must match. With no filters, search includes every visible
native PR and merge-only receipt; there is no implicit open-state restriction.

| Filter | Meaning |
| --- | --- |
| `query` | Literal substring in the title **or** body, 1–256 UTF-8 bytes without NUL. It does not search comments or reviews. |
| `case_sensitive` | Defaults to false, which folds ASCII letters only. True requires `query`. Unicode normalization, regex and fuzzy matching are not performed. |
| `state` | `all` (default), `open`, `closed` or `merged`. Reopened PRs are open. |
| `opened_by` | Exact original opener principal ID, not the last metadata editor or merge submitter. |
| `source_ref`, `target_ref` | Exact complete `refs/heads/*` names. |
| `source_ref_hex`, `target_ref_hex` | Lowercase hex alternatives for exact native branch bytes, including names without UTF-8 text. Supply at most one encoding per side. |

A merge-only receipt can match state and branch filters, but it has no invented
title, body or opener. Native merge records with retained PR metadata can match
that metadata. Canonical metadata and event consistency are validated before
filtering; malformed state and source failures never become successful nonmatches.

## Local CLI

```sh
fg pr search "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --state open --target-ref refs/heads/main --query "storage" \
  --limit 20 --max-scan 200
```

Use `--opened-by <principal-id>`, `--source-ref-hex <bytes>`, or
`--case-sensitive` as needed. SHA-256 repositories require
`--object-format sha256`. The CLI defaults to 50 results and 1,000 examined visible
candidates; `--limit` accepts 1–100 and `--max-scan` accepts 1–1,000. These limits
are independent, so the scan ceiling may be smaller than the result ceiling.

The local operator owns repository access and must explicitly pass
`--trusted-local`. No principal, publication key or body file is accepted for
search. Output is deterministic JSON, emitted only after successful node shutdown.
Exit 0 means a bounded result, including a partial or empty result. Exit 2 means
input, source, cleanup or output failure.

## HTTP

Enable the existing PR gateway with `--allow-pulls` and provide a credential with
the explicit `pulls-read` scope. Write permission does not imply read permission.
Use the repository URL from the listener's readiness record:

```sh
curl --get "$REPO_URL/api/v1/pulls/search" \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'query=storage' \
  --data-urlencode 'state=open' \
  --data-urlencode 'target_ref=refs/heads/main' \
  --data-urlencode 'limit=20' \
  --data-urlencode 'max_scan=200'
```

The route accepts the filter fields above plus `after`, `limit`, `max_scan`,
`expected_head` and optional existing `render` profiles. `case_sensitive` accepts
only `true` or `false`. Unknown fields, repeated fields, ambiguous reference
encodings, request bodies, `Expect: 100-continue` and `Git-Protocol` are refused.
Search consumes the existing authenticated read quota and preserves the listener's
request deadline. An exhausted read quota returns HTTP 429 without partial rows.
Do not send an idempotency key: this read creates no transaction. HTTP defaults
and numeric limits match the CLI.

The response type is `pull_request_search`. It carries the usual repository
identity, incarnation, object format, `source_head` and `snapshot_token`, plus
the normalized `filters`, `after`, `limit`, `max_scan`, `scanned`, `count`,
`complete`, `stop_reason`, `next_after` and canonical `pull_requests` rows.
Optional rendered body fields sit beside unchanged canonical body bytes.

## MCP

The existing pull-read launch option exposes `frankengit_pull_search`; sponsored
agent access additionally requires the existing `PULLS_READ` operation. Search
does not add a capability scope, review approval or merge permission.

```json
{
  "name": "frankengit_pull_search",
  "arguments": {
    "query": "storage",
    "state": "open",
    "target_ref": "refs/heads/main",
    "limit": 10,
    "max_scan": 200
  }
}
```

MCP retains its smaller output profile: `limit` is an integer from 1–20,
defaulting to 5. `max_scan` is an integer from 1–1,000, defaulting to 1,000.
`after` and returned `next_after` use exact decimal **strings**, not floating-point
JSON numbers. `case_sensitive` is a JSON boolean. The shared MCP response and
rendering byte budgets remain in force.

## Continue a search without losing matches

The cursor names the last **examined visible PR**, which may not be a match.
An empty partial page is valid. Continue whenever `complete` is false, using
`next_after` and the original `snapshot_token` as `expected_head`, with the same
filters. A nonzero `after` without `expected_head` is refused before storage reads.

| `stop_reason` | `complete` | Meaning |
| --- | --- | --- |
| `exhausted` | true | Every remaining visible candidate in the selected snapshot was examined; `next_after` is null. |
| `result_limit` | false | The match ceiling was reached with unexamined candidates remaining. |
| `scan_limit` | false | The visible-candidate ceiling was reached with unexamined candidates remaining. |

`count` is the number of matches in this page; it is not an estimated total.
`scanned` counts examined visible candidates only. A partial response does not
promise another match. Exhaustion takes precedence over a limit reached on the
last candidate. Each call makes at most ten source-page reads and preserves
typed source errors instead of emitting accumulated partial success.

The node selects the authenticated head and current hidden-ref policy once per
search call. Both source and target refs must be visible before any row can
contribute text, counts or cursors. A retained token is not a credential or a
historical-policy bypass; unavailable retained snapshots fail rather than
silently refreshing to latest. Altering filters intentionally starts a different
search over the remaining suffix; the browser captures the applied filters and
reuses them on continuation. Press Search to apply edited filters from the start.

The PR browser's normal list remains available. Its search form supports the
same predicates and separate page/scan ceilings, and offers continuation even
when a bounded page contains no matches. Refresh reruns the applied search from
the beginning at the latest available head. PR text is rendered as untrusted
content and never becomes an instruction or publication authority.
