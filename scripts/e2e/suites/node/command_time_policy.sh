#!/usr/bin/env bash
# e2e: one operator time policy for fg commands (frankengit-root-doctrine-x2mv.4.50).
# Bead: frankengit-root-doctrine-x2mv.4.50, acceptance 2 (and the permitted twin).
#
# Proves, against a prebuilt fg (FG_BIN) and stock git:
# - a write run under a deliberately tiny global --timeout-secs ends WITHOUT a
#   false terminal claim: either the typed "no terminal outcome" (ambiguous)
#   result or a typed refusal before any seal, never a success;
# - fg outcome observes that key without inventing a decision;
# - retrying the IDENTICAL command under the default policy (the node's
#   session timeout, not the Database class's flat 15 s) commits, fg outcome
#   then reports exactly that committed decision, and a further identical
#   retry returns the same decision with exactly one branch created;
# - malformed global timeouts are refused before any work.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init command-time-policy
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.50
fge_context non_claim 'One local file-backed node and fg branch writes; the tiny timeout proves the typed non-terminal path, not a latency profile.'
fge_context load_average "$(cut -d' ' -f1-3 /proc/loadavg)"

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd CMD-TIME-001 'FG_BIN names a prebuilt executable fg' test -x "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

TENANT=11111111111111111111111111111111
REPOID=22222222222222222222222222222222
PRINCIPAL=33333333333333333333333333333333
KEY=command-time-policy-topic
WORK="$(fge_tempdir command-time-policy)"
STORAGE="$WORK/node"
SRC="$WORK/src"

git init -q -b main "$SRC"
git -C "$SRC" config user.email command-time@invalid.example
git -C "$SRC" config user.name 'command time fixture'
printf 'one\n' > "$SRC/file.txt"
git -C "$SRC" add file.txt
git -C "$SRC" commit -qm 'base'
TIP=$(git -C "$SRC" rev-parse HEAD)

INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" sha1 >"$WORK/init.out" 2>"$WORK/init.err" || INIT_RC=$?
fge_assert_eq CMD-TIME-002 0 "$INIT_RC" 'a fresh node initializes'
IMPORT_RC=0
"$FG_BIN" import "$STORAGE" "$TENANT" "$REPOID" "$PRINCIPAL" command-time-import "$SRC/.git" \
  >"$WORK/import.out" 2>"$WORK/import.err" || IMPORT_RC=$?
fge_assert_eq CMD-TIME-003 0 "$IMPORT_RC" 'the source imports, so main exists'

create() { # extra leading fg arguments, then the output stem
  local stem=$1
  shift
  local rc=0
  "$FG_BIN" "$@" branch create "$STORAGE" "$TENANT" "$REPOID" --trusted-local \
    --principal "$PRINCIPAL" --idempotency-key "$KEY" --ref refs/heads/topic --target "$TIP" \
    >"$WORK/$stem.out" 2>"$WORK/$stem.err" || rc=$?
  printf '%s' "$rc"
}
outcome() {
  local stem=$1 rc=0
  "$FG_BIN" outcome "$STORAGE" "$TENANT" "$REPOID" --trusted-local --principal "$PRINCIPAL" \
    --idempotency-key "$KEY" >"$WORK/$stem.out" 2>"$WORK/$stem.err" || rc=$?
  printf '%s' "$rc"
}

fge_phase action
# 1. Malformed global timeouts are refused before any work (exit 2, named).
index=0
for bad in 0 0.0 -1 1s 1e3 0.0000000001; do
  index=$((index + 1))
  BAD_RC=0
  "$FG_BIN" --timeout-secs "$bad" branch list "$STORAGE" "$TENANT" "$REPOID" --trusted-local \
    >"$WORK/bad.out" 2>"$WORK/bad.err" || BAD_RC=$?
  fge_assert_eq "CMD-TIME-01$index" 2 "$BAD_RC" "global --timeout-secs '$bad' is refused"
  fge_assert_cmd "CMD-TIME-02$index" "the refusal for '$bad' names the option" grep -q -- '--timeout-secs' "$WORK/bad.err"
done
MISSING_RC=0
"$FG_BIN" --timeout-secs >"$WORK/missing.out" 2>"$WORK/missing.err" || MISSING_RC=$?
fge_assert_eq CMD-TIME-019 2 "$MISSING_RC" 'a global --timeout-secs without a value is refused'

# 2. The tiny timeout: no false terminal claim.
TINY_RC=$(create tiny --timeout-secs 0.000001)
fge_context tiny_exit "$TINY_RC"
fge_context tiny_stderr "$(head -c 400 "$WORK/tiny.err")"
fge_assert_cmd CMD-TIME-040 'a microsecond budget never reports success' test "$TINY_RC" -ne 0
fge_assert_cmd CMD-TIME-041 'the result is the typed non-terminal outcome or a typed refusal before any seal' \
  grep -Eq 'no terminal branch outcome returned: .*this is not evidence of non-commit|refused before admission: .*sealed nothing' "$WORK/tiny.err"
BEFORE_RC=$(outcome outcome-before)
fge_context outcome_after_tiny_exit "$BEFORE_RC"
fge_assert_cmd CMD-TIME-042 'fg outcome observes the key without inventing a refusal (0 committed or 4 non-terminal)' \
  bash -c '[ "$1" = 0 ] || [ "$1" = 4 ]' _ "$BEFORE_RC"

# 3. The identical retry under the default policy commits.
RETRY_RC=$(create retry)
fge_assert_eq CMD-TIME-030 0 "$RETRY_RC" 'the identical command under the default policy commits'
AFTER_RC=$(outcome outcome-after)
fge_assert_eq CMD-TIME-031 0 "$AFTER_RC" 'fg outcome now reports exactly the committed decision'
AGAIN_RC=$(create again)
fge_assert_eq CMD-TIME-032 0 "$AGAIN_RC" 'a further identical retry returns the same terminal result'
fge_assert_cmd CMD-TIME-033 'both retries report the same decision' \
  bash -c 'python3 -c "
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
keys = [k for k in (\"tx_id\", \"decision_sequence\", \"repository_commit_id\") if k in a]
assert keys and all(a[k] == b[k] for k in keys), (a, b)
" "$1" "$2"' _ "$WORK/retry.out" "$WORK/again.out"
LIST_RC=0
"$FG_BIN" branch list "$STORAGE" "$TENANT" "$REPOID" --trusted-local >"$WORK/list.out" 2>"$WORK/list.err" || LIST_RC=$?
fge_assert_eq CMD-TIME-034 0 "$LIST_RC" 'branch list reads the repository'
fge_assert_cmd CMD-TIME-035 'exactly one refs/heads/topic exists, at the target' \
  python3 -c '
import json, sys
page = json.load(open(sys.argv[1]))
topic = [b for b in page["branches"] if bytes.fromhex(b["reference_hex"]) == b"refs/heads/topic"]
assert len(topic) == 1 and topic[0]["tip"] == sys.argv[2], page["branches"]
' "$WORK/list.out" "$TIP"

fge_artifact "$WORK/tiny.err" text
fge_artifact "$WORK/retry.out" json
fge_phase teardown
