#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SUBJECT="$ROOT/scripts/bv_compat.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/frankengit-bv-compat-test.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

pass_count=0
fail() {
  printf 'bv-compat-test: FAIL: %s\n' "$1" >&2
  exit 1
}
pass() {
  pass_count=$((pass_count + 1))
  printf 'bv-compat-test: ok %s - %s\n' "$pass_count" "$1"
}
expect_failure() {
  description=$1
  shift
  set +e
  "$@" >"$WORK/failure.stdout" 2>"$WORK/failure.stderr"
  status=$?
  set -e
  [ "$status" -ne 0 ] || fail "$description unexpectedly succeeded"
}
assert_no_compat_tempdirs() {
  if find "$WORK/tmp" -mindepth 1 -maxdepth 1 -name 'frankengit-bv-compat.*' -print -quit | grep -q .; then
    fail 'a compatibility temporary directory leaked'
  fi
}

mkdir -p "$WORK/tmp" "$WORK/repo/.beads" "$WORK/capture"
git -C "$WORK/repo" init -q

cat > "$WORK/repo/.beads/issues.jsonl" <<'JSONL'
{"id":"open-one","status":"open","description":"literal text: \"status\":\"batch_pending\" must remain text"}
{"id":"pending-one","status":"batch_pending","description":"awaiting verification","comments":[{"text":"embedded status batch_pending stays untouched"}]}
{"id":"closed-one","status":"closed","description":"done"}
JSONL

cat > "$WORK/fake-bv" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[ "${1-}" = "--db" ] || exit 41
db="${2-}"
shift 2
: "${BV_TEST_CAPTURE:?}"
printf '%s\n' "$PWD" > "$BV_TEST_CAPTURE/cwd"
printf '%s\n' "$db" > "$BV_TEST_CAPTURE/db-path"
printf '%s\n' "$@" > "$BV_TEST_CAPTURE/args"
cp "$db" "$BV_TEST_CAPTURE/projected.jsonl"
printf 'fake-bv-stderr\n' >&2
printf '{"fake":"stdout","records":3}\n'
FAKE
chmod +x "$WORK/fake-bv"

source_hash_before="$(sha256sum "$WORK/repo/.beads/issues.jsonl" | awk '{print $1}')"
BV_TEST_CAPTURE="$WORK/capture" \
BV_BIN="$WORK/fake-bv" \
FGIT_REPO_ROOT="$WORK/repo" \
TMPDIR="$WORK/tmp" \
  "$SUBJECT" --robot-triage --format toon >"$WORK/stdout" 2>"$WORK/stderr"
source_hash_after="$(sha256sum "$WORK/repo/.beads/issues.jsonl" | awk '{print $1}')"

[ "$source_hash_before" = "$source_hash_after" ] || fail 'the authoritative tracker changed'
[ "$(cat "$WORK/stdout")" = '{"fake":"stdout","records":3}' ] || fail 'launcher contaminated bv stdout'
grep -q 'projected 1 batch_pending record(s) to review across 3 tracker record(s)' "$WORK/stderr" || fail 'projection diagnostic is absent'
grep -q 'fake-bv-stderr' "$WORK/stderr" || fail 'bv stderr was not preserved'
[ "$(cat "$WORK/capture/cwd")" = "$(cd "$WORK/repo" && pwd -P)" ] || fail 'bv did not execute from the repository root'
[ "$(sed -n '1p' "$WORK/capture/args")" = '--robot-triage' ] || fail 'robot mode was not forwarded'
[ "$(sed -n '2p' "$WORK/capture/args")" = '--format' ] || fail 'format flag was not forwarded'
[ "$(sed -n '3p' "$WORK/capture/args")" = 'toon' ] || fail 'format value was not forwarded'
[ "$(wc -l < "$WORK/capture/projected.jsonl" | tr -d ' ')" = 3 ] || fail 'projection changed the record count'
"${PYTHON_BIN:-python3}" - "$WORK/capture/projected.jsonl" "$WORK/repo/.beads/issues.jsonl" <<'PY'
import json
import sys

projected_path, source_path = sys.argv[1:]
with open(projected_path, encoding="utf-8") as handle:
    projected = [json.loads(line) for line in handle]
with open(source_path, encoding="utf-8") as handle:
    source = [json.loads(line) for line in handle]
assert [row["status"] for row in projected] == ["open", "review", "closed"]
assert [row["status"] for row in source] == ["open", "batch_pending", "closed"]
assert projected[0]["description"] == source[0]["description"]
assert projected[1]["description"] == source[1]["description"]
assert projected[1]["comments"] == source[1]["comments"]
PY
projection_path="$(cat "$WORK/capture/db-path")"
[ ! -e "$projection_path" ] || fail 'the private projection survived launcher exit'
assert_no_compat_tempdirs
pass 'projects exactly batch_pending, preserves stdout, source bytes, cwd, arguments, and cleanup'

rm -f "$WORK/capture/cwd"
expect_failure 'separate --db override' env \
  BV_TEST_CAPTURE="$WORK/capture" BV_BIN="$WORK/fake-bv" FGIT_REPO_ROOT="$WORK/repo" TMPDIR="$WORK/tmp" \
  "$SUBJECT" --robot-triage --db "$WORK/other.jsonl"
grep -q 'caller-supplied --db is forbidden' "$WORK/failure.stderr" || fail 'separate --db refusal is not typed'
[ ! -e "$WORK/capture/cwd" ] || fail 'bv ran after a separate --db override'
assert_no_compat_tempdirs
pass 'refuses a caller-supplied separate --db override before invocation'

expect_failure 'joined --db override' env \
  BV_TEST_CAPTURE="$WORK/capture" BV_BIN="$WORK/fake-bv" FGIT_REPO_ROOT="$WORK/rpo" TMPDIR="$WORK/tmp" \
  "$SUBJECT" --robot-triage --db="$WORK/other.jsonl"
grep -q 'caller-supplied --db is forbidden' "$WORK/failure.stderr" || fail 'joined --db refusal is not typed'
assert_no_compat_tempdirs
pass 'refuses a caller-supplied joined --db override'

expect_failure 'non-robot mode' env \
  BV_TEST_CAPTURE="$WORK/capture" BV_BIN="$WORK/fake-bv" FGIT_REPO_ROOT="$WORK/repo" TMPDIR="$WORK/tmp" \
  "$SUBJECT" --format toon
grep -q 'only bv robot/read-only modes are allowed' "$WORK/failure.stderr" || fail 'non-robot refusal is not typed'
assert_no_compat_tempdirs
pass 'refuses non-robot bv modes'

expect_failure 'missing bv binary' env \
  BV_BIN="$WORK/does-not-exist" FGIT_REPO_ROOT="$WORK/repo" TMPDIR="$WORK/tmp" \
  "$SUBJECT" --robot-next
grep -q 'is not executable' "$WORK/failure.stderr" || fail 'missing-bv refusal is not typed'
assert_no_compat_tempdirs
pass 'refuses a missing bv executable'

cp "$WORK/repo/.beads/issues.jsonl" "$WORK/repo/.beads/issues.valid.jsonl"
printf '%s\n' '{"id":"valid","status":"open"}' '{not-json' > "$WORK/repo/.beads/issues.jsonl"
malformed_hash="$(sha256sum "$WORK/repo/.beads/issues.jsonl" | awk '{print $1}')"
rm -f "$WORK/capture/cwd"
expect_failure 'malformed tracker row' env \
  BV_TEST_CAPTURE="$WORK/capture" BV_BIN="$WORK/fake-bv" FGIT_REPO_ROOT="$WORK/repo" TMPDIR="$WORK/tmp" \
  "$SUBJECT" --robot-alerts
grep -q 'malformed tracker JSON at line 2' "$WORK/failure.stderr" || fail 'malformed-row refusal does not name the line'
[ "$malformed_hash" = "$(sha256sum "$WORK/repo/.beads/issues.jsonl" | awk '{print $1}')" ] || fail 'malformed source changed'
[ ! -e "$WORK/capture/cwd" ] || fail 'bv ran on a malformed projection'
assert_no_compat_tempdirs
mv "$WORK/repo/.beads/issues.valid.jsonl" "$WORK/repo/.beads/issues.jsonl"
pass 'fails closed on malformed JSON before invoking bv and reaps staging'

cat > "$WORK/repo/.beads/issues.jsonl" <<'JSONL'
{"id":"open-only","status":"open"}
{"id":"closed-only","status":"closed"}
JSONL
rm -rf "$WORK/capture"
mkdir -p "$WORK/capture"
BV_TEST_CAPTURE="$WORK/capture" \
BV_BIN="$WORK/fake-bv" \
FGIT_REPO_ROOT="$WORK/repo" \
TMPDIR="$WORK/tmp" \
  "$SUBJECT" --robot-plan >"$WORK/no-pending.stdout" 2>"$WORK/no-pending.stderr"
grep -q 'projected 0 batch_pending record(s) to review across 2 tracker record(s)' "$WORK/no-pending.stderr" || fail 'zero-mapping state was not reported truthfully'
assert_no_compat_tempdirs
pass 'accepts a future tracker with no batch_pending records without fabricating work'

printf 'bv-compat-test: PASS: %s assertions\n' "$pass_count"
