#!/usr/bin/env bash
# e2e: native import receipts survive reopen and cannot replay over newer refs.
# Bridge: frankengit-root-doctrine-x2mv.4.28 (bounded import/recovery slice).
# Real fg processes and embedded storage. Git constructs/verifies isolated
# source fixtures only; no differential, crash-injection or throughput claim.
set -euo pipefail

# A missing binary is non-pass, never an instruction to build or emulate fg.
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'import recovery requires FG_BIN naming a prebuilt native fg' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init import-recovery
fge_context bead frankengit-root-doctrine-x2mv.4.28
fge_context evidence_class e2e_binary_local_import
fge_context non_claim 'No crash injection, large-import performance, general Git compatibility or completed durability profile claim.'
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context git_version "$(git --version)"
fge_context git_digest "$(fge_digest_file "$(command -v git)")"

fge_phase setup
WORK="$(fge_tempdir import-recovery)"
mkdir -p "$WORK/home" "$WORK/templates"
export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME='Import fixture' GIT_COMMITTER_NAME='Import fixture'
export GIT_AUTHOR_EMAIL='import@example.invalid' GIT_COMMITTER_EMAIL='import@example.invalid'
export GIT_AUTHOR_DATE='2000-01-01T00:00:00 +0000' GIT_COMMITTER_DATE='2000-01-01T00:00:00 +0000'
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
unset GIT_COMMON_DIR GIT_NAMESPACE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
TENANT=11111111111111111111111111111111
REPOSITORY=22222222222222222222222222222222
PRINCIPAL=33333333333333333333333333333333
OTHER=55555555555555555555555555555555
TIMEOUT=600

# Every invocation is a fresh fg process. Captured files survive suite failure.
# Pass expected nonzero exits explicitly: a refusal must not masquerade as pass
# by merely making some command fail somewhere in the campaign.
run_fg() {
    local id=$1 expected=$2; shift 2
    OUT="$WORK/$id.out"; ERR="$WORK/$id.err"
    fge_run_timeout "$TIMEOUT" "$id" bash -c \
        'out=$1; err=$2; shift 2; exec "$@" >"$out" 2>"$err"' \
        _ "$OUT" "$ERR" "$FG_BIN" "$@" || true
    local actual=$FGE_LAST_EXIT
    fge_assert_exit "$id" "$expected" "$actual"
    fge_artifact "$OUT" command_stdout
    fge_artifact "$ERR" command_stderr
    [[ "$actual" == "$expected" ]] || fge_die "$id returned $actual, expected $expected"
    OUTPUT="$(cat "$OUT")"
}
field() {
    fge_json_top "$1" || fge_die 'expected one complete JSON object'
    [[ -v "FGE_JSON[$2]" ]] || fge_die "missing JSON field $2"
    printf '%s' "${FGE_JSON[$2]}"
}
hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
refs() {
    run_fg "$1" 0 refs "$STORE" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$FORMAT" --limit 100
    REFERENCES="$(field "$OUTPUT" references)"
    fge_assert_eq "$1-PAGE" false "$(field "$OUTPUT" has_more)" 'the entire bounded fixture is visible'
}
recover() {
    run_fg "$1" "$2" outcome "$STORE" "$TENANT" "$REPOSITORY" \
        --trusted-local --principal "$PRINCIPAL" --idempotency-key "$3" --object-format "$FORMAT"
    local transaction decision
    transaction="$(field "$OUTPUT" transaction)"
    decision="$(field "$OUTPUT" decision)"
    fge_assert_eq "$1-TX" "$(field "$4" tx_id)" "$(field "$transaction" tx_id)"
    fge_assert_eq "$1-STATE" "$(field "$4" state)" "$(field "$OUTPUT" state)"
    fge_assert_eq "$1-SEQUENCE" "$(field "$4" decision_sequence)" "$(field "$decision" decision_sequence)"
    if [[ "$2" == 0 ]]; then
        fge_assert_eq "$1-RECORD" "$(field "$4" repository_commit_id)" "$(field "$decision" repository_commit_id)"
    else
        fge_assert_eq "$1-RECORD" "$(field "$4" refusal_record_id)" "$(field "$decision" refusal_record_id)"
        fge_assert_eq "$1-CODE" "$(field "$4" refusal_code)" "$(field "$decision" code)"
    fi
}

# Deterministic loose object fixture. The second commit initially has no ref;
# its later admission is separate from merely existing on the local filesystem.
fixture() {
    git init -q --bare -b main --object-format="$FORMAT" --template="$WORK/templates" "$SOURCE"
    BLOB="$(printf 'bounded source import\n' | git -C "$SOURCE" hash-object -w --stdin)"
    TREE="$(printf '100644 blob %s\tdata.txt\n' "$BLOB" | git -C "$SOURCE" mktree)"
    OLD="$(printf 'initial import\n' | git -C "$SOURCE" commit-tree "$TREE")"
    NEW="$(printf 'later import\n' | git -C "$SOURCE" commit-tree "$TREE" -p "$OLD")"
    git -C "$SOURCE" update-ref refs/heads/main "$OLD"
    git -C "$SOURCE" update-ref refs/heads/topic "$OLD"
    git -C "$SOURCE" update-ref refs/tags/v1 "$OLD"
    git -C "$SOURCE" fsck --strict --no-reflogs >"$WORK/$FORMAT-fsck.out" 2>"$WORK/$FORMAT-fsck.err"
    printf '%s\n' "$FORMAT $BLOB $TREE $OLD $NEW" >"$WORK/$FORMAT-input-identities.txt"
}

for FORMAT in sha1 sha256; do
    ID="IMPORT-${FORMAT^^}"
    SOURCE="$WORK/$FORMAT-source"; STORE="$WORK/$FORMAT-node"
    KEY="import-$FORMAT-original"; REFUSED_KEY="import-$FORMAT-refused"
    fge_context object_format "$FORMAT"
    fge_phase setup
    fixture
    fge_artifact "$WORK/$FORMAT-input-identities.txt" fixture_identity
    # Malformed budgets and duplicate flags must refuse before creating a node.
    run_fg "$ID-001" 2 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$KEY" "$SOURCE" --json --timeout-secs 0
    fge_assert_cmd "$ID-002" 'bad timeout did not open storage' test ! -e "$STORE"
    run_fg "$ID-003" 2 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$KEY" "$SOURCE" --json --json
    fge_assert_cmd "$ID-004" 'duplicate flag did not open storage' test ! -e "$STORE"
    run_fg "$ID-005" 0 init "$STORE" "$TENANT" "$REPOSITORY" "$FORMAT"

    fge_phase action
    # No override: exercise the new import-specific context factory.
    run_fg "$ID-010" 0 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$KEY" "$SOURCE" --json
    FIRST=$OUTPUT
    fge_assert_eq "$ID-011" '"source_import_outcome"' "$(field "$FIRST" type)"
    fge_assert_eq "$ID-012" '"committed"' "$(field "$FIRST" state)"
    fge_assert_eq "$ID-013" true "$(field "$FIRST" atomic)"
    fge_assert_eq "$ID-014" true "$(field "$FIRST" terminal)"
    fge_assert_eq "$ID-015" 3 "$(field "$FIRST" command_count)"
    fge_assert_eq "$ID-016" true "$(field "$FIRST" node_closed)"
    fge_assert_eq "$ID-017" null "$(field "$FIRST" cleanup_error)"
    fge_assert_eq "$ID-018" "\"$TENANT\"" "$(field "$FIRST" tenant_id)"
    fge_assert_eq "$ID-019" "\"$REPOSITORY\"" "$(field "$FIRST" repository_id)"
    fge_assert_eq "$ID-020" "\"$PRINCIPAL\"" "$(field "$FIRST" principal_id)"
    fge_assert_not_contains "$ID-021" "$FIRST" "$KEY" 'receipt must not print retry key'
    fge_assert_not_contains "$ID-022" "$FIRST" "$SOURCE" 'receipt must not print source path'
    refs "$ID-025"
    INITIAL_REFS="[{\"reference_hex\":\"$(hex refs/heads/main)\",\"tip\":\"$OLD\"},{\"reference_hex\":\"$(hex refs/heads/topic)\",\"tip\":\"$OLD\"},{\"reference_hex\":\"$(hex refs/tags/v1)\",\"tip\":\"$OLD\"}]"
    fge_assert_eq "$ID-026" "$INITIAL_REFS" "$REFERENCES" 'all source refs publish together'

    # A new process and a different runtime budget recover the exact decision.
    run_fg "$ID-030" 0 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$KEY" "$SOURCE" --timeout-secs 600 --json
    fge_assert_eq "$ID-031" "$FIRST" "$OUTPUT" 'reopen and timeout choice do not create a new logical import'
    # Changed source semantics must not reuse that key or move the old refs.
    git -C "$SOURCE" update-ref refs/heads/main "$NEW"
    run_fg "$ID-032" 2 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$KEY" "$SOURCE" --json
    refs "$ID-033"
    fge_assert_eq "$ID-034" "$INITIAL_REFS" "$REFERENCES"
    git -C "$SOURCE" update-ref refs/heads/main "$OLD"

    # Admit the descendant under a new, disjoint ref, then really advance main
    # using the existing exact-expected-tip branch API. Old import replay must
    # not restore the original tip or discard the later ref.
    LATER="$WORK/$FORMAT-later-source"
    cp -R "$SOURCE" "$LATER"
    git -C "$LATER" symbolic-ref HEAD refs/heads/later
    git -C "$LATER" update-ref refs/heads/later "$NEW"
    git -C "$LATER" update-ref -d refs/heads/main
    git -C "$LATER" update-ref -d refs/heads/topic
    git -C "$LATER" update-ref -d refs/tags/v1
    run_fg "$ID-040" 0 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "import-$FORMAT-later" "$LATER" --json
    fge_assert_eq "$ID-041" 1 "$(field "$OUTPUT" command_count)"
    run_fg "$ID-042" 0 branch update "$STORE" "$TENANT" "$REPOSITORY" \
        --trusted-local --object-format "$FORMAT" --principal "$PRINCIPAL" \
        --idempotency-key "import-$FORMAT-advance" --ref refs/heads/main --expected-tip "$OLD" --target "$NEW"
    refs "$ID-043"
    ADVANCED_REFS="[{\"reference_hex\":\"$(hex refs/heads/later)\",\"tip\":\"$NEW\"},{\"reference_hex\":\"$(hex refs/heads/main)\",\"tip\":\"$NEW\"},{\"reference_hex\":\"$(hex refs/heads/topic)\",\"tip\":\"$OLD\"},{\"reference_hex\":\"$(hex refs/tags/v1)\",\"tip\":\"$OLD\"}]"
    fge_assert_eq "$ID-044" "$ADVANCED_REFS" "$REFERENCES"
    run_fg "$ID-045" 0 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$KEY" "$SOURCE" --json
    fge_assert_eq "$ID-046" "$FIRST" "$OUTPUT" 'historical receipt survives newer canonical writes'
    refs "$ID-047"
    fge_assert_eq "$ID-048" "$ADVANCED_REFS" "$REFERENCES" 'retry cannot rewind main or remove later'

    # Near-identical fresh-key request: existing main refuses the WHOLE import,
    # including the new ref. Its refusal must itself be exactly recoverable.
    git -C "$SOURCE" update-ref refs/heads/should-not-publish "$NEW"
    run_fg "$ID-050" 3 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$REFUSED_KEY" "$SOURCE" --json
    REFUSAL=$OUTPUT
    fge_assert_eq "$ID-051" '"refused"' "$(field "$REFUSAL" state)"
    fge_assert_eq "$ID-052" '"ExpectedOldRefMismatch"' "$(field "$REFUSAL" refusal_code)"
    fge_assert_eq "$ID-053" null "$(field "$REFUSAL" repository_commit_id)"
    fge_assert_eq "$ID-054" 4 "$(field "$REFUSAL" command_count)"
    run_fg "$ID-055" 3 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$REFUSED_KEY" "$SOURCE" --json
    fge_assert_eq "$ID-056" "$REFUSAL" "$OUTPUT"
    refs "$ID-057"
    fge_assert_eq "$ID-058" "$ADVANCED_REFS" "$REFERENCES" 'refusal publishes no partial ref set'
    git -C "$SOURCE" update-ref -d refs/heads/should-not-publish
    run_fg "$ID-060" 0 import "$STORE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$KEY" "$SOURCE"
    fge_assert_eq "$ID-061" 'published 3 source-import ref commands' "$OUTPUT" 'legacy text contract survives'

    # Recovery must not need the original mutable source to exist at all.
    mv "$SOURCE" "$SOURCE-offline"
    recover "$ID-070" 0 "$KEY" "$FIRST"
    recover "$ID-071" 3 "$REFUSED_KEY" "$REFUSAL"
    run_fg "$ID-072" 4 outcome "$STORE" "$TENANT" "$REPOSITORY" --trusted-local \
        --principal "$OTHER" --idempotency-key "$KEY" --object-format "$FORMAT"
    fge_assert_eq "$ID-073" false "$(field "$OUTPUT" terminal)" 'same key under a different principal has no decision'
    fge_assert_eq "$ID-074" null "$(field "$OUTPUT" transaction)"
    refs "$ID-075"
    fge_assert_eq "$ID-076" "$ADVANCED_REFS" "$REFERENCES" 'read-only recovery does not republish'
    fge_phase assert
    fge_note "$ID-complete" 'Both terminal decisions recovered through fresh fg processes; original source absent; later main preserved.'
done
