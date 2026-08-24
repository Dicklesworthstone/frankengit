#!/usr/bin/env bash
# e2e: FG-059 creation retries preserve their first incarnation and stale
# caller-supplied cache incarnations refuse through the assembled fg binary.
set -euo pipefail

IL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IL_REPO=$(cd "$IL_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$IL_REPO/scripts/e2e/lib.sh"

fge_init fg059-incarnation-lifecycle
fge_context bead frankengit-fg059-incarnations-migration-v6f
fge_context crate fgit-cli
fge_context non_claim 'This one-process lane proves creation-attempt recovery and stale cache refusal only. Rename, transfer, routing flip, and cross-deployment cutover remain blocked on frankengit-b5ph.'

TENANT=59595959595959595959595959595959
REPOSITORY=60606060606060606060606060606060
STALE=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
KEY=fg059-create-once

fge_phase setup
BUILD_TARGET=$(fge_tempdir fg059-incarnation-lifecycle-binary)
WORK=$(fge_tempdir fg059-incarnation-lifecycle-work)

fge_phase action
BUILD_RC=0
fge_run fg059-incarnation-build-fg \
  env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="$BUILD_TARGET" \
  cargo build --locked -p fgit-cli \
  || BUILD_RC=$?
fge_assert_eq FG-059-E2E-030 0 "$BUILD_RC" \
  'the assembled fg binary is built from this checkout in a lane-private target root'
FG_BIN="$BUILD_TARGET/debug/fg"
fge_assert_cmd FG-059-E2E-031 'the assembled fg binary is executable' test -x "$FG_BIN"

fge_capture fg059-first-create \
  "$FG_BIN" init "$WORK/repository" "$TENANT" "$REPOSITORY" \
  --creation-idempotency-key "$KEY" sha256 || true
FIRST_RC=$FGE_LAST_EXIT
FIRST_OUT=$FGE_LAST_STDOUT
fge_assert_exit FG-059-E2E-032 0 "$FIRST_RC" \
  'first keyed creation mints and publishes the repository incarnation'
fge_assert_contains FG-059-E2E-033 "$FIRST_OUT" 'initialized authority head' \
  'first keyed creation reports the minting outcome'

fge_capture fg059-identical-retry \
  "$FG_BIN" init "$WORK/repository" "$TENANT" "$REPOSITORY" \
  --creation-idempotency-key "$KEY" sha256 || true
RETRY_RC=$FGE_LAST_EXIT
RETRY_OUT=$FGE_LAST_STDOUT
fge_assert_exit FG-059-E2E-034 0 "$RETRY_RC" \
  'lost-response retry with the same key is admitted'
fge_assert_contains FG-059-E2E-035 "$RETRY_OUT" 'authority head already initialized' \
  'retry observes the existing first-writer creation rather than minting again'

fge_capture fg059-fixed-field-mismatch \
  "$FG_BIN" init "$WORK/repository" "$TENANT" "$REPOSITORY" \
  --creation-idempotency-key "$KEY" sha1 || true
MISMATCH_RC=$FGE_LAST_EXIT
MISMATCH_ERR=$FGE_LAST_STDERR
fge_assert_cmd FG-059-E2E-036 'same creation key with changed fixed fields refuses' \
  test "$MISMATCH_RC" -ne 0
fge_assert_contains FG-059-E2E-037 "$MISMATCH_ERR" \
  'creation idempotency key was reused with different fixed request bytes' \
  'the fixed-field collision is explicit rather than a fresh incarnation'

fge_capture fg059-stale-cache \
  "$FG_BIN" doctor "$WORK/repository" "$TENANT" "$REPOSITORY" \
  --expected-incarnation "$STALE" || true
STALE_RC=$FGE_LAST_EXIT
STALE_ERR=$FGE_LAST_STDERR
fge_assert_cmd FG-059-E2E-038 'a stale cache incarnation refuses before service' \
  test "$STALE_RC" -ne 0
fge_assert_contains FG-059-E2E-039 "$STALE_ERR" 'authenticated head selects' \
  'the stale-cache refusal identifies an authenticated incarnation mismatch'

fge_capture fg059-current-free-twin \
  "$FG_BIN" doctor "$WORK/repository" "$TENANT" "$REPOSITORY" || true
CURRENT_RC=$FGE_LAST_EXIT
fge_assert_exit FG-059-E2E-040 0 "$CURRENT_RC" \
  'the identical cache-free doctor path remains permitted'

fge_phase teardown
