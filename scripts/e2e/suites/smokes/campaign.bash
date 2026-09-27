# Shared driver for scripts/e2e/suites/smokes/*.sh. Sourced, never run: the
# name does not end in .sh, so run_all.sh does not discover it.
#
# Each suite calls fge_init itself (the library derives the script identity
# from its caller) and then fge_smoke_campaign, which runs one root-level
# scripts/e2e/<campaign>.py against the prebuilt fg named by FG_BIN. Before
# frankengit-root-doctrine-x2mv.4.18 these campaigns had no invoker in any
# suite or lane, so their results were never evidence of anything.
#
# fge_smoke_campaign CAMPAIGN ACCEPTANCE_ID DESCRIPTION [EXTRA_ARG...]
fge_smoke_campaign() {
  local campaign=$1 id=$2 desc=$3
  shift 3
  fge_kind e2e-binary
  fge_context campaign "scripts/e2e/$campaign.py"
  fge_context non_claim 'The campaign asserts its own contract; its stdout summary is retained as an artifact. Uses the host git, not the pinned oracle.'
  fge_phase setup
  local fg=${FG_BIN:-}
  fge_assert_cmd "$id-BIN" 'FG_BIN names a prebuilt fg binary' test -n "$fg"
  [ -x "$fg" ] || fge_die 'FG_BIN must name a prebuilt executable'
  fge_phase action
  fge_run_timeout "${FGE_SMOKE_TIMEOUT:-1500}" campaign \
    python3 "$E2E_ROOT/$campaign.py" --fg "$fg" "$@" || true
  fge_phase assert
  fge_assert_exit "$id" 0 "$FGE_LAST_EXIT" "$desc"
  fge_phase teardown
}
