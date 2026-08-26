#!/usr/bin/env bash
# FG-056: quota/admission economy evidence (frankengit-fg056-quotas-abuse-0xn).
#
# Exercises the deterministic core of the plan-36 system at library level:
#   1. the five-outcome admission matrix against the obligation ledger,
#   2. fairness rotation with the bounded-wait starvation guarantee,
#   3. the abuse skeleton's reversible containment on the push surface
#      (per-key isolation included).
#
# These are DETERMINISTIC drills over typed state, not a live multi-tenant
# soak: capacity numbers come from ledger roots declared in-process. A live
# cluster drill is future work and is not claimed here.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

fge_init fg056-quota-admission

run_drill() {
  local id="$1" package="$2" filter="$3" claim="$4"
  local exit_code=0

  fge_capture "${id}-out" \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test -p "${package}" --lib -- "${filter}" || exit_code=$?

  if [[ "${exit_code}" -ne 0 ]]; then
    fge_fail "${id}" "drill failed: ${claim}"
    return 0
  fi
  fge_assert_exit "${id}" 0 0 "${claim}"
}

run_drill "FG056-E2E-admission-matrix-001" fgit-resource \
  'quota::admission::tests' \
  "the five admission outcomes decide deterministically against ceilings and the ledger"

run_drill "FG056-E2E-hierarchy-001" fgit-resource \
  'quota::hierarchy::tests' \
  "scope chains validate and effective ceilings take the per-grade minimum"

run_drill "FG056-E2E-fairness-bounded-wait-001" fgit-resource \
  'quota::fairness::tests' \
  "rotation bounds any contender wait to lanes-minus-one picks"

run_drill "FG056-E2E-containment-reversibility-001" fgit-node \
  'push_quota_tests' \
  "push containment is typed, reversible, and isolated per principal"
