#!/usr/bin/env bash
# e2e: validate verification replay artifacts without claiming a checker pass.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VERIFY="${REPOSITORY_ROOT}/scripts/verify.sh"

artifact_field_sha256() {
  local json="$1"
  local key="$2"
  local expression="\"${key}\":\"([0-9a-f]{64})\""

  if [[ "${json}" =~ ${expression} ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
}

read_if_regular() {
  local path="$1"

  if [[ -f "${path}" ]]; then
    cat -- "${path}"
  fi
}

fge_init verify-artifact-probe
fge_phase setup
artifact_root="$(fge_tempdir verify-replay)"
normal_root="${artifact_root}/normal"
failure_root="${artifact_root}/failure"
no_artifact_root="${artifact_root}/no-artifact"
full_root="${artifact_root}/full"
release_root="${artifact_root}/release"

fge_phase action
set +e
fge_capture invalid-artifact-failure env VERIFY_ARTIFACT_DIR=/dev/null "${VERIFY}" invalid-lane
invalid_failure_exit=$?
set -e
fge_assert_exit FG-001-PROBE-001 2 "${invalid_failure_exit}" "artifact-directory failure preserves the verifier usage exit"

set +e
fge_capture invalid-first env VERIFY_ARTIFACT_DIR="${failure_root}" "${VERIFY}" invalid-lane
invalid_first_exit=$?
set -e
fge_assert_exit FG-001-PROBE-002 2 "${invalid_first_exit}" "invalid lane produces a replay artifact and retains exit 2"

set +e
fge_capture invalid-second env VERIFY_ARTIFACT_DIR="${failure_root}" "${VERIFY}" invalid-lane
invalid_second_exit=$?
set -e
fge_assert_exit FG-001-PROBE-003 2 "${invalid_second_exit}" "repeat invalid lane retains exit 2"

set +e
fge_capture no-artifact env VERIFY_ARTIFACT_DIR="${no_artifact_root}" "${VERIFY}" --no-artifact invalid-lane
no_artifact_exit=$?
set -e
fge_assert_exit FG-001-PROBE-004 2 "${no_artifact_exit}" "no-artifact escape hatch retains verifier exit 2"

set +e
fge_capture docs-artifact env VERIFY_ARTIFACT_DIR="${normal_root}" "${VERIFY}" docs
docs_exit=$?
set -e
fge_assert_exit FG-001-PROBE-005 0 "${docs_exit}" "docs lane succeeds with replay evidence enabled"

set +e
fge_capture full-refusal env VERIFY_ARTIFACT_DIR="${full_root}" "${VERIFY}" full
full_exit=$?
set -e
fge_assert_exit FG-001-PROBE-020 3 "${full_exit}" "full lane retains its typed pre-implementation refusal"

set +e
fge_capture release-refusal env VERIFY_ARTIFACT_DIR="${release_root}" "${VERIFY}" release
release_exit=$?
set -e
fge_assert_exit FG-001-PROBE-021 3 "${release_exit}" "release lane retains its typed pre-implementation refusal"

shopt -s nullglob
normal_artifacts=("${normal_root}"/*.json)
failure_artifacts=("${failure_root}"/*.json)
no_artifacts=("${no_artifact_root}"/*.json)
full_artifacts=("${full_root}"/*.json)
release_artifacts=("${release_root}"/*.json)
shopt -u nullglob
fge_phase assert
fge_assert_eq FG-001-PROBE-006 1 "${#normal_artifacts[@]}" "docs lane emits exactly one artifact"
fge_assert_eq FG-001-PROBE-007 2 "${#failure_artifacts[@]}" "each invalid-lane invocation emits an artifact"
fge_assert_eq FG-001-PROBE-008 0 "${#no_artifacts[@]}" "no-artifact escape hatch emits no artifact"
fge_assert_eq FG-001-PROBE-022 1 "${#full_artifacts[@]}" "full refusal emits exactly one artifact"
fge_assert_eq FG-001-PROBE-023 1 "${#release_artifacts[@]}" "release refusal emits exactly one artifact"

docs_artifact="${normal_artifacts[0]:-}"
first_failure_artifact="${failure_artifacts[0]:-}"
second_failure_artifact="${failure_artifacts[1]:-}"
full_artifact="${full_artifacts[0]:-}"
release_artifact="${release_artifacts[0]:-}"
fge_assert_file FG-001-PROBE-009 "${docs_artifact}" "docs replay artifact exists"
fge_assert_ndjson FG-001-PROBE-010 "${docs_artifact}" "docs replay artifact is a parseable JSON object"

docs_json="$(read_if_regular "${docs_artifact}")"
first_failure_json="$(read_if_regular "${first_failure_artifact}")"
second_failure_json="$(read_if_regular "${second_failure_artifact}")"
fge_assert_contains FG-001-PROBE-011 "${docs_json}" '"schema":"frankengit.verify-replay.v1"' "artifact records its schema"
fge_assert_contains FG-001-PROBE-012 "${docs_json}" '"lane":"docs"' "artifact records the lane"
fge_assert_contains FG-001-PROBE-013 "${docs_json}" '"command_argv":[' "artifact records exact argv"
fge_assert_contains FG-001-PROBE-014 "${docs_json}" '"head":"' "artifact records source revision"
fge_assert_contains FG-001-PROBE-015 "${docs_json}" '"rustc_version":"' "artifact records the Rust compiler"
fge_assert_contains FG-001-PROBE-016 "${docs_json}" '"cargo_version":"' "artifact records Cargo"
fge_assert_contains FG-001-PROBE-017 "${docs_json}" '"captured_output_sha256":"' "artifact records captured output digest"
fge_assert_contains FG-001-PROBE-018 "${first_failure_json}" '"exit_code":2' "artifact records preserved nonzero exit"
full_json="$(read_if_regular "${full_artifact}")"
release_json="$(read_if_regular "${release_artifact}")"
fge_assert_contains FG-001-PROBE-024 "${full_json}" '"exit_code":3' "full artifact records the typed refusal"
fge_assert_contains FG-001-PROBE-025 "${release_json}" '"exit_code":3' "release artifact records the typed refusal"

first_diff_sha256="$(artifact_field_sha256 "${first_failure_json}" dirty_diff_sha256)"
second_diff_sha256="$(artifact_field_sha256 "${second_failure_json}" dirty_diff_sha256)"
fge_assert_eq FG-001-PROBE-019 "${first_diff_sha256}" "${second_diff_sha256}" "dirty-diff digest is stable for identical source state"

if [[ -f "${docs_artifact}" ]]; then
  fge_artifact "${docs_artifact}" verify-replay-artifact
fi
