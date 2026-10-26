#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Replay artifact schema (frankengit.verify-replay.v1), written as one JSON
# object per lane invocation:
#   schema, schema_version, created_at_utc, lane, command_argv, head,
#   dirty, dirty_status, dirty_status_sha256, dirty_diff_sha256,
#   rustc_version, cargo_version, exit_code, wall_time_ms,
#   stdout_sha256, stderr_sha256, captured_output_format,
#   captured_output_file, captured_output_sha256.
# 'captured_output_sha256' hashes the exact bytes of the two captured streams
# under the explicit v1 framing "stdout\0<bytes>\0stderr\0<bytes>". Evidence
# writing retains that exact framed byte stream in the sibling
# 'captured_output_file'. Any evidence-write failure only warns on stderr and
# never replaces the lane's exit status. '--no-artifact' suppresses this wrapper
# for tight local loops.
readonly VERIFY_ARTIFACT_SCHEMA="frankengit.verify-replay.v1"
readonly VERIFY_ARTIFACT_SCHEMA_VERSION=1

export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

# AGENTS.md §16.2: builds use the caller's Cargo/RCH routing and private target
# directory. Never force a local compiler here. Tools that inspect this checkout
# are built for the CALLER's host, returned by Cargo/RCH, then executed here:
# `cargo run` could instead inspect a worker's filtered copy (notably no Beads).
# Explicit input roots also avoid embedded worker CARGO_MANIFEST_DIR paths.
VERIFY_NATIVE_HOST=''
VERIFY_TARGET_DIRECTORY=''

echo_step() { printf '\033[1;36m==> %s\033[0m\n' "$*" >&2; }
artifact_warning() { printf 'verify: replay artifact unavailable: %s\n' "$1" >&2 || true; }
print_usage() {
  printf 'usage: %s [--no-artifact] {docs|constitution|fast|e2e|full|release}\n' "$0" >&2
  printf 'feature lanes: exact-patch|index-maintenance|source-symbols|symbol-index|symbol-index-native|symbol-index-maintenance|review-protection|admission-tests|native-rebase-check|native-rebase-test|pull-request-checks|continuous-serve|tier-a\n' >&2
}
refuse_dormant() {
  printf '\033[1;33m==> %s\033[0m\n' "$1" >&2
  printf 'This is a typed pre-implementation refusal, not a passing gate.\n' >&2
  exit 3
}

prepare_native_tools() {
  [[ -n "${VERIFY_NATIVE_HOST}" ]] && return 0
  if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
    printf 'verify: set CARGO_TARGET_DIR to a pane-private durable target directory (AGENTS.md 16.2)\n' >&2
    return 2
  fi
  local compiler_version metadata
  compiler_version="$(rustc -vV)"
  VERIFY_NATIVE_HOST="$(printf '%s\n' "$compiler_version" | sed -n 's/^host: //p')"
  if ! [[ "${VERIFY_NATIVE_HOST}" =~ ^[a-zA-Z0-9_]+(-[a-zA-Z0-9_]+)+$ ]]; then
    printf 'verify: cannot determine one native caller host from rustc -vV\n' >&2
    return 2
  fi
  metadata="$(cargo metadata --locked --no-deps --format-version 1)"
  VERIFY_TARGET_DIRECTORY="$(printf '%s' "$metadata" | "${PYTHON_BIN:-python3}" -c '
import json, os, sys
try:
    target = json.load(sys.stdin)["target_directory"]
    if not isinstance(target, str) or not os.path.isabs(target) or any(c in target for c in "\0\r\n"):
        raise ValueError("expected an absolute target_directory without control separators")
except (ValueError, KeyError, TypeError) as error:
    print(f"verify: invalid Cargo target metadata: {error}", file=sys.stderr)
    sys.exit(2)
print(target)
')"
}

native_binary_path() {
  local suffix=''
  case "${VERIFY_NATIVE_HOST}" in *-windows-*) suffix='.exe' ;; esac
  printf '%s/%s/debug/%s%s\n' "$VERIFY_TARGET_DIRECTORY" "$VERIFY_NATIVE_HOST" "$1" "$suffix"
}

run_native_tool() {
  local package="$1" binary="$2" executable
  shift 2
  prepare_native_tools
  cargo build --locked --target "$VERIFY_NATIVE_HOST" -p "$package" --bin "$binary"
  executable="$(native_binary_path "$binary")"
  if [[ ! -x "$executable" ]]; then
    printf 'verify: no returned native executable at %s\n' "$executable" >&2
    return 1
  fi
  "$executable" "$@"
}

run_docs() {
  echo_step "Checking pinned Rust bootstrap metadata before Cargo"
  "$ROOT/scripts/check_toolchain_bootstrap_links.sh"
  echo_step "Checking FrankenGit documentation and registries"
  run_native_tool fgit-registry-check fgit-registry-check docs --root "$ROOT"
}

run_constitution() {
  echo_step "Checking dependency and memory-safety constitution"
  run_native_tool fgit-registry-check fgit-registry-check constitution --root "$ROOT"
  cargo metadata --locked --no-deps --format-version 1 >/dev/null
}

run_fast() {
  run_docs
  run_constitution
  echo_step "Checking verifier command contracts"
  bash "$ROOT/scripts/tests/verify_test.sh"
  echo_step "Checking formatting"
  cargo fmt --all -- --check
  echo_step "Checking workspace"
  cargo check --workspace --all-targets --locked
  # FG-048a: the generated schema artifacts are committed, and this is
  # what keeps that safe. `check` never writes, so a verify run cannot
  # repair the drift it is supposed to report.
  echo_step "Checking the generated schema artifacts are current"
  run_native_tool fgit-schema fgit-schema-gen check "$ROOT/crates/fgit-schema/generated" --workspace-root "$ROOT"
  echo_step "Running workspace tests"
  # --no-fail-fast is mandatory: without it, cargo stops after the first test
  # binary that fails and never runs the rest, so a single red test (e.g. an
  # in-development EXPECTED-RED) silently masks every acceptance test that would
  # have run after it. That truncation produced a false-green orchestrator close
  # of the fg007b/§5.2 acceptance suite; the flag makes every failure visible.
  cargo test --workspace --all-targets --locked --no-fail-fast
  echo_step "Running Clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings
}

# The product lane (frankengit-root-doctrine-x2mv.4.18). It builds `fg` once
# and runs, through scripts/e2e/run_all.sh, every discovered suite whose
# declared evidence kind says it exercises the product or the browser shell:
# e2e-binary (a prebuilt fg with stock clients, including every registered
# smoke campaign), real-browser (fg plus an installed Chrome) and js-unit (the
# browser contract tests). Cargo-test wrappers are not selected: they are not
# evidence that the product works, and `fast` already runs the tests they wrap.
# Suites that need a missing client (Chrome, Node, the pinned oracle) report a
# non-pass skip, so this lane cannot go green by skipping them.
run_e2e() {
  # fg-mcp is built with fg: the MCP suites drive both executables.
  echo_step "Building the fg and fg-mcp binaries once for the product suites"
  prepare_native_tools
  cargo build --locked --target "$VERIFY_NATIVE_HOST" -p fgit-cli --bin fg --bin fg-mcp
  local executable binary fg_binary mcp_binary
  for binary in fg fg-mcp; do
    executable="$(native_binary_path "$binary")"
    [ -x "$executable" ] || {
      printf 'verify: no returned native executable at %s\n' "$executable" >&2
      return 1
    }
  done
  fg_binary="$(native_binary_path fg)"
  mcp_binary="$(native_binary_path fg-mcp)"
  local -a suites=()
  local suite
  while IFS= read -r suite; do
    suites+=("$suite")
  done < <(grep -rlE --include='*.sh' \
    '^fge_kind (e2e-binary|real-browser|js-unit)$|^fge_smoke_campaign ' \
    "$ROOT/scripts/e2e/suites" | LC_ALL=C sort)
  [ "${#suites[@]}" -gt 0 ] || {
    printf 'verify: e2e: no product suites discovered\n' >&2
    return 1
  }
  echo_step "Running ${#suites[@]} product suites against $fg_binary"
  FG_BIN="$fg_binary" FG_MCP_BIN="$mcp_binary" "$ROOT/scripts/e2e/run_all.sh" \
    --timeout "${FGE_E2E_TIMEOUT:-1800}" "${suites[@]}"
}

run_full() {
  refuse_dormant "Full conformance/lab/fault/fuzz/corpus lane is not implemented yet"
}

run_release() {
  # D14 (license model) is launch-blocking, and it is checked FIRST and on its
  # own. The dormancy refusal below is TEMPORARY: FG-035/FG-091 remove it the
  # day a releasable binary exists. A launch-blocking licensing requirement that
  # rode on that refusal would silently disappear at exactly the moment it
  # starts to matter, so it does not ride on it. See FG-062 and
  # docs/LICENSING_DECISION.md; the gate exits 3 while the decision is deferred.
  echo_step "Checking the D14 license gate"
  "$ROOT/scripts/license_gate.sh"

  # The runner probe is intentionally narrower than a release attempt: target
  # builds require a caller-supplied durable root, exact matrix, and bounded
  # fgit-runner obligation. Calling the repository-owned entrypoint here keeps
  # release behavior out of workflow YAML while the lane below remains a typed
  # exit-3 refusal until the complete native matrix exists.
  echo_step "Checking DSR release-attempt runner wiring"
  run_native_tool fgit-release fgit-release-attempt --release-gate-probe

  refuse_dormant "No releasable FrankenGit binary or complete native target matrix exists yet"
}

run_lane() {
  case "$1" in
    docs) run_docs ;;
    constitution) run_constitution ;;
    fast) run_fast ;;
    e2e) run_e2e ;;
    full) run_full ;;
    release) run_release ;;
    # Feature lanes: thin dispatch to repository-owned verification scripts so
    # workflow manifests delegate to ./scripts/verify.sh instead of embedding
    # unique correctness invocations (AGENTS.md section 12).
    exact-patch) exec "$ROOT/scripts/verify_exact_patch.sh" ;;
    index-maintenance) exec "$ROOT/scripts/verify_index_maintenance.sh" ;;
    source-symbols) exec "$ROOT/scripts/verify_source_symbols.sh" ;;
    symbol-index) exec "$ROOT/scripts/verify_symbol_index.sh" ;;
    symbol-index-native) exec "$ROOT/scripts/verify_symbol_index.sh" native ;;
    symbol-index-maintenance) exec "$ROOT/scripts/verify_symbol_index.sh" maintenance ;;
    review-protection) exec "$ROOT/scripts/verify_review_protection.sh" ;;
    admission-tests) exec cargo test --locked -p fgit-admission --all-targets --no-fail-fast ;;
    native-rebase-check) exec "$ROOT/scripts/verify_native_rebase.sh" check ;;
    native-rebase-test) exec "$ROOT/scripts/verify_native_rebase.sh" test ;;
    pull-request-checks) exec "$ROOT/scripts/verify_pull_request_checks.sh" ;;
    continuous-serve) exec "$ROOT/scripts/verify_continuous_serve.sh" ;;
    tier-a) exec "$ROOT/scripts/verify_tier_a.sh" ;;
    *)
      print_usage
      return 2
      ;;
  esac
}

json_escape() {
  local value="$1"
  local escaped=""
  local character=""
  local ordinal=0
  local index=0

  for ((index = 0; index < ${#value}; index++)); do
    character="${value:index:1}"
    case "${character}" in
      '"') escaped+='\"' ;;
      '\') escaped+='\\' ;;
      $'\b') escaped+='\b' ;;
      $'\f') escaped+='\f' ;;
      $'\n') escaped+='\n' ;;
      $'\r') escaped+='\r' ;;
      $'\t') escaped+='\t' ;;
      *)
        if [[ "${character}" =~ [[:cntrl:]] ]]; then
          printf -v ordinal '%d' "'${character}"
          printf -v character '\\u%04x' "${ordinal}"
        fi
        escaped+="${character}"
        ;;
    esac
  done
  printf '%s' "${escaped}"
}

json_array() {
  local item=""
  local separator=""
  local result='['

  for item in "$@"; do
    result+="${separator}\"$(json_escape "${item}")\""
    separator=','
  done
  result+=']'
  printf '%s' "${result}"
}

sha256_stdin() {
  local digest=""
  local remainder=""

  if command -v sha256sum >/dev/null 2>&1; then
    if ! read -r digest remainder < <(sha256sum); then
      return 1
    fi
  elif command -v shasum >/dev/null 2>&1; then
    if ! read -r digest remainder < <(shasum -a 256); then
      return 1
    fi
  else
    return 1
  fi
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

sha256_file() {
  local path="$1"
  [[ -f "${path}" ]] || return 1
  sha256_stdin < "${path}"
}

now_epoch_ns() {
  local value=""

  value="$(date +%s%N 2>/dev/null || true)"
  if [[ "${value}" =~ ^[0-9]{19,}$ ]]; then
    printf '%s\n' "${value}"
  else
    value="$(date +%s 2>/dev/null || printf '0')"
    printf '%s000000000\n' "${value}"
  fi
}

tool_version() {
  local tool="$1"

  if command -v "${tool}" >/dev/null 2>&1; then
    "${tool}" -V 2>&1 || printf 'unavailable'
  else
    printf 'unavailable'
  fi
}

capture_source_state() {
  VERIFY_HEAD="$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
  VERIFY_DIRTY_STATUS="$(git -c color.status=false status --porcelain=v1 --untracked-files=all 2>/dev/null || true)"
  VERIFY_DIRTY=false
  if [[ -n "${VERIFY_DIRTY_STATUS}" ]]; then
    VERIFY_DIRTY=true
  fi
  VERIFY_RUSTC_VERSION="$(tool_version rustc)"
  VERIFY_CARGO_VERSION="$(tool_version cargo)"

  if ! VERIFY_DIRTY_STATUS_SHA256="$(printf '%s' "${VERIFY_DIRTY_STATUS}" | sha256_stdin)"; then
    VERIFY_DIRTY_STATUS_SHA256=''
    artifact_warning 'cannot hash dirty status'
  fi
  if ! VERIFY_DIRTY_DIFF_SHA256="$(git -c color.ui=false diff --binary HEAD 2>/dev/null | sha256_stdin)"; then
    VERIFY_DIRTY_DIFF_SHA256=''
    artifact_warning 'cannot hash dirty diff'
  fi
}

emit_captured_output() {
  local stdout_path="$1"
  local stderr_path="$2"

  printf 'stdout\0'
  cat -- "${stdout_path}"
  printf '\0stderr\0'
  cat -- "${stderr_path}"
}

artifact_timestamp_utc() {
  local nanoseconds=""
  local seconds=""

  # Do not depend on a particular `date -u` implementation accepting a literal
  # trailing Z alongside %N.  POSIX date does not define %N, so accept it only
  # when it expands to the complete numeric subsecond suffix and otherwise
  # take the portable seconds-resolution path.  LC_ALL and TZ are deliberately
  # set for this command rather than inherited from the lane environment.
  nanoseconds="$(LC_ALL=C TZ=UTC0 date '+%Y%m%dT%H%M%S%N' 2>/dev/null || true)"
  if [[ "${nanoseconds}" =~ ^[0-9]{8}T[0-9]{6}[0-9]{9}$ ]]; then
    printf '%sZ\n' "${nanoseconds}"
    return 0
  fi

  seconds="$(LC_ALL=C TZ=UTC0 date '+%Y%m%dT%H%M%S' 2>/dev/null || true)"
  if [[ "${seconds}" =~ ^[0-9]{8}T[0-9]{6}$ ]]; then
    printf '%sZ\n' "${seconds}"
    return 0
  fi

  return 1
}

write_replay_artifact() {
  local lane_name="$1"
  local command_json="$2"
  local started_ns="$3"
  local finished_ns="$4"
  local lane_exit="$5"
  local stdout_path="$6"
  local stderr_path="$7"
  local artifact_root="${VERIFY_ARTIFACT_DIR:-${ROOT}/evidence/verify}"
  local timestamp=""
  local artifact_path=""
  local output_path=""
  local temporary_artifact_path=""
  local temporary_output_path=""
  local wall_time_ms=0
  local stdout_sha256=""
  local stderr_sha256=""
  local captured_output_sha256=""

  if ! timestamp="$(artifact_timestamp_utc)"; then
    artifact_warning 'cannot format a UTC artifact timestamp'
    return 0
  fi
  artifact_path="${artifact_root}/${timestamp}-${lane_name}.json"
  output_path="${artifact_root}/${timestamp}-${lane_name}.output"
  wall_time_ms=$(((finished_ns - started_ns) / 1000000))

  if ! stdout_sha256="$(sha256_file "${stdout_path}")"; then
    artifact_warning 'cannot hash captured stdout'
    return 0
  fi
  if ! stderr_sha256="$(sha256_file "${stderr_path}")"; then
    artifact_warning 'cannot hash captured stderr'
    return 0
  fi
  if ! mkdir -p "${artifact_root}"; then
    artifact_warning "cannot create ${artifact_root}"
    return 0
  fi
  if [[ -e "${artifact_path}" || -e "${output_path}" ]]; then
    artifact_warning "refusing to overwrite ${artifact_path} or its captured output"
    return 0
  fi
  if ! temporary_output_path="$(mktemp "${artifact_root}/.verify-output.XXXXXXXX")"; then
    artifact_warning "cannot allocate captured output for ${artifact_path}"
    return 0
  fi
  if ! emit_captured_output "${stdout_path}" "${stderr_path}" > "${temporary_output_path}"; then
    artifact_warning "cannot retain captured output for ${artifact_path}"
    rm -f -- "${temporary_output_path}" || true
    return 0
  fi
  if ! captured_output_sha256="$(sha256_file "${temporary_output_path}")"; then
    artifact_warning 'cannot hash retained captured output'
    rm -f -- "${temporary_output_path}" || true
    return 0
  fi
  if ! temporary_artifact_path="$(mktemp "${artifact_root}/.verify-artifact.XXXXXXXX")"; then
    artifact_warning "cannot allocate an artifact in ${artifact_root}"
    rm -f -- "${temporary_output_path}" || true
    return 0
  fi

  if ! {
    printf '{'
    printf '"schema":"%s",' "$(json_escape "${VERIFY_ARTIFACT_SCHEMA}")"
    printf '"schema_version":%s,' "${VERIFY_ARTIFACT_SCHEMA_VERSION}"
    printf '"created_at_utc":"%s",' "$(json_escape "${timestamp}")"
    printf '"lane":"%s",' "$(json_escape "${lane_name}")"
    printf '"command_argv":%s,' "${command_json}"
    printf '"head":"%s",' "$(json_escape "${VERIFY_HEAD}")"
    printf '"dirty":%s,' "${VERIFY_DIRTY}"
    printf '"dirty_status":"%s",' "$(json_escape "${VERIFY_DIRTY_STATUS}")"
    printf '"dirty_status_sha256":"%s",' "${VERIFY_DIRTY_STATUS_SHA256}"
    printf '"dirty_diff_sha256":"%s",' "${VERIFY_DIRTY_DIFF_SHA256}"
    printf '"rustc_version":"%s",' "$(json_escape "${VERIFY_RUSTC_VERSION}")"
    printf '"cargo_version":"%s",' "$(json_escape "${VERIFY_CARGO_VERSION}")"
    printf '"exit_code":%s,' "${lane_exit}"
    printf '"wall_time_ms":%s,' "${wall_time_ms}"
    printf '"stdout_sha256":"%s",' "${stdout_sha256}"
    printf '"stderr_sha256":"%s",' "${stderr_sha256}"
    printf '"captured_output_format":"stdout\\u0000<bytes>\\u0000stderr\\u0000<bytes>",'
    printf '"captured_output_file":"%s",' "$(json_escape "${timestamp}-${lane_name}.output")"
    printf '"captured_output_sha256":"%s"}\n' "${captured_output_sha256}"
  } > "${temporary_artifact_path}"; then
    artifact_warning "cannot write ${artifact_path}"
    rm -f -- "${temporary_artifact_path}" "${temporary_output_path}" || true
    return 0
  fi
  if ! mv -- "${temporary_output_path}" "${output_path}"; then
    artifact_warning "cannot publish captured output for ${artifact_path}"
    rm -f -- "${temporary_artifact_path}" "${temporary_output_path}" || true
    return 0
  fi
  if ! mv -- "${temporary_artifact_path}" "${artifact_path}"; then
    artifact_warning "cannot publish ${artifact_path}"
    rm -f -- "${temporary_artifact_path}" "${output_path}" || true
    return 0
  fi
}

artifact_enabled=true
declare -a command_argv=("$0" "$@")
declare -a lane_args=()
argument=""
for argument in "$@"; do
  if [[ "${argument}" == "--no-artifact" ]]; then
    artifact_enabled=false
  else
    lane_args+=("${argument}")
  fi
done

if [[ "${#lane_args[@]}" -ne 1 ]]; then
  print_usage
  exit 2
fi
lane="${lane_args[0]}"

if [[ "${artifact_enabled}" == false ]]; then
  run_lane "${lane}"
  exit "$?"
fi

capture_source_state
command_json="$(json_array "${command_argv[@]}")"
started_ns="$(now_epoch_ns)"
if ! stdout_path="$(mktemp "${TMPDIR:-/tmp}/frankengit-verify-stdout.XXXXXXXX")"; then
  artifact_warning 'cannot allocate stdout capture; running lane without an artifact'
  set +e
  (
    set -e
    run_lane "${lane}"
  )
  lane_exit=$?
  set -e
  exit "${lane_exit}"
fi
if ! stderr_path="$(mktemp "${TMPDIR:-/tmp}/frankengit-verify-stderr.XXXXXXXX")"; then
  artifact_warning 'cannot allocate stderr capture; running lane without an artifact'
  rm -f -- "${stdout_path}" || true
  set +e
  (
    set -e
    run_lane "${lane}"
  )
  lane_exit=$?
  set -e
  exit "${lane_exit}"
fi

set +e
(
  set -e
  run_lane "${lane}"
) > "${stdout_path}" 2> "${stderr_path}"
lane_exit=$?
set -e
finished_ns="$(now_epoch_ns)"
write_replay_artifact "${lane}" "${command_json}" "${started_ns}" "${finished_ns}" "${lane_exit}" "${stdout_path}" "${stderr_path}"

if ! cat -- "${stdout_path}"; then
  artifact_warning 'cannot replay captured stdout'
fi
if ! cat -- "${stderr_path}" >&2; then
  artifact_warning 'cannot replay captured stderr'
fi
rm -f -- "${stdout_path}" "${stderr_path}" || true
exit "${lane_exit}"
