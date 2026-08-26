#!/usr/bin/env bash
# e2e: FG-042c account-security adversarial corpus.
#
# Runs the five in-crate campaign suites against the landed fgit-identity
# controls and receipts the aggregate: session fixation/hijack/rotation,
# recovery delay/notification/downgrade wall, OAuth PKCE/redirect/replay,
# passkey challenge-binding/clone-detection, stuffing rate-limit opacity,
# plus elevation-token lifecycle. Each suite pairs every refusal with a
# near-identical permitted twin, so a control that simply always refuses
# cannot satisfy this lane.
set -euo pipefail

AS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AS_REPO=$(cd "$AS_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$AS_REPO/scripts/e2e/lib.sh"

fge_init fg042c-account-security-corpus
fge_context bead frankengit-fg042c-account-security-evidence-9xq9
fge_context crate fgit-identity

fge_phase setup

for suite in \
  auth_adversarial_sessions.rs \
  auth_adversarial_recovery.rs \
  auth_adversarial_oauth.rs \
  auth_adversarial_passkey.rs \
  auth_adversarial_rate_limit.rs; do
  fge_assert_file "FG-042C-CORPUS-FILE-$suite" \
    "$AS_REPO/crates/fgit-identity/tests/$suite" \
    "campaign suite $suite is checked in"
done

fge_phase action

for target in auth_adversarial_sessions auth_adversarial_recovery auth_adversarial_oauth \
  auth_adversarial_passkey auth_adversarial_rate_limit; do
  fge_run "corpus-$target" \
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AS_REPO/target}" \
    cargo test --locked -p fgit-identity --test "$target" || true
  rc=$FGE_LAST_EXIT
  fge_assert_exit "FG-042C-CORPUS-$target" 0 "$rc" \
    "campaign suite $target passes against the landed controls"
done

fge_phase teardown
