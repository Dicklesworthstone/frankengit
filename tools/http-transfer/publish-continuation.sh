#!/usr/bin/env bash
set -euo pipefail

BASE=2ab7584ebdedd2da1e22e1c00b992d707defa253
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"

temp="$RUNNER_TEMP/http-continuation"
mkdir -p "$temp/payload"
cat tools/http-transfer/continuation.part00 \
    tools/http-transfer/continuation.part01 \
    tools/http-transfer/continuation.part02 \
    tools/http-transfer/continuation.part03 \
    tools/http-transfer/continuation.part04 > "$temp/payload.b64"
test "$(sha256sum "$temp/payload.b64" | awk '{print $1}')" = 0f3f168bcb7811d5634677edc9c5f61c6bf6dc748a03bd144e8ab0a3925ab85b
base64 -d "$temp/payload.b64" > "$temp/patches.tar.gz"
test "$(sha256sum "$temp/patches.tar.gz" | awk '{print $1}')" = a9482edab3451b7dbd6d5d8c244ddd8528180d3724207e3619dd3a7ebadb57c2
tar -xzf "$temp/patches.tar.gz" -C "$temp/payload"
printf '%s  %s\n' \
  9cc4a44e9562e2be604f838d3f7d43ec6fad753246a712ecfced12fdc8de96ed "$temp/payload/commits/0001-feat-wire-implement-native-stateless-HTTP-fetch-nego.patch" \
  1d1dd3f9388ad87db5816df65398ac481bd30a38ccd2d0706eed610704293e1c "$temp/payload/commits/0002-feat-wire-compose-HTTP-RPC-bodies-with-native-Git-an.patch" \
  9e00ab2b68cca8bcc63182443e06f765cbd68faba5fbdc209a9c46d489fcb1d2 "$temp/payload/commits/0003-feat-wire-preserve-stateless-v2-negotiation-and-mult.patch" \
  6473155af42c6a57ae918ab30d4b475689e7abc8250f04d1c547bf05aac59a1e "$temp/payload/commits/0004-feat-wire-stream-bounded-native-packs-into-HTTP-resp.patch" \
  bbb57aa086637e432909e17ddeffc370ba4ca3c92ca8ea5991bbef76f55e0891 "$temp/payload/commits/0005-fix-wire-validate-negotiation-controls-and-retain-fr.patch" \
  | sha256sum -c -

work="$temp/work"
git worktree add --detach "$work" "$BASE"
cd "$work"
git config user.name 'Jeff Emanuel'
git config user.email '35050222+Dicklesworthstone@users.noreply.github.com'
for patch in "$temp"/payload/commits/000*.patch; do
  git am --committer-date-is-author-date "$patch"
done
test "$(git rev-list --count "$BASE"..HEAD)" = 5

cat > "$temp/expected-subjects.txt" <<'SUBJECTS'
feat(wire): implement native stateless HTTP fetch negotiation rounds (FG-105a)
feat(wire): compose HTTP RPC bodies with native Git and quarantine (FG-105a)
feat(wire): preserve stateless v2 negotiation and multiplexed responses (FG-105a)
feat(wire): stream bounded native packs into HTTP responses (FG-105a)
fix(wire): validate negotiation controls and retain fragmentation invariance (FG-105a)
SUBJECTS
git log --reverse --format='%s' "$BASE"..HEAD > "$temp/actual-subjects.txt"
cmp "$temp/expected-subjects.txt" "$temp/actual-subjects.txt"
git diff "$BASE"..HEAD --check

cat > "$temp/expected-files.txt" <<'FILES'
crates/fgit-wire/src/lib.rs
crates/fgit-wire/src/smart_http.rs
crates/fgit-wire/src/smart_http/response.rs
crates/fgit-wire/src/smart_http/rpc.rs
crates/fgit-wire/tests/smart_http_response.rs
crates/fgit-wire/tests/smart_http_rpc.rs
crates/fgit-wire/tests/stateless_http_negotiation.rs
FILES
git diff --name-only "$BASE"..HEAD | sort > "$temp/actual-files.txt"
cmp "$temp/expected-files.txt" "$temp/actual-files.txt"

test "$(git hash-object crates/fgit-wire/src/lib.rs)" = c603b2cca00a55980d37914f48b4bb6af264ac39
test "$(git hash-object crates/fgit-wire/src/smart_http.rs)" = 9aee279464e0862aea9c5cbcfb715753e21b638c
test "$(git hash-object crates/fgit-wire/src/smart_http/rpc.rs)" = c687dec3756d355878cfa33e829a04084ab894ca
test "$(git hash-object crates/fgit-wire/src/smart_http/response.rs)" = 94243f918c3a1ff719214abcd7c5308c84e88405
test "$(git hash-object crates/fgit-wire/tests/stateless_http_negotiation.rs)" = 3a7d920f0484cc57b20262ed2169161959d07a53
test "$(git hash-object crates/fgit-wire/tests/smart_http_rpc.rs)" = c3e5fe7887deda23fe5cbc7370e6b72ebf765ae0
test "$(git hash-object crates/fgit-wire/tests/smart_http_response.rs)" = 6c125abdd7fc3cf30c9128bab9a44e0ef68ab6bc

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="$RUNNER_TEMP/frankengit-http-target"
echo '=== formatting owned continuation files ==='
mapfile -t owned_files < "$temp/expected-files.txt"
set +e
rustfmt --edition 2024 --config skip_children=true "${owned_files[@]}"
fmt_rc=$?
set -e
echo "rustfmt rc=$fmt_rc"
git status --short
test "$fmt_rc" = 0

git diff --name-only | sort > "$temp/formatted-files.txt"
if test -s "$temp/formatted-files.txt"; then
  echo 'formatted files:'
  cat "$temp/formatted-files.txt"
  unexpected="$(comm -23 "$temp/formatted-files.txt" "$temp/expected-files.txt")"
  if test -n "$unexpected"; then
    echo 'unexpected formatter ownership:' >&2
    printf '%s\n' "$unexpected" >&2
    exit 1
  fi
  git diff --check
  while IFS= read -r path; do git add -- "$path"; done < "$temp/formatted-files.txt"
  git commit -m 'fix(wire): normalize smart HTTP continuation formatting (FG-105a)'
fi

test -z "$(git status --porcelain)"
rustfmt --edition 2024 --config skip_children=true --check "${owned_files[@]}"
echo '=== focused wire tests ==='
cargo test -p fgit-wire --lib --test stateless_http_negotiation --test smart_http_rpc --test smart_http_response

git diff "$BASE"..HEAD --check
remote_main="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$remote_main" = "$BASE"
echo "publishing $(git rev-parse HEAD) over exact predecessor $BASE"
git push origin HEAD:refs/heads/main
published="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
test "$published" = "$(git rev-parse HEAD)"
echo "PUBLISHED=$published"
