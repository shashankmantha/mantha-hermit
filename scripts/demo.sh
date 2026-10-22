#!/usr/bin/env bash
# Hermit end to end on the example rules: sort into packs, clean-set test, export,
# sign, verify, and reject a tampered bundle. No Ollama, no network, about 10 seconds.
#
#   ./scripts/demo.sh            (after `pip install -e .`)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/hermit-demo.XXXXXX")"
trap 'echo; echo "Demo workspace kept at: $work"' EXIT

mkdir -p "$work/config"
cp "$here"/config/*.toml "$work/config/"
python3 - "$work/config/hermit.toml" "$here/examples/clean" "$work/keys/minisign.key" <<'EOF'
import re, sys
path, clean, key = sys.argv[1:]
t = open(path).read()
t = re.sub(r'^clean_dirs = .*$', f'clean_dirs = ["{clean}"]', t, flags=re.M)
t = re.sub(r'^secret_key = .*$', f'secret_key = "{key}"', t, flags=re.M)
t = re.sub(r'^release_repo = .*$', 'release_repo = ""', t, flags=re.M)
t = re.sub(r'^yara_x_version = .*$', 'yara_x_version = ""', t, flags=re.M)
open(path, "w").write(t)
EOF

h() { echo; echo "\$ hermit $*"; hermit --config-dir "$work/config" "$@"; }
step() { echo; echo "=== $*"; }
rules=(--rules "$here/examples/rules" --no-fetch --no-llm --yes)

step "1. Plain-English requests become pack updates (rules-only mode, no model needed)"
h ask "update rule list to include all new rules related to video games" "${rules[@]}"
h ask "add new core threats" "${rules[@]}"
h ask "add new cracked software rules" "${rules[@]}"
h ask "add the new riskware rules" "${rules[@]}"

step "2. New rules start on probation at info; end it early (clean-set tested first)"
h promote --now --yes
h packs

step "3. Why a rule landed where it did"
h explain SUSP_Example_Defender_Exclusion --rules "$here/examples/rules"

step "4. Phase 1a: unsigned bundle folder in contract v1 layout"
h export-bundle --unsigned "$work/bundle"
h validate "$work/bundle"

step "5. Phase 1b: sign a bundle (minisign format) and verify it the way Mantha Ray will"
h keygen
h publish --no-push
tarball="$(ls "$work"/out/bundles/*/mantha-packs-*.tar.gz | head -1)"
h verify "$tarball"

step "6. A tampered bundle is rejected"
cp "$tarball" "$tarball.minisig" "$work/"
tampered="$work/$(basename "$tarball")"
python3 - "$tampered" <<'EOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 1
open(p, "wb").write(bytes(b))
EOF
if hermit --config-dir "$work/config" verify "$tampered"; then
  echo "ERROR: tampered bundle was accepted"; exit 1
fi
echo
echo "Demo finished: packs built, bundle signed and verified, tampering caught."
