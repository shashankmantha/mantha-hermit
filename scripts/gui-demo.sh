#!/usr/bin/env bash
# Try the Hermit web app on the example rules, in a throwaway workspace.
# Works without Ollama (rules-only mode); with Ollama running, the model is used too.
#
#   ./scripts/gui-demo.sh            (after `pip install -e .`)
#   then try: "update rule list to include all new rules related to video games"
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/hermit-gui.XXXXXX")"

mkdir -p "$work/config" "$work/sources"
cp "$here"/config/*.toml "$work/config/"
: > "$work/config/sources.toml"                 # use every folder in sources/
cp -r "$here/examples/rules" "$work/sources/examples"
python3 - "$work/config/hermit.toml" "$here/examples/clean" "$work/keys/minisign.key" <<'EOF'
import re, sys
path, clean, key = sys.argv[1:]
t = open(path).read()
t = re.sub(r'^clean_dirs = .*$', f'clean_dirs = ["{clean}"]', t, flags=re.M)
t = re.sub(r'^secret_key = .*$', f'secret_key = "{key}"', t, flags=re.M)
t = re.sub(r'^release_repo = .*$', 'release_repo = ""', t, flags=re.M)
t = re.sub(r'^fetch_before_ask = .*$', 'fetch_before_ask = false', t, flags=re.M)
open(path, "w").write(t)
EOF
hermit --config-dir "$work/config" keygen >/dev/null 2>&1 || true

echo "Demo workspace: $work"
exec hermit --config-dir "$work/config" serve "$@"
