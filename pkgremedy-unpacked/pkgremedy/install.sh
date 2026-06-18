#!/usr/bin/env bash
# Symlink pkgremedy onto your PATH (repo stays the source of truth; wrappers
# resolve their real directory through the symlink).
#   pkgremedy      -> the Python CLI (native scan/plan/apply/fix/envfix)
#   pkgremedy-run  -> one-command docker build-from-base + run
# For a fully isolated native run that bootstraps its own scanners, use
# ./pkgremedy.sh native -- <args> from the repo, or `pipx install .`.
set -euo pipefail
HERE="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${1:-$HOME/.local/bin}"
mkdir -p "$BIN"
chmod +x "$HERE/pkgremedy.py" "$HERE"/*.sh
ln -sf "$HERE/pkgremedy.py"     "$BIN/pkgremedy"
ln -sf "$HERE/pkgremedy-run.sh" "$BIN/pkgremedy-run"
echo "linked into $BIN:  pkgremedy (CLI), pkgremedy-run (docker one-shot)"
echo "ensure $BIN is on your PATH. native CLI needs pip-audit/pipdeptree/ruamel.yaml"
echo "available (pipx install . is the easy way), or use ./pkgremedy.sh native."
