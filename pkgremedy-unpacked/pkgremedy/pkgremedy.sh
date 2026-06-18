#!/usr/bin/env bash
# pkgremedy launcher — run the same tool in Docker or natively.
#
#   ./pkgremedy.sh [MODE] [-- pkgremedy args...]
#
# MODE:
#   auto    (default) use docker if available, else native
#   docker  run in the container image (builds it on first use)
#   native  run on this machine using an isolated, cached tools venv
#
# Examples:
#   ./pkgremedy.sh                       # scan current dir's image or env
#   ./pkgremedy.sh native -- plan --fail-on fixable
#   ./pkgremedy.sh native -- plan --python /path/to/target/venv/bin/python
#   ./pkgremedy.sh docker -- plan --md reports/plan.md
#   ./pkgremedy.sh native -- plan --ecosystem both --env myenv
#
# Native mode keeps the scanners (pip-audit, pipdeptree) in a separate venv at
# ~/.cache/pkgremedy so they never get installed into the environment you scan.
set -euo pipefail

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"; SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
HERE="$(cd -P "$(dirname "$SOURCE")" && pwd)"
SCRIPT="$HERE/pkgremedy.py"
IMAGE="${PKGREMEDY_IMAGE:-pkgremedy:latest}"
CACHE="${PKGREMEDY_CACHE:-$HOME/.cache/pkgremedy}"
TOOLS_VENV="$CACHE/venv"

MODE="auto"
case "${1:-}" in
  auto|docker|native) MODE="$1"; shift ;;
esac
[[ "${1:-}" == "--" ]] && shift   # allow an explicit separator
ARGS=("$@")
[[ ${#ARGS[@]} -eq 0 ]] && ARGS=("scan")

have() { command -v "$1" >/dev/null 2>&1; }

run_native() {
  if ! have python3; then echo "python3 not found." >&2; exit 1; fi
  # build/refresh the isolated tools venv once
  if [[ ! -x "$TOOLS_VENV/bin/python" ]]; then
    echo "[native] creating tools venv at $TOOLS_VENV" >&2
    python3 -m venv "$TOOLS_VENV"
    "$TOOLS_VENV/bin/python" -m pip install -q --upgrade pip pip-audit pipdeptree ruamel.yaml
  fi
  # If the user did NOT pass --python and is sitting in an activated venv/conda
  # env, target that interpreter explicitly so the scan reflects it (and stays
  # clean, since the scanners live in the tools venv, not the target).
  local extra=()
  if [[ ! " ${ARGS[*]} " == *" --python "* && -n "${VIRTUAL_ENV:-}" ]]; then
    extra=(--python "$VIRTUAL_ENV/bin/python")
  fi
  exec "$TOOLS_VENV/bin/python" "$SCRIPT" "${ARGS[@]}" "${extra[@]}"
}

run_docker() {
  if ! have docker; then echo "docker not found." >&2; exit 1; fi
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[docker] building $IMAGE" >&2
    docker build -t "$IMAGE" "$HERE"
  fi
  # mount cwd so --md/--json paths land on the host; reports dir is handy
  exec docker run --rm -v "$PWD:/work" -w /work "$IMAGE" "${ARGS[@]}"
}

case "$MODE" in
  native) run_native ;;
  docker) run_docker ;;
  auto)   if have docker; then run_docker; else run_native; fi ;;
esac
