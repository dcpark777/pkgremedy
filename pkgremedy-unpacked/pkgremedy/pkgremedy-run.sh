#!/usr/bin/env bash
# pkgremedy-run — one command: build an image from YOUR base + environment.yml
# (reproducing `conda env create -f environment.yml`), run pkgremedy inside it,
# stream the report, and write the patched file back to your project dir.
#
#   ./pkgremedy-run.sh --base <IMAGE> [--file environment.yml] [--channel conda-forge]
#                      [--no-cache] [-- <pkgremedy args>]
#
# Defaults to:  envfix --file environment.yml --out environment.fixed.yml
# So the common case is literally:
#   ./pkgremedy-run.sh --base your.registry/spark-base:2026.06
#
# Repeat runs are fast: Docker caches the env layer and only rebuilds it when
# environment.yml changes. Set PKGREMEDY_BASE to avoid retyping --base.
# Set PKGREMEDY_DRY=1 to print the docker commands instead of running them.
set -euo pipefail

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"; SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
HERE="$(cd -P "$(dirname "$SOURCE")" && pwd)"
BASE="${PKGREMEDY_BASE:-}"
FILE="environment.yml"
NO_CACHE=""
DRY="${PKGREMEDY_DRY:-0}"

# --- parse wrapper flags; everything after `--` (or the first unknown) passes through
PASS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)     BASE="$2"; shift 2 ;;
    --file)     FILE="$2"; shift 2 ;;
    --channel)  EXTRA_CHANNELS="${EXTRA_CHANNELS:-} $2"; shift 2 ;;
    --no-cache) NO_CACHE="--no-cache"; shift ;;
    --dry)      DRY=1; shift ;;
    --)         shift; PASS+=("$@"); break ;;
    *)          PASS+=("$1"); shift ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
[[ -n "$BASE" ]] || die "need --base <image> (or set PKGREMEDY_BASE)"
[[ -f "$FILE" ]] || die "environment file not found: $FILE"
command -v docker >/dev/null 2>&1 || { echo "docker not found — showing commands only." >&2; DRY=1; }

PROJ="$(cd "$(dirname "$FILE")" && pwd)"
FNAME="$(basename "$FILE")"
# env name = the file's `name:` (what `conda env create -f` uses)
NAME="$(grep -E '^[[:space:]]*name:' "$FILE" | head -1 | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '"'"'"' ')"
NAME="${NAME:-app}"
TAG="pkgremedy-app:${NAME}"

# channels declared in environment.yml (preserve order), for the scanner install
FILE_CHANNELS="$(awk '
  /^channels:/ {inch=1; next}
  inch && /^[^[:space:]-]/ {inch=0}
  inch && /^[[:space:]]*-/ {gsub(/^[[:space:]]*-[[:space:]]*/,""); gsub(/["'"'"']/,""); print}
' "$FILE" | tr "\n" " ")"
# extra channels passed via repeated --channel
EXTRA_CHANNELS="${EXTRA_CHANNELS:-}"

# default action: envfix, writing the patched file into the mounted project dir
if [[ ${#PASS[@]} -eq 0 ]]; then
  PASS=(envfix --file "$FNAME" --out environment.fixed.yml)
else
  # for scan/plan/apply/fix, inject --env <name> if the user didn't specify one
  case "${PASS[0]}" in
    scan|plan|apply|fix)
      [[ " ${PASS[*]} " == *" --env "* ]] || PASS+=(--ecosystem conda --env "$NAME") ;;
  esac
fi

# --- assemble a minimal build context (Dockerfile + script + the env file)
CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
cp "$HERE/Dockerfile" "$HERE/pkgremedy.py" "$CTX/"
cp "$FILE" "$CTX/environment.yml"   # Dockerfile's COPY expects this name

BUILD=(docker build $NO_CACHE
  --build-arg BASE_IMAGE="$BASE"
  --build-arg ENV_NAME="$NAME"
  --build-arg CHANNELS="$(echo "$FILE_CHANNELS $EXTRA_CHANNELS" | xargs)"
  -t "$TAG" "$CTX")
# forward extra channels to pkgremedy's verify/apply too
CHAN_ARGS=()
for c in $EXTRA_CHANNELS; do CHAN_ARGS+=(--channel "$c"); done
RUN=(docker run --rm
  -v "$PROJ:/work" -w /work
  -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/cache
  "$TAG" "${PASS[@]}" "${CHAN_ARGS[@]}")

if [[ "$DRY" == "1" ]]; then
  echo "# build context: $CTX  (Dockerfile, pkgremedy.py, environment.yml)"
  echo "# env name from file: $NAME"
  printf '%q ' "${BUILD[@]}"; echo
  printf '%q ' "${RUN[@]}";   echo
  exit 0
fi

echo ">> building $TAG from $BASE (cached after first run)…" >&2
"${BUILD[@]}"
echo ">> running: pkgremedy ${PASS[*]}" >&2
"${RUN[@]}"
echo ">> done. Outputs (e.g. environment.fixed.yml) are in $PROJ" >&2
