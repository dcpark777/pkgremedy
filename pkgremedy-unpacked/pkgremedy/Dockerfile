# syntax=docker/dockerfile:1
# pkgremedy scanner image — bring your own base.
#
# Works whether or not your base already has an env manager: if mamba/micromamba/
# conda is absent, the micromamba static binary is dropped in, then the conda env
# is created from your environment.yml. Requires a glibc Linux base with a shell
# (Debian/Ubuntu/UBI/miniconda/etc). NOT supported: Alpine/musl, scratch, distroless.
#
# Build:
#   docker build -t pkgremedy:latest .
#   docker build --build-arg BASE_IMAGE=your.registry/golden-python:3.12 -t pkgremedy:latest .
#   docker build --build-arg BASE_IMAGE=continuumio/miniconda3 --build-arg ENV_NAME=appenv -t pkgremedy:latest .
# Provide an environment.yml in the build context to control the env exactly.

ARG BASE_IMAGE=mambaorg/micromamba:latest
FROM ${BASE_IMAGE}

ARG TARGETARCH
ARG ENV_NAME=appenv
ARG CHANNEL=conda-forge
ARG CHANNELS=""
ENV MAMBA_ROOT_PREFIX=/opt/conda

USER root

# 1) Ensure an env manager exists; bootstrap micromamba if not.
RUN set -eux; \
    if   command -v mamba      >/dev/null 2>&1; then MGR=mamba; \
    elif command -v micromamba >/dev/null 2>&1; then MGR=micromamba; \
    elif command -v conda      >/dev/null 2>&1; then MGR=conda; \
    else \
      case "${TARGETARCH:-amd64}" in arm64) MA=linux-aarch64 ;; *) MA=linux-64 ;; esac; \
      command -v curl >/dev/null 2>&1 || command -v tar >/dev/null 2>&1 || \
        (apt-get update && apt-get install -y --no-install-recommends curl ca-certificates bzip2) || \
        (microdnf install -y curl bzip2 tar) || (yum install -y curl bzip2 tar) || true; \
      curl -Ls "https://micro.mamba.pm/api/micromamba/${MA}/latest" | tar -xj -C /usr/local bin/micromamba; \
      MGR=micromamba; \
    fi; \
    echo "$MGR" > /opt/.pkgmgr

# 2) Create the conda env (from environment.yml if you supply one) + scanners.
#    filelock is required or pip-audit's FileCache import crashes.
COPY environment.ym[l] /tmp/pkgremedy/
RUN set -eux; MGR="$(cat /opt/.pkgmgr)"; \
    if [ -f /tmp/pkgremedy/environment.yml ]; then \
      if [ "$MGR" = micromamba ]; then $MGR create -y -n "${ENV_NAME}" -f /tmp/pkgremedy/environment.yml; \
      else $MGR env create -n "${ENV_NAME}" -f /tmp/pkgremedy/environment.yml; fi; \
    else \
      $MGR create -y -n "${ENV_NAME}" -c "${CHANNEL}" python=3.12 pip; \
    fi; \
    CH=""; for c in $CHANNELS; do CH="$CH -c $c"; done; CH="$CH -c conda-forge"; \
    ( $MGR install -y -n "${ENV_NAME}" $CH pip-audit pipdeptree filelock ruamel.yaml \
      || $MGR run -n "${ENV_NAME}" python -m pip install pip-audit pipdeptree filelock ruamel.yaml ); \
    $MGR clean -a -y

COPY pkgremedy.py /opt/pkgremedy/pkgremedy.py

# 3) Base-agnostic entrypoint: run pkgremedy *inside* the env via the detected mgr.
RUN printf '#!/bin/sh\nexec "$(cat /opt/.pkgmgr)" run -n "%s" python /opt/pkgremedy/pkgremedy.py "$@"\n' \
        "${ENV_NAME}" > /usr/local/bin/pkgremedy-entry && chmod +x /usr/local/bin/pkgremedy-entry

ENTRYPOINT ["/usr/local/bin/pkgremedy-entry"]
# default: scan the baked env. If you changed ENV_NAME, change --env to match.
CMD ["scan", "--ecosystem", "conda", "--env", "appenv", "--fail-on", "fixable"]
