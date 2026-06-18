# Running pkgremedy in Docker

The image scans the environment **installed inside it** (pip-audit audits the
live interpreter), so you bake the env in and then scan it — you get *installed*
versions, not a re-resolve.

## Bring your own base image
`BASE_IMAGE` is a build arg. The Dockerfile handles three cases automatically:

| your base has… | what happens |
|---|---|
| mamba / conda / micromamba already | it's used as-is |
| Python/pip but no conda | micromamba static binary is dropped in, env created |
| neither (minimal Debian/UBI) | micromamba bootstrapped (brings its own Python) |

```bash
# default base
docker build -t pkgremedy:latest .

# your hardened/golden base
docker build --build-arg BASE_IMAGE=your.registry/golden-python:3.12 -t pkgremedy:latest .

# a conda-based base, with your env name
docker build --build-arg BASE_IMAGE=continuumio/miniconda3 \
             --build-arg ENV_NAME=appenv -t pkgremedy:latest .
```

**Control the env exactly:** drop an `environment.yml` in the build context. It's
used to create the env (`micromamba create -f` / `conda env create -f`); the
scanners (`pip-audit pipdeptree filelock`) are added on top. No file → a minimal
`python + pip` env is created.

Build-args: `BASE_IMAGE`, `ENV_NAME` (default `appenv`), `CHANNEL` (default
`conda-forge` — point at your internal channel), `TARGETARCH` (auto via BuildKit).

**Requirements / limits:** glibc Linux base with a shell. Not supported: Alpine
(musl), `scratch`, distroless. `filelock` is installed deliberately — without it
pip-audit's file cache crashes.

## Run it
```bash
docker run --rm pkgremedy:latest                                  # scan baked env (CMD default)
docker run --rm pkgremedy:latest plan --ecosystem conda --env appenv
docker run --rm -v "$PWD/reports:/work" -w /work pkgremedy:latest \
    plan --ecosystem conda --env appenv --md /work/plan.md
```
Everything after the image name is passed to pkgremedy. If you changed
`ENV_NAME`, pass the matching `--env`.

## Pattern A — gate your own app / pipeline / KFP-component image
Add an audit stage on top of your real image; it inherits the exact deps.
```dockerfile
FROM myorg/fraud-trainer:1.4 AS app
FROM app AS audit
USER root
RUN pip install --no-cache-dir pip-audit pipdeptree filelock ruamel.yaml   # or conda install
COPY pkgremedy.py /opt/pkgremedy.py
RUN python /opt/pkgremedy.py scan --fail-on fixable            # conda env? add --ecosystem conda --env <name>
```

## CI gate
```bash
docker run --rm pkgremedy:latest scan --ecosystem conda --env appenv --fail-on fixable
```
`--fail-on {none,fixable,any}` → exit 1 fails the build.

## Producing a remediated env
`apply` mutates only that container's env; capture the fixed pins:
```bash
docker run --rm -v "$PWD/out:/out" pkgremedy:latest sh -c \
  "$(cat /opt/.pkgmgr) run -n appenv python /opt/pkgremedy/pkgremedy.py apply --ecosystem conda --env appenv --yes \
   && $(cat /opt/.pkgmgr) env export -n appenv > /out/environment.lock.yml"
```

## Air-gapped notes (Capital One-style)
- Pin `BASE_IMAGE` to a tag or `@sha256` digest.
- Point `CHANNEL` / `.condarc` and `PIP_INDEX_URL` at internal mirrors; the
  verify/apply steps need index access at run time.
- micromamba bootstrap fetches from micro.mamba.pm — if egress is blocked, use a
  base that already has conda/mamba, or vendor the micromamba binary into the base.

## Validated where possible
No Docker daemon in the build sandbox, so the image wasn't `docker build`-ed.
But each mechanism it relies on was tested live: micromamba bootstrap, env
creation from environment.yml, scanner install (incl. filelock), and the
`micromamba run -n ENV python pkgremedy.py` entrypoint flow with correct gating.
Do one local build against your real base to confirm.
