# Changelog

All notable changes to pkgremedy are documented here.
Format follows Keep a Changelog; versioning is semantic.

## [0.1.0] - 2026-06
First release.

### Added
- **Scanning** of pip and conda environments via `pip-audit` (one normalized
  model for both ecosystems).
- **Commands**: `scan`, `plan` (default), `apply`, `fix`, `envfix`.
  - `plan` adds the reverse-dependency "why-chain", the minimal safe target
    version (smallest bump clearing every CVE), and a dry-run conflict check.
  - `apply` upgrades conflict-free fixes, then re-scans to confirm.
  - `fix PACKAGE [--to VERSION]` — targeted remediation for a package you name
    (scanner-independent), with the same verify-before-apply machinery.
  - `envfix` — for hybrid conda+pip projects built with `conda env create -f`:
    maps each finding to the exact `environment.yml` edit, routed to the correct
    section by realized provenance (conda- vs pip-managed), preserving comments
    via ruamel.yaml; writes `environment.fixed.yml`.
- **Cross-environment scanning** without pollution: `--python` (pip, uses
  `pip-audit --path` + `pipdeptree --python`) and `--env` (conda).
- **Channels**: your `environment.yml` channels are honored (in order) for
  verify/apply/scanner-install, with conda-forge appended only as a fallback;
  add more with repeatable `--channel`.
- **CI gating** via `--fail-on {none,fixable,any}`.
- **Docker**: a bring-your-own-base `Dockerfile` (auto-detects/bootstraps
  conda/mamba/micromamba; installs scanners incl. `filelock`).
- **One-command wrapper** `pkgremedy-run.sh`: builds from your base + env file,
  runs pkgremedy inside, streams the report, writes results back to your repo.
- **Launcher** `pkgremedy.sh`: run in docker or natively (native bootstraps an
  isolated tools venv so the scanned env is never polluted).
- Packaging: `pyproject.toml`, `install.sh`, `Makefile`, example env, CI snippets.

### Known limitations
- conda repoquery only sees conda-managed packages; transitive parents of
  pip-section packages are resolved via `pipdeptree` inside the env instead.
- Native (non-Python) conda binaries aren't seen by pip-audit; supplement with
  `grype <env-prefix>`.
- Docker images require a glibc base with a shell (not Alpine/scratch/distroless).
- `envfix` reproduces `base + conda env create -f`; if your production image does
  more to the env, scan the built image directly.
