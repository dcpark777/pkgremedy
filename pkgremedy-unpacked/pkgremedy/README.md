# pkgremedy

One thin CLI that resolves known vulnerabilities in **pip** and **conda** envs,
runnable **in Docker or natively** from a single launcher. Stdlib-only, no AI.
Deterministic core: it scans, explains, proposes a minimal fix, and **dry-run
solves to prove the fix resolves** before touching anything.

## Repository layout
```
pkgremedy/
├── pkgremedy.py        # the tool (stdlib-only; scan/plan/apply/fix/envfix)
├── pkgremedy.sh        # launcher: run in docker or natively (auto)
├── pkgremedy-run.sh    # one command: build from your base + env file, run, return results
├── Dockerfile          # pkgremedy's own scanner image (NOT your production one)
├── pyproject.toml      # pip/pipx install of the native CLI
├── install.sh          # symlink the CLI + wrapper onto your PATH
├── Makefile            # make envfix / scan / native / build
├── ci/                 # GitHub Actions + Jenkins gate snippets
├── examples/
│   └── environment.yml # sample hybrid conda + pip env
├── README.md  DOCKER.md  CHANGELOG.md  LICENSE  VERSION
```
`pkgremedy.py`, `Dockerfile`, and `pkgremedy-run.sh` must stay in the same
directory (the wrapper copies its siblings into the build context).

## Install
```bash
pipx install .            # native CLI: `pkgremedy` (pulls pip-audit/pipdeptree/ruamel)
./install.sh              # or symlink: pkgremedy (CLI) + pkgremedy-run (docker one-shot)
```
For the hybrid-env Docker flow you just need the repo checkout — see the
one-command section below. CI gating snippets live in `ci/`.



## What it answers per vulnerable package
1. **Where does it come from?** reverse-dependency chain (direct vs. transitive, which top-level package pulls it in)
2. **What version is safe?** smallest bump that clears *every* CVE on that package
3. **Does the fix resolve?** real `--dry-run` solve, conflicts surfaced before apply

## One command for a hybrid env (no manual build/enter/run)
If your Dockerfile does `conda env create -f environment.yml` on a platform base
image, `pkgremedy-run.sh` does the whole loop in one shot — builds an image from
your base + file, runs pkgremedy inside it, streams the report, and writes the
patched file back to your project dir:
```bash
./pkgremedy-run.sh --base your.registry/spark-base:2026.06
# -> reads name: from environment.yml, builds (cached), runs envfix,
#    writes environment.fixed.yml next to your environment.yml
```
Pass other commands after `--` (env name is injected automatically):
```bash
./pkgremedy-run.sh --base spark-base:latest -- scan          # gate-style scan
./pkgremedy-run.sh --base spark-base:latest -- envfix --verify-build
```
Set `PKGREMEDY_BASE` to skip `--base`; `--channel` for an internal mirror;
`--no-cache` to force a fresh env; `PKGREMEDY_DRY=1` to print the docker commands.
Repeat runs are fast — Docker rebuilds the env layer only when environment.yml changes.

## Run it — one launcher, two modes
```bash
./pkgremedy.sh                       # auto: docker if available, else native
./pkgremedy.sh native -- plan --fail-on fixable
./pkgremedy.sh docker -- plan --md reports/plan.md
```
- **native** builds an isolated tools venv at `~/.cache/pkgremedy` so the scanners
  (`pip-audit`, `pipdeptree`) are **never installed into the env you're scanning**.
  If you're in an activated venv it targets that env automatically.
- **docker** builds `pkgremedy:latest` on first use and mounts the cwd for reports.

Everything after `--` is passed straight to `pkgremedy.py`.

## Or call the script directly
```bash
pip install pip-audit pipdeptree         # into a tools env, not your target
python pkgremedy.py scan                  # findings only
python pkgremedy.py plan                   # + why-chain, target, conflict check (default)
python pkgremedy.py plan --md plan.md       # ticket-ready Markdown
python pkgremedy.py apply --yes             # upgrade conflict-free fixes, then re-scan
```

### Remediate a package you name (you already know it's vulnerable)
`fix` is scanner-independent — useful when the CVE isn't in the advisory DB yet,
it's an internal finding, or you just want a specific version. It still locates
where the package comes from, dry-run verifies the change resolves, and re-scans.
```bash
python pkgremedy.py fix jinja2 --to 3.1.6              # plan: >=3.1.6
python pkgremedy.py fix jinja2 --to ==3.1.6 --apply --yes   # exact pin, applied
python pkgremedy.py fix requests                        # latest resolvable
python pkgremedy.py fix jinja2 --to 3.1.6 --ecosystem conda --env appenv --apply --yes
```
`--to` accepts a bare version (`3.1.6` → `>=3.1.6`), an operator spec (`==3.1.6`,
`<4`), or omit it for the newest the solver allows. It refuses to apply a change
that doesn't resolve cleanly.

### Remediate via your environment.yml (hybrid conda+pip envs)
For projects where the Dockerfile does `conda env create -f environment.yml` and
you only control that file (conda deps + a `pip:` section), `envfix` scans the
realized env and tells you the exact file edit per finding, in the right section.
Run it **inside the built image**. The env name is read from the file's `name:`,
so `--env` is optional.
```bash
python pkgremedy.py envfix --file environment.yml --out environment.fixed.yml
python pkgremedy.py envfix --file environment.yml --verify-build
python pkgremedy.py envfix jinja2 --to 3.1.6 --file environment.yml   # + a manual one
```
Because `conda env create -f` builds the env entirely from your file, everything
in it is, in principle, pinnable by you. Each fixable finding is classified and
routed automatically:
- **your pin (conda/pip)** — declared in your file → that line is updated.
- **add pin – not declared (conda/pip)** — a transitive (or base-provided) dep →
  an overriding pin is added to the matching section, with the parent shown
  (`via Flask`) so you can choose to bump the parent instead.
- **escalate** — no published fix, or the bump won't solve against your channels
  (e.g. a platform-pinned spark build) → listed and deliberately *not* written,
  so the patched file stays buildable.

Provenance (conda- vs pip-managed) is detected from `conda list` channels, so the
edit lands in the correct section; `ruamel.yaml` preserves comments and order.
Verification is base-aware (dry-runs the bump into the realized env, which already
contains everything the base provided). `--verify-build` also solves the patched
file from scratch — but that excludes base-image packages, so the authoritative
final check is rebuilding your image with `environment.fixed.yml`.

**Channels:** conda-forge is not assumed. Your `environment.yml` `channels:` are
used (in order) for the dry-run verify, and conda-forge is appended only as a
last-resort fallback. Add more with repeatable `--channel` (e.g. an internal
mirror). The env itself is still created from your file, so its channels always win.

**Tip:** standardize the `name:` in environment.yml to a fixed value across
projects; the tool, your CMD, and `--env` then all key off the same name.

### Scanning another environment without polluting it
```bash
# pip: point at any interpreter; uses pip-audit --path + pipdeptree --python
python pkgremedy.py plan --python /path/to/target/venv/bin/python

# conda: by env name (runs pip_audit inside that env)
python pkgremedy.py plan --ecosystem conda --env myenv
python pkgremedy.py plan --ecosystem both  --env myenv
```

## CI gating
`--fail-on {none,fixable,any}` sets the exit code (1 = fail the build):
```bash
./pkgremedy.sh native -- scan --fail-on fixable
docker run --rm pkgremedy-app:audit scan --fail-on fixable
```

## How each step is wired
| step | pip | conda |
|---|---|---|
| scan | `python -m pip_audit --format json` (`--path` for a target env) | `conda run -n ENV python -m pip_audit` |
| why-chain | `python -m pipdeptree -r -p PKG` (`--python` for a target) | `(m)conda repoquery whoneeds PKG` |
| verify | `<python> -m pip install --dry-run` | `conda install --dry-run --json` |
| apply | `<python> -m pip install --upgrade` | `conda install -n ENV` |

The same pip-audit JSON normalizes both ecosystems, so one parser serves both.
Scanners are invoked as **modules of whichever interpreter runs pkgremedy**, so
behavior is identical in Docker and native mode (no PATH assumptions).

## Status / caveats
- **pip path: tested end-to-end** both in-env and cross-env (`--python`), including
  the conflict branch, the `--fail-on` exit codes, and the launcher's native flow.
- **conda path: written, not run here** (no conda env / Docker daemon in the build
  sandbox). It mirrors the pip flow; verify the `repoquery whoneeds` and
  `conda install --dry-run --json` shapes against your conda/mamba and adjust the
  two small parsers if output differs.
- **Native conda binaries** (openssl, zlib, …) aren't Python packages, so pip-audit
  won't see them. Supplement with `grype <env-prefix> -o json`.
- **Transitive fixes**: it pins the child to the safe version *and* names the parent,
  so you can choose to bump the parent instead — it never silently rewrites the graph.
- See `DOCKER.md` for image patterns, CI gating, and air-gapped notes.
