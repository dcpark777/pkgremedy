#!/usr/bin/env python3
"""
pkgremedy - resolve known vulnerabilities in pip and conda environments.

For every vulnerable package it answers the three questions that actually
matter when remediating:

  1. WHERE does it come from?  -> reverse-dependency chain (who requires it)
  2. WHAT version is safe?     -> minimum bump that clears every CVE on it
  3. DOES the fix resolve?     -> dry-run solve to confirm no new conflicts

Deterministic core, no network writes, no AI. It proposes a plan and only
mutates an environment when you explicitly run `apply`.

Scanners used (all emit the same normalized JSON, so one parser serves both):
  pip   :  pip-audit --format json   (current interpreter)
  conda :  conda run -n <env> python -m pip_audit --format json
           (covers the Python packages in the env; for native binaries such
            as openssl/zlib supplement with `grype <prefix>` -- see --help)

Why-chain + conflict check per ecosystem:
  pip   :  pipdeptree -r -p <pkg> --json-tree   /   pip install --dry-run
  conda :  (m)conda repoquery whoneeds <pkg>    /   conda install --dry-run --json
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

__version__ = "0.1.0"

# ----------------------------------------------------------------------------
# version comparison (prefer packaging; fall back to a tolerant local parser)
# ----------------------------------------------------------------------------
try:
    from packaging.version import Version as _V  # type: ignore

    def vkey(s: str):
        try:
            return _V(s)
        except Exception:
            return _V("0")
except Exception:  # packaging not importable in this interpreter
    import re

    def vkey(s: str):
        parts = re.findall(r"\d+", s or "")
        return tuple(int(p) for p in parts[:4]) or (0,)


def vgt(a: str, b: str) -> bool:
    return vkey(a) > vkey(b)


# ----------------------------------------------------------------------------
# normalized model
# ----------------------------------------------------------------------------
@dataclass
class Finding:
    ecosystem: str            # "pip" | "conda"
    package: str
    installed: str
    vuln_ids: list[str] = field(default_factory=list)
    # per-vuln minimal fix version (None == no known fix)
    per_vuln_fix: list[Optional[str]] = field(default_factory=list)
    requirers: list[str] = field(default_factory=list)   # immediate parents
    top_level: list[str] = field(default_factory=list)   # roots that pull it in
    target: Optional[str] = None       # version we propose upgrading to
    resolves: Optional[bool] = None    # dry-run result
    resolve_note: str = ""
    spec: Optional[str] = None         # manual override, e.g. "jinja2==3.1.6"

    @property
    def is_transitive(self) -> bool:
        return bool(self.requirers)

    @property
    def has_fix(self) -> bool:
        return self.target is not None


def spec_for(f: Finding) -> str:
    """Install spec used for verify/apply: a manual override, else >= target."""
    return f.spec if f.spec else f"{f.package}>={f.target}"


def installed_version_pip(pkg: str, python: Optional[str]) -> Optional[str]:
    pybin = python or sys.executable
    cp = run([pybin, "-m", "pip", "show", pkg])
    for ln in cp.stdout.splitlines():
        if ln.lower().startswith("version:"):
            return ln.split(":", 1)[1].strip()
    return None


def installed_version_conda(pkg: str, env: str) -> Optional[str]:
    runner = conda_runner()
    if not runner:
        return None
    # works for python packages whether conda- or pip-installed in the env
    cp = run([runner, "run", "-n", env, "python", "-m", "pip", "show", pkg])
    for ln in cp.stdout.splitlines():
        if ln.lower().startswith("version:"):
            return ln.split(":", 1)[1].strip()
    # fall back to conda metadata (native / non-python packages)
    cp = run([runner, "list", "-n", env, "--json"])
    try:
        for p in json.loads(cp.stdout or "[]"):
            if p.get("name", "").lower() == pkg.lower():
                return p.get("version")
    except json.JSONDecodeError:
        pass
    return None


def build_spec(pkg: str, to: Optional[str]) -> str:
    """Turn a package + desired version into an install spec.
    --to may be a bare version (3.1.6 -> >=3.1.6), an operator spec (==3.1.6,
    >=3.1.6, <4), or omitted (-> latest resolvable)."""
    if not to:
        return pkg  # newest version the solver allows
    ops = ("==", ">=", "<=", "~=", "!=", ">", "<")
    return f"{pkg}{to}" if to.startswith(ops) else f"{pkg}>={to}"


# ----------------------------------------------------------------------------
# small subprocess helper
# ----------------------------------------------------------------------------
def run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout
    )


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def module_present(name: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(name) is not None


def conda_runner() -> Optional[str]:
    """First available env manager: mamba, micromamba, or conda."""
    for r in ("mamba", "micromamba", "conda"):
        if have(r):
            return r
    return None


def channel_flags(channels: Optional[list]) -> list:
    """Build `-c` flags from the given channels, with conda-forge appended last
    as a fallback (your channels keep priority)."""
    chans = [c for c in (channels or []) if isinstance(c, str) and c.strip()]
    if "conda-forge" not in chans:
        chans = chans + ["conda-forge"]
    flags: list = []
    for c in chans:
        flags += ["-c", c]
    return flags


# ----------------------------------------------------------------------------
# scanning  (pip-audit JSON is the shared format for both ecosystems)
# ----------------------------------------------------------------------------
def _parse_pip_audit(raw: str, ecosystem: str) -> list[Finding]:
    data = json.loads(raw)
    findings: list[Finding] = []
    for dep in data.get("dependencies", []):
        vulns = dep.get("vulns", [])
        if not vulns:
            continue
        ids, fixes = [], []
        for v in vulns:
            # prefer a CVE alias for readability, else the native id
            cve = next((a for a in v.get("aliases", []) if a.startswith("CVE")), None)
            ids.append(cve or v.get("id", "?"))
            fv = v.get("fix_versions") or []
            # minimal fixed version for this single vuln
            fixes.append(min(fv, key=vkey) if fv else None)
        findings.append(
            Finding(
                ecosystem=ecosystem,
                package=dep["name"].lower(),
                installed=dep.get("version", "?"),
                vuln_ids=ids,
                per_vuln_fix=fixes,
            )
        )
    return findings


def _site_packages(python: str) -> Optional[str]:
    cp = run([python, "-c", "import site;print(site.getsitepackages()[0])"])
    return cp.stdout.strip() or None


def scan_pip(python: Optional[str] = None) -> list[Finding]:
    if not module_present("pip_audit"):
        sys.exit("pip-audit not importable by this interpreter. Install it: "
                 f"{sys.executable} -m pip install pip-audit")
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json"]
    if python:  # audit another env's site-packages without installing into it
        sp = _site_packages(python)
        if sp:
            cmd += ["--path", sp]
    cp = run(cmd)
    if not cp.stdout.strip():
        sys.exit(f"pip-audit produced no output:\n{cp.stderr}")
    return _parse_pip_audit(cp.stdout, "pip")


def scan_conda(env: str) -> list[Finding]:
    runner = conda_runner()
    if not runner:
        sys.exit("No conda env manager (mamba/micromamba/conda) found on PATH.")
    cp = run([runner, "run", "-n", env, "python", "-m", "pip_audit", "--format", "json"])
    if not cp.stdout.strip():
        sys.exit(
            "No scanner output from the conda env. Ensure pip-audit is available "
            f"inside it (e.g. `{runner} install -n {env} -c conda-forge pip-audit filelock`).\n"
            f"stderr:\n{cp.stderr}"
        )
    return _parse_pip_audit(cp.stdout, "conda")


# ----------------------------------------------------------------------------
# target version: smallest bump that clears EVERY vuln on the package
# ----------------------------------------------------------------------------
def choose_target(f: Finding) -> None:
    known = [v for v in f.per_vuln_fix if v]
    if not known:
        f.target = None  # no fix published for at least one tracked CVE
        return
    # to clear all vulns we need >= the highest of the per-vuln minimum fixes
    candidate = max(known, key=vkey)
    f.target = candidate if vgt(candidate, f.installed) else f.installed


# ----------------------------------------------------------------------------
# why-chain (reverse dependencies)
# ----------------------------------------------------------------------------
def _collect_leaves(node: dict, acc: list[str]) -> None:
    deps = node.get("dependencies", [])
    if not deps:
        return
    for d in deps:
        if not d.get("dependencies"):
            acc.append(d.get("package_name") or d.get("key", "?"))
        _collect_leaves(d, acc)


def why_pip(f: Finding, python: Optional[str] = None) -> None:
    if not module_present("pipdeptree"):
        f.requirers = []
        return
    cmd = [sys.executable, "-m", "pipdeptree", "-r", "-p", f.package, "--json-tree"]
    if python:
        cmd += ["--python", python]
    cp = run(cmd)
    try:
        trees = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return
    immediate, roots = [], []
    for root in trees:
        for d in root.get("dependencies", []):
            immediate.append(d.get("package_name") or d.get("key"))
        _collect_leaves(root, roots)
    f.requirers = sorted({r for r in immediate if r})
    f.top_level = sorted({r for r in roots if r}) or f.requirers


def why_conda(f: Finding, env: str) -> None:
    runner = conda_runner()
    if not runner:
        return
    cp = run([runner, "repoquery", "whoneeds", f.package, "-n", env, "--json"])
    try:
        data = json.loads(cp.stdout or "{}")
    except json.JSONDecodeError:
        return
    # repoquery whoneeds returns {"result":{"pkgs":[{"name":...},...]}}
    pkgs = (data.get("result") or {}).get("pkgs", []) if isinstance(data, dict) else []
    f.requirers = sorted({p.get("name") for p in pkgs if p.get("name")})
    f.top_level = f.requirers


# ----------------------------------------------------------------------------
# conflict check (dry-run solve with the proposed versions)
# ----------------------------------------------------------------------------
def verify_pip(findings: list[Finding], python: Optional[str] = None) -> None:
    specs = [spec_for(f) for f in findings if f.has_fix]
    if not specs:
        return
    pybin = python or sys.executable
    cp = run([pybin, "-m", "pip", "install", "--dry-run", "--quiet", *specs])
    ok = cp.returncode == 0
    note = "" if ok else (cp.stderr.strip().splitlines() or ["resolution failed"])[-1]
    for f in findings:
        if f.has_fix:
            f.resolves, f.resolve_note = ok, note


def verify_conda(findings: list[Finding], env: str, channels: Optional[list] = None) -> None:
    specs = [spec_for(f) for f in findings if f.has_fix]
    if not specs:
        return
    runner = conda_runner()
    if not runner:
        return
    cp = run([runner, "install", "-n", env, "--dry-run", "--json",
              *channel_flags(channels), *specs])
    ok = cp.returncode == 0
    note = ""
    if not ok:
        try:
            note = json.loads(cp.stdout).get("message", "")[:200]
        except Exception:
            note = (cp.stderr.strip().splitlines() or ["solve failed"])[-1]
    for f in findings:
        if f.has_fix:
            f.resolves, f.resolve_note = ok, note


# ----------------------------------------------------------------------------
# apply
# ----------------------------------------------------------------------------
def apply_pip(findings: list[Finding], python: Optional[str] = None) -> int:
    specs = [spec_for(f) for f in findings if f.has_fix and f.resolves]
    if not specs:
        print("Nothing safely applicable.")
        return 0
    pybin = python or sys.executable
    print("Running:", pybin, "-m pip install --upgrade " + " ".join(specs))
    return run([pybin, "-m", "pip", "install", "--upgrade", *specs], timeout=1800).returncode


def apply_conda(findings: list[Finding], env: str, channels: Optional[list] = None) -> int:
    specs = [spec_for(f) for f in findings if f.has_fix and f.resolves]
    if not specs:
        print("Nothing safely applicable.")
        return 0
    runner = conda_runner()
    if not runner:
        return 1
    print("Running:", f"{runner} install -n {env} -y " + " ".join(specs))
    return run([runner, "install", "-n", env, "-y", *channel_flags(channels), *specs],
               timeout=1800).returncode


# ----------------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------------
def origin(f: Finding) -> str:
    if not f.is_transitive:
        return "direct dependency"
    roots = ", ".join(f.top_level[:3]) + ("…" if len(f.top_level) > 3 else "")
    return f"transitive via {roots}"


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("No known vulnerabilities found.")
        return
    rows = []
    for f in sorted(findings, key=lambda x: (not x.has_fix, x.package)):
        if not f.has_fix:
            target, ok = "(no fix published)", "—"
        else:
            target = f.target if vgt(f.target, f.installed) else "already safe?"
            ok = {True: "yes", False: "CONFLICT", None: "?"}[f.resolves]
        rows.append((f"[{f.ecosystem}]", f.package, f.installed, "→", target,
                     str(len(f.vuln_ids)), ok, origin(f)))

    head = ("eco", "package", "installed", "", "target", "CVEs", "resolves", "origin")
    widths = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    line = lambda r: "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r))
    print(line(head))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(line(r))
    print()
    for f in findings:
        print(f"[{f.ecosystem}] {f.package} {f.installed}: {', '.join(f.vuln_ids)}")
        print(f"        origin : {origin(f)}")
        if f.is_transitive and f.has_fix:
            print(f"        action : pin {f.package}>={f.target}, or bump the parent "
                  f"({', '.join(f.top_level[:3])}) to a release that requires it")
        if f.resolves is False:
            print(f"        WARNING: proposed fix does not resolve cleanly -> {f.resolve_note}")


def write_markdown(findings: list[Finding], path: str) -> None:
    lines = ["# Vulnerability remediation plan", ""]
    lines.append("| eco | package | installed | target | CVEs | resolves | origin |")
    lines.append("|---|---|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: (not x.has_fix, x.package)):
        target = f.target or "(no fix)"
        ok = {True: "yes", False: "CONFLICT", None: "?"}.get(f.resolves, "—")
        lines.append(f"| {f.ecosystem} | {f.package} | {f.installed} | {target} | "
                     f"{len(f.vuln_ids)} | {ok} | {origin(f)} |")
    lines += ["", "## Details", ""]
    for f in findings:
        lines.append(f"### {f.package} ({f.ecosystem}) {f.installed}")
        lines.append(f"- CVEs: {', '.join(f.vuln_ids)}")
        lines.append(f"- Origin: {origin(f)}")
        if f.has_fix:
            lines.append(f"- Proposed: `{f.package}>={f.target}`")
        else:
            lines.append("- No fixed version published for at least one CVE — manual review.")
        if f.resolves is False:
            lines.append(f"- ⚠️ Does not resolve cleanly: {f.resolve_note}")
        lines.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


# ----------------------------------------------------------------------------
# pipeline
# ----------------------------------------------------------------------------
def gather(ecosystem: str, env: str, python: Optional[str] = None) -> list[Finding]:
    findings: list[Finding] = []
    if ecosystem in ("pip", "both"):
        findings += scan_pip(python)
    if ecosystem in ("conda", "both"):
        findings += scan_conda(env)
    return findings


def enrich(findings: list[Finding], env: str, do_verify: bool,
           python: Optional[str] = None, channels: Optional[list] = None) -> None:
    for f in findings:
        choose_target(f)
        if f.ecosystem == "pip":
            why_pip(f, python)
        else:
            why_conda(f, env)
    if do_verify:
        verify_pip([f for f in findings if f.ecosystem == "pip"], python)
        verify_conda([f for f in findings if f.ecosystem == "conda"], env, channels)


def gate(findings: list[Finding], fail_on: str) -> int:
    """CI exit code: 1 if findings trip the chosen threshold, else 0."""
    if fail_on == "any" and findings:
        return 1
    if fail_on == "fixable" and any(f.has_fix for f in findings):
        return 1
    return 0


import re as _re


def spec_name(s: str) -> str:
    """Parse a package name out of a conda/pip spec line."""
    s = s.strip()
    if "::" in s:               # strip channel prefix, e.g. conda-forge::numpy
        s = s.split("::", 1)[1]
    m = _re.match(r"^([A-Za-z0-9_.\-]+)", s)
    return m.group(1).lower() if m else s.lower()


def conda_manager_map(env: str) -> dict:
    """name(lower) -> {'version','channel','manager'} for the realized env.
    manager is 'pip' when the channel is pypi, else 'conda'."""
    runner = conda_runner()
    out: dict = {}
    if not runner:
        return out
    cp = run([runner, "list", "-n", env, "--json"])
    try:
        for p in json.loads(cp.stdout or "[]"):
            ch = (p.get("channel") or "").lower()
            out[p.get("name", "").lower()] = {
                "version": p.get("version"),
                "channel": p.get("channel"),
                "manager": "pip" if ch == "pypi" else "conda",
            }
    except json.JSONDecodeError:
        pass
    return out


def file_pin(f: Finding) -> str:
    """The pin string to write into environment.yml."""
    return f.spec if f.spec else f"{f.package}>={f.target}"


def _load_yaml(path: str):
    """Return (lib, doc) where lib in {'ruamel','pyyaml'} or (None, None)."""
    try:
        from ruamel.yaml import YAML
        y = YAML()
        y.preserve_quotes = True
        y.indent(mapping=2, sequence=4, offset=2)
        with open(path) as fh:
            return ("ruamel", y, y.load(fh))
    except ImportError:
        pass
    try:
        import yaml
        with open(path) as fh:
            return ("pyyaml", yaml, yaml.safe_load(fh))
    except ImportError:
        return (None, None, None)


def _pip_list(deps):
    """Return the list under the `pip:` mapping in a dependencies list, or None."""
    for item in deps:
        if isinstance(item, dict) and "pip" in item:
            return item["pip"]
    return None


def _set_or_add(seq, name: str, pin: str) -> str:
    """Update an existing entry for `name` in seq, else append `pin`.
    Returns 'updated' or 'added'."""
    for i, item in enumerate(seq):
        if isinstance(item, str) and spec_name(item) == name:
            seq[i] = pin
            return "updated"
    seq.append(pin)
    return "added"


def env_parents(name: str, env: str, manager: str) -> list[str]:
    """Top-level packages in the env that pull in `name` (for undeclared deps)."""
    runner = conda_runner()
    if not runner:
        return []
    if manager == "conda":
        cp = run([runner, "repoquery", "whoneeds", name, "-n", env, "--json"])
        try:
            pkgs = (json.loads(cp.stdout or "{}").get("result") or {}).get("pkgs", [])
            return sorted({p.get("name") for p in pkgs if p.get("name")})
        except json.JSONDecodeError:
            return []
    # pip-managed: pipdeptree inside the env
    cp = run([runner, "run", "-n", env, "python", "-m", "pipdeptree",
              "-r", "-p", name, "--json-tree"])
    try:
        trees = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return []
    roots: list[str] = []
    for root in trees:
        _collect_leaves(root, roots)
    return sorted({r for r in roots if r})


def cmd_envfix(args) -> int:
    path = args.file
    lib, yamlmod, doc = _load_yaml(path)
    if doc is None:
        sys.exit("Could not read environment.yml (need ruamel.yaml or PyYAML "
                 "in this interpreter). Install: pip install ruamel.yaml")
    deps = doc.get("dependencies") or []
    conda_names = {spec_name(x) for x in deps if isinstance(x, str)}
    pip_seq = _pip_list(deps)
    pip_names = {spec_name(x) for x in (pip_seq or []) if isinstance(x, str)}
    env = args.env or doc.get("name") or "base"
    channels = list(doc.get("channels") or []) + list(args.channel or [])

    # 1) scan the realized env + optional manual injection
    findings = scan_conda(env)
    for f in findings:
        choose_target(f)
    if args.package:
        pkg = args.package.lower()
        manual = Finding(ecosystem="conda", package=pkg,
                         installed="(manual)", target=(args.to or "latest"),
                         spec=build_spec(pkg, args.to))
        findings = [f for f in findings if f.package != pkg] + [manual]

    mgr = conda_manager_map(env)
    runner = conda_runner()

    applied, escalate = [], []
    for f in sorted(findings, key=lambda x: x.package):
        name = f.package
        if not f.has_fix:
            f.resolve_note = "no fixed version published"
            escalate.append(("no-fix", f, None, None))
            continue
        manager = mgr.get(name, {}).get("manager", "conda")
        # decide section + provenance bucket
        if name in pip_names:
            section, bucket = "pip", "your pin (pip)"
        elif name in conda_names:
            section, bucket = "conda", "your pin (conda)"
        else:
            # not in your file: with `conda env create -f`, this is a transitive
            # dep of something you declared. Pinning it in the matching section
            # overrides the resolution.
            section = manager
            f.top_level = env_parents(name, env, manager)
            via = f" via {', '.join(f.top_level[:3])}" if f.top_level else ""
            bucket = f"add pin – not declared{via} ({manager})"
        # fast, base-aware verify: dry-run the bump into the realized env
        if manager == "pip":
            cp = run([runner, "run", "-n", env, "python", "-m", "pip",
                      "install", "--dry-run", "--quiet", file_pin(f)])
            f.resolves = cp.returncode == 0
            f.resolve_note = "" if f.resolves else (cp.stderr.strip().splitlines() or ["conflict"])[-1]
        else:
            cp = run([runner, "install", "-n", env, "--dry-run", "--json",
                      *channel_flags(channels), file_pin(f)])
            f.resolves = cp.returncode == 0
            if not f.resolves:
                try:
                    f.resolve_note = json.loads(cp.stdout).get("message", "")[:160]
                except Exception:
                    f.resolve_note = (cp.stderr.strip().splitlines() or ["solve failed"])[-1]
        if f.resolves:
            applied.append((bucket, f, section))
        else:
            escalate.append(("conflict", f, section, bucket))

    # 2) write patched file with the clean edits
    out = args.out or "environment.fixed.yml"
    wrote = False
    if applied and lib:
        for bucket, f, section in applied:
            pin = file_pin(f)
            if section == "pip":
                if pip_seq is None:
                    newpip = {"pip": [pin]}
                    deps.append(newpip)
                    pip_seq = newpip["pip"]
                else:
                    _set_or_add(pip_seq, f.package, pin)
            else:
                # update in place if present, else insert before the pip: mapping
                updated = False
                for i, item in enumerate(deps):
                    if isinstance(item, str) and spec_name(item) == f.package:
                        deps[i] = pin
                        updated = True
                        break
                if not updated:
                    pip_idx = next((i for i, it in enumerate(deps)
                                    if isinstance(it, dict) and "pip" in it), len(deps))
                    deps.insert(pip_idx, pin)
        with open(out, "w") as fh:
            if lib == "ruamel":
                yamlmod.dump(doc, fh)
            else:
                yamlmod.safe_dump(doc, fh, default_flow_style=False, sort_keys=False)
        wrote = True

    # 3) report
    print(f"environment.yml: {path}   realized env: {env}\n")
    if applied:
        print("WILL FIX (written to patched file):")
        for bucket, f, section in applied:
            print(f"  [{section:5}] {f.package} {f.installed} -> {file_pin(f)}   ({bucket})")
        print()
    if escalate:
        print("CANNOT FIX FROM environment.yml (escalate to platform / wait for base refresh):")
        for kind, f, section, bucket in escalate:
            why = "no published fix" if kind == "no-fix" else f"upgrade conflicts: {f.resolve_note}"
            print(f"  {f.package} {f.installed}: {why}")
        print()
    if wrote:
        print(f"Wrote patched file -> {out}")
        print("Pins added for not-declared packages constrain transitive/base-provided "
              "deps; revisit them when your direct deps or the base image move.")
    elif applied and not lib:
        print("(No YAML library available, so the file wasn't rewritten — apply the "
              "edits above manually, or install ruamel.yaml.)")

    if args.verify_build and wrote:
        print("\n--verify-build: solving the patched file from scratch…")
        rc = run([runner, "create", "-n", "_pkgremedy_verify", "-f", out, "--dry-run"]).returncode
        run([runner, "env", "remove", "-n", "_pkgremedy_verify", "-y"])
        print("  file solves cleanly." if rc == 0 else "  WARNING: patched file does NOT "
              "solve from scratch (note: this check excludes base-image packages).")

    return gate(findings, args.fail_on)


def cmd_fix(args) -> int:
    """Targeted remediation: you name the package (and optionally the version),
    pkgremedy locates where it comes from, dry-run verifies the change resolves,
    and (with apply) bumps it and re-scans."""
    pkg = args.package.lower()
    eco = args.ecosystem if args.ecosystem in ("pip", "conda") else "pip"
    inst = (installed_version_pip(pkg, args.python) if eco == "pip"
            else installed_version_conda(pkg, args.env))
    if inst is None:
        print(f"'{pkg}' is not installed in the target {eco} environment — nothing to change.")
        return 0

    spec = build_spec(pkg, args.to)
    f = Finding(ecosystem=eco, package=pkg, installed=inst,
                target=(args.to or "latest"), spec=spec)
    # where does it come from?
    if eco == "pip":
        why_pip(f, args.python)
        verify_pip([f], args.python)
    else:
        why_conda(f, args.env)
        verify_conda([f], args.env, args.channel)

    print(f"[{eco}] {pkg}: installed {inst}  ->  change to `{spec}`")
    print(f"        origin : {origin(f)}")
    if f.is_transitive:
        print(f"        note   : transitive — pinning {pkg} adds a constraint; "
              f"or bump the parent ({', '.join(f.top_level[:3])}) instead")
    resolved = {True: "yes", False: "NO", None: "?"}[f.resolves]
    print(f"        resolves cleanly: {resolved}")
    if f.resolves is False:
        print(f"        conflict: {f.resolve_note}")

    if not args.apply:
        print("\n(plan only — re-run with --apply to make the change)")
        return gate([f], args.fail_on)
    if not f.resolves:
        print("\nNot applying: the requested change does not resolve cleanly.")
        return 1
    if not args.yes:
        if input(f"\nApply `{spec}`? [y/N] ").strip().lower() != "y":
            print("Aborted.")
            return 0
    rc = (apply_pip([f], args.python) if eco == "pip"
          else apply_conda([f], args.env, args.channel))
    print("\nRe-scanning to confirm…")
    post = gather(eco, args.env, args.python)
    for g in post:
        choose_target(g)
    still = [g for g in post if g.package == pkg]
    new_inst = (installed_version_pip(pkg, args.python) if eco == "pip"
                else installed_version_conda(pkg, args.env))
    print(f"{pkg} is now {new_inst}; "
          + ("still flagged by the scanner." if still else "no longer flagged by the scanner."))
    return rc


def main() -> int:
    p = argparse.ArgumentParser(
        prog="pkgremedy",
        description="Resolve known vulnerabilities in pip and conda environments.",
        epilog="Native (non-Python) conda packages: supplement with `grype <env-prefix> -o json`.",
    )
    p.add_argument("command", choices=["scan", "plan", "apply", "fix", "envfix"], nargs="?",
                   default="plan",
                   help="scan | plan (default) | apply | fix PACKAGE | "
                        "envfix: emit environment.yml edits for a conda env")
    p.add_argument("package", nargs="?", help="for `fix`/`envfix`: a package to remediate")
    p.add_argument("--file", metavar="PATH", default="environment.yml",
                   help="for `envfix`: path to your environment.yml")
    p.add_argument("--out", metavar="PATH",
                   help="for `envfix`: patched file to write (default environment.fixed.yml)")
    p.add_argument("--verify-build", action="store_true",
                   help="for `envfix`: also solve the patched file from scratch")
    p.add_argument("--to", metavar="VERSION",
                   help="for `fix`: target version. bare (3.1.6 => >=3.1.6), operator "
                        "(==3.1.6, <4, >=3.1.6), or omit for latest resolvable")
    p.add_argument("--apply", action="store_true", help="for `fix`: make the change (else plan only)")
    p.add_argument("--version", action="version", version=f"pkgremedy {__version__}")
    p.add_argument("--ecosystem", choices=["pip", "conda", "both"], default="pip")
    p.add_argument("--env", default=None,
                   help="conda env name. For envfix, defaults to the `name:` in "
                        "environment.yml; otherwise defaults to base.")
    p.add_argument("--python", metavar="PATH",
                   help="target interpreter to scan (pip): audits that env without "
                        "installing into it. Default: the interpreter running pkgremedy.")
    p.add_argument("--channel", action="append", metavar="CH",
                   help="extra conda channel(s) for verify/apply (repeatable). For "
                        "envfix, your environment.yml channels are used automatically. "
                        "conda-forge is always appended as a fallback.")
    p.add_argument("--json", metavar="PATH", help="write findings as JSON")
    p.add_argument("--md", metavar="PATH", help="write a Markdown plan (good for tickets)")
    p.add_argument("--yes", action="store_true", help="apply without the confirmation prompt")
    p.add_argument("--fail-on", choices=["none", "fixable", "any"], default="none",
                   help="exit non-zero for CI gating: any vuln, only fixable ones, or never (default)")
    args = p.parse_args()

    if args.command == "envfix":
        return cmd_envfix(args)

    args.env = args.env or "base"   # default for all other conda commands

    if args.command == "fix":
        if not args.package:
            p.error("`fix` needs a package name, e.g. `pkgremedy fix jinja2 --to 3.1.6`")
        return cmd_fix(args)

    findings = gather(args.ecosystem, args.env, args.python)

    if args.command == "scan":
        for f in findings:
            choose_target(f)
        print_report(findings)
    else:
        enrich(findings, args.env, do_verify=True, python=args.python, channels=args.channel)
        print_report(findings)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([f.__dict__ for f in findings], fh, indent=2, default=lambda o: o.__dict__)
        print(f"\nWrote JSON -> {args.json}")
    if args.md:
        write_markdown(findings, args.md)
        print(f"Wrote Markdown plan -> {args.md}")

    if args.command == "apply":
        actionable = [f for f in findings if f.has_fix and f.resolves]
        if not actionable:
            print("\nNothing both fixable and conflict-free to apply.")
            return gate(findings, args.fail_on)
        if not args.yes:
            ans = input(f"\nApply {len(actionable)} upgrade(s)? [y/N] ").strip().lower()
            if ans != "y":
                print("Aborted.")
                return 0
        rc = 0
        rc |= apply_pip([f for f in actionable if f.ecosystem == "pip"], args.python)
        if args.ecosystem in ("conda", "both"):
            rc |= apply_conda([f for f in actionable if f.ecosystem == "conda"], args.env, args.channel)
        print("\nRe-scanning to confirm…")
        post = gather(args.ecosystem, args.env, args.python)
        for f in post:
            choose_target(f)
        print_report(post)
        return rc or gate(post, args.fail_on)
    return gate(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
