"""Open-source scanners, used when the run's ``scan_engine`` is ``scanner``.

SAST: Semgrep CE   -> SARIF -> sarif adapter
SCA:  OSV-Scanner  -> JSON  -> osv adapter (resolves transitive Maven/Gradle deps too)

The workflow installs both at pinned versions (OSV-Scanner checksum-verified) and
exports FIXPOINT_SEMGREP_BIN / FIXPOINT_OSV_SCANNER_BIN. This module only runs them
on the pinned checkout and normalises their output into the common finding format,
so triage, plan, fix, verify and publish work exactly as for AI-discovered findings.
Scanners read the target code; they never execute it, and they get no secrets.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from fixpoint import adapters, log
from fixpoint.config import Policy
from fixpoint.model import Finding, fingerprint, merge_findings, normalise_path, write_json
from fixpoint.scan import ScanResult

LOG = log.get(__name__)

PLACEHOLDER_SNIPPETS = {"", "requires login"}


class ScannerError(RuntimeError):
    pass


def binary(name: str) -> str | None:
    """Path of an installed scanner: FIXPOINT_<NAME>_BIN, else PATH."""
    env = {"semgrep": "FIXPOINT_SEMGREP_BIN", "osv-scanner": "FIXPOINT_OSV_SCANNER_BIN"}[name]
    path = os.environ.get(env) or shutil.which(name)
    return path if path and Path(path).exists() else None


def _env() -> dict[str, str]:
    """Scanners get no secrets: only what they need to run and reach their rule/advisory sources."""
    keep = ("PATH", "LANG", "LC_ALL", "TMPDIR", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["HOME"] = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR") or "/tmp"  # noqa: S108
    env["SEMGREP_SEND_METRICS"] = "off"
    return env


def _cfg(policy: Policy, name: str) -> dict[str, Any]:
    return (policy.raw.get("scanners") or {}).get(name) or {}


def _relativise(path: str, repo_dir: Path) -> str:
    p = normalise_path(path)
    root = str(repo_dir.resolve()).replace("\\", "/").rstrip("/") + "/"
    if p.startswith(root):
        return p[len(root):]
    if p.startswith("/") and os.path.isabs(p):
        try:
            return Path(p).resolve().relative_to(repo_dir.resolve()).as_posix()
        except ValueError:
            return p
    return p


# -- Semgrep (SAST) ---------------------------------------------------------------


def run_semgrep(repo_dir: Path, out: Path, policy: Policy) -> dict[str, Any]:
    exe = binary("semgrep")
    if not exe:
        raise ScannerError("semgrep is not installed (the workflow installs it when scan_engine=scanner)")
    cfg = _cfg(policy, "semgrep")
    argv = [exe, "scan", "--sarif", "--output", str(out.resolve()), "--metrics=off", "--disable-version-check",
            "--quiet", "--timeout", str(int(cfg.get("per_rule_timeout", 30)))]
    for c in cfg.get("configs") or ["p/default"]:
        argv += ["--config", str(c)]
    for e in cfg.get("exclude") or []:
        argv += ["--exclude", str(e)]
    argv.append(".")
    out.parent.mkdir(parents=True, exist_ok=True)
    LOG.info("semgrep: configs=%s", cfg.get("configs") or ["p/default"])
    try:
        r = subprocess.run(argv, cwd=repo_dir, env=_env(), capture_output=True, text=True,
                           timeout=int(cfg.get("timeout_seconds", 1800)), check=False)
    except subprocess.TimeoutExpired as e:
        raise ScannerError("semgrep timed out") from e
    # 0 = ran (findings or not); 1 = findings with --error; anything else is a failure
    if r.returncode not in (0, 1) or not out.is_file():
        raise ScannerError(f"semgrep exit {r.returncode}: {log.redact(r.stderr.strip())[-800:]}")
    return json.loads(out.read_text(encoding="utf-8"))


def sast_findings(doc: dict[str, Any], repo_dir: Path, sha: str) -> list[Finding]:
    """SARIF -> findings, anchored at the pinned commit. Semgrep CE may withhold the snippet
    ("requires login"), so the snippet is read from the scanned file itself."""
    findings = []
    for f in adapters.parse(doc, "sarif", "sast"):
        f.source = "scanner:semgrep"
        f.location.file = _relativise(f.location.file, repo_dir)
        f.properties["report_revision"] = sha  # scanned this exact commit
        if f.location.snippet.strip().lower() in PLACEHOLDER_SNIPPETS:
            f.location.snippet = ""
            p = repo_dir / f.location.file
            if p.is_file() and not p.is_symlink() and f.location.start_line >= 1:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                end = min(max(f.location.end_line, f.location.start_line), len(lines))
                f.location.snippet = "\n".join(lines[f.location.start_line - 1 : end])
        f.id = fingerprint(f)  # same id as any other source reporting the same code
        findings.append(f)
    return merge_findings(findings)


# -- OSV-Scanner (SCA) -------------------------------------------------------------


def _osv_once(argv: list[str], repo_dir: Path, timeout: int) -> tuple[dict[str, Any], str]:
    try:
        r = subprocess.run(argv, cwd=repo_dir, env=_env(), capture_output=True, text=True, timeout=timeout,
                           check=False)
    except subprocess.TimeoutExpired as e:
        raise ScannerError("osv-scanner timed out") from e
    # 0 = no vulns, 1 = vulns found, 128 = no package sources found (nothing to scan)
    if r.returncode == 128 and "no package sources" in (r.stderr + r.stdout).lower():
        return {"results": []}, r.stderr
    if r.returncode not in (0, 1):
        raise ScannerError(f"osv-scanner exit {r.returncode}: {log.redact(r.stderr.strip())[-800:]}")
    try:
        return json.loads(r.stdout or '{"results": []}'), r.stderr
    except json.JSONDecodeError as e:
        raise ScannerError("osv-scanner produced invalid JSON") from e


def package_count(doc: dict[str, Any], ecosystem: str | None = None) -> int:
    return sum(1 for res in doc.get("results") or [] for p in res.get("packages") or []
               if ecosystem is None or (p.get("package") or {}).get("ecosystem") == ecosystem)


def _has_pom(repo_dir: Path) -> bool:
    return any(p.is_file() for p in repo_dir.rglob("pom.xml") if ".git" not in p.parts)


def run_osv_scanner(repo_dir: Path, policy: Policy, out: Path | None = None) -> dict[str, Any]:
    """Scan with every resolved package listed (--all-packages) and OSV-Scanner's log kept.

    Maven: pom.xml versions inherited from a parent/BOM are resolved through deps.dev by default.
    If a pom.xml exists but nothing Maven was resolved, retry once against Maven Central
    (--data-source=native) before concluding there is nothing to report.
    """
    exe = binary("osv-scanner")
    if not exe:
        raise ScannerError("osv-scanner is not installed (the workflow installs it when scan_engine=scanner)")
    cfg = _cfg(policy, "osv_scanner")
    timeout = int(cfg.get("timeout_seconds", 1800))
    base = [exe, "scan", "source", "-r", "--all-packages", "--verbosity", "info", "--format", "json",
            *[str(a) for a in cfg.get("extra_args") or []]]
    doc, stderr = _osv_once([*base, "."], repo_dir, timeout)
    logs = [f"$ {' '.join(base[1:])} .", stderr]
    if _has_pom(repo_dir) and package_count(doc, "Maven") == 0 and cfg.get("maven_native_fallback", True):
        LOG.warning("osv-scanner resolved no Maven packages from pom.xml via deps.dev; retrying with Maven Central")
        doc2, stderr2 = _osv_once([*base, "--data-source=native", "."], repo_dir, timeout)
        logs += [f"$ {' '.join(base[1:])} --data-source=native .", stderr2]
        if package_count(doc2, "Maven") > 0:
            doc = doc2
            doc["fixpoint_data_source"] = "native"
    LOG.info("osv-scanner: %d packages resolved (%d Maven)", package_count(doc), package_count(doc, "Maven"))
    if out:
        write_json(out, doc)
        out.with_suffix(".log").write_text(log.redact("\n".join(logs)), encoding="utf-8")
    return doc


def sca_findings(doc: dict[str, Any], repo_dir: Path) -> list[Finding]:
    findings = []
    for f in adapters.parse(doc, "osv", "sca"):
        f.source = "scanner:osv-scanner"
        f.properties["osv_confirmed"] = True
        if f.package:
            f.package.manifest = _relativise(f.package.manifest, repo_dir)
            f.location.file = f.package.manifest
        f.id = fingerprint(f)
        findings.append(f)
    return merge_findings(findings)


def osv_rescan(repo_dir: Path, policy: Policy, package: str, vulns: set[str]) -> tuple[bool, str]:
    """Re-run OSV-Scanner on the patched tree: is ``package`` still affected by any of ``vulns``?"""
    doc = run_osv_scanner(repo_dir, policy)
    still: set[str] = set()
    for res in doc.get("results") or []:
        for p in res.get("packages") or []:
            if (p.get("package") or {}).get("name", "").lower() != package.lower():
                continue
            for v in p.get("vulnerabilities") or []:
                ids = {v.get("id", ""), *(v.get("aliases") or [])}
                still |= {i.upper() for i in ids} & vulns
    if still:
        return False, f"osv-scanner still reports {sorted(still)} for {package}"
    return True, f"osv-scanner: {package} no longer affected by {sorted(vulns)}"


# -- entry point ---------------------------------------------------------------------


def scan(kind: str, repo_dir: Path, sha: str, policy: Policy, raw_dir: Path) -> ScanResult:
    if kind == "sast":
        raw = raw_dir / "semgrep.sarif"
        doc = run_semgrep(repo_dir, raw, policy)
        found = sast_findings(doc, repo_dir, sha)
        tool = ((doc.get("runs") or [{}])[0].get("tool") or {}).get("driver") or {}
        engine = f"semgrep {tool.get('semanticVersion') or tool.get('version') or ''}".strip()
        configs = _cfg(policy, "semgrep").get("configs") or ["p/default"]
        meta = {"sast_mode": "scanner", "sast_engine": f"{engine} ({', '.join(configs)})", "scanner_raw": raw.name}
    elif kind == "sca":
        raw = raw_dir / "osv-scanner.json"
        doc = run_osv_scanner(repo_dir, policy, raw)
        found = sca_findings(doc, repo_dir)
        resolved = package_count(doc)
        source = doc.get("fixpoint_data_source", "deps.dev")
        meta = {"sca_mode": "scanner", "sca_engine": f"osv-scanner, {resolved} packages resolved via {source}",
                "scanner_raw": raw.name, "packages_resolved": resolved}
        if resolved == 0 and _has_manifest(repo_dir, policy):
            return ScanResult(found, {**meta, "discover_errors": [
                "osv-scanner resolved no dependencies although the repo has a manifest; "
                "dependency findings may be missing (see osv-scanner.log in the artifact)"]})
    else:
        raise ScannerError(f"unknown kind {kind!r}")
    LOG.info("%s scanner: %d findings", kind, len(found))
    return ScanResult(found, {**meta, "discover_errors": []})


def _has_manifest(repo_dir: Path, policy: Policy) -> bool:
    from fixpoint.scan import find_manifests  # local import: scan is imported at module load

    return bool(find_manifests(repo_dir, policy))


def is_deterministic(f: Finding) -> bool:
    """Findings from a scanner or a supplied report (not from the model's own discovery)."""
    return bool(re.match(r"^(scanner|report):", f.source))
