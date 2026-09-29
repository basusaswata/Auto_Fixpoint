"""Verify a patch. Two independent phases, run in separate jobs:

``rescan`` (verify-ai job: model key, never runs target-repo code)
    diff rules; apply; SCA: OSV re-scan of the new version; verify skill on the diff
    (finding gone, nothing new, test meaningful).
``build`` (verify-build job: no secrets at all, runs target-repo code)
    diff rules; apply; install / build / test commands chosen by marker file.

A patch is only signed when both verdicts pass for the same patch hash.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from fixpoint import diffutil, log, prompts, rules, schemas, worktree
from fixpoint.agent import AgentError, AgentRequest, AgentRuntime, skills_dir, wrap_untrusted
from fixpoint.config import Policy, SkillsLock
from fixpoint.fix import detect_commands
from fixpoint.model import Finding, sha256_bytes
from fixpoint.osvapi import Dependency, OsvClient, OsvError
from fixpoint.triage import finding_context

LOG = log.get(__name__)
check = rules.check


def _verdict(group: dict[str, Any], phase: str, patch_sha: str, checks: list[dict[str, Any]], **extra: Any) -> dict:
    return {"group_id": group["id"], "phase": phase, "patch_sha256": patch_sha,
            "passed": rules.all_passed(checks), "checks": checks, **extra}


def _static_and_apply(patch: str, repo_dir: Path, policy: Policy, group: dict, meta: dict) -> list[dict]:
    checks = rules.check_patch(patch, policy, group, meta)
    if not rules.all_passed(checks):
        return checks
    try:
        touched = worktree.apply_patch(repo_dir, patch)
        checks.append(check("apply", True, f"applied to {len(touched)} file(s)"))
    except diffutil.PatchError as e:
        checks.append(check("apply", False, str(e)))
    return checks


# -- build phase --------------------------------------------------------------

# marker file -> toolchain the build job must install (GitHub-hosted runners start bare)
TOOLCHAIN = {
    "package-lock.json": "node", "yarn.lock": "node", "pnpm-lock.yaml": "node", "package.json": "node",
    "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java",
    "go.mod": "go",
    "pyproject.toml": "python", "requirements.txt": "python",
}
VERSION_FILES = {
    "node": (".nvmrc", ".node-version"),
    "java": (".java-version", ".sdkmanrc", ".tool-versions"),
    "go": ("go.mod",),
    "python": (".python-version",),
}


def toolchain(repo_dir: Path, policy: Policy) -> dict[str, str]:
    """Which toolchain verify-build needs, from the same marker the build commands use."""
    cmds = detect_commands(repo_dir, policy)
    kind = TOOLCHAIN.get(cmds.marker, "") if cmds else ""
    version_file = next((f for f in VERSION_FILES.get(kind, ()) if (repo_dir / f).is_file()
                         and not (repo_dir / f).is_symlink()), "")
    return {
        "kind": kind,
        "marker": cmds.marker if cmds else "",
        "version_file": str(repo_dir / version_file) if version_file else "",
        "needs_maven": str(kind == "java" and cmds is not None and cmds.marker == "pom.xml"
                           and not (repo_dir / "mvnw").is_file()).lower(),
    }



def _scrubbed_env(policy: Policy, home: Path) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8", "CI": "true"}
    for k in policy.verify.get("pass_env") or []:
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def _run(argv: list[str], cwd: Path, env: dict[str, str], timeout: int, prefix: list[str]) -> tuple[int, str]:
    try:
        r = subprocess.run([*prefix, *argv], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
                           check=False)
        return r.returncode, log.redact((r.stdout + "\n" + r.stderr)[-2000:])
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return 127, f"command not found: {e.filename}"


def verify_build(group: dict[str, Any], patch: str, meta: dict[str, Any], repo_dir: Path,
                 policy: Policy) -> dict[str, Any]:
    patch_sha = sha256_bytes(patch.encode("utf-8"))
    checks = _static_and_apply(patch, repo_dir, policy, group, meta)
    if not rules.all_passed(checks):
        return _verdict(group, "build", patch_sha, checks)
    cfg = policy.verify
    cmds = detect_commands(repo_dir, policy)
    if cmds is None:
        checks.append(check("build", not cfg.get("require_build", True),
                            "no known build marker found" + ("; require_build is on" if cfg.get("require_build", True)
                                                             else "; skipped")))
        return _verdict(group, "build", patch_sha, checks)
    timeout = int(cfg.get("timeout_seconds", 1800))
    prefix = list(cfg.get("sandbox_prefix") or [])
    with tempfile.TemporaryDirectory(prefix="fixpoint-build-home-") as home:
        env = _scrubbed_env(policy, Path(home))
        if TOOLCHAIN.get(cmds.marker) == "python":
            # Target deps go into their own venv, never into the interpreter running Fixpoint.
            venv = Path(home) / "venv"
            py = shutil.which("python3", path=env["PATH"]) or sys.executable
            subprocess.run([py, "-m", "venv", str(venv)], check=True, capture_output=True)
            env["PATH"] = f"{venv / 'bin'}{os.pathsep}{env['PATH']}"
            env["VIRTUAL_ENV"] = str(venv)
        for step in ("install", "build", "test"):
            argv = getattr(cmds, step)
            if not argv:
                continue
            rc, tail = _run(argv, repo_dir, env, timeout, prefix)
            checks.append(check(step, rc == 0, f"`{' '.join(argv)}` exit {rc}" + ("" if rc == 0 else f"\n{tail}")))
            if rc != 0:
                break
    if group["kind"] == "sast" and meta.get("test_added"):
        p = repo_dir / meta["test_added"]["path"]
        checks.append(check("new-test-present", p.is_file(), meta["test_added"]["path"]))
    return _verdict(group, "build", patch_sha, checks, marker=cmds.marker)


# -- rescan phase ---------------------------------------------------------------


def _osv_rescan(group: dict[str, Any], meta: dict[str, Any], repo_dir: Path, osv: OsvClient) -> list[dict]:
    p = group["package"]
    target = meta.get("new_version") or p["target_version"]
    out = []
    manifest = repo_dir / p["manifest"]
    text = manifest.read_text(encoding="utf-8", errors="replace") if manifest.is_file() else ""
    out.append(check("manifest-version", target in text and p["name"].split(":")[-1] in text,
                     f"{p['manifest']} names {p['name']} {target}"))
    if target != p["target_version"]:
        out.append(check("planned-version", False, f"agent used {target}, plan said {p['target_version']}"))
    try:
        before = osv.vulns_at(Dependency(p["ecosystem"], p["name"], p["current_version"], p["manifest"]))
        after = osv.vulns_at(Dependency(p["ecosystem"], p["name"], target, p["manifest"]))
    except (OsvError, OSError, ValueError) as e:
        out.append(check("osv-rescan", False, f"OSV lookup failed: {e}"))
        return out
    wanted = {x.upper() for x in group.get("cve") or []}
    still = sorted(wanted & after)
    new = sorted(after - before)
    out.append(check("finding-gone", not still, f"still affected by {still}" if still else
                     f"{p['name']}@{target} not affected by {sorted(wanted)}"))
    out.append(check("no-new-vulns", not new, f"new advisories at {target}: {new}" if new else "none"))
    return out


def verify_rescan(group: dict[str, Any], findings: list[Finding], patch: str, meta: dict[str, Any], repo_dir: Path,
                  repo: str, sha: str, policy: Policy, lock: SkillsLock, runtime: AgentRuntime,
                  osv: OsvClient | None = None) -> dict[str, Any]:
    patch_sha = sha256_bytes(patch.encode("utf-8"))
    checks = _static_and_apply(patch, repo_dir, policy, group, meta)
    if not rules.all_passed(checks):
        return _verdict(group, "rescan", patch_sha, checks)
    cfg = policy.verify
    if group["kind"] == "sca":
        osv = osv or OsvClient(policy.discover["sca"].get("osv_api", "https://api.osv.dev"))
        checks += _osv_rescan(group, meta, repo_dir, osv)
    skill = lock.skill("verify")
    blocks = "\n\n".join(finding_context(f, repo_dir, int(policy.triage.get("context_lines", 25))) for f in findings)
    prompt = prompts.render("verify", skill=skill, repo=repo, sha=sha, findings=blocks,
                            patch=wrap_untrusted(f"patch:{group['id']}", patch))
    req = AgentRequest(role="verify", prompt=prompt, schema=schemas.VERIFY, cwd=repo_dir, add_dirs=[skills_dir()],
                       max_budget_usd=float(cfg.get("max_budget_usd", 3.0)))
    try:
        res = runtime.run(req)
    except AgentError as e:
        checks.append(check("verify-skill", False, f"verifier failed: {e}"))
        return _verdict(group, "rescan", patch_sha, checks)
    d = res.data
    by_id = {x["id"]: x for x in d["findings"]}
    if group["kind"] == "sast":
        not_fixed = [fid for fid in group["finding_ids"] if not (by_id.get(fid) or {}).get("fixed")]
        checks.append(check("finding-gone", not not_fixed,
                            f"verifier says still present: {not_fixed}" if not_fixed else "verifier: fixed"))
        if policy.tests.get("require_new_test_for_sast", True):
            checks.append(check("test-meaningful", d["test_meaningful"],
                                "test exercises the flaw" if d["test_meaningful"] else "test does not exercise the flaw"))
    new = [f"{i.get('cwe', '')} {i.get('file', '')}:{i.get('line', 0)} {i['description'][:160]}" for i in d["new_issues"]]
    checks.append(check("no-new-findings", not new, "; ".join(new) or "none"))
    min_conf = float(cfg.get("min_confidence", 0.7))
    checks.append(check("verifier-confidence", d["confidence"] >= min_conf, f"{d['confidence']:.2f} (min {min_conf})"))
    return _verdict(group, "rescan", patch_sha, checks, verifier_model=res.model, summary=d["summary"][:2000])
