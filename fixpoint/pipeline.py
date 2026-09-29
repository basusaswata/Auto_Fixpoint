"""Run inputs, pinning, and a local end-to-end runner (dev and evals).

In CI each stage runs as its own CLI command in its own job; ``run_local``
chains the same functions in-process (no signing, no publishing).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fixpoint import align as align_mod
from fixpoint import fix as fix_mod
from fixpoint import ingest, log, scan, triage, verify, worktree
from fixpoint import plan as plan_mod
from fixpoint.agent import AgentRuntime
from fixpoint.config import REPO_RE, Policy, SkillsLock
from fixpoint.gh import GitHub
from fixpoint.model import Finding, merge_findings, save_findings, write_json
from fixpoint.osvapi import OsvClient

LOG = log.get(__name__)

BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)[A-Za-z0-9._/-]{1,200}(?<!\.lock)(?<![/.])$")
FORMATS = {"sast": ("auto", "sarif"), "sca": ("auto", "snyk", "osv", "sarif")}


class InputError(ValueError):
    pass


def _report(value: str, name: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if v.startswith("https://"):
        if re.search(r"\s", v):
            raise InputError(f"{name}: invalid URL")
        return v
    if v.startswith(("/", "~")) or ".." in Path(v).parts or re.search(r"[^A-Za-z0-9._/-]", v):
        raise InputError(f"{name}: must be an https URL or a relative path inside the workspace")
    return v


def validate_inputs(raw: dict[str, Any]) -> dict[str, Any]:
    repo = str(raw.get("repo") or "").strip()
    if not REPO_RE.match(repo):
        raise InputError("repo must be org/name")
    branch = str(raw.get("branch") or "").strip()
    if not BRANCH_RE.match(branch):
        raise InputError("branch is not a valid git branch name")
    mode = str(raw.get("mode") or "review").strip()
    if mode not in ("review", "fix"):
        raise InputError("mode must be review or fix")
    max_prs_raw = str(raw.get("max_prs") or "").strip()
    if max_prs_raw and not re.match(r"^\d{1,3}$", max_prs_raw):
        raise InputError("max_prs must be a non-negative integer")
    out = {
        "repo": repo,
        "branch": branch,
        "mode": mode,
        "max_prs": int(max_prs_raw) if max_prs_raw else None,
        "dry_run": str(raw.get("dry_run") or "").lower() in ("1", "true", "yes"),
    }
    for kind in ("sast", "sca"):
        out[f"{kind}_report"] = _report(str(raw.get(f"{kind}_report") or ""), f"{kind}_report")
        fmt = str(raw.get(f"{kind}_format") or "auto").strip() or "auto"
        if fmt not in FORMATS[kind]:
            raise InputError(f"{kind}_format must be one of {FORMATS[kind]}")
        out[f"{kind}_format"] = fmt
    actor = str(raw.get("actor") or "").strip()
    out["actor"] = actor if re.match(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$", actor) else "unknown"
    return out


def run_context_from_env(inputs: dict[str, Any]) -> dict[str, Any]:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    fp_repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    return {
        **inputs,
        "sha": "",
        "run_id": run_id,
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "run_url": f"{server}/{fp_repo}/actions/runs/{run_id}" if fp_repo else "",
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
        "fixpoint_repo": fp_repo,
        "server_url": server,
    }


def pin(run: dict[str, Any], policy: Policy, gh: GitHub) -> dict[str, Any]:
    if not policy.is_enrolled(run["repo"]):
        raise InputError(f"{run['repo']} is not enrolled in policy/policy.yaml")
    sha = gh.branch_sha(run["repo"], run["branch"])
    if not re.match(r"^[0-9a-f]{40}$", sha):
        raise InputError("could not resolve branch to a commit")
    LOG.info("pinned %s@%s -> %s", run["repo"], run["branch"], sha)
    return {**run, "sha": sha}


# -- local end-to-end ------------------------------------------------------------------


@dataclass
class LocalResult:
    findings: list[Finding]
    meta: dict[str, Any]
    plan: dict[str, Any]
    fixes: list[dict[str, Any]]
    verdicts: list[dict[str, Any]]


def get_findings(repo_dir: Path, run: dict[str, Any], policy: Policy, lock: SkillsLock, runtime: AgentRuntime,
                 osv: OsvClient | None = None) -> tuple[list[Finding], dict[str, Any]]:
    """REPORT or DISCOVER, decided separately for SAST and SCA; then align."""
    all_f: list[list[Finding]] = []
    meta: dict[str, Any] = {"skill_version": lock.version, "discover_errors": []}
    max_bytes = int(policy.limits.get("report_max_bytes", 25 * 1024 * 1024))
    for kind in ("sast", "sca"):
        src = run.get(f"{kind}_report")
        if src:
            fs = ingest.ingest(src, run.get(f"{kind}_format", "auto"), kind, max_bytes)
            meta[f"{kind}_mode"], meta[f"{kind}_format"] = "report", run.get(f"{kind}_format", "auto")
        else:
            res = (scan.discover_sast if kind == "sast" else scan.discover_sca)(
                repo_dir, run["repo"], run["sha"], policy, lock, runtime,
                *([osv] if kind == "sca" else []))
            fs = res.findings
            errs = res.meta.pop("discover_errors", [])
            meta.update(res.meta)
            meta["discover_errors"] += errs
        all_f.append(fs)
    findings = merge_findings(*all_f)
    align_mod.align(findings, repo_dir, run["sha"], scan.find_manifests(repo_dir, policy))
    return findings, meta


def run_local(repo_dir: Path, run: dict[str, Any], policy: Policy, lock: SkillsLock, runtime: AgentRuntime,
              out_dir: Path, osv: OsvClient | None = None, build: bool = True) -> LocalResult:
    findings, meta = get_findings(repo_dir, run, policy, lock, runtime, osv)
    triage.triage(findings, repo_dir, run["repo"], run["sha"], policy, lock, runtime)
    save_findings(out_dir / "findings.json", findings, meta)
    p = plan_mod.plan(findings, policy, run["branch"], run.get("max_prs"), 0)
    write_json(out_dir / "plan.json", p)
    by_id = {f.id: f for f in findings}
    fixes, verdicts = [], []
    for g in p["groups"]:
        gf = [by_id[i] for i in g["finding_ids"]]
        m = fix_mod.run_fix(g, gf, repo_dir, run["repo"], run["sha"], policy, lock, runtime, out_dir / "fix")
        fixes.append(m)
        if m["status"] != "patched":
            continue
        patch = (out_dir / "fix" / g["id"] / "patch.diff").read_text(encoding="utf-8")
        v = verify.verify_rescan(g, gf, patch, m, repo_dir, run["repo"], run["sha"], policy, lock, runtime, osv)
        worktree.reset(repo_dir)
        verdicts.append(v)
        if build:
            vb = verify.verify_build(g, patch, m, repo_dir, policy)
            worktree.reset(repo_dir)
            verdicts.append(vb)
    for v in verdicts:
        write_json(out_dir / "verify" / f"{v['group_id']}.{v['phase']}.verdict.json", v)
    return LocalResult(findings, meta, p, fixes, verdicts)
