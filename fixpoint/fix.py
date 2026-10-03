"""Fix: run fix_cwe / fix_cve for one plan group in a sandbox, capture the patch."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fixpoint import diffutil, log, prompts, rules, schemas, worktree
from fixpoint.agent import (
    EDIT_TOOLS,
    READ_TOOLS,
    AgentError,
    AgentRequest,
    AgentRuntime,
    skills_dir,
    wrap_untrusted,
)
from fixpoint.config import Policy, SkillsLock
from fixpoint.model import Finding, sha256_bytes, write_json
from fixpoint.triage import finding_context

LOG = log.get(__name__)


def detect_commands(repo_dir: Path, policy: Policy):
    for c in policy.verify_commands:
        if (repo_dir / c.marker).is_file():
            return c
    return None


def dependency_note(pkg: dict[str, Any]) -> str:
    """How the dependency reaches the build, so the fix-cve agent pins it the right way."""
    if pkg.get("transitive"):
        return (f"`{pkg['name']}` is a TRANSITIVE dependency: it is not declared in `{pkg['manifest']}` but pulled in by "
                "another dependency or the parent. Pin it explicitly in that manifest with the ecosystem's override "
                "mechanism (Maven: a `<dependencyManagement>` entry with groupId, artifactId and version; Gradle: a "
                "constraint; npm: `overrides`; Python: a pinned requirement). The manifest must name the package and "
                "the target version. Do not upgrade unrelated dependencies.")
    if pkg.get("managed"):
        return (f"`{pkg['name']}` is declared in `{pkg['manifest']}` WITHOUT a version (it is managed by a parent/BOM). "
                "Add an explicit version for it (Maven: `<version>` on that dependency, or a `<dependencyManagement>` "
                "entry), so the manifest names the package and the target version.")
    return f"`{pkg['name']}` is declared directly in `{pkg['manifest']}`: change its version there."


def run_fix(group: dict[str, Any], findings: list[Finding], repo_dir: Path, repo: str, sha: str, policy: Policy,
            lock: SkillsLock, runtime: AgentRuntime, out_dir: Path) -> dict[str, Any]:
    gid = group["id"]
    gdir = out_dir / gid
    gdir.mkdir(parents=True, exist_ok=True)
    role = group["role"]
    skill = lock.skill(role)
    cfg = policy.fix
    blocks = "\n\n".join(finding_context(f, repo_dir, int(policy.triage.get("context_lines", 25))) for f in findings)
    bash: list[list[str]] = []
    bash_note = "You have no shell. Do not try to run commands; verification happens later."
    if cfg.get("allow_bash"):
        cmds = detect_commands(repo_dir, policy)
        if cmds:
            bash = [c for c in (cmds.install, cmds.build, cmds.test) if c]
            bash_note = "You may run only these exact commands: " + "; ".join(" ".join(c) for c in bash)
    common = {
        "skill": skill, "repo": repo, "sha": sha, "findings": blocks, "bash_note": bash_note,
        "forbidden": ", ".join(policy.forbidden_paths),
        "max_files": policy.limits["changed_files"], "max_lines": policy.limits["changed_lines"],
    }
    if group["kind"] == "sca":
        p = group["package"]
        prompt = prompts.render(
            "fix-cve", package=p["name"], ecosystem=p["ecosystem"], current_version=p["current_version"],
            target_version=p["target_version"], manifest=p["manifest"], dependency_note=dependency_note(p),
            vulns=wrap_untrusted("vulns", ", ".join(group["cve"])), **common,
        )
    else:
        prompt = prompts.render("fix-cwe", **common)
    req = AgentRequest(role=role, prompt=prompt, schema=schemas.FIX, cwd=repo_dir, tools=READ_TOOLS + EDIT_TOOLS,
                       bash_commands=bash, add_dirs=[skills_dir()],
                       max_budget_usd=float(cfg.get("max_budget_usd", 5.0)),
                       timeout_seconds=int(cfg.get("timeout_seconds", 1800)))
    meta: dict[str, Any] = {
        "group_id": gid, "finding_ids": group["finding_ids"], "kind": group["kind"], "skill": skill,
        "skill_version": lock.version, "base_sha": sha, "status": "failed",
    }
    try:
        res = runtime.run(req)
    except AgentError as e:
        meta["error"] = str(e)
        write_json(gdir / "meta.json", meta)
        worktree.reset(repo_dir)
        return meta
    data = res.data
    patch = worktree.capture_diff(repo_dir)
    worktree.reset(repo_dir)
    meta.update({
        "model": res.model, "rationale": data["rationale"], "test_added": data.get("test_added"),
        "reported_changed_files": data["changed_files"], "new_version": data.get("new_version", ""),
        "notes": data.get("notes", ""), "agent_status": data["status"],
    })
    if data["status"] != "fixed" or not patch.strip():
        meta["error"] = "agent could not fix" if data["status"] != "fixed" else "agent produced no changes"
        write_json(gdir / "meta.json", meta)
        return meta
    patch_bytes = patch.encode("utf-8")
    meta["patch_sha256"] = sha256_bytes(patch_bytes)
    precheck = rules.check_patch(patch, policy, group, meta)
    meta["precheck"] = precheck
    meta["status"] = "patched" if rules.all_passed(precheck) else "rejected"
    try:
        meta["changed_files"] = [f.path for f in diffutil.parse(patch)]
    except diffutil.PatchError:
        meta["changed_files"] = []  # reported by precheck already
    (gdir / "patch.diff").write_bytes(patch_bytes)
    write_json(gdir / "meta.json", meta)
    LOG.info("fix %s: %s", gid, meta["status"])
    return meta
