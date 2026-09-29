"""Triage: one disposition per open finding. Policy overrides the model.

* fix with confidence < triage.min_confidence           -> human_review
* fix with severity not in triage.fix_severities        -> human_review
* fix on an SCA finding with no known fixed version     -> human_review
* fix on a discovered SCA finding not confirmed by OSV  -> human_review
* failed agent call                                     -> whole batch human_review
* finding missing from the agent's answer               -> human_review
"""

from __future__ import annotations

from pathlib import Path

from fixpoint import log, prompts, schemas
from fixpoint.agent import AgentError, AgentRequest, AgentRuntime, skills_dir, wrap_untrusted
from fixpoint.config import Policy, SkillsLock
from fixpoint.model import Evidence, Finding
from fixpoint.scan import batched

LOG = log.get(__name__)


def finding_context(f: Finding, repo_dir: Path, lines: int) -> str:
    loc = f.location
    parts = [
        f"id: {f.id}",
        f"kind: {f.kind}",
        f"rule: {f.rule_id}",
        f"cwe: {', '.join(f.cwe) or '-'}",
        f"cve: {', '.join(f.cve) or '-'}",
        f"severity: {f.severity}",
        f"title: {f.title}",
        f"message: {f.message[:1500]}",
    ]
    if f.package:
        p = f.package
        parts.append(f"package: {p.ecosystem}/{p.name}@{p.version} in {p.manifest}; fixed in: "
                     f"{', '.join(p.fixed_versions) or 'no fixed version known'}")
    if f.path:
        parts.append("reported path: " + " -> ".join(f.path))
    if f.kind == "sast" and loc.file:
        parts.append(f"location: {loc.file}:{loc.start_line}-{loc.end_line}")
        p = repo_dir / loc.file
        if p.is_file() and not p.is_symlink():
            src = p.read_text(encoding="utf-8", errors="replace").splitlines()
            a = max(1, loc.start_line - lines)
            b = min(len(src), loc.end_line + lines)
            numbered = "\n".join(f"{i:>5}{'>' if loc.start_line <= i <= loc.end_line else ' '} {src[i - 1]}"
                                 for i in range(a, b + 1))
            parts.append(f"code ({loc.file}:{a}-{b}, '>' marks the flagged lines):\n{numbered}")
    return wrap_untrusted(f"finding:{f.id}", "\n".join(parts))


def override(f: Finding, policy: Policy) -> None:
    """Apply policy to a model disposition. Mutates f."""
    if f.disposition != "fix":
        return
    reasons = []
    min_conf = float(policy.triage["min_confidence"])
    if f.confidence is None or f.confidence < min_conf:
        reasons.append(f"confidence {f.confidence} below {min_conf}")
    if f.severity not in policy.triage["fix_severities"]:
        reasons.append(f"severity {f.severity} not eligible for automatic fix")
    if f.kind == "sca":
        if not f.package or not f.package.fixed_versions:
            reasons.append("no fixed version known")
        if f.source.startswith("discover:") and not f.properties.get("osv_confirmed"):
            reasons.append("vulnerability not confirmed by a deterministic source")
    if reasons:
        f.disposition = "human_review"
        f.notes.append("policy override: " + "; ".join(reasons))


def triage(findings: list[Finding], repo_dir: Path, repo: str, sha: str, policy: Policy, lock: SkillsLock,
           runtime: AgentRuntime) -> list[Finding]:
    cfg = policy.triage
    todo = [f for f in findings if f.status == "open" and f.disposition is None]
    skill = lock.skill("triage")
    for i, batch in enumerate(batched(todo, int(cfg.get("batch_size", 8))), 1):
        blocks = "\n\n".join(finding_context(f, repo_dir, int(cfg.get("context_lines", 25))) for f in batch)
        prompt = prompts.render("triage", skill=skill, repo=repo, sha=sha, findings=blocks)
        req = AgentRequest(role="triage", prompt=prompt, schema=schemas.TRIAGE, cwd=repo_dir,
                           add_dirs=[skills_dir()], max_budget_usd=float(cfg.get("max_budget_usd", 3.0)))
        try:
            res = runtime.run(req)
            answers = {r["id"]: r for r in res.data["results"]}
            model = res.model
        except AgentError as e:
            LOG.error("triage batch %d failed, sending %d findings to human_review: %s", i, len(batch), e)
            for f in batch:
                f.disposition, f.confidence = "human_review", 0.0
                f.reasoning = f"triage failed: {e}"
            continue
        for f in batch:
            a = answers.get(f.id)
            if a is None:
                f.disposition, f.confidence, f.reasoning = "human_review", 0.0, "triage returned no verdict"
                continue
            f.disposition = a["disposition"]
            f.confidence = float(a["confidence"])
            f.reasoning = a["reasoning"]
            f.evidence = [*f.evidence, *(Evidence(**e) for e in a["evidence"])]
            f.properties["triage_model"] = model
            override(f, policy)
    counts: dict[str, int] = {}
    for f in todo:
        counts[str(f.disposition)] = counts.get(str(f.disposition), 0) + 1
    LOG.info("triage: %s", counts)
    return findings
