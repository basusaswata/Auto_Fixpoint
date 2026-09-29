"""Plan: group fix findings, order by severity, cap, and set strategy/autonomy.

SCA:  one group per (ecosystem, package, manifest) - one upgrade covers every CVE.
SAST: one group per finding.
Cap = min(max_prs input, limits.prs_per_run, limits.open_bot_prs_per_repo - open bot PRs).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from fixpoint import log, versions
from fixpoint.config import Policy
from fixpoint.model import PLAN_SCHEMA, SEVERITY_RANK, Finding

LOG = log.get(__name__)


def _slug(s: str, n: int = 40) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:n] or "x"


def _h(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:8]


def branch_slug(branch: str) -> str:
    return _slug(branch, 50)


def compute_cap(policy: Policy, max_prs: int | None, open_bot_prs: int) -> tuple[int, dict[str, int]]:
    lim = policy.limits
    parts = {
        "policy_prs_per_run": int(lim["prs_per_run"]),
        "open_pr_headroom": max(0, int(lim["open_bot_prs_per_repo"]) - open_bot_prs),
    }
    if max_prs is not None:
        parts["max_prs_input"] = max(0, int(max_prs))
    return min(parts.values()), parts


def plan(findings: list[Finding], policy: Policy, branch: str, max_prs: int | None,
         open_bot_prs: int) -> dict[str, Any]:
    rule = policy.branch_rule(branch)
    fixable = [f for f in findings if f.status == "open" and f.disposition == "fix"]
    groups: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []

    # Policy check #1 (of three): only eligible findings are planned.
    for f in list(fixable):
        if f.severity not in policy.triage["fix_severities"] or (f.confidence or 0) < policy.triage["min_confidence"]:
            fixable.remove(f)
            deferred.append({"finding_ids": [f.id], "reason": "not eligible under policy at plan time"})

    # Other open advisories on the same package+manifest (e.g. triaged not_reachable): the
    # upgrade clears them too when the branch strategy allows a version that fixes everything.
    siblings: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        if f.kind == "sca" and f.package and f.status == "open" and f.disposition != "fix":
            siblings.setdefault((f.package.ecosystem, f.package.name.lower(), f.package.manifest), []).append(f)

    sca: dict[tuple[str, str, str], list[Finding]] = {}
    for f in fixable:
        if f.kind == "sca" and f.package:
            key = (f.package.ecosystem, f.package.name.lower(), f.package.manifest)
            sca.setdefault(key, []).append(f)
        elif f.kind == "sast":
            cwe = f.cwe[0] if f.cwe else (f.rule_id or "weakness")
            groups.append({
                "id": f"sast-{_slug(cwe, 20)}-{f.id[-8:]}",
                "kind": "sast",
                "finding_ids": [f.id],
                "severity": f.severity,
                "title": f.title or f.message[:90],
                "cwe": f.cwe,
                "cve": [],
                "rule_id": f.rule_id,
                "role": "fix_cwe",
                "strategy": "patch",
                "autonomy": "pr" if rule.autonomy == "auto-merge-patch" else rule.autonomy,
                "files": [f.location.file],
            })

    same_major = rule.cve_upgrade == "same-major-lowest-safe"
    for (eco, _name, manifest), fs in sca.items():
        pkg = fs[0].package
        assert pkg is not None
        targets, included = [], []
        for f in fs:
            t = versions.lowest_fix(pkg.version, f.package.fixed_versions if f.package else [], same_major)
            if t is None:
                deferred.append({"finding_ids": [f.id], "reason":
                                 f"no {'same-major ' if same_major else ''}fixed version above {pkg.version}"})
                continue
            targets.append(t)
            included.append(f)
        if not included:
            continue
        target = max(targets, key=versions.Version)
        also: list[str] = []
        extra = [versions.lowest_fix(pkg.version, s.package.fixed_versions if s.package else [], same_major)
                 for s in siblings.get((eco, _name, manifest), [])]
        if extra and all(extra):
            target = max([target, *extra], key=versions.Version)  # type: ignore[list-item]
            also = sorted({c for s in siblings[(eco, _name, manifest)] for c in (s.cve or [s.rule_id])})
        autonomy = rule.autonomy
        if autonomy == "auto-merge-patch" and not versions.is_patch_bump(pkg.version, target):
            autonomy = "pr"
        groups.append({
            "id": f"sca-{_slug(pkg.name, 30)}-{_h(eco, pkg.name.lower(), manifest)}",
            "kind": "sca",
            "finding_ids": sorted(f.id for f in included),
            "severity": min((f.severity for f in included), key=SEVERITY_RANK.__getitem__),
            "title": f"upgrade {pkg.name}",
            "cwe": sorted({c for f in included for c in f.cwe}),
            "cve": sorted({c for f in included for c in (f.cve or [f.rule_id])} | set(also)),
            "also_fixes": also,
            "rule_id": included[0].rule_id,
            "role": "fix_cve",
            "strategy": rule.cve_upgrade,
            "autonomy": autonomy,
            "files": [manifest],
            "package": {"ecosystem": eco, "name": pkg.name, "manifest": manifest,
                        "current_version": pkg.version, "target_version": target},
        })

    groups.sort(key=lambda g: (SEVERITY_RANK[g["severity"]], g["kind"] != "sca", g["id"]))
    cap, cap_parts = compute_cap(policy, max_prs, open_bot_prs)
    planned, over = groups[:cap], groups[cap:]
    for g in over:
        deferred.append({"group_id": g["id"], "finding_ids": g["finding_ids"], "reason": f"cap {cap} reached"})
    LOG.info("plan: %d groups planned, %d deferred (cap=%d %s)", len(planned), len(deferred), cap, cap_parts)
    return {
        "schema": PLAN_SCHEMA,
        "meta": {"branch": branch, "branch_rule": rule.match, "cap": cap, "cap_parts": cap_parts,
                 "open_bot_prs": open_bot_prs},
        "groups": planned,
        "deferred": deferred,
    }
