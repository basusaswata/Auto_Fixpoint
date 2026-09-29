"""Report: summary.md, dispositioned SARIF and OpenVEX. Always runs; tolerates
missing inputs from failed jobs and says so."""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
from typing import Any

from fixpoint import __version__
from fixpoint.model import DISPOSITIONS, STATUSES, Finding, read_json, write_json

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def _load(path: Path | None) -> Any:
    try:
        return read_json(path) if path and path.is_file() else None
    except ValueError:
        return None


def _suppression_justification(f: Finding) -> str:
    return f"{f.disposition or f.status}: {f.reasoning or ', '.join(f.notes) or 'no reasoning recorded'}"[:1000]


def to_sarif(findings: list[Finding], run: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f.rule_id or (f.cwe[0] if f.cwe else f.kind)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": (f.title or rid)[:200]},
                "properties": {"tags": ["security", *[f"external/cwe/{c.lower()}" for c in f.cwe]],
                               "security-severity": SECURITY_SEVERITY[f.severity]},
            }
        loc = f.location
        region: dict[str, Any] = {}
        if loc.start_line:
            region = {"startLine": loc.start_line, "endLine": max(loc.end_line, loc.start_line)}
            if loc.snippet:
                region["snippet"] = {"text": loc.snippet[:2000]}
        r: dict[str, Any] = {
            "ruleId": rid,
            "level": LEVEL[f.severity],
            "message": {"text": (f.message or f.title)[:4000]},
            "partialFingerprints": {"fixpointId/v1": f.id},
            "properties": {
                "fixpoint.status": f.status,
                "fixpoint.disposition": f.disposition,
                "fixpoint.confidence": f.confidence,
                "fixpoint.reasoning": f.reasoning,
                "fixpoint.evidence": [e.__dict__ for e in f.evidence],
                "fixpoint.source": f.source,
                "fixpoint.notes": f.notes,
                "cve": f.cve,
            },
        }
        if loc.file:
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": loc.file}, "region": region}
                               if region else {"artifactLocation": {"uri": loc.file}}}]
        if f.package:
            r["properties"]["package"] = f.package.__dict__
        if f.properties.get("pr"):
            r["properties"]["fixpoint.pr"] = f.properties["pr"]
        # Anything not headed for (or already in) a fix is recorded as a suppression with a justification.
        if f.disposition in ("false_positive", "not_reachable", "accepted_risk") or f.status in ("rejected",):
            r["suppressions"] = [{"kind": "external", "status": "accepted",
                                  "justification": _suppression_justification(f)}]
        elif f.disposition == "human_review":
            r["suppressions"] = [{"kind": "external", "status": "underReview",
                                  "justification": _suppression_justification(f)}]
        results.append(r)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Fixpoint", "version": __version__, "informationUri":
                                "https://github.com/" + str(run.get("fixpoint_repo", "")),
                                "rules": list(rules.values())}},
            "versionControlProvenance": [{"repositoryUri": f"https://github.com/{run.get('repo', '')}",
                                          "revisionId": run.get("sha", ""), "branch": run.get("branch", "")}],
            "results": results,
        }],
    }


def _purl(f: Finding) -> str:
    p = f.package
    assert p is not None
    eco = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "Maven": "maven", "RubyGems": "gem",
           "Packagist": "composer", "crates.io": "cargo", "NuGet": "nuget"}.get(p.ecosystem, p.ecosystem.lower())
    name = p.name.replace(":", "/") if eco == "maven" else p.name
    if eco == "pypi":
        name = name.lower().replace("_", "-")
    return f"pkg:{eco}/{name}@{p.version}"


def to_openvex(findings: list[Finding], run: dict[str, Any], published: dict[str, str]) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    statements = []
    for f in findings:
        if f.kind != "sca" or not f.package:
            continue
        for vuln in f.cve or [f.rule_id]:
            st: dict[str, Any] = {"vulnerability": {"name": vuln}, "products": [{"@id": _purl(f)}], "timestamp": now}
            if f.disposition == "not_reachable":
                st.update(status="not_affected", justification="vulnerable_code_not_in_execute_path",
                          impact_statement=f.reasoning[:1000])
            elif f.disposition == "false_positive":
                st.update(status="not_affected", justification="vulnerable_code_not_present",
                          impact_statement=f.reasoning[:1000])
            elif f.disposition == "fix" or f.status in ("in_flight", "fixed"):
                if f.status == "fixed":
                    st.update(status="fixed")
                else:
                    pr = published.get(f.id) or (f.properties.get("pr") or {}).get("url")
                    action = f"Upgrade {f.package.name} to a fixed version ({', '.join(f.package.fixed_versions[:3])})"
                    st.update(status="affected", action_statement=action + (f"; fix proposed in {pr}" if pr else
                                                                             "; fix pending"))
            elif f.disposition == "accepted_risk":
                st.update(status="affected", action_statement=f"Risk accepted: {f.reasoning[:500]}")
            else:
                st.update(status="under_investigation")
            statements.append(st)
    doc_id = hashlib.sha256(f"{run.get('repo')}@{run.get('sha')}#{run.get('run_id')}".encode()).hexdigest()[:24]
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/fixpoint/{doc_id}",
        "author": "Fixpoint",
        "timestamp": now,
        "version": 1,
        "statements": statements,
    }


def summary_md(findings: list[Finding], meta: dict[str, Any], plan: dict | None, fixes: list[dict],
               signs: dict | None, publish: dict | None, run: dict[str, Any], missing: list[str]) -> str:
    L = [f"# Fixpoint report: `{run.get('repo')}` @ `{run.get('branch')}`", ""]
    L.append(f"Commit `{run.get('sha', '')[:12]}` · mode **{run.get('mode', 'review')}** · "
             f"[run]({run.get('run_url', '')}) · requested by @{run.get('actor', '?')}")
    L.append("")
    L.append(f"- SAST: **{meta.get('sast_mode', '?')}** ({meta.get('sast_engine', meta.get('sast_format', ''))})")
    L.append(f"- SCA: **{meta.get('sca_mode', '?')}** ({meta.get('sca_engine', meta.get('sca_format', ''))})")
    if meta.get("skill_version"):
        L.append(f"- Skills: `{meta['skill_version']}`")
    if missing:
        L.append(f"- ⚠️ Missing stage outputs (a job failed or was skipped): {', '.join(missing)}")
    errs = meta.get("discover_errors") or []
    if errs:
        L.append(f"- ⚠️ Discover errors: {len(errs)}")
        L += [f"  - {e[:300]}" for e in errs[:10]]
    L += ["", "## Findings", "", "| | count |", "|---|---:|", f"| total | {len(findings)} |"]
    for s in STATUSES:
        n = sum(1 for f in findings if f.status == s)
        if n:
            L.append(f"| status: {s} | {n} |")
    for d in DISPOSITIONS:
        n = sum(1 for f in findings if f.disposition == d)
        if n:
            L.append(f"| disposition: {d} | {n} |")
    opened = [r for r in (publish or {}).get("results", []) if r.get("status") in ("opened", "dry_run")]
    L += ["", "## Pull requests", ""]
    if opened:
        for r in opened:
            link = f"[#{r['number']}]({r['url']})" if r.get("url") else "(dry run)"
            L.append(f"- {link} `{r.get('group_id')}` {r.get('title', '')} ({r.get('autonomy')})")
    else:
        L.append("- none")
    not_pub = [r for r in (publish or {}).get("results", []) if r.get("status") not in ("opened", "dry_run")]
    not_signed = [r for r in (signs or {}).get("results", []) if r.get("status") not in ("signed", "unsigned")]
    failed_fix = [m for m in fixes if m.get("status") != "patched"]
    if not_pub or not_signed or failed_fix:
        L += ["", "## Not published", ""]
        L += [f"- fix `{m['group_id']}`: {m.get('status')} - {m.get('error') or _failed_checks(m.get('precheck'))}"
              for m in failed_fix]
        L += [f"- verify/sign `{r['group_id']}`: {r.get('reason', '')[:300]}" for r in not_signed]
        L += [f"- publish `{r.get('group_id', r.get('bundle'))}`: {r.get('status')} - {r.get('reason', '')[:300]}"
              for r in not_pub]
    if plan and plan.get("deferred"):
        L += ["", "## Deferred", ""]
        L += [f"- {', '.join(d.get('finding_ids', []))[:120]}: {d['reason']}" for d in plan["deferred"][:50]]
    hr = [f for f in findings if f.disposition == "human_review"]
    if hr:
        L += ["", "## Needs human review", ""]
        L += [f"- `{f.id}` {f.severity} {', '.join(f.cve or f.cwe)} `{f.location.file}:{f.location.start_line}` - "
              f"{(f.reasoning or '; '.join(f.notes))[:200]}" for f in hr[:50]]
    stale = [f for f in findings if f.status in ("stale", "unlocatable")]
    if stale:
        L += ["", "## Stale / unlocatable", ""]
        L += [f"- `{f.id}` {f.status}: {f.reasoning[:200]}" for f in stale[:50]]
    return "\n".join(L) + "\n"


def _failed_checks(checks: list[dict] | None) -> str:
    return "; ".join(f"{c['name']}: {c['detail'][:150]}" for c in checks or [] if not c.get("passed")) or "-"


def build(findings_path: Path, plan_path: Path | None, fix_dir: Path | None, sign_path: Path | None,
          publish_path: Path | None, run: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    from fixpoint.model import load_findings

    missing = []
    findings: list[Finding] = []
    meta: dict[str, Any] = {}
    if findings_path.is_file():
        findings, meta = load_findings(findings_path)
    else:
        missing.append("findings")
    plan = _load(plan_path)
    if plan_path and plan is None and run.get("mode") == "fix":
        missing.append("plan")
    fixes = [read_json(p) for p in sorted(fix_dir.rglob("meta.json"))] if fix_dir and fix_dir.exists() else []
    signs = _load(sign_path)
    publish = _load(publish_path)
    if run.get("mode") == "fix" and plan and plan.get("groups"):
        if not fixes:
            missing.append("fix")
        if signs is None:
            missing.append("sign")
        if publish is None:
            missing.append("publish")
    published = {}
    for r in (publish or {}).get("results", []):
        if r.get("url") and plan:
            for g in plan.get("groups", []):
                if g["id"] == r.get("group_id"):
                    published.update({fid: r["url"] for fid in g["finding_ids"]})
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"summary": out_dir / "summary.md", "sarif": out_dir / "fixpoint.sarif",
             "openvex": out_dir / "openvex.json"}
    paths["summary"].write_text(summary_md(findings, meta, plan, fixes, signs, publish, run, missing), encoding="utf-8")
    write_json(paths["sarif"], to_sarif(findings, run))
    write_json(paths["openvex"], to_openvex(findings, run, published))
    return paths
