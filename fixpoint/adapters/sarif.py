"""SARIF 2.1.0 adapter (CodeQL, Semgrep, Snyk Code, AISecCore scgra-reviewer, ...)."""

from __future__ import annotations

import re
from typing import Any

from fixpoint.model import (
    Finding,
    FormatError,
    Location,
    Package,
    normalise_cwe,
    normalise_severity,
    severity_from_cvss,
)

LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _cwes(*objs: Any) -> list[str]:
    out: set[str] = set()
    for o in objs:
        if not isinstance(o, dict):
            continue
        props = o.get("properties") or {}
        for tag in props.get("tags") or []:
            c = normalise_cwe(tag)
            if c:
                out.add(c)
        for key in ("cwe", "cwes", "CWE"):
            vals = props.get(key)
            for v in vals if isinstance(vals, list) else [vals] if vals else []:
                c = normalise_cwe(v)
                if c:
                    out.add(c)
        for rel in o.get("relationships") or []:
            tgt = (rel.get("target") or {}).get("id", "")
            c = normalise_cwe(tgt)
            if c:
                out.add(c)
    return sorted(out)


def _severity(result: dict, rule: dict) -> str:
    for o in (result, rule):
        props = (o or {}).get("properties") or {}
        sec = props.get("security-severity")
        if sec is not None:
            try:
                return severity_from_cvss(float(sec))
            except (TypeError, ValueError):
                pass
        for key in ("severity", "problem.severity"):
            if props.get(key):
                return normalise_severity(props[key])
    level = result.get("level") or ((rule or {}).get("defaultConfiguration") or {}).get("level") or "warning"
    return LEVEL_TO_SEVERITY.get(level, "medium")


def _rule_index(run: dict) -> dict[str, dict]:
    rules: dict[str, dict] = {}
    driver = ((run.get("tool") or {}).get("driver")) or {}
    for comp in [driver, *((run.get("tool") or {}).get("extensions") or [])]:
        for r in comp.get("rules") or []:
            if r.get("id"):
                rules[r["id"]] = r
    return rules


def parse(doc: Any, kind: str = "sast") -> list[Finding]:
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise FormatError("not a SARIF document")
    findings: list[Finding] = []
    for run in doc["runs"]:
        tool = (((run.get("tool") or {}).get("driver")) or {}).get("name") or "sarif"
        scanner = re.sub(r"[^a-z0-9]+", "-", tool.lower()).strip("-") or "sarif"
        rules = _rule_index(run)
        driver_rules = (((run.get("tool") or {}).get("driver")) or {}).get("rules") or []
        revision = ""
        for vcp in run.get("versionControlProvenance") or []:
            revision = vcp.get("revisionId") or revision
        for res in run.get("results") or []:
            if res.get("suppressions"):
                continue  # already dispositioned upstream
            rule_id = res.get("ruleId") or ""
            rule = rules.get(rule_id) or {}
            if not rule and isinstance(res.get("ruleIndex"), int) and res["ruleIndex"] < len(driver_rules):
                rule = driver_rules[res["ruleIndex"]]
                rule_id = rule_id or rule.get("id", "")
            locs = res.get("locations") or [{}]
            phys = (locs[0] or {}).get("physicalLocation") or {}
            region = phys.get("region") or {}
            uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
            start = int(region.get("startLine") or 0)
            end = int(region.get("endLine") or start)
            snippet = ((region.get("snippet") or {}).get("text")) or ""
            message = ((res.get("message") or {}).get("text")) or ""
            title = (
                ((rule.get("shortDescription") or {}).get("text"))
                or rule.get("name")
                or message.split("\n")[0][:120]
            )
            flow: list[str] = []
            for cf in res.get("codeFlows") or []:
                for tf in cf.get("threadFlows") or []:
                    for step in tf.get("locations") or []:
                        pl = ((step.get("location") or {}).get("physicalLocation")) or {}
                        f = ((pl.get("artifactLocation") or {}).get("uri")) or "?"
                        ln = ((pl.get("region") or {}).get("startLine")) or 0
                        txt = (((step.get("location") or {}).get("message") or {}).get("text")) or ""
                        flow.append(f"{txt} ({f}:{ln})".strip())
                break
            props = {"report_revision": revision} if revision else {}
            if kind == "sca":
                p = res.get("properties") or {}
                cves = sorted({m.upper() for m in CVE_RE.findall(" ".join([rule_id, message, title]))})
                pkg = Package(
                    ecosystem=str(p.get("ecosystem") or p.get("packageManager") or ""),
                    name=str(p.get("packageName") or p.get("package") or ""),
                    version=str(p.get("packageVersion") or p.get("version") or ""),
                    fixed_versions=[str(v) for v in p.get("fixedVersions") or p.get("fixedIn") or []],
                    manifest=uri,
                )
                findings.append(Finding(
                    kind="sca", source=f"report:{scanner}", rule_id=rule_id, title=title, message=message,
                    severity=_severity(res, rule), cwe=_cwes(res, rule), cve=cves,
                    location=Location(file=uri, start_line=start, end_line=end, snippet=snippet),
                    package=pkg, properties=props,
                ))
                continue
            findings.append(Finding(
                kind="sast", source=f"report:{scanner}", rule_id=rule_id, title=title, message=message,
                severity=_severity(res, rule), cwe=_cwes(res, rule),
                location=Location(file=uri, start_line=start, end_line=end, snippet=snippet),
                path=flow, properties=props,
            ))
    return findings
