"""OSV-Scanner JSON adapter (``osv-scanner --format json``), plus helpers that turn
OSV vulnerability records into findings (shared with the OSV API client)."""

from __future__ import annotations

import re
from typing import Any

from fixpoint.model import Finding, FormatError, Location, Package, normalise_severity, severity_from_cvss

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def fixed_versions(vuln: dict, ecosystem: str, name: str) -> list[str]:
    out: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name", "").lower() != name.lower():
            continue
        if ecosystem and pkg.get("ecosystem", "").split(":")[0].lower() != ecosystem.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in out:
                    out.append(str(ev["fixed"]))
    return out


def vuln_severity(vuln: dict, group_max: str | None = None) -> str:
    if group_max:
        try:
            return severity_from_cvss(float(group_max))
        except (TypeError, ValueError):
            pass
    for key in ("database_specific", "ecosystem_specific"):
        sev = (vuln.get(key) or {}).get("severity")
        if sev:
            return normalise_severity(sev)
    for aff in vuln.get("affected") or []:
        sev = (aff.get("database_specific") or aff.get("ecosystem_specific") or {}).get("severity")
        if sev:
            return normalise_severity(sev)
    return "medium"


def vuln_cves(vuln: dict) -> list[str]:
    ids = [vuln.get("id", ""), *(vuln.get("aliases") or [])]
    return sorted({i.upper() for i in ids if CVE_RE.match(i or "")})


def vuln_cwes(vuln: dict) -> list[str]:
    return list((vuln.get("database_specific") or {}).get("cwe_ids") or [])


def to_finding(vuln: dict, ecosystem: str, name: str, version: str, manifest: str, source: str,
               group_max: str | None = None) -> Finding:
    cves = vuln_cves(vuln)
    return Finding(
        kind="sca",
        source=source,
        rule_id=str(vuln.get("id", "")),
        title=str(vuln.get("summary") or vuln.get("id") or ""),
        message=str(vuln.get("details") or vuln.get("summary") or "")[:2000],
        severity=vuln_severity(vuln, group_max),
        cwe=vuln_cwes(vuln),
        cve=cves,
        location=Location(file=manifest),
        package=Package(
            ecosystem=ecosystem, name=name, version=version,
            fixed_versions=fixed_versions(vuln, ecosystem, name), manifest=manifest,
        ),
        properties={"osv_ids": sorted({vuln.get("id", ""), *(vuln.get("aliases") or [])} - {""})},
    )


def parse(doc: Any, kind: str = "sca") -> list[Finding]:
    if kind != "sca":
        raise FormatError("osv reports only carry sca findings")
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        raise FormatError("not an osv-scanner JSON document")
    findings: list[Finding] = []
    for res in doc["results"]:
        manifest = ((res.get("source") or {}).get("path")) or ""
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            vulns = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            groups = p.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                ids = g.get("ids") or []
                primary = next((vulns[i] for i in ids if i in vulns), None)
                if primary is None:
                    continue
                # Merge aliases of every record in the group so all CVEs are captured.
                merged = dict(primary)
                aliases = set(primary.get("aliases") or [])
                for i in ids:
                    if i in vulns:
                        aliases |= {i, *(vulns[i].get("aliases") or [])}
                aliases |= set(g.get("aliases") or [])
                merged["aliases"] = sorted(aliases - {primary.get("id")})
                findings.append(to_finding(
                    merged, pkg.get("ecosystem", ""), pkg.get("name", ""), pkg.get("version", ""),
                    manifest, "report:osv-scanner", g.get("max_severity"),
                ))
    return findings
