"""Snyk Open Source adapter (``snyk test --json``, single or --all-projects)."""

from __future__ import annotations

from typing import Any

from fixpoint.model import Finding, FormatError, Location, Package, normalise_severity

ECOSYSTEM = {
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "pip": "PyPI",
    "poetry": "PyPI",
    "pipenv": "PyPI",
    "maven": "Maven",
    "gradle": "Maven",
    "sbt": "Maven",
    "gomodules": "Go",
    "golangdep": "Go",
    "govendor": "Go",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "nuget": "NuGet",
    "paket": "NuGet",
    "cargo": "crates.io",
}


def parse(doc: Any, kind: str = "sca") -> list[Finding]:
    if kind != "sca":
        raise FormatError("snyk open-source reports only carry sca findings")
    projects = doc if isinstance(doc, list) else [doc]
    findings: list[Finding] = []
    for proj in projects:
        if not isinstance(proj, dict) or "vulnerabilities" not in proj:
            raise FormatError("not a snyk test --json document")
        manifest = proj.get("displayTargetFile") or proj.get("targetFile") or ""
        pm = str(proj.get("packageManager") or "").lower()
        for v in proj.get("vulnerabilities") or []:
            if v.get("type") == "license":
                continue
            ids = v.get("identifiers") or {}
            eco = ECOSYSTEM.get(str(v.get("packageManager") or pm).lower(), str(v.get("packageManager") or pm))
            name = v.get("packageName") or v.get("moduleName") or ""
            findings.append(Finding(
                kind="sca",
                source="report:snyk",
                rule_id=str(v.get("id") or ""),
                title=str(v.get("title") or ""),
                message=f"{name}@{v.get('version')} is vulnerable ({v.get('title')}). "
                        f"Introduced through: {' > '.join(v.get('from') or [])}",
                severity=normalise_severity(v.get("severity")),
                cwe=list(ids.get("CWE") or []),
                cve=list(ids.get("CVE") or []),
                location=Location(file=manifest),
                package=Package(
                    ecosystem=eco, name=name, version=str(v.get("version") or ""),
                    fixed_versions=[str(x) for x in v.get("fixedIn") or []], manifest=manifest,
                ),
                properties={"introduced_through": v.get("from") or [], "ghsa": ids.get("GHSA") or []},
            ))
    return findings
