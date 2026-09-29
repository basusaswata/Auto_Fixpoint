"""Deterministic vulnerability lookup against the OSV API (api.osv.dev).

Used to confirm dependencies inventoried by the SCA skill and to re-scan an
upgraded version in verify. The model never supplies CVE ids or fixed versions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from fixpoint import log
from fixpoint.adapters import osv as osv_adapter
from fixpoint.model import Finding

LOG = log.get(__name__)


class OsvError(RuntimeError):
    pass


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest: str


class OsvClient:
    def __init__(self, base: str = "https://api.osv.dev", session: Any = None, timeout: int = 30) -> None:
        if not base.startswith("https://"):
            raise OsvError("OSV API must be https")
        self.base = base.rstrip("/")
        self.http = session or requests.Session()
        self.timeout = timeout

    def _post(self, path: str, body: dict) -> dict:
        r = self.http.post(f"{self.base}{path}", json=body, timeout=self.timeout)
        if r.status_code != 200:
            raise OsvError(f"OSV {path} HTTP {r.status_code}")
        return r.json()

    def _get(self, path: str) -> dict:
        r = self.http.get(f"{self.base}{path}", timeout=self.timeout)
        if r.status_code != 200:
            raise OsvError(f"OSV {path} HTTP {r.status_code}")
        return r.json()

    def vuln_ids(self, deps: list[Dependency]) -> list[list[str]]:
        """querybatch: ids of vulns affecting each dependency (same order)."""
        out: list[list[str]] = []
        for i in range(0, len(deps), 500):
            chunk = deps[i : i + 500]
            body = {"queries": [
                {"package": {"ecosystem": d.ecosystem, "name": d.name}, "version": d.version} for d in chunk
            ]}
            res = self._post("/v1/querybatch", body).get("results") or []
            if len(res) != len(chunk):
                raise OsvError("OSV querybatch returned a mismatched result count")
            for r in res:
                ids = [v["id"] for v in r.get("vulns") or []]
                if r.get("next_page_token"):
                    LOG.warning("OSV result paginated; some advisories may be missing")
                out.append(ids)
        return out

    def vuln(self, vid: str) -> dict:
        return self._get(f"/v1/vulns/{requests.utils.quote(vid, safe='')}")

    def findings_for(self, deps: list[Dependency], source: str) -> list[Finding]:
        findings: list[Finding] = []
        cache: dict[str, dict] = {}
        for dep, ids in zip(deps, self.vuln_ids(deps), strict=True):
            for vid in ids:
                if vid not in cache:
                    cache[vid] = self.vuln(vid)
                rec = cache[vid]
                f = osv_adapter.to_finding(rec, dep.ecosystem, dep.name, dep.version, dep.manifest, source)
                f.properties["osv_confirmed"] = True
                findings.append(f)
        return findings

    def vulns_at(self, dep: Dependency) -> set[str]:
        """All ids + aliases of vulns affecting dep (used by verify re-scan)."""
        ids = self.vuln_ids([dep])[0]
        out: set[str] = set()
        for vid in ids:
            rec = self.vuln(vid)
            out |= {rec.get("id", vid), *(rec.get("aliases") or [])}
        return {x.upper() for x in out}
