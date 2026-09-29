"""Dedupe against GitHub, which is the only state store.

Every Fixpoint PR body carries ``<!-- fixpoint-findings: id1,id2 -->``.

* open PR against this branch           -> in_flight
* merged PR against this branch         -> fixed
* PR closed without merge (any branch)  -> rejected: a human said no, never re-raise
Precedence when several PRs cover one finding: in_flight > fixed > rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fixpoint import log
from fixpoint.model import Finding
from fixpoint.prbody import parse_finding_ids

LOG = log.get(__name__)
_RANK = {"in_flight": 0, "fixed": 1, "rejected": 2}


@dataclass
class PrIndex:
    state: dict[str, tuple[str, dict[str, Any]]] = field(default_factory=dict)  # id -> (status, pr summary)
    open_bot_prs: int = 0

    def status_of(self, finding_id: str) -> str | None:
        hit = self.state.get(finding_id)
        return hit[0] if hit else None


def build_index(prs: list[dict[str, Any]], branch: str) -> PrIndex:
    idx = PrIndex()
    for pr in prs:
        base = (pr.get("base") or {}).get("ref", "")
        if pr.get("state") == "open":
            status = "in_flight" if base == branch else None
            if base == branch:
                idx.open_bot_prs += 1
        elif pr.get("merged_at"):
            status = "fixed" if base == branch else None
        else:
            status = "rejected"
        if status is None:
            continue
        summary = {"number": pr.get("number"), "url": pr.get("html_url"), "base": base}
        for fid in parse_finding_ids(pr.get("body")):
            cur = idx.state.get(fid)
            if cur is None or _RANK[status] < _RANK[cur[0]]:
                idx.state[fid] = (status, summary)
    return idx


def apply(findings: list[Finding], idx: PrIndex) -> list[Finding]:
    counts: dict[str, int] = {}
    for f in findings:
        if f.status != "open":
            continue
        hit = idx.state.get(f.id)
        if hit:
            f.status = hit[0]
            f.properties["pr"] = hit[1]
            counts[f.status] = counts.get(f.status, 0) + 1
    LOG.info("dedupe: %s, open bot PRs on branch: %d", counts or "no matches", idx.open_bot_prs)
    return findings
