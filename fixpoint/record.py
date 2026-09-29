"""Reconcile: record outcomes of recently closed Fixpoint PRs.

merged -> outcome "merged"; closed unmerged -> "rejected" with a reason from a
``fixpoint-reason/<reason>`` label, else the last human comment. Rejected cases
are exported as eval cases so skill upgrades are tested against them.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

import requests

from fixpoint import log, prbody
from fixpoint.gh import GitHub

LOG = log.get(__name__)


def _parse_time(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def reason_for(pr: dict[str, Any], comments: list[dict[str, Any]], label_prefix: str) -> tuple[str, str]:
    for lab in pr.get("labels") or []:
        name = lab.get("name", "")
        if name.startswith(label_prefix):
            return name[len(label_prefix):], "label"
    humans = [c for c in comments if (c.get("user") or {}).get("type") != "Bot"]
    if humans:
        text = re.sub(r"\s+", " ", humans[-1].get("body") or "").strip()
        return text[:500], "comment"
    return "unspecified", "none"


def outcomes(gh: GitHub, repo: str, since_days: int, label_prefix: str) -> list[dict[str, Any]]:
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=since_days)
    out = []
    for pr in gh.fixpoint_prs(repo, state="closed"):
        closed = _parse_time(pr.get("closed_at"))
        if closed is None or closed < since:
            continue
        meta = prbody.parse_meta(pr.get("body"))
        rec: dict[str, Any] = {
            "repo": repo, "number": pr["number"], "url": pr.get("html_url"), "base": (pr.get("base") or {}).get("ref"),
            "closed_at": pr.get("closed_at"), "finding_ids": prbody.parse_finding_ids(pr.get("body")),
            "group_id": meta.get("group_id"), "kind": meta.get("kind"), "skill_version": meta.get("skill_version"),
            "model": meta.get("model"), "outcome": "merged" if pr.get("merged_at") else "rejected",
        }
        if rec["outcome"] == "rejected":
            rec["reason"], rec["reason_source"] = reason_for(pr, gh.issue_comments(repo, pr["number"]), label_prefix)
        out.append(rec)
    return out


def eval_cases(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "case_id": f"{r['repo'].replace('/', '__')}-{r['number']}",
        "repo": r["repo"], "base": r["base"], "pr": r["url"], "finding_ids": r["finding_ids"],
        "group_id": r["group_id"], "kind": r["kind"], "skill_version": r["skill_version"],
        "expected": "no_pr", "reason": r.get("reason", ""),
    } for r in records if r["outcome"] == "rejected"]


def post_metrics(url: str, token: str | None, payload: dict[str, Any]) -> None:
    if not url.startswith("https://"):
        raise ValueError("metrics endpoint must be https")
    headers = {"Content-Type": "application/json"}
    if token:
        log.register_secret(token)
        headers["Authorization"] = f"Bearer {token}"
    r = requests.post(url, json=payload, headers=headers, timeout=30)
    if r.status_code >= 300:
        LOG.warning("metrics POST returned %s", r.status_code)
