"""Eval metrics. Pure functions over pipeline outputs + a case's expected.json.

discover_precision  matched discovered SAST findings / all discovered SAST findings
discover_recall     expected SAST flaws found / expected SAST flaws
fix_rate            groups whose patch passed both verify phases / planned groups
build_break_rate    patches whose install/build/test failed / patches that reached the build phase
false_fix_rate      patches that passed verify but whose oracle still matches (flaw still present)
                    / patches that passed verify
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from fixpoint import diffutil

SLACK = 3  # lines of tolerance around an expected range

LOWER_IS_BETTER = {"build_break_rate", "false_fix_rate"}


def _matches(finding: dict[str, Any], exp: dict[str, Any]) -> bool:
    loc = finding.get("location") or {}
    if loc.get("file") != exp["file"]:
        return False
    lo, hi = exp["lines"]
    line = int(loc.get("start_line") or 0)
    if not (lo - SLACK <= line <= hi + SLACK):
        return False
    want = set(exp.get("cwe") or [])
    return not want or bool(want & set(finding.get("cwe") or []))


@dataclass
class CaseCounts:
    discovered: int = 0
    true_pos: int = 0
    expected: int = 0
    found: int = 0
    planned: int = 0
    verified: int = 0
    reached_build: int = 0
    build_broken: int = 0
    false_fixes: int = 0
    sca_expected: int = 0
    sca_correct: int = 0
    notes: list[str] = field(default_factory=list)


def score_case(expected: dict[str, Any], findings: list[dict[str, Any]], plan: dict[str, Any],
               verdicts: list[dict[str, Any]], patches: dict[str, str], files: dict[str, str]) -> CaseCounts:
    """``patches``: group id -> patch text; ``files``: original repo files (path -> text)."""
    c = CaseCounts()
    sast = [f for f in findings if f["kind"] == "sast" and f.get("status") != "unlocatable"]
    c.discovered = len(sast)
    c.expected = len(expected.get("sast") or [])
    c.true_pos = sum(1 for f in sast if any(_matches(f, e) for e in expected.get("sast") or []))
    c.found = sum(1 for e in expected.get("sast") or [] if any(_matches(f, e) for f in sast))

    for exp in expected.get("sca") or []:
        c.sca_expected += 1
        hits = [f for f in findings if f["kind"] == "sca" and (f.get("package") or {}).get("name", "").lower()
                == exp["package"].lower() and (not exp.get("cve") or exp["cve"] in (f.get("cve") or []))]
        if exp.get("disposition") == "fix":
            ok = any(f.get("disposition") == "fix" for f in hits)
        else:
            # absent entirely is fine for not_reachable (e.g. no advisory at all), a fix is not
            ok = not any(f.get("disposition") == "fix" for f in hits)
        c.sca_correct += int(ok)
        if not ok:
            c.notes.append(f"sca {exp['package']}: expected {exp.get('disposition')}")

    groups = plan.get("groups") or []
    c.planned = len(groups)
    by_group: dict[str, dict[str, dict]] = {}
    for v in verdicts:
        by_group.setdefault(v["group_id"], {})[v["phase"]] = v
    for g in groups:
        vs = by_group.get(g["id"], {})
        if "build" in vs:
            steps = [ch for ch in vs["build"]["checks"] if ch["name"] in ("install", "build", "test")]
            if steps:
                c.reached_build += 1
                c.build_broken += int(not all(ch["passed"] for ch in steps))
        passed = all(vs.get(ph, {}).get("passed") for ph in ("rescan", "build")) and len(vs) == 2
        if not passed:
            continue
        c.verified += 1
        if _still_vulnerable(g, findings, expected, patches.get(g["id"], ""), files):
            c.false_fixes += 1
            c.notes.append(f"false fix: {g['id']}")
    return c


def _still_vulnerable(group: dict, findings: list[dict], expected: dict, patch: str, files: dict[str, str]) -> bool:
    if not patch:
        return True
    patched = dict(files)
    for fp in diffutil.parse(patch):
        new = diffutil.apply_file(patched.get(fp.path), fp)
        if new is None:
            patched.pop(fp.path, None)
        else:
            patched[fp.path] = new
    ids = set(group["finding_ids"])
    for f in (x for x in findings if x["id"] in ids):
        for exp in expected.get("sast") or []:
            oracle = exp.get("oracle")
            if oracle and _matches(f, exp) and re.search(oracle["absent_regex"], patched.get(oracle["file"], "")):
                return True
    return False


def aggregate(cases: list[CaseCounts]) -> dict[str, float]:
    def ratio(n: int, d: int, empty: float) -> float:
        return round(n / d, 4) if d else empty

    s = {k: sum(getattr(c, k) for c in cases) for k in CaseCounts.__dataclass_fields__ if k != "notes"}
    return {
        "discover_precision": ratio(s["true_pos"], s["discovered"], 1.0),
        "discover_recall": ratio(s["found"], s["expected"], 1.0),
        "fix_rate": ratio(s["verified"], s["planned"], 0.0),
        "build_break_rate": ratio(s["build_broken"], s["reached_build"], 0.0),
        "false_fix_rate": ratio(s["false_fixes"], s["verified"], 0.0),
        "sca_triage_accuracy": ratio(s["sca_correct"], s["sca_expected"], 1.0),
    }


def regressions(current: dict[str, float], baseline: dict[str, float], tolerance: float) -> list[str]:
    out = []
    for k, base in baseline.items():
        if k not in current:
            continue
        cur = current[k]
        worse = cur > base + tolerance if k in LOWER_IS_BETTER else cur < base - tolerance
        if worse:
            out.append(f"{k}: {cur} vs baseline {base} (tolerance {tolerance})")
    return out
