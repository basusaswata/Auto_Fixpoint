import json

from evals import metrics
from tests.conftest import ROOT


def fnd(i, file, line, cwe, disp="fix", kind="sast"):
    return {"id": i, "kind": kind, "cwe": [cwe], "disposition": disp, "status": "open",
            "location": {"file": file, "start_line": line}}


EXPECTED = {
    "sast": [{"cwe": ["CWE-89"], "file": "app.py", "lines": [10, 12],
              "oracle": {"file": "app.py", "absent_regex": "execute\\(f\""}},
             {"cwe": ["CWE-78"], "file": "app.py", "lines": [20, 22]}],
    "sca": [{"package": "pyyaml", "cve": "CVE-1", "disposition": "fix"},
            {"package": "requests", "disposition": "not_reachable"}],
}
FILES = {"app.py": "".join("x\n" for _ in range(11)) + 'cur.execute(f"SELECT {a}")\n'}
GOOD = ("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -12 +12 @@\n"
        '-cur.execute(f"SELECT {a}")\n+cur.execute("SELECT ?", (a,))\n')
NOOP = ("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -11,2 +11,2 @@\n x\n"
        '-cur.execute(f"SELECT {a}")\n+cur.execute(f"SELECT {a}")  # safe\n')


def verdicts(gid, rescan=True, build=True, steps=True):
    b = [{"name": "test", "passed": build, "detail": ""}] if steps else []
    return [{"group_id": gid, "phase": "rescan", "passed": rescan, "checks": []},
            {"group_id": gid, "phase": "build", "passed": build, "checks": b}]


def test_precision_recall_and_fix_metrics():
    findings = [fnd("a", "app.py", 11, "CWE-89"), fnd("b", "app.py", 40, "CWE-79"),
                {"id": "s1", "kind": "sca", "cve": ["CVE-1"], "disposition": "fix", "package": {"name": "PyYAML"}},
                {"id": "s2", "kind": "sca", "cve": ["CVE-2"], "disposition": "not_reachable",
                 "package": {"name": "requests"}}]
    plan = {"groups": [{"id": "g1", "finding_ids": ["a"]}, {"id": "g2", "finding_ids": ["b"]}]}
    c = metrics.score_case(EXPECTED, findings, plan, verdicts("g1") + verdicts("g2", build=False),
                           {"g1": GOOD}, FILES)
    m = metrics.aggregate([c])
    assert m["discover_precision"] == 0.5 and m["discover_recall"] == 0.5
    assert m["fix_rate"] == 0.5 and m["build_break_rate"] == 0.5 and m["false_fix_rate"] == 0.0
    assert m["sca_triage_accuracy"] == 1.0


def test_false_fix_detected_by_oracle():
    findings = [fnd("a", "app.py", 12, "CWE-89")]
    plan = {"groups": [{"id": "g1", "finding_ids": ["a"]}]}
    c = metrics.score_case(EXPECTED, findings, plan, verdicts("g1"), {"g1": NOOP}, FILES)
    assert c.false_fixes == 1 and metrics.aggregate([c])["false_fix_rate"] == 1.0


def test_regressions():
    base = {"discover_recall": 0.8, "false_fix_rate": 0.1}
    assert metrics.regressions({"discover_recall": 0.78, "false_fix_rate": 0.12}, base, 0.05) == []
    r = metrics.regressions({"discover_recall": 0.6, "false_fix_rate": 0.3}, base, 0.05)
    assert len(r) == 2


def test_seeded_cases_are_well_formed():
    cases = sorted((ROOT / "evals" / "cases").iterdir())
    assert len(cases) >= 3
    for case in cases:
        exp = json.loads((case / "expected.json").read_text())
        for e in exp["sast"]:
            text = (case / "repo" / e["file"]).read_text().splitlines()
            lo, hi = e["lines"]
            assert 1 <= lo <= hi <= len(text), case.name
            if e.get("oracle"):
                import re
                assert re.search(e["oracle"]["absent_regex"], (case / "repo" / e["oracle"]["file"]).read_text()), \
                    f"{case.name}: oracle must match the vulnerable code"
