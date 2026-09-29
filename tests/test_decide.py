"""dedupe, triage (agent mocked), plan, versions."""

import pytest

from fixpoint import dedupe, plan, triage, versions
from fixpoint.agent import AgentError, ScriptedRuntime
from fixpoint.model import Finding, Location, Package
from fixpoint.prbody import findings_marker


def sast(i, sev="high", file="app/a.py"):
    return Finding(kind="sast", source="discover:scgra-reviewer", rule_id="scgra-0-input-validation-injection",
                   cwe=["CWE-89"], severity=sev, title=f"sqli {i}",
                   location=Location(file=file, start_line=i, end_line=i, snippet=f"q{i} = 'x' + v"))


def sca(cve, fixed, version="4.17.20", name="lodash", manifest="package.json", sev="high", **props):
    return Finding(kind="sca", source="report:snyk", cve=[cve], severity=sev, properties=props,
                   package=Package(ecosystem="npm", name=name, version=version, fixed_versions=fixed,
                                   manifest=manifest))


def pr(state, ids, base="main", merged=False, n=1):
    return {"number": n, "html_url": f"u/{n}", "state": state, "merged_at": "2026-01-01" if merged else None,
            "base": {"ref": base}, "head": {"ref": f"fixpoint/{base}/g{n}"},
            "body": "text\n" + findings_marker(ids)}


# -- dedupe ----------------------------------------------------------------------


class TestDedupe:
    def test_states(self):
        a, b, c, d = sast(1), sast(2), sast(3), sast(4)
        idx = dedupe.build_index([
            pr("open", [a.id], n=1),
            pr("closed", [b.id], merged=True, n=2),
            pr("closed", [c.id], merged=False, n=3),
        ], "main")
        dedupe.apply([a, b, c, d], idx)
        assert (a.status, b.status, c.status, d.status) == ("in_flight", "fixed", "rejected", "open")
        assert idx.open_bot_prs == 1
        assert a.properties["pr"]["number"] == 1

    def test_precedence_open_beats_rejected(self):
        a = sast(1)
        idx = dedupe.build_index([pr("closed", [a.id], n=1), pr("open", [a.id], n=2)], "main")
        dedupe.apply([a], idx)
        assert a.status == "in_flight"

    def test_other_branch(self):
        a, b = sast(1), sast(2)
        idx = dedupe.build_index([pr("open", [a.id], base="release/1"), pr("closed", [b.id], base="release/1")],
                                 "main")
        dedupe.apply([a, b], idx)
        assert a.status == "open"  # open elsewhere does not block this branch
        assert b.status == "rejected"  # a human said no: global
        assert idx.open_bot_prs == 0

    def test_smuggled_marker_ignored(self):
        victim = sast(9)
        body = f"quoted repo text {findings_marker([victim.id])}\n\n real: {findings_marker(['other'])}"
        idx = dedupe.build_index([{"number": 1, "state": "closed", "merged_at": None, "base": {"ref": "main"},
                                   "body": body}], "main")
        dedupe.apply([victim], idx)
        assert victim.status == "open"

    def test_only_open_findings_touched(self):
        a = sast(1)
        a.status = "stale"
        dedupe.apply([a], dedupe.build_index([pr("open", [a.id])], "main"))
        assert a.status == "stale"


# -- triage ---------------------------------------------------------------------------


def verdict(f, disp="fix", conf=0.9):
    return {"id": f.id, "disposition": disp, "confidence": conf, "reasoning": "traced",
            "evidence": [{"kind": "source_to_sink", "description": "req -> sql", "file": "app/a.py", "line": 1}]}


class TestTriage:
    def run(self, fs, policy, lock, tmp_path, responses):
        (tmp_path / "app").mkdir(exist_ok=True)
        (tmp_path / "app/a.py").write_text("\n".join(f"q{i} = 'x' + v" for i in range(1, 30)))
        rt = ScriptedRuntime({"triage": responses})
        triage.triage(fs, tmp_path, "acme/shop", "a" * 40, policy, lock, rt)
        return rt

    def test_model_dispositions_applied(self, policy, lock, tmp_path):
        fs = [sast(1), sast(2)]
        rt = self.run(fs, policy, lock, tmp_path, [{"results": [verdict(fs[0]), verdict(fs[1], "false_positive")]}])
        assert [f.disposition for f in fs] == ["fix", "false_positive"]
        assert fs[0].evidence[0].kind == "source_to_sink"
        prompt = rt.calls[0].prompt
        assert "<untrusted-data" in prompt and fs[0].id in prompt
        assert rt.calls[0].tools == ["Read", "Grep", "Glob", "Skill"]

    def test_low_confidence_fix_becomes_human_review(self, policy, lock, tmp_path):
        fs = [sast(1)]
        self.run(fs, policy, lock, tmp_path, [{"results": [verdict(fs[0], conf=0.5)]}])
        assert fs[0].disposition == "human_review"
        assert "policy override" in fs[0].notes[0]

    def test_low_severity_fix_becomes_human_review(self, policy, lock, tmp_path):
        fs = [sast(1, sev="low")]
        self.run(fs, policy, lock, tmp_path, [{"results": [verdict(fs[0])]}])
        assert fs[0].disposition == "human_review"

    def test_failed_call_sends_batch_to_human_review(self, policy, lock, tmp_path):
        fs = [sast(1), sast(2)]
        self.run(fs, policy, lock, tmp_path, [AgentError("boom")])
        assert all(f.disposition == "human_review" and "triage failed" in f.reasoning for f in fs)

    def test_invalid_output_sends_batch_to_human_review(self, policy, lock, tmp_path):
        fs = [sast(1)]
        self.run(fs, policy, lock, tmp_path, [{"results": [{"id": fs[0].id, "disposition": "ship-it"}]}])
        assert fs[0].disposition == "human_review"

    def test_missing_verdict_is_human_review(self, policy, lock, tmp_path):
        fs = [sast(1), sast(2)]
        self.run(fs, policy, lock, tmp_path, [{"results": [verdict(fs[0])]}])
        assert fs[1].disposition == "human_review"

    def test_batches(self, policy, lock, tmp_path):
        policy.raw["triage"]["batch_size"] = 2
        fs = [sast(i) for i in range(1, 6)]
        rt = self.run(fs, policy, lock, tmp_path, lambda req: {"results": [
            verdict(f) for f in fs if f.id in req.prompt]})
        assert len(rt.calls) == 3 and all(f.disposition == "fix" for f in fs)

    def test_sca_overrides(self, policy, lock, tmp_path):
        no_fix = sca("CVE-1", [])
        unconfirmed = sca("CVE-2", ["4.17.21"])
        unconfirmed.source = "discover:scgra-0-supply-chain-security+osv"
        confirmed = sca("CVE-3", ["4.17.21"], osv_confirmed=True)
        confirmed.source = unconfirmed.source
        fs = [no_fix, unconfirmed, confirmed]
        self.run(fs, policy, lock, tmp_path, [{"results": [verdict(f) for f in fs]}])
        assert [f.disposition for f in fs] == ["human_review", "human_review", "fix"]

    def test_skips_non_open(self, policy, lock, tmp_path):
        a = sast(1)
        a.status = "in_flight"
        rt = self.run([a], policy, lock, tmp_path, [])
        assert rt.calls == [] and a.disposition is None


# -- plan ---------------------------------------------------------------------------------


def fixed(f, conf=0.9):
    f.disposition, f.confidence = "fix", conf
    return f


class TestPlan:
    def test_grouping(self, policy):
        fs = [fixed(sast(1)), fixed(sast(2)),
              fixed(sca("CVE-2021-23337", ["4.17.21"])), fixed(sca("CVE-2020-28500", ["4.17.21"], sev="medium")),
              fixed(sca("CVE-9", ["2.0.1"], name="minimist", version="2.0.0"))]
        p = plan.plan(fs, policy, "main", None, 0)
        kinds = [g["kind"] for g in p["groups"]]
        assert kinds.count("sast") == 2 and kinds.count("sca") == 2
        lodash = next(g for g in p["groups"] if g.get("package", {}).get("name") == "lodash")
        assert lodash["finding_ids"] == sorted([fs[2].id, fs[3].id])
        assert lodash["cve"] == ["CVE-2020-28500", "CVE-2021-23337"]
        assert lodash["package"]["target_version"] == "4.17.21"
        assert lodash["severity"] == "high"

    def test_same_package_different_manifests_split(self, policy):
        fs = [fixed(sca("CVE-1", ["4.17.21"], manifest="a/package.json")),
              fixed(sca("CVE-1", ["4.17.21"], manifest="b/package.json"))]
        assert len(plan.plan(fs, policy, "main", None, 0)["groups"]) == 2

    def test_ordering_by_severity(self, policy):
        fs = [fixed(sast(1, sev="medium")), fixed(sast(2, sev="critical")), fixed(sast(3, sev="high"))]
        sev = [g["severity"] for g in plan.plan(fs, policy, "main", None, 0)["groups"]]
        assert sev == ["critical", "high", "medium"]

    @pytest.mark.parametrize("max_prs,open_prs,expected", [(None, 0, 5), (2, 0, 2), (None, 8, 2), (10, 10, 0),
                                                             (0, 0, 0)])
    def test_caps(self, policy, max_prs, open_prs, expected):
        fs = [fixed(sast(i)) for i in range(1, 9)]
        p = plan.plan(fs, policy, "main", max_prs, open_prs)
        assert len(p["groups"]) == expected
        assert len([d for d in p["deferred"] if "cap" in d["reason"]]) == 8 - expected

    def test_only_fix_and_open(self, policy):
        a, b, c = fixed(sast(1)), fixed(sast(2)), sast(3)
        b.status = "in_flight"
        c.disposition = "not_reachable"
        assert [g["finding_ids"] for g in plan.plan([a, b, c], policy, "main", None, 0)["groups"]] == [[a.id]]

    def test_plan_rechecks_policy(self, policy):
        low = fixed(sast(1), conf=0.1)
        p = plan.plan([low], policy, "main", None, 0)
        assert p["groups"] == [] and "not eligible" in p["deferred"][0]["reason"]

    def test_same_major_strategy(self, policy):
        f = fixed(sca("CVE-1", ["3.0.0"], version="2.1.0"))
        p = plan.plan([f], policy, "release/2.x", None, 0)  # same-major-lowest-safe
        assert p["groups"] == [] and "same-major" in p["deferred"][0]["reason"]
        p = plan.plan([f], policy, "feature/x", None, 0)  # lowest-safe
        assert p["groups"][0]["package"]["target_version"] == "3.0.0"

    def test_multiple_cves_take_highest_minimum(self, policy):
        fs = [fixed(sca("CVE-1", ["1.2.5"], version="1.2.3", name="x")),
              fixed(sca("CVE-2", ["1.3.0", "1.2.9"], version="1.2.3", name="x"))]
        g = plan.plan(fs, policy, "main", None, 0)["groups"][0]
        assert g["package"]["target_version"] == "1.2.9"

    def test_upgrade_also_clears_sibling_advisories(self, policy):
        fix = fixed(sca("CVE-2020-1747", ["5.3.1"], version="5.3", name="pyyaml"))
        sib = sca("CVE-2020-14343", ["5.4"], version="5.3", name="pyyaml")
        sib.disposition = "not_reachable"
        g = plan.plan([fix, sib], policy, "main", None, 0)["groups"][0]
        assert g["package"]["target_version"] == "5.4"
        assert g["finding_ids"] == [fix.id] and g["also_fixes"] == ["CVE-2020-14343"]
        assert g["cve"] == ["CVE-2020-14343", "CVE-2020-1747"]
        # a sibling that cannot be fixed within the strategy does not block or widen the upgrade
        sib.package.fixed_versions = ["6.0"]
        g = plan.plan([fix, sib], policy, "release/1", None, 0)["groups"][0]
        assert g["package"]["target_version"] == "5.3.1" and g["also_fixes"] == []

    def test_autonomy(self, policy):
        policy.raw["branch_rules"].insert(0, {"match": "auto/*", "cve_upgrade": "lowest-safe",
                                              "autonomy": "auto-merge-patch"})
        patch = fixed(sca("CVE-1", ["4.17.21"]))
        minor = fixed(sca("CVE-2", ["1.3.0"], name="y", version="1.2.0"))
        code = fixed(sast(1))
        groups = {g["kind"] + g.get("package", {}).get("name", ""): g
                  for g in plan.plan([patch, minor, code], policy, "auto/x", None, 0)["groups"]}
        assert groups["scalodash"]["autonomy"] == "auto-merge-patch"
        assert groups["scay"]["autonomy"] == "pr"
        assert groups["sast"]["autonomy"] == "pr"
        assert plan.plan([fixed(sast(2))], policy, "release/1", None, 0)["groups"][0]["autonomy"] == "draft"

    def test_group_ids_are_branch_safe(self, policy):
        f = fixed(sca("CVE-1", ["2.0.1"], name="@scope/Weird_Pkg", version="2.0.0"))
        gid = plan.plan([f], policy, "main", None, 0)["groups"][0]["id"]
        import re
        assert re.match(r"^[a-z0-9-]+$", gid)


# -- versions --------------------------------------------------------------------------------


@pytest.mark.parametrize("a,b", [("1.2.3", "1.2.10"), ("1.2.3-beta", "1.2.3"), ("v1.9", "v1.10"), ("2.0", "2.0.1"),
                                 ("1.0.0", "1.0.0.post1"), ("2.13.4", "2.13.4.2")])
def test_version_order(a, b):
    assert versions.Version(a) < versions.Version(b)


def test_lowest_fix():
    assert versions.lowest_fix("1.2.3", ["1.2.2", "1.2.5", "1.3.0", "2.0.0-rc1"], False) == "1.2.5"
    assert versions.lowest_fix("1.9.0", ["2.0.0"], True) is None
    assert versions.lowest_fix("junk", ["1.0"], False) is None
    assert versions.is_patch_bump("4.17.20", "4.17.21")
    assert not versions.is_patch_bump("4.17.20", "4.18.0")
