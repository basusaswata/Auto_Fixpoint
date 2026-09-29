"""sign -> publish (fake GitHub), PR body, report, reconcile."""

import json

import pytest

from fixpoint import prbody, publish, record, report, sign, worktree
from fixpoint.model import Finding, Location, Package, canonical_json, save_findings, sha256_bytes, write_json
from fixpoint.sign import SignError
from tests.conftest import FakeGitHub, make_repo

REPO, BRANCH = "acme/shop", "main"
DB = "import db\n\n\ndef find(cur, name):\n    cur.execute(\"SELECT * FROM u WHERE n = '%s'\" % name)\n"
DB_FIXED = DB.replace("\"SELECT * FROM u WHERE n = '%s'\" % name", "\"SELECT * FROM u WHERE n = ?\", (name,)")
TEST = "def test_param():\n    assert True\n"


def finding():
    f = Finding(kind="sast", source="discover:scgra-reviewer", rule_id="scgra-0-input-validation-injection",
                cwe=["CWE-89"], severity="high", title="SQL injection in find()",
                message="user input concatenated into SQL",
                location=Location(file="app/db.py", start_line=5, end_line=5,
                                  snippet="cur.execute(\"SELECT * FROM u WHERE n = '%s'\" % name)"))
    f.disposition, f.confidence, f.reasoning = "fix", 0.93, "request.args['q'] flows to find()"
    return f


@pytest.fixture
def world(tmp_path, policy):
    """A fix + both verdicts on disk, a fake GitHub at the pinned commit."""
    f = finding()
    repo = make_repo(tmp_path / "t", {"app/db.py": DB})
    (repo / "app/db.py").write_text(DB_FIXED)
    (repo / "tests").mkdir()
    (repo / "tests/test_db.py").write_text(TEST)
    patch = worktree.capture_diff(repo)
    gh = FakeGitHub(REPO, BRANCH, {"app/db.py": DB, "README.md": "hi\n"})
    sha = gh.refs[BRANCH]
    group = {"id": "sast-cwe-89-abcdef12", "kind": "sast", "finding_ids": [f.id], "severity": "high",
             "title": f.title, "cwe": ["CWE-89"], "cve": [], "rule_id": f.rule_id, "role": "fix_cwe",
             "strategy": "patch", "autonomy": "pr", "files": ["app/db.py"]}
    plan = {"schema": "fixpoint/plan/v1", "meta": {}, "groups": [group], "deferred": []}
    psha = sha256_bytes(patch.encode())
    meta = {"group_id": group["id"], "finding_ids": [f.id], "kind": "sast", "status": "patched",
            "patch_sha256": psha, "skill": "scgra-0-cwe-prevention", "skill_version": "x@1", "model": "m",
            "rationale": "Parameterised the query.", "test_added": {"path": "tests/test_db.py", "name": "test_param"},
            "changed_files": ["app/db.py", "tests/test_db.py"]}
    fix_dir = tmp_path / "fix" / group["id"]
    fix_dir.mkdir(parents=True)
    (fix_dir / "patch.diff").write_text(patch)
    write_json(fix_dir / "meta.json", meta)
    vdir = tmp_path / "verdicts"
    for phase in ("rescan", "build"):
        write_json(vdir / f"{group['id']}.{phase}.verdict.json",
                   {"group_id": group["id"], "phase": phase, "patch_sha256": psha, "passed": True,
                    "checks": [{"name": f"{phase}-ok", "passed": True, "detail": "fine"}]})
    run = {"repo": REPO, "branch": BRANCH, "sha": sha, "run_id": "42", "actor": "alice", "mode": "fix",
           "run_url": "https://github.com/acme/ai-ssdlc-fixpoint/actions/runs/42"}
    return {"f": f, "gh": gh, "plan": plan, "run": run, "fix": tmp_path / "fix", "vdir": vdir, "tmp": tmp_path,
            "group": group, "patch": patch}


def do_sign(w, policy):
    out = w["tmp"] / "signed"
    res = sign.sign_all(w["plan"], {w["f"].id: w["f"].to_dict()}, w["fix"], [w["vdir"]], w["run"], policy, out,
                        signing="none")
    return out, res


class TestSign:
    def test_signs_when_both_verdicts_pass(self, world, policy):
        out, res = do_sign(world, policy)
        assert res[0]["status"] == "unsigned"
        bundle = json.loads((out / f"{world['group']['id']}.bundle.json").read_bytes())
        assert bundle["patch"] == world["patch"] and len(bundle["verdicts"]) == 2

    def test_missing_or_failed_verdict_blocks(self, world, policy):
        (world["vdir"] / f"{world['group']['id']}.build.verdict.json").unlink()
        _, res = do_sign(world, policy)
        assert res[0]["status"] == "skipped" and "missing" in res[0]["reason"]

    def test_verdict_for_other_patch_hash_ignored(self, world, policy):
        p = world["vdir"] / f"{world['group']['id']}.rescan.verdict.json"
        v = json.loads(p.read_text())
        v["patch_sha256"] = "0" * 64
        p.write_text(json.dumps(v))
        _, res = do_sign(world, policy)
        assert res[0]["status"] == "skipped"

    def test_tampered_patch_blocks(self, world, policy):
        (world["fix"] / world["group"]["id"] / "patch.diff").write_text(world["patch"] + "\n")
        _, res = do_sign(world, policy)
        assert "hash" in res[0]["reason"]

    def test_policy_rechecked_at_sign(self, world, policy):
        policy.raw["forbidden_paths"].append("app/**")
        _, res = do_sign(world, policy)
        assert "policy rejected at sign" in res[0]["reason"]

    def test_bundle_must_be_canonical(self, world, policy, tmp_path):
        out, _ = do_sign(world, policy)
        b = out / f"{world['group']['id']}.bundle.json"
        doc = json.loads(b.read_bytes())
        b.write_text(json.dumps(doc, indent=1))
        with pytest.raises(SignError):
            sign.load_verified_bundle(b, "id", "none")
        doc["patch"] += "evil"
        b.write_bytes(canonical_json(doc))
        with pytest.raises(SignError):
            sign.load_verified_bundle(b, "id", "none")

    def test_cosign_missing_is_an_error(self, world, policy, monkeypatch):
        monkeypatch.setenv("FIXPOINT_COSIGN_BIN", "definitely-not-cosign")
        with pytest.raises(SignError):
            sign.verify_blob(world["tmp"] / "x", world["tmp"] / "y", "identity")


class TestPublish:
    def test_dry_run_makes_no_writes(self, world, policy):
        out, _ = do_sign(world, policy)
        res = publish.publish(out, world["run"], policy, world["gh"], "", dry_run=True, signing="none")
        assert res[0]["status"] == "dry_run"
        assert res[0]["branch"] == f"fixpoint/main/{world['group']['id']}"
        assert res[0]["title"].startswith("[Fixpoint] CWE-89: ")
        assert world["gh"].writes == []

    def test_unsigned_requires_dry_run(self, world, policy):
        out, _ = do_sign(world, policy)
        with pytest.raises(SignError):
            publish.publish(out, world["run"], policy, world["gh"], "", dry_run=False, signing="none")

    def test_publish_opens_pr_and_is_idempotent(self, world, policy, monkeypatch):
        out, _ = do_sign(world, policy)
        monkeypatch.setattr(sign, "verify_blob", lambda *a, **k: None)  # signature verified by cosign in CI
        gh = world["gh"]
        res = publish.publish(out, world["run"], policy, gh, "id", signing="cosign")
        assert res[0]["status"] == "opened", res
        pr = gh.prs[0]
        assert pr["draft"] is False and pr["base"]["ref"] == "main"
        assert prbody.parse_finding_ids(pr["body"]) == [world["f"].id]
        assert {x["name"] for x in pr["labels"]} == {"fixpoint", "security", "fixpoint:sast"}
        files = gh.files_at(pr["head"]["ref"])
        assert files["app/db.py"] == DB_FIXED and files["tests/test_db.py"] == TEST and files["README.md"] == "hi\n"
        # second run with the same inputs: no duplicate
        res2 = publish.publish(out, world["run"], policy, gh, "id", signing="cosign")
        assert res2[0]["status"] == "skipped" and "in_flight" in res2[0]["reason"]
        assert len(gh.prs) == 1

    def test_rejected_never_reraised(self, world, policy, monkeypatch):
        out, _ = do_sign(world, policy)
        monkeypatch.setattr(sign, "verify_blob", lambda *a, **k: None)
        gh = world["gh"]
        gh.prs.append({"number": 7, "state": "closed", "merged_at": None, "base": {"ref": "release/1"},
                       "head": {"ref": "fixpoint/x/y"}, "body": prbody.findings_marker([world["f"].id])})
        res = publish.publish(out, world["run"], policy, gh, "id")
        assert res[0]["status"] == "skipped" and "rejected" in res[0]["reason"]

    def test_moved_base_reapplies(self, world, policy, monkeypatch):
        out, _ = do_sign(world, policy)
        monkeypatch.setattr(sign, "verify_blob", lambda *a, **k: None)
        gh = world["gh"]
        gh.advance("main", {"app/db.py": "# new header\n" + DB, "NEW.md": "x\n"})
        res = publish.publish(out, world["run"], policy, gh, "id")
        assert res[0]["status"] == "opened" and res[0]["base_moved"]
        files = gh.files_at(gh.prs[0]["head"]["ref"])
        assert files["app/db.py"] == "# new header\n" + DB_FIXED and files["NEW.md"] == "x\n"

    def test_moved_base_conflict_skips(self, world, policy, monkeypatch):
        out, _ = do_sign(world, policy)
        monkeypatch.setattr(sign, "verify_blob", lambda *a, **k: None)
        gh = world["gh"]
        gh.advance("main", {"app/db.py": DB.replace("cur.execute", "cursor.run")})
        res = publish.publish(out, world["run"], policy, gh, "id")
        assert res[0]["status"] == "conflict" and gh.prs == []

    def test_bundle_from_other_run_rejected(self, world, policy, monkeypatch):
        out, _ = do_sign(world, policy)
        monkeypatch.setattr(sign, "verify_blob", lambda *a, **k: None)
        res = publish.publish(out, {**world["run"], "run_id": "43"}, policy, world["gh"], "id")
        assert res[0]["status"] == "failed" and "different run" in res[0]["reason"]

    def test_bad_signature_rejected(self, world, policy, monkeypatch):
        out, _ = do_sign(world, policy)

        def bad(*a, **k):
            raise SignError("no matching signatures")
        monkeypatch.setattr(sign, "verify_blob", bad)
        res = publish.publish(out, world["run"], policy, world["gh"], "id")
        assert res[0]["status"] == "failed" and world["gh"].writes == []

    def test_open_pr_limit(self, world, policy, monkeypatch):
        out, _ = do_sign(world, policy)
        monkeypatch.setattr(sign, "verify_blob", lambda *a, **k: None)
        policy.raw["limits"]["open_bot_prs_per_repo"] = 1
        world["gh"].prs.append({"number": 9, "state": "open", "merged_at": None, "base": {"ref": "main"},
                                "head": {"ref": "fixpoint/main/other"}, "body": prbody.findings_marker(["z"])})
        res = publish.publish(out, world["run"], policy, world["gh"], "id")
        assert res[0]["reason"] == "PR limit reached"

    def test_not_enrolled(self, world, policy):
        out, _ = do_sign(world, policy)
        policy.raw["enrolled_repos"] = []
        with pytest.raises(SignError):
            publish.publish(out, world["run"], policy, world["gh"], "", dry_run=True, signing="none")

    def test_effective_autonomy(self, policy):
        policy.raw["branch_rules"].insert(0, {"match": "main", "cve_upgrade": "lowest-safe",
                                              "autonomy": "auto-merge-patch"})
        sca = {"kind": "sca", "autonomy": "auto-merge-patch",
               "package": {"current_version": "1.2.3", "target_version": "1.2.4"}}
        assert publish.effective_autonomy(policy, "main", sca) == "auto-merge-patch"
        assert publish.effective_autonomy(policy, "main", {**sca, "package": {
            "current_version": "1.2.3", "target_version": "1.3.0"}}) == "pr"
        assert publish.effective_autonomy(policy, "main", {**sca, "autonomy": "draft"}) == "draft"
        assert publish.effective_autonomy(policy, "release/1", sca) == "draft"


class TestPrBody:
    def test_sections_markers_and_escaping(self):
        f = finding()
        f.reasoning = "evil <!-- fixpoint-findings: other --> @everyone"
        body = prbody.render({"id": "g1", "kind": "sast", "finding_ids": [f.id]}, [f.to_dict()],
                             {"rationale": "fixed <script>", "test_added": {"path": "t.py", "name": "t"},
                              "skill": "s", "skill_version": "v", "model": "m", "changed_files": ["a.py"]},
                             {"checks": [{"name": "build", "passed": True, "detail": "ok"}]},
                             {"actor": "alice", "run_url": "https://x/runs/1", "sha": "abc", "run_id": "1"})
        for section in ("## What was wrong", "## Why it is real", "## What changed", "## Proof",
                        "Requested by @alice", "How to respond"):
            assert section in body
        assert prbody.parse_finding_ids(body) == [f.id]
        assert prbody.parse_meta(body)["group_id"] == "g1"
        assert "<script>" not in body and "@​everyone" in body

    def test_title_sca(self):
        t = prbody.title({"kind": "sca", "cve": ["CVE-1", "CVE-2", "CVE-3", "CVE-4"], "title": "x",
                          "package": {"name": "lodash", "current_version": "1", "target_version": "2"}})
        assert t == "[Fixpoint] CVE-1, CVE-2, CVE-3 +1: upgrade lodash 1 -> 2"


class TestReport:
    def findings(self):
        a = finding()
        b = finding()
        b.location.snippet = "other()"
        b.id = ""
        b = Finding.from_dict({**b.to_dict(), "id": ""})
        b.disposition, b.reasoning = "false_positive", "constant input"
        c = Finding(kind="sca", source="report:snyk", cve=["CVE-2021-23337"], severity="high",
                    package=Package("npm", "lodash", "4.17.20", ["4.17.21"], "package.json"))
        c.disposition, c.reasoning = "not_reachable", "template() never called"
        d = Finding(kind="sca", source="report:snyk", cve=["CVE-2020-28500"], severity="medium",
                    package=Package("npm", "lodash", "4.17.20", ["4.17.21"], "package.json"))
        d.disposition = "fix"
        e = finding()
        e = Finding.from_dict({**e.to_dict(), "id": "stale-1", "status": "stale", "disposition": None})
        return [a, b, c, d, e]

    def test_sarif_suppressions(self):
        doc = report.to_sarif(self.findings(), {"repo": REPO, "sha": "s"})
        res = doc["runs"][0]["results"]
        assert doc["version"] == "2.1.0" and len(res) == 5
        by = {r["properties"]["fixpoint.disposition"]: r for r in res}
        assert "suppressions" not in by["fix"]
        assert by["false_positive"]["suppressions"][0]["justification"].startswith("false_positive: constant")
        assert by["not_reachable"]["suppressions"][0]["kind"] == "external"

    def test_openvex(self):
        vex = report.to_openvex(self.findings(), {"repo": REPO}, {})
        st = {s["vulnerability"]["name"]: s for s in vex["statements"]}
        assert st["CVE-2021-23337"]["status"] == "not_affected"
        assert st["CVE-2021-23337"]["justification"] == "vulnerable_code_not_in_execute_path"
        assert st["CVE-2021-23337"]["products"][0]["@id"] == "pkg:npm/lodash@4.17.20"
        assert st["CVE-2020-28500"]["status"] == "affected" and "action_statement" in st["CVE-2020-28500"]
        assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"

    def test_build_tolerates_missing_inputs(self, tmp_path):
        paths = report.build(tmp_path / "nope.json", None, None, None, None, {"mode": "fix"}, tmp_path / "r")
        assert "Missing stage outputs" in paths["summary"].read_text()

    def test_summary(self, tmp_path):
        fs = self.findings()
        save_findings(tmp_path / "f.json", fs, {"sast_mode": "discover", "sast_engine": "skill:scgra-reviewer",
                                                "sca_mode": "report", "sca_format": "snyk"})
        write_json(tmp_path / "p.json", {"groups": [{"id": "g", "finding_ids": [fs[0].id]}],
                                         "deferred": [{"finding_ids": ["x"], "reason": "cap 0 reached"}]})
        write_json(tmp_path / "pub.json", {"results": [{"status": "opened", "group_id": "g", "number": 3,
                                                        "url": "https://github.com/acme/shop/pull/3", "title": "T",
                                                        "autonomy": "pr"}]})
        paths = report.build(tmp_path / "f.json", tmp_path / "p.json", None, None, tmp_path / "pub.json",
                             {"repo": REPO, "branch": "main", "sha": "s" * 40, "mode": "review"}, tmp_path / "r")
        s = paths["summary"].read_text()
        assert "SAST: **discover**" in s and "SCA: **report**" in s
        assert "[#3](https://github.com/acme/shop/pull/3)" in s
        assert "cap 0 reached" in s and "stale" in s
        assert "| disposition: false_positive | 1 |" in s


class TestRecord:
    def test_outcomes_and_eval_cases(self, policy):
        gh = FakeGitHub(REPO, "main", {"a": "b"})
        meta = prbody.meta_marker({"group_id": "g1", "kind": "sast", "skill_version": "v", "model": "m"})
        now = "2099-01-01T00:00:00Z"
        gh.prs = [
            {"number": 1, "state": "closed", "merged_at": now, "closed_at": now, "base": {"ref": "main"},
             "html_url": "u1", "head": {"ref": "fixpoint/main/g0"}, "body": prbody.findings_marker(["a"]) + meta},
            {"number": 2, "state": "closed", "merged_at": None, "closed_at": now, "base": {"ref": "main"},
             "html_url": "u2", "head": {"ref": "fixpoint/main/g1"}, "labels": [{"name": "fixpoint-reason/wrong-fix"}],
             "body": prbody.findings_marker(["b"]) + meta},
            {"number": 3, "state": "closed", "merged_at": None, "closed_at": now, "base": {"ref": "main"},
             "html_url": "u3", "head": {"ref": "fixpoint/main/g2"}, "body": prbody.findings_marker(["c"])},
            {"number": 4, "state": "closed", "merged_at": None, "closed_at": "2000-01-01T00:00:00Z",
             "base": {"ref": "main"}, "head": {"ref": "fixpoint/main/g3"}, "body": ""},
        ]
        gh.comments[3] = [{"user": {"type": "User"}, "body": "we sanitise this upstream"},
                          {"user": {"type": "Bot"}, "body": "bot noise"}]
        recs = record.outcomes(gh, REPO, 7, "fixpoint-reason/")
        by = {r["number"]: r for r in recs}
        assert set(by) == {1, 2, 3}
        assert by[1]["outcome"] == "merged"
        assert (by[2]["reason"], by[2]["reason_source"]) == ("wrong-fix", "label")
        assert by[3]["reason"] == "we sanitise this upstream"
        cases = record.eval_cases(recs)
        assert [c["expected"] for c in cases] == ["no_pr", "no_pr"] and cases[0]["finding_ids"] == ["b"]

    def test_metrics_https_only(self):
        with pytest.raises(ValueError):
            record.post_metrics("http://x", None, {})
