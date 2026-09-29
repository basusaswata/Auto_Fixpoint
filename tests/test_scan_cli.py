"""DISCOVER (agent + OSV mocked), ingest, inputs validation, CLI wiring, skills hashing."""

import json

import pytest

from fixpoint import cli, ingest, scan, skills
from fixpoint.agent import AgentError, ScriptedRuntime
from fixpoint.config import load_skills_lock
from fixpoint.model import load_findings, write_json
from fixpoint.osvapi import Dependency, OsvClient
from fixpoint.pipeline import InputError, validate_inputs
from tests.conftest import FIXTURES, ROOT, make_repo

FILES = {
    "app/routes.py": "@app.route('/u')\ndef u():\n    q = request.args['q']\n    return db.find(q)\n",
    "app/db.py": "def find(q):\n    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % q)\n",
    "app/util.py": "def add(a, b):\n    return a + b\n",
    "README.md": "# hi\n",
    "tests/test_util.py": "def test_add():\n    assert add(1, 2) == 3\n",
    "node_modules/x/index.js": "eval(x)\n",
    ".github/workflows/ci.yml": "on: push\n",
    "requirements.txt": "flask==2.0.0\npyyaml==5.3\nrequests>=2\n",
}


def disc(file, line, conf=0.9, cwe="CWE-89", snippet="cur.execute(\"SELECT * FROM u WHERE n='%s'\" % q)"):
    return {"cwe": cwe, "rule_id": "scgra-0-input-validation-injection", "title": "SQLi", "message": "m",
            "file": file, "start_line": line, "end_line": line, "snippet": snippet, "severity": "high",
            "confidence": conf, "source_to_sink": ["request.args['q'] (app/routes.py:3)", "cur.execute (app/db.py:2)"]}


def test_select_files_ranks_and_excludes(tmp_path, policy):
    repo = make_repo(tmp_path / "r", FILES)
    ranked = scan.select_files(repo, policy)
    names = [r[0] for r in ranked]
    assert "node_modules/x/index.js" not in names and ".github/workflows/ci.yml" not in names
    assert "tests/test_util.py" not in names and "README.md" not in names
    assert names.index("app/db.py") < names.index("app/util.py")
    assert names.index("app/routes.py") < names.index("app/util.py")
    policy.raw["discover"]["sast"]["max_files"] = 1
    assert len(scan.select_files(repo, policy)) == 1


def test_discover_sast(tmp_path, policy, lock):
    repo = make_repo(tmp_path / "r", FILES)
    policy.raw["discover"]["sast"]["batch_size"] = 2
    responses = [
        {"findings": [disc("app/db.py", 2), disc("app/elsewhere.py", 1), disc("app/db.py", 2, conf=0.1,
                                                                               cwe="CWE-20")],
         "files_reviewed": ["app/db.py", "app/routes.py"]},
        AgentError("rate limited"),
    ]
    rt = ScriptedRuntime({"review": responses})
    res = scan.discover_sast(repo, "acme/shop", "a" * 40, policy, lock, rt)
    assert len(res.findings) == 1  # outside-batch and low-confidence dropped
    f = res.findings[0]
    assert f.source == "discover:scgra-reviewer" and f.cwe == ["CWE-89"] and f.confidence == 0.9
    assert f.path and f.evidence[0].kind == "source_to_sink"
    assert res.meta["sast_mode"] == "discover" and len(res.meta["discover_errors"]) == 1
    assert "scgra-reviewer" in rt.calls[0].prompt and "<untrusted-data" in rt.calls[0].prompt
    assert rt.calls[0].tools == ["Read", "Grep", "Glob", "Skill"]


class FakeOsv(OsvClient):
    def __init__(self):
        super().__init__()
        self.seen = []

    def vuln_ids(self, deps):
        self.seen = deps
        return [["GHSA-8q59-q68h-6hv4"] if d.name == "pyyaml" else [] for d in deps]

    def vuln(self, vid):
        osv = json.loads((FIXTURES / "osv-scanner.json").read_text())
        return osv["results"][0]["packages"][0]["vulnerabilities"][0]


def test_discover_sca_grounds_inventory_and_confirms_with_osv(tmp_path, policy, lock):
    repo = make_repo(tmp_path / "r", FILES)
    inv = {"dependencies": [
        {"ecosystem": "PyPI", "name": "flask", "version": "2.0.0", "pinned": True, "manifest": "requirements.txt"},
        {"ecosystem": "PyPI", "name": "pyyaml", "version": "5.3", "pinned": True, "manifest": "requirements.txt"},
        {"ecosystem": "PyPI", "name": "requests", "version": ">=2", "pinned": False, "manifest": "requirements.txt"},
        {"ecosystem": "PyPI", "name": "django", "version": "1.2", "pinned": True, "manifest": "requirements.txt"},
        {"ecosystem": "npm", "name": "x", "version": "1.0.0", "pinned": True, "manifest": "../../etc/passwd"},
    ]}
    osv = FakeOsv()
    res = scan.discover_sca(repo, "acme/shop", "a" * 40, policy, lock, ScriptedRuntime({"discover_sca": [inv]}), osv)
    assert sorted(d.name for d in osv.seen) == ["flask", "pyyaml"]  # hallucinated django and unpinned dropped
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.cve == ["CVE-2020-14343"] and f.package.fixed_versions == ["5.4"]
    assert f.properties["osv_confirmed"] is True
    assert res.meta["unpinned_skipped"] == 1


def test_discover_sca_osv_failure_is_reported(tmp_path, policy, lock):
    repo = make_repo(tmp_path / "r", FILES)
    inv = {"dependencies": [{"ecosystem": "PyPI", "name": "pyyaml", "version": "5.3", "pinned": True,
                             "manifest": "requirements.txt"}]}
    import requests

    class Down(OsvClient):
        def vuln_ids(self, deps):
            raise requests.ConnectionError("osv.dev unreachable")

    res = scan.discover_sca(repo, "a/b", "a" * 40, policy, lock, ScriptedRuntime({"discover_sca": [inv]}), Down())
    assert res.findings == [] and "osv" in res.meta["discover_errors"][0]


def test_osv_https_only():
    with pytest.raises(Exception):
        OsvClient("http://api.osv.dev")
    assert Dependency("PyPI", "a", "1", "r").name == "a"


def test_ingest_path_rules(tmp_path):
    fs = ingest.ingest(str(FIXTURES / "snyk.json"), "auto", "sca", 10_000_000, FIXTURES.parent)
    assert len(fs) == 2
    with pytest.raises(ingest.IngestError):
        ingest.ingest(str(FIXTURES / "snyk.json"), "auto", "sca", 10_000_000, tmp_path)  # outside workspace
    with pytest.raises(ingest.IngestError):
        ingest.ingest("http://example.com/r.json", "auto", "sca", 10, None)
    with pytest.raises(ingest.IngestError):
        ingest.ingest(str(FIXTURES / "snyk.json"), "auto", "sca", 10, None)  # too big


class TestInputs:
    def ok(self, **kw):
        return validate_inputs({"repo": "acme/shop", "branch": "release/1.2", **kw})

    def test_defaults(self):
        r = self.ok()
        assert r["mode"] == "review" and r["max_prs"] is None and r["sast_report"] == "" and r["actor"] == "unknown"

    @pytest.mark.parametrize("field,value", [
        ("repo", "acme"), ("repo", "acme/shop; rm -rf /"), ("branch", "main..x"), ("branch", "-x"),
        ("branch", "a b"), ("branch", "$(id)"), ("mode", "yolo"), ("max_prs", "-1"), ("max_prs", "a"),
        ("sast_report", "http://x/r.sarif"), ("sast_report", "../../secret"), ("sast_report", "/etc/passwd"),
        ("sca_format", "trivy"),
    ])
    def test_rejects(self, field, value):
        raw = {"repo": "acme/shop", "branch": "main", field: value}
        with pytest.raises(InputError):
            validate_inputs(raw)

    def test_accepts_reports(self):
        r = self.ok(sast_report="https://x/y.sarif", sca_report="reports/snyk.json", sca_format="snyk", max_prs="3",
                    mode="fix", actor="dependabot[bot]")
        assert r["max_prs"] == 3 and r["sca_format"] == "snyk" and r["actor"] == "dependabot[bot]"


def test_cli_inputs_ingest_plan_report(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    for k, v in {"FP_REPO": "basusaswata/fixpoint-demo-app", "FP_BRANCH": "main", "FP_MODE": "fix",
                 "FP_MAX_PRS": "2", "FP_ACTOR": "alice"}.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "gh_out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    run = tmp_path / "run.json"
    assert cli.main(["inputs", "--out", str(run)]) == 0
    assert "owner=basusaswata" in out.read_text()
    doc = json.loads(run.read_text())
    doc["sha"] = "a" * 40
    write_json(run, doc)
    assert cli.main(["ingest", "--kind", "sca", "--report", str(FIXTURES / "snyk.json"), "--out",
                     str(tmp_path / "sca.json")]) == 0
    fs, meta = load_findings(tmp_path / "sca.json")
    assert meta["sca_mode"] == "report" and len(fs) == 2
    for f in fs:
        f.disposition, f.confidence = "fix", 0.95
    from fixpoint.model import save_findings

    save_findings(tmp_path / "tri.json", fs, meta)
    assert cli.main(["plan", "--in", str(tmp_path / "tri.json"), "--run", str(run), "--out",
                     str(tmp_path / "plan.json")]) == 0
    assert 'has_groups=true' in out.read_text()
    assert cli.main(["report", "--findings", str(tmp_path / "tri.json"), "--plan", str(tmp_path / "plan.json"),
                     "--run", str(run), "--out-dir", str(tmp_path / "rep")]) == 0
    assert (tmp_path / "rep" / "openvex.json").is_file()


def test_cli_errors_return_nonzero(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("FP_REPO", "bad")
    assert cli.main(["inputs", "--out", str(tmp_path / "r.json")]) == 1


def test_skills_hash_and_install(tmp_path):
    lock = load_skills_lock(ROOT / "skills.lock")
    pack = tmp_path / "pack"
    (pack / "AISecCore/skills").mkdir(parents=True)
    (pack / "AISecCore/agents").mkdir(parents=True)
    for name in set(lock.roles.values()):
        target = "agents" if name == "scgra-reviewer" else "skills"
        (pack / f"AISecCore/{target}/{name}.md").write_text(
            f"---\nid: {name}\ndescription: test skill\nglobs: **/*.py\n---\n# {name}\nbody\n")
    h1 = skills.tree_sha256(pack, ["AISecCore"])
    (pack / "AISecCore/.DS_Store").write_text("junk")
    assert skills.tree_sha256(pack, ["AISecCore"]) == h1
    home = tmp_path / "home"
    names = skills.install(pack, home, lock)
    assert set(names) == set(lock.roles.values())
    text = (home / ".claude/skills/scgra-reviewer/SKILL.md").read_text()
    assert text.startswith("---\nname: scgra-reviewer\ndescription: \"test skill\"\n---")
    (pack / "AISecCore/skills/scgra-0-cwe-prevention.md").write_text("tampered")
    assert skills.tree_sha256(pack, ["AISecCore"]) != h1


def test_skills_install_requires_role_skills(tmp_path):
    lock = load_skills_lock(ROOT / "skills.lock")
    (tmp_path / "AISecCore/skills").mkdir(parents=True)
    with pytest.raises(skills.SkillsError):
        skills.install(tmp_path, tmp_path / "h", lock)
