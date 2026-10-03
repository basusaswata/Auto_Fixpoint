"""Scanner mode (scan_engine=scanner): Semgrep + OSV-Scanner, faked by small executables."""

import json
import os
import stat

import pytest

from fixpoint import align, cli, fix, plan, scanners, triage
from fixpoint.model import Finding, Location, fingerprint, load_findings, write_json
from fixpoint.pipeline import InputError, validate_inputs
from tests.conftest import FIXTURES, ROOT, make_repo

SHA = "a" * 40

CONTROLLER = """package com.homelab.vulbankapi;

public class VulnBankController {
    private JdbcTemplate jdbcTemplate;

    public List<Map<String, Object>> search(String name) {
        return jdbcTemplate.queryForList("SELECT * FROM user WHERE username = '" + name + "'");
    }

    public String logExploit(String input) {
        logger.info("Logging user input: " + input);
        return "Logged: " + input;
    }
}
"""

POM = """<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.0.0</version>
  </parent>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
      <scope>runtime</scope>
    </dependency>
  </dependencies>
</project>
"""

REPO_FILES = {"src/main/java/com/homelab/vulbankapi/VulnBankController.java": CONTROLLER, "pom.xml": POM}


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "target", REPO_FILES)


def fake_tool(tmp_path, name, body):
    """A stand-in scanner: records argv + env, then runs ``body`` (shell)."""
    path = tmp_path / "bin" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    log = tmp_path / f"{name}.calls"
    path.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nenv > "{tmp_path}/{name}.env"\n{body}\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path, log


@pytest.fixture
def semgrep(tmp_path, monkeypatch):
    sarif = (FIXTURES / "semgrep.vulnbank.sarif").read_text()
    (tmp_path / "semgrep.out").write_text(sarif)
    body = (f'out=""; while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done\n'
            f'cp "{tmp_path}/semgrep.out" "$out"\nexit 0')
    path, log = fake_tool(tmp_path, "semgrep", body)
    monkeypatch.setenv("FIXPOINT_SEMGREP_BIN", str(path))
    return log


@pytest.fixture
def osv_scanner(tmp_path, monkeypatch, repo):
    doc = (FIXTURES / "osv-scanner.vulnbank.json").read_text().replace("__REPO__", str(repo.resolve()))
    (tmp_path / "osv.out").write_text(doc)
    path, log = fake_tool(tmp_path, "osv-scanner", f'cat "{tmp_path}/osv.out"\nexit 1')
    monkeypatch.setenv("FIXPOINT_OSV_SCANNER_BIN", str(path))
    return log


# -- SAST: Semgrep ------------------------------------------------------------------------


def test_semgrep_run_and_normalise(repo, semgrep, policy, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("FIXPOINT_WRITE_TOKEN", "ghs_secret")
    res = scanners.scan("sast", repo, SHA, policy, tmp_path / "work")
    argv = semgrep.read_text()
    assert argv.startswith("scan --sarif --output") and "--metrics=off" in argv
    assert "--config p/default" in argv and "--config p/owasp-top-ten" in argv and "--exclude node_modules" in argv
    env = (tmp_path / "semgrep.env").read_text()
    assert "sk-ant-secret" not in env and "ghs_secret" not in env  # scanners never see secrets
    assert (tmp_path / "work" / "semgrep.sarif").is_file()  # raw output kept for the artifact
    assert res.meta["sast_mode"] == "scanner" and res.meta["sast_engine"].startswith("semgrep 1.179.0")
    sqli = next(f for f in res.findings if f.cwe == ["CWE-89"])
    assert sqli.source == "scanner:semgrep" and sqli.severity == "high"
    assert sqli.location.file == "src/main/java/com/homelab/vulbankapi/VulnBankController.java"
    # "requires login" placeholder replaced by the real line from the pinned checkout
    assert "queryForList" in sqli.location.snippet
    assert sqli.properties["report_revision"] == SHA
    # same code from the AI scan gets the same id -> no duplicate PRs across engines
    ai = Finding(kind="sast", source="discover:scgra-reviewer", cwe=["CWE-89"],
                 location=Location(file=sqli.location.file, start_line=7, end_line=7, snippet=sqli.location.snippet))
    assert sqli.id == ai.id == fingerprint(sqli)


def test_semgrep_findings_flow_to_fix(repo, semgrep, policy, lock, tmp_path):
    from fixpoint.agent import ScriptedRuntime

    res = scanners.scan("sast", repo, SHA, policy, tmp_path / "work")
    fs = align.align(res.findings, repo, SHA)
    assert all(f.status == "open" for f in fs) and fs[0].location.start_line in (7, 11)
    rt = ScriptedRuntime({"triage": lambda req: {"results": [
        {"id": f.id, "disposition": "fix", "confidence": 0.9, "reasoning": "tainted", "evidence": []} for f in fs]}})
    triage.triage(fs, repo, "acme/shop", SHA, policy, lock, rt)
    assert "comes from a scanner" in rt.calls[0].prompt  # triage told to map scanner rule ids to skills by CWE
    p = plan.plan(fs, policy, "main", None, 0)
    assert {g["kind"] for g in p["groups"]} == {"sast"} and len(p["groups"]) == 2


def test_semgrep_failures(repo, policy, tmp_path, monkeypatch):
    path, _ = fake_tool(tmp_path, "semgrep", "echo 'rule download failed' >&2\nexit 2")
    monkeypatch.setenv("FIXPOINT_SEMGREP_BIN", str(path))
    with pytest.raises(scanners.ScannerError, match="exit 2"):
        scanners.scan("sast", repo, SHA, policy, tmp_path / "w")
    monkeypatch.setenv("FIXPOINT_SEMGREP_BIN", str(tmp_path / "nope"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(scanners.ScannerError, match="not installed"):
        scanners.scan("sast", repo, SHA, policy, tmp_path / "w")


# -- SCA: OSV-Scanner ------------------------------------------------------------------------


def test_osv_scanner_transitive_and_managed(repo, osv_scanner, policy, tmp_path):
    res = scanners.scan("sca", repo, SHA, policy, tmp_path / "work")
    assert res.meta["sca_mode"] == "scanner" and (tmp_path / "work" / "osv-scanner.json").is_file()
    assert osv_scanner.read_text().strip() == "scan source -r --format json ."
    by = {f.package.name: f for f in res.findings if "spring-web" not in f.package.name}
    web = [f for f in res.findings if f.package.name == "org.springframework:spring-web"]
    assert len(web) == 2 and all(f.package.manifest == "pom.xml" for f in res.findings)  # absolute path relativised
    assert all(f.source == "scanner:osv-scanner" and f.properties["osv_confirmed"] for f in res.findings)

    align.align(res.findings, repo, SHA)
    # spring-web is not in pom.xml at all -> transitive, still open (scanner resolved the tree)
    assert all(f.status == "open" and f.properties.get("transitive") for f in web)
    # h2 is declared without a version (managed by the parent) -> open + managed, NOT stale
    h2 = by["com.h2database:h2"]
    assert h2.status == "open" and h2.properties.get("managed") and h2.location.start_line == 14

    for f in res.findings:
        f.disposition, f.confidence = "fix", 0.9
    groups = {g["package"]["name"]: g for g in plan.plan(res.findings, policy, "main", None, 0)["groups"]}
    g = groups["org.springframework:spring-web"]
    assert g["package"]["transitive"] and g["package"]["target_version"] == "6.0.19"  # clears both CVEs
    assert g["source"] == "scanner:osv-scanner" and g["cve"] == ["CVE-2024-22243", "CVE-2024-22262"]
    assert "dependencyManagement" in fix.dependency_note(g["package"])
    assert "WITHOUT a version" in fix.dependency_note(groups["com.h2database:h2"]["package"])


def test_osv_scanner_edge_cases(repo, policy, tmp_path, monkeypatch):
    path, _ = fake_tool(tmp_path, "osv-scanner", "echo 'No package sources found' >&2\nexit 128")
    monkeypatch.setenv("FIXPOINT_OSV_SCANNER_BIN", str(path))
    assert scanners.scan("sca", repo, SHA, policy, tmp_path / "w").findings == []
    path, _ = fake_tool(tmp_path, "osv-scanner", "echo boom >&2\nexit 127")
    monkeypatch.setenv("FIXPOINT_OSV_SCANNER_BIN", str(path))
    with pytest.raises(scanners.ScannerError, match="exit 127"):
        scanners.scan("sca", repo, SHA, policy, tmp_path / "w")


def test_osv_rescan(repo, osv_scanner, policy, tmp_path, monkeypatch):
    ok, detail = scanners.osv_rescan(repo, policy, "org.springframework:spring-web", {"CVE-2024-22243"})
    assert not ok and "CVE-2024-22243" in detail
    path, _ = fake_tool(tmp_path, "osv-scanner", 'echo \'{"results": []}\'\nexit 0')
    monkeypatch.setenv("FIXPOINT_OSV_SCANNER_BIN", str(path))
    ok, _ = scanners.osv_rescan(repo, policy, "org.springframework:spring-web", {"CVE-2024-22243"})
    assert ok


def test_align_name_boundaries(tmp_path):
    from fixpoint.model import Package

    (tmp_path / "pom.xml").write_text(POM)
    f = Finding(kind="sca", source="discover:skill+osv", cve=["CVE-1"],
                package=Package("Maven", "org.example:spring-web", "6.0.2", ["6.0.19"], "pom.xml"))
    align.align([f], tmp_path, SHA)
    assert f.status == "unlocatable"  # discovered (not scanner-resolved) + not declared -> not trusted


# -- inputs + CLI --------------------------------------------------------------------------------


def test_scan_engine_input():
    assert validate_inputs({"repo": "a/b", "branch": "main"})["scan_engine"] == "ai"
    assert validate_inputs({"repo": "a/b", "branch": "main", "scan_engine": "scanner"})["scan_engine"] == "scanner"
    with pytest.raises(InputError):
        validate_inputs({"repo": "a/b", "branch": "main", "scan_engine": "trivy"})


def test_cli_scan(repo, semgrep, tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    run = tmp_path / "run.json"
    write_json(run, {"repo": "basusaswata/VulnBankAPI", "branch": "main", "sha": SHA, "scan_engine": "scanner"})
    out = tmp_path / "work" / "sast.json"
    assert cli.main(["scan", "--kind", "sast", "--repo-dir", str(repo), "--run", str(run), "--out", str(out)]) == 0
    fs, meta = load_findings(out)
    assert meta["sast_mode"] == "scanner" and len(fs) == 2 and (out.parent / "semgrep.sarif").is_file()
    assert json.loads((out.parent / "semgrep.sarif").read_text())["version"] == "2.1.0"
    assert os.environ.get("FIXPOINT_SEMGREP_BIN")


def test_verify_runs_osv_scanner_on_patched_tree(tmp_path, policy, lock, monkeypatch):
    from fixpoint import verify, worktree
    from fixpoint.agent import ScriptedRuntime

    fixed_pom = POM.replace("  <dependencies>", "  <dependencyManagement><dependencies><dependency>\n"
                            "    <groupId>org.springframework</groupId><artifactId>spring-web</artifactId>\n"
                            "    <version>6.0.19</version></dependency></dependencies></dependencyManagement>\n"
                            "  <dependencies>", 1)
    src = make_repo(tmp_path / "src", REPO_FILES)
    (src / "pom.xml").write_text(fixed_pom)
    patch = worktree.capture_diff(src)
    group = {"id": "sca-spring-web-1", "kind": "sca", "finding_ids": ["x"], "cve": ["CVE-2024-22243"],
             "source": "scanner:osv-scanner", "role": "fix_cve",
             "package": {"ecosystem": "Maven", "name": "org.springframework:spring-web", "manifest": "pom.xml",
                         "current_version": "6.0.2", "target_version": "6.0.19", "transitive": True}}
    meta = {"new_version": "6.0.19", "test_added": None}

    class Osv:
        def vulns_at(self, dep):
            return {"CVE-2024-22243"} if dep.version == "6.0.2" else set()

    verdict = {"findings": [], "new_issues": [], "test_meaningful": False, "confidence": 0.9, "summary": "ok"}
    for clean, expect in ((True, True), (False, False)):
        body = 'echo \'{"results": []}\'\nexit 0' if clean else f'cat "{FIXTURES}/osv-scanner.vulnbank.json"\nexit 1'
        path, _ = fake_tool(tmp_path / ("c" if clean else "d"), "osv-scanner", body)
        monkeypatch.setenv("FIXPOINT_OSV_SCANNER_BIN", str(path))
        repo = make_repo(tmp_path / f"t{clean}", REPO_FILES)
        v = verify.verify_rescan(group, [], patch, meta, repo, "a/b", SHA, policy, lock,
                                 ScriptedRuntime({"verify": [verdict]}), Osv())
        check = next(c for c in v["checks"] if c["name"] == "osv-scanner-rescan")
        assert check["passed"] is expect and v["passed"] is expect, v["checks"]
