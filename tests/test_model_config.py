import pytest

from fixpoint.config import ConfigError, glob_match, validate_policy
from fixpoint.model import Finding, Location, Package, merge_findings, normalise_cwe, normalise_severity


def sast(file="app/db.py", line=10, snippet="cur.execute(q % name)", cwe="CWE-89", source="report:codeql", rule="r"):
    return Finding(kind="sast", source=source, rule_id=rule, cwe=[cwe],
                   location=Location(file=file, start_line=line, end_line=line, snippet=snippet))


class TestFingerprint:
    def test_stable_across_line_moves_and_whitespace(self):
        a = sast(line=10, snippet="  cur.execute(q  %  name)\n")
        b = sast(line=99, snippet="cur.execute(q % name)")
        assert a.id == b.id

    def test_independent_of_scanner_and_rule(self):
        assert sast(source="report:codeql", rule="py/sql").id == sast(source="discover:x", rule="scgra-0").id

    def test_changes_with_file_cwe_or_code(self):
        base = sast()
        assert base.id != sast(file="app/other.py").id
        assert base.id != sast(cwe="CWE-78").id
        assert base.id != sast(snippet="cur.execute(q, (name,))").id

    def test_prefix_and_determinism(self):
        assert sast().id.startswith("sast-") and sast().id == sast().id

    def test_sca_fingerprint(self):
        def mk(cves, version="4.17.20"):
            return Finding(kind="sca", source="report:snyk", cve=cves,
                           package=Package(ecosystem="npm", name="lodash", version=version))
        assert mk(["CVE-2021-23337", "CVE-2020-28500"]).id == mk(["cve-2020-28500", "CVE-2021-23337"]).id
        assert mk(["CVE-2021-23337"]).id != mk(["CVE-2021-23337"], "4.17.19").id
        assert mk(["CVE-2021-23337"]).id.startswith("sca-")

    def test_roundtrip(self):
        f = sast()
        f.disposition, f.confidence = "fix", 0.9
        g = Finding.from_dict(f.to_dict())
        assert g.to_dict() == f.to_dict()

    def test_bad_disposition_rejected(self):
        d = sast().to_dict()
        d["disposition"] = "yolo"
        with pytest.raises(ValueError):
            Finding.from_dict(d)


def test_normalisers():
    assert normalise_cwe("external/cwe/cwe-089") == "CWE-89"
    assert normalise_cwe("CWE-79: XSS") == "CWE-79"
    assert normalise_severity("MODERATE") == "medium"
    assert normalise_severity("error") == "high"
    assert normalise_severity("weird") == "medium"


def test_merge_collapses_duplicates_and_keeps_worst_severity():
    a = sast(source="report:codeql")
    a.severity = "medium"
    b = sast(source="discover:scgra-reviewer")
    b.severity = "high"
    merged = merge_findings([a], [b])
    assert len(merged) == 1
    assert merged[0].severity == "high"
    assert merged[0].properties["also_reported_by"] == ["discover:scgra-reviewer"]


class TestGlob:
    @pytest.mark.parametrize("path,pattern,ok", [
        (".github/workflows/x.yml", ".github/**", True),
        ("a/.github/x", ".github/**", False),
        ("tests/test_a.py", "**/tests/**", True),
        ("src/tests/a.py", "**/tests/**", True),
        ("test_a.py", "**/test_*.py", True),
        ("pkg/test_a.py", "**/test_*.py", True),
        ("src/a.py", "**/test_*.py", False),
        ("config/.env", "**/.env", True),
        (".env", "**/.env", True),
        ("CODEOWNERS", "CODEOWNERS", True),
        ("docs/CODEOWNERS", "CODEOWNERS", False),
        (".cursorrules", ".cursor*", True),
    ])
    def test_glob(self, path, pattern, ok):
        assert glob_match(path, pattern) is ok


class TestPolicy:
    def test_branch_rules_first_match(self, policy):
        assert policy.branch_rule("main").autonomy == "pr"
        assert policy.branch_rule("release/2.1").autonomy == "draft"
        assert policy.branch_rule("release/2.1").cve_upgrade == "same-major-lowest-safe"
        assert policy.branch_rule("feature/x").cve_upgrade == "lowest-safe"

    def test_enrolment_case_insensitive(self, policy):
        assert policy.is_enrolled("ACME/shop")
        assert not policy.is_enrolled("acme/other")

    def test_invalid_policy(self, policy):
        raw = dict(policy.raw)
        raw["branch_rules"] = [{"match": "*", "cve_upgrade": "latest", "autonomy": "pr"}]
        with pytest.raises(ConfigError):
            validate_policy(raw)
        raw = dict(policy.raw)
        raw["triage"] = {**policy.raw["triage"], "min_confidence": 2}
        with pytest.raises(ConfigError):
            validate_policy(raw)

    def test_skills_lock(self, lock):
        assert lock.source == "git"
        assert len(lock.commit) == 40
        assert len(lock.content_sha256) == 64
        assert lock.skill("review") == "scgra-reviewer"
        assert lock.version.startswith("basusaswata/SecCodeAndRevAgent@")
