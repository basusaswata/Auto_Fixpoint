import json

import pytest

from fixpoint import adapters
from fixpoint.model import FormatError
from tests.conftest import FIXTURES


def load(name):
    return json.loads((FIXTURES / name).read_text())


def test_codeql_sarif():
    fs = adapters.parse(load("codeql.sarif"), "auto", "sast")
    assert len(fs) == 2  # suppressed result skipped
    sqli = next(f for f in fs if f.rule_id == "py/sql-injection")
    assert sqli.cwe == ["CWE-89"]
    assert sqli.severity == "high"  # security-severity 8.8
    assert sqli.source == "report:codeql"
    assert sqli.location.file == "app/db.py" and sqli.location.start_line == 12
    assert "cur.execute" in sqli.location.snippet
    assert sqli.path == ["request.args (app/views.py:8)", "cur.execute (app/db.py:12)"]
    assert sqli.properties["report_revision"] == "1" * 40
    weak = next(f for f in fs if f.rule_id != "py/sql-injection")
    assert weak.cwe == ["CWE-327", "CWE-328", "CWE-916"]
    assert weak.location.snippet == ""


def test_semgrep_sarif_cwe_from_tag_text():
    fs = adapters.parse(load("semgrep.sarif"), "sarif", "sast")
    assert len(fs) == 1
    f = fs[0]
    assert f.cwe == ["CWE-89"]
    assert f.severity == "high"  # level error
    assert f.source == "report:semgrep-oss"
    assert f.location.end_line == 22


def test_snyk():
    fs = adapters.parse(load("snyk.json"), "auto", "sca")
    assert len(fs) == 2  # license issue skipped
    f = next(x for x in fs if "CVE-2021-23337" in x.cve)
    assert f.package.ecosystem == "npm" and f.package.name == "lodash" and f.package.version == "4.17.20"
    assert f.package.fixed_versions == ["4.17.21"]
    assert f.package.manifest == "package-lock.json"
    assert f.cwe == ["CWE-78"] and f.severity == "high"


def test_snyk_all_projects_list():
    doc = [load("snyk.json"), load("snyk.json")]
    assert len(adapters.parse(doc, "snyk", "sca")) == 4


def test_osv_scanner_groups_merge_aliases():
    fs = adapters.parse(load("osv-scanner.json"), "auto", "sca")
    assert len(fs) == 1
    f = fs[0]
    assert f.cve == ["CVE-2020-14343"]
    assert f.severity == "critical"  # max_severity 9.8
    assert f.package.fixed_versions == ["5.4"]
    assert f.package.manifest == "requirements.txt"
    assert f.cwe == ["CWE-20"]


def test_format_kind_mismatch_and_detection():
    with pytest.raises(FormatError):
        adapters.parse(load("snyk.json"), "snyk", "sast")
    with pytest.raises(FormatError):
        adapters.detect({"hello": 1})
    assert adapters.detect(load("codeql.sarif")) == "sarif"
    assert adapters.detect(load("osv-scanner.json")) == "osv"
    assert adapters.detect(load("snyk.json")) == "snyk"


def test_ids_stable_between_runs():
    a = [f.id for f in adapters.parse(load("codeql.sarif"), "auto", "sast")]
    b = [f.id for f in adapters.parse(load("codeql.sarif"), "auto", "sast")]
    assert a == b
