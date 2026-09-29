from fixpoint.align import align
from fixpoint.model import Finding, Location, Package

SHA = "a" * 40

DB = """import sqlite3


def find(cur, name):
    # look up a user
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()
"""


def f_at(line, snippet, file="app/db.py", **props):
    return Finding(kind="sast", source="report:x", cwe=["CWE-89"], properties=props,
                   location=Location(file=file, start_line=line, end_line=line, snippet=snippet))


def write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_moved_code_is_reanchored(tmp_path):
    write(tmp_path, "app/db.py", "# header\n# more\n\n" + DB)
    f = f_at(6, 'cur.execute("SELECT * FROM users WHERE name = \'%s\'" % name)')
    align([f], tmp_path, SHA)
    assert f.status == "open"
    assert f.location.start_line == 9
    assert any("re-anchored" in n for n in f.notes)


def test_nearest_duplicate_wins(tmp_path):
    write(tmp_path, "app/db.py", "x = 1\n" * 3 + "dup()\n" + "y = 2\n" * 20 + "dup()\n")
    f = f_at(23, "dup()")
    align([f], tmp_path, SHA)
    assert f.location.start_line == 25


def test_whitespace_changes_still_match(tmp_path):
    write(tmp_path, "app/db.py", DB.replace("    cur.execute(", "        cur.execute(  "))
    f = f_at(6, 'cur.execute("SELECT * FROM users WHERE name = \'%s\'" % name)')
    align([f], tmp_path, SHA)
    assert f.status == "open" and f.location.start_line == 6


def test_fuzzy_match(tmp_path):
    write(tmp_path, "app/db.py", DB.replace("users", "users_v2"))
    f = f_at(6, 'cur.execute("SELECT * FROM users WHERE name = \'%s\'" % name)')
    align([f], tmp_path, SHA)
    assert f.status == "open" and "fuzzy snippet match" in f.notes


def test_deleted_file_is_stale(tmp_path):
    f = f_at(6, "anything")
    align([f], tmp_path, SHA)
    assert f.status == "stale"


def test_snippet_gone_is_stale(tmp_path):
    write(tmp_path, "app/db.py", "def find(cur, name):\n    return cur.execute(Q, (name,))\n")
    f = f_at(6, 'cur.execute("SELECT * FROM users WHERE name = \'%s\'" % name)')
    align([f], tmp_path, SHA)
    assert f.status == "stale"


def test_missing_snippet_is_unlocatable(tmp_path):
    write(tmp_path, "app/db.py", DB)
    f = f_at(6, "")
    align([f], tmp_path, SHA)
    assert f.status == "unlocatable"


def test_missing_snippet_anchored_when_report_revision_matches(tmp_path):
    write(tmp_path, "app/db.py", DB)
    f = f_at(6, "", report_revision=SHA)
    align([f], tmp_path, SHA)
    assert f.status == "open" and "cur.execute" in f.location.snippet


def test_path_traversal_unlocatable(tmp_path):
    f = f_at(1, "x", file="../etc/passwd")
    align([f], tmp_path, SHA)
    assert f.status == "unlocatable"


def sca(manifest="requirements.txt", version="5.3"):
    return Finding(kind="sca", source="report:osv", cve=["CVE-2020-14343"],
                   package=Package(ecosystem="PyPI", name="pyyaml", version=version, fixed_versions=["5.4"],
                                   manifest=manifest))


def test_sca_manifest_present(tmp_path):
    write(tmp_path, "requirements.txt", "flask==2.0.0\npyyaml==5.3\n")
    f = sca()
    align([f], tmp_path, SHA)
    assert f.status == "open" and f.location.start_line == 2


def test_sca_version_already_bumped_is_stale(tmp_path):
    write(tmp_path, "requirements.txt", "pyyaml==6.0.1\n")
    f = sca()
    align([f], tmp_path, SHA)
    assert f.status == "stale"


def test_sca_manifest_found_elsewhere(tmp_path):
    write(tmp_path, "svc/requirements.txt", "pyyaml==5.3\n")
    f = sca(manifest="")
    align([f], tmp_path, SHA, manifests=["svc/requirements.txt"])
    assert f.status == "open" and f.package.manifest == "svc/requirements.txt"


def test_sca_manifest_deleted(tmp_path):
    f = sca()
    align([f], tmp_path, SHA)
    assert f.status == "stale"
