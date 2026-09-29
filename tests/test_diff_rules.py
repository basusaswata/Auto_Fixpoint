import pytest

from fixpoint import diffutil, rules, worktree
from tests.conftest import make_repo

BASE = "".join(f"line {i}\n" for i in range(1, 21))


def diff_of(tmp_path, before: dict, after: dict) -> str:
    repo = make_repo(tmp_path / "r", before)
    for rel, content in after.items():
        p = repo / rel
        if content is None:
            p.unlink()
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    return worktree.capture_diff(repo)


class TestApply:
    def test_roundtrip_modify_add_delete(self, tmp_path):
        after = {"a.txt": BASE.replace("line 5\n", "line five\n"), "new/b.txt": "hello\n", "gone.txt": None}
        patch = diff_of(tmp_path, {"a.txt": BASE, "gone.txt": "bye\n"}, after)
        files = {f.path: f for f in diffutil.parse(patch)}
        assert files["new/b.txt"].status == "added" and files["gone.txt"].status == "deleted"
        assert diffutil.apply_file(BASE, files["a.txt"]) == after["a.txt"]
        assert diffutil.apply_file(None, files["new/b.txt"]) == "hello\n"
        assert diffutil.apply_file("bye\n", files["gone.txt"]) is None

    def test_moved_base_applies_with_offset(self, tmp_path):
        patch = diff_of(tmp_path, {"a.txt": BASE}, {"a.txt": BASE.replace("line 15\n", "line XV\n")})
        fp = diffutil.parse(patch)[0]
        moved = "header 1\nheader 2\n" + BASE
        assert diffutil.apply_file(moved, fp) == moved.replace("line 15\n", "line XV\n")

    def test_conflict(self, tmp_path):
        patch = diff_of(tmp_path, {"a.txt": BASE}, {"a.txt": BASE.replace("line 15\n", "line XV\n")})
        fp = diffutil.parse(patch)[0]
        with pytest.raises(diffutil.Conflict):
            diffutil.apply_file(BASE.replace("line 14\n", "changed upstream\n"), fp)
        with pytest.raises(diffutil.Conflict):
            diffutil.apply_file(None, fp)

    def test_no_newline_at_eof(self, tmp_path):
        before = "a\nb"
        after = "a\nc"
        patch = diff_of(tmp_path, {"x": before}, {"x": after})
        assert "\\ No newline" in patch
        assert diffutil.apply_file(before, diffutil.parse(patch)[0]) == after
        patch2 = diff_of(tmp_path / "2", {"x": before}, {"x": "a\nb\n"})
        assert diffutil.apply_file(before, diffutil.parse(patch2)[0]) == "a\nb\n"

    def test_binary_and_traversal_rejected(self):
        binary = "diff --git a/x.png b/x.png\nindex 1..2 100644\nBinary files a/x.png and b/x.png differ\n"
        fp = diffutil.parse(binary)[0]
        assert fp.binary
        with pytest.raises(diffutil.PatchError):
            diffutil.apply_file("", fp)
        evil = "diff --git a/../x b/../x\n--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n"
        with pytest.raises(diffutil.PatchError):
            diffutil.parse(evil)

    def test_bad_counts(self):
        bad = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-a\n+b\n"
        with pytest.raises(diffutil.PatchError):
            diffutil.parse(bad)


SAST_GROUP = {"id": "g", "kind": "sast", "finding_ids": ["f"]}
META = {"test_added": {"path": "tests/test_db.py", "name": "test_sqli"}}


def names_failed(checks):
    return sorted(c["name"] for c in checks if not c["passed"])


class TestRules:
    def test_good_sast_patch(self, tmp_path, policy):
        patch = diff_of(tmp_path, {"app/db.py": "q = 'a' + x\n"},
                        {"app/db.py": "q = ('a', x)\n", "tests/test_db.py": "def test_sqli():\n    assert True\n"})
        assert names_failed(rules.check_patch(patch, policy, SAST_GROUP, META)) == []

    def test_forbidden_path(self, tmp_path, policy):
        patch = diff_of(tmp_path, {".github/workflows/ci.yml": "a\n"}, {".github/workflows/ci.yml": "b\n",
                                                                           "tests/test_db.py": "x\n"})
        assert "forbidden-paths" in names_failed(rules.check_patch(patch, policy, SAST_GROUP, META))

    def test_test_deletion_and_weakening(self, tmp_path, policy):
        before = {"tests/test_a.py": "def test_a():\n    assert f() == 1\n    assert g() == 2\n",
                  "tests/test_b.py": "def test_b():\n    assert True\n", "app/x.py": "a\n"}
        after = {"tests/test_a.py": "def test_a():\n    f()\n", "tests/test_b.py": None, "app/x.py": "b\n",
                 "tests/test_db.py": "import pytest\n@pytest.mark.skip\ndef test_sqli():\n    assert 1\n"}
        failed = names_failed(rules.check_patch(diff_of(tmp_path, before, after), policy, SAST_GROUP, META))
        assert "no-test-deletion" in failed and "no-test-weakening" in failed

    def test_size_limits(self, tmp_path, policy):
        policy.raw["limits"]["changed_lines"] = 3
        patch = diff_of(tmp_path, {"a.py": BASE}, {"a.py": BASE.replace("line", "LINE"), "tests/test_db.py": "x\n"})
        assert "size" in names_failed(rules.check_patch(patch, policy, SAST_GROUP, META))

    def test_sast_requires_new_test(self, tmp_path, policy):
        patch = diff_of(tmp_path, {"a.py": "a\n"}, {"a.py": "b\n"})
        assert "new-test" in names_failed(rules.check_patch(patch, policy, SAST_GROUP, {"test_added": None}))
        assert "new-test" in names_failed(rules.check_patch(patch, policy, SAST_GROUP, META))

    def test_sca_requires_manifest(self, tmp_path, policy):
        grp = {"id": "g", "kind": "sca", "package": {"manifest": "package.json"}}
        patch = diff_of(tmp_path, {"src/a.js": "a\n"}, {"src/a.js": "b\n"})
        assert names_failed(rules.check_patch(patch, policy, grp, {})) == ["manifest-updated"]

    def test_empty_patch(self, policy):
        assert names_failed(rules.check_patch("", policy, SAST_GROUP, META)) == ["patch-parse"]
