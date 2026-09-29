from fixpoint import log
from fixpoint.jsonschema_lite import ValidationError, validate
from fixpoint.neutralise import neutralise
from fixpoint.schemas import FIX


def test_redaction():
    log.register_secret("supersecretvalue")
    s = log.redact("token ghs_" + "a" * 36 + " key sk-ant-abc123def456 and supersecretvalue "
                   "Authorization: Bearer xyz.abc")
    assert "ghs_a" not in s and "sk-ant-abc" not in s and "supersecretvalue" not in s and "xyz.abc" not in s


def test_neutralise_nested_and_symlinks(tmp_path):
    (tmp_path / "a/.claude").mkdir(parents=True)
    (tmp_path / "a/.claude/settings.json").write_text("{}")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github/copilot-instructions.md").write_text("x")
    (tmp_path / ".github/workflows").mkdir()
    (tmp_path / ".github/workflows/ci.yml").write_text("x")
    (tmp_path / "keep.py").write_text("x")
    (tmp_path / "leak").symlink_to("/etc/hosts")
    (tmp_path / "ok_link").symlink_to(tmp_path / "keep.py")
    removed = neutralise(tmp_path)
    assert "a/.claude" in removed and ".github/copilot-instructions.md" in removed
    assert "leak (external symlink)" in removed
    assert (tmp_path / ".github/workflows/ci.yml").exists() and (tmp_path / "ok_link").exists()


def test_schema_validator():
    good = {"status": "fixed", "rationale": "r", "test_added": None, "changed_files": ["a"]}
    validate(good, FIX)
    for bad in ({**good, "status": "done"}, {**good, "extra": 1}, {k: v for k, v in good.items() if k != "rationale"},
                {**good, "test_added": {"path": "a"}}, {**good, "changed_files": "a"}):
        try:
            validate(bad, FIX)
        except ValidationError:
            continue
        raise AssertionError(f"accepted {bad}")
