"""Deterministic patch rules. Run in verify, again in sign, and again in publish."""

from __future__ import annotations

import re
from typing import Any

from fixpoint import diffutil
from fixpoint.config import Policy, any_glob

ASSERT_RE = re.compile(
    r"(\bassert\w*\b|\bexpect\s*\(|\.should\b|\bshould\.|\bverify\s*\(|\bassertThat\b|\bt\.(Error|Fatal)f?\s*\(|"
    r"\brequire\.\w+\s*\(|\bself\.assert\w+\s*\(|\bpytest\.raises\b|\bassertRaises\b|\bassertThrows\b)"
)
SKIP_RE = re.compile(
    r"(@Disabled\b|@Ignore\b|pytest\.mark\.skip|pytest\.mark\.xfail|unittest\.skip|\bxit\s*\(|\bxdescribe\s*\(|"
    r"\b(it|describe|test)\.skip\s*\(|\bt\.Skip(Now|f)?\s*\(|@unittest\.expectedFailure|\.only\s*\()"
)


def check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def check_patch(patch: str, policy: Policy, group: dict[str, Any], meta: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        files = diffutil.parse(patch)
    except diffutil.PatchError as e:
        return [check("patch-parse", False, str(e))]
    out = [check("patch-parse", bool(files), f"{len(files)} file(s)" if files else "empty patch")]
    if not files:
        return out

    bad = [f.path for f in files if f.binary or f.mode_change or f.rename]
    out.append(check("text-only", not bad, f"binary/mode/rename changes: {bad}" if bad else "text changes only"))

    forbidden = [f.path for f in files if any_glob(f.path, policy.forbidden_paths)]
    out.append(check("forbidden-paths", not forbidden, f"touches {forbidden}" if forbidden else "none touched"))

    n_files, n_lines = diffutil.stats(files)
    lim = policy.limits
    out.append(check("size", n_files <= lim["changed_files"] and n_lines <= lim["changed_lines"],
                     f"{n_files} files / {n_lines} lines (limits {lim['changed_files']} / {lim['changed_lines']})"))

    tests_cfg = policy.tests
    test_files = [f for f in files if policy.is_test_path(f.path)]
    deleted = [f.path for f in test_files if f.status == "deleted"]
    if tests_cfg.get("forbid_deletion", True):
        out.append(check("no-test-deletion", not deleted, f"deletes {deleted}" if deleted else "no tests deleted"))
    if tests_cfg.get("forbid_weakening", True):
        weakened = []
        for f in test_files:
            if f.status != "modified":
                continue
            removed = sum(1 for ln in f.removed_lines() if ASSERT_RE.search(ln))
            added = sum(1 for ln in f.added_lines() if ASSERT_RE.search(ln))
            if removed > added:
                weakened.append(f"{f.path} (-{removed} +{added} assertions)")
        for f in test_files:
            if any(SKIP_RE.search(ln) for ln in f.added_lines()):
                weakened.append(f"{f.path} (adds skip/only marker)")
        out.append(check("no-test-weakening", not weakened, "; ".join(weakened) or "no assertions removed"))

    if group.get("kind") == "sast" and tests_cfg.get("require_new_test_for_sast", True):
        test = meta.get("test_added") or {}
        changed_tests = {f.path for f in test_files if f.status != "deleted" and f.added}
        ok = bool(test) and test.get("path") in changed_tests
        out.append(check("new-test", ok, f"test {test.get('path')}" if ok else
                         f"SAST fix must add a test in a test path; reported {test.get('path')!r}, "
                         f"test files changed: {sorted(changed_tests)}"))

    if group.get("kind") == "sca":
        manifest = (group.get("package") or {}).get("manifest")
        touched = {f.path for f in files}
        out.append(check("manifest-updated", manifest in touched, f"{manifest} {'changed' if manifest in touched else 'not changed'}"))
    return out


def all_passed(checks: list[dict[str, Any]]) -> bool:
    return bool(checks) and all(c["passed"] for c in checks)
