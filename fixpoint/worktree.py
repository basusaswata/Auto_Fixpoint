"""Sandbox working copies of the target repo for fix and verify jobs.

Workers never clone with a token: the prepare job uploads ``git archive`` of the
pinned commit and each worker unpacks it into a fresh, neutralised git repo.
"""

from __future__ import annotations

import subprocess
import tarfile
from pathlib import Path

from fixpoint import diffutil, log
from fixpoint.neutralise import GIT, baseline, neutralise

LOG = log.get(__name__)


def archive(repo: Path, sha: str, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "archive", "--format=tar", "-o", str(out), sha], cwd=repo, check=True)
    return out


def from_archive(tar_path: Path, dest: Path) -> str:
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise RuntimeError(f"{dest} is not empty")
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest, filter="data")
    subprocess.run([*GIT, "init", "-q"], cwd=dest, check=True)
    neutralise(dest)
    sha = baseline(dest)
    assert sha
    return sha


def reset(repo: Path) -> None:
    subprocess.run([*GIT, "reset", "-q", "--hard", "HEAD"], cwd=repo, check=True)
    subprocess.run([*GIT, "clean", "-q", "-fdx"], cwd=repo, check=True)


def capture_diff(repo: Path) -> str:
    subprocess.run([*GIT, "add", "-A"], cwd=repo, check=True, capture_output=True)
    r = subprocess.run(
        [*GIT, "diff", "--cached", "--no-color", "--no-ext-diff", "--no-renames", "--no-textconv", "HEAD"],
        cwd=repo, check=True, capture_output=True,
    )
    return r.stdout.decode("utf-8", "replace")


def apply_patch(repo: Path, patch: str) -> list[str]:
    """Apply with Fixpoint's own applier (same code as publish). Returns touched paths."""
    touched = []
    for fp in diffutil.parse(patch):
        target = repo / fp.path
        if target.is_symlink():
            raise diffutil.Conflict(f"{fp.path}: refusing to write through a symlink")
        old = target.read_text(encoding="utf-8") if target.is_file() else None
        new = diffutil.apply_file(old, fp)
        if new is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(new, encoding="utf-8")
        touched.append(fp.path)
    return touched
