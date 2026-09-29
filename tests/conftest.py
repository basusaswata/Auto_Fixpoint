from __future__ import annotations

import copy
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Unit tests never touch the network."""
    import requests

    def boom(*a, **k):
        raise AssertionError("network access in unit tests")

    monkeypatch.setattr(requests.Session, "request", boom)
    monkeypatch.setattr(requests, "get", boom)
    monkeypatch.setattr(requests, "post", boom)


@pytest.fixture
def policy():
    from fixpoint.config import load_policy

    p = load_policy(ROOT / "policy" / "policy.yaml")
    p.raw["enrolled_repos"] = ["acme/shop"]
    return p


@pytest.fixture
def lock():
    from fixpoint.config import load_skills_lock

    return load_skills_lock(ROOT / "skills.lock")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=repo, check=True,
                          capture_output=True, text=True).stdout


def make_repo(tmp: Path, files: dict[str, str]) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    git(tmp, "init", "-q")
    git(tmp, "add", "-A")
    git(tmp, "commit", "-q", "-m", "init")
    return tmp


PYTHON = sys.executable


class FakeGitHub:
    """In-memory stand-in for fixpoint.gh.GitHub (same method names)."""

    def __init__(self, repo: str, branch: str, files: dict[str, str]) -> None:
        self.repo = repo
        self.blobs: dict[str, bytes] = {}
        self.commits: dict[str, dict] = {}
        self.refs: dict[str, str] = {}
        self.prs: list[dict] = []
        self.writes: list[tuple] = []
        self.comments: dict[int, list[dict]] = {}
        self.auto_merge: list[str] = []
        sha = self._commit({p: ("100644", c.encode()) for p, c in files.items()}, [])
        self.refs[branch] = sha

    # helpers
    def _blob(self, data: bytes) -> str:
        sha = hashlib.sha1(data).hexdigest()  # noqa: S324 - fake
        self.blobs[sha] = data
        return sha

    def _commit(self, files: dict[str, tuple[str, bytes]], parents: list[str]) -> str:
        tree = {p: (m, self._blob(c)) for p, (m, c) in files.items()}
        sha = hashlib.sha1(repr((sorted(tree.items()), parents, len(self.commits))).encode()).hexdigest()  # noqa: S324
        self.commits[sha] = {"tree": tree, "parents": parents}
        return sha

    def advance(self, branch: str, changes: dict[str, str | None]) -> str:
        base = copy.deepcopy(self.commits[self.refs[branch]]["tree"])
        files = {p: (m, self.blobs[b]) for p, (m, b) in base.items()}
        for p, c in changes.items():
            if c is None:
                files.pop(p, None)
            else:
                files[p] = ("100644", c.encode())
        sha = self._commit(files, [self.refs[branch]])
        self.refs[branch] = sha
        return sha

    def files_at(self, ref: str) -> dict[str, str]:
        sha = self.refs.get(ref, ref)
        return {p: self.blobs[b].decode() for p, (_, b) in self.commits[sha]["tree"].items()}

    # API surface
    def branch_sha(self, repo, branch):
        return self.refs[branch]

    def commit(self, repo, sha):
        return {"tree": {"sha": "tree:" + sha}}

    def tree_entry(self, repo, commit_sha, path, _cache=None):
        hit = self.commits[commit_sha]["tree"].get(path)
        return {"path": path, "mode": hit[0], "type": "blob", "sha": hit[1]} if hit else None

    def blob(self, repo, sha):
        return self.blobs[sha]

    def fixpoint_prs(self, repo, state="all", max_pages=10):
        return [p for p in self.prs if state == "all" or p["state"] == state]

    def open_pr_for_head(self, repo, head):
        return next((p for p in self.prs if p["state"] == "open" and p["head"]["ref"] == head), None)

    def issue_comments(self, repo, number):
        return self.comments.get(number, [])

    def create_blob(self, repo, content):
        self.writes.append(("blob",))
        return self._blob(content)

    def create_tree(self, repo, base_tree, entries):
        self.writes.append(("tree",))
        base_commit = base_tree.split(":", 1)[1]
        tree = dict(self.commits[base_commit]["tree"])
        for e in entries:
            if e["sha"] is None:
                tree.pop(e["path"], None)
            else:
                tree[e["path"]] = (e["mode"], e["sha"])
        tid = "t" + hashlib.sha1(repr(sorted(tree.items())).encode()).hexdigest()  # noqa: S324
        self.commits.setdefault("__trees__", {})[tid] = tree
        return tid

    def create_commit(self, repo, message, tree, parents):
        self.writes.append(("commit", message))
        t = self.commits["__trees__"][tree]
        sha = hashlib.sha1(repr((tree, parents, message)).encode()).hexdigest()  # noqa: S324
        self.commits[sha] = {"tree": t, "parents": parents}
        return sha

    def upsert_ref(self, repo, branch, sha):
        self.writes.append(("ref", branch))
        self.refs[branch] = sha

    def create_pull(self, repo, title, head, base, body, draft):
        self.writes.append(("pull", head))
        n = len(self.prs) + 1
        pr = {"number": n, "html_url": f"https://github.com/{repo}/pull/{n}", "node_id": f"PR_{n}", "state": "open",
              "merged_at": None, "title": title, "body": body, "draft": draft, "head": {"ref": head},
              "base": {"ref": base}, "labels": []}
        self.prs.append(pr)
        return pr

    def add_labels(self, repo, number, labels):
        self.prs[number - 1]["labels"] = [{"name": x} for x in labels]

    def enable_auto_merge(self, node_id, method="SQUASH"):
        self.auto_merge.append(node_id)
