"""Minimal GitHub REST/GraphQL client (github.com and GHES).

API bases come from GITHUB_API_URL / GITHUB_GRAPHQL_URL (set by Actions), so
the same code works on GHES. Tokens are GitHub App installation tokens only.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any, Iterator
from urllib.parse import quote

import requests

from fixpoint import log

LOG = log.get(__name__)

MARKER_PREFIX = "fixpoint/"


class GitHubError(RuntimeError):
    def __init__(self, msg: str, status: int = 0) -> None:
        super().__init__(msg)
        self.status = status


class GitHub:
    def __init__(self, token: str, api: str | None = None, graphql: str | None = None,
                 session: Any = None, retries: int = 3) -> None:
        if not token:
            raise GitHubError("no GitHub token")
        log.register_secret(token)
        self.api = (api or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        self.graphql_url = graphql or os.environ.get("GITHUB_GRAPHQL_URL") or f"{self.api}/graphql"
        if not self.api.startswith("https://"):
            raise GitHubError("GitHub API must be https")
        self.http = session or requests.Session()
        self.http.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "fixpoint",
        })
        self.retries = retries

    # -- plumbing ----------------------------------------------------------------
    def request(self, method: str, path: str, **kw: Any) -> Any:
        url = path if path.startswith("https://") else f"{self.api}{path}"
        for attempt in range(self.retries + 1):
            r = self.http.request(method, url, timeout=60, **kw)
            retryable = r.status_code >= 500 or (
                r.status_code in (403, 429) and ("rate limit" in r.text.lower() or "retry-after" in r.headers)
            )
            if retryable and attempt < self.retries:
                wait = min(int(r.headers.get("retry-after", 2 ** (attempt + 1))), 60)
                LOG.warning("GitHub %s %s -> %s, retrying in %ss", method, path, r.status_code, wait)
                time.sleep(wait)
                continue
            if r.status_code >= 400:
                msg = r.text[:300]
                raise GitHubError(f"GitHub {method} {path} -> {r.status_code}: {log.redact(msg)}", r.status_code)
            if r.status_code == 204 or not r.content:
                return None
            return r.json()
        raise GitHubError(f"GitHub {method} {path}: retries exhausted")

    def paginate(self, path: str, params: dict | None = None, max_pages: int = 10) -> Iterator[dict]:
        params = dict(params or {})
        params.setdefault("per_page", 100)
        for page in range(1, max_pages + 1):
            params["page"] = page
            items = self.request("GET", path, params=params) or []
            yield from items
            if len(items) < params["per_page"]:
                return

    # -- repo reads ------------------------------------------------------------------
    def branch_sha(self, repo: str, branch: str) -> str:
        data = self.request("GET", f"/repos/{repo}/commits/{quote(branch, safe='')}")
        return data["sha"]

    def commit(self, repo: str, sha: str) -> dict:
        return self.request("GET", f"/repos/{repo}/git/commits/{sha}")

    def tree(self, repo: str, sha: str) -> dict:
        return self.request("GET", f"/repos/{repo}/git/trees/{sha}")

    def tree_entry(self, repo: str, commit_sha: str, path: str, _cache: dict | None = None) -> dict | None:
        """Walk the tree from a commit to ``path``; returns {path, mode, type, sha} or None."""
        cache = _cache if _cache is not None else {}
        ckey = f"commit:{commit_sha}"
        if ckey not in cache:
            cache[ckey] = self.commit(repo, commit_sha)["tree"]["sha"]
        tree_sha = cache[ckey]
        parts = path.split("/")
        for i, part in enumerate(parts):
            if tree_sha not in cache:
                cache[tree_sha] = {e["path"]: e for e in self.tree(repo, tree_sha).get("tree", [])}
            entry = cache[tree_sha].get(part)
            if entry is None:
                return None
            if i == len(parts) - 1:
                return entry
            if entry["type"] != "tree":
                return None
            tree_sha = entry["sha"]
        return None

    def blob(self, repo: str, sha: str) -> bytes:
        data = self.request("GET", f"/repos/{repo}/git/blobs/{sha}")
        return base64.b64decode(data["content"]) if data.get("encoding") == "base64" else data["content"].encode()

    # -- PRs ----------------------------------------------------------------------------
    def fixpoint_prs(self, repo: str, state: str = "all", max_pages: int = 10) -> list[dict]:
        out = []
        for pr in self.paginate(f"/repos/{repo}/pulls", {"state": state, "sort": "updated", "direction": "desc"},
                                max_pages):
            if (pr.get("head") or {}).get("ref", "").startswith(MARKER_PREFIX):
                out.append(pr)
        return out

    def open_pr_for_head(self, repo: str, head_branch: str) -> dict | None:
        owner = repo.split("/")[0]
        prs = self.request("GET", f"/repos/{repo}/pulls", params={"head": f"{owner}:{head_branch}", "state": "open"})
        return prs[0] if prs else None

    def issue_comments(self, repo: str, number: int) -> list[dict]:
        return list(self.paginate(f"/repos/{repo}/issues/{number}/comments", max_pages=3))

    # -- writes (publish job only) ------------------------------------------------------
    def create_blob(self, repo: str, content: bytes) -> str:
        body = {"content": base64.b64encode(content).decode(), "encoding": "base64"}
        return self.request("POST", f"/repos/{repo}/git/blobs", json=body)["sha"]

    def create_tree(self, repo: str, base_tree: str, entries: list[dict]) -> str:
        return self.request("POST", f"/repos/{repo}/git/trees", json={"base_tree": base_tree, "tree": entries})["sha"]

    def create_commit(self, repo: str, message: str, tree: str, parents: list[str]) -> str:
        # No author/committer: GitHub signs the commit as the App -> "Verified".
        body = {"message": message, "tree": tree, "parents": parents}
        return self.request("POST", f"/repos/{repo}/git/commits", json=body)["sha"]

    def get_ref(self, repo: str, branch: str) -> dict | None:
        try:
            return self.request("GET", f"/repos/{repo}/git/ref/heads/{quote(branch, safe='/')}")
        except GitHubError as e:
            if e.status == 404:
                return None
            raise

    def upsert_ref(self, repo: str, branch: str, sha: str) -> None:
        if self.get_ref(repo, branch) is None:
            self.request("POST", f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
        else:
            self.request("PATCH", f"/repos/{repo}/git/refs/heads/{quote(branch, safe='/')}",
                         json={"sha": sha, "force": True})

    def create_pull(self, repo: str, title: str, head: str, base: str, body: str, draft: bool) -> dict:
        return self.request("POST", f"/repos/{repo}/pulls",
                            json={"title": title, "head": head, "base": base, "body": body, "draft": draft,
                                  "maintainer_can_modify": True})

    def add_labels(self, repo: str, number: int, labels: list[str]) -> None:
        if labels:
            self.request("POST", f"/repos/{repo}/issues/{number}/labels", json={"labels": labels})

    def enable_auto_merge(self, pr_node_id: str, method: str = "SQUASH") -> None:
        q = ("mutation($id:ID!,$m:PullRequestMergeMethod!){enablePullRequestAutoMerge("
             "input:{pullRequestId:$id,mergeMethod:$m}){clientMutationId}}")
        data = self.request("POST", self.graphql_url, json={"query": q, "variables": {"id": pr_node_id, "m": method}})
        if data and data.get("errors"):
            raise GitHubError(f"enablePullRequestAutoMerge failed: {data['errors'][0].get('message', '')[:200]}")
