"""Publish: the only stage with a write token. No AI here.

For each signed bundle, in order:
1. verify the signature against this workflow's identity (before parsing it);
2. check it belongs to this run, repo and branch;
3. re-check policy (enrolment, diff rules, autonomy);
4. re-check dedupe against live GitHub state and the open-PR limit;
5. if the base moved since the pin, re-apply the patch to the new head (skip on conflict);
6. commit through the Git Data API (blobs -> tree -> commit -> ref): GitHub signs it;
7. open the PR (draft or ready per branch rule), add labels, maybe enable auto-merge.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fixpoint import dedupe, diffutil, log, prbody, rules, versions
from fixpoint.config import Policy
from fixpoint.gh import GitHub, GitHubError
from fixpoint.model import write_json
from fixpoint.plan import branch_slug
from fixpoint.sign import SignError, load_verified_bundle

LOG = log.get(__name__)


def head_branch(branch: str, group_id: str) -> str:
    return f"fixpoint/{branch_slug(branch)}/{group_id}"


def effective_autonomy(policy: Policy, branch: str, group: dict[str, Any]) -> str:
    rule = policy.branch_rule(branch).autonomy
    order = ["draft", "pr", "auto-merge-patch"]
    # Never more autonomy than both the live policy and the plan allow.
    auto = order[min(order.index(rule), order.index(group.get("autonomy", "draft")))]
    if auto == "auto-merge-patch":
        p = group.get("package") or {}
        if group.get("kind") != "sca" or not versions.is_patch_bump(p.get("current_version", ""),
                                                                    p.get("target_version", "")):
            auto = "pr"
    return auto


def build_changes(gh: GitHub, repo: str, head_sha: str, patch: str) -> list[dict[str, Any]]:
    """Apply the patch to files at head_sha. Returns tree entries. Raises Conflict."""
    cache: dict = {}
    changes = []
    for fp in diffutil.parse(patch):
        entry = gh.tree_entry(repo, head_sha, fp.path, cache)
        if entry is not None and entry["type"] != "blob":
            raise diffutil.Conflict(f"{fp.path}: not a regular file at head")
        if entry is not None and entry.get("mode") == "120000":
            raise diffutil.Conflict(f"{fp.path}: is a symlink at head")
        old = gh.blob(repo, entry["sha"]).decode("utf-8") if entry else None
        new = diffutil.apply_file(old, fp)
        mode = entry["mode"] if entry else "100644"
        changes.append({"path": fp.path, "mode": mode, "content": new})
    return changes


def publish(bundles_dir: Path, run: dict[str, Any], policy: Policy, gh: GitHub, identity: str,
            dry_run: bool = False, signing: str = "cosign", out: Path | None = None) -> list[dict[str, Any]]:
    repo, branch, pinned = run["repo"], run["branch"], run["sha"]
    results: list[dict[str, Any]] = []
    if signing != "cosign" and not dry_run:
        raise SignError("unsigned bundles can only be used with --dry-run")
    if not policy.is_enrolled(repo):
        raise SignError(f"{repo} is not enrolled in policy")

    live = gh.fixpoint_prs(repo, state="all")
    idx = dedupe.build_index(live, branch)
    headroom = max(0, int(policy.limits["open_bot_prs_per_repo"]) - idx.open_bot_prs)
    budget = min(int(policy.limits["prs_per_run"]), headroom)
    head_sha = gh.branch_sha(repo, branch)
    moved = head_sha != pinned
    if moved:
        LOG.warning("base %s moved since pin: %s -> %s", branch, pinned[:12], head_sha[:12])

    for bpath in sorted(bundles_dir.glob("*.bundle.json")):
        res: dict[str, Any] = {"bundle": bpath.name, "status": "skipped"}
        results.append(res)
        try:
            bundle = load_verified_bundle(bpath, identity, signing)
        except (SignError, ValueError) as e:
            res.update(status="failed", reason=f"bundle rejected: {e}")
            continue
        group, meta, patch = bundle["group"], bundle["meta"], bundle["patch"]
        res["group_id"] = group["id"]
        b_run = bundle["run"]
        if (b_run.get("repo"), b_run.get("branch"), b_run.get("sha"), str(b_run.get("run_id"))) != (
                repo, branch, pinned, str(run.get("run_id"))):
            res.update(status="failed", reason="bundle belongs to a different run/repo/branch")
            continue
        checks = rules.check_patch(patch, policy, group, meta)  # policy check #3
        if not rules.all_passed(checks):
            res["reason"] = "policy: " + "; ".join(c["detail"] for c in checks if not c["passed"])
            continue
        states = {fid: idx.status_of(fid) for fid in group["finding_ids"]}
        blocked = {k: v for k, v in states.items() if v}
        if blocked:
            res["reason"] = f"dedupe: {blocked}"
            continue
        hb = head_branch(branch, group["id"])
        if gh.open_pr_for_head(repo, hb):
            res["reason"] = f"open PR already exists for {hb}"
            continue
        if budget <= 0:
            res["reason"] = "PR limit reached"
            continue
        try:
            changes = build_changes(gh, repo, head_sha, patch)
        except diffutil.PatchError as e:
            res.update(status="conflict", reason=f"patch does not apply to {head_sha[:12]}: {e}")
            continue
        autonomy = effective_autonomy(policy, branch, group)
        title = prbody.title(group)
        body = prbody.render(group, bundle["findings"], meta, _merge_verdicts(bundle["verdicts"], moved, head_sha),
                             bundle["run"])
        labels = list(dict.fromkeys([*(policy.pr.get("labels") or []),
                                     (policy.pr.get("kind_labels") or {}).get(group["kind"], "")]))
        labels = [x for x in labels if x]
        res.update(branch=hb, title=title, autonomy=autonomy, labels=labels, base_moved=moved,
                   files=[c["path"] for c in changes])
        if dry_run:
            res.update(status="dry_run", body=body)
            LOG.info("[dry-run] would open %s -> %s: %s", hb, branch, title)
            budget -= 1
            continue
        try:
            pr = _create(gh, repo, branch, head_sha, hb, title, body, changes, autonomy, labels, group, run)
        except GitHubError as e:
            res.update(status="failed", reason=str(e))
            continue
        res.update(status="opened", number=pr["number"], url=pr["html_url"])
        budget -= 1
        for fid in group["finding_ids"]:
            idx.state[fid] = ("in_flight", {"number": pr["number"], "url": pr["html_url"], "base": branch})
    if out:
        write_json(out, {"results": results, "dry_run": dry_run, "base_moved": moved, "head_sha": head_sha})
    return results


def _merge_verdicts(verdicts: list[dict], moved: bool, head: str) -> dict[str, Any]:
    checks = [c for v in verdicts for c in v.get("checks", [])]
    if moved:
        checks.append({"name": "rebased", "passed": True,
                       "detail": f"base moved after verification; patch re-applied cleanly onto {head[:12]}"})
    return {"checks": checks}


def _create(gh: GitHub, repo: str, branch: str, head_sha: str, hb: str, title: str, body: str,
            changes: list[dict], autonomy: str, labels: list[str], group: dict, run: dict) -> dict:
    base_tree = gh.commit(repo, head_sha)["tree"]["sha"]
    entries = []
    for c in changes:
        if c["content"] is None:
            entries.append({"path": c["path"], "mode": c["mode"], "type": "blob", "sha": None})
        else:
            blob = gh.create_blob(repo, c["content"].encode("utf-8"))
            entries.append({"path": c["path"], "mode": c["mode"], "type": "blob", "sha": blob})
    tree = gh.create_tree(repo, base_tree, entries)
    message = (f"{title}\n\nFixpoint-Findings: {','.join(sorted(group['finding_ids']))}\n"
               f"Fixpoint-Run: {run.get('run_url', '')}\n")
    commit = gh.create_commit(repo, message, tree, [head_sha])
    gh.upsert_ref(repo, hb, commit)
    pr = gh.create_pull(repo, title, hb, branch, body, draft=(autonomy == "draft"))
    try:
        gh.add_labels(repo, pr["number"], labels)
    except GitHubError as e:
        LOG.warning("could not add labels to #%s: %s", pr["number"], e)
    if autonomy == "auto-merge-patch":
        try:
            gh.enable_auto_merge(pr["node_id"])
        except GitHubError as e:
            LOG.warning("auto-merge not enabled on #%s: %s", pr["number"], e)
    LOG.info("opened #%s %s", pr["number"], pr["html_url"])
    return pr
