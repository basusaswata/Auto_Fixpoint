"""``fixpoint`` CLI. One subcommand per stage; every stage reads and writes JSON files."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from fixpoint import log

LOG = log.get("fixpoint")


def _policy(a: argparse.Namespace):
    from fixpoint.config import load_policy

    return load_policy(a.policy)


def _lock(a: argparse.Namespace):
    from fixpoint.config import load_skills_lock

    return load_skills_lock(a.skills_lock)


def _run(a: argparse.Namespace) -> dict[str, Any]:
    from fixpoint.model import read_json

    return read_json(a.run)


def _token(name: str) -> str:
    tok = os.environ.get(name, "")
    if not tok:
        raise SystemExit(f"{name} is not set")
    log.register_secret(tok)
    return tok


def _gh(name: str):
    from fixpoint.gh import GitHub

    return GitHub(_token(name))


def _gh_output(**kv: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in kv.items():
            if "\n" in v:
                raise ValueError("multi-line outputs are not supported")
            fh.write(f"{k}={v}\n")


def _runtime():
    from fixpoint.agent import get_runtime

    return get_runtime()


def _load_plan_group(plan_path: str, gid: str) -> tuple[dict, dict]:
    from fixpoint.model import read_json

    plan = read_json(plan_path)
    for g in plan["groups"]:
        if g["id"] == gid:
            return plan, g
    raise SystemExit(f"group {gid} not in plan")


def _group_findings(findings_path: str, group: dict):
    from fixpoint.model import load_findings

    fs, _ = load_findings(findings_path)
    by_id = {f.id: f for f in fs}
    return [by_id[i] for i in group["finding_ids"] if i in by_id]


# -- commands -------------------------------------------------------------------------


def cmd_inputs(a: argparse.Namespace) -> int:
    from fixpoint.model import write_json
    from fixpoint.pipeline import run_context_from_env, validate_inputs

    raw = {k: os.environ.get(f"FP_{k.upper()}", "") for k in
           ("repo", "branch", "sast_report", "sast_format", "sca_report", "sca_format", "mode", "max_prs",
            "dry_run", "actor", "scan_engine")}
    run = run_context_from_env(validate_inputs(raw))
    write_json(a.out, run)
    owner, name = run["repo"].split("/")
    _gh_output(repo=run["repo"], owner=owner, name=name, branch=run["branch"], mode=run["mode"],
               dry_run=str(run["dry_run"]).lower(), sast_report=run["sast_report"], sca_report=run["sca_report"],
               scan_engine=run["scan_engine"])
    return 0


def cmd_pin(a: argparse.Namespace) -> int:
    from fixpoint.model import write_json
    from fixpoint.pipeline import pin

    run = pin(_run(a), _policy(a), _gh("FIXPOINT_READ_TOKEN"))
    write_json(a.run, run)
    _gh_output(sha=run["sha"])
    return 0


def cmd_skills(a: argparse.Namespace) -> int:
    from fixpoint import skills

    if a.action == "hash":
        lock = _lock(a)
        print(skills.tree_sha256(Path(a.dir), lock.paths))
        return 0
    lock = _lock(a)
    skills.check_lock(lock)
    home = Path(a.home or os.environ.get("FIXPOINT_AGENT_HOME") or Path.home())
    tok = os.environ.get("FIXPOINT_READ_TOKEN") or None
    if a.from_dir:
        root = Path(a.from_dir)
        got = skills.tree_sha256(root, lock.paths)
        if got != lock.content_sha256:
            raise SystemExit(f"skills content hash mismatch: expected {lock.content_sha256}, got {got}")
        names = skills.install(root, home, lock)
    else:
        names = skills.fetch_verify_install(lock, home, tok)
    print(json.dumps({"skills_version": lock.version, "installed": names}))
    return 0


def cmd_neutralise(a: argparse.Namespace) -> int:
    from fixpoint.neutralise import baseline, neutralise

    removed = neutralise(Path(a.repo_dir))
    if a.baseline:
        baseline(Path(a.repo_dir))
    print(json.dumps({"removed": removed}))
    return 0


def cmd_worktree(a: argparse.Namespace) -> int:
    from fixpoint import worktree

    if a.action == "archive":
        worktree.archive(Path(a.repo_dir), a.sha, Path(a.tar))
    else:
        worktree.from_archive(Path(a.tar), Path(a.repo_dir))
    return 0


def cmd_toolchain(a: argparse.Namespace) -> int:
    from fixpoint.verify import toolchain

    tc = toolchain(Path(a.repo_dir), _policy(a))
    _gh_output(**tc)
    print(json.dumps(tc))
    return 0


def cmd_ingest(a: argparse.Namespace) -> int:
    from fixpoint.ingest import ingest
    from fixpoint.model import save_findings

    policy = _policy(a)
    report, workspace = a.report, Path(a.workspace) if a.workspace else None
    if a.base_dir and not report.startswith("https://"):
        # a relative report path is a file inside the target repo checkout
        workspace = Path(a.base_dir)
        report = str(workspace / report)
    fs = ingest(report, a.format, a.kind, int(policy.limits.get("report_max_bytes", 26214400)), workspace)
    save_findings(a.out, fs, {f"{a.kind}_mode": "report", f"{a.kind}_format": a.format})
    return 0


def cmd_discover(a: argparse.Namespace) -> int:
    from fixpoint import scan
    from fixpoint.model import save_findings

    run, policy, lock = _run(a), _policy(a), _lock(a)
    fn = scan.discover_sast if a.kind == "sast" else scan.discover_sca
    res = fn(Path(a.repo_dir), run["repo"], run["sha"], policy, lock, _runtime())
    res.meta["skill_version"] = lock.version
    save_findings(a.out, res.findings, res.meta)
    return 0


def cmd_scan(a: argparse.Namespace) -> int:
    """Run an open-source scanner (Semgrep for SAST, OSV-Scanner for SCA) and convert its output."""
    from fixpoint import scanners
    from fixpoint.model import save_findings

    run, lock = _run(a), _lock(a)
    out = Path(a.out)
    res = scanners.scan(a.kind, Path(a.repo_dir), run["sha"], _policy(a), out.parent)
    res.meta["skill_version"] = lock.version
    save_findings(out, res.findings, res.meta)
    print(json.dumps({"kind": a.kind, "findings": len(res.findings)}))
    return 0


def cmd_align(a: argparse.Namespace) -> int:
    from fixpoint import align, scan
    from fixpoint.model import load_findings, merge_findings, save_findings

    run, policy = _run(a), _policy(a)
    groups, meta = [], {"discover_errors": []}
    for p in a.inputs:
        fs, m = load_findings(p)
        groups.append(fs)
        errs = m.pop("discover_errors", [])
        meta.update(m)
        meta["discover_errors"] += errs
    findings = merge_findings(*groups)
    align.align(findings, Path(a.repo_dir), run["sha"], scan.find_manifests(Path(a.repo_dir), policy))
    save_findings(a.out, findings, meta)
    return 0


def cmd_dedupe(a: argparse.Namespace) -> int:
    from fixpoint import dedupe
    from fixpoint.model import load_findings, save_findings

    run = _run(a)
    fs, meta = load_findings(a.inputs)
    idx = dedupe.build_index(_gh("FIXPOINT_READ_TOKEN").fixpoint_prs(run["repo"]), run["branch"])
    dedupe.apply(fs, idx)
    meta["open_bot_prs"] = idx.open_bot_prs
    save_findings(a.out, fs, meta)
    return 0


def cmd_triage(a: argparse.Namespace) -> int:
    from fixpoint import triage
    from fixpoint.model import load_findings, save_findings

    run = _run(a)
    fs, meta = load_findings(a.inputs)
    triage.triage(fs, Path(a.repo_dir), run["repo"], run["sha"], _policy(a), _lock(a), _runtime())
    save_findings(a.out, fs, meta)
    return 0


def cmd_plan(a: argparse.Namespace) -> int:
    from fixpoint import plan
    from fixpoint.model import load_findings, write_json

    run = _run(a)
    fs, meta = load_findings(a.inputs)
    p = plan.plan(fs, _policy(a), run["branch"], run.get("max_prs"), int(meta.get("open_bot_prs", 0)))
    if run.get("mode") != "fix":
        p["meta"]["note"] = "review mode: nothing will be fixed or published"
    write_json(a.out, p)
    ids = [g["id"] for g in p["groups"]] if run.get("mode") == "fix" else []
    _gh_output(groups=json.dumps(ids, separators=(",", ":")), has_groups=str(bool(ids)).lower())
    return 0


def cmd_fix(a: argparse.Namespace) -> int:
    from fixpoint import fix

    run = _run(a)
    _, group = _load_plan_group(a.plan, a.group)
    meta = fix.run_fix(group, _group_findings(a.findings, group), Path(a.repo_dir), run["repo"], run["sha"],
                       _policy(a), _lock(a), _runtime(), Path(a.out_dir))
    print(json.dumps({"group_id": group["id"], "status": meta["status"]}))
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    from fixpoint import verify
    from fixpoint.model import read_json, write_json

    run = _run(a)
    _, group = _load_plan_group(a.plan, a.group)
    gdir = Path(a.fix_dir) / group["id"]
    out = Path(a.out_dir) / f"{group['id']}.{a.phase}.verdict.json"
    if not (gdir / "patch.diff").is_file():
        write_json(out, {"group_id": group["id"], "phase": a.phase, "passed": False, "patch_sha256": "",
                         "checks": [{"name": "patch", "passed": False, "detail": "no patch from fix job"}]})
        return 0
    patch = (gdir / "patch.diff").read_text(encoding="utf-8")
    meta = read_json(gdir / "meta.json")
    policy = _policy(a)
    if a.phase == "build":
        v = verify.verify_build(group, patch, meta, Path(a.repo_dir), policy)
    else:
        v = verify.verify_rescan(group, _group_findings(a.findings, group), patch, meta, Path(a.repo_dir),
                                 run["repo"], run["sha"], policy, _lock(a), _runtime())
    write_json(out, v)
    LOG.info("verify %s %s: %s", a.phase, group["id"], "PASS" if v["passed"] else "FAIL")
    return 0


def cmd_fix_all(a: argparse.Namespace) -> int:
    """Single-job mode: fix every planned group, then AI-verify it, in one checkout."""
    from fixpoint import fix, verify, worktree
    from fixpoint.model import load_findings, read_json, write_json

    run, policy, lock, runtime = _run(a), _policy(a), _lock(a), _runtime()
    plan = read_json(a.plan)
    fs, _ = load_findings(a.findings)
    by_id = {f.id: f for f in fs}
    repo_dir, out = Path(a.repo_dir), Path(a.out_dir)
    for g in plan["groups"]:
        gf = [by_id[i] for i in g["finding_ids"] if i in by_id]
        meta = fix.run_fix(g, gf, repo_dir, run["repo"], run["sha"], policy, lock, runtime, out / "fix")
        if meta["status"] != "patched":
            LOG.info("fix %s: %s", g["id"], meta["status"])
            continue
        patch = (out / "fix" / g["id"] / "patch.diff").read_text(encoding="utf-8")
        v = verify.verify_rescan(g, gf, patch, meta, repo_dir, run["repo"], run["sha"], policy, lock, runtime)
        worktree.reset(repo_dir)
        write_json(out / "verdicts" / f"{g['id']}.rescan.verdict.json", v)
        LOG.info("verify rescan %s: %s", g["id"], "PASS" if v["passed"] else "FAIL")
    return 0


def cmd_build_all(a: argparse.Namespace) -> int:
    """Single-job mode: install/build/test every patch that passed the AI re-scan."""
    from fixpoint import verify, worktree
    from fixpoint.model import read_json, write_json

    policy = _policy(a)
    plan = read_json(a.plan)
    repo_dir, out = Path(a.repo_dir), Path(a.out_dir)
    for g in plan["groups"]:
        rescan = out / "verdicts" / f"{g['id']}.rescan.verdict.json"
        if not rescan.is_file() or not read_json(rescan).get("passed"):
            continue  # no point building a patch that already failed
        gdir = out / "fix" / g["id"]
        patch = (gdir / "patch.diff").read_text(encoding="utf-8")
        v = verify.verify_build(g, patch, read_json(gdir / "meta.json"), repo_dir, policy)
        worktree.reset(repo_dir)
        write_json(out / "verdicts" / f"{g['id']}.build.verdict.json", v)
        LOG.info("verify build %s: %s", g["id"], "PASS" if v["passed"] else "FAIL")
    return 0


def cmd_sign(a: argparse.Namespace) -> int:
    from fixpoint import sign
    from fixpoint.model import read_json

    findings = {f["id"]: f for f in read_json(a.findings)["findings"]}
    res = sign.sign_all(read_json(a.plan), findings, Path(a.fix_dir), [Path(d) for d in a.verdict_dir], _run(a),
                        _policy(a), Path(a.out_dir), a.signing)
    print(json.dumps({r["group_id"]: r["status"] for r in res}))
    return 0


def cmd_publish(a: argparse.Namespace) -> int:
    from fixpoint import publish

    tok = "FIXPOINT_READ_TOKEN" if a.dry_run and not os.environ.get("FIXPOINT_WRITE_TOKEN") else "FIXPOINT_WRITE_TOKEN"
    res = publish.publish(Path(a.bundles), _run(a), _policy(a), _gh(tok), a.identity, a.dry_run, a.signing,
                          Path(a.out), allow_unsigned=a.allow_unsigned)
    for r in res:
        line = f"{r['status']:>8}  {r.get('group_id', r.get('bundle'))}  {r.get('url') or r.get('reason', '')}"
        print(line)
        if r["status"] == "dry_run":
            print(f"          branch: {r['branch']}  autonomy: {r['autonomy']}  labels: {r['labels']}")
            print(f"          title:  {r['title']}")
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    from fixpoint import report

    run = _run(a) if a.run and Path(a.run).is_file() else {}
    paths = report.build(Path(a.findings), Path(a.plan) if a.plan else None, Path(a.fix_dir) if a.fix_dir else None,
                         Path(a.sign) if a.sign else None, Path(a.publish) if a.publish else None, run,
                         Path(a.out_dir))
    summary = paths["summary"].read_text(encoding="utf-8")
    if a.job_summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary)
    print(summary)
    return 0


def cmd_record(a: argparse.Namespace) -> int:
    from fixpoint import record
    from fixpoint.model import write_json

    policy = _policy(a)
    gh = _gh("FIXPOINT_READ_TOKEN")
    prefix = policy.pr.get("reason_label_prefix", "fixpoint-reason/")
    recs = []
    for repo in a.repo:
        recs += record.outcomes(gh, repo, a.since_days, prefix)
    payload = {"outcomes": recs, "merged": sum(r["outcome"] == "merged" for r in recs),
               "rejected": sum(r["outcome"] == "rejected" for r in recs)}
    write_json(a.out, payload)
    if a.evals_out:
        write_json(a.evals_out, {"cases": record.eval_cases(recs)})
    url = os.environ.get("FIXPOINT_METRICS_URL")
    if url:
        record.post_metrics(url, os.environ.get("FIXPOINT_METRICS_TOKEN"), payload)
    print(json.dumps({"merged": payload["merged"], "rejected": payload["rejected"]}))
    return 0


def cmd_local(a: argparse.Namespace) -> int:
    from fixpoint import pipeline

    run = {"repo": a.repo, "branch": a.branch, "sha": a.sha or "0" * 40, "mode": "fix", "max_prs": a.max_prs,
           "sast_report": a.sast_report or "", "sast_format": "auto", "sca_report": a.sca_report or "",
           "sca_format": "auto"}
    res = pipeline.run_local(Path(a.repo_dir), run, _policy(a), _lock(a), _runtime(), Path(a.out_dir),
                             build=not a.no_build)
    print(json.dumps({"findings": len(res.findings), "groups": len(res.plan["groups"]),
                      "patched": sum(m["status"] == "patched" for m in res.fixes),
                      "verified": sum(v["passed"] for v in res.verdicts)}))
    return 0


# -- parser -----------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fixpoint", description=__doc__)
    p.add_argument("--policy", default=os.environ.get("FIXPOINT_POLICY", "policy/policy.yaml"))
    p.add_argument("--skills-lock", default=os.environ.get("FIXPOINT_SKILLS_LOCK", "skills.lock"))
    p.add_argument("--log-level", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("inputs", help="validate run inputs from FP_* env vars")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_inputs)

    s = sub.add_parser("pin", help="resolve branch to a commit SHA (read token)")
    s.add_argument("--run", required=True)
    s.set_defaults(fn=cmd_pin)

    s = sub.add_parser("skills", help="install or hash the pinned skills pack")
    s.add_argument("action", choices=["install", "hash"])
    s.add_argument("--home")
    s.add_argument("--dir", help="(hash) directory containing the pack paths")
    s.add_argument("--from-dir", help="(install) install from a local copy instead of fetching")
    s.set_defaults(fn=cmd_skills)

    s = sub.add_parser("neutralise", help="strip agent config from a target checkout")
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--baseline", action="store_true", help="commit a local baseline after neutralising")
    s.set_defaults(fn=cmd_neutralise)

    s = sub.add_parser("worktree", help="archive a pinned tree / unpack it into a sandbox")
    s.add_argument("action", choices=["archive", "unpack"])
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--tar", required=True)
    s.add_argument("--sha", default="HEAD")
    s.set_defaults(fn=cmd_worktree)

    s = sub.add_parser("toolchain", help="report the build toolchain verify-build must install")
    s.add_argument("--repo-dir", required=True)
    s.set_defaults(fn=cmd_toolchain)

    s = sub.add_parser("ingest", help="REPORT mode: adapt a scanner report")
    s.add_argument("--kind", choices=["sast", "sca"], required=True)
    s.add_argument("--report", required=True)
    s.add_argument("--format", default="auto")
    s.add_argument("--workspace")
    s.add_argument("--base-dir", help="resolve a relative report path inside this directory (the target repo)")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser("discover", help="DISCOVER mode: scan with the skill (SAST) or skill+OSV (SCA)")
    s.add_argument("--kind", choices=["sast", "sca"], required=True)
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_discover)

    s = sub.add_parser("scan", help="scanner mode: run Semgrep (sast) or OSV-Scanner (sca) and convert the output")
    s.add_argument("--kind", choices=["sast", "sca"], required=True)
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--out", required=True, help="findings JSON; the raw scanner output is written next to it")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("align", help="merge findings and re-anchor them to the pinned commit")
    s.add_argument("--in", dest="inputs", action="append", required=True)
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_align)

    for name, fn, helptext in (("dedupe", cmd_dedupe, "resolve in_flight/fixed/rejected from GitHub"),
                               ("triage", cmd_triage, "disposition each open finding"),
                               ("plan", cmd_plan, "group, order and cap fixes")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--in", dest="inputs", required=True)
        s.add_argument("--run", required=True)
        s.add_argument("--out", required=True)
        if name == "triage":
            s.add_argument("--repo-dir", required=True)
        s.set_defaults(fn=fn)

    s = sub.add_parser("fix", help="fix one plan group in the sandbox")
    s.add_argument("--plan", required=True)
    s.add_argument("--findings", required=True)
    s.add_argument("--group", required=True)
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--out-dir", required=True)
    s.set_defaults(fn=cmd_fix)

    s = sub.add_parser("verify", help="verify one patch (phase rescan or build)")
    s.add_argument("--phase", choices=["rescan", "build"], required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--findings", required=True)
    s.add_argument("--group", required=True)
    s.add_argument("--fix-dir", required=True)
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--out-dir", required=True)
    s.set_defaults(fn=cmd_verify)

    for name, fn, helptext in (("fix-all", cmd_fix_all, "single job: fix + AI-verify every planned group"),
                               ("build-all", cmd_build_all, "single job: install/build/test every verified patch")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--plan", required=True)
        s.add_argument("--findings", required=True)
        s.add_argument("--repo-dir", required=True)
        s.add_argument("--run", required=True)
        s.add_argument("--out-dir", required=True, help="writes <out-dir>/fix/<group>/ and <out-dir>/verdicts/")
        s.set_defaults(fn=fn)

    s = sub.add_parser("sign", help="bundle and sign verified patches (cosign keyless)")
    s.add_argument("--plan", required=True)
    s.add_argument("--findings", required=True)
    s.add_argument("--fix-dir", required=True)
    s.add_argument("--verdict-dir", action="append", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--out-dir", required=True)
    s.add_argument("--signing", choices=["cosign", "none"], default="cosign")
    s.set_defaults(fn=cmd_sign)

    s = sub.add_parser("publish", help="verify signatures and raise PRs (write token)")
    s.add_argument("--bundles", required=True)
    s.add_argument("--run", required=True)
    s.add_argument("--identity", default=os.environ.get("FIXPOINT_SIGNER_IDENTITY", ""))
    s.add_argument("--out", required=True)
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--signing", choices=["cosign", "none"], default="cosign")
    s.add_argument("--allow-unsigned", action="store_true",
                   help="single-job mode: bundles were built in this same job, no signed handoff")
    s.set_defaults(fn=cmd_publish)

    s = sub.add_parser("report", help="summary.md, dispositioned SARIF, OpenVEX")
    s.add_argument("--findings", required=True)
    s.add_argument("--plan")
    s.add_argument("--fix-dir")
    s.add_argument("--sign")
    s.add_argument("--publish")
    s.add_argument("--run")
    s.add_argument("--out-dir", required=True)
    s.add_argument("--job-summary", action="store_true")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("record", help="record outcomes of closed Fixpoint PRs")
    s.add_argument("--repo", action="append", required=True)
    s.add_argument("--since-days", type=int, default=7)
    s.add_argument("--out", required=True)
    s.add_argument("--evals-out")
    s.set_defaults(fn=cmd_record)

    s = sub.add_parser("local", help="run discover -> verify locally on a checkout (no sign/publish)")
    s.add_argument("--repo-dir", required=True)
    s.add_argument("--repo", default="local/repo")
    s.add_argument("--branch", default="main")
    s.add_argument("--sha")
    s.add_argument("--max-prs", type=int)
    s.add_argument("--sast-report")
    s.add_argument("--sca-report")
    s.add_argument("--out-dir", default="out")
    s.add_argument("--no-build", action="store_true")
    s.set_defaults(fn=cmd_local)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log.setup(args.log_level)
    try:
        return int(args.fn(args) or 0)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - top-level: log redacted, fail the step
        LOG.error("%s failed: %s: %s", args.cmd, type(e).__name__, log.redact(str(e))[:1000])
        if os.environ.get("FIXPOINT_DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
