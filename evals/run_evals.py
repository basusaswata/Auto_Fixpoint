"""Run Fixpoint against the seeded vulnerable repos and score it.

    python -m evals.run_evals                      # all cases, real agent + OSV
    python -m evals.run_evals --case py-flask-injection --no-build
    python -m evals.run_evals --external /path/to/owasp-benchmark-subset   # dirs with repo/ + expected.json

Needs the agent runtime (claude + ANTHROPIC_API_KEY, skills installed in
FIXPOINT_AGENT_HOME) and network to osv.dev. Exits 1 if any metric regresses
against evals/baseline.json beyond its tolerance. Writes evals/results/<ts>/.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import tarfile
import tempfile
from dataclasses import asdict
from pathlib import Path

from evals import metrics
from fixpoint import log, pipeline, worktree
from fixpoint.agent import get_runtime
from fixpoint.config import load_policy, load_skills_lock
from fixpoint.model import write_json

ROOT = Path(__file__).resolve().parent.parent
LOG = log.get("evals")


def case_dirs(external: list[str], only: list[str]) -> list[Path]:
    dirs = sorted((ROOT / "evals" / "cases").iterdir())
    for ext in external:
        dirs += sorted(p for p in Path(ext).iterdir() if (p / "expected.json").is_file())
    return [d for d in dirs if d.is_dir() and (not only or d.name in only)]


def run_case(case: Path, policy, lock, runtime, out: Path, build: bool) -> metrics.CaseCounts:
    expected = json.loads((case / "expected.json").read_text())
    src = case / "repo"
    files = {p.relative_to(src).as_posix(): p.read_text(encoding="utf-8")
             for p in src.rglob("*") if p.is_file()}
    with tempfile.TemporaryDirectory(prefix=f"fixpoint-eval-{case.name}-") as tmp:
        tar = Path(tmp) / "src.tar"
        with tarfile.open(tar, "w") as tf:
            for rel in files:
                tf.add(src / rel, arcname=rel)
        repo = Path(tmp) / "repo"
        sha = worktree.from_archive(tar, repo)
        run = {"repo": f"evals/{case.name}", "branch": "main", "sha": sha, "mode": "fix", "max_prs": None,
               "sast_report": "", "sca_report": "", "sast_format": "auto", "sca_format": "auto"}
        res = pipeline.run_local(repo, run, policy, lock, runtime, out / case.name, build=build)
    patches = {}
    for g in res.plan["groups"]:
        p = out / case.name / "fix" / g["id"] / "patch.diff"
        if p.is_file():
            patches[g["id"]] = p.read_text()
    verdicts = res.verdicts
    if not build:  # score as if build passed so rescan-only runs still produce a fix rate
        verdicts = verdicts + [{"group_id": v["group_id"], "phase": "build", "passed": True, "checks": []}
                               for v in res.verdicts if v["phase"] == "rescan"]
    counts = metrics.score_case(expected, [f.to_dict() for f in res.findings], res.plan, verdicts, patches, files)
    LOG.info("%s: %s", case.name, {k: v for k, v in asdict(counts).items() if k != "notes"})
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", action="append", default=[])
    ap.add_argument("--external", action="append", default=[])
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--baseline", default=str(ROOT / "evals" / "baseline.json"))
    ap.add_argument("--update-baseline", action="store_true")
    a = ap.parse_args(argv)
    log.setup()
    policy = load_policy(ROOT / "policy" / "policy.yaml")
    policy.raw["limits"]["prs_per_run"] = 100
    policy.raw["limits"]["open_bot_prs_per_repo"] = 100
    lock = load_skills_lock(ROOT / "skills.lock")
    runtime = get_runtime()
    out = ROOT / "evals" / "results" / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    per_case = {c.name: run_case(c, policy, lock, runtime, out, not a.no_build) for c in case_dirs(a.external, a.case)}
    current = metrics.aggregate(list(per_case.values()))
    base = json.loads(Path(a.baseline).read_text())
    regressed = metrics.regressions(current, base["metrics"], float(base.get("tolerance", 0.05)))
    write_json(out / "results.json", {"skills_version": lock.version, "metrics": current,
                                      "cases": {k: asdict(v) for k, v in per_case.items()}, "regressions": regressed})
    print(json.dumps({"skills_version": lock.version, "metrics": current, "regressions": regressed}, indent=2))
    if a.update_baseline:
        write_json(a.baseline, {**base, "metrics": current})
    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main())
