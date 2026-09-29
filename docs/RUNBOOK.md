# Fixpoint runbook

## Trigger a run

**UI:** Actions → `fixpoint` → Run workflow. Start every new repo with `mode: review`.

**CLI:**
```bash
gh workflow run fixpoint.yml -R <org>/ai-ssdlc-fixpoint -f repo=<org>/<repo> -f branch=main -f mode=review
```

**From another system** (`repository_dispatch`, same fields in `client_payload`):
```bash
gh api repos/<org>/ai-ssdlc-fixpoint/dispatches -f event_type=fixpoint-sweep \
  -F client_payload[repo]=<org>/<repo> -F client_payload[branch]=release/2.3 \
  -F client_payload[mode]=fix -F client_payload[max_prs]=2 -F client_payload[requested_by]=<login>
```

Inputs: `repo`, `branch` (required); `sast_report`, `sca_report` (https URL or a path in the Fixpoint
workspace; empty = DISCOVER), `sast_format` (`auto|sarif`), `sca_format` (`auto|snyk|osv|sarif`), `mode`
(`review|fix`), `max_prs`, `dry_run`. One run per repo+branch at a time; later ones queue.

Local, without GitHub (skills installed in `FIXPOINT_AGENT_HOME`, `ANTHROPIC_API_KEY` set):
```bash
fixpoint local --repo-dir /path/to/checkout --out-dir out --no-build
```

## Read the report

The `report` job writes the job summary and uploads `fixpoint-report` with:

- `summary.md`: which mode each scan type used (REPORT/DISCOVER and engine), counts per status and
  disposition, PR links, patches that were not published and why (fix failure, failed verify check, signature,
  conflict, dedupe), deferred groups (cap, no fixed version in strategy), `human_review` items, stale and
  unlocatable findings, and discover errors.
- `fixpoint.sarif`: every finding. Non-fix dispositions carry a SARIF `suppression` with the justification;
  `human_review` is `underReview`. Upload it to code scanning if you want it in the Security tab.
- `openvex.json`: SCA statements (`not_reachable` → `not_affected` / `vulnerable_code_not_in_execute_path`;
  `fix` → `affected` + action).

Intermediate artifacts (`prepare`, `fix-*`, `verdict-*`, `signed`, `publish`) hold every stage's JSON for
debugging; each stage can be re-run locally from them with the same CLI subcommand.

## Handle a bad PR

1. **Close it without merging** and add a label `fixpoint-reason/<reason>` (`false-positive`, `wrong-fix`,
   `breaks-behaviour`, `accepted-risk`, `duplicate`), or leave a comment saying why before closing.
2. That's all. Dedupe marks its findings `rejected`; Fixpoint will not raise them again on any branch.
   `reconcile.yml` records the outcome and exports an eval case.
3. If the PR was harmful (touched something it shouldn't have), treat it as an incident: check the run's
   `signed/*.bundle.json` and verdicts, tighten `policy.yaml` (`forbidden_paths`, limits), and add an eval case.
4. To stop Fixpoint for a repo immediately, remove it from `enrolled_repos` (pin and publish both refuse), or
   disable the workflow.

To undo a rejection (a human changed their mind), reopen the original PR or fix it by hand; Fixpoint never
overrides a human "no".

## Roll back a skills version

1. Revert the `skills.lock` commit (restores the previous `commit` + `content_sha256`), via PR.
2. Merge. The next run installs the old pack; hashes are verified, so a partial rollback cannot happen.
3. Open PRs raised with the bad version show it in their body (`Skill: ... from <repo>@<sha>`) and in the
   hidden metadata; search `is:pr is:open head:fixpoint/ "SecCodeAndRevAgent@<bad sha>"` and close the
   suspicious ones with `fixpoint-reason/wrong-fix`.

## Add a scanner adapter

1. Add `fixpoint/adapters/<name>.py` with `parse(doc, kind) -> list[Finding]`. Map CWE/CVE ids, severity,
   file/line and a verbatim `snippet` (without a snippet, SAST findings are only locatable when the report's
   revision equals the pinned SHA).
2. Register it in `fixpoint/adapters/__init__.py` (`ADAPTERS`, `FORMATS_FOR_KIND`, `detect`).
3. Add a real-world sample to `tests/fixtures/` and tests in `tests/test_adapters.py` (fields, auto-detect,
   stable ids).
4. Add the format to the `choice` options in `.github/workflows/fixpoint.yml` and `FORMATS` in
   `fixpoint/pipeline.py`.

## Other operations

- **Raise caps:** `limits` in `policy/policy.yaml` (the `max_prs` input can only lower them).
- **Enable auto-merge:** set a branch rule to `autonomy: auto-merge-patch`; only patch-level SCA bumps qualify,
  and the target repo must allow auto-merge with required checks.
- **Switch SCA to OSV-Scanner:** install `osv-scanner` on the runner image and set `discover.sca.engine:
  osv-scanner`.
- **Re-run a failed publish:** re-run the `publish` job; dedupe and the open-PR check make it idempotent.
  Bundles are bound to the run id, so bundles from an older run are rejected.
