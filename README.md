# Fixpoint (ai-ssdlc-fixpoint)

Out-of-band AI review → fix → PR engine. Fixpoint reviews a target repository for security flaws,
fixes them with the pinned [AISecCore skills](https://github.com/basusaswata/SecCodeAndRevAgent), proves
each fix (diff rules, OSV re-scan, independent verify skill, build + tests), signs it, and raises a PR.
Target repos get no workflow files and no changes other than those PRs.

- `docs/SETUP.md`: GitHub Apps, secrets, protected environment, runners, egress, skills.lock releases
- `docs/ARCHITECTURE.md`: flow diagram, trust boundaries, privilege table, finding format
- `docs/RUNBOOK.md`: trigger, read the report, handle a bad PR, roll back skills, add an adapter

```
.github/workflows/fixpoint.yml     main pipeline (prepare → fix → verify-ai/verify-build → sign → publish → report)
.github/workflows/reconcile.yml    scheduled outcome loop
.github/workflows/ci.yml           lint + unit tests
.github/actions/setup-fixpoint/    token, pin, checkout/unpack, neutralise, agent, skills
fixpoint/                          Python 3.11 package, CLI `fixpoint`
prompts/                           role prompt templates + guardrail
templates/pr_body.md               PR body
policy/policy.yaml                 limits, forbidden paths, thresholds, branch rules, verify commands
skills.lock                        pinned skills pack + role → skill map
tests/                             unit tests (agent and GitHub mocked, no network)
evals/                             seeded vulnerable repos + metrics
```

## Develop

```bash
python3.11 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check fixpoint tests evals
.venv/bin/python -m pytest
```

Each stage is a CLI subcommand that reads and writes JSON:
`inputs, pin, skills, neutralise, worktree, ingest, discover, align, dedupe, triage, plan, fix, verify, sign,
publish, report, record, local`. `fixpoint <cmd> --help` for arguments.
