# Fixpoint setup

## 1. Two GitHub Apps

Create both at the org level (**Settings → Developer settings → GitHub Apps → New**). Disable webhooks.
Neither App needs any event subscriptions.

### `fixpoint-read`

| Repository permission | Access | Why |
|---|---|---|
| Contents | Read | pin, checkout, read files |
| Pull requests | Read | dedupe, reconcile |
| Issues | Read | reconcile reads closing comments |
| Metadata | Read | mandatory |

### `fixpoint-write`

| Repository permission | Access | Why |
|---|---|---|
| Contents | Read & write | blobs, trees, commits, `fixpoint/*` branches |
| Pull requests | Read & write | open PRs, enable auto-merge |
| Issues | Read & write | labels on PRs |
| Metadata | Read | mandatory |

Do **not** grant Workflows, Actions, Administration or Secrets. Without `workflows` the App cannot create or
modify `.github/workflows/*` even if every other check failed.

Commits created through the Git Data API without an explicit author are signed by GitHub and show as
**Verified**, authored by `fixpoint-write[bot]`.

### Installing

Install both Apps on each target repo you enrol (and nothing else). The skills repo
`basusaswata/SecCodeAndRevAgent` is public, so no installation is needed there; if you make it private,
also install `fixpoint-read` on it and pass its token to `fixpoint skills install` (`FIXPOINT_READ_TOKEN`).

Workflows request tokens with `owner` + `repositories: <target>`, so every token is scoped to one repo and
expires within an hour.

## 2. Secrets, variables, environment

In `ai-ssdlc-fixpoint` → Settings:

**Variables**

| Name | Example | Notes |
|---|---|---|
| `FIXPOINT_READ_APP_ID` | `123456` | |
| `FIXPOINT_WRITE_APP_ID` | `123457` | set on the `fixpoint-publish` environment |
| `FIXPOINT_MODEL` | `claude-sonnet-5-5` | default if unset |
| `FIXPOINT_CLAUDE_VERSION` | `2.1.212` | pinned Claude Code version |
| `FIXPOINT_RUNNER` | `["self-hosted","linux","fixpoint-sandbox"]` | JSON array of labels |
| `FIXPOINT_BUILD_RUNNER` | `["self-hosted","linux","fixpoint-build"]` | optional separate pool for target code |
| `FIXPOINT_PUBLISH_RUNNER` | `["self-hosted","linux","fixpoint-publish"]` | optional hardened pool |
| `FIXPOINT_METRICS_URL` | `https://metrics.example.com/fixpoint` | optional, reconcile POST |

**Repository secrets**

| Name | Used by |
|---|---|
| `FIXPOINT_READ_APP_KEY` | prepare, publish (dry run), reconcile |
| `FIXPOINT_ANTHROPIC_API_KEY` | prepare, fix, verify-ai |
| `FIXPOINT_METRICS_TOKEN` | reconcile (optional) |

**Environment `fixpoint-publish`** (Settings → Environments → New):

- Secret `FIXPOINT_WRITE_APP_KEY` (environment secret, not repository secret).
- Variable `FIXPOINT_WRITE_APP_ID`.
- Deployment branches: **Selected branches → `main` only**. This stops a modified workflow on another branch
  from reaching the write key.
- Optional: required reviewers, if a human should approve each publish.

Protect `main` of `ai-ssdlc-fixpoint` (reviews required, CODEOWNERS on `policy/`, `skills.lock`,
`.github/`). The cosign signer identity is `https://github.com/<org>/ai-ssdlc-fixpoint/.github/workflows/fixpoint.yml@refs/heads/main`.

**Model access alternatives.** The default is a direct API key. For Amazon Bedrock set
`CLAUDE_CODE_USE_BEDROCK=1` and AWS credentials on the AI steps (add an OIDC role step to those jobs);
for Vertex set `CLAUDE_CODE_USE_VERTEX=1` with Workload Identity Federation. `fixpoint/agent.py` already
passes those variables through; nothing else changes.

**GHES.** The Python code reads `GITHUB_API_URL` / `GITHUB_GRAPHQL_URL` (set by Actions). For signing set
`FIXPOINT_OIDC_ISSUER=https://<ghes-host>/_services/token` on the publish job and point cosign at your
Sigstore instance if public Sigstore is not reachable.

## 3. Runners and egress

Self-hosted, **ephemeral** (one job per VM/container, destroyed afterwards), non-root, no cloud metadata
access. Labels: `self-hosted, linux, fixpoint-sandbox` (configurable above). Images need: `git`, Python
3.11, Node.js 20+ (Claude Code), `cosign` (installed by the workflow), and the toolchains of your target
repos for `verify-build` (Node/npm, JDK + Maven/Gradle, Go, Python + pytest ...). Pre-installing the pinned
Claude Code version in the image avoids an npm download per job.

Egress allowlist (deny everything else):

| Destination | Jobs | Purpose |
|---|---|---|
| `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `*.actions.githubusercontent.com`, `pipelines.actions.githubusercontent.com`, `results-receiver.actions.githubusercontent.com`, `*.blob.core.windows.net` | all | Actions runtime, artifacts, API, skills fetch |
| `api.anthropic.com` (or your Bedrock/Vertex endpoint) | prepare, fix, verify-ai | model |
| `api.osv.dev` | prepare, verify-ai | vulnerability data |
| `fulcio.sigstore.dev`, `rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev` | sign, publish | keyless signing / verification |
| your package mirror (e.g. `artifactory.example.com`) | verify-build (+ npm for Claude Code if not pre-installed) | dependencies |

`verify-build` should reach only the package mirror. Set `PIP_INDEX_URL`, `NPM_CONFIG_REGISTRY`, `GOPROXY`
etc. in the runner image; `policy.verify.pass_env` passes only those through to target code. Optionally set
`policy.verify.sandbox_prefix` to a `bwrap`/container wrapper for an extra layer.

## 4. Enrol a repo

Add it to `enrolled_repos` in `policy/policy.yaml` via PR, install both Apps on it, then trigger a
`mode: review` run first.

## 5. skills.lock release process

`skills.lock` pins the AISecCore pack by commit and content hash. To upgrade:

1. Pick the new commit (or tag) of `basusaswata/SecCodeAndRevAgent`.
2. Compute the hash:
   ```bash
   git clone https://github.com/basusaswata/SecCodeAndRevAgent /tmp/sk && git -C /tmp/sk checkout <sha>
   fixpoint skills hash --dir /tmp/sk
   ```
3. Update `commit` and `content_sha256` (and `roles` if skill names changed).
4. Run the evals (`python -m evals.run_evals`) with the new pack installed; attach `evals/results/*/results.json`
   to the PR. The run fails if any metric regresses beyond the baseline tolerance.
5. Merge after review; update `evals/baseline.json` in the same PR if the numbers improved.

Release-asset mode: when the skills repo publishes signed tarballs, set `source: release`, `tag`, `asset`,
`sha256` and `require_attestation: true` (uses `gh attestation verify` on the runner).
