# Fixpoint setup

## 1. One GitHub App

Create one App (org **Settings → Developer settings → GitHub Apps → New**), e.g. `fixpoint-bot`. Disable
webhooks; no event subscriptions.

| Repository permission | Access | Why |
|---|---|---|
| Contents | Read & write | checkout, blobs/trees/commits, `fixpoint/*` branches |
| Pull requests | Read & write | dedupe, open PRs, auto-merge |
| Issues | Read & write | labels on PRs, reconcile reads closing comments |
| Metadata | Read | mandatory |

Do **not** grant Workflows, Actions, Administration or Secrets: without `workflows` the App cannot touch
`.github/workflows/*` even if every other check failed.

Install it on each target repo you enrol, and nothing else. The skills repo
`basusaswata/SecCodeAndRevAgent` is public, so no installation is needed there.

Commits are created through the Git Data API without an explicit author, so GitHub signs them and shows
them as **Verified**, authored by `fixpoint-bot[bot]`.

## 2. Secrets and variables

In `ai-ssdlc-fixpoint` → Settings → Secrets and variables → Actions:

| Kind | Name | Value |
|---|---|---|
| Variable | `FIXPOINT_APP_ID` | the App id |
| Secret | `FIXPOINT_APP_KEY` | the App private key (PEM) |
| Secret | `FIXPOINT_ANTHROPIC_API_KEY` | Anthropic API key |
| Variable (optional) | `FIXPOINT_MODEL` | default `claude-sonnet-5-5` |
| Variable (optional) | `FIXPOINT_CLAUDE_VERSION` | default `2.1.212` |
| Variable (optional) | `FIXPOINT_JAVA_VERSION` | JDK when a Java repo pins none (default 17) |
| Variable (optional) | `FIXPOINT_METRICS_URL` / secret `FIXPOINT_METRICS_TOKEN` | reconcile POST |

Protect `main` of `ai-ssdlc-fixpoint` (reviews required on `policy/`, `skills.lock`, `.github/`): whoever can
change the workflow can use the App key.

## 3. Runner: one GitHub-hosted job, nothing pre-installed

`fixpoint.yml` is a single job on `ubuntu-latest`. It installs everything itself, pinned:

| Tool | Installed by |
|---|---|
| git (if missing) | `apt-get` |
| Python 3.11 + `fixpoint` CLI (`pyyaml`, `requests`) | `actions/setup-python` + `pip install .` |
| Node.js 20 + Claude Code `FIXPOINT_CLAUDE_VERSION` | `actions/setup-node` + `npm install -g` |
| AISecCore skills (commit + hash from `skills.lock`) | `fixpoint skills install` |
| Target build toolchain (only in `mode: fix` with planned fixes) | `fixpoint toolchain` + the matching setup action |

Build toolchain per marker file (versions from the repo's own files when present):

| Marker | Installed | Version from |
|---|---|---|
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` | Node.js + `corepack enable` | `.nvmrc` / `.node-version`, else 20 |
| `pom.xml` | Temurin JDK + Maven (`apt`, unless `./mvnw` exists) | `.java-version` / `.sdkmanrc` / `.tool-versions`, else 17 |
| `build.gradle(.kts)` | Temurin JDK; the repo's `./gradlew` fetches Gradle | as above |
| `go.mod` | Go (`cache: false`) | `go.mod` |
| `pyproject.toml`, `requirements.txt` | Python; a throwaway venv per build, pytest added | `.python-version`, else 3.11 |

### POC security trade-offs of the single job

Everything shares one VM, so the separation is per step rather than per job:

- The model key is only in the environment of the AI steps (discover, triage, fix + verify).
- The App token used for checkout and dedupe is **revoked** before any target-repo code runs; a fresh token is
  minted only for the final "Raise PRs" step.
- The install/build/test step has no secrets in its environment, and child processes get a scrubbed env.
- No egress allowlist is enforced (a hosted VM cannot be firewalled from the workflow).
- Bundles are not cosign-signed: nothing crosses a job boundary, so `publish --allow-unsigned` is used.

Target-repo code still runs on the same VM as a process that held secrets earlier. For production, go back to
the split multi-job pipeline (git history, commit `70a5ec0`) with signed handoff and a protected environment.

Hosts the job contacts, for when you move to an enforced allowlist:

| Destination | Purpose |
|---|---|
| `github.com`, `api.github.com`, `codeload.github.com`, `*.githubusercontent.com`, `*.actions.githubusercontent.com`, `*.blob.core.windows.net` | Actions runtime, artifacts, API, action + tool downloads |
| `api.anthropic.com` | model |
| `api.osv.dev` | vulnerability data |
| `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `registry.yarnpkg.com`, `nodejs.org` | Python / Node |
| `repo.maven.apache.org`, `repo1.maven.org`, `services.gradle.org`, `plugins.gradle.org`, `downloads.gradle.org`, `api.adoptium.net` | Java |
| `proxy.golang.org`, `sum.golang.org`, `go.dev`, `dl.google.com`, `storage.googleapis.com` | Go |
| `*.archive.ubuntu.com`, `security.ubuntu.com` | apt (git / maven only if missing) |

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
