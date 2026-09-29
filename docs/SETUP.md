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
| `FIXPOINT_RUNNER` | `["ubuntu-latest"]` (default) | JSON array of labels |
| `FIXPOINT_BUILD_RUNNER` | `["ubuntu-latest"]` | optional separate pool for target code |
| `FIXPOINT_EGRESS_POLICY` | `block` | `audit` to observe first |
| `FIXPOINT_EXTRA_ENDPOINTS` | `artifactory.example.com:443` | extra allowed hosts |
| `FIXPOINT_JAVA_VERSION` | `17` | JDK when the repo pins none |
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

### Default: GitHub-hosted runners (`ubuntu-latest`), nothing pre-installed

Fixpoint assumes a bare Ubuntu VM and installs everything itself, pinned:

| Tool | Installed by | Jobs |
|---|---|---|
| git, tar, unzip | `apt-get` (only if missing) | all that use the composite action |
| Python 3.11 + `fixpoint` (`pyyaml`, `requests`) | `actions/setup-python` + `pip` | all |
| Node.js 20 + Claude Code `FIXPOINT_CLAUDE_VERSION` | `actions/setup-node` + `npm install -g` | prepare, fix, verify-ai |
| AISecCore skills (commit + hash from `skills.lock`) | `fixpoint skills install` | prepare, fix, verify-ai |
| cosign | `sigstore/cosign-installer` | sign, publish |
| Target build toolchain, detected from the repo's marker file | `fixpoint toolchain` + setup actions | verify-build only |

Build toolchain per marker (versions from the repo's own files when present):

| Marker | Installed | Version from |
|---|---|---|
| `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` | Node.js + `corepack enable` (yarn/pnpm) | `.nvmrc` / `.node-version`, else 20 |
| `pom.xml` | Temurin JDK + Maven (`apt`, unless `./mvnw` exists) | `.java-version` / `.sdkmanrc` / `.tool-versions`, else `FIXPOINT_JAVA_VERSION` (17) |
| `build.gradle(.kts)` | Temurin JDK; the repo's `./gradlew` downloads Gradle | as above |
| `go.mod` | Go (`cache: false`) | `go.mod` |
| `pyproject.toml`, `requirements.txt` | Python (+ a throwaway venv per build, pytest added) | `.python-version`, else 3.11 |

Hosted runners are ephemeral VMs (one job, then destroyed), which is the isolation Fixpoint wants for jobs
that touch untrusted code. No caches are used anywhere, so target code can never poison this repo's
Actions cache.

### Egress allowlist on hosted runners

You cannot firewall a GitHub-hosted VM, so every job starts with
[`step-security/harden-runner`](https://github.com/step-security/harden-runner) (pinned by SHA) in
**`block`** mode with the allowlist in `FIXPOINT_ALLOWED_ENDPOINTS` (top of `fixpoint.yml` / `reconcile.yml`):

| Destination | Purpose |
|---|---|
| `github.com`, `api.github.com`, `codeload.github.com`, `*.githubusercontent.com`, `*.actions.githubusercontent.com`, `*.blob.core.windows.net` | Actions runtime, artifacts, API, action + tool downloads |
| `api.anthropic.com` | model |
| `api.osv.dev` | vulnerability data |
| `fulcio.sigstore.dev`, `rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev` | keyless signing / verification |
| `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `registry.yarnpkg.com`, `nodejs.org` | Python / Node packages and runtimes |
| `repo.maven.apache.org`, `repo1.maven.org`, `services.gradle.org`, `plugins.gradle.org`, `downloads.gradle.org`, `api.adoptium.net` | Java |
| `proxy.golang.org`, `sum.golang.org`, `go.dev`, `dl.google.com`, `storage.googleapis.com` | Go |
| `*.archive.ubuntu.com`, `security.ubuntu.com` | apt (git / maven only if missing) |

Variables:

- `FIXPOINT_EGRESS_POLICY`: `block` (default) or `audit`. Use `audit` for a first run if a target repo needs
  hosts you haven't listed; harden-runner's insights page then shows every destination it called.
- `FIXPOINT_EXTRA_ENDPOINTS`: space-separated `host:443` entries appended to the list, e.g. a private
  registry or a Bedrock/Vertex endpoint.
- `FIXPOINT_DISABLE_SUDO`: `false` by default, because the composite action may `apt-get install` git or Maven.

Trade-off: harden-runner's community tier sends a job's network insights (destinations, not payloads) to
StepSecurity. If that is not acceptable, use self-hosted runners with a network-level allowlist instead.

### Alternative: self-hosted runners

Set `FIXPOINT_RUNNER` (and optionally `FIXPOINT_BUILD_RUNNER` / `FIXPOINT_PUBLISH_RUNNER`) to a JSON label list,
e.g. `["self-hosted","linux","fixpoint-sandbox"]`. Use ephemeral, non-root runners without cloud metadata
access, enforce the same destinations at the network layer, and set `FIXPOINT_EGRESS_POLICY=audit` (or keep
harden-runner, which also supports self-hosted). Pre-installing the pinned Claude Code version and your
toolchains in the image is optional; the install steps run either way and pin the same versions.

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
