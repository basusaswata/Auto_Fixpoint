# Fixpoint architecture

Fixpoint reviews a target repository out of band, fixes what it can prove, and raises pull requests.
It lives in its own repo; target repos get no workflow files and no changes other than Fixpoint's PRs.

## Flow

```mermaid
flowchart TD
    T([workflow_dispatch / repository_dispatch fixpoint-sweep]) --> IN[inputs: validate]
    IN --> PIN[pin: branch -> SHA<br/>read App token]
    PIN --> CO[checkout @SHA, persist-credentials=false<br/>archive source.tar<br/>neutralise agent config]
    CO --> SAST{sast_report?}
    CO --> SCA{sca_report?}
    SAST -- yes --> ING1[ingest: SARIF adapter]
    SAST -- no --> DS[discover SAST<br/>review skill, risk-ranked batches]
    SCA -- yes --> ING2[ingest: Snyk / OSV / SARIF adapter]
    SCA -- no --> DC[discover SCA<br/>supply-chain skill inventory<br/>+ OSV API confirmation]
    ING1 & DS & ING2 & DC --> AL[align: re-anchor by snippet<br/>stale / unlocatable]
    AL --> DD[dedupe: GitHub PR markers<br/>in_flight / fixed / rejected]
    DD --> TR[triage skill<br/>+ policy override]
    TR --> PL[plan: group, order, cap<br/>strategy + autonomy]
    PL -- mode=review --> RP
    PL -- mode=fix --> FX[fix x N<br/>matrix, one sandbox per group]
    FX --> VA[verify-ai x N<br/>diff rules, OSV re-scan, verify skill]
    FX --> VB[verify-build x N<br/>install/build/test, no secrets]
    VA & VB --> SG[sign: re-check policy<br/>cosign keyless bundle]
    SG --> PB[publish: verify signature, policy, dedupe<br/>moved base, Git Data API, PR]
    PB --> RP[report: summary.md, SARIF, OpenVEX<br/>always runs]
    PB -. later .-> RC[reconcile.yml: merged / rejected<br/>eval cases]
```

## Jobs and privileges

| Job | AI | Target-repo code runs | GitHub token | Other secrets | Notes |
|---|---|---|---|---|---|
| `prepare` | yes | no | **read** App, target repo only (pin, checkout, dedupe) | model key | archives the pinned tree for workers |
| `fix` (matrix) | yes | no (Bash off by default) | **none** | model key | unpacks the archive; no git credential exists anywhere |
| `verify-ai` (matrix) | yes | no | none | model key | diff rules, OSV re-scan, verify skill |
| `verify-build` (matrix) | no | **yes** | none | **none** | install/build/test with a scrubbed env |
| `sign` | no | no | none | `id-token: write` | re-checks policy, signs bundle (Sigstore keyless) |
| `publish` | no | no | **write** App, target repo only | env `fixpoint-publish` | verifies signature first; dry run uses the read App |
| `report` | no | no | none | none | `if: always()` |
| `reconcile` | no | no | read App per enrolled repo | optional metrics token | scheduled |

`GITHUB_TOKEN` has `permissions: {}` at workflow level and is never used cross-repo. No PATs.

## Trust boundaries

1. **Target repo → agent.** The repo is untrusted input. Before any agent runs, agent config is deleted
   (`.claude/`, `CLAUDE.md`, `AGENTS.md`, `.cursor*`, `.github/copilot-instructions.md`, `.mcp.json`, and
   similar), symlinks that leave the repo are removed, git hooks are disabled. The agent runs with a private
   `HOME` containing only Fixpoint's skills, `--setting-sources user`, `--strict-mcp-config` (no MCP servers),
   `--permission-mode dontAsk`, `--tools` restricted per role, deny rules for secrets/CI files, a guardrail
   system prompt, and every repo/finding excerpt wrapped in `<untrusted-data>` tags. Its environment is
   scrubbed: no GitHub tokens, no `ACTIONS_ID_TOKEN_REQUEST_*`.
2. **Agent → pipeline.** Model output is structured (`--json-schema`), validated again in Python, and never
   executed. File paths are normalised and confined to the repo; SCA versions from the inventory must appear
   verbatim in the manifest; CVEs and fixed versions come only from OSV or a scanner report.
3. **Target code → runner.** Only `verify-build` executes target code, and that job holds no secrets and no
   tokens. Its verdict can only claim "build passed" — equivalent to the repo owner controlling their tests.
4. **AI jobs → publish.** The patch reaching publish is the byte-exact patch from the `fix` job (hash-checked),
   bundled with both verdicts and signed in the `sign` job. Publish verifies the signature against
   `https://github.com/<fixpoint repo>/.github/workflows/fixpoint.yml@<ref>` and the Actions OIDC issuer, checks
   the bundle belongs to this run/repo/branch/SHA, then re-applies policy and dedupe against live GitHub.
5. **PR body.** Model/scanner text is HTML-escaped, `@mentions` are defused, and the hidden markers are
   parsed from the last occurrence only, so markers smuggled into quoted content are ignored.

Policy is enforced three times: **plan** (eligibility), **verify + sign** (diff rules on the exact bytes),
**publish** (diff rules, enrolment, autonomy, dedupe, PR limits against live state).

## Skills

The pinned pack is `basusaswata/SecCodeAndRevAgent` (AISecCore). It is fetched at the commit in `skills.lock`,
its content hash is verified, and it is installed into the agent's private `~/.claude/skills/<id>/SKILL.md`
(the raw pack is also available read-only at `~/.claude/fixpoint-skills`). The pack contains one review
procedure (`scgra-reviewer`) plus 24 topic skills (`scgra-0-*`, `scgra-1-*`); there are no separate triage /
remediation / verify skills, so each role is driven by a Fixpoint prompt template (`prompts/`) that loads the
role's skill and the topic skill named in the finding:

| Role | Skill (skills.lock) | Prompt |
|---|---|---|
| review (DISCOVER SAST) | `scgra-reviewer` | `prompts/discover-sast.md` |
| discover_sca (inventory) | `scgra-0-supply-chain-security` | `prompts/discover-sca.md` |
| triage | `scgra-reviewer` | `prompts/triage.md` |
| fix_cwe | `scgra-0-cwe-prevention` | `prompts/fix-cwe.md` |
| fix_cve | `scgra-0-supply-chain-security` | `prompts/fix-cve.md` |
| verify | `scgra-reviewer` | `prompts/verify.md` |

When dedicated skills ship, change the names in `skills.lock`; nothing else changes.

## Common finding format

Defined in `fixpoint/model.py`. Every stage reads and writes
`{"schema": "fixpoint/findings/v1", "meta": {...}, "findings": [...]}`.

| Field | Set by | Meaning |
|---|---|---|
| `id` | ingest/discover | stable fingerprint. SAST: `sast-` + sha256(CWEs, file, normalised snippet). SCA: `sca-` + sha256(ecosystem, package, version, CVEs). Independent of line numbers, scanner and wording |
| `kind` | ingest/discover | `sast` or `sca` |
| `source` | ingest/discover | `report:<scanner>` or `discover:<skill>` |
| `rule_id`, `title`, `message` | ingest/discover | scanner rule / AISecCore skill id, text |
| `severity` | ingest/discover | `critical`, `high`, `medium`, `low`, `info` |
| `cwe[]`, `cve[]` | ingest/discover | normalised `CWE-89`, `CVE-2020-14343` |
| `location` | ingest/discover, align | `file`, `start_line`, `end_line`, `snippet` (align updates lines) |
| `package` | ingest/discover | `ecosystem`, `name`, `version`, `fixed_versions[]`, `manifest` |
| `path[]` | ingest/discover | source-to-sink steps |
| `status` | align, dedupe | `open`, `stale`, `unlocatable`, `in_flight`, `fixed`, `rejected` |
| `disposition` | triage | `fix`, `false_positive`, `not_reachable`, `accepted_risk`, `human_review` |
| `confidence`, `reasoning`, `evidence[]` | triage | evidence items: `kind` (`source_to_sink`, `reachability`, `code`, `advisory`, `note`), `description`, `file`, `line` |
| `notes[]`, `properties{}` | any | audit notes (e.g. policy overrides), extra data (`osv_confirmed`, `pr`, ...) |

Other documents: `plan.json` (`fixpoint/plan/v1`: groups + deferred), `fix/<group>/{patch.diff,meta.json}`,
`verdicts/<group>.<phase>.verdict.json`, `signed/<group>.bundle.json` + `.sigstore.json`, `publish.json`.

## Idempotency and state

GitHub is the only state store. Every PR body ends with
`<!-- fixpoint-findings: id1,id2 -->` and a base64 metadata block; the head branch is
`fixpoint/<branch-slug>/<group-id>`. Group ids are derived from finding ids, so re-running the same inputs
produces the same groups; dedupe (prepare) and the live re-check (publish) turn them into `in_flight` and skip.
Closed-unmerged PRs mark their findings `rejected` on every branch, forever.

## Fail-safe rules

| Situation | Result |
|---|---|
| triage call fails / answer missing / invalid JSON | whole batch → `human_review` |
| `fix` below confidence or severity threshold | `human_review` |
| SCA with no known fixed version, or discovered SCA not confirmed by OSV | `human_review` |
| no fixed version within the branch's upgrade strategy | deferred |
| agent `cannot_fix`, empty diff, forbidden path, size, test deletion/weakening, missing test | no bundle |
| no build marker (with `require_build`) or build/test fails | no bundle |
| verify skill: finding still present, new issue, weak test, low confidence | no bundle |
| OSV re-scan: vuln still present, new vuln, OSV unreachable | no bundle |
| signature invalid, bundle from another run, policy/dedupe fails at publish | skipped, reported |
| base moved and patch does not apply | skipped as `conflict`, reported |
