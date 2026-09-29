"""Policy and skills.lock loading, validation and helpers."""

from __future__ import annotations

import fnmatch
import functools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

AUTONOMY = ("draft", "pr", "auto-merge-patch")
CVE_UPGRADE = ("lowest-safe", "same-major-lowest-safe")
ROLES = ("review", "triage", "fix_cwe", "fix_cve", "verify", "discover_sca")

REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ConfigError(ValueError):
    pass


# -- globbing -------------------------------------------------------------


@functools.lru_cache(maxsize=1024)
def _glob_re(pattern: str) -> re.Pattern[str]:
    """Path glob with ``**`` support. ``*`` and ``?`` never cross ``/``."""
    i, out = 0, []
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def glob_match(path: str, pattern: str) -> bool:
    return bool(_glob_re(pattern).match(path))


def any_glob(path: str, patterns: list[str]) -> bool:
    return any(glob_match(path, p) for p in patterns)


# -- policy -----------------------------------------------------------------


@dataclass
class BranchRule:
    match: str
    cve_upgrade: str
    autonomy: str


@dataclass
class VerifyCommand:
    marker: str
    install: list[str] = field(default_factory=list)
    build: list[str] = field(default_factory=list)
    test: list[str] = field(default_factory=list)


@dataclass
class Policy:
    raw: dict[str, Any]

    # convenient accessors ------------------------------------------------
    @property
    def enrolled_repos(self) -> list[str]:
        return list(self.raw.get("enrolled_repos") or [])

    def is_enrolled(self, repo: str) -> bool:
        return repo.lower() in {r.lower() for r in self.enrolled_repos}

    @property
    def limits(self) -> dict[str, int]:
        return self.raw["limits"]

    @property
    def forbidden_paths(self) -> list[str]:
        return list(self.raw.get("forbidden_paths") or [])

    @property
    def tests(self) -> dict[str, Any]:
        return self.raw.get("tests") or {}

    def is_test_path(self, path: str) -> bool:
        return any_glob(path, list(self.tests.get("patterns") or []))

    @property
    def triage(self) -> dict[str, Any]:
        return self.raw["triage"]

    @property
    def discover(self) -> dict[str, Any]:
        return self.raw["discover"]

    @property
    def fix(self) -> dict[str, Any]:
        return self.raw.get("fix") or {}

    @property
    def verify(self) -> dict[str, Any]:
        return self.raw["verify"]

    @property
    def pr(self) -> dict[str, Any]:
        return self.raw.get("pr") or {}

    @property
    def verify_commands(self) -> list[VerifyCommand]:
        return [VerifyCommand(**c) for c in self.verify.get("commands") or []]

    def branch_rule(self, branch: str) -> BranchRule:
        for r in self.raw.get("branch_rules") or []:
            if fnmatch.fnmatchcase(branch, r["match"]):
                return BranchRule(**r)
        # No rule matched: the most conservative behaviour.
        return BranchRule(match="<default>", cve_upgrade="same-major-lowest-safe", autonomy="draft")


def _require(d: dict[str, Any], path: str, typ: type | tuple[type, ...]) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise ConfigError(f"policy: missing {path}")
        cur = cur[part]
    if not isinstance(cur, typ):
        raise ConfigError(f"policy: {path} must be {typ}")
    return cur


def validate_policy(raw: dict[str, Any]) -> Policy:
    if not isinstance(raw, dict):
        raise ConfigError("policy: not a mapping")
    for key in ("prs_per_run", "open_bot_prs_per_repo", "changed_files", "changed_lines"):
        v = _require(raw, f"limits.{key}", int)
        if v < 0:
            raise ConfigError(f"policy: limits.{key} must be >= 0")
    for repo in raw.get("enrolled_repos") or []:
        if not REPO_RE.match(str(repo)):
            raise ConfigError(f"policy: bad enrolled repo {repo!r}")
    conf = _require(raw, "triage.min_confidence", (int, float))
    if not 0 <= conf <= 1:
        raise ConfigError("policy: triage.min_confidence must be in [0, 1]")
    for s in _require(raw, "triage.fix_severities", list):
        if s not in ("critical", "high", "medium", "low", "info"):
            raise ConfigError(f"policy: unknown severity {s!r}")
    _require(raw, "discover.sast", dict)
    _require(raw, "discover.sca", dict)
    if raw["discover"]["sca"].get("engine", "skill") not in ("skill", "osv-scanner"):
        raise ConfigError("policy: discover.sca.engine must be skill or osv-scanner")
    _require(raw, "verify.commands", list)
    for c in raw["verify"]["commands"]:
        if "marker" not in c or "/" in c["marker"]:
            raise ConfigError("policy: verify command needs a root-level marker")
        for k in ("install", "build", "test"):
            if not isinstance(c.get(k, []), list) or not all(isinstance(x, str) for x in c.get(k, [])):
                raise ConfigError(f"policy: verify.commands[{c['marker']}].{k} must be an argv list")
    rules = _require(raw, "branch_rules", list)
    if not rules:
        raise ConfigError("policy: branch_rules must not be empty")
    for r in rules:
        if r.get("autonomy") not in AUTONOMY:
            raise ConfigError(f"policy: bad autonomy {r.get('autonomy')!r}")
        if r.get("cve_upgrade") not in CVE_UPGRADE:
            raise ConfigError(f"policy: bad cve_upgrade {r.get('cve_upgrade')!r}")
        if not isinstance(r.get("match"), str):
            raise ConfigError("policy: branch rule needs match")
    return Policy(raw)


def load_policy(path: str | Path = "policy/policy.yaml") -> Policy:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ConfigError(f"policy file not found: {path}") from e
    return validate_policy(raw)


# -- skills.lock ------------------------------------------------------------


@dataclass
class SkillsLock:
    source: str
    repo: str
    commit: str
    paths: list[str]
    content_sha256: str
    roles: dict[str, str]
    require_attestation: bool = False
    tag: str = ""
    asset: str = ""
    sha256: str = ""
    ref: str = ""

    @property
    def version(self) -> str:
        """Human-readable version recorded on every PR."""
        if self.source == "release":
            return f"{self.repo}@{self.tag}"
        return f"{self.repo}@{self.commit[:12]}"

    def skill(self, role: str) -> str:
        if role not in self.roles:
            raise ConfigError(f"skills.lock: no skill for role {role!r}")
        return self.roles[role]


def load_skills_lock(path: str | Path = "skills.lock") -> SkillsLock:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError("skills.lock: not a mapping")
    source = raw.get("source", "git")
    if source not in ("git", "release"):
        raise ConfigError("skills.lock: source must be git or release")
    repo = str(raw.get("repo", ""))
    if not REPO_RE.match(repo):
        raise ConfigError("skills.lock: bad repo")
    roles = raw.get("roles") or {}
    missing = [r for r in ROLES if r not in roles]
    if missing:
        raise ConfigError(f"skills.lock: missing roles {missing}")
    for name in roles.values():
        if not re.match(r"^[a-z0-9][a-z0-9._-]*$", str(name)):
            raise ConfigError(f"skills.lock: bad skill name {name!r}")
    lock = SkillsLock(
        source=source,
        repo=repo,
        commit=str(raw.get("commit", "")),
        paths=list(raw.get("paths") or []),
        content_sha256=str(raw.get("content_sha256", "")),
        roles={k: str(v) for k, v in roles.items()},
        require_attestation=bool(raw.get("require_attestation", False)),
        tag=str(raw.get("tag", "")),
        asset=str(raw.get("asset", "")),
        sha256=str(raw.get("sha256", "")),
        ref=str(raw.get("ref", "")),
    )
    if source == "git" and not SHA_RE.match(lock.commit):
        raise ConfigError("skills.lock: commit must be a full 40-char SHA")
    if source == "release" and not (lock.tag and lock.asset and re.match(r"^[0-9a-f]{64}$", lock.sha256)):
        raise ConfigError("skills.lock: release source needs tag, asset and sha256")
    return lock
