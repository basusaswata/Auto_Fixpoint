"""Skills supply chain: fetch the pinned pack, verify it, install it.

The pack is installed in two forms under the agent's private HOME:

* ``~/.claude/skills/<skill-id>/SKILL.md`` - one Claude Code skill per
  ``scgra-*`` guidance file and one for the ``scgra-reviewer`` procedure, so the
  agent can load them with the Skill tool;
* ``~/.claude/fixpoint-skills/<paths>`` - the raw pack, read-only reference
  for prompts that cite a skill file by path.

Nothing is ever written into the target repository.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import yaml

from fixpoint import log
from fixpoint.config import ConfigError, SkillsLock

LOG = log.get(__name__)


class SkillsError(RuntimeError):
    pass


def tree_sha256(root: Path, paths: list[str]) -> str:
    """Deterministic content hash of files under ``paths`` (relative to root).

    sha256 over sorted lines ``<sha256(file)>  <relpath>\\n``. Ignores .DS_Store.
    """
    entries: list[str] = []
    for rel in paths:
        base = root / rel
        if not base.exists():
            raise SkillsError(f"skills pack path missing: {rel}")
        files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for f in files:
            if f.name == ".DS_Store":
                continue
            if f.is_symlink():
                raise SkillsError(f"symlink in skills pack refused: {f.relative_to(root)}")
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
            entries.append(f"{digest}  {f.relative_to(root).as_posix()}\n")
    return hashlib.sha256("".join(sorted(entries)).encode()).hexdigest()


def fetch_git(lock: SkillsLock, dest: Path, token: str | None = None, host: str = "github.com") -> Path:
    """Fetch exactly ``lock.commit`` (shallow) into dest. Token is optional (public repos)."""
    dest.mkdir(parents=True, exist_ok=True)
    url = f"https://{host}/{lock.repo}.git"
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(dest), "GIT_TERMINAL_PROMPT": "0"}
    cfg: list[str] = ["-c", "credential.helper="]
    if token:
        log.register_secret(token)
        # Header auth: the token is never written to .git/config or the URL.
        import base64

        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        log.register_secret(basic)
        cfg += ["-c", f"http.extraHeader=Authorization: Basic {basic}"]

    def git(*args: str) -> None:
        r = subprocess.run(["git", *cfg, *args], cwd=dest, env=env, capture_output=True, text=True, check=False)
        if r.returncode != 0:
            raise SkillsError(f"git {args[0]} failed: {log.redact(r.stderr.strip())[:500]}")

    git("init", "-q")
    git("fetch", "-q", "--depth", "1", url, lock.commit)
    git("-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=dest, capture_output=True, text=True, env=env, check=True)
    if head.stdout.strip() != lock.commit:
        raise SkillsError("fetched commit does not match skills.lock")
    shutil.rmtree(dest / ".git")
    return dest


def fetch_release(lock: SkillsLock, dest: Path, token: str | None = None, api: str = "https://api.github.com") -> Path:
    import requests

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(f"{api}/repos/{lock.repo}/releases/tags/{lock.tag}", headers=headers, timeout=30)
    r.raise_for_status()
    assets = [a for a in r.json().get("assets", []) if a.get("name") == lock.asset]
    if not assets:
        raise SkillsError(f"release {lock.tag} has no asset {lock.asset}")
    dl = requests.get(
        assets[0]["url"], headers={**headers, "Accept": "application/octet-stream"}, timeout=120
    )
    dl.raise_for_status()
    data = dl.content
    got = hashlib.sha256(data).hexdigest()
    if got != lock.sha256:
        raise SkillsError(f"skills asset checksum mismatch: expected {lock.sha256}, got {got}")
    dest.mkdir(parents=True, exist_ok=True)
    tar_path = dest.parent / lock.asset
    tar_path.write_bytes(data)
    if lock.require_attestation:
        verify_attestation(tar_path, lock.repo)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        tf.extractall(dest, filter="data")  # rejects absolute paths, traversal, devices
    return dest


def verify_attestation(artifact: Path, repo: str) -> None:
    r = subprocess.run(
        ["gh", "attestation", "verify", str(artifact), "--repo", repo], capture_output=True, text=True, check=False
    )
    if r.returncode != 0:
        raise SkillsError(f"attestation verification failed: {log.redact(r.stderr.strip())[:500]}")


def _frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.S)
    if not m:
        return {}, text
    try:
        # Some packs use unquoted globs like **/*.py which YAML reads as an alias.
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        meta = {}
        for line in m.group(1).splitlines():
            if ":" in line and not line.startswith(" "):
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip().strip('"')
    return (meta if isinstance(meta, dict) else {}), m.group(2)


def _one_line(s: str, limit: int = 900) -> str:
    return re.sub(r"\s+", " ", s).strip()[:limit]


def install(pack_root: Path, home: Path, lock: SkillsLock) -> list[str]:
    """Install the verified pack under ``home/.claude``. Returns installed skill names."""
    claude = home / ".claude"
    skills_dir = claude / "skills"
    raw_dir = claude / "fixpoint-skills"
    for d in (skills_dir, raw_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    for rel in lock.paths:
        shutil.copytree(pack_root / rel, raw_dir / rel, ignore=shutil.ignore_patterns(".DS_Store"))

    installed: list[str] = []
    candidates: list[Path] = []
    for rel in lock.paths:
        base = pack_root / rel
        candidates += sorted(base.glob("skills/*.md")) + sorted(base.glob("agents/*.md"))
        candidates += sorted(base.glob("**/SKILL.md"))
    for src in candidates:
        text = src.read_text(encoding="utf-8")
        meta, body = _frontmatter(text)
        name = str(meta.get("name") or meta.get("id") or (src.parent.name if src.name == "SKILL.md" else src.stem))
        if not re.match(r"^[a-z0-9][a-z0-9._-]*$", name) or name in installed:
            continue
        desc = _one_line(str(meta.get("description") or f"AISecCore skill {name}"))
        pack_rel = src.relative_to(pack_root).as_posix()
        desc_yaml = yaml.safe_dump(desc, default_style='"', width=10**6).strip()
        header = (
            f"---\nname: {name}\ndescription: {desc_yaml}\n---\n\n"
            f"<!-- installed by fixpoint from {lock.version}:{pack_rel} -->\n"
            f"The full skill pack is available read-only at `{raw_dir}`. When this text refers to\n"
            f"`AISecCore/...` paths, resolve them under that directory, never in the target repository.\n\n"
        )
        out = skills_dir / name / "SKILL.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(header + body, encoding="utf-8")
        installed.append(name)

    for role, skill in lock.roles.items():
        if skill not in installed:
            raise SkillsError(f"skills.lock role {role} -> {skill!r} is not in the pack")
    LOG.info("installed %d skills from %s into %s", len(installed), lock.version, skills_dir)
    return installed


def fetch_verify_install(lock: SkillsLock, home: Path, token: str | None = None, host: str = "github.com",
                         api: str = "https://api.github.com") -> list[str]:
    with tempfile.TemporaryDirectory(prefix="fixpoint-skills-") as tmp:
        root = Path(tmp) / "pack"
        if lock.source == "git":
            fetch_git(lock, root, token, host)
            got = tree_sha256(root, lock.paths)
            if got != lock.content_sha256:
                raise SkillsError(f"skills content hash mismatch: expected {lock.content_sha256}, got {got}")
        else:
            fetch_release(lock, root, token, api)
            if lock.content_sha256 and lock.paths:
                got = tree_sha256(root, lock.paths)
                if got != lock.content_sha256:
                    raise SkillsError("skills content hash mismatch after release extraction")
        return install(root, home, lock)


def check_lock(lock: SkillsLock) -> None:
    if lock.source == "git" and not re.match(r"^[0-9a-f]{64}$", lock.content_sha256):
        raise ConfigError("skills.lock: content_sha256 must be set (run `fixpoint skills hash`)")
