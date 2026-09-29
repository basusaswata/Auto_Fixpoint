"""Strip agent configuration from an untrusted target checkout.

Runs before any agent sees the repository. Also disables git hooks and records
a local baseline commit so later diffs contain only the agent's changes.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from fixpoint import log

LOG = log.get(__name__)

# Paths (relative to the repo root, and in any subdirectory) that configure AI agents.
AGENT_CONFIG_NAMES = (
    ".claude",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    ".mcp.json",
    ".github/copilot-instructions.md",
    ".github/instructions",
    ".github/prompts",
    ".github/chatmodes",
    ".windsurf",
    ".windsurfrules",
    ".codex",
    ".opencode",
    ".agents",
    ".aider.conf.yml",
    ".continue",
    ".clinerules",
    ".roo",
    "GEMINI.md",
    ".gemini",
)

GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=fixpoint", "-c", "user.email=fixpoint@invalid"]


def _remove(p: Path) -> None:
    if p.is_symlink() or p.is_file():
        p.unlink()
    elif p.is_dir():
        shutil.rmtree(p)


def neutralise(repo: Path) -> list[str]:
    repo = repo.resolve()
    removed: list[str] = []
    for path in sorted(repo.rglob("*"), key=lambda p: len(p.parts)):
        if ".git" in path.relative_to(repo).parts or not (path.exists() or path.is_symlink()):
            continue
        rel = path.relative_to(repo).as_posix()
        name = path.name
        hit = (
            name in AGENT_CONFIG_NAMES
            or rel in AGENT_CONFIG_NAMES
            or name.startswith(".cursor")
            or any(rel.endswith("/" + n) for n in AGENT_CONFIG_NAMES if "/" in n)
        )
        if hit:
            _remove(path)
            removed.append(rel)
    # Symlinks pointing outside the repo could let an agent read runner files.
    for path in repo.rglob("*"):
        if path.is_symlink() and ".git" not in path.relative_to(repo).parts:
            target = path.resolve()
            if not str(target).startswith(str(repo) + "/"):
                rel = path.relative_to(repo).as_posix()
                path.unlink()
                removed.append(rel + " (external symlink)")
    for rel in removed:
        LOG.info("neutralised %s", rel)
    return removed


def baseline(repo: Path) -> str | None:
    """Commit the neutralised tree locally (never pushed) and return its sha."""
    if not (repo / ".git").exists():
        return None
    subprocess.run([*GIT, "config", "core.hooksPath", "/dev/null"], cwd=repo, check=True)
    subprocess.run([*GIT, "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        [*GIT, "commit", "-q", "--no-verify", "--allow-empty", "-m", "fixpoint: neutralised baseline"],
        cwd=repo, check=True, capture_output=True,
    )
    out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True)
    return out.stdout.strip()
