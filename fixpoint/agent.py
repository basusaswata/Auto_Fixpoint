"""Agent runtime boundary. Everything that talks to a model goes through here.

``ClaudeCodeRuntime`` drives Claude Code headless (``claude -p``). To swap the
runtime, implement ``AgentRuntime.run`` and register it in ``get_runtime``.

Hardening applied to every call:
* the prompt goes in on stdin, wrapped repo/finding content is tagged untrusted;
* a guardrail system prompt is appended;
* ``--setting-sources user`` with a private HOME (only Fixpoint's own skills),
  ``--strict-mcp-config`` with no MCP servers, deny rules for secrets and CI files;
* ``--tools`` restricts the tool set per role and ``--permission-mode dontAsk``
  denies anything not explicitly allowed;
* a scrubbed environment (no GitHub tokens, no OIDC request token);
* structured output via ``--json-schema``, validated again here. Model output
  is data: it is never executed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from fixpoint import log
from fixpoint.jsonschema_lite import ValidationError, validate
from fixpoint.prompts import PROMPTS_DIR

LOG = log.get(__name__)

READ_TOOLS = ["Read", "Grep", "Glob", "Skill"]
EDIT_TOOLS = ["Edit", "Write"]


# Environment passed to the agent process. Everything else is dropped.
BASE_ENV = ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR")
MODEL_ENV = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "AWS_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "CLOUD_ML_REGION",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "HTTPS_PROXY",
    "NO_PROXY",
)

DENY_RULES = [
    "Read(**/.env)",
    "Read(**/.env.*)",
    "Read(**/*.pem)",
    "Read(**/*.key)",
    "Read(**/.npmrc)",
    "Read(**/.pypirc)",
    "Read(**/.netrc)",
    "Read(**/.git-credentials)",
    "Read(**/.git/config)",
    "Read(~/.ssh/**)",
    "Read(~/.aws/**)",
    "Read(~/.config/**)",
    "Read(~/.claude.json)",
    "Read(//proc/**)",
    "Read(//etc/**)",
    "Read(//var/run/**)",
    "Edit(.github/**)",
    "Edit(**/.git/**)",
    "Write(.github/**)",
    "Write(**/.git/**)",
    "Edit(.claude/**)",
    "Write(.claude/**)",
    "WebFetch",
    "WebSearch",
]


class AgentError(RuntimeError):
    """The agent call failed or returned something unusable. Callers fail safe."""


@dataclass
class AgentRequest:
    role: str  # review | triage | fix_cwe | fix_cve | verify | discover_sca
    prompt: str
    schema: dict[str, Any]
    cwd: Path
    tools: list[str] = field(default_factory=lambda: list(READ_TOOLS))
    bash_commands: list[list[str]] = field(default_factory=list)
    add_dirs: list[Path] = field(default_factory=list)
    max_budget_usd: float = 3.0
    timeout_seconds: int = 1800


@dataclass
class AgentResult:
    data: dict[str, Any]
    model: str = ""
    cost_usd: float = 0.0
    session_id: str = ""
    duration_s: float = 0.0


class AgentRuntime(Protocol):
    name: str

    def run(self, req: AgentRequest) -> AgentResult: ...


# -- untrusted data ---------------------------------------------------------


def wrap_untrusted(label: str, content: str) -> str:
    """Wrap content in explicit untrusted-data tags. Closing tags inside are defused."""
    safe_label = re.sub(r"[^A-Za-z0-9_.:/@ -]", "_", label)[:200]
    body = re.sub(r"(?i)</?\s*untrusted-data", lambda m: m.group(0).replace("<", "&lt;"), content)
    return f'<untrusted-data source="{safe_label}">\n{body}\n</untrusted-data>'


def guardrail_prompt() -> str:
    return (PROMPTS_DIR / "guardrail.md").read_text(encoding="utf-8")


# -- Claude Code -------------------------------------------------------------


def _bash_rule(argv: list[str]) -> str:
    if not argv or any(re.search(r"[;&|`$<>()\n\\]", a) for a in argv):
        raise AgentError(f"refusing unsafe bash allowlist entry: {argv!r}")
    return f"Bash({' '.join(argv)})"


def _extract_json(text: str) -> Any:
    text = (text or "").strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise AgentError("agent returned no JSON object")
    return json.loads(text[start : end + 1])


class ClaudeCodeRuntime:
    name = "claude-code"

    def __init__(self, binary: str | None = None, model: str | None = None, home: Path | None = None,
                 fallback_model: str | None = None, bare: bool = False) -> None:
        self.binary = binary or os.environ.get("FIXPOINT_CLAUDE_BIN") or "claude"
        self.model = model or os.environ.get("FIXPOINT_MODEL") or ""
        self.fallback_model = fallback_model or os.environ.get("FIXPOINT_FALLBACK_MODEL") or ""
        self.home = Path(home or os.environ.get("FIXPOINT_AGENT_HOME") or Path.home())
        self.bare = bare or os.environ.get("FIXPOINT_AGENT_BARE") == "1"

    def build_argv(self, req: AgentRequest) -> list[str]:
        tools = list(dict.fromkeys(req.tools))
        allowed = [t for t in tools if t != "Bash"]
        if req.bash_commands:
            tools.append("Bash")
            allowed += [_bash_rule(c) for c in req.bash_commands]
        settings = {
            "permissions": {"deny": DENY_RULES},
            "disableAllHooks": True,
            "enableAllProjectMcpServers": False,
        }
        argv = [
            self.binary,
            "-p",
            "--output-format", "json",
            "--json-schema", json.dumps(req.schema, separators=(",", ":")),
            "--setting-sources", "user",
            "--settings", json.dumps(settings, separators=(",", ":")),
            "--strict-mcp-config",
            "--permission-mode", "dontAsk",
            "--tools", ",".join(tools),
            "--allowedTools", *allowed,
            "--append-system-prompt", guardrail_prompt(),
            "--no-session-persistence",
            "--max-budget-usd", f"{req.max_budget_usd:.2f}",
        ]
        if self.model:
            argv += ["--model", self.model]
        if self.fallback_model:
            argv += ["--fallback-model", self.fallback_model]
        if self.bare:
            argv.append("--bare")
        for d in req.add_dirs:
            argv += ["--add-dir", str(d)]
        return argv

    def env(self) -> dict[str, str]:
        env = {k: os.environ[k] for k in (*BASE_ENV, *MODEL_ENV) if k in os.environ}
        extra = os.environ.get("FIXPOINT_AGENT_PASS_ENV", "")
        for k in filter(None, (x.strip() for x in extra.split(","))):
            if re.search(r"TOKEN|GITHUB|ACTIONS_|SECRET|PASSWORD|KEY", k) and k not in MODEL_ENV:
                raise AgentError(f"refusing to pass {k} to the agent")
            if k in os.environ:
                env[k] = os.environ[k]
        env["HOME"] = str(self.home)
        env["DISABLE_AUTOUPDATER"] = "1"
        env["DISABLE_TELEMETRY"] = "1"
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
        env["CI"] = "true"
        return env

    def run(self, req: AgentRequest) -> AgentResult:
        if shutil.which(self.binary) is None and not Path(self.binary).exists():
            raise AgentError(f"agent binary not found: {self.binary}")
        argv = self.build_argv(req)
        LOG.info("agent[%s] start: tools=%s budget=$%.2f", req.role, ",".join(req.tools), req.max_budget_usd)
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                argv, input=req.prompt, cwd=req.cwd, env=self.env(), capture_output=True, text=True,
                timeout=req.timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise AgentError(f"agent[{req.role}] timed out after {req.timeout_seconds}s") from e
        dt = time.monotonic() - t0
        return self.parse(req, proc.returncode, proc.stdout, proc.stderr, dt)

    @staticmethod
    def parse(req: AgentRequest, returncode: int, stdout: str, stderr: str, duration: float = 0.0) -> AgentResult:
        try:
            out = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise AgentError(
                f"agent[{req.role}] exit {returncode}, non-JSON output: {log.redact(stderr or stdout)[:400]}"
            ) from e
        if not isinstance(out, dict):
            raise AgentError(f"agent[{req.role}] unexpected output shape")
        if out.get("is_error") or out.get("subtype") not in (None, "success") or returncode != 0:
            detail = log.redact(str(out.get("result") or out.get("subtype") or stderr))[:400]
            raise AgentError(f"agent[{req.role}] failed: {detail}")
        data = out.get("structured_output")
        if data is None:
            try:
                data = _extract_json(str(out.get("result", "")))
            except (json.JSONDecodeError, AgentError) as e:
                raise AgentError(f"agent[{req.role}] returned no structured output") from e
        try:
            validate(data, req.schema)
        except ValidationError as e:
            raise AgentError(f"agent[{req.role}] output failed schema validation: {e}") from e
        model = ",".join(sorted((out.get("modelUsage") or {}).keys()))
        LOG.info("agent[%s] done in %.0fs cost=$%.3f", req.role, duration, float(out.get("total_cost_usd") or 0))
        return AgentResult(
            data=data, model=model, cost_usd=float(out.get("total_cost_usd") or 0.0),
            session_id=str(out.get("session_id", "")), duration_s=duration,
        )


# -- scripted runtime (tests, evals without a model, local dry runs) ----------


class ScriptedRuntime:
    """Returns canned responses per role. Each role maps to a list consumed in order,
    or to a callable ``(req) -> dict``. An ``Exception`` instance is raised."""

    name = "scripted"

    def __init__(self, responses: dict[str, Any], model: str = "scripted-model",
                 edits: dict[str, Any] | None = None) -> None:
        self.responses = {k: (list(v) if isinstance(v, list) else v) for k, v in responses.items()}
        self.model = model
        self.edits = edits or {}
        self.calls: list[AgentRequest] = []

    def run(self, req: AgentRequest) -> AgentResult:
        self.calls.append(req)
        r = self.responses.get(req.role)
        if r is None:
            raise AgentError(f"scripted runtime has no response for role {req.role}")
        if callable(r):
            data = r(req)
        elif isinstance(r, list):
            if not r:
                raise AgentError(f"scripted runtime exhausted for role {req.role}")
            data = r.pop(0)
        else:
            data = r
        if isinstance(data, Exception):
            raise data
        # Optional file edits to simulate a fix agent: {role: {path: content}}.
        for rel, content in (self.edits.get(req.role) or {}).items():
            p = req.cwd / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        try:
            validate(data, req.schema)
        except ValidationError as e:
            raise AgentError(f"agent[{req.role}] output failed schema validation: {e}") from e
        return AgentResult(data=data, model=self.model)


def get_runtime(spec: str | None = None) -> AgentRuntime:
    """``claude`` (default) or ``scripted:<path.json>``."""
    spec = spec or os.environ.get("FIXPOINT_AGENT", "claude")
    if spec == "claude":
        return ClaudeCodeRuntime()
    if spec.startswith("scripted:"):
        doc = json.loads(Path(spec.split(":", 1)[1]).read_text(encoding="utf-8"))
        return ScriptedRuntime(doc.get("responses", {}), edits=doc.get("edits"))
    raise AgentError(f"unknown agent runtime {spec!r}")


def skills_dir(home: Path | None = None) -> Path:
    home = Path(home or os.environ.get("FIXPOINT_AGENT_HOME") or Path.home())
    return home / ".claude" / "fixpoint-skills"
