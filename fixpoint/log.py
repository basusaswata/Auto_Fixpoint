"""Logging with secret redaction.

Every log record passes through a filter that masks anything that looks like a
token, key or credential, plus any value registered with ``register_secret``.
"""

from __future__ import annotations

import logging
import os
import re
import sys

_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"),  # Anthropic keys
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ids
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(authorization:\s*)(bearer|token)\s+\S+"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWTs
]

_secrets: set[str] = set()

# Environment variables whose values are always masked if present.
_SECRET_ENV = (
    "ANTHROPIC_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "FIXPOINT_READ_TOKEN",
    "FIXPOINT_WRITE_TOKEN",
    "FIXPOINT_METRICS_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)


def register_secret(value: str | None) -> None:
    if value and len(value) >= 6:
        _secrets.add(value)


def redact(text: str) -> str:
    if not text:
        return text
    for s in _secrets:
        text = text.replace(s, "***")
    for p in _PATTERNS:
        text = p.sub(lambda m: (m.group(1) if m.re.groups else "") + "***", text)
    return text


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        record.msg = redact(msg)
        record.args = None
        return True


def setup(level: str | None = None) -> None:
    for name in _SECRET_ENV:
        register_secret(os.environ.get(name))
    root = logging.getLogger()
    if getattr(root, "_fixpoint_configured", False):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    handler.addFilter(_RedactFilter())
    root.handlers[:] = [handler]
    root.setLevel((level or os.environ.get("FIXPOINT_LOG_LEVEL") or "INFO").upper())
    root._fixpoint_configured = True  # type: ignore[attr-defined]


def get(name: str) -> logging.Logger:
    return logging.getLogger(name)
