"""REPORT mode: fetch a scanner report and convert it to the common format."""

from __future__ import annotations

import json
from pathlib import Path

import requests

from fixpoint import adapters, log
from fixpoint.model import Finding, FormatError

LOG = log.get(__name__)


class IngestError(RuntimeError):
    pass


def fetch(source: str, max_bytes: int, workspace: Path | None = None) -> bytes:
    """Load a report from an https URL or a local path (inside the workspace when given)."""
    if source.startswith("http://"):
        raise IngestError("report URLs must use https")
    if source.startswith("https://"):
        with requests.get(source, timeout=60, stream=True, allow_redirects=True) as r:
            if r.url and not r.url.startswith("https://"):
                raise IngestError("report URL redirected to a non-https location")
            if r.status_code != 200:
                raise IngestError(f"report download failed: HTTP {r.status_code}")
            buf = bytearray()
            for chunk in r.iter_content(65536):
                buf += chunk
                if len(buf) > max_bytes:
                    raise IngestError(f"report exceeds {max_bytes} bytes")
            return bytes(buf)
    p = Path(source).expanduser().resolve()
    if workspace is not None:
        ws = workspace.resolve()
        if ws != p and ws not in p.parents:
            raise IngestError("report path is outside the workspace")
    if not p.is_file():
        raise IngestError(f"report not found: {source}")
    if p.stat().st_size > max_bytes:
        raise IngestError(f"report exceeds {max_bytes} bytes")
    return p.read_bytes()


def ingest(source: str, fmt: str, kind: str, max_bytes: int, workspace: Path | None = None) -> list[Finding]:
    data = fetch(source, max_bytes, workspace)
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FormatError(f"report is not valid JSON: {e}") from e
    findings = adapters.parse(doc, fmt, kind)
    LOG.info("ingested %d %s findings (%s)", len(findings), kind, fmt)
    return findings
