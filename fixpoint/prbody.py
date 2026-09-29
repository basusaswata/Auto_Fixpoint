"""PR title/body rendering and the hidden markers used as GitHub-side state."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from string import Template
from typing import Any

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "pr_body.md"

FINDINGS_RE = re.compile(r"<!--\s*fixpoint-findings:\s*([A-Za-z0-9_,\s-]*?)\s*-->")
META_RE = re.compile(r"<!--\s*fixpoint-meta:\s*([A-Za-z0-9+/=]+)\s*-->")


def findings_marker(ids: list[str]) -> str:
    return f"<!-- fixpoint-findings: {','.join(sorted(ids))} -->"


def meta_marker(meta: dict[str, Any]) -> str:
    raw = base64.b64encode(json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()).decode()
    return f"<!-- fixpoint-meta: {raw} -->"


def parse_finding_ids(body: str | None) -> list[str]:
    """Ids from the LAST marker. Fixpoint writes it at the very end of the body, so a
    marker smuggled into quoted repo content earlier in the body is ignored."""
    matches = list(FINDINGS_RE.finditer(body or ""))
    if not matches:
        return []
    return sorted({x.strip() for x in matches[-1].group(1).split(",") if x.strip()})


def parse_meta(body: str | None) -> dict[str, Any]:
    matches = list(META_RE.finditer(body or ""))
    if not matches:
        return {}
    m = matches[-1]
    try:
        return json.loads(base64.b64decode(m.group(1)))
    except (ValueError, json.JSONDecodeError):
        return {}


def _md_escape(s: str) -> str:
    """Neutralise markdown/HTML from untrusted text (model or scanner output) in the PR body."""
    s = (s or "").replace("\r", "")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"@(?=[A-Za-z0-9])", "@​", s)  # no accidental mentions
    return s.strip()


def title(group: dict[str, Any]) -> str:
    ids = group.get("cve") or group.get("cwe") or [group.get("rule_id") or "finding"]
    shown = ", ".join(ids[:3]) + (f" +{len(ids) - 3}" if len(ids) > 3 else "")
    desc = group.get("title") or ""
    if group.get("kind") == "sca" and group.get("package"):
        p = group["package"]
        desc = f"upgrade {p['name']} {p['current_version']} -> {p['target_version']}"
    desc = re.sub(r"\s+", " ", desc).strip()[:90]
    return f"[Fixpoint] {shown}: {desc}"


def render(group: dict[str, Any], findings: list[dict[str, Any]], meta: dict[str, Any],
           verification: dict[str, Any], run: dict[str, Any]) -> str:
    wrong, why = [], []
    for f in findings:
        loc = f.get("location") or {}
        where = f"`{loc.get('file')}:{loc.get('start_line')}`" if f["kind"] == "sast" else f"`{loc.get('file')}`"
        label = ", ".join(f.get("cve") or f.get("cwe") or [f.get("rule_id", "")])
        wrong.append(f"- **{label}** ({f.get('severity')}) at {where}: {_md_escape(f.get('title') or f.get('message', ''))}")
        if f["kind"] == "sast" and loc.get("snippet"):
            snippet = loc["snippet"].replace("```", "`​``").replace("<!--", "<!​--")
            code = "\n".join("  " + ln for ln in snippet.strip().splitlines())
            wrong.append(f"  ```\n{code}\n  ```")
        ev = [e for e in f.get("evidence") or [] if e.get("description")]
        why.append(f"- `{f['id']}` - {_md_escape(f.get('reasoning', ''))} (confidence {f.get('confidence')})")
        for e in ev[:6]:
            at = f" `{e['file']}:{e.get('line', 0)}`" if e.get("file") else ""
            why.append(f"  - {e.get('kind')}: {_md_escape(e['description'])}{at}")
        if f.get("path"):
            why.append("  - path: " + " -> ".join(_md_escape(p) for p in f["path"][:12]))
    checks = "\n".join(
        f"- {'✅' if c.get('passed') else '❌'} **{c['name']}**: {_md_escape(str(c.get('detail', '')))[:400]}"
        for c in verification.get("checks") or []
    )
    test = meta.get("test_added")
    test_line = f"`{test['path']}` ({_md_escape(test['name'])})" if test else "none (dependency upgrade)"
    values = {
        "what_wrong": "\n".join(wrong) or "-",
        "why_real": "\n".join(why) or "-",
        "what_changed": _md_escape(meta.get("rationale", "")) or "-",
        "files_changed": "\n".join(f"- `{p}`" for p in meta.get("changed_files") or []) or "-",
        "test_added": test_line,
        "checks": checks or "-",
        "actor": re.sub(r"[^A-Za-z0-9-]", "", str(run.get("actor", "unknown"))) or "unknown",
        "run_url": run.get("run_url", ""),
        "skill_version": meta.get("skill_version", ""),
        "skill": meta.get("skill", ""),
        "model": meta.get("model", ""),
        "base_sha": run.get("sha", ""),
        "group_id": group["id"],
        "findings_marker": findings_marker(group["finding_ids"]),
        "meta_marker": meta_marker({
            "group_id": group["id"], "finding_ids": sorted(group["finding_ids"]), "kind": group["kind"],
            "skill_version": meta.get("skill_version", ""), "model": meta.get("model", ""),
            "run_id": run.get("run_id", ""), "base_sha": run.get("sha", ""),
            "patch_sha256": meta.get("patch_sha256", ""),
        }),
    }
    return Template(TEMPLATE.read_text(encoding="utf-8")).substitute(values)
