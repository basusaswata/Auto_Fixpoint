"""The common finding format and the JSON documents passed between stages.

Every stage reads and writes JSON. A findings document looks like::

    {"schema": "fixpoint/findings/v1", "meta": {...}, "findings": [Finding, ...]}

See docs/ARCHITECTURE.md for the field-by-field description.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

FINDINGS_SCHEMA = "fixpoint/findings/v1"
PLAN_SCHEMA = "fixpoint/plan/v1"

KINDS = ("sast", "sca")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = worse

# Status is set by align and dedupe. Only "open" findings go on to triage.
STATUSES = ("open", "stale", "unlocatable", "in_flight", "fixed", "rejected")
# Disposition is set by triage.
DISPOSITIONS = ("fix", "false_positive", "not_reachable", "accepted_risk", "human_review")


class FormatError(ValueError):
    """Raised when a document does not match the expected format."""


def normalise_severity(value: Any) -> str:
    v = str(value or "").strip().lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "moderate": "medium",
        "note": "low",
        "none": "info",
        "informational": "info",
        "negligible": "info",
        "unknown": "medium",
    }
    v = aliases.get(v, v)
    return v if v in SEVERITY_RANK else "medium"


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def normalise_cwe(value: Any) -> str | None:
    m = re.search(r"(?i)cwe[-_ :]?(\d+)", str(value or ""))
    if m:
        return f"CWE-{int(m.group(1))}"
    if str(value).isdigit():
        return f"CWE-{int(value)}"
    return None


def normalise_path(path: str) -> str:
    p = (path or "").replace("\\", "/")
    p = re.sub(r"^file://", "", p)
    while p.startswith("./"):
        p = p[2:]
    return re.sub(r"/{2,}", "/", p)


def is_safe_relpath(path: str) -> bool:
    """A repo-relative path with no traversal and no absolute prefix."""
    if not path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return False
    return ".." not in Path(path).parts


def normalise_snippet(snippet: str | None) -> str:
    """Whitespace-insensitive form used for fingerprints and re-anchoring."""
    if not snippet:
        return ""
    lines = [re.sub(r"\s+", " ", ln.strip()) for ln in snippet.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def _digest(*parts: str) -> str:
    h = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return h[:20]


@dataclass
class Location:
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""


@dataclass
class Package:
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    manifest: str = ""


@dataclass
class Evidence:
    kind: str = "note"  # source_to_sink | reachability | code | advisory | note
    description: str = ""
    file: str = ""
    line: int = 0


@dataclass
class Finding:
    kind: str
    source: str  # report:<scanner> | discover:<skill>
    rule_id: str = ""
    title: str = ""
    message: str = ""
    severity: str = "medium"
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    location: Location = field(default_factory=Location)
    package: Package | None = None
    # Discover-time flow description, e.g. ["request.args['q'] (app.py:10)", "cursor.execute (db.py:44)"]
    path: list[str] = field(default_factory=list)
    # Set by later stages
    id: str = ""
    confidence: float | None = None
    status: str = "open"
    disposition: str | None = None
    reasoning: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise FormatError(f"unknown kind {self.kind!r}")
        self.severity = normalise_severity(self.severity)
        self.cwe = sorted({c for c in (normalise_cwe(x) for x in self.cwe) if c})
        self.cve = sorted({str(c).strip().upper() for c in self.cve if str(c).strip()})
        self.location.file = normalise_path(self.location.file)
        if not self.id:
            self.id = fingerprint(self)

    # -- serialisation -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.package is None:
            d.pop("package")
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        d = dict(d)
        loc = Location(**_known(Location, d.pop("location", None) or {}))
        pkg_raw = d.pop("package", None)
        pkg = Package(**_known(Package, pkg_raw)) if pkg_raw else None
        ev = [Evidence(**_known(Evidence, e)) for e in d.pop("evidence", None) or []]
        f = cls(location=loc, package=pkg, evidence=ev, **_known(cls, d))
        if f.status not in STATUSES:
            raise FormatError(f"{f.id}: unknown status {f.status!r}")
        if f.disposition is not None and f.disposition not in DISPOSITIONS:
            raise FormatError(f"{f.id}: unknown disposition {f.disposition!r}")
        return f


def _known(cls: type, d: dict[str, Any]) -> dict[str, Any]:
    names = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
    return {k: v for k, v in d.items() if k in names}


def fingerprint(f: Finding) -> str:
    """Stable id. Independent of line numbers, scanner and message wording.

    SAST: CWE + file + normalised snippet (falls back to rule id without a CWE).
    SCA:  ecosystem + package + version + CVEs (falls back to rule id without CVEs).
    """
    if f.kind == "sca":
        pkg = f.package or Package()
        vulns = ",".join(f.cve) or f.rule_id
        return "sca-" + _digest("sca", pkg.ecosystem.lower(), pkg.name.lower(), pkg.version, vulns)
    cwe = ",".join(f.cwe) or f.rule_id
    snippet = normalise_snippet(f.location.snippet)
    if not snippet:
        # No snippet: the line number is all we have. Such findings are
        # usually unlocatable later, but the id must still be deterministic.
        snippet = f"@{f.location.start_line}"
    return "sast-" + _digest("sast", cwe, f.location.file, snippet)


# -- documents ------------------------------------------------------------


def write_json(path: str | os.PathLike[str], doc: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)


def read_json(path: str | os.PathLike[str]) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def findings_doc(findings: list[Finding], meta: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": FINDINGS_SCHEMA,
        "meta": meta or {},
        "findings": [f.to_dict() for f in findings],
    }


def load_findings(path: str | os.PathLike[str]) -> tuple[list[Finding], dict[str, Any]]:
    doc = read_json(path)
    if not isinstance(doc, dict) or doc.get("schema") != FINDINGS_SCHEMA:
        raise FormatError(f"{path}: not a {FINDINGS_SCHEMA} document")
    return [Finding.from_dict(x) for x in doc.get("findings", [])], dict(doc.get("meta") or {})


def save_findings(path: str | os.PathLike[str], findings: list[Finding], meta: dict[str, Any] | None = None) -> None:
    write_json(path, findings_doc(findings, meta))


def merge_findings(*groups: list[Finding]) -> list[Finding]:
    """Merge lists, collapsing identical fingerprints (first one wins, sources recorded)."""
    out: dict[str, Finding] = {}
    for group in groups:
        for f in group:
            if f.id in out:
                existing = out[f.id]
                srcs = existing.properties.setdefault("also_reported_by", [])
                if f.source != existing.source and f.source not in srcs:
                    srcs.append(f.source)
                if SEVERITY_RANK[f.severity] < SEVERITY_RANK[existing.severity]:
                    existing.severity = f.severity
            else:
                out[f.id] = f
    return list(out.values())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
