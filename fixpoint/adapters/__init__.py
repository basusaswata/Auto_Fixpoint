"""Report adapters: scanner output -> common finding format.

To add an adapter: write ``parse(doc, kind) -> list[Finding]`` in a new module,
register it in ``ADAPTERS`` and teach ``detect`` to recognise it.
"""

from __future__ import annotations

from typing import Any, Callable

from fixpoint.adapters import osv, sarif, snyk
from fixpoint.model import Finding, FormatError

ADAPTERS: dict[str, Callable[[Any, str], list[Finding]]] = {
    "sarif": sarif.parse,
    "snyk": snyk.parse,
    "osv": osv.parse,
}

FORMATS_FOR_KIND = {"sast": ("sarif",), "sca": ("snyk", "osv", "sarif")}


def detect(doc: Any) -> str:
    if isinstance(doc, dict) and "runs" in doc and str(doc.get("version", "")).startswith("2."):
        return "sarif"
    if isinstance(doc, dict) and isinstance(doc.get("results"), list) and all(
        isinstance(r, dict) and "packages" in r for r in doc["results"]
    ):
        return "osv"
    if isinstance(doc, dict) and "vulnerabilities" in doc:
        return "snyk"
    if isinstance(doc, list) and doc and all(isinstance(x, dict) and "vulnerabilities" in x for x in doc):
        return "snyk"
    raise FormatError("could not auto-detect report format")


def parse(doc: Any, fmt: str, kind: str) -> list[Finding]:
    if fmt == "auto":
        fmt = detect(doc)
    if fmt not in ADAPTERS:
        raise FormatError(f"unknown report format {fmt!r}")
    if fmt not in FORMATS_FOR_KIND[kind]:
        raise FormatError(f"format {fmt} cannot carry {kind} findings")
    return ADAPTERS[fmt](doc, kind)
