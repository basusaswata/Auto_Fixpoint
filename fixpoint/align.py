"""Re-anchor findings to the pinned commit by snippet, not by line number.

* file gone                        -> stale
* snippet found (exact, normalised) -> open, lines updated (nearest match wins)
* snippet found fuzzily (>= 0.85)  -> open, lines updated, note recorded
* snippet not found                -> stale (the code is gone)
* no snippet: report revision == pinned sha and line in range -> open (snippet filled)
              otherwise                                        -> unlocatable
* SCA: manifest present and names the package at that version -> open;
       manifest present but version gone -> stale; no manifest found -> unlocatable
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from fixpoint import log
from fixpoint.model import Finding, is_safe_relpath, normalise_path, normalise_snippet

LOG = log.get(__name__)
FUZZY_THRESHOLD = 0.85


def _norm_lines(text: str) -> list[str]:
    return [normalise_snippet(ln) for ln in text.splitlines()]


def locate(file_lines: list[str], snippet: str, hint_line: int) -> tuple[int, int, bool] | None:
    """Return (start, end, exact) 1-indexed for the best match of snippet in the file."""
    want = [ln for ln in _norm_lines(snippet) if ln]
    if not want:
        return None
    norm = _norm_lines("\n".join(file_lines))
    # Index of non-empty lines so blank-line differences don't break matching.
    idx = [i for i, ln in enumerate(norm) if ln]
    seq = [norm[i] for i in idx]
    n = len(want)
    exact = [k for k in range(len(seq) - n + 1) if seq[k : k + n] == want]
    if exact:
        best = min(exact, key=lambda k: abs(idx[k] + 1 - hint_line))
        return idx[best] + 1, idx[best + n - 1] + 1, True
    target = "\n".join(want)
    best_k, best_ratio = -1, 0.0
    for k in range(len(seq) - n + 1):
        ratio = difflib.SequenceMatcher(None, "\n".join(seq[k : k + n]), target, autojunk=False).ratio()
        if ratio > best_ratio or (ratio == best_ratio and best_k >= 0
                                  and abs(idx[k] + 1 - hint_line) < abs(idx[best_k] + 1 - hint_line)):
            best_k, best_ratio = k, ratio
    if best_k >= 0 and best_ratio >= FUZZY_THRESHOLD:
        return idx[best_k] + 1, idx[best_k + n - 1] + 1, False
    return None


def align_sast(f: Finding, repo: Path, pinned_sha: str) -> None:
    rel = normalise_path(f.location.file)
    if not is_safe_relpath(rel):
        f.status, f.reasoning = "unlocatable", "unsafe or empty path"
        return
    path = repo / rel
    if path.is_symlink() or not path.is_file():
        f.status, f.reasoning = "stale", f"{rel} no longer exists at {pinned_sha[:12]}"
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not normalise_snippet(f.location.snippet):
        rev = str(f.properties.get("report_revision") or "")
        if rev and pinned_sha.startswith(rev[:12]) and 1 <= f.location.start_line <= len(lines):
            end = min(max(f.location.end_line, f.location.start_line), len(lines))
            f.location.snippet = "\n".join(lines[f.location.start_line - 1 : end])
            f.location.end_line = end
            f.notes.append("anchored by line: report revision matches pinned commit")
            return
        f.status, f.reasoning = "unlocatable", "no snippet to re-anchor and report revision differs from pin"
        return
    hit = locate(lines, f.location.snippet, f.location.start_line)
    if hit is None:
        f.status, f.reasoning = "stale", f"snippet not found in {rel} at {pinned_sha[:12]}"
        return
    start, end, exact = hit
    if (start, end) != (f.location.start_line, f.location.end_line):
        f.notes.append(f"re-anchored from line {f.location.start_line} to {start}")
    if not exact:
        f.notes.append("fuzzy snippet match")
    f.location.start_line, f.location.end_line = start, end


def align_sca(f: Finding, repo: Path, manifests: list[str] | None = None) -> None:
    pkg = f.package
    if pkg is None or not pkg.name:
        f.status, f.reasoning = "unlocatable", "no package information"
        return
    name = pkg.name.split(":")[-1]
    # whole-token match: "h2" must not match "com.h2database", "spring-web" not "spring-webmvc"
    name_re = re.compile(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])")
    own = normalise_path(pkg.manifest) if pkg.manifest else ""
    candidates = [own] if own else []
    candidates += [m for m in manifests or [] if m not in candidates]
    for rel in candidates:
        if not rel or not is_safe_relpath(rel):
            continue
        p = repo / rel
        if not p.is_file() or p.is_symlink():
            continue
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        hits = [i for i, ln in enumerate(lines) if name_re.search(ln)]
        if not hits:
            continue
        # The version may sit on the same line (requirements.txt) or a few lines below (pom.xml).
        # Never read past the end of this dependency block into the next one.
        window = {i: re.split(r"</(dependency|plugin|parent)>", "\n".join(lines[i : i + 4]))[0] for i in hits}
        exact = [i for i in hits if pkg.version and pkg.version in window[i]]
        pinned_other = [i for i in hits if re.search(r"\d+\.\d+", window[i]) and i not in exact]
        if exact:
            at = exact[0]
        elif pinned_other:
            if rel == own:
                f.status, f.reasoning = "stale", f"{pkg.name}@{pkg.version} no longer in {rel}"
                return
            continue
        else:
            at = hits[0]  # declared without a version: managed by a parent / BOM
            f.properties["managed"] = True
            f.notes.append(f"{pkg.name} is declared in {rel} without a version (managed by a parent/BOM)")
        pkg.manifest = rel
        f.location.file = rel
        f.location.start_line = f.location.end_line = at + 1
        f.location.snippet = lines[at].strip()[:500]
        return
    if own and (repo / own).is_file() and re.match(r"^(scanner|report):", f.source):
        # A scanner resolved it through the dependency tree: a transitive dependency.
        f.properties["transitive"] = True
        f.location.file = own
        f.notes.append(f"{pkg.name}@{pkg.version} is a transitive dependency of {own} (not declared directly)")
        return
    if own and not (repo / own).exists():
        f.status, f.reasoning = "stale", f"manifest {pkg.manifest} no longer exists"
    else:
        f.status, f.reasoning = "unlocatable", f"{pkg.name} not found in any manifest"


def align(findings: list[Finding], repo: Path, pinned_sha: str, manifests: list[str] | None = None) -> list[Finding]:
    for f in findings:
        if f.status != "open":
            continue
        if f.kind == "sast":
            align_sast(f, repo, pinned_sha)
        else:
            align_sca(f, repo, manifests)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    LOG.info("align: %s", counts)
    return findings
