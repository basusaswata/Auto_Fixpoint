"""Parse and apply git unified diffs (text files only).

The same applier is used by verify (onto the checkout) and publish (onto blobs
fetched from the current head), so the tree that was tested is the tree that is
committed. Context must match exactly; hunks may shift (moved base) but never fuzz.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from fixpoint.model import is_safe_relpath

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchError(ValueError):
    pass


class Conflict(PatchError):
    pass


@dataclass
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    lines: list[tuple[str, str]] = field(default_factory=list)  # (op, text) op in ' ', '-', '+'
    old_no_eol: bool = False
    new_no_eol: bool = False

    @property
    def old_seg(self) -> list[str]:
        return [t for op, t in self.lines if op in " -"]

    @property
    def new_seg(self) -> list[str]:
        return [t for op, t in self.lines if op in " +"]


@dataclass
class FilePatch:
    path: str
    status: str  # added | modified | deleted
    hunks: list[Hunk] = field(default_factory=list)
    binary: bool = False
    mode_change: bool = False
    new_mode: str = "100644"
    rename: bool = False

    @property
    def added(self) -> int:
        return sum(1 for h in self.hunks for op, _ in h.lines if op == "+")

    @property
    def removed(self) -> int:
        return sum(1 for h in self.hunks for op, _ in h.lines if op == "-")

    def removed_lines(self) -> list[str]:
        return [t for h in self.hunks for op, t in h.lines if op == "-"]

    def added_lines(self) -> list[str]:
        return [t for h in self.hunks for op, t in h.lines if op == "+"]


def _strip_prefix(p: str) -> str:
    if p.startswith('"'):
        raise PatchError(f"quoted paths are not supported: {p}")
    if p == "/dev/null":
        return p
    return p[2:] if p[:2] in ("a/", "b/") else p


def parse(text: str) -> list[FilePatch]:
    files: list[FilePatch] = []
    cur: FilePatch | None = None
    hunk: Hunk | None = None
    old_path = new_path = ""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("diff --git "):
            m = re.match(r"^diff --git (\S+) (\S+)$", ln)
            if not m:
                raise PatchError(f"unsupported diff header: {ln[:200]}")
            new_path = _strip_prefix(m.group(2))
            cur = FilePatch(path=new_path, status="modified")
            files.append(cur)
            hunk = None
        elif cur is None:
            raise PatchError("patch text before first diff header")
        elif hunk is None and ln.startswith("new file mode "):
            cur.status, cur.new_mode = "added", ln.split()[-1]
        elif hunk is None and ln.startswith("deleted file mode "):
            cur.status = "deleted"
        elif hunk is None and (ln.startswith("old mode ") or ln.startswith("new mode ")):
            cur.mode_change = True
        elif hunk is None and (ln.startswith("rename ") or ln.startswith("copy ") or ln.startswith("similarity ")):
            cur.rename = True
        elif hunk is None and (ln.startswith("Binary files ") or ln.startswith("GIT binary patch")):
            cur.binary = True
        elif hunk is None and ln.startswith("index "):
            parts = ln.split()
            if len(parts) == 3 and cur.status == "modified":
                cur.new_mode = parts[2]
        elif hunk is None and ln.startswith("--- "):
            old_path = _strip_prefix(ln[4:])
        elif hunk is None and ln.startswith("+++ "):
            new_path = _strip_prefix(ln[4:])
            if new_path != "/dev/null":
                cur.path = new_path
            elif old_path != "/dev/null":
                cur.path = old_path
        elif ln.startswith("@@"):
            m = HUNK_RE.match(ln)
            if not m:
                raise PatchError(f"bad hunk header: {ln[:200]}")
            hunk = Hunk(int(m.group(1)), int(m.group(2) or 1), int(m.group(3)), int(m.group(4) or 1))
            cur.hunks.append(hunk)
        elif hunk is not None and ln[:1] in (" ", "-", "+"):
            hunk.lines.append((ln[0], ln[1:]))
        elif hunk is not None and ln == "":
            hunk.lines.append((" ", ""))  # some tools strip the space on empty context lines
        elif hunk is not None and ln.startswith("\\"):
            op = hunk.lines[-1][0] if hunk.lines else " "
            if op in " -":
                hunk.old_no_eol = True
            if op in " +":
                hunk.new_no_eol = True
        else:
            raise PatchError(f"unexpected patch line: {ln[:200]}")
        i += 1
    for f in files:
        if not f.binary and not is_safe_relpath(f.path):
            raise PatchError(f"unsafe path in patch: {f.path}")
        for h in f.hunks:
            if len(h.old_seg) != h.old_len or len(h.new_seg) != h.new_len:
                raise PatchError(f"{f.path}: hunk line counts do not match header")
    return files


def _find(haystack: list[str], needle: list[str], preferred: int, lo: int) -> int:
    n = len(needle)
    if n == 0:
        return max(lo, min(preferred, len(haystack)))
    positions = [k for k in range(lo, len(haystack) - n + 1) if haystack[k : k + n] == needle]
    if not positions:
        raise Conflict("context does not match")
    return min(positions, key=lambda k: (abs(k - preferred), k))


def apply_file(content: str | None, fp: FilePatch) -> str | None:
    """Apply one file patch to content (None = file absent). Returns new content, None = delete."""
    if fp.binary or fp.mode_change or fp.rename:
        raise PatchError(f"{fp.path}: binary/mode/rename changes are not supported")
    if fp.status == "added":
        if content is not None:
            raise Conflict(f"{fp.path}: file already exists")
        content = ""
    elif content is None:
        raise Conflict(f"{fp.path}: file does not exist")
    if content == "":
        lines, eol = [], False
    else:
        lines = content.split("\n")
        eol = lines[-1] == ""
        if eol:
            lines.pop()
    offset, lo = 0, 0
    for h in fp.hunks:
        preferred = (h.old_start - 1 if h.old_len else h.old_start) + offset
        try:
            pos = _find(lines, h.old_seg, preferred, lo)
        except Conflict as e:
            raise Conflict(f"{fp.path}: hunk @@ -{h.old_start},{h.old_len} does not apply ({e})") from e
        end = pos + len(h.old_seg)
        touches_end = end == len(lines)
        lines[pos:end] = h.new_seg
        offset += len(h.new_seg) - len(h.old_seg)
        lo = pos + len(h.new_seg)
        if touches_end:
            eol = not h.new_no_eol and bool(lines)
    if fp.status == "deleted":
        if lines:
            raise Conflict(f"{fp.path}: deleted file content does not match")
        return None
    return "\n".join(lines) + ("\n" if eol else "")


def stats(files: list[FilePatch]) -> tuple[int, int]:
    """(changed files, changed lines)."""
    return len(files), sum(f.added + f.removed for f in files)
