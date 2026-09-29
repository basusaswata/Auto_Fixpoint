"""Version comparison good enough for choosing upgrade targets across ecosystems.

Verify re-checks the chosen version against OSV, so a comparison mistake can
only cause a rejected patch, never a vulnerable PR.
"""

from __future__ import annotations

import re
from functools import total_ordering

_RELEASE_QUALIFIERS = {"", "release", "final", "ga", "jre", "android"}


@total_ordering
class Version:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        s = raw.strip().lstrip("vV").split("+", 1)[0]
        m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", s)
        if not m:
            raise ValueError(f"unparseable version {raw!r}")
        self.nums = tuple(int(x) for x in m.group(1).split("."))
        rest = m.group(2).lstrip(".-_").lower()
        # post-releases sort after the release; everything else non-empty is a pre-release
        if rest.startswith("post") or rest in _RELEASE_QUALIFIERS:
            self.pre = None
            self.post = rest.startswith("post")
        else:
            self.pre = rest
            self.post = False

    def _key(self) -> tuple:
        nums = self.nums + (0,) * (6 - len(self.nums))
        return (nums[:6], 0 if self.pre is not None else 1, int(self.post), self.pre or "")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._key() == other._key()

    def __lt__(self, other: Version) -> bool:
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    @property
    def major(self) -> int:
        return self.nums[0]

    @property
    def minor(self) -> int:
        return self.nums[1] if len(self.nums) > 1 else 0

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None


def parse(raw: str) -> Version | None:
    try:
        return Version(raw)
    except ValueError:
        return None


def lowest_fix(current: str, fixed: list[str], same_major: bool) -> str | None:
    """Lowest fixed version above current (optionally in the same major), ignoring pre-releases."""
    cur = parse(current)
    if cur is None:
        return None
    cands = []
    for f in fixed:
        v = parse(f)
        if v is None or v.is_prerelease or not (v > cur):
            continue
        if same_major and v.major != cur.major:
            continue
        cands.append(v)
    return min(cands).raw if cands else None


def is_patch_bump(current: str, target: str) -> bool:
    a, b = parse(current), parse(target)
    return bool(a and b and a.major == b.major and a.minor == b.minor and b > a)
