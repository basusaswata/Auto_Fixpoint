"""Prompt templates (prompts/*.md) rendered with ``string.Template``.

Only the template is interpreted; substituted values are inserted verbatim,
so untrusted content cannot introduce new placeholders.
"""

from __future__ import annotations

from pathlib import Path
from string import Template

# Shipped inside the package (package data), so it works after a plain `pip install .`
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def render(name: str, **values: object) -> str:
    text = (PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")
    return Template(text).substitute({k: str(v) for k, v in values.items()})
