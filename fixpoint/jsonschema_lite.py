"""A small JSON Schema validator (the subset Fixpoint's schemas use).

Supports: type, properties, required, additionalProperties (bool), items,
enum, minimum, maximum, minLength, maxLength, maxItems, pattern.
Keeps the dependency list to pyyaml + requests.
"""

from __future__ import annotations

import re
from typing import Any

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


class ValidationError(ValueError):
    pass


def _is_type(value: Any, t: str) -> bool:
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[t])


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_is_type(value, x) for x in types):
            raise ValidationError(f"{path}: expected {t}, got {type(value).__name__}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(f"{path}: {value!r} not in {schema['enum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValidationError(f"{path}: {value} < {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValidationError(f"{path}: {value} > {schema['maximum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ValidationError(f"{path}: string too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ValidationError(f"{path}: string too long")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise ValidationError(f"{path}: does not match {schema['pattern']}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                raise ValidationError(f"{path}: missing required {req!r}")
        for k, v in value.items():
            if k in props:
                validate(v, props[k], f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                raise ValidationError(f"{path}: unexpected property {k!r}")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ValidationError(f"{path}: too many items")
        if "items" in schema:
            for i, item in enumerate(value):
                validate(item, schema["items"], f"{path}[{i}]")
