"""Structured-output schemas for every agent role (passed to --json-schema)."""

from __future__ import annotations

SEVERITY = {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}
CONFIDENCE = {"type": "number", "minimum": 0, "maximum": 1}
LINE = {"type": "integer", "minimum": 0}
SHORT = {"type": "string", "maxLength": 2000}
LONG = {"type": "string", "maxLength": 8000}

EVIDENCE = {
    "type": "object",
    "properties": {
        "kind": {"type": "string", "enum": ["source_to_sink", "reachability", "code", "advisory", "note"]},
        "description": SHORT,
        "file": {"type": "string", "maxLength": 500},
        "line": LINE,
    },
    "required": ["kind", "description"],
    "additionalProperties": False,
}

DISCOVER_SAST = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 200,
            "items": {
                "type": "object",
                "properties": {
                    "cwe": {"type": "string", "pattern": "^CWE-[0-9]+$"},
                    "rule_id": {"type": "string", "maxLength": 200},
                    "title": {"type": "string", "maxLength": 300},
                    "message": SHORT,
                    "file": {"type": "string", "maxLength": 500},
                    "start_line": LINE,
                    "end_line": LINE,
                    "snippet": {"type": "string", "maxLength": 4000},
                    "severity": SEVERITY,
                    "confidence": CONFIDENCE,
                    "source": SHORT,
                    "sink": SHORT,
                    "source_to_sink": {"type": "array", "maxItems": 30, "items": SHORT},
                },
                "required": ["cwe", "rule_id", "title", "message", "file", "start_line", "end_line",
                             "snippet", "severity", "confidence", "source_to_sink"],
                "additionalProperties": False,
            },
        },
        "files_reviewed": {"type": "array", "items": {"type": "string"}},
        "notes": SHORT,
    },
    "required": ["findings", "files_reviewed"],
    "additionalProperties": False,
}

ECOSYSTEMS = ["npm", "PyPI", "Go", "Maven", "RubyGems", "Packagist", "crates.io", "NuGet"]

DISCOVER_SCA = {
    "type": "object",
    "properties": {
        "dependencies": {
            "type": "array",
            "maxItems": 2000,
            "items": {
                "type": "object",
                "properties": {
                    "ecosystem": {"type": "string", "enum": ECOSYSTEMS},
                    "name": {"type": "string", "maxLength": 300},
                    "version": {"type": "string", "maxLength": 100},
                    "pinned": {"type": "boolean"},
                    "manifest": {"type": "string", "maxLength": 500},
                    "line": LINE,
                    "direct": {"type": "boolean"},
                    "concern": SHORT,
                },
                "required": ["ecosystem", "name", "version", "pinned", "manifest"],
                "additionalProperties": False,
            },
        },
        "notes": SHORT,
    },
    "required": ["dependencies"],
    "additionalProperties": False,
}

TRIAGE = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "maxLength": 100},
                    "disposition": {
                        "type": "string",
                        "enum": ["fix", "false_positive", "not_reachable", "accepted_risk", "human_review"],
                    },
                    "confidence": CONFIDENCE,
                    "reasoning": LONG,
                    "evidence": {"type": "array", "maxItems": 20, "items": EVIDENCE},
                },
                "required": ["id", "disposition", "confidence", "reasoning", "evidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["results"],
    "additionalProperties": False,
}

FIX = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["fixed", "cannot_fix"]},
        "rationale": LONG,
        "test_added": {
            "type": ["object", "null"],
            "properties": {"path": {"type": "string", "maxLength": 500}, "name": {"type": "string", "maxLength": 300}},
            "required": ["path", "name"],
            "additionalProperties": False,
        },
        "changed_files": {"type": "array", "maxItems": 100, "items": {"type": "string", "maxLength": 500}},
        "new_version": {"type": "string", "maxLength": 100},
        "notes": SHORT,
    },
    "required": ["status", "rationale", "test_added", "changed_files"],
    "additionalProperties": False,
}

VERIFY = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "maxLength": 100},
                    "fixed": {"type": "boolean"},
                    "reasoning": LONG,
                },
                "required": ["id", "fixed", "reasoning"],
                "additionalProperties": False,
            },
        },
        "new_issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cwe": {"type": "string", "maxLength": 20},
                    "file": {"type": "string", "maxLength": 500},
                    "line": LINE,
                    "description": SHORT,
                    "severity": SEVERITY,
                },
                "required": ["description", "severity"],
                "additionalProperties": False,
            },
        },
        "test_meaningful": {"type": "boolean"},
        "confidence": CONFIDENCE,
        "summary": LONG,
    },
    "required": ["findings", "new_issues", "test_meaningful", "confidence", "summary"],
    "additionalProperties": False,
}
