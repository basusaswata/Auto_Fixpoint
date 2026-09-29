"""Signed handoff between the AI jobs and the publish job.

The sign job (no AI, no target-repo code, ``id-token: write``) packs each verified
patch into a canonical bundle and signs it with cosign keyless (Sigstore).
Publish verifies the signature against this workflow's OIDC identity before it
reads anything else from the bundle.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from fixpoint import log, rules
from fixpoint.config import Policy
from fixpoint.model import canonical_json, read_json, sha256_bytes, write_json

LOG = log.get(__name__)

BUNDLE_SCHEMA = "fixpoint/patch-bundle/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"


class SignError(RuntimeError):
    pass


def _cosign() -> str:
    path = shutil.which(os.environ.get("FIXPOINT_COSIGN_BIN", "cosign"))
    if not path:
        raise SignError("cosign not installed")
    return path


def sign_blob(path: Path) -> Path:
    out = path.with_suffix(".sigstore.json")
    r = subprocess.run([_cosign(), "sign-blob", "--yes", "--bundle", str(out), str(path)],
                       capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise SignError(f"cosign sign-blob failed: {log.redact(r.stderr)[-500:]}")
    return out


def verify_blob(path: Path, sig: Path, identity: str, issuer: str | None = None) -> None:
    # GHES: set FIXPOINT_OIDC_ISSUER to https://<host>/_services/token
    issuer = issuer or os.environ.get("FIXPOINT_OIDC_ISSUER") or OIDC_ISSUER
    if not identity:
        raise SignError("no signer identity configured")
    r = subprocess.run(
        [_cosign(), "verify-blob", "--bundle", str(sig), "--certificate-identity", identity,
         "--certificate-oidc-issuer", issuer, str(path)],
        capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        raise SignError(f"signature verification failed: {log.redact(r.stderr)[-500:]}")


def build_bundle(run: dict[str, Any], group: dict[str, Any], findings: list[dict[str, Any]], meta: dict[str, Any],
                 patch: str, verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": BUNDLE_SCHEMA,
        "run": {k: run.get(k, "") for k in ("repo", "branch", "sha", "run_id", "run_attempt", "actor", "run_url",
                                             "workflow_ref")},
        "group": group,
        "findings": findings,
        "meta": meta,
        "patch": patch,
        "patch_sha256": sha256_bytes(patch.encode("utf-8")),
        "verdicts": verdicts,
    }


def sign_all(plan: dict[str, Any], findings_by_id: dict[str, dict], fix_dir: Path, verdict_dirs: list[Path],
             run: dict[str, Any], policy: Policy, out_dir: Path, signing: str = "cosign") -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    verdicts: dict[str, list[dict]] = {}
    for d in verdict_dirs:
        for p in sorted(d.rglob("*.verdict.json")) if d.exists() else []:
            v = read_json(p)
            verdicts.setdefault(v["group_id"], []).append(v)
    results = []
    for g in plan["groups"]:
        gid = g["id"]
        res: dict[str, Any] = {"group_id": gid, "status": "skipped"}
        results.append(res)
        meta_p, patch_p = fix_dir / gid / "meta.json", fix_dir / gid / "patch.diff"
        if not meta_p.is_file() or not patch_p.is_file():
            res["reason"] = "no patch produced"
            continue
        meta = read_json(meta_p)
        patch = patch_p.read_text(encoding="utf-8")
        psha = sha256_bytes(patch.encode("utf-8"))
        if meta.get("patch_sha256") != psha:
            res["reason"] = "patch hash does not match fix metadata"
            continue
        vs = [v for v in verdicts.get(gid, []) if v.get("patch_sha256") == psha]
        phases = {v["phase"]: v for v in vs}
        missing = [ph for ph in ("rescan", "build") if ph not in phases]
        failed = [ph for ph, v in phases.items() if not v.get("passed")]
        if missing or failed:
            res["reason"] = f"verify missing {missing}" if missing else f"verify failed: {failed}"
            res["verdicts"] = vs
            continue
        # Policy check (#2 of 3) on the exact bytes being signed.
        checks = rules.check_patch(patch, policy, g, meta)
        if not rules.all_passed(checks):
            res["reason"] = "policy rejected at sign: " + "; ".join(c["detail"] for c in checks if not c["passed"])
            continue
        bundle = build_bundle(run, g, [findings_by_id[i] for i in g["finding_ids"] if i in findings_by_id],
                              meta, patch, [phases["rescan"], phases["build"]])
        bpath = out_dir / f"{gid}.bundle.json"
        bpath.write_bytes(canonical_json(bundle))
        if signing == "cosign":
            try:
                sign_blob(bpath)
            except SignError as e:
                bpath.unlink()
                res["reason"] = str(e)
                continue
        res["status"] = "signed" if signing == "cosign" else "unsigned"
        res.pop("reason", None)
    write_json(out_dir / "sign.json", {"results": results})
    return results


def load_verified_bundle(bpath: Path, identity: str, signing: str = "cosign") -> dict[str, Any]:
    """Verify first, parse second."""
    if signing == "cosign":
        verify_blob(bpath, bpath.with_suffix(".sigstore.json"), identity)
    raw = bpath.read_bytes()
    bundle = json.loads(raw)
    if bundle.get("schema") != BUNDLE_SCHEMA:
        raise SignError("not a Fixpoint patch bundle")
    if canonical_json(bundle) != raw:
        raise SignError("bundle is not in canonical form")
    if sha256_bytes(bundle["patch"].encode("utf-8")) != bundle["patch_sha256"]:
        raise SignError("bundle patch hash mismatch")
    return bundle
