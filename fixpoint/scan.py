"""DISCOVER mode.

SAST: files chosen by policy, riskiest first, reviewed in batches by the review skill.
SCA:  engine ``skill`` - the supply-chain skill inventories manifests, then every
      dependency is looked up in OSV (deterministic); engine ``osv-scanner`` - run
      the OSV-Scanner binary. The model never decides versions or CVE ids.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fixpoint import adapters, log, prompts, schemas
from fixpoint.agent import AgentError, AgentRequest, AgentRuntime, skills_dir, wrap_untrusted
from fixpoint.config import Policy, SkillsLock, any_glob, glob_match
from fixpoint.model import Evidence, Finding, Location, is_safe_relpath, merge_findings, normalise_path
from fixpoint.osvapi import Dependency, OsvClient, OsvError

LOG = log.get(__name__)

# Risk categories: (name, path regex, content regex).
RISK = [
    ("entry", r"(main|app|server|index|routes?|controllers?|handlers?|views?|api|endpoints?|urls|servlet|resource)",
     r"(@app\.route|@(Get|Post|Put|Delete|Request)Mapping|router\.(get|post|put|delete)|app\.(get|post)\(|"
     r"http\.HandleFunc|@RestController|def (get|post)\(self|express\(\))"),
    ("auth", r"(auth|login|logout|session|jwt|oauth|saml|password|token|acl|permission|rbac)",
     r"(password|jwt\.|verify_password|bcrypt|authenticate|authoriz|session\[|setCookie|set_cookie)"),
    ("data", r"(db|database|sql|query|repositor(y|ies)|dao|models?|orm|store|persistence)",
     r"(execute\(|executeQuery|rawQuery|\.query\(|cursor\.|SELECT |INSERT |UPDATE |DELETE FROM|\$where|find\(\{)"),
    ("crypto", r"(crypto|cipher|hash|encrypt|decrypt|ssl|tls|cert|sign|hmac|random)",
     r"(md5|sha1|DES|ECB|Cipher\.getInstance|createCipher|hashlib\.|Math\.random|random\.random|verify=False|"
     r"InsecureSkipVerify|rejectUnauthorized)"),
    ("deser", r"(serial|pickle|marshal|yaml|xml|parser)",
     r"(pickle\.loads?|yaml\.load\(|unserialize\(|ObjectInputStream|readObject\(|marshal\.loads|"
     r"XMLDecoder|BinaryFormatter|DocumentBuilderFactory|etree\.parse)"),
    ("template", r"(template|render|view|html|jinja|jsp|erb|handlebars)",
     r"(render_template_string|innerHTML|dangerouslySetInnerHTML|\|\s*safe|Markup\(|v-html|th:utext|"
     r"<%=|document\.write)"),
    ("upload", r"(upload|multipart|files?|attachment|storage|download|static)",
     r"(multer|request\.files|MultipartFile|save\(|send_file|sendFile|open\(.*\+|path\.join\(.*req)"),
    ("exec", r"(exec|shell|command|cmd|process|spawn|script|eval)",
     r"(subprocess\.|os\.system|os\.popen|Runtime\.getRuntime|ProcessBuilder|child_process|exec\(|execSync|"
     r"spawn\(|eval\(|shell=True|new Function\()"),
]
_RISK_RE = [(n, re.compile(p, re.I), re.compile(c)) for n, p, c in RISK]


@dataclass
class ScanResult:
    findings: list[Finding]
    meta: dict[str, Any]


# -- file selection ---------------------------------------------------------


def list_repo_files(repo: Path) -> list[str]:
    if (repo / ".git").exists():
        r = subprocess.run(["git", "ls-files", "-z"], cwd=repo, capture_output=True, check=False)
        if r.returncode == 0:
            return sorted(p for p in r.stdout.decode("utf-8", "replace").split("\0") if p)
    out = []
    for p in repo.rglob("*"):
        rel = p.relative_to(repo)
        if p.is_file() and not p.is_symlink() and ".git" not in rel.parts:
            out.append(rel.as_posix())
    return sorted(out)


def risk_score(rel: str, content: str) -> tuple[int, list[str]]:
    score, cats = 0, []
    for name, path_re, content_re in _RISK_RE:
        hit = 0
        if path_re.search(rel):
            hit += 3
        if content_re.search(content):
            hit += 2
        if hit:
            cats.append(name)
            score += hit
    return score, cats


def select_files(repo: Path, policy: Policy) -> list[tuple[str, int, list[str]]]:
    cfg = policy.discover["sast"]
    exts = {e.lower() for e in cfg.get("extensions") or []}
    excludes = list(cfg.get("excludes") or []) + policy.forbidden_paths
    max_bytes = int(cfg.get("max_file_bytes", 200000))
    ranked = []
    for rel in list_repo_files(repo):
        if not is_safe_relpath(rel) or Path(rel).suffix.lower() not in exts or any_glob(rel, excludes):
            continue
        p = repo / rel
        if p.is_symlink() or not p.is_file():
            continue
        size = p.stat().st_size
        if size == 0 or size > max_bytes:
            continue
        content = p.read_text(encoding="utf-8", errors="replace")[:50000]
        score, cats = risk_score(rel, content)
        ranked.append((rel, score, cats))
    ranked.sort(key=lambda t: (-t[1], t[0]))
    return ranked[: int(cfg.get("max_files", 60))]


def batched(items: list, size: int) -> list[list]:
    size = max(1, size)
    return [items[i : i + size] for i in range(0, len(items), size)]


# -- SAST ---------------------------------------------------------------------


def discover_sast(repo_dir: Path, repo: str, sha: str, policy: Policy, lock: SkillsLock,
                  runtime: AgentRuntime) -> ScanResult:
    cfg = policy.discover["sast"]
    skill = lock.skill("review")
    selected = select_files(repo_dir, policy)
    batches = batched(selected, int(cfg.get("batch_size", 8)))
    findings: list[Finding] = []
    errors: list[str] = []
    reviewed: set[str] = set()
    min_conf = float(cfg.get("min_confidence", 0.0))
    for i, batch in enumerate(batches, 1):
        files = [rel for rel, _, _ in batch]
        listing = "\n".join(f"- {rel}  (risk: {', '.join(c) or 'baseline'})" for rel, _, c in batch)
        prompt = prompts.render(
            "discover-sast", skill=skill, skills_dir=skills_dir(), repo=repo, sha=sha,
            batch=i, batches=len(batches), files=wrap_untrusted("file-list", listing),
        )
        req = AgentRequest(
            role="review", prompt=prompt, schema=schemas.DISCOVER_SAST, cwd=repo_dir,
            add_dirs=[skills_dir()], max_budget_usd=float(cfg.get("max_budget_usd", 4.0)),
        )
        try:
            res = runtime.run(req)
        except AgentError as e:
            LOG.error("discover batch %d/%d failed: %s", i, len(batches), e)
            errors.append(f"batch {i}: {e}")
            continue
        reviewed |= set(res.data.get("files_reviewed") or [])
        allowed = set(files)
        for raw in res.data["findings"]:
            rel = normalise_path(raw["file"])
            if rel not in allowed or not is_safe_relpath(rel):
                LOG.warning("dropping discover finding outside batch: %s", rel)
                continue
            if raw["confidence"] < min_conf:
                continue
            f = Finding(
                kind="sast",
                source=f"discover:{skill}",
                rule_id=raw["rule_id"],
                title=raw["title"],
                message=raw["message"],
                severity=raw["severity"],
                cwe=[raw["cwe"]],
                location=Location(file=rel, start_line=raw["start_line"],
                                  end_line=max(raw["end_line"], raw["start_line"]), snippet=raw["snippet"]),
                path=list(raw.get("source_to_sink") or []),
                confidence=raw["confidence"],
                evidence=[Evidence(kind="source_to_sink", description=" -> ".join(raw["source_to_sink"]))]
                if raw.get("source_to_sink") else [],
                properties={"discover_model": res.model, "source": raw.get("source", ""), "sink": raw.get("sink", "")},
            )
            findings.append(f)
    meta = {
        "sast_mode": "discover",
        "sast_engine": f"skill:{skill}",
        "files_selected": [rel for rel, _, _ in selected],
        "files_reviewed": sorted(reviewed),
        "batches": len(batches),
        "discover_errors": errors,
    }
    return ScanResult(merge_findings(findings), meta)


# -- SCA ------------------------------------------------------------------------


def find_manifests(repo_dir: Path, policy: Policy) -> list[str]:
    names = list(policy.discover["sca"].get("manifests") or [])
    excludes = ["**/node_modules/**", "**/vendor/**", "**/.venv/**", "**/venv/**", "AISecCore/**"]
    out = []
    for rel in list_repo_files(repo_dir):
        base = rel.rsplit("/", 1)[-1]
        if any(glob_match(base, n) for n in names) and not any_glob(rel, excludes) and is_safe_relpath(rel):
            out.append(rel)
    return out


def discover_sca_skill(repo_dir: Path, repo: str, sha: str, policy: Policy, lock: SkillsLock,
                       runtime: AgentRuntime, osv: OsvClient | None = None) -> ScanResult:
    cfg = policy.discover["sca"]
    skill = lock.skill("discover_sca")
    manifests = find_manifests(repo_dir, policy)
    meta: dict[str, Any] = {"sca_mode": "discover", "sca_engine": f"skill:{skill}+osv-api",
                            "manifests": manifests, "discover_errors": []}
    if not manifests:
        return ScanResult([], meta)
    prompt = prompts.render(
        "discover-sca", skill=skill, repo=repo, sha=sha,
        manifests=wrap_untrusted("manifest-list", "\n".join(f"- {m}" for m in manifests)),
    )
    req = AgentRequest(role="discover_sca", prompt=prompt, schema=schemas.DISCOVER_SCA, cwd=repo_dir,
                       add_dirs=[skills_dir()], max_budget_usd=float(cfg.get("max_budget_usd", 3.0)))
    try:
        res = runtime.run(req)
    except AgentError as e:
        meta["discover_errors"].append(f"inventory: {e}")
        return ScanResult([], meta)
    deps: dict[tuple, Dependency] = {}
    unpinned = 0
    for d in res.data["dependencies"]:
        manifest = normalise_path(d["manifest"])
        if manifest not in manifests:
            continue
        if not d["pinned"] or not re.match(r"^v?[0-9A-Za-z][0-9A-Za-z.+_-]*$", d["version"]):
            unpinned += 1
            continue
        # Ground the model's claim: the version string must literally appear in the manifest.
        text = (repo_dir / manifest).read_text(encoding="utf-8", errors="replace")
        if d["version"] not in text or d["name"].split(":")[-1] not in text:
            LOG.warning("inventory entry not found in %s: %s@%s (dropped)", manifest, d["name"], d["version"])
            continue
        key = (d["ecosystem"], d["name"].lower(), d["version"])
        deps.setdefault(key, Dependency(d["ecosystem"], d["name"], d["version"], manifest))
    meta.update({"dependencies": len(deps), "unpinned_skipped": unpinned})
    if not cfg.get("confirm_with_osv_api", True):
        meta["discover_errors"].append("confirm_with_osv_api is off: no SCA findings produced")
        return ScanResult([], meta)
    osv = osv or OsvClient(cfg.get("osv_api", "https://api.osv.dev"))
    try:
        found = osv.findings_for(list(deps.values()), source=f"discover:{skill}+osv")
    except (OsvError, OSError, ValueError) as e:
        meta["discover_errors"].append(f"osv: {e}")
        return ScanResult([], meta)
    return ScanResult(merge_findings(found), meta)


def discover_sca_osv_scanner(repo_dir: Path) -> ScanResult:
    binary = shutil.which("osv-scanner")
    meta: dict[str, Any] = {"sca_mode": "discover", "sca_engine": "osv-scanner", "discover_errors": []}
    if not binary:
        meta["discover_errors"].append("osv-scanner not installed")
        return ScanResult([], meta)
    r = subprocess.run([binary, "scan", "source", "-r", "--format", "json", "."], cwd=repo_dir,
                       capture_output=True, text=True, timeout=1800, check=False)
    if r.returncode not in (0, 1):
        meta["discover_errors"].append(f"osv-scanner exit {r.returncode}")
        return ScanResult([], meta)
    doc = json.loads(r.stdout or '{"results": []}')
    found = adapters.parse(doc, "osv", "sca")
    for f in found:
        f.source = "discover:osv-scanner"
        f.properties["osv_confirmed"] = True
    return ScanResult(merge_findings(found), meta)


def discover_sca(repo_dir: Path, repo: str, sha: str, policy: Policy, lock: SkillsLock,
                 runtime: AgentRuntime, osv: OsvClient | None = None) -> ScanResult:
    if policy.discover["sca"].get("engine", "skill") == "osv-scanner":
        return discover_sca_osv_scanner(repo_dir)
    return discover_sca_skill(repo_dir, repo, sha, policy, lock, runtime, osv)
