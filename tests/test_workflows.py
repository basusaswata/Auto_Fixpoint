"""Static checks on the workflows: pinning, injection safety, privilege split."""

import re

import pytest
import yaml

from tests.conftest import ROOT

WF = ROOT / ".github" / "workflows"
ACTION = ROOT / ".github" / "actions" / "setup-fixpoint" / "action.yml"
ALL = sorted(WF.glob("*.yml")) + [ACTION]


def load(p):
    return yaml.safe_load(p.read_text())


def steps_of(doc):
    if "runs" in doc:
        yield "composite", doc["runs"]["steps"]
    for name, job in (doc.get("jobs") or {}).items():
        yield name, job.get("steps") or []


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_third_party_actions_pinned_to_sha(path):
    for _, steps in steps_of(load(path)):
        for s in steps:
            uses = s.get("uses")
            if uses and not uses.startswith("./"):
                assert re.match(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", uses), f"{path.name}: unpinned {uses}"


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_no_untrusted_expressions_in_run(path):
    """Inputs/event data reach scripts only via env vars, never via ${{ }} in run:."""
    for _, steps in steps_of(load(path)):
        for s in steps:
            run = s.get("run") or ""
            for expr in re.findall(r"\$\{\{(.*?)\}\}", run):
                pytest.fail(f"{path.name}: expression in run block: {expr.strip()}")


def test_secrets_only_where_needed():
    doc = load(WF / "fixpoint.yml")
    jobs = doc["jobs"]
    text = {name: yaml.safe_dump(job) for name, job in jobs.items()}
    assert doc["permissions"] == {}
    for name, t in text.items():
        if name != "publish":
            assert "FIXPOINT_WRITE_APP_KEY" not in t, f"write key referenced in {name}"
    assert jobs["publish"]["environment"] == "fixpoint-publish"
    assert "ANTHROPIC" not in text["publish"] and "ANTHROPIC" not in text["sign"]
    # the job that runs target-repo code has no secrets at all
    assert "secrets." not in text["verify-build"]
    assert "secrets." not in text["fix"].replace("secrets.FIXPOINT_ANTHROPIC_API_KEY", "")
    assert "READ_APP_KEY" not in text["fix"] + text["verify-ai"] + text["verify-build"]
    assert jobs["sign"]["permissions"] == {"id-token": "write"}
    for name in ("fix", "verify-ai", "verify-build", "publish", "report"):
        assert jobs[name]["permissions"] == {}, name
    assert jobs["report"]["if"] == "always()"


def test_checkouts_do_not_persist_credentials():
    for path in ALL:
        for _, steps in steps_of(load(path)):
            for s in steps:
                if str(s.get("uses", "")).startswith("actions/checkout@"):
                    assert s["with"]["persist-credentials"] is False, path.name


def test_triggers_and_concurrency():
    doc = load(WF / "fixpoint.yml")
    on = doc.get("on") or doc.get(True)
    assert "workflow_dispatch" in on and on["repository_dispatch"]["types"] == ["fixpoint-sweep"]
    assert doc["concurrency"]["cancel-in-progress"] is False
    assert "client_payload.repo" in doc["concurrency"]["group"]
    for field in ("repo", "branch", "sast_report", "sast_format", "sca_report", "sca_format", "mode", "max_prs"):
        assert field in on["workflow_dispatch"]["inputs"]
