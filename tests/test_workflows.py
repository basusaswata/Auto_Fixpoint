"""Static checks on the workflows: pinning, injection safety, secret scoping in the single job."""

import re

import pytest
import yaml

from tests.conftest import ROOT

WF = ROOT / ".github" / "workflows"
ALL = sorted(WF.glob("*.yml"))


def load(p):
    return yaml.safe_load(p.read_text())


def steps_of(doc):
    for name, job in (doc.get("jobs") or {}).items():
        yield name, job.get("steps") or []


def main_steps():
    doc = load(WF / "fixpoint.yml")
    assert list(doc["jobs"]) == ["fixpoint"], "the POC pipeline is a single job"
    return doc, doc["jobs"]["fixpoint"]["steps"]


def step(steps, name_prefix):
    return next(s for s in steps if s.get("name", "").startswith(name_prefix))


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
            for expr in re.findall(r"\$\{\{(.*?)\}\}", s.get("run") or ""):
                pytest.fail(f"{path.name}: expression in run block: {expr.strip()}")


def test_checkouts_do_not_persist_credentials():
    for path in ALL:
        for _, steps in steps_of(load(path)):
            for s in steps:
                if str(s.get("uses", "")).startswith("actions/checkout@"):
                    assert s["with"]["persist-credentials"] is False, path.name


def test_no_harden_runner_and_hosted_runner():
    for path in ALL:
        assert "harden-runner" not in path.read_text(), path.name
    doc, _ = main_steps()
    assert doc["jobs"]["fixpoint"]["runs-on"] == "ubuntu-latest"
    assert doc["permissions"] == {} and doc["jobs"]["fixpoint"]["permissions"] == {"contents": "read"}


def test_triggers_and_concurrency():
    doc, _ = main_steps()
    on = doc.get("on") or doc.get(True)
    assert "workflow_dispatch" in on and on["repository_dispatch"]["types"] == ["fixpoint-sweep"]
    assert doc["concurrency"]["cancel-in-progress"] is False
    for field in ("repo", "branch", "sast_report", "sast_format", "sca_report", "sca_format", "mode", "max_prs",
                  "dry_run"):
        assert field in on["workflow_dispatch"]["inputs"]


def test_self_sufficient_install():
    _, steps = main_steps()
    uses = " ".join(str(s.get("uses", "")) for s in steps)
    for action in ("actions/setup-python@", "actions/setup-node@", "actions/setup-java@", "actions/setup-go@"):
        assert action in uses
    install = step(steps, "Install git, fixpoint CLI and Claude Code")["run"]
    assert "npm install -g" in install and "pip install" in install
    assert "fixpoint skills install" in step(steps, "Fetch pinned skills")["run"]


def test_report_or_ai_scan():
    _, steps = main_steps()
    for kind in ("SAST", "SCA"):
        ingest = step(steps, f"{kind} - ingest report")
        scan = next(s for s in steps if s.get("name", "").startswith(f"{kind} - AI"))
        assert "!= ''" in ingest["if"] and "== ''" in scan["if"]
        assert "ANTHROPIC_API_KEY" in scan["env"] and "ANTHROPIC_API_KEY" not in ingest.get("env", {})


def test_secret_scoping_inside_the_job():
    doc, steps = main_steps()
    assert "secrets." not in yaml.safe_dump(doc["jobs"]["fixpoint"].get("env", {}))
    names = [s.get("name", "") for s in steps]
    # the model key only on AI steps
    for s in steps:
        if "ANTHROPIC_API_KEY" in (s.get("env") or {}):
            assert any(k in s["name"] for k in ("AI", "Triage", "Fix")), s["name"]
    # the step that runs target-repo code has no secrets and no token
    build = step(steps, "Install, build and test every patch")
    assert "env" not in build
    # the checkout token is revoked before any target code runs; the publish token is minted after
    i_revoke = names.index("Revoke the checkout token")
    i_build = names.index(build["name"])
    i_write = names.index("App token for publishing")
    assert i_revoke < i_build < i_write
    assert step(steps, "App token for the target repo")["with"]["skip-token-revoke"] is True
    publish = step(steps, "Raise PRs")
    assert "--allow-unsigned" in publish["run"] and "steps.write-token" in publish["env"]["FIXPOINT_WRITE_TOKEN"]


def test_report_always_runs():
    _, steps = main_steps()
    assert step(steps, "Report")["if"] == "always()"
    assert step(steps, "Upload results")["if"] == "always()"
