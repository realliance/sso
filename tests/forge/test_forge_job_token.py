"""Acceptance for the Forgejo fork's job-token permissions (luma-homeops plan forgejo-fork-job-token-permissions,
Task 15), written red before the rollout of v15.0.11-realliance.3 and green after it:

- a job is sent only the secrets its workflow names (patch A);
- a workflow's `permissions: {}` leaves its job token unable to push or dispatch (the permissions patches).

(`test_member_can_create_org` is in test_forge_signin.py and `test_ci_dispatch_token_reads_orgs_and_repositories`
in test_forge_ci_dispatch.py.) The probes run on `tiny`, which is free, in public throwaway repos that carry only
random throwaway secrets; every repo is deleted afterwards, also on failure. Runner masking (Task 0, step 5): the
runner masks every secret its task carries, so a secret that was delivered always reads `***`. That is why the log
test looks for the *unreferenced* secret in the clear: only a secret the forge did not send can show up.
"""
import base64
import secrets

import pytest
import requests

from forge_helpers import FORGE, delete_branch, forge_api, forge_login, push_probe_workflow, wait_for
from ci_helpers import RUN_DONE, run_status

pytestmark = pytest.mark.slow

MARK = "job-token acceptance (realliance/sso tests)"
DISPATCH_WORKFLOW = ".forgejo/workflows/dispatch-target.yaml"
RUN_WAIT = 600          # tiny is one job at a time and starts a pod per job


@pytest.fixture
def repo(forge_user):
    """A public throwaway repo with a `main` branch and a `workflow_dispatch` workflow, owned by a fresh
    throwaway member. Not the admin: `tiny` charges an owner a day's minutes per job (20 reserved of 20), so
    each test's job needs an owner of its own. The member goes with the forge_user fixture."""
    u = forge_user(groups=("/apps/forgejo", "/realliance"))
    forge_login(u)
    name = f"jt-acc-{secrets.token_hex(4)}"
    r = forge_api("POST", "/api/v1/user/repos", sudo=u.name, json={"name": name, "private": False, "auto_init": True,
                                                       "default_branch": "main", "description": MARK})
    r.raise_for_status()
    full = r.json()["full_name"]
    try:
        wf = ("name: dispatch-target\non: workflow_dispatch\njobs:\n  noop:\n    runs-on: tiny\n"
              "    steps:\n      - run: echo dispatched\n")
        w = forge_api("POST", f"/api/v1/repos/{full}/contents/{DISPATCH_WORKFLOW}",
                      json={"content": base64.b64encode(wf.encode()).decode(), "message": "dispatch target",
                            "branch": "main"})
        w.raise_for_status()
        yield full
    finally:
        forge_api("DELETE", f"/api/v1/repos/{full}")


def _job_log(repo: str, sha: str) -> str:
    """The probe job's whole log as text, fetched with no credentials (the repo is public)."""
    run = forge_api("GET", f"/api/v1/repos/{repo}/actions/runs", params={"head_sha": sha}).json()["workflow_runs"][0]
    r = requests.get(f"{FORGE}/{repo}/actions/runs/{run['index_in_repo']}/jobs/0/attempt/1/logs", timeout=30)
    return r.text if r.status_code == 200 else f"(log answered {r.status_code})"


def _run_done(repo: str, sha: str) -> str | None:
    wait_for(lambda: run_status(repo, sha) in RUN_DONE, RUN_WAIT, every=5)
    return run_status(repo, sha)


def test_job_gets_only_named_secrets(repo):
    s1, s2 = secrets.token_hex(16), secrets.token_hex(16)
    for name, value in (("S1", s1), ("S2", s2)):
        r = forge_api("PUT", f"/api/v1/repos/{repo}/actions/secrets/{name}", json={"data": value})
        assert r.status_code in (201, 204)
    script = f'echo "first=[{s1}]"; echo "second=[{s2}]"'
    branch, sha = push_probe_workflow(repo, "tiny", script, env={"S1": "${{ secrets.S1 }}"})
    try:
        status = _run_done(repo, sha)
        log = _job_log(repo, sha)
    finally:
        delete_branch(repo, branch)
    assert status == "success"
    # S1 is named, so it is delivered and masked; S2 is not named, so it is not sent, not masked, and clear.
    first_clear, first_masked = f"first=[{s1}]" in log, "first=[***]" in log
    second_clear = f"second=[{s2}]" in log
    assert (first_clear, first_masked) == (False, True), "the named secret should be masked"
    assert second_clear, "the unnamed secret should not have been sent (so it is not masked)"


NO_PERMISSIONS = f"""\
set -u
repo="$GITHUB_REPOSITORY"
server="$GITHUB_SERVER_URL"
auth="Authorization: token $JOB_TOKEN"
dir=$(mktemp -d) && cd "$dir" && git init -q . && git -c user.name=probe -c user.email=probe@example.invalid commit -q --allow-empty -m probe
push=$(git -c "http.extraheader=$auth" push "$server/$repo.git" HEAD:refs/heads/perm-probe 2>&1); push_rc=$?
echo "push exit $push_rc"; echo "$push" | tail -3
case "$push" in *403*) push_403=1;; *) push_403=0;; esac
code=$(node -e '
fetch(process.env.GITHUB_SERVER_URL + "/api/v1/repos/" + process.env.GITHUB_REPOSITORY + "/actions/workflows/dispatch-target.yaml/dispatches",
  {{method: "POST", headers: {{Authorization: "token " + process.env.JOB_TOKEN, "Content-Type": "application/json"}}, body: JSON.stringify({{ref: "main"}})}})
  .then(r => console.log(r.status)).catch(() => console.log("error"))')
echo "dispatch status $code"
test "$push_rc" -ne 0 && test "$push_403" = 1 && test "$code" = 403
"""


def test_empty_permissions_cannot_push_or_dispatch(repo):
    branch, sha = push_probe_workflow(repo, "tiny", NO_PERMISSIONS, permissions={},
                                      env={"JOB_TOKEN": "${{ github.token }}"})
    try:
        status = _run_done(repo, sha)
        log = _job_log(repo, sha)
        pushed = forge_api("GET", f"/api/v1/repos/{repo}/branches/perm-probe").status_code
    finally:
        delete_branch(repo, branch)
    assert pushed == 404, "the job pushed a branch with an empty permissions block"
    assert status == "success", "push or dispatch did not answer 403:\n" + "\n".join(
        line for line in log.splitlines() if "exit" in line or "status" in line)
