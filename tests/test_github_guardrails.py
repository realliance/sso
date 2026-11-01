"""Task 2 — repos and GitHub guardrails exist as designed."""
import json
import subprocess
from pathlib import Path

import yaml

from conftest import REPO

OPERATORS = yaml.safe_load((REPO / "operators.yml").read_text())["operators"]
OPERATOR_LOGINS = {o["github"] for o in OPERATORS}


def gh(path: str):
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


def ruleset(repo: str, name: str) -> dict:
    match = [r for r in gh(f"repos/{repo}/rulesets") if r["name"] == name]
    assert match, f"no ruleset {name}"
    return gh(f"repos/{repo}/rulesets/{match[0]['id']}")


def test_sso_is_public():
    assert gh("repos/realliance/sso")["visibility"] == "public"


def test_secrets_repo_private():
    assert gh("repos/realliance/sso-secrets")["visibility"] == "private"


def test_ruleset_rules():
    rules = {r["type"]: r for r in ruleset("realliance/sso", "main-protection")["rules"]}
    assert {"pull_request", "required_signatures", "non_fast_forward", "deletion"} <= rules.keys()
    assert rules["pull_request"]["parameters"]["required_approving_review_count"] == 0  # 1 at go-live (Task 15)


def test_production_env_reviewers():
    env = gh("repos/realliance/sso/environments/production")
    reviewers = {r["reviewer"]["login"] for p in env["protection_rules"]
                 if p["type"] == "required_reviewers" for r in p["reviewers"]}
    assert reviewers == OPERATOR_LOGINS


def test_production_env_main_only():
    env = gh("repos/realliance/sso/environments/production")
    assert env["deployment_branch_policy"] == {"protected_branches": False, "custom_branch_policies": True}
    names = {p["name"] for p in gh("repos/realliance/sso/environments/production/deployment-branch-policies")["branch_policies"]}
    assert names == {"main"}


def test_plan_env_exists():
    assert gh("repos/realliance/sso/environments/plan")["name"] == "plan"


def test_secrets_repo_encrypted_without_key(tmp_path):
    subprocess.run(["gh", "repo", "clone", "realliance/sso-secrets", str(tmp_path / "c"), "--", "-q"], check=True)
    assert not (tmp_path / "c/host/secrets.yml").read_bytes().startswith(b"#")
    assert (tmp_path / "c/host/secrets.yml").read_bytes()[:10] == b"\x00GITCRYPT\x00"
