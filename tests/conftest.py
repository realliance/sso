"""Shared test helpers for Realliance SSO.

Host tests run with testinfra:  pytest tests/host --hosts=ssh://root@23.163.0.48
Realm tests talk to https://sso.realliance.net with credentials from the
unlocked realliance/sso-secrets checkout (default ~/Repos/realliance-sso-secrets,
override with SSO_SECRETS_DIR).
"""
import os
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SECRETS_DIR = Path(os.environ.get("SSO_SECRETS_DIR", Path.home() / "Repos/realliance-sso-secrets"))
BOX = "23.163.0.48"

GROUP_VARS = yaml.safe_load((REPO / "host/group_vars/sso.yml").read_text())
OPERATOR_SSH_KEYS = GROUP_VARS["operator_ssh_keys"]


def _load_env(path: Path) -> dict:
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.removeprefix("export ").strip()] = v.strip().strip("'\"")
    return out


def _load_secrets() -> dict:
    data = {}
    host = SECRETS_DIR / "host/secrets.yml"
    if host.exists():
        data.update(yaml.safe_load(host.read_text()) or {})
    data.update(_load_env(SECRETS_DIR / "realm/secrets.env"))
    return data


SECRETS = _load_secrets()


@pytest.fixture(scope="session")
def secrets() -> dict:
    return SECRETS
