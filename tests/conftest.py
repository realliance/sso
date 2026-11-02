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


# --- Keycloak HTTP helpers (Task 6+) -------------------------------------------------------
import requests  # noqa: E402

SSO = "https://sso.realliance.net"
CLIENT_SECRETS = {"tofu-apply": "tofu_apply_client_secret", "tofu-plan": "tofu_plan_client_secret"}


def get(path, token, **kw):
    return requests.get(f"{SSO}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=20, **kw)


def put(path, token, json=None):
    return requests.put(f"{SSO}{path}", headers={"Authorization": f"Bearer {token}"}, json=json, timeout=20)


def post(path, token, json=None):
    return requests.post(f"{SSO}{path}", headers={"Authorization": f"Bearer {token}"}, json=json, timeout=20)


def admin_token(client="tofu-apply") -> str:
    r = requests.post(f"{SSO}/realms/master/protocol/openid-connect/token", timeout=20,
                      data={"grant_type": "client_credentials", "client_id": client,
                            "client_secret": SECRETS[CLIENT_SECRETS[client]]})
    r.raise_for_status()
    return r.json()["access_token"]


def password_grant(realm, client_id, username, password):
    return requests.post(f"{SSO}/realms/{realm}/protocol/openid-connect/token", timeout=20,
                         data={"grant_type": "password", "client_id": client_id,
                               "username": username, "password": password})


def find_user(realm, username, token) -> dict:
    users = get(f"/admin/realms/{realm}/users", token, params={"username": username, "exact": "true"}).json()
    assert len(users) == 1, f"user {username} not found in {realm}"
    return users[0]


def totp_configured(realm, user, token) -> bool:
    creds = get(f"/admin/realms/{realm}/users/{user['id']}/credentials", token).json()
    return any(c["type"] == "otp" for c in creds)
