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


# --- realliance realm helpers (Task 9+) -------------------------------------------------------
REALM = "realliance"


def realm_get(suffix=""):
    r = get(f"/admin/realms/{REALM}{suffix}", admin_token())
    r.raise_for_status()
    return r.json()


def flow_executions(alias):
    return realm_get(f"/authentication/flows/{alias}/executions")


def execution_config(execution):
    cfg_id = execution.get("authenticationConfig")
    return realm_get(f"/authentication/config/{cfg_id}")["config"] if cfg_id else {}


def flow_id(alias):
    return next(f["id"] for f in realm_get("/authentication/flows") if f["alias"] == alias)


def client_by_id(client_id):
    clients = realm_get(f"/clients?clientId={client_id}")
    assert len(clients) == 1, f"client {client_id} not found"
    return clients[0]


# --- users and browser-flow driving (Task 9+) ----------------------------------------------
import base64  # noqa: E402
import hashlib  # noqa: E402
import re  # noqa: E402
import secrets as _secrets  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from html import unescape  # noqa: E402


@dataclass
class User:
    id: str
    name: str
    pw: str


@pytest.fixture
def user_factory():
    made = []

    def make(groups=(), required_actions=()):
        name = f"test-{_secrets.token_hex(4)}"
        pw = _secrets.token_urlsafe(18)
        token = admin_token()
        body = {"username": name, "email": f"{name}@example.invalid", "emailVerified": True, "enabled": True,
                "firstName": "Test", "lastName": "User", "requiredActions": list(required_actions),
                "credentials": [{"type": "password", "value": pw, "temporary": False}], "groups": list(groups)}
        r = post(f"/admin/realms/{REALM}/users", token, body)
        assert r.status_code == 201, r.text
        user = User(id=r.headers["Location"].rsplit("/", 1)[1], name=name, pw=pw)
        made.append(user)
        return user

    yield make
    token = admin_token()
    for u in made:
        requests.delete(f"{SSO}/admin/realms/{REALM}/users/{u.id}", timeout=20,
                        headers={"Authorization": f"Bearer {token}"})


def _form_action(html):
    m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', html) or \
        re.search(r'<form[^>]*action="([^"]+)"', html)
    assert m, "no login form on page"
    return unescape(m.group(1))


def browser_login(username, password, client_id="account-console"):
    """Drive the realm's browser flow like a browser. Returns (session, final response)."""
    s = requests.Session()
    verifier = _secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    redirect = f"{SSO}/realms/{REALM}/account/"
    page = s.get(f"{SSO}/realms/{REALM}/protocol/openid-connect/auth", timeout=20, params={
        "client_id": client_id, "redirect_uri": redirect, "response_type": "code", "scope": "openid",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": _secrets.token_hex(8)})
    r = s.post(_form_action(page.text), data={"username": username, "password": password},
               allow_redirects=False, timeout=20)
    # Follow Keycloak's own login-action hops (required actions, MFA prompts) like a browser would,
    # but stop before the app: a redirect to redirect_uri with a code means the user is signed in.
    while r.status_code in (302, 303) and "/login-actions/" in r.headers.get("Location", ""):
        r = s.get(r.headers["Location"], allow_redirects=False, timeout=20)
    return s, r
