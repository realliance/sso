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
CLIENT_SECRETS = {"tofu-apply": "tofu_apply_client_secret", "tofu-plan": "tofu_plan_client_secret",
                  "forge-bot": "forge_bot_client_secret"}


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
                         data={"grant_type": "password", "client_id": client_id, "scope": "openid",
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
import hmac  # noqa: E402
import re  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402
import warnings  # noqa: E402
import secrets as _secrets  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from html import unescape  # noqa: E402


@dataclass
class User:
    id: str
    name: str
    pw: str
    totp_secret: str | None = None   # set when a sign-in helper enrols TOTP
    totp_counter: int | None = None  # last 30-s window used, so no code is ever replayed


def totp(raw_secret: str, at: float | None = None) -> str:
    # Keycloak keys TOTP with the raw totpSecret bytes (the QR/base32 form encodes the same bytes).
    key = raw_secret.encode()
    counter = int((at or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


@pytest.fixture
def user_factory():
    made = []

    def make(groups=(), required_actions=(), attributes=None, username=None, email=None, last_name="User"):
        name = username or f"test-{_secrets.token_hex(4)}"
        pw = _secrets.token_urlsafe(18)
        token = admin_token()
        # Created DISABLED, then enabled: the enrol workflow (invite-user on user_created) skips
        # disabled users, so throwaway users never send invite mail (Resend's free tier is 100/day).
        body = {"username": name, "email": email or f"{name}@example.invalid", "emailVerified": True, "enabled": False,
                "firstName": "Test", **({"lastName": last_name} if last_name else {}),
                "requiredActions": list(required_actions),
                "credentials": [{"type": "password", "value": pw, "temporary": False}], "groups": list(groups),
                "attributes": attributes or {}}
        r = post(f"/admin/realms/{REALM}/users", token, body)
        assert r.status_code == 201, r.text
        user = User(id=r.headers["Location"].rsplit("/", 1)[1], name=name, pw=pw)
        rep = get(f"/admin/realms/{REALM}/users/{user.id}", token).json()
        rep["enabled"] = True
        r = put(f"/admin/realms/{REALM}/users/{user.id}", token, rep)
        assert r.status_code == 204
        made.append(user)
        return user

    yield make
    failures = _teardown_users(made)
    if failures:
        warnings.warn("user_factory teardown left things behind: " + "; ".join(failures), stacklevel=1)


def _teardown_users(made):
    """Best-effort cleanup of `made`: each user's forge account first (purged with its repos; a 404
    means it never signed in), then the Keycloak user. One failure never stops the rest. Returns
    the failures as strings that name a user and a status, never a credential."""
    failures = []
    forge_up = False
    try:
        # Lazy: realm-only runs never need the forge helpers or its credentials.
        from forge_helpers import FORGE_SECRETS, forge_api
        forge_up = bool(_load_env(FORGE_SECRETS).get("FORGEJO_ADMIN_TOKEN"))
        if not forge_up:
            failures.append("forge credentials not configured, forge accounts not deleted")
    except Exception as e:  # noqa: BLE001
        failures.append(f"forge helpers unavailable ({type(e).__name__})")
    for u in made:
        if forge_up:
            try:
                # An org that shares the name is not ours to delete (see test_username_collision_refused).
                if forge_api("GET", f"/api/v1/orgs/{u.name}").status_code != 200:
                    r = forge_api("DELETE", f"/api/v1/admin/users/{u.name}", params={"purge": "true"})
                    if r.status_code not in (204, 404):
                        failures.append(f"forge account {u.name}: HTTP {r.status_code}")
            except requests.RequestException as e:
                failures.append(f"forge account {u.name}: {type(e).__name__}")
                if isinstance(e, (requests.ConnectionError, requests.Timeout)):
                    forge_up = False  # unreachable: stop paying a timeout per user
        try:
            r = requests.delete(f"{SSO}/admin/realms/{REALM}/users/{u.id}", timeout=20,
                                headers={"Authorization": f"Bearer {admin_token()}"})
            if r.status_code not in (204, 404):
                failures.append(f"keycloak user {u.name}: HTTP {r.status_code}")
        except requests.RequestException as e:
            failures.append(f"keycloak user {u.name}: {type(e).__name__}")
    return failures


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


# --- groups / acceptance clients (Task 11+) --------------------------------------------------
import base64 as _b64  # noqa: E402
import json as _json  # noqa: E402


def group_id(path):
    r = get(f"/admin/realms/{REALM}/group-by-path/{path.lstrip('/')}", admin_token())
    r.raise_for_status()
    return r.json()["id"]


def create_group(name):
    r = post(f"/admin/realms/{REALM}/groups", admin_token(), {"name": name})
    assert r.status_code == 201, r.text
    return r.headers["Location"].rsplit("/", 1)[1]


def delete_group(gid):
    requests.delete(f"{SSO}/admin/realms/{REALM}/groups/{gid}", timeout=20,
                    headers={"Authorization": f"Bearer {admin_token()}"})


def decode(jwt):
    payload = jwt.split(".")[1]
    return _json.loads(_b64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _set_enabled(client_id, enabled):
    c = client_by_id(client_id)
    c["enabled"] = enabled
    r = put(f"/admin/realms/{REALM}/clients/{c['id']}", admin_token(), c)
    assert r.status_code == 204, r.text


@pytest.fixture
def acceptance_clients():
    names = ("acceptance-tests", "acceptance-tests-noscope")
    for n in names:
        _set_enabled(n, True)
    yield names
    for n in names:
        _set_enabled(n, False)


# --- forge (project 2): Realliance users who sign in to git.realliance.net -----------------------
@pytest.fixture
def forge_user(user_factory):
    """Keycloak users with /apps/forgejo (by default) and TOTP as their factor. Teardown purges the
    Forgejo account sign-in created, never an org that happens to share the name."""
    from forge_helpers import forge_api
    made = []

    def make(groups=("/apps/forgejo",), email=None, username=None):
        u = user_factory(groups=groups, attributes={"mfa": ["totp"]}, username=username, email=email)
        made.append(u)
        return u

    yield make
    for u in made:
        if forge_api("GET", f"/api/v1/orgs/{u.name}").status_code != 200:
            forge_api("DELETE", f"/api/v1/admin/users/{u.name}", params={"purge": "true"})
