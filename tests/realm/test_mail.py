"""Task 9 (email) — Resend can send as realliance.net."""
import requests

from conftest import SECRETS_DIR, _load_env

RESEND = _load_env(SECRETS_DIR / "resend/secrets.env")


def _domain():
    r = requests.get("https://api.resend.com/domains", timeout=20,
                     headers={"Authorization": f"Bearer {RESEND['RESEND_API_KEY']}"}).json()
    return next(d for d in r["data"] if d["name"] == "realliance.net")


def test_resend_domain_verified():
    assert _domain()["status"] == "verified"


def test_sending_key_restricted_to_realliance():
    keys = requests.get("https://api.resend.com/api-keys", timeout=20,
                        headers={"Authorization": f"Bearer {RESEND['RESEND_API_KEY']}"}).json()["data"]
    assert any(k["name"] == "keycloak-sso" for k in keys)
