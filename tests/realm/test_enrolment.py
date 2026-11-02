"""Task 12 — a new user is emailed a set-up link by the `enrol` workflow."""
import secrets
import time

import requests
import yaml

from conftest import REALM, SECRETS_DIR, SSO, _load_env, admin_token, get, post, realm_get

RESEND = _load_env(SECRETS_DIR / "resend/secrets.env")


def _resend_emails_to(address):
    r = requests.get("https://api.resend.com/emails?limit=50", timeout=20,
                     headers={"Authorization": f"Bearer {RESEND['RESEND_API_KEY']}"}).json()
    return [e for e in r.get("data", []) if address in e.get("to", [])]


def test_enrol_workflow_on_user_created():
    # The workflows endpoint answers in YAML.
    flows = {w["name"]: w for w in yaml.safe_load(get(f"/admin/realms/{REALM}/workflows", admin_token()).text)}
    enrol = flows["enrol"]
    assert enrol.get("on") in ("user_created", "user-created") and enrol.get("enabled", True) in (True, "true")
    assert [s["uses"] for s in enrol["steps"]] == ["invite-user"]


def test_invite_links_last_72_hours():
    assert realm_get()["actionTokenGeneratedByAdminLifespan"] == 72 * 3600


def test_new_user_gets_an_invite_email():
    address = f"delivered+kc-{secrets.token_hex(4)}@resend.dev"
    token = admin_token()
    r = post(f"/admin/realms/{REALM}/users", token, {"username": f"test-{secrets.token_hex(4)}", "email": address,
                                                       "enabled": True, "firstName": "Invite", "lastName": "Test"})
    assert r.status_code == 201, r.text
    uid = r.headers["Location"].rsplit("/", 1)[1]
    try:
        deadline = time.time() + 90
        while time.time() < deadline and not _resend_emails_to(address):
            time.sleep(5)
        mails = _resend_emails_to(address)
        assert mails, "no invite email reached Resend within 90 s"
        assert mails[0]["from"].endswith("<sso@realliance.net>") or mails[0]["from"] == "sso@realliance.net"
    finally:
        requests.delete(f"{SSO}/admin/realms/{REALM}/users/{uid}", timeout=20,
                        headers={"Authorization": f"Bearer {admin_token()}"})


def test_disabled_user_gets_no_invite():
    address = f"delivered+kc-off-{secrets.token_hex(4)}@resend.dev"
    r = post(f"/admin/realms/{REALM}/users", admin_token(), {"username": f"test-{secrets.token_hex(4)}", "email": address,
                                                               "enabled": False, "firstName": "Off", "lastName": "Test"})
    uid = r.headers["Location"].rsplit("/", 1)[1]
    try:
        time.sleep(20)
        assert _resend_emails_to(address) == []
    finally:
        requests.delete(f"{SSO}/admin/realms/{REALM}/users/{uid}", timeout=20,
                        headers={"Authorization": f"Bearer {admin_token()}"})
