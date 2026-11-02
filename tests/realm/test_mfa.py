"""Task 9 (amended 2026-11-02) — password first, MFA required (TOTP, FIDO2 key or passkey)."""
import hashlib
import hmac
import re
import struct
import time
from html import unescape

from conftest import _form_action, browser_login, flow_executions, password_grant, realm_get


def _totp(raw_secret: str, at=None) -> str:
    # Keycloak keys TOTP with the raw totpSecret bytes (the QR/base32 form encodes the same bytes).
    key = raw_secret.encode()
    counter = int((at or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def _children(ex, parent_display):
    parent = next(e for e in ex if e.get("displayName") == parent_display)
    i = ex.index(parent)
    out = []
    for e in ex[i + 1:]:
        if e["level"] <= parent["level"]:
            break
        if e["level"] == parent["level"] + 1:
            out.append(e)
    return parent, out


def test_flow_is_password_then_required_mfa():
    ex = flow_executions("realliance-browser")
    assert any(e.get("providerId") == "auth-username-password-form" and e["requirement"] == "REQUIRED" for e in ex)
    mfa, branches = _children(ex, "realliance-mfa")
    assert mfa["requirement"] == "REQUIRED"
    assert {b["displayName"]: b["requirement"] for b in branches} == {
        "realliance-mfa-choose": "CONDITIONAL", "realliance-mfa-enroll": "CONDITIONAL"}
    _, choose = _children(ex, "realliance-mfa-choose")
    assert {e.get("providerId"): e["requirement"] for e in choose} == {
        "conditional-user-configured": "REQUIRED", "auth-otp-form": "ALTERNATIVE",
        "webauthn-authenticator": "ALTERNATIVE", "auth-recovery-authn-code-form": "ALTERNATIVE"}


def test_password_only_user_is_forced_to_set_up_mfa(user_factory):
    u = user_factory()
    _, r = browser_login(u.name, u.pw)
    assert r.status_code == 200, f"signed straight in without MFA (status {r.status_code})"
    assert 'name="totpSecret"' in r.text  # TOTP set-up page


def test_user_with_totp_is_asked_for_a_code_not_setup(user_factory):
    u = user_factory()
    s, setup = browser_login(u.name, u.pw)
    raw = unescape(re.search(r'name="totpSecret" value="([^"]+)"', setup.text).group(1))
    done = s.post(_form_action(setup.text), allow_redirects=False, timeout=20, data={
        "totp": _totp(raw), "totpSecret": raw, "userLabel": "test"})
    assert done.status_code in (302, 303), "TOTP enrolment was not accepted"
    _, again = browser_login(u.name, u.pw)
    assert again.status_code == 200
    assert 'name="otp"' in again.text and 'name="totpSecret"' not in again.text


def test_wrong_password_is_refused(user_factory):
    u = user_factory()
    _, r = browser_login(u.name, "definitely-not-the-password")
    assert r.status_code == 200 and "Invalid username or password" in r.text


def test_passkey_first_ui_off():
    assert realm_get()["webAuthnPolicyPasswordlessPasskeysEnabled"] is False


def test_webauthn_second_factor_policy():
    r = realm_get()
    assert r["webAuthnPolicyRpId"] == "sso.realliance.net"
    assert r["webAuthnPolicyUserVerificationRequirement"] == "preferred"


def test_admin_cli_password_grant_refused(user_factory):
    u = user_factory()
    r = password_grant("realliance", "admin-cli", u.name, u.pw)
    assert r.status_code in (400, 401) and r.json()["error"] == "unauthorized_client"
