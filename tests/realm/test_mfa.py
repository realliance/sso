"""Task 9 (amended 2026-11-02) — password first, MFA required (TOTP, FIDO2 key or passkey)."""
import re
from html import unescape

from conftest import _form_action, browser_login, flow_executions, password_grant, realm_get
from conftest import totp as _totp


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


def test_new_user_enrols_webauthn_by_default(user_factory):
    u = user_factory()
    _, r = browser_login(u.name, u.pw)
    assert r.status_code == 200, f"signed straight in without MFA (status {r.status_code})"
    assert "execution=webauthn-register" in r.url and 'name="totpSecret"' not in r.text


def test_totp_user_enrols_totp(user_factory):
    u = user_factory(attributes={"mfa": ["totp"]})
    _, r = browser_login(u.name, u.pw)
    assert r.status_code == 200, f"signed straight in without MFA (status {r.status_code})"
    assert 'name="totpSecret"' in r.text  # TOTP set-up page


def test_user_with_totp_is_asked_for_a_code_not_setup(user_factory):
    u = user_factory(attributes={"mfa": ["totp"]})
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


def test_enrol_branch_prefers_webauthn_unless_mfa_totp():
    ex = flow_executions("realliance-browser")
    _, enroll = _children(ex, "realliance-mfa-enroll")
    key = lambda e: e["displayName"] if e.get("authenticationFlow") else e.get("providerId")
    assert {key(e): e["requirement"] for e in enroll} == {
        "conditional-sub-flow-executed": "REQUIRED",
        "realliance-mfa-enroll-totp": "CONDITIONAL", "realliance-mfa-enroll-webauthn": "CONDITIONAL"}
    _, webauthn = _children(ex, "realliance-mfa-enroll-webauthn")
    assert {e.get("providerId"): e["requirement"] for e in webauthn} == {
        "conditional-sub-flow-executed": "REQUIRED", "webauthn-authenticator": "REQUIRED"}


def test_brute_force_protection():
    r = realm_get()
    assert r["bruteForceProtected"] is True and r["permanentLockout"] is False
    assert r["failureFactor"] == 10 and r["maxFailureWaitSeconds"] == 900
