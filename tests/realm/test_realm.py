"""Task 9 — the realliance realm: settings, SMTP, passkey-first sign-in."""
from conftest import admin_token, execution_config, flow_executions, get, put, realm_get


def test_realm_settings():
    r = realm_get()
    assert r["registrationAllowed"] is False and r["verifyEmail"] is True
    assert r["duplicateEmailsAllowed"] is False and r["resetPasswordAllowed"] is True
    # Delegation is by PR (amendment 2026-11-02): no fine-grained admin permissions, no organizations.
    assert r["adminPermissionsEnabled"] is False and r["organizationsEnabled"] is False


def test_smtp():
    s = realm_get()["smtpServer"]
    assert s["host"] == "smtp.resend.com" and s["port"] == "465" and s["ssl"] == "true"
    assert s["from"] == "sso@realliance.net" and s["fromDisplayName"] == "Realliance SSO"
    assert s["user"] == "resend" and s["auth"] == "true"


def test_browser_flow_bound():
    assert realm_get()["browserFlow"] == "realliance-browser"


def test_required_actions_enabled():
    ra = {a["alias"]: a for a in realm_get("/authentication/required-actions")}
    for alias in ("VERIFY_EMAIL", "UPDATE_PASSWORD", "CONFIGURE_TOTP", "webauthn-register", "CONFIGURE_RECOVERY_AUTHN_CODES"):
        assert ra[alias]["enabled"] is True, alias


def test_tofu_plan_has_view_only():
    token = admin_token("tofu-plan")
    r = get("/admin/realms/realliance", token)
    assert r.status_code == 200
    r = put("/admin/realms/realliance", token, {"displayName": "x"})
    assert r.status_code == 403


def test_admin_events_logged():
    ev = realm_get("/events/config")
    assert ev["adminEventsEnabled"] is True and ev["adminEventsDetailsEnabled"] is True


def test_no_user_holds_a_management_role():
    # GitOps lockdown: no account in this realm may administer it (break-glass admins live in master).
    mgmt = next(c for c in realm_get("/clients?clientId=realm-management"))
    for user in realm_get("/users?max=500"):
        roles = realm_get(f"/users/{user['id']}/role-mappings/clients/{mgmt['id']}/composite")
        assert roles == [], f"{user['username']} holds {[r['name'] for r in roles]}"


def test_session_lifetimes():
    """Chris 2026-11-02: 'Remember me' keeps people signed in (14 d idle / 30 d max); otherwise 8 h / 24 h."""
    r = realm_get("")
    assert r["rememberMe"] is True
    assert (r["ssoSessionIdleTimeout"], r["ssoSessionMaxLifespan"]) == (8 * 3600, 24 * 3600)
    assert (r["ssoSessionIdleTimeoutRememberMe"], r["ssoSessionMaxLifespanRememberMe"]) == (14 * 86400, 30 * 86400)
