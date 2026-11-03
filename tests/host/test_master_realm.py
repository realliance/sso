"""Task 6 — master realm: automation clients and break-glass admins; no temporary admin."""
from conftest import SECRETS, admin_token, find_user, get, password_grant, post, totp_configured


def test_tofu_apply_can_admin():
    token = admin_token("tofu-apply")
    assert get("/admin/realms", token).status_code == 200


def test_tofu_plan_cannot_create_realm():
    token = admin_token("tofu-plan")
    assert post("/admin/realms", token, {"realm": "should-not-exist"}).status_code == 403


def _temp_admin_absent():
    r = password_grant("master", "admin-cli", "temp-admin", SECRETS["keycloak_bootstrap_admin_password"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"  # RFC 6749 5.2
    users = get("/admin/realms/master/users", admin_token(), params={"username": "temp-admin", "exact": "true"}).json()
    assert users == []


def test_temp_admin_gone():
    _temp_admin_absent()


def test_break_glass_admins_need_totp():
    token = admin_token("tofu-apply")
    for username in ("chris-admin", "connor-admin"):
        user = find_user("master", username, token)
        assert "CONFIGURE_TOTP" in user["requiredActions"] or totp_configured("master", user, token)


def test_break_glass_admins_are_realm_admins():
    token = admin_token("tofu-apply")
    for username in ("chris-admin", "connor-admin"):
        user = find_user("master", username, token)
        roles = get(f"/admin/realms/master/users/{user['id']}/role-mappings/realm", token).json()
        assert "admin" in {r["name"] for r in roles}


def test_temp_admin_not_recreated_after_restart(host):
    host.run_expect([0], "systemctl restart keycloak")
    host.run_expect([0], "for i in $(seq 60); do curl -sf http://127.0.0.1:9000/health/ready >/dev/null && exit 0; sleep 5; done; exit 1")
    _temp_admin_absent()


FORGE_BOT_ROLES = {"view-users", "query-users", "query-groups", "manage-users", "view-events"}


def test_forge_bot_holds_exactly_its_roles():
    t = admin_token("tofu-apply")
    c = get("/admin/realms/master/clients", t, params={"clientId": "forge-bot"}).json()[0]
    sa = get(f"/admin/realms/master/clients/{c['id']}/service-account-user", t).json()
    mgmt = get("/admin/realms/master/clients", t, params={"clientId": "realliance-realm"}).json()[0]
    roles = get(f"/admin/realms/master/users/{sa['id']}/role-mappings/clients/{mgmt['id']}", t).json()
    assert {r["name"] for r in roles} == FORGE_BOT_ROLES
    assert "admin" not in {r["name"] for r in get(f"/admin/realms/master/users/{sa['id']}/role-mappings/realm", t).json()}


def test_forge_bot_reads_but_cannot_administer():
    t = admin_token("forge-bot")
    assert get("/admin/realms/realliance/users", t, params={"max": 1}).status_code == 200
    assert get("/admin/realms/realliance/admin-events", t, params={"max": 1}).status_code == 200
    assert post("/admin/realms/realliance/clients", t, {"clientId": "should-not-exist"}).status_code == 403
    assert post("/admin/realms", t, {"realm": "should-not-exist"}).status_code == 403
