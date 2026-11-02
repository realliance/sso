"""sso.realliance.net behind the Cloudflare proxy: Managed Challenge only on the reset pages,
nothing else challenged, real client IPs reach Keycloak, origin reachable only from Cloudflare."""
import secrets
import socket

import pytest
import requests

from conftest import BOX, SECRETS, SSO, admin_token, browser_login, get

RESET = f"{SSO}/realms/realliance/login-actions/reset-credentials?client_id=account-console"
CLI_UAS = [{"User-Agent": "curl/8.10.1"}, {"User-Agent": ""}, {"User-Agent": "git-credential-manager/2.6"}]


def test_served_through_cloudflare():
    r = requests.get(f"{SSO}/realms/realliance/.well-known/openid-configuration", timeout=10)
    assert r.headers.get("server") == "cloudflare" and "cf-ray" in r.headers


@pytest.mark.parametrize("headers", CLI_UAS, ids=["curl", "no-ua", "gcm"])
def test_cli_style_clients_never_challenged(headers):
    for path in ("/realms/realliance/.well-known/openid-configuration",
                 "/realms/realliance/protocol/openid-connect/certs"):
        r = requests.get(f"{SSO}{path}", headers=headers, timeout=10)
        assert r.status_code == 200 and "cf-mitigated" not in r.headers, path
    tok = requests.post(f"{SSO}/realms/master/protocol/openid-connect/token", headers=headers, timeout=10,
                        data={"grant_type": "client_credentials", "client_id": "tofu-plan",
                              "client_secret": SECRETS["tofu_plan_client_secret"]})
    assert tok.status_code == 200 and "access_token" in tok.json()


def test_reset_page_is_challenged():
    r = requests.get(RESET, timeout=10, allow_redirects=False)
    assert r.status_code == 403 and r.headers.get("cf-mitigated") == "challenge"


def test_reset_post_without_clearance_is_blocked():
    r = requests.post(RESET, data={"username": "nobody"}, timeout=10, allow_redirects=False)
    assert r.status_code == 403


def test_login_page_not_challenged():
    page = requests.get(f"{SSO}/realms/realliance/account/", timeout=10)
    assert page.status_code == 200 and "cf-mitigated" not in page.headers


def test_origin_refuses_non_cloudflare_clients():
    for port in (80, 443):
        with pytest.raises(OSError):
            socket.create_connection((BOX, port), timeout=4)


def test_keycloak_sees_the_real_client_ip(user_factory):
    trace = requests.get(f"{SSO}/cdn-cgi/trace", timeout=10).text
    my_ip = dict(line.split("=", 1) for line in trace.splitlines() if "=" in line)["ip"]
    u = user_factory()
    browser_login(u.name, "wrong-" + secrets.token_hex(4))
    events = get("/admin/realms/realliance/events", admin_token(), params={"type": "LOGIN_ERROR", "max": 5}).json()
    mine = [e for e in events if e.get("details", {}).get("username") == u.name]
    assert mine and mine[0]["ipAddress"] == my_ip
