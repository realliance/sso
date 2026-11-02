"""Task 5 — sso.realliance.net points at the box and serves Keycloak over ACME TLS."""
import socket

import pytest
import requests

from conftest import BOX, SECRETS_DIR, _load_env

HOST = "sso.realliance.net"


@pytest.fixture
def on_the_box():
    # Until the explicit record exists, *.realliance.net resolves to the homelab (Traefik).
    assert socket.gethostbyname(HOST) == BOX, "sso.realliance.net does not resolve to the box"


def test_dns_points_at_box():
    assert socket.gethostbyname(HOST) == BOX


def test_discovery_over_tls(on_the_box):
    r = requests.get(f"https://{HOST}/realms/master/.well-known/openid-configuration", timeout=10)
    assert r.json()["issuer"] == f"https://{HOST}/realms/master"


def test_certificate_is_publicly_trusted(on_the_box):
    # requests verifies against the system/certifi store; a self-signed or staging cert fails here
    assert requests.get(f"https://{HOST}/", timeout=10, allow_redirects=False).status_code < 500


def test_http_redirects(on_the_box):
    r = requests.get(f"http://{HOST}/", allow_redirects=False, timeout=10)
    assert r.status_code in (301, 308) and r.headers["location"].startswith("https://")


def test_management_not_public():
    for port in (8080, 9000):
        with pytest.raises(OSError):
            socket.create_connection((BOX, port), timeout=3)


def test_cloudflare_token_scoped():
    token = _load_env(SECRETS_DIR / "dns/secrets.env")["CLOUDFLARE_API_TOKEN"]
    r = requests.get("https://api.cloudflare.com/client/v4/zones?per_page=50",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10).json()
    zones = sorted(z["name"] for z in r["result"])
    assert zones == ["realliance.net"]


def test_root_redirects_to_account_console(on_the_box):
    r = requests.get(f"https://{HOST}/", allow_redirects=False, timeout=10)
    assert r.status_code in (302, 307) and r.headers["location"].endswith("/realms/realliance/account/")
