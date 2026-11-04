"""The realliance realm serves the Realliance login and account themes (installed by the keycloak role).

LIVE and READ-ONLY. Unauthenticated GETs of the public pages (the same requests any visitor makes) plus a
realm GET with the existing token. Run it after the box has pulled and restarted Keycloak:

    pytest tests/realm/test_login_theme.py

Why more than the realm attribute: Keycloak silently falls back to the stock theme when a named theme
directory is missing or malformed, so `loginTheme == "realliance"` stays green while the fonts and colours
are not served. These tests follow the real stylesheet and font links from the rendered pages.
"""
import hashlib
import re
from pathlib import Path
from urllib.parse import urljoin

import requests

from conftest import SSO, realm_get

THEME = Path(__file__).resolve().parents[2] / "host/roles/keycloak/files/themes/realliance"
LOGIN_PAGE = (f"{SSO}/realms/realliance/protocol/openid-connect/auth?client_id=account-console"
              f"&redirect_uri={SSO}/realms/realliance/account/&response_type=code&scope=openid"
              "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=theme-test")
ACCOUNT_PAGE = f"{SSO}/realms/realliance/account/"


def _fetch(url, **kw):
    return requests.get(url, timeout=20, **kw)


def _stylesheets(html: str) -> list[str]:
    out = []
    for tag in re.findall(r"<link\b[^>]*>", html):
        if re.search(r'rel="stylesheet"', tag):
            m = re.search(r'href="([^"]+)"', tag)
            if m:
                out.append(m.group(1))
    return out


def _assert_theme_served(page_url: str, kind: str, parent: str):
    page = _fetch(page_url)
    assert page.status_code == 200, f"{page_url} -> {page.status_code}"
    sheets = _stylesheets(page.text)
    ours = [s for s in sheets if re.fullmatch(rf"/resources/[^/]+/{kind}/realliance/css/realliance\.[0-9a-f]{{8}}\.css", s)]
    assert ours, (f"no /resources/<ver>/{kind}/realliance/css/realliance.<8 hex>.css link on {page_url}; "
                  f"stylesheets: {sheets} (a /{kind}/{parent}/ path only means Keycloak fell back to the stock theme)")
    css_url = urljoin(page.url, ours[0])
    css = _fetch(css_url)
    assert css.status_code == 200, f"{css_url} -> {css.status_code}"
    assert css.headers["content-type"].startswith("text/css")
    # byte-for-byte the file in this checkout: a stale (older round) or cached stylesheet must fail
    repo = (THEME / kind / "resources/css/realliance.css").read_bytes()
    assert hashlib.sha256(css.content).hexdigest() == hashlib.sha256(repo).hexdigest(), (
        f"{css_url} differs from the repo's {kind} realliance.css (stale deploy or cached copy)")
    fonts = re.findall(r'url\(\s*"([^"]+\.woff2)"\s*\)', css.text)
    assert len(fonts) == 6, fonts
    for rel in fonts:
        font_url = urljoin(css_url, rel)
        r = _fetch(font_url)
        assert r.status_code == 200, f"{font_url} -> {r.status_code}"
        assert r.content[:4] == b"wOF2", f"{font_url} is not woff2"
    # every other stylesheet the page links (the parent theme's own sheets) must also be served
    for s in sheets:
        if s.startswith("/resources/"):
            other = _fetch(urljoin(page.url, s))
            assert other.status_code == 200, f"{s} -> {other.status_code}"


def test_login_theme_selected():
    assert realm_get()["loginTheme"] == "realliance"


def test_account_theme_selected():
    assert realm_get()["accountTheme"] == "realliance"


def test_login_page_serves_the_theme_stylesheet_and_fonts():
    _assert_theme_served(LOGIN_PAGE, "login", "keycloak.v2")


def test_account_console_serves_the_theme_stylesheet_and_fonts():
    _assert_theme_served(ACCOUNT_PAGE, "account", "keycloak.v3")
    # the console's own bundle must still come through the theme (parent fallback), or the SPA would not load
    sheets = _stylesheets(_fetch(ACCOUNT_PAGE).text)
    assert any(re.fullmatch(r"/resources/[^/]+/account/realliance/assets/main-[^/]+\.css", s) for s in sheets), sheets
    # ... and so must its JS entry (the SPA does not start without it)
    html = _fetch(ACCOUNT_PAGE).text
    scripts = [m for tag in re.findall(r"<script\b[^>]*>", html) for m in re.findall(r'src="([^"]+)"', tag)]
    mains = [s for s in scripts if re.fullmatch(r"/resources/[^/]+/account/realliance/assets/main-[^/]+\.js", s)]
    assert mains, f"no account/realliance/assets/main-*.js script on {ACCOUNT_PAGE}; scripts: {scripts}"
    r = _fetch(urljoin(ACCOUNT_PAGE, mains[0]))
    assert r.status_code == 200 and r.content, f"{mains[0]} -> {r.status_code}"
