"""Forge (project 2) — signing in to git.realliance.net through Realliance SSO, and what Forgejo
lets an account do (spec Success 1, 2; plan Task 4 + Review Focus 1)."""
import secrets
from urllib.parse import urlparse

import requests

from forge_helpers import FORGE, forge_api, forge_login, forge_login_attempt, forge_signed_in


def test_member_signin_creates_account(forge_user):
    u = forge_user()
    forge_login(u)
    acct = forge_api("GET", f"/api/v1/users/{u.name}").json()
    assert acct["login"] == u.name  # USERNAME=nickname falls back to preferred_username
    assert acct["is_admin"] is False


def test_admin_group_makes_site_admin(forge_user):
    u = forge_user(groups=("/apps/forgejo", "/forgejo-admins"))
    forge_login(u)
    assert forge_api("GET", f"/api/v1/users/{u.name}").json()["is_admin"] is True


def test_no_forgejo_access_refused_at_sso(forge_user):
    u = forge_user(groups=("/realliance",))
    _, r = forge_login_attempt(u)
    assert urlparse(r.url).hostname == "sso.realliance.net", f"left the SSO for {r.url}"
    assert forge_api("GET", f"/api/v1/users/{u.name}").status_code == 404


def test_no_local_password_forms():
    login = requests.get(f"{FORGE}/user/login", timeout=20)
    assert login.status_code == 200 and "/user/oauth2/realliance" in login.text  # the SSO button
    for page in (login, requests.get(f"{FORGE}/user/sign_up", timeout=20)):
        assert 'name="password"' not in page.text


def test_user_list_hidden_from_anonymous():
    assert requests.get(f"{FORGE}/explore/repos", timeout=20).status_code == 200  # Explore itself is public
    r = requests.get(f"{FORGE}/explore/users", allow_redirects=False, timeout=20)
    # DISABLE_USERS_PAGE answers with a redirect to /explore (or a refusal), never the list
    assert r.status_code in (303, 403, 404) and not r.headers.get("Location", "").endswith("/explore/users")
    # the API must not list users to anonymous visitors either (final review, re-graded 13)
    api = requests.get(f"{FORGE}/api/v1/users/search", params={"q": "chris"}, timeout=20)  # an existing user
    assert api.status_code in (401, 403, 404) or api.json().get("data") == [], f"anonymous user search: {api.status_code}"


def test_member_can_create_org(forge_user):
    """A plain member may create an organisation (the fork's job-token permissions rollout lifts the old
    ban). Red against v15.0.11-realliance.2, which answers 403."""
    u = forge_user()
    forge_login(u)
    org = f"t-{secrets.token_hex(3)}"
    try:
        r = forge_api("POST", "/api/v1/orgs", sudo=u.name, json={"username": org})
        assert r.status_code == 201
    finally:
        forge_api("DELETE", f"/api/v1/orgs/{org}")


def test_username_collision_refused(forge_user):
    org = f"test-{secrets.token_hex(4)}"
    assert forge_api("POST", "/api/v1/orgs", json={"username": org, "visibility": "private"}).status_code == 201
    try:
        u = forge_user(username=org)
        s, r = forge_login_attempt(u)
        assert urlparse(r.url).hostname == urlparse(FORGE).hostname
        assert not forge_signed_in(s)
        assert forge_api("GET", f"/api/v1/orgs/{org}").json()["username"] == org  # still the org, no user
    finally:
        forge_api("DELETE", f"/api/v1/orgs/{org}")


def test_settings_link_to_realliance_account(forge_user):
    """Forgejo's user settings menu links to the Realliance account page (template override)."""
    u = forge_user()
    s = forge_login(u)
    page = s.get(f"{FORGE}/user/settings", timeout=20).text
    assert 'href="https://sso.realliance.net/realms/realliance/account/"' in page


def test_catppuccin_themes_offered(forge_user):
    """Every Catppuccin flavour/accent (and the auto variants) is a selectable theme with its CSS served."""
    u = forge_user()
    s = forge_login(u)
    page = s.get(f"{FORGE}/user/settings/appearance", timeout=20).text
    for theme in ("catppuccin-latte-rosewater", "catppuccin-mocha-mauve", "catppuccin-frappe-blue",
                  "catppuccin-macchiato-lavender", "catppuccin-teal-auto"):
        assert f'value="{theme}"' in page, theme
        css = requests.get(f"{FORGE}/assets/css/theme-{theme}.css", timeout=20)
        assert css.status_code == 200 and "text/css" in css.headers.get("Content-Type", ""), theme
    assert 'value="forgejo-auto"' in page  # Forgejo's own themes stay


def test_default_theme_is_catppuccin_sapphire_auto():
    page = requests.get(f"{FORGE}/explore/repos", timeout=20).text
    assert 'data-theme="catppuccin-sapphire-auto"' in page
