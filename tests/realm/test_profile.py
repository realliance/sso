"""The declared user profile: what people must and may tell us about themselves."""
import re
from html import unescape

from conftest import _form_action, browser_login, realm_get, totp


def _attrs():
    return {a["name"]: a for a in realm_get("/users/profile")["attributes"]}


def test_first_name_required_last_name_optional():
    a = _attrs()
    assert a["firstName"]["required"]["roles"] == ["user"]
    assert "required" not in a["lastName"]  # many people would rather not give a full name


def test_names_editable_by_their_owner():
    a = _attrs()
    for name in ("email", "firstName", "lastName"):
        assert "user" in a[name]["permissions"]["edit"], name


def test_no_last_name_signs_in_without_profile_prompt(user_factory):
    u = user_factory(attributes={"mfa": ["totp"]}, last_name=None)
    s, setup = browser_login(u.name, u.pw)
    raw = unescape(re.search(r'name="totpSecret" value="([^"]+)"', setup.text).group(1))
    r = s.post(_form_action(setup.text), allow_redirects=False, timeout=20,
               data={"totp": totp(raw), "totpSecret": raw, "userLabel": "test"})
    while r.status_code in (302, 303) and "/login-actions/" in r.headers.get("Location", ""):
        r = s.get(r.headers["Location"], allow_redirects=False, timeout=20)
    # signed in: redirected to the app with a code, never stopped at "update your profile"
    assert r.status_code in (302, 303) and "code=" in r.headers.get("Location", ""), \
        f"stopped at {r.url} ({r.status_code}); lastName form: {'name=\"lastName\"' in r.text}"


def test_pronouns_optional_and_self_editable():
    a = _attrs()["pronouns"]
    assert "required" not in a
    assert "user" in a["permissions"]["edit"] and "user" in a["permissions"]["view"]
    assert a["validations"]["length"]["max"] in ("40", 40)


def test_pronouns_saved_for_a_user(user_factory):
    from conftest import REALM, admin_token, get, put
    u = user_factory()
    token = admin_token()
    rep = get(f"/admin/realms/{REALM}/users/{u.id}", token).json()
    rep.setdefault("attributes", {})["pronouns"] = ["they/them"]
    assert put(f"/admin/realms/{REALM}/users/{u.id}", token, rep).status_code == 204
    assert get(f"/admin/realms/{REALM}/users/{u.id}", token).json()["attributes"]["pronouns"] == ["they/them"]
