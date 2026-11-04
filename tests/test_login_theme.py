"""Static checks for the Realliance login theme (no box needed):

    pytest tests/test_login_theme.py

The theme extends keycloak.v2 and adds only a stylesheet and self-hosted fonts. Nothing may load from
Google Fonts or any CDN; every @font-face src must be a file that ships; the realm must select the
theme and the Ansible role must install it.
"""
import posixpath
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
THEME = REPO / "host/roles/keycloak/files/themes/realliance"
LOGIN = THEME / "login"
CSS = LOGIN / "resources/css/realliance.css"
CDN_HOSTS = ("fonts.googleapis.com", "fonts.gstatic.com", "googleapis.com", "gstatic.com",
             "cdnjs", "jsdelivr", "unpkg.com", "bunny.net", "typekit")


def _props() -> dict:
    out = {}
    for line in (LOGIN / "theme.properties").read_text().splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def test_theme_extends_keycloak_v2_and_only_adds_the_sheet():
    p = _props()
    assert p == {"parent": "keycloak.v2", "styles": "css/styles.css css/realliance.css"}


def test_no_cdn_anywhere_in_the_theme():
    files = [f for f in THEME.rglob("*") if f.is_file() and f.suffix in {".css", ".properties", ".ftl", ".js", ".html", ".md"}]
    assert CSS in files
    for f in files:
        if f.name == "README.md":
            continue  # names the hosts only to say we never use them
        text = f.read_text(errors="replace").lower()
        for host in CDN_HOSTS:
            assert host not in text, f"{f.relative_to(REPO)} references {host}"
    assert not re.search(r"https?://", CSS.read_text())


def test_every_font_face_src_ships():
    css = CSS.read_text()
    faces = re.findall(r"@font-face\s*\{[^}]*\}", css)
    assert len(faces) == 6
    for face in faces:
        assert "font-display:swap" in face.replace(" ", "")
        urls = re.findall(r"url\(\s*[\"']?([^\"')]+)", face)
        assert len(urls) == 1 and urls[0].endswith(".woff2")
        target = LOGIN / "resources" / posixpath.normpath(posixpath.join("css", urls[0]))
        assert target.is_file(), f"{urls[0]} does not ship"
        assert target.read_bytes()[:4] == b"wOF2"
        assert target.stat().st_size < 100_000


def test_licences_ship_with_the_fonts():
    for name in ("atkinson-hyperlegible", "fredoka", "noto-sans-mono"):
        text = (LOGIN / f"resources/fonts/OFL-{name}.txt").read_text()
        assert "SIL OPEN FONT LICENSE" in text.upper()


def test_realm_selects_the_theme_and_the_role_installs_it():
    assert re.search(r'^\s*login_theme\s*=\s*"realliance"', (REPO / "realm/realm.tf").read_text(), re.M)
    tasks = yaml.safe_load((REPO / "host/roles/keycloak/tasks/main.yml").read_text())
    copy = [t for t in tasks if "ansible.builtin.copy" in t and t["ansible.builtin.copy"]["src"] == "themes/realliance"]
    assert len(copy) == 1
    assert copy[0]["ansible.builtin.copy"]["dest"].rstrip("/") == "/opt/keycloak/themes"
    assert copy[0]["notify"] == "Restart keycloak"
