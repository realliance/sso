"""Static checks for the Realliance login and account themes (no box needed):

    pytest tests/test_login_theme.py

The login theme extends keycloak.v2 and the account theme extends keycloak.v3; each adds only a stylesheet and
self-hosted fonts (plus, in the stylesheet, the forge palette). Nothing may load from
Google Fonts or any CDN; every @font-face src must be a file that ships; the realm must select the
theme and the Ansible role must install it.
"""
import hashlib
import posixpath
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
THEME = REPO / "host/roles/keycloak/files/themes/realliance"
LOGIN = THEME / "login"
ACCOUNT = THEME / "account"
CSS = LOGIN / "resources/css/realliance.css"
ACCOUNT_CSS = ACCOUNT / "resources/css/realliance.css"
BOTH = ((LOGIN, CSS), (ACCOUNT, ACCOUNT_CSS))
CDN_HOSTS = ("fonts.googleapis.com", "fonts.gstatic.com", "googleapis.com", "gstatic.com",
             "cdnjs", "jsdelivr", "unpkg.com", "bunny.net", "typekit")
HASHED = re.compile(r"^(?P<base>.+)\.(?P<h>[0-9a-f]{8})\.(?P<ext>css|woff2|svg|png)$")


def _props(theme: Path = LOGIN) -> dict:
    out = {}
    for line in (theme / "theme.properties").read_text().splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def test_theme_extends_keycloak_v2_and_only_adds_the_sheet():
    p = _props()
    assert set(p) == {"parent", "styles"} and p["parent"] == "keycloak.v2"
    assert re.fullmatch(r"css/styles\.css css/realliance\.[0-9a-f]{8}\.css", p["styles"]), p["styles"]


def test_no_cdn_anywhere_in_the_theme():
    files = [f for f in THEME.rglob("*") if f.is_file() and f.suffix in {".css", ".properties", ".ftl", ".js", ".html", ".md"}]
    assert CSS in files and ACCOUNT_CSS in files
    for f in files:
        if f.name == "README.md":
            continue  # names the hosts only to say we never use them
        text = f.read_text(errors="replace").lower()
        for host in CDN_HOSTS:
            assert host not in text, f"{f.relative_to(REPO)} references {host}"
    for sheet in (CSS, ACCOUNT_CSS):
        assert not re.search(r"https?://", sheet.read_text())


def test_every_font_face_src_ships():
    for theme, sheet in BOTH:
        _check_font_faces(theme, sheet)


def _check_font_faces(theme: Path, sheet: Path):
    css = sheet.read_text()
    faces = re.findall(r"@font-face\s*\{[^}]*\}", css)
    assert len(faces) == 6
    for face in faces:
        assert "font-display:swap" in face.replace(" ", "")
        urls = re.findall(r"url\(\s*[\"']?([^\"')]+)", face)
        assert len(urls) == 1 and urls[0].endswith(".woff2")
        target = theme / "resources" / posixpath.normpath(posixpath.join("css", urls[0]))
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


# --- account console theme (keycloak.v3) ----------------------------------------------------------

def test_account_theme_extends_keycloak_v3_and_only_adds_the_sheet():
    # keycloak.v3's index.ftl renders properties.styles as <link> tags (26.8.1); v3 sets none of its own
    p = _props(ACCOUNT)
    assert set(p) == {"parent", "styles", "favIcon"} and p["parent"] == "keycloak.v3"
    assert re.fullmatch(r"css/realliance\.[0-9a-f]{8}\.css", p["styles"]), p["styles"]
    assert re.fullmatch(r"/favicon\.[0-9a-f]{8}\.svg", p["favIcon"]), p["favIcon"]
    for theme in (LOGIN, ACCOUNT):
        assert not list(theme.glob("*.ftl")), "templates would pin the theme to one Keycloak version"
        assert not list(theme.rglob("*.js")), "no scripts: CSS-only theme"


def test_every_stylesheet_named_by_the_themes_ships():
    # login also names the parent's css/styles.css, which comes from keycloak.v2 (not shipped here). Each theme
    # ships its realliance.css (the source) as the content-hashed copy that styles= names (scripts/sync-brand.sh).
    for theme, sheet in BOTH:
        ours = _props(theme)["styles"].split()[-1]
        shipped = theme / "resources" / ours
        assert shipped.is_file(), f"{theme.name}: {ours} does not ship"
        assert shipped.read_bytes() == sheet.read_bytes(), (
            f"{theme.name}: realliance.css changed without a new hashed copy: run scripts/sync-brand.sh <tag in brand.lock.json>")
    assert (ACCOUNT / "resources" / _props(ACCOUNT)["favIcon"].lstrip("/")).is_file()


def test_hashed_names_match_their_content_and_none_is_stale():
    referenced = set()
    for theme, sheet in BOTH:
        p = _props(theme)
        referenced |= {Path(s).name for s in p["styles"].split()} | {Path(p.get("favIcon", "")).name}
        referenced |= {Path(u).name for u in re.findall(r"url\(\s*[\"']?([^\"')]+)", sheet.read_text())}
    for f in THEME.rglob("*"):
        m = HASHED.match(f.name)
        if f.is_file() and m:
            assert hashlib.sha256(f.read_bytes()).hexdigest()[:8] == m["h"], f"{f.relative_to(REPO)}: name does not match its content"
            assert f.name in referenced, f"{f.relative_to(REPO)} is hashed but nothing references it (stale: re-run sync-brand.sh)"


def _one(directory: Path, pattern: str) -> Path:
    found = sorted(directory.glob(pattern))
    assert len(found) == 1, f"want exactly one {pattern} in {directory.relative_to(REPO)}, found {[f.name for f in found]}"
    return found[0]


def test_account_fonts_are_byte_identical_to_the_login_fonts():
    login = {p.name: p.read_bytes() for p in (LOGIN / "resources/fonts").iterdir()}
    account = {p.name: p.read_bytes() for p in (ACCOUNT / "resources/fonts").iterdir()}
    assert login == account and len(login) == 9  # 6 woff2 + 3 OFL texts


def _block(css: str) -> str:
    start = css.index("==== Realliance palette")
    return css[start:css.index("==== Patternfly 5 globals")]


def test_palette_block_is_identical_in_both_themes():
    assert _block(CSS.read_text()) == _block(ACCOUNT_CSS.read_text())
    # the variables are the forge's Catppuccin values, copied verbatim (spot check the anchors)
    block = _block(CSS.read_text())
    for value in ("#11111b", "#181825", "#45475a", "#cdd6f4", "#74c7ec", "#f38ba8", "#a6e3a1"):
        assert value in block


HIDING = (r"display\s*:\s*none", r"visibility\s*:\s*(hidden|collapse)", r"opacity\s*:\s*0(\.0+)?\s*(;|!|$)",
          r"position\s*:\s*(absolute|fixed)", r"\bclip\s*:", r"clip-path\s*:", r"\bleft\s*:\s*-", r"\btop\s*:\s*-",
          r"font-size\s*:\s*0(?![\d.])", r"pointer-events\s*:\s*none",
          r"overflow(-[xy])?\s*:\s*(hidden|clip)",
          r"(?<![\w-])(min-|max-)?(width|height)\s*:\s*0(px|%|em|rem)?\s*(;|!|$)",
          r"transform\s*:[^;]*scale[XYZ3d]*\(\s*0(?![\d.])",
          r"transform\s*:[^;]*translate[XYZ3d]*\([^)]*-?\d{3,}",
          r"transform\s*:[^;]*translate[XYZ3d]*\([^)]*-?[1-9]\d{2,}%")


def hiding_declarations(css: str) -> list[str]:
    """Every `selector { declaration }` that could hide, clip, collapse or move something. No allowlist: the
    sheets only restyle, so any hit is a regression, whatever it selects (controls, errors, alerts, links)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    hits = []
    for selector, body in re.findall(r"([^{}@]+)\{([^{}]*)\}", css):
        if "font-face" in selector:
            continue
        for decl in body.split(";"):
            decl = decl.replace("!important", "").strip() + ";"
            for bad in HIDING:
                if re.search(bad, decl):
                    hits.append(f"{selector.strip()} {{ {decl} }}")
    return hits


def test_hiding_check_catches_each_pattern():
    for bad in ("overflow:hidden", "overflow-x:clip", "clip-path:inset(50%)", "width:0", "max-height:0", "height: 0px",
                "transform:scale(0)", "transform:translateX(-9999px)", "transform: translate(0,-200%)", "opacity:0",
                "visibility:hidden", "display:none", "display:none!important"):
        assert hiding_declarations(f"input,.pf-v5-c-alert a{{{bad}}}"), bad
    for ok in ("border-radius:8px", "width:0.5rem", "opacity:0.9", "transform:scale(1)", "border:0", "max-width:100%"):
        assert not hiding_declarations(f".x{{{ok}}}"), ok


def test_css_never_hides_or_moves_a_control():
    for sheet in (CSS, ACCOUNT_CSS):
        hits = hiding_declarations(sheet.read_text())
        assert not hits, f"{sheet.relative_to(REPO)}: {hits}"


def test_no_image_polygon_background_remains():
    css = CSS.read_text()
    assert "background-image:none" in css.replace(" ", "")


def test_realm_selects_the_account_theme_for_the_realliance_realm_only():
    tf = "".join(p.read_text() for p in (REPO / "realm").glob("*.tf"))
    assert len(re.findall(r'^\s*account_theme\s*=\s*"realliance"', tf, re.M)) == 1
    assert len(re.findall(r'^\s*login_theme\s*=\s*"realliance"', tf, re.M)) == 1
    # the master realm (break-glass admin console) is not managed here, so it stays stock
    assert re.findall(r'resource "keycloak_realm" "(\w+)"', tf) == ["realliance"]


# --- Realliance logo ---
LOGO_FILES = [_one(LOGIN / "resources/img", "realliance-logo-mocha.*.svg"), _one(LOGIN / "resources/img", "realliance-logo-latte.*.svg"),
              LOGIN / "resources/img/favicon.ico", _one(ACCOUNT / "resources", "favicon.*.svg")]


def test_logo_and_favicon_files_ship_without_external_references():
    for f in LOGO_FILES:
        assert f.is_file() and f.stat().st_size > 0, f"missing {f.relative_to(REPO)}"
    assert LOGO_FILES[2].read_bytes()[:4] == b"\x00\x00\x01\x00", "favicon.ico is not an ICO"
    for f in (LOGO_FILES[0], LOGO_FILES[1], LOGO_FILES[3]):
        t = f.read_text()
        assert "http" not in t.replace('xmlns="http://www.w3.org/2000/svg"', ""), f"{f.name} references a URL"
        assert not re.search(r"<(image|use|script|foreignObject|text)\b|@import|url\(|font-family|href=", t), f.name
    # each mark ships with its own ink: the dark-mode (mocha) one has light letters, the light-mode (latte) one dark
    assert "#cdd6f4" in LOGO_FILES[0].read_text().lower() and "#4c4f69" in LOGO_FILES[1].read_text().lower()


def test_header_mark_is_css_only_and_follows_the_palette_scheme():
    css = CSS.read_text()
    m = re.search(r"#kc-header-wrapper::before\{([^}]*)\}", css)
    mocha, latte = LOGO_FILES[0].name, LOGO_FILES[1].name
    assert m and f"url(../img/{mocha})" in m.group(1), "dark mark is the default"
    assert re.search(rf"@media \(prefers-color-scheme: light\)\{{#kc-header-wrapper::before\{{background-image:url\(\.\./img/{re.escape(latte)}\)\}}\}}", css)
    assert (LOGIN / "resources/css" / f"../img/{latte}").resolve().is_file()
