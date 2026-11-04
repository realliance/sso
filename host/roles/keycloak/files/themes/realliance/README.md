# Realliance login theme

`login/` extends Keycloak's stock `keycloak.v2` login theme (parent) and adds one stylesheet,
`resources/css/realliance.css`, plus self-hosted fonts: Atkinson Hyperlegible (body, 400/700 + italics),
Fredoka (headings, variable 300-700), Noto Sans Mono (code, variable 100-900). All SIL OFL 1.1; the
licences sit in `login/resources/fonts/OFL-*.txt`. Nothing loads from Google Fonts or any CDN
(`tests/test_login_theme.py`). Latin subset only (no latin-ext), `font-display: swap`. No preload:
Keycloak has no head hook short of forking `template.ftl`, which would tie the theme to each
Keycloak upgrade; the six files total ~160 KB.

Source: <https://github.com/google/fonts> at `2fe1e8c6b137fb13041a7cfca6fdcd8a910ea4dc` (`ofl/`).
`scripts/build-login-fonts.sh` pins the sha256 of every source file and rebuilds the woff2 files (it is the
same recipe as `luma-homeops/scripts/build-forge-fonts.sh`).

Delivery: the `keycloak` Ansible role copies this directory to `/opt/keycloak/themes/realliance` (restarting
Keycloak; themes need no `kc.sh build`), and `realm/realm.tf` sets `login_theme = "realliance"`. The account
console (`keycloak.v3`) and emails are untouched.
