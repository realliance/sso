# Realliance themes (login and account console)

Two directory themes, both named `realliance`, both made of one stylesheet plus self-hosted fonts and no
templates or scripts, so a missing or broken one falls back to the stock theme (Keycloak logs a warning and
renders the default; sign-in is never blocked):

- `login/` extends `keycloak.v2` (Patternfly 5 login pages: sign-in, error, logout confirm, OTP, info).
  `styles=css/styles.css css/realliance.css` (the child's `styles=` replaces the parent's list, so the parent's
  own sheet is named first).
- `account/` extends `keycloak.v3` (the React + Patternfly 5 account console). `styles=css/realliance.css`.
  Keycloak 26.8.1's account `index.ftl` renders `properties.styles` as `<link>` tags after the app's own
  stylesheet, and v3 sets no `styles` of its own, so this is the supported CSS-only route; the React app is
  not forked. The console's bundle is still served through the theme by parent fallback.

Look: the forge's default Catppuccin theme (`git.realliance.net`, Mocha dark, Latte light by OS preference),
values copied verbatim into the `--rl-*` palette block (each variable is annotated with the forge variable
it copies). The palette block is byte-identical in both
stylesheets (`tests/test_login_theme.py`). Corners: 8px controls, 12px cards. Solid page background, no image.
The CSS never hides or moves a control or message (tested).

Fonts: Atkinson Hyperlegible (body, 400/700 + italics), Fredoka (headings, variable 300-700), Noto Sans Mono
(code, variable 100-900). All SIL OFL 1.1; the licences sit beside the fonts in `*/resources/fonts/OFL-*.txt`.
`account/resources/fonts` is a byte-identical copy of `login/resources/fonts` (tested). Nothing loads from Google
Fonts or any CDN. Latin subset only (no latin-ext), `font-display: swap`. No preload: Keycloak has no head hook
short of forking `template.ftl`.

Source: <https://github.com/google/fonts> at `2fe1e8c6b137fb13041a7cfca6fdcd8a910ea4dc` (`ofl/`).
`scripts/build-login-fonts.sh` pins the sha256 of every source file, rebuilds the woff2 files and refreshes the
account copy (same recipe as `luma-homeops/scripts/build-forge-fonts.sh`).

Delivery: the `keycloak` Ansible role copies this directory to `/opt/keycloak/themes/realliance` (restarting
Keycloak; directory themes need no `kc.sh build`), and `realm/realm.tf` sets `login_theme` and `account_theme`
on the `realliance` realm only. The master realm (break-glass admin console) is not managed here and stays stock.

Deploy order (the forge refuses to start while SSO discovery is down): merge this repo FIRST, wait for the box
to pull and Keycloak to restart (about 5-7 min), confirm a real sign-in works and `pytest
tests/realm/test_login_theme.py` passes (it fetches the live login page and account console and checks the
stylesheet and every woff2 return 200). Only then merge the matching luma-homeops forge change. Never deploy
both in one window, and never during a pages acceptance or forge-bot test run.

Cache note: `/resources/<ver>/...` is cached for a long time (and Cloudflare sits in front), so a later edit to
`realliance.css` may be served stale; rename the file or purge when changing it.

Revert: `git revert` the theme commit (the realm falls back to `keycloak.v2`/`keycloak.v3` once the setting is
gone); the orphan directory `/opt/keycloak/themes/realliance` can be removed by hand.
