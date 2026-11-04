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

Source: the brand kit, **git.realliance.net/realliance/brand** (Inkscape logo sources, palette, fonts pinned to
google/fonts `2fe1e8c6b137fb13041a7cfca6fdcd8a910ea4dc` by sha256; its `dist/` is built and committed there).
Never edit the fonts, the logos or the favicons here: `scripts/sync-brand.sh <tag> [--rebuild]` verifies the
signed tag against `keys/` + `operators.yml`, copies what the theme uses (sha256-checked against the brand's
`dist/manifest.json`), and records the release in `brand.lock.json`.

Content-hashed names: every file a page loads is `<name>.<8 hex of its sha256>.<ext>`, so a change is a new URL
(Cloudflare and Keycloak cache `/resources/<ver>/...` for 30 days). `css/realliance.css` is the source to edit;
the sync ships it as `css/realliance.<8 hex>.css` (named by `styles=` in `theme.properties`) and re-points its
`url()`s; the account favicon is `favIcon=`. After a hand edit of either `realliance.css`, re-run the sync with
the current tag (`brand.lock.json`) to re-hash it; `tests/test_login_theme.py` fails until you do. Only
`login/resources/img/favicon.ico` keeps its name (Keycloak requests it by name): it changes URL only when
Keycloak's resource version does (an upgrade), so after a change it may stay stale for up to 30 days unless the
URL is purged in Cloudflare. ansible-pull never deletes old files on the host, so stale pages keep working.

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

Revert: `git revert` the theme commit (signed, push to `main`); the realm falls back to `keycloak.v2`/`keycloak.v3`
once the settings are gone. The `copy` task never deletes anything, so **`/opt/keycloak/themes/realliance` stays on
the box after a revert**. It is harmless: nothing references it, and an unreferenced directory theme is never loaded.
To remove it (optional, no restart needed since nothing uses it; Keycloak re-scans themes on its next restart):
`ssh root@23.163.0.48 'rm -rf /opt/keycloak/themes/realliance'`, only after the realm no longer names `realliance`
(check with `pytest tests/realm/test_login_theme.py`, which should again fail with "fell back to stock").

Contrast: `tests/test_contrast.py` computes WCAG contrast from the palette blocks of both stylesheets (text and
links 4.5:1, focus indicators 3:1, light and dark). The light text colours are therefore darker Catppuccin shades
than the forge's decorative ones; see the EXCEPTION note in the palette comment.

Logo: the login header shows the Realliance mark (`login/resources/img/realliance-logo-{mocha,latte}.svg`) above the real
"REALLIANCE" text via `#kc-header-wrapper::before`, swapped with the palette's light media query. Favicons:
`login/resources/img/favicon.ico` and `account/resources/favicon.svg`. All are self-contained (no external references).
