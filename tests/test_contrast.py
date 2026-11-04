"""WCAG contrast of the Realliance palette, light and dark, for both stylesheets (no box needed).

    pytest tests/test_contrast.py

Parses the `--rl-*` palette out of the stylesheet: the dark values in the first :root block and the light
values in the `@media (prefers-color-scheme: light)` block. Text and links need 4.5:1 on every surface they
can sit on; focus indicators and input focus borders need 3:1 against their neighbours.
"""
import re
from pathlib import Path

import pytest

THEME = Path(__file__).resolve().parent.parent / "host/roles/keycloak/files/themes/realliance"
SHEETS = {"login": THEME / "login/resources/css/realliance.css", "account": THEME / "account/resources/css/realliance.css"}


def _rgb(value: str):
    value = value.strip()
    m = re.fullmatch(r"#([0-9a-fA-F]{6})", value)
    if m:
        return tuple(int(m.group(1)[i:i + 2], 16) / 255 for i in (0, 2, 4))
    m = re.fullmatch(r"rgb\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*\)", value)
    assert m, f"unparsed colour {value!r}"
    return tuple(float(g) / 255 for g in m.groups())


def luminance(value: str) -> float:
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in _rgb(value))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _vars(block: str) -> dict:
    return {k: v.strip() for k, v in re.findall(r"(--rl-[\w-]+)\s*:\s*([^;]+);", re.sub(r"/\*.*?\*/", "", block, flags=re.S))}


def palettes(sheet: Path):
    css = sheet.read_text()
    start = css.index("==== Realliance palette")
    section = css[start:css.index("==== Patternfly 5 globals")]
    media = section.index("@media (prefers-color-scheme: light)")
    dark = _vars(section[:media])
    light = {**dark, **_vars(section[media:])}
    return {"dark": dark, "light": light}


# (foreground, backgrounds it can sit on, minimum ratio, why)
def _pairs(mode: str):
    surfaces = ["--rl-bg", "--rl-surface"] + (["--rl-surface-hover"] if mode == "dark" else [])
    text, ui = 4.5, 3.0
    out = []
    for fg in ("--rl-text", "--rl-text-muted", "--rl-primary", "--rl-primary-hover",
               "--rl-error", "--rl-success", "--rl-warning", "--rl-info"):  # body, links, hover, alert titles, error text
        out += [(fg, bg, text) for bg in surfaces]
    out += [("--rl-input-text", "--rl-input-bg", text), ("--rl-text-muted", "--rl-input-bg", text)]  # input text, placeholder
    out += [("--rl-primary-contrast", "--rl-primary", text), ("--rl-primary-contrast", "--rl-primary-hover", text)]  # button label
    out += [("--rl-error-text", "--rl-error", text), ("--rl-success-text", "--rl-success", text)]
    out += [("--rl-accent", bg, ui) for bg in surfaces]  # keyboard focus outline
    out += [("--rl-primary", "--rl-input-bg", ui), ("--rl-primary", "--rl-surface", ui)]  # input focus border
    return out


@pytest.mark.parametrize("mode", ["light", "dark"])
@pytest.mark.parametrize("name", sorted(SHEETS))
def test_palette_contrast(name, mode):
    pal = palettes(SHEETS[name])[mode]
    failures = [f"{fg} {pal[fg]} on {bg} {pal[bg]} = {contrast(pal[fg], pal[bg]):.2f} < {need}"
                for fg, bg, need in _pairs(mode) if contrast(pal[fg], pal[bg]) < need]
    assert not failures, f"{name} {mode}:\n" + "\n".join(failures)


def test_contrast_function_known_values():
    assert round(contrast("#000000", "#ffffff"), 2) == 21.0
    assert round(contrast("#209fb5", "#e6e9ef"), 2) == 2.58  # the round-2 forge value that failed
