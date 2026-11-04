#!/usr/bin/env bash
# Rebuild the Realliance SSO login-theme web fonts (host/roles/keycloak/files/themes/realliance/login/resources/fonts).
# Docs: host/roles/keycloak/files/themes/realliance/README.md. Same pins and subset as luma-homeops' build-forge-fonts.sh.
# Downloads are untrusted data: they go into a fresh
# mktemp dir, are verified against the sha256 pinned below, and are only ever read by fonttools.
#
#   scripts/build-login-fonts.sh            # rebuild into the repo, then `git diff --stat`
#   OUT=/some/dir scripts/build-login-fonts.sh
set -euo pipefail

GOOGLE_FONTS_COMMIT=2fe1e8c6b137fb13041a7cfca6fdcd8a910ea4dc   # github.com/google/fonts, 2026-11-03
RAW=https://raw.githubusercontent.com/google/fonts/$GOOGLE_FONTS_COMMIT/ofl
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$HERE/host/roles/keycloak/files/themes/realliance/login/resources/fonts}

# path-under-ofl/ sha256
SOURCES='
atkinsonhyperlegible/AtkinsonHyperlegible-Regular.ttf 7fb917c89019896d0b52ee84b7cbb3304c18cb90b19a62f5e32712bd23e97669
atkinsonhyperlegible/AtkinsonHyperlegible-Italic.ttf 021beda4d3c6edfc78872e436d74009f9a1bcb294331908fe5747c61d3dcc514
atkinsonhyperlegible/AtkinsonHyperlegible-Bold.ttf 5a3b0c8cc8ca545155150b4512a1fa248298df121c50d6557e651e61fbdab92f
atkinsonhyperlegible/AtkinsonHyperlegible-BoldItalic.ttf 7a46f1b0ef2f64b61065c1a6b5a11fcb9b019b44062d88ba121a083cc39e86bf
atkinsonhyperlegible/OFL.txt f32d22b3908fcad2c86a74000614ec22e6a7f66ea7e867e616026a27aebdc143
fredoka/Fredoka%5Bwdth,wght%5D.ttf 2ba02e68b152868aef9ba28e24b3648c7d457fe6f25c761f2c2c53fb61a73fc8
fredoka/OFL.txt 5c9e7eee5c6b25f4b05b8d53b2e470ea4962f9ced742d044a98f7d95d1375bab
notosansmono/NotoSansMono%5Bwdth,wght%5D.ttf 2cb2adb378a8f574213e23df697050b83c54c27df465a2015552740b2769a081
notosansmono/OFL.txt cee9892f9f0cc8fe882c9e9537ee6a89621d86ee7ceaf70b02e2b2b1c25c061a
'

# latin: Basic Latin, Latin-1, Latin Extended-A bits for common punctuation/ligatures, general punctuation,
# euro, trademark, arrows/minus. No latin-ext block (size is not the issue, need is).
UNICODES='U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD'

if [ -z "${FONTS_INNER:-}" ]; then
  # fonttools + brotli (woff2) in one interpreter; the plain pyftsubset wrapper cannot see brotli.
  FONTS_INNER=1 exec nix shell --impure \
    --expr 'let p = import <nixpkgs> {}; in p.python3.withPackages (ps: [ps.fonttools ps.brotli])' \
    -c bash "$0" "$@"
fi

work=$(mktemp -d)            # fresh and empty
trap 'rm -rf "$work"' EXIT
mkdir "$work/src" "$work/tmp"
while read -r path sum; do
  [ -n "$path" ] || continue
  name=$(basename "${path//%5B/[}"); name=${name//%5D/]}
  curl -sfL "$RAW/$path" -o "$work/src/$name"
  echo "$sum  $work/src/$name" | sha256sum -c --quiet - || { echo "sha256 mismatch: $path" >&2; exit 1; }
done <<<"$SOURCES"

sub() { python -I -m fontTools.subset "$1" --unicodes="$UNICODES" --flavor=woff2 --layout-features='*' --output-file="$2"; }
mkdir -p "$OUT"
for w in Regular Italic Bold BoldItalic; do
  sub "$work/src/AtkinsonHyperlegible-$w.ttf" "$OUT/atkinson-hyperlegible-$w.woff2"
done
# Fredoka (wght 300-700) and Noto Sans Mono (wght 100-900) stay variable on wght; the width axis is pinned at 100.
python -I -m fontTools.varLib.instancer "$work/src/Fredoka[wdth,wght].ttf" wdth=100 -o "$work/tmp/fredoka.ttf" -q
python -I -m fontTools.varLib.instancer "$work/src/NotoSansMono[wdth,wght].ttf" wdth=100 -o "$work/tmp/nsm.ttf" -q
sub "$work/tmp/fredoka.ttf" "$OUT/fredoka-latin.woff2"
sub "$work/tmp/nsm.ttf" "$OUT/noto-sans-mono-latin.woff2"
ls -l "$OUT"
