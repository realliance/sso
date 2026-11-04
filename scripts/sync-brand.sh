#!/usr/bin/env bash
# Sync the Realliance brand kit (git.realliance.net/realliance/brand) into the Keycloak theme.
#
#   scripts/sync-brand.sh <tag> [--rebuild]      e.g. scripts/sync-brand.sh v0.1.0
#
# 1. Fetches <tag> and verifies it: an annotated tag named <tag>, signed by an operator. The keyring is
#    this repo's own: keys/*.asc are imported into a throwaway GNUPGHOME and only the operators'
#    gpg_fingerprint values in operators.yml are trusted (never the GitHub web-flow key).
# 2. Copies the files the theme uses from dist/ at that tag, each checked against dist/manifest.json
#    (sha256). Hashed files keep the brand's content hash (realliance-logo-mocha.<8 hex>.svg); the
#    login favicon stays img/favicon.ico, the name Keycloak requests.
# 3. Points the references at the new names: url()s in both themes' realliance.css (the sources; edit
#    those), which are then shipped as hashed copies realliance.<8 hex>.css named by theme.properties
#    styles=; the account favicon via favIcon=. Deletes hashed (and formerly unhashed) copies nothing
#    references, checks that both palette blocks still equal the brand's palette, and records the sync
#    in brand.lock.json.
# 4. --rebuild: also rebuilds the tag with Nix and fails unless it equals the committed dist/.
#
# Never deploys anything: review `git diff`, run the tests, open a PR. ansible-pull copies the theme
# (and restarts Keycloak) after the merge; it never deletes old files on the host, so a stale page that
# still names an old hashed file keeps working.
set -euo pipefail

BRAND_REPO=${BRAND_REPO:-https://git.realliance.net/realliance/brand.git}

tag=${1:-}
rebuild=false
[ "${2:-}" = "--rebuild" ] && rebuild=true
if ! [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { [ $# -gt 1 ] && ! $rebuild; } || [ $# -gt 2 ]; then
  echo "usage: $0 <vX.Y.Z> [--rebuild]" >&2
  exit 2
fi

HERE=$(cd "$(dirname "$0")/.." && pwd)
THEME=$HERE/host/roles/keycloak/files/themes/realliance
LOCK=$HERE/brand.lock.json
mapfile -t TRUSTED < <(sed -nE 's/^\s*gpg_fingerprint:\s*([0-9A-Fa-f]{40})\s*$/\1/p' "$HERE/operators.yml")
[ ${#TRUSTED[@]} -gt 0 ] || { echo "sync-brand: no operator gpg_fingerprint in operators.yml" >&2; exit 1; }

# consumer path (under the theme) <- dist logical name; "hashed" or "fixed" consumer name
MAP='
login/resources/img/realliance-logo-mocha.svg   img/logo-mocha.svg              hashed
login/resources/img/realliance-logo-latte.svg   img/logo-latte.svg              hashed
login/resources/img/favicon.ico                 fixed/keycloak/img/favicon.ico  fixed
account/resources/favicon.svg                   img/icon.svg                    hashed
'
for t in login account; do
  for f in atkinson-hyperlegible-Regular atkinson-hyperlegible-Italic atkinson-hyperlegible-Bold atkinson-hyperlegible-BoldItalic fredoka-latin noto-sans-mono-latin; do
    MAP+="$t/resources/fonts/$f.woff2 fonts/$f.woff2 hashed"$'\n'
  done
  for f in OFL-atkinson-hyperlegible OFL-fredoka OFL-noto-sans-mono; do
    MAP+="$t/resources/fonts/$f.txt fonts/$f.txt fixed"$'\n'
  done
done

die() { echo "sync-brand: $*" >&2; exit 1; }
hashed_name() { local d b e; d=$(dirname "$1"); b=$(basename "$1"); e=${b##*.}; echo "$d/${b%.*}.${2:0:8}.$e"; }
repoint() { # file base ext newbasename: every /<base>(.<8 hex>).<ext> -> /<newbasename>
  B="$2" E="$3" N="$4" perl -0pi -e 's{(?<=/)\Q$ENV{B}\E(?:\.[0-9a-f]{8})?\.\Q$ENV{E}\E(?![\w.-])}{$ENV{N}}g' "$1"
}
prune() { # dir base ext keep [keep-unhashed]
  local f
  for f in "$1/$2.$3" "$1/$2".????????."$3"; do
    [ -e "$f" ] || continue
    [ "$(basename "$f")" = "$4" ] && continue
    [ "${5:-}" = keep-unhashed ] && [ "$(basename "$f")" = "$2.$3" ] && continue
    [[ $(basename "$f") =~ ^$2(\.[0-9a-f]{8})?\.$3$ ]] || continue
    rm -- "$f"
    echo "removed ${f#"$HERE"/}"
  done
}
# palette <css> <mode>: the --rl-* values of the palette block (dark = first :root, light = the media block over it)
palette() {
  M="$2" perl -0ne '
    my ($s) = /==== Realliance palette(.*?)==== Patternfly 5 globals/s or die "no palette block\n";
    $s =~ s{/\*.*?\*/}{}gs;
    my ($dark, $light) = split /\@media \(prefers-color-scheme: light\)/, $s, 2;
    my %v; while ($dark =~ /(--rl-[\w-]+)\s*:\s*([^;]+);/g) { (my $x = $2) =~ s/\s+$//; $v{$1} = $x }
    if ($ENV{M} eq "latte") { while ($light =~ /(--rl-[\w-]+)\s*:\s*([^;]+);/g) { (my $x = $2) =~ s/\s+$//; $v{$1} = $x } }
    print "$_=$v{$_}\n" for sort keys %v;
  ' "$1" 2>/dev/null || true
}

work=$(mktemp -d)
trap 'gpgconf --homedir "$work/gnupg" --kill all >/dev/null 2>&1 || true; rm -rf -- "$work"' EXIT
brand=$work/brand

# ---- 1. fetch and verify the signed tag against keys/ + operators.yml
mkdir -m 700 "$work/gnupg"
GNUPGHOME=$work/gnupg gpg --batch --quiet --import "$HERE"/keys/*.asc 2>/dev/null || die "cannot import keys/*.asc"
git init -q "$brand"
git -C "$brand" fetch -q --depth=1 --no-tags "$BRAND_REPO" "+refs/tags/$tag:refs/tags/$tag" || die "cannot fetch $tag from $BRAND_REPO"
[ "$(git -C "$brand" cat-file -t "refs/tags/$tag")" = tag ] || die "$tag is not an annotated (signed) tag"
[ "$(git -C "$brand" cat-file tag "refs/tags/$tag" | sed -n 's/^tag //p')" = "$tag" ] || die "tag object is not named $tag"
status=$(GNUPGHOME=$work/gnupg git -C "$brand" verify-tag --raw "refs/tags/$tag" 2>&1 >/dev/null) || die "signature of $tag does not verify against keys/*.asc"
grep -qE '^\[GNUPG:\] (BADSIG|EXPKEYSIG|REVKEYSIG|EXPSIG|ERRSIG)' <<<"$status" && die "signature of $tag is bad, expired or revoked"
signer=$(awk '$2 == "VALIDSIG" {print $NF; exit}' <<<"$status")
ok=false
for f in "${TRUSTED[@]}"; do [ "${f^^}" = "$signer" ] && ok=true; done
$ok || die "$tag is signed by $signer, who is not an operator (operators.yml)"
commit=$(git -C "$brand" rev-parse "refs/tags/$tag^{commit}")
tagobj=$(git -C "$brand" rev-parse "refs/tags/$tag")
git -C "$brand" -c advice.detachedHead=false checkout -q "$commit"
echo "verified $tag ($commit), signed by operator $signer"
manifest=$brand/dist/manifest.json
[ -f "$manifest" ] || die "$tag has no dist/manifest.json"

# ---- 4 (first, so nothing is touched if it fails)
if $rebuild; then
  out=$(nix build --no-link --print-out-paths "git+file://$brand?rev=$commit&shallow=1#dist") || die "nix build of $tag failed"
  diff -r --brief "$out" "$brand/dist" || die "a fresh build of $tag differs from its committed dist/"
  echo "rebuilt $tag: identical to its committed dist/ ($out)"
fi

# palette: every --rl-* value of both blocks must equal the brand's palette.json (before touching anything)
for t in login account; do
  for mode in mocha latte; do
    vals=$(palette "$THEME/$t/resources/css/realliance.css" "$mode")
    [ -n "$vals" ] || die "$t realliance.css has no palette block"
    while IFS= read -r line; do
      k=${line%%=*}; v=${line#*=}
      want=$(jq -r --arg m "$mode" --arg k "${k#--rl-}" '.[$m][$k] // "(not in the brand palette)"' "$brand/dist/palette.json")
      [ "$v" = "$want" ] || die "$t realliance.css $mode $k is '$v', realliance/brand $tag has '$want': align the palette block (or the brand) first"
    done <<<"$vals"
  done
done
echo "palette blocks of both themes equal realliance/brand $tag palette.json"

# ---- 2. copy, each file checked against the manifest
declare -A newname
lockfiles='{}'
while read -r dest logical mode; do
  [ -n "$dest" ] || continue
  file=$(jq -er --arg l "$logical" '.files[$l].file' "$manifest") || die "$logical is not in the manifest of $tag"
  sum=$(jq -er --arg l "$logical" '.files[$l].sha256' "$manifest")
  echo "$sum  $brand/dist/$file" | sha256sum -c --quiet - || die "dist/$file does not match its sha256 in manifest.json"
  target=$dest
  [ "$mode" = hashed ] && target=$(hashed_name "$dest" "$sum")
  install -m 0644 "$brand/dist/$file" "$THEME/$target"
  newname[$dest]=$(basename "$target")
  lockfiles=$(jq -c --arg t "$target" --arg l "$logical" --arg s "$sum" '. + {($t): {from: $l, sha256: $s}}' <<<"$lockfiles")
done <<<"$MAP"

# ---- 3. references, hashed stylesheets, stale copies
grep -q '^favIcon=' "$THEME/account/theme.properties" || printf 'favIcon=/favicon.svg\n' >> "$THEME/account/theme.properties"
while read -r dest logical mode; do
  [ "$mode" = hashed ] || continue
  t=${dest%%/*}; b=$(basename "$dest"); base=${b%.*}; ext=${b##*.}
  for f in "$THEME/$t/resources/css/realliance.css" "$THEME/$t/theme.properties"; do repoint "$f" "$base" "$ext" "${newname[$dest]}"; done
  prune "$THEME/$(dirname "$dest")" "$base" "$ext" "${newname[$dest]}"
done <<<"$MAP"
for t in login account; do
  src=$THEME/$t/resources/css/realliance.css
  for u in $(grep -oE '\.\./(fonts|img)/[^)"]+' "$src" | sort -u); do
    [ -f "$THEME/$t/resources/css/$u" ] || die "$t realliance.css references $u, which does not exist"
  done
  sum=$(sha256sum "$src" | cut -d' ' -f1)
  hashed=realliance.${sum:0:8}.css
  install -m 0644 "$src" "$THEME/$t/resources/css/$hashed"
  repoint "$THEME/$t/theme.properties" realliance css "$hashed"
  prune "$THEME/$t/resources/css" realliance css "$hashed" keep-unhashed
  grep -q "^styles=.*css/$hashed" "$THEME/$t/theme.properties" || die "$t/theme.properties styles= does not name css/$hashed"
  lockfiles=$(jq -c --arg t "$t/resources/css/$hashed" --arg s "$sum" --arg f "host/roles/keycloak/files/themes/realliance/$t/resources/css/realliance.css" \
    '. + {($t): {from: $f, sha256: $s}}' <<<"$lockfiles")
done

jq -n --arg repo "${BRAND_REPO%.git}" --arg tag "$tag" --arg tagobj "$tagobj" --arg commit "$commit" --arg signer "$signer" \
  --arg msum "$(sha256sum "$manifest" | cut -d' ' -f1)" --argjson files "$lockfiles" \
  '{about: "Written by scripts/sync-brand.sh: the realliance/brand release the Keycloak theme assets come from (paths under host/roles/keycloak/files/themes/realliance). Do not edit.",
    repo: $repo, tag: $tag, tag_object: $tagobj, commit: $commit, signer: $signer, manifest_sha256: $msum,
    files: ($files | to_entries | sort_by(.key) | from_entries)}' > "$LOCK"
echo "synced realliance/brand $tag into ${THEME#"$HERE"/}; review with: git status && git diff --stat"
