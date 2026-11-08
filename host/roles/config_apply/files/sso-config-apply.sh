#!/usr/bin/env bash
# Apply realliance/sso realm/ and realliance/sso-people from Git.
# Managed by realliance/sso (host/roles/config_apply).
# Usage: sso-config-apply [changed|force]
#
# - realliance/sso: its head must verify against the pull keyring (operators and GitHub's web-flow key). realm/
#   applies only when that head changed, or on `force`.
# - realliance/sso-people: no keyring check on the head. sso-ledger walks every commit since last good (operator
#   keys and the path-limited ledger key only, never web-flow), then checks ledger.yaml and decides the guests.
#   LEDGER_MODE (ledger.env) says what the verdict does:
#     apply  people.yaml applies at the head only on a valid walk; a freeze or a failed walk applies nothing.
#     check  people.yaml applies from newest_trusted, or the stored last good if the walk failed, with the
#            guests handed before; the statuses say what apply would have done. Nothing in the ledger path blocks.
#   A failed content step never blocks either mode: the people apply takes the last handed guests.
# - LEDGER_DRILL_REF (ledger-drills): walked and checked with --dry in its own state; statuses only, never applied.
#
# The test harness moves every path: SSO_DIR, PEOPLE_DIR, STATE_DIR, SSO_ETC, SSO_LOCK, SSO_LEDGER_BIN,
# SSO_LEDGER_TIMEOUT (seconds per sso-ledger step, default 120) and TF_PLUGIN_CACHE_DIR. PEOPLE_REF=<branch>
# checks a test branch in throwaway ledger state, anchored at main's last good, and applies it with the last
# handed guests; main's ledger state is never touched.
set -euo pipefail
mode=${1:-changed}
SSO=${SSO_DIR:-/var/lib/sso-pull}
PEOPLE=${PEOPLE_DIR:-/var/lib/sso-people}
STATE=${STATE_DIR:-/var/lib/sso-config-apply}
ETC=${SSO_ETC:-/etc/realliance-sso}
LEDGER_BIN=${SSO_LEDGER_BIN:-/usr/local/sbin/sso-ledger}
LEDGER_TIMEOUT=${SSO_LEDGER_TIMEOUT:-120}
ref=${PEOPLE_REF:-main}

exec 9>"${SSO_LOCK:-/run/realliance-sso.lock}"
flock 9                                   # never overlap ansible-pull or another apply

install -d -m 0700 "$STATE" "$STATE/status"
set -a; . "$ETC/tofu.env"; set +a
. "$ETC/ledger.env"                       # LEDGER_MODE, LEDGER_DRILL_REF, PEOPLE_ANCHOR
case "${LEDGER_MODE:-}" in
  check) pfx="check: " ;;
  apply) pfx="" ;;
  *) echo "refusing: LEDGER_MODE in $ETC/ledger.env must be check or apply"; exit 1 ;;
esac
[[ ${PEOPLE_ANCHOR:-} =~ ^[0-9a-f]{40}$ ]] || { echo "refusing: PEOPLE_ANCHOR in $ETC/ledger.env is not a full sha"; exit 1; }
drill_ref=${LEDGER_DRILL_REF:-}
export GNUPGHOME=$ETC/gnupg TF_IN_AUTOMATION=1 TF_PLUGIN_CACHE_DIR=${TF_PLUGIN_CACHE_DIR:-/var/cache/tofu-plugins}
mkdir -p "$TF_PLUGIN_CACHE_DIR"
export GIT_SSH_COMMAND="ssh -i $ETC/people_deploy_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$ETC/known_hosts_github"

scratch=()
cleanup() { if [ ${#scratch[@]} -gt 0 ]; then rm -rf -- "${scratch[@]}"; fi; }
trap cleanup EXIT

jget() {  # file path… — one line per dotted path: a string as is, true/false, empty for null or absent
  python3 -I - "$@" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    doc = json.load(f)
for path in sys.argv[2:]:
    v = doc
    for key in path.split("."):
        v = v.get(key) if isinstance(v, dict) else None
    if v is None:
        v = ""
    elif isinstance(v, bool):
        v = "true" if v else "false"
    elif not isinstance(v, str):
        v = json.dumps(v)
    print(v.replace("\n", " "))
PY
}

statuses_from() {  # file key — apply_st, apply_desc, ledger_st, ledger_desc from <key>.apply and <key>.ledger
  local out
  local -a vals
  out=$(jget "$1" "$2.apply.state" "$2.apply.description" "$2.ledger.state" "$2.ledger.description") || out=
  mapfile -t vals <<<"$out"
  apply_st=${vals[0]:-failure} apply_desc=${vals[1]:-statuses unreadable}
  ledger_st=${vals[2]:-failure} ledger_desc=${vals[3]:-statuses unreadable}
}

post() {  # repo sha context state description — the token goes to curl on stdin, never in argv
  local body
  body=$(python3 -I -c 'import json, sys; print(json.dumps({"state": sys.argv[1], "context": sys.argv[2], "description": sys.argv[3]}))' "$4" "$3" "$5") || return 1
  printf 'Authorization: Bearer %s\n' "$GITHUB_STATUS_TOKEN" | curl -fsS -o /dev/null -X POST -H @- \
    -H "Accept: application/vnd.github+json" "https://api.github.com/repos/realliance/$1/statuses/$2" -d "$body"
}

status() {  # slot repo sha context state description — posted only when (sha, state, description) changed
  [ -n "${GITHUB_STATUS_TOKEN:-}" ] || return 0
  local memo="$STATE/status/$1" said="$3 $5 $6"
  [ "$(cat "$memo" 2>/dev/null)" != "$said" ] || return 0
  if post "$2" "$3" "$4" "$5" "$6"; then printf '%s\n' "$said" > "$memo"
  else echo "warning: could not set $4 on realliance/$2"; fi
}

ledger() { timeout -k 10 "$LEDGER_TIMEOUT" "$LEDGER_BIN" "$@"; }

stored_last_good() {  # state-dir default — the last good the walk stored there, else `default`
  local lg
  lg=$(jget "$1/state.json" last_good 2>/dev/null) || lg=
  [[ $lg =~ ^[0-9a-f]{40}$ ]] || lg=$2
  echo "$lg"
}

no_guests() {  # file — a var-file with no guests, written as sso-ledger writes one
  (umask 077; printf '{\n "guests": {}\n}\n' > "$1")
}

fallback() {  # state-dir — the var-file becomes the last handed guests, or none
  ledger fallback --state "$1" && return 0
  echo "ledger: fallback failed; the var-file hands no guests"
  no_guests "$1/guests.next.json"
}

ledger_check() {  # label state-dir head anchor [dry] — walk, then content. Sets walked, apply_commit and the
                  # statuses. Content runs after any walk that returned a verdict, a freeze included, and never
                  # after one that failed: walk.json is then gone, or not this head's.
  local label=$1 st=$2 head=$3 anchor=$4 dry=${5:-} rc=0
  walked=false apply_commit=
  install -d -m 0700 "$st"
  rm -f "$st/walk.json" "$st/content.json"
  [ -n "$dry" ] || rm -f "$st/guests.next.json"
  ledger walk --mode "$LEDGER_MODE" --repo "$PEOPLE" --head "$head" --state "$st" --keyring "$ETC/gnupg-people" \
    --trust "$ETC/people-trust.json" --anchor "$anchor" ${dry:+--dry} || rc=$?
  if [ "$rc" != 0 ] || [ "$(jget "$st/walk.json" head 2>/dev/null)" != "$head" ]; then
    echo "$label: walk failed (exit $rc)"
    apply_st=failure apply_desc="${pfx}walk failed" ledger_st=pending ledger_desc="${pfx}walk failed"
    return 0
  fi
  walked=true
  apply_commit=$(jget "$st/walk.json" apply_commit) || apply_commit=
  rc=0
  ledger content --mode "$LEDGER_MODE" --repo "$PEOPLE" --walk "$st/walk.json" --state "$st" \
    --keycloak-url "${TF_VAR_keycloak_url:-http://127.0.0.1:8080}" \
    --keycloak-secret-file "$ETC/ledger-lookup.secret" ${dry:+--dry} || rc=$?
  if [ "$rc" = 0 ] && [ -f "$st/content.json" ] && { [ -n "$dry" ] || [ -f "$st/guests.next.json" ]; }; then
    statuses_from "$st/content.json" statuses
  else
    if [ -n "$dry" ]; then echo "$label: content failed (exit $rc)"
    else echo "ledger: content failed; people apply continues with the last handed guests"; fallback "$st"; fi
    statuses_from "$st/walk.json" fallback_statuses
  fi
}

if ! git -C "$SSO" verify-commit HEAD 2>/dev/null; then
  echo "refusing: realliance/sso HEAD has no trusted signature"; exit 1
fi
sso_sha=$(git -C "$SSO" rev-parse HEAD)

# sso-people: a full clone that checks every object it fetches. Its head is checked by the walk, not a keyring.
[ -d "$PEOPLE/.git" ] || git clone -q -c fetch.fsckObjects=true "$PEOPLE_REPO" "$PEOPLE"
git -C "$PEOPLE" fetch -q origin "+refs/heads/$ref:refs/remotes/origin/$ref"
people_sha=$(git -C "$PEOPLE" rev-parse --verify "refs/remotes/origin/$ref^{commit}")
drill_sha=
if [ "$ref" = main ] && [ -n "$drill_ref" ] && [ "$drill_ref" != main ]; then
  if err=$(git -C "$PEOPLE" fetch -q origin "+refs/heads/$drill_ref:refs/remotes/origin/$drill_ref" 2>&1); then
    drill_sha=$(git -C "$PEOPLE" rev-parse --verify "refs/remotes/origin/$drill_ref^{commit}")
  else                                    # no such branch is the usual case: say nothing then
    case $err in *"couldn't find remote ref"*) ;; *) echo "$drill_ref: not fetched: ${err##*$'\n'}" ;; esac
    git -C "$PEOPLE" update-ref -d "refs/remotes/origin/$drill_ref" 2>/dev/null || true
  fi
fi

if [ "$ref" = main ]; then
  slot=main lstate=$STATE/ledger anchor=$PEOPLE_ANCHOR
else
  slot=ref lstate=$(mktemp -d "$STATE/ledger-ref.XXXXXX") anchor=$(stored_last_good "$STATE/ledger" "$PEOPLE_ANCHOR")
  scratch+=("$lstate")
fi
ledger_check ledger "$lstate" "$people_sha" "$anchor"
if ! $walked && [ "$LEDGER_MODE" = check ]; then
  # D2: bash applies the stored last good and never works out a newer commit itself.
  apply_commit=$(stored_last_good "$lstate" "$anchor")
  git -C "$PEOPLE" cat-file -e "$apply_commit^{commit}" 2>/dev/null || apply_commit=
  [ -z "$apply_commit" ] || fallback "$lstate"
fi
people_commit=$apply_commit             # kept: the drill check below sets its own
p_apply_st=$apply_st p_apply_desc=$apply_desc p_ledger_st=$ledger_st p_ledger_desc=$ledger_desc
publish() {
  status "people-$slot-apply" sso-people "$people_sha" sso/apply "$p_apply_st" "$p_apply_desc"
  status "people-$slot-ledger" sso-people "$people_sha" sso/ledger "$p_ledger_st" "$p_ledger_desc"
}

if [ -n "$drill_sha" ]; then
  if [ "$drill_sha" = "$people_sha" ]; then
    echo "$drill_ref: at $ref's head; not checked again"
  else
    ledger_check "$drill_ref" "$STATE/ledger-drills" "$drill_sha" "$(stored_last_good "$STATE/ledger" "$PEOPLE_ANCHOR")" dry
    status drills-apply sso-people "$drill_sha" sso/apply "$apply_st" "$apply_desc"
    status drills-ledger sso-people "$drill_sha" sso/ledger "$ledger_st" "$ledger_desc"
  fi
fi

next=$lstate/guests.next.json
if [ -n "$people_commit" ] && [ ! -f "$next" ]; then no_guests "$next"; fi
sum_of() { sha256sum < "$1" | cut -d' ' -f1; }
guests_sum=none
[ -z "$people_commit" ] || guests_sum=$(sum_of "$next")
if [ "$mode" = changed ] && [ "$ref" = main ] && [ -n "$people_commit" ] \
   && [ "$(cat "$STATE/sso" 2>/dev/null)" = "$sso_sha" ] \
   && [ "$(cat "$STATE/people-head" 2>/dev/null)" = "$people_sha" ] \
   && [ "$(cat "$STATE/people" 2>/dev/null)" = "$people_commit" ] \
   && [ "$(cat "$STATE/people-guests" 2>/dev/null)" = "$guests_sum" ]; then
  publish
  exit 0                                  # nothing new since the last successful apply
fi

apply() { tofu -chdir="$1" init -input=false -no-color >/dev/null && tofu -chdir="$1" apply -auto-approve -input=false -no-color "${@:2}"; }
people_resources() { tofu -chdir="$PEOPLE" init -input=false -no-color >/dev/null && tofu -chdir="$PEOPLE" state list; }

if [ "$mode" = force ] || [ "$(cat "$STATE/sso" 2>/dev/null)" != "$sso_sha" ]; then
  if apply "$SSO/realm"; then
    echo "$sso_sha" > "$STATE/sso"; status sso sso "$sso_sha" sso/apply success "realm applied"
  else
    status sso sso "$sso_sha" sso/apply failure "realm apply failed"; exit 1
  fi
fi

rc=0
if [ -z "$people_commit" ]; then
  echo "no realliance/sso-people apply: $p_apply_desc"
  rc=1
else
  git -C "$PEOPLE" checkout -q --detach "$people_commit"
  if [ "$ref" = main ]; then prev=$lstate/handed.json; else prev=$STATE/ledger/handed.json; fi
  if [ ! -f "$prev" ]; then
    prev=$(mktemp "$STATE/no-guests.XXXXXX"); scratch+=("$prev"); no_guests "$prev"
  fi
  [ "$ref" = main ] || next=$prev         # a test branch never hands guests of its own
  applied=
  if [ "$(sum_of "$next")" = "$(sum_of "$prev")" ]; then
    if apply "$PEOPLE" -var-file="$next"; then applied=$next; fi
  else
    before=$(people_resources) || before=unreadable
    if apply "$PEOPLE" -var-file="$next"; then
      applied=$next
    else
      after=$(people_resources) || after=unreadable
      if [ "$before" = unreadable ] || [ "$after" = unreadable ] \
         || [ -n "$(comm -13 <(sort <<<"$before") <(sort <<<"$after"))" ]; then
        # Dropping the new guests now would destroy what this apply made, or trip prevent_destroy.
        echo "people apply failed, and tofu state may hold part of the new guests; no retry without them"
      else
        echo "people apply failed with the new guests; retrying with the last handed guests"
        if apply "$PEOPLE" -var-file="$prev"; then applied=$prev; fi
      fi
    fi
  fi
  if [ -z "$applied" ]; then
    p_apply_st=failure p_apply_desc="people apply failed"
    rc=1
  elif [ "$ref" != main ]; then
    rm -f "$STATE/people-head"            # main's next run applies main again
  else
    applied_sum=$(sum_of "$applied")
    if [ "$applied" = "$next" ]; then
      ledger settle --state "$lstate" --applied || echo "warning: sso-ledger settle --applied failed"
    else
      ledger settle --state "$lstate" --failed-new || echo "warning: sso-ledger settle --failed-new failed"
      p_apply_desc="${pfx}applied without the new guests (apply-failed)"
    fi
    echo "$people_commit" > "$STATE/people"
    echo "$people_sha" > "$STATE/people-head"
    echo "$applied_sum" > "$STATE/people-guests"
  fi
fi
publish
[ "$rc" = 0 ] || exit 1
date -u +%FT%TZ > "$STATE/last-success"
echo "applied realliance/sso $sso_sha and realliance/sso-people $people_commit (head $people_sha, $LEDGER_MODE)"
