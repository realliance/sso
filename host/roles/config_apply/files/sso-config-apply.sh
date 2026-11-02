#!/usr/bin/env bash
# Apply realliance/sso realm/ and realliance/sso-people from Git — signed commits only.
# Managed by realliance/sso (host/roles/config_apply).
# Usage: sso-config-apply [changed|force]      (tests may set PEOPLE_REF=<branch>)
set -euo pipefail
mode=${1:-changed}
SSO=/var/lib/sso-pull
PEOPLE=/var/lib/sso-people
STATE=/var/lib/sso-config-apply
ref=${PEOPLE_REF:-main}

exec 9>/run/realliance-sso.lock
flock 9                                   # never overlap ansible-pull or another apply

install -d -m 0700 "$STATE"
set -a; . /etc/realliance-sso/tofu.env; set +a
export GNUPGHOME=/etc/realliance-sso/gnupg TF_IN_AUTOMATION=1 TF_PLUGIN_CACHE_DIR=/var/cache/tofu-plugins
mkdir -p "$TF_PLUGIN_CACHE_DIR"
export GIT_SSH_COMMAND="ssh -i /etc/realliance-sso/people_deploy_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/realliance-sso/known_hosts_github"

status() {  # repo sha state description — commit status, only if a token is configured
  [ -n "${GITHUB_STATUS_TOKEN:-}" ] || return 0
  curl -fsS -o /dev/null -X POST -H "Authorization: Bearer $GITHUB_STATUS_TOKEN" \
    -H "Accept: application/vnd.github+json" "https://api.github.com/repos/realliance/$1/statuses/$2" \
    -d "{\"state\":\"$3\",\"context\":\"sso/apply\",\"description\":\"$4\"}" \
    || echo "warning: could not set the commit status on realliance/$1"
}

if ! git -C "$SSO" verify-commit HEAD 2>/dev/null; then
  echo "refusing: realliance/sso HEAD has no trusted signature"; exit 1
fi
sso_sha=$(git -C "$SSO" rev-parse HEAD)

[ -d "$PEOPLE/.git" ] || git clone -q "$PEOPLE_REPO" "$PEOPLE"
git -C "$PEOPLE" fetch -q origin "$ref"
people_sha=$(git -C "$PEOPLE" rev-parse FETCH_HEAD)
if ! git -C "$PEOPLE" verify-commit "$people_sha" 2>/dev/null; then
  echo "refusing: realliance/sso-people $ref ($people_sha) has no trusted signature"
  status sso-people "$people_sha" failure "unsigned head refused"
  exit 1
fi
git -C "$PEOPLE" checkout -q --detach "$people_sha"

if [ "$mode" = changed ] && [ "$(cat "$STATE/sso" 2>/dev/null)" = "$sso_sha" ] \
   && [ "$(cat "$STATE/people" 2>/dev/null)" = "$people_sha" ]; then
  exit 0                                  # nothing new since the last successful apply
fi

apply() { tofu -chdir="$1" init -input=false -no-color >/dev/null && tofu -chdir="$1" apply -auto-approve -input=false -no-color; }

if apply "$SSO/realm"; then
  echo "$sso_sha" > "$STATE/sso"; status sso "$sso_sha" success "realm applied"
else
  status sso "$sso_sha" failure "realm apply failed"; exit 1
fi
if apply "$PEOPLE"; then
  echo "$people_sha" > "$STATE/people"; status sso-people "$people_sha" success "people applied"
else
  status sso-people "$people_sha" failure "people apply failed"; exit 1
fi
date -u +%FT%TZ > "$STATE/last-success"
echo "applied realliance/sso $sso_sha and realliance/sso-people $people_sha"
