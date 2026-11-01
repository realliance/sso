#!/usr/bin/env bash
# Idempotently apply the GitHub guardrails for realliance/sso:
#   - ruleset `main-protection` on the default branch: PR required, signed commits,
#     no force-push, no deletion. Review count is REVIEWS (0 during build-out, 1 at go-live).
#   - environment `plan`: no reviewers, any branch (PR plans).
#   - environment `production`: every operator in operators.yml must approve, `main` only.
# Usage: scripts/github-guardrails.sh   (needs gh auth with admin on realliance/sso)
set -euo pipefail

REPO=${REPO:-realliance/sso}
REVIEWS=${REVIEWS:-0}
here=$(cd "$(dirname "$0")/.." && pwd)

logins=$(python3 -c 'import sys,yaml; print(" ".join(o["github"] for o in yaml.safe_load(open(sys.argv[1]))["operators"]))' "$here/operators.yml")

ruleset=$(cat <<JSON
{
  "name": "main-protection",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_signatures" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": $REVIEWS,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false } }
  ]
}
JSON
)

id=$(gh api "repos/$REPO/rulesets" -q '.[] | select(.name=="main-protection") | .id')
if [ -n "$id" ]; then
  gh api -X PUT "repos/$REPO/rulesets/$id" --input - <<<"$ruleset" >/dev/null
else
  gh api -X POST "repos/$REPO/rulesets" --input - <<<"$ruleset" >/dev/null
fi
echo "ruleset main-protection: reviews=$REVIEWS"

gh api -X PUT "repos/$REPO/environments/plan" --input - <<<'{}' >/dev/null
echo "environment plan"

reviewers=$(for l in $logins; do printf '{"type":"User","id":%s},' "$(gh api "users/$l" -q .id)"; done)
gh api -X PUT "repos/$REPO/environments/production" --input - >/dev/null <<JSON
{
  "reviewers": [${reviewers%,}],
  "prevent_self_review": false,
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
JSON
existing=$(gh api "repos/$REPO/environments/production/deployment-branch-policies" -q '.branch_policies[].name')
grep -qx main <<<"$existing" || gh api -X POST "repos/$REPO/environments/production/deployment-branch-policies" \
  -f name=main -f type=branch >/dev/null
echo "environment production: reviewers=$logins, branch=main"
