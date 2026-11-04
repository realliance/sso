"""Helpers for the runner-class (ci-dispatch) acceptance tests. Secrets come from the unlocked
realliance/sso-secrets checkout and never reach argv or output."""
from conftest import _load_env
from forge_helpers import FORGE_SECRETS, forge_api

CI_TOKEN_KEY = "CI_DISPATCH_FORGEJO_TOKEN"
# Local site administrators; the test adds the Owners at run time from the realliance-ops Owners team.
EXPECTED_ADMINS = {"forgejo-admin", "forge-bot", "forge-ci", "ci-dispatch"}


def ci_token() -> str:
    """The ci-dispatch API token (KeyError if it is not minted yet). Never print it."""
    return _load_env(FORGE_SECRETS)[CI_TOKEN_KEY]


def forge_api_paged(path: str, limit: int = 50, **kw) -> list[dict]:
    """Every item of a paged Forgejo list endpoint, as the break-glass admin (50 is the page cap)."""
    items, page = [], 1
    while True:
        r = forge_api("GET", path, params={"page": page, "limit": limit}, **kw)
        r.raise_for_status()
        batch = r.json()
        items += batch
        if len(batch) < limit:
            return items
        page += 1
