"""forge-ci's package token — pushes images to the forge registry, and only as far as its team allows."""
import secrets

from conftest import _load_env
from forge_helpers import (FORGE_SECRETS, PACKAGE_TOKEN_REPO_SCOPED, anonymous_manifest, forge_api,
                           oci_push)


def test_package_token_scope():
    tok = _load_env(FORGE_SECRETS)["FORGE_CI_PACKAGE_TOKEN"]
    tag = f"probe-{secrets.token_hex(3)}"
    try:
        assert oci_push("realliance/forge-bot", tag, "forge-ci", tok) == 201
        assert anonymous_manifest("realliance/forge-bot", tag).status_code == 200   # public with the org
        assert oci_push("forge-bot/b0-probe", tag, "forge-ci", tok) in (401, 403)   # another owner
        other = oci_push("realliance/b0-other", tag, "forge-ci", tok)
        assert other in (401, 403) if PACKAGE_TOKEN_REPO_SCOPED else other == 201
    finally:
        for name in ("forge-bot", "b0-other"):
            forge_api("DELETE", f"/api/v1/packages/realliance/container/{name}/{tag}")
