"""The realliance realm serves the Realliance login theme (installed by the keycloak role)."""
from conftest import realm_get


def test_login_theme_selected():
    assert realm_get()["loginTheme"] == "realliance"
