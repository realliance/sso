# Built-in clients we must change. admin-cli's password grant would mint an admin-API token from a
# password alone, skipping the browser flow's MFA — so direct grants are off in this realm.
import {
  to = keycloak_openid_client.admin_cli
  id = "realliance/a971d4ed-fc5b-4a92-aa23-1b70d672f059"
}

resource "keycloak_openid_client" "admin_cli" {
  realm_id                     = keycloak_realm.realliance.id
  client_id                    = "admin-cli"
  name                         = "$${client_admin-cli}"
  enabled                      = true
  access_type                  = "PUBLIC"
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  full_scope_allowed           = true
  frontchannel_logout_enabled  = false
  consent_required             = false

  # Keep Keycloak's built-in values (provider defaults differ).
  backchannel_logout_session_required = false
  use_refresh_tokens                  = false
}
