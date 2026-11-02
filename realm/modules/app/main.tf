# One app behind Realliance SSO: client, client roles, access group /apps/<client_id> granted
# <client_id>.user, and a per-client browser flow that denies anyone without that role.
locals {
  base_scopes = ["acr", "basic", "email", "profile", "roles", "web-origins"]
}

module "browser" {
  source           = "../browser_flow"
  realm_id         = var.realm_id
  prefix           = var.client_id
  description      = "Realliance sign-in for ${var.client_id}; denies users without ${var.client_id}.user."
  deny_unless_role = "${var.client_id}.user"
}

# Password grant flow for test clients: username, password, then the same access check (no MFA).
resource "keycloak_authentication_flow" "direct_grant" {
  count       = var.direct_access_grants ? 1 : 0
  realm_id    = var.realm_id
  alias       = "${var.client_id}-direct-grant"
  description = "Test-only password grant for ${var.client_id} with access check."
}

resource "keycloak_authentication_execution" "dg_username" {
  count             = var.direct_access_grants ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_flow.direct_grant[0].alias
  authenticator     = "direct-grant-validate-username"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution" "dg_password" {
  count             = var.direct_access_grants ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_flow.direct_grant[0].alias
  authenticator     = "direct-grant-validate-password"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_authentication_subflow" "dg_access" {
  count             = var.direct_access_grants ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_flow.direct_grant[0].alias
  alias             = "${var.client_id}-direct-grant-access"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 30
}

resource "keycloak_authentication_execution" "dg_lacks_role" {
  count             = var.direct_access_grants ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.dg_access[0].alias
  authenticator     = "conditional-user-role"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "dg_lacks_role" {
  count        = var.direct_access_grants ? 1 : 0
  realm_id     = var.realm_id
  execution_id = keycloak_authentication_execution.dg_lacks_role[0].id
  alias        = "${var.client_id}-direct-grant-lacks-access-role"
  config = {
    condUserRole = "${var.client_id}.user"
    negate       = "true"
  }
}

resource "keycloak_authentication_execution" "dg_deny" {
  count             = var.direct_access_grants ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.dg_access[0].alias
  authenticator     = "deny-access-authenticator"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_openid_client" "this" {
  realm_id                     = var.realm_id
  client_id                    = var.client_id
  name                         = var.name
  enabled                      = var.enabled
  access_type                  = var.access_type
  standard_flow_enabled        = true
  direct_access_grants_enabled = var.direct_access_grants
  valid_redirect_uris          = var.redirect_uris
  pkce_code_challenge_method   = "S256"

  authentication_flow_binding_overrides {
    browser_id      = module.browser.id
    direct_grant_id = var.direct_access_grants ? keycloak_authentication_flow.direct_grant[0].id : null
  }

  depends_on = [module.browser, keycloak_authentication_execution_config.dg_lacks_role,
  keycloak_authentication_execution.dg_deny, keycloak_authentication_execution.dg_password]
}

resource "keycloak_role" "this" {
  for_each  = toset(var.roles)
  realm_id  = var.realm_id
  client_id = keycloak_openid_client.this.id
  name      = each.value
}

resource "keycloak_openid_client_default_scopes" "this" {
  realm_id       = var.realm_id
  client_id      = keycloak_openid_client.this.id
  default_scopes = concat(local.base_scopes, var.extra_default_scopes)
}

resource "keycloak_group" "access" {
  realm_id  = var.realm_id
  parent_id = var.apps_parent_group_id
  name      = var.client_id
}

resource "keycloak_group_roles" "access" {
  realm_id   = var.realm_id
  group_id   = keycloak_group.access.id
  role_ids   = [keycloak_role.this["user"].id]
  exhaustive = true
}
