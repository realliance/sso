# tofu-plan (master service account, created by host/roles/master_realm) gets read-only rights
# on this realm, so PR plans run without admin power.
data "keycloak_openid_client" "tofu_plan" {
  realm_id  = "master"
  client_id = "tofu-plan"
}

data "keycloak_openid_client" "realliance_management" {
  realm_id = "master"
  # Constant name, not a reference: a reference defers this read whenever the realm has pending
  # changes and forces the role grants to be recreated. Fresh install: apply
  # -target=keycloak_realm.realliance first (docs/runbook.md).
  client_id = "realliance-realm"
}

resource "keycloak_openid_client_service_account_role" "tofu_plan_view" {
  for_each = toset([
    "view-realm", "view-clients", "view-users", "view-identity-providers",
    "view-authorization", "view-events", "query-groups", "query-clients", "query-users", "query-realms",
  ])
  realm_id                = "master"
  service_account_user_id = data.keycloak_openid_client.tofu_plan.service_account_user_id
  client_id               = data.keycloak_openid_client.realliance_management.id
  role                    = each.value
}

# forge-bot (Forgejo sync service, luma-homeops) is a master-realm service account like the tofu
# clients, so no realliance user holds a management role (test_no_user_holds_a_management_role).
# manage-users is accepted full user-admin power over the realm; the mitigations are in
# luma-homeops docs/forgejo.md. Its only intended write is the `picture` attribute.
data "keycloak_openid_client" "forge_bot" {
  realm_id  = "master"
  client_id = "forge-bot"
}

resource "keycloak_openid_client_service_account_role" "forge_bot" {
  for_each                = toset(["view-users", "query-users", "query-groups", "manage-users", "view-events"])
  realm_id                = "master"
  service_account_user_id = data.keycloak_openid_client.forge_bot.service_account_user_id
  client_id               = data.keycloak_openid_client.realliance_management.id
  role                    = each.value
}
