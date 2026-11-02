# Apps behind Realliance SSO. README "Adding an app" explains the module.

# Forgejo at git.realliance.net (project 2). Needs the groups claim: Forgejo makes members of
# forgejo-admins site admins and maps community groups to org teams at each sign-in.
module "forgejo" {
  source               = "./modules/app"
  realm_id             = keycloak_realm.realliance.id
  client_id            = "forgejo"
  name                 = "Forgejo"
  redirect_uris        = ["https://git.realliance.net/user/oauth2/realliance/callback"]
  extra_default_scopes = [keycloak_openid_client_scope.groups.name]
  apps_parent_group_id = keycloak_group.apps.id
}

# Test-only clients (password grant enabled), disabled except while tests/realm/test_apps.py runs.
module "acceptance_tests" {
  source               = "./modules/app"
  realm_id             = keycloak_realm.realliance.id
  client_id            = "acceptance-tests"
  name                 = "Acceptance tests"
  access_type          = "PUBLIC"
  direct_access_grants = true
  enabled              = false
  redirect_uris        = ["https://sso.realliance.net/realms/realliance/account/*"]
  extra_default_scopes = [keycloak_openid_client_scope.groups.name]
  apps_parent_group_id = keycloak_group.apps.id
}

module "acceptance_tests_noscope" {
  source               = "./modules/app"
  realm_id             = keycloak_realm.realliance.id
  client_id            = "acceptance-tests-noscope"
  name                 = "Acceptance tests (no groups scope)"
  access_type          = "PUBLIC"
  direct_access_grants = true
  enabled              = false
  redirect_uris        = ["https://sso.realliance.net/realms/realliance/account/*"]
  apps_parent_group_id = keycloak_group.apps.id
}
