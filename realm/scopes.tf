# `groups` claim: flat array of group names. NOT a realm default scope — only clients that list it
# in extra_default_scopes (e.g. Forgejo) receive it, so hidden-project names never reach other apps.
resource "keycloak_openid_client_scope" "groups" {
  realm_id               = keycloak_realm.realliance.id
  name                   = "groups"
  description            = "Group membership as a flat array claim."
  include_in_token_scope = true
}

resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id            = keycloak_realm.realliance.id
  client_scope_id     = keycloak_openid_client_scope.groups.id
  name                = "groups"
  claim_name          = "groups"
  full_path           = false
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}
