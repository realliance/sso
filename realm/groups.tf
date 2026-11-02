# Group STRUCTURE only. Membership — and hidden-project groups — live in the private
# realliance/sso-people repo; nothing here may manage memberships.
resource "keycloak_group" "community" {
  for_each = toset(["realmic", "realliance"])
  realm_id = keycloak_realm.realliance.id
  name     = each.value
}

# Parent for per-app access groups (/apps/<client_id>), created by module "app".
resource "keycloak_group" "apps" {
  realm_id = keycloak_realm.realliance.id
  name     = "apps"
}
