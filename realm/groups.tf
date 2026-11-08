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

# Forgejo (project 2). Public names, so they live here; membership is in realliance/sso-people.
# forgejo-admins: Forgejo site admins (synced at each sign-in, --admin-group).
# realliance-maintainers: the realliance org's maintainers team (Forgejo --group-team-map).
resource "keycloak_group" "forgejo" {
  for_each = toset(["forgejo-admins", "realliance-maintainers"])
  realm_id = keycloak_realm.realliance.id
  name     = each.value
}

# Invited guests (member invites): top level, no roles. The people layer in realliance/sso-people puts each
# guest the box admits from ledger.yaml here; nothing here grants it anything.
resource "keycloak_group" "guests" {
  realm_id = keycloak_realm.realliance.id
  name     = "guests"
}
