# Enrolment: when a user is created (by realliance/sso-people), Keycloak emails a one-time link to
# verify their email and set a password. invite-user skips disabled users and users without an
# email, so `active: false` people are never invited. MFA (TOTP) enrolment is forced at first
# sign-in by the browser flow.
resource "keycloak_workflow" "enrol" {
  realm   = keycloak_realm.realliance.id
  name    = "enrol"
  on      = "user_created"
  enabled = true

  step {
    uses = "invite-user"
  }
}
