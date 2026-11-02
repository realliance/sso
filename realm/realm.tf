resource "keycloak_realm" "realliance" {
  realm        = "realliance"
  enabled      = true
  display_name = "Realliance"

  # Invite-only: no self-registration. Verified email is the recovery channel.
  registration_allowed     = false
  verify_email             = true
  login_with_email_allowed = true
  duplicate_emails_allowed = false
  reset_password_allowed   = true
  remember_me              = true
  ssl_required             = "external"

  # Delegation is by PR to realliance/sso-people (amendment 2026-11-02): no fine-grained admin
  # permissions, no organizations — less surface, and no human account administers this realm.
  # NB keycloak provider 5.10.0 cannot switch these from true to false (false is omitted from the
  # update); they were turned off once via the admin REST API on 2026-11-02 and now match.
  admin_permissions_enabled = false
  organizations_enabled     = false

  smtp_server {
    host              = "smtp.resend.com"
    port              = 465
    ssl               = true
    starttls          = false
    from              = "sso@realliance.net"
    from_display_name = "Realliance SSO"
    auth {
      username = "resend"
      password = var.smtp_password # stored in state (private, encrypted B2 bucket); provider 5.10.0 has no write-only form
    }
  }

  # WebAuthn as a SECOND factor: FIDO2 security keys and passkeys. Credentials are bound to
  # this hostname: never rename sso.realliance.net.
  web_authn_policy {
    relying_party_entity_name     = "Realliance"
    relying_party_id              = "sso.realliance.net"
    user_verification_requirement = "preferred"
  }

  # Password first (decided 2026-11-02): no passkey-first sign-in.
  web_authn_passwordless_policy {
    relying_party_entity_name     = "Realliance"
    relying_party_id              = "sso.realliance.net"
    passwordless_passkeys_enabled = false
  }
}

resource "keycloak_required_action" "this" {
  for_each = {
    VERIFY_EMAIL                   = "Verify Email"
    UPDATE_PASSWORD                = "Update Password"
    CONFIGURE_TOTP                 = "Configure OTP"
    webauthn-register              = "Webauthn Register"
    CONFIGURE_RECOVERY_AUTHN_CODES = "Recovery Authentication Codes"
  }
  realm_id = keycloak_realm.realliance.id
  alias    = each.key
  name     = each.value
  enabled  = true
}

# Passwordless (passkey-first) registration is not offered.
resource "keycloak_required_action" "passwordless_off" {
  realm_id = keycloak_realm.realliance.id
  alias    = "webauthn-register-passwordless"
  name     = "Webauthn Register Passwordless"
  enabled  = false
}

moved {
  from = keycloak_required_action.this["webauthn-register-passwordless"]
  to   = keycloak_required_action.passwordless_off
}

# Every admin change (by the box's tofu-apply or a break-glass admin) is logged with details.
resource "keycloak_realm_events" "realliance" {
  realm_id                     = keycloak_realm.realliance.id
  admin_events_enabled         = true
  admin_events_details_enabled = true
  events_enabled               = true
  events_expiration            = 2592000 # 30 days
  events_listeners             = ["jboss-logging"]
}
