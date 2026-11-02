# realliance-browser: SSO cookie | linked-login redirector | forms.
# Forms: username + password, then MFA (REQUIRED):
#   realliance-mfa-choose  (if the user has any second factor) — TOTP, WebAuthn (FIDO2 key or
#                          passkey) or a recovery code
#   realliance-mfa-enroll  (if "choose" did not run) — forced TOTP set-up
# Alternatives alone would let a user with no second factor straight in; the enroll branch is
# what makes MFA mandatory (tests/realm/test_mfa.py proves both branches).
resource "keycloak_authentication_flow" "browser" {
  realm_id    = keycloak_realm.realliance.id
  alias       = "realliance-browser"
  description = "Password, then MFA (TOTP, FIDO2/passkey, recovery code)."
}

resource "keycloak_authentication_execution" "browser_cookie" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_flow.browser.alias
  authenticator     = "auth-cookie"
  requirement       = "ALTERNATIVE"
  priority          = 10
}

resource "keycloak_authentication_execution" "browser_idp_redirector" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_flow.browser.alias
  authenticator     = "identity-provider-redirector"
  requirement       = "ALTERNATIVE"
  priority          = 20
}

resource "keycloak_authentication_subflow" "browser_forms" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_flow.browser.alias
  alias             = "realliance-browser-forms"
  provider_id       = "basic-flow"
  requirement       = "ALTERNATIVE"
  priority          = 30
}

resource "keycloak_authentication_execution" "forms_username_password" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.browser_forms.alias
  authenticator     = "auth-username-password-form"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_subflow" "mfa" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.browser_forms.alias
  alias             = "realliance-mfa"
  provider_id       = "basic-flow"
  requirement       = "REQUIRED"
  priority          = 20
}

# --- branch 1: the user already has a second factor ------------------------------------------
resource "keycloak_authentication_subflow" "mfa_choose" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.mfa.alias
  alias             = "realliance-mfa-choose"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 10
}

resource "keycloak_authentication_execution" "mfa_has_factor" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.mfa_choose.alias
  authenticator     = "conditional-user-configured"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution" "mfa_option" {
  for_each = {
    "auth-otp-form"                 = 20
    "webauthn-authenticator"        = 30
    "auth-recovery-authn-code-form" = 40
  }
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.mfa_choose.alias
  authenticator     = each.key
  requirement       = "ALTERNATIVE"
  priority          = each.value
}

# --- branch 2: no second factor yet → enrol TOTP ----------------------------------------------
resource "keycloak_authentication_subflow" "mfa_enroll" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.mfa.alias
  alias             = "realliance-mfa-enroll"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 20
}

resource "keycloak_authentication_execution" "mfa_choose_skipped" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.mfa_enroll.alias
  authenticator     = "conditional-sub-flow-executed"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "mfa_choose_skipped" {
  realm_id     = keycloak_realm.realliance.id
  execution_id = keycloak_authentication_execution.mfa_choose_skipped.id
  alias        = "realliance-mfa-choose-not-executed"
  config = {
    flow_to_check = keycloak_authentication_subflow.mfa_choose.alias
    check_result  = "not-executed"
  }
}

resource "keycloak_authentication_execution" "mfa_enroll_totp" {
  realm_id          = keycloak_realm.realliance.id
  parent_flow_alias = keycloak_authentication_subflow.mfa_enroll.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_authentication_bindings" "realliance" {
  realm_id     = keycloak_realm.realliance.id
  browser_flow = keycloak_authentication_flow.browser.alias

  depends_on = [
    keycloak_authentication_execution.browser_cookie,
    keycloak_authentication_execution.browser_idp_redirector,
    keycloak_authentication_execution.forms_username_password,
    keycloak_authentication_execution.mfa_has_factor,
    keycloak_authentication_execution.mfa_option,
    keycloak_authentication_execution_config.mfa_choose_skipped,
    keycloak_authentication_execution.mfa_enroll_totp,
  ]
}
