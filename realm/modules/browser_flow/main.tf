# Password, then required MFA (choose a configured factor, or be forced to enrol TOTP).
# With deny_unless_role, sign-in options are wrapped in a REQUIRED "authenticate" subflow (Keycloak
# ignores ALTERNATIVEs that sit beside a REQUIRED/CONDITIONAL sibling) followed by a CONDITIONAL
# "access" subflow that denies users without the role.
locals {
  deny = var.deny_unless_role != null
  top  = local.deny ? keycloak_authentication_subflow.authenticate[0].alias : keycloak_authentication_flow.this.alias
}

resource "keycloak_authentication_flow" "this" {
  realm_id    = var.realm_id
  alias       = "${var.prefix}-browser"
  description = var.description
}

resource "keycloak_authentication_subflow" "authenticate" {
  count             = local.deny ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_flow.this.alias
  alias             = "${var.prefix}-authenticate"
  provider_id       = "basic-flow"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution" "cookie" {
  realm_id          = var.realm_id
  parent_flow_alias = local.top
  authenticator     = "auth-cookie"
  requirement       = "ALTERNATIVE"
  priority          = 10
}

resource "keycloak_authentication_execution" "idp_redirector" {
  realm_id          = var.realm_id
  parent_flow_alias = local.top
  authenticator     = "identity-provider-redirector"
  requirement       = "ALTERNATIVE"
  priority          = 20
}

resource "keycloak_authentication_subflow" "forms" {
  realm_id          = var.realm_id
  parent_flow_alias = local.top
  alias             = "${var.prefix}-browser-forms"
  provider_id       = "basic-flow"
  requirement       = "ALTERNATIVE"
  priority          = 30
}

resource "keycloak_authentication_execution" "username_password" {
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.forms.alias
  authenticator     = "auth-username-password-form"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_subflow" "mfa" {
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.forms.alias
  alias             = "${var.prefix}-mfa"
  provider_id       = "basic-flow"
  requirement       = "REQUIRED"
  priority          = 20
}

resource "keycloak_authentication_subflow" "mfa_choose" {
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.mfa.alias
  alias             = "${var.prefix}-mfa-choose"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 10
}

resource "keycloak_authentication_execution" "mfa_has_factor" {
  realm_id          = var.realm_id
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
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.mfa_choose.alias
  authenticator     = each.key
  requirement       = "ALTERNATIVE"
  priority          = each.value
}

resource "keycloak_authentication_subflow" "mfa_enroll" {
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.mfa.alias
  alias             = "${var.prefix}-mfa-enroll"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 20
}

resource "keycloak_authentication_execution" "mfa_choose_skipped" {
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.mfa_enroll.alias
  authenticator     = "conditional-sub-flow-executed"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "mfa_choose_skipped" {
  realm_id     = var.realm_id
  execution_id = keycloak_authentication_execution.mfa_choose_skipped.id
  alias        = "${var.prefix}-mfa-choose-not-executed"
  config = {
    flow_to_check = keycloak_authentication_subflow.mfa_choose.alias
    check_result  = "not-executed"
  }
}

resource "keycloak_authentication_execution" "mfa_enroll_totp" {
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.mfa_enroll.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"
  priority          = 20
}

# --- optional access check ---------------------------------------------------------------------
resource "keycloak_authentication_subflow" "access" {
  count             = local.deny ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_flow.this.alias
  alias             = "${var.prefix}-access"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"
  priority          = 20
}

resource "keycloak_authentication_execution" "lacks_role" {
  count             = local.deny ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.access[0].alias
  authenticator     = "conditional-user-role"
  requirement       = "REQUIRED"
  priority          = 10
}

resource "keycloak_authentication_execution_config" "lacks_role" {
  count        = local.deny ? 1 : 0
  realm_id     = var.realm_id
  execution_id = keycloak_authentication_execution.lacks_role[0].id
  alias        = "${var.prefix}-lacks-access-role"
  config = {
    condUserRole = var.deny_unless_role
    negate       = "true"
  }
}

resource "keycloak_authentication_execution" "deny" {
  count             = local.deny ? 1 : 0
  realm_id          = var.realm_id
  parent_flow_alias = keycloak_authentication_subflow.access[0].alias
  authenticator     = "deny-access-authenticator"
  requirement       = "REQUIRED"
  priority          = 20
}
